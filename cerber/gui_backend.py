"""Backend of Cerber.app: runs one command and reports progress as JSON Lines (see app/PROTOCOL.md).

    python -m cerber.gui_backend scan PATH… | sandbox ARCHIVE | github URL | huggingface URL
                                 | laptop --level quick|patterns|deep|mega | quarantine PATH | history | info

stdout carries only protocol events; everything else goes to stderr.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import sys
import threading
import time
import traceback

from . import config

VERDICT_ORDER = ["CLEAN", "INFO", "SUSPICIOUS", "PUA", "MALICIOUS"]
ENV_TO_VERDICT = {"malicious": "MALICIOUS", "pua": "PUA", "suspicious": "SUSPICIOUS", "low": "INFO", "info": "CLEAN"}
# quick level: where infections usually land + the executables of everything running right now
QUICK_LOCATIONS = ["~/Downloads", "~/Desktop", "~/Library/LaunchAgents", "/Library/LaunchAgents",
                   "/Library/LaunchDaemons", "/Library/PrivilegedHelperTools", "/Library/StartupItems",
                   "/Users/Shared", "/tmp", "/private/var/tmp",
                   "~/Library/Application Support/Google/Chrome/Default/Extensions"]
APPLE_PREFIXES = ("/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/", "/usr/lib/",
                  "/Library/Apple/")
LAPTOP_ROOTS = ["/Applications", "/Users", "/Library", "/opt", "/usr/local", "/private/etc", "/private/var",
                "/private/tmp", "/cores"]
def _netaudit_collectors() -> list[str]:
    """Collectors that only run at the Mega level (network, remote access, logs)."""
    from .envscan import COLLECTORS
    return [c[0] for c in COLLECTORS if c[0].startswith("netaudit")]
INDEX = "gui-index.jsonl"
LEVEL_PL = {"quick": "Szybki", "patterns": "Średni", "deep": "Dokładny", "mega": "Mega"}


class Emitter:
    def __init__(self):
        self._out = os.fdopen(os.dup(1), "w", buffering=1, encoding="utf-8")
        os.dup2(2, 1)                   # print() from libraries must not corrupt the protocol
        self._lock = threading.Lock()

    def __call__(self, obj: dict) -> None:
        line = json.dumps(obj, ensure_ascii=False, default=str)
        with self._lock:
            self._out.write(line + "\n")
            self._out.flush()


emit: Emitter
SCAN_ROOTS: list[str] = []          # quarantine is only offered for files under what the user asked to scan
from .report import QUARANTINE_SCORE, high_risk  # noqa: E402,F401 - one rule for app and reports


def _read_selfcheck(work: str, kind: str) -> list[str]:
    try:
        with open(os.path.join(work, "out", f"selfcheck-{kind}.json")) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return []


def log(msg: str) -> None:
    emit({"ev": "log", "msg": msg})


def stage(sid: str, title: str) -> None:
    emit({"ev": "stage", "id": sid, "title": title})


# ------------------------------------------------------------------ conversions

def _rel(p: str | None, base: str | None) -> str | None:
    if p and base and p.startswith(base.rstrip("/") + "/"):
        return os.path.relpath(p, base)
    return p


def public_result(r: dict, base: str | None = None, sandboxed: bool = False) -> dict:
    meta = r.get("meta") or {}
    path = r["path"]
    if sandboxed:
        disp = r.get("display_path") or (os.path.relpath(path, base) if base and path.startswith(base)
                                         else os.path.basename(path))
        if r.get("container_only") and not disp.endswith(" (całe archiwum)"):
            disp += " (całe archiwum)"
    else:
        disp = path
    exists = (not sandboxed) and os.path.isfile(path)
    in_roots = any(path == root or path.startswith(root.rstrip("/") + "/") for root in SCAN_ROOTS)
    risky = high_risk(r)
    can_q = exists and in_roots and risky and not r.get("quarantined")
    note = None if can_q or r.get("quarantined") else (
        "Kopia z sandboksu – katalog roboczy został już usunięty" if sandboxed else
        "Pliku już nie ma na dysku" if not exists else
        f"Niskie ryzyko (poniżej {QUARANTINE_SCORE} pkt) – kwarantanna niepotrzebna" if not risky else
        "Plik spoza skanowanych miejsc")
    return {
        "path": path if not sandboxed else disp,
        "display_path": disp,
        "verdict": r["verdict"], "score": r.get("score", 0), "primary": r.get("primary"),
        "size": r.get("size", 0), "ftype": r.get("ftype"), "sha256": r.get("sha256"),
        "worst_object": _rel(meta.get("worst_object") or r.get("worst_object"), base if sandboxed else None),
        "can_quarantine": can_q, "quarantine_note": note,
        "quarantined": r.get("quarantined"),
        "ai": r.get("ai"),
        "errors": (r.get("errors") or [])[:5],
        "detections": [{"name": d.get("name"), "engine": d.get("engine"), "confidence": d.get("confidence"),
                        "score": d.get("score"), "description": d.get("description"),
                        "object": _rel(d.get("object"), base if sandboxed else None),
                        "pua": d.get("pua", False)} for d in (r.get("detections") or [])[:60]],
        "detonation": _public_detonation(r.get("detonation")),
    }


def _public_detonation(det: dict | None) -> dict | None:
    """What the script did in the sealed detonation sandbox (trimmed for the app)."""
    if not det:
        return None
    return {"ran": det.get("ran"), "kind": det.get("kind"), "seconds": det.get("seconds"),
            "timed_out": det.get("timed_out"), "verdict": det.get("verdict"), "score": det.get("score"),
            "behaviors": (det.get("behaviors") or [])[:30], "commands": (det.get("commands") or [])[:40],
            "network": (det.get("network") or [])[:30], "files_read": (det.get("files_read") or [])[:40],
            "files_written": (det.get("files_written") or [])[:40],
            "stages": [{"source_preview": (st.get("source_preview") or "")[:600],
                        "detections": [d.get("name") if isinstance(d, dict) else str(d)
                                       for d in (st.get("detections") or [])][:10]}
                       for st in (det.get("stages") or [])[:5]],
            "limitations": (det.get("limitations") or [])[:10]}


def worst(*verdicts: str) -> str:
    return max((v for v in verdicts if v in VERDICT_ORDER), key=VERDICT_ORDER.index, default="CLEAN")


# ------------------------------------------------------------------ scanning helpers

def make_opts(level: str, ai: bool):
    from .scanner import ScanOptions
    # among the laptop levels only Mega uses AI; target scans use it only when the app passes --ai
    o = ScanOptions(deep=True, level=level, defer_ai=ai or level == "mega")
    o.collect_cloud = level == "mega"          # Mega downloads risky cloud-only files (run_cloud_step)
    if level == "quick":
        o.max_file_size = 256 << 20
        o.file_timeout = 120
    return o


def _sandbox_disabled() -> bool:
    return os.environ.get("CERBER_NO_SANDBOX") == "1"


class Cancel:
    """SIGINT/SIGTERM from the app → cancel event (sandboxed children get SIGINT and stop gracefully)."""

    def __init__(self):
        self.event = threading.Event()
        signal.signal(signal.SIGINT, lambda *_: self.event.set())
        signal.signal(signal.SIGTERM, lambda *_: self.event.set())

    @property
    def set(self) -> bool:
        return self.event.is_set()


# What a sandboxed child may say to the app (app/PROTOCOL.md, "Events from sandboxed children"). A child taken over
# by a scanned file must not speak for this unsandboxed process: `done`/`history` carry report paths the app opens,
# `quarantined`, `ai_installed` (a llama-server path the app would start), `api_ready`, `info` … come only from here.
CHILD_EVENTS = frozenset({"log", "stage", "progress", "finding", "error", "sandbox_violation"})
NETWATCH_EVENTS = frozenset({"log", "error", "sandbox_violation", "net_event", "net_status", "watch_target"})
IPHONE_EVENTS = frozenset({"log", "stage", "progress", "error", "sandbox_violation", "iphone_finding"})
REPORT_KEYS = ("report_html", "report_json")


def _report_path_ok(p) -> bool:
    """None/"" or a path that resolves inside Cerber's reports folder."""
    if p is None or p == "":
        return True
    if not isinstance(p, str) or "\x00" in p or len(p) > 4096:
        return False
    base = os.path.realpath(config.REPORTS)
    return os.path.realpath(p).startswith(base + os.sep)


def _report_paths_ok(obj, depth: int = 0) -> bool:
    """Every report_html / report_json anywhere in `obj` lies inside config.REPORTS (nesting is bounded)."""
    if depth > 16:
        return False
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in REPORT_KEYS and not _report_path_ok(v):
                return False
            if isinstance(v, (dict, list)) and not _report_paths_ok(v, depth + 1):
                return False
    elif isinstance(obj, list):
        return all(_report_paths_ok(v, depth + 1) for v in obj if isinstance(v, (dict, list)))
    return True


def child_event(ev, allowed: frozenset = CHILD_EVENTS) -> dict | None:
    """`ev` from a sandboxed child when the app may see it, otherwise None (dropped, noted on stderr)."""
    kind = ev.get("ev") if isinstance(ev, dict) else None
    if kind in allowed and _report_paths_ok(ev):
        return ev
    if kind != "inner_done":
        print(f"Cerber: odrzucono zdarzenie procesu z sandboksa: {str(kind)[:40]!r}", file=sys.stderr)
    return None


def _relay(sandboxed: bool):
    def relay(ev: dict) -> None:
        ev = child_event(ev)
        if ev is None:
            return
        if ev["ev"] == "finding":
            item = ev.get("item")
            try:
                if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                    raise TypeError("item")
                ev = {"ev": "finding", "item": public_result(item, sandboxed=sandboxed)}
            except (KeyError, TypeError, AttributeError, ValueError):
                print("Cerber: odrzucono nieprawidłowe znalezisko z sandboksa", file=sys.stderr)
                return
        emit(ev)
    return relay


class LiveWatch:
    """Mega: network & behaviour watch for the rest of the session (envscan.netwatch in the `env` sandbox,
    on a background thread). New files/programs it reports are handed to the running file scan."""

    def __init__(self):
        self.stop_ev = threading.Event()
        self.lock = threading.Lock()
        self.targets: dict[str, str] = {}
        self.scanned: set[str] = set()
        self.handed: set[str] = set()
        self.feed: str | None = None
        self.result: dict | None = None
        self.thread = threading.Thread(target=self._run, daemon=True, name="cerber-livewatch")

    def _relay(self, ev: dict) -> None:
        if child_event(ev, NETWATCH_EVENTS) is None:
            return
        kind = ev.get("ev")
        if kind == "net_event":
            if isinstance(ev.get("item"), dict):
                from .watch import clean_net_item       # known keys, plain types, bounded lengths
                emit({"ev": "net_event", "item": clean_net_item(ev["item"])})
            return
        if kind == "watch_target":
            p = ev.get("path")
            if isinstance(p, str) and p.startswith("/") and "\n" not in p and len(p) < 4096:
                with self.lock:
                    if p not in self.targets and len(self.targets) < 1000:
                        self.targets[p] = str(ev.get("reason") or "")[:200]
                        self._write([p])
            return
        if kind in ("net_status", "log", "sandbox_violation"):
            emit(ev)
        elif kind == "error":
            emit({**ev, "fatal": False})

    def _write(self, paths: list[str]) -> None:
        if not self.feed:
            return
        try:
            with open(self.feed, "a") as fh:
                for p in paths:
                    fh.write(json.dumps({"path": p}, ensure_ascii=False) + "\n")
                    self.handed.add(p)
        except OSError:
            pass

    def attach(self, feed: str) -> None:
        with self.lock:
            self.feed, self.handed = feed, set()
            self._write([p for p in self.targets if p not in self.scanned])

    def detach(self, scanned: list[str] | None) -> None:
        with self.lock:
            self.feed = None
            self.scanned |= set(scanned or [])

    def pending(self) -> list[str]:
        with self.lock:
            return [p for p in self.targets if p not in self.scanned]

    def mark_scanned(self, paths: list[str]) -> None:
        with self.lock:
            self.scanned |= set(paths)

    def _run(self) -> None:
        from .sandbox import new_workspace, remove_workspace, run_inner
        if _sandbox_disabled():
            from .envscan.netwatch import NetWatch
            from .envscan.util import EnvContext
            ctx = EnvContext({"deep": True})
            w = NetWatch(ctx, self._relay, root_pid=os.getpid())
            w.loop(self.stop_ev)
            self.result = {**w.summary(), "findings": [
                {"category": f.category, "title": f.title, "location": f.location, "severity": f.severity,
                 "score": f.detection.score, "description": f.detection.description,
                 "evidence": f.detection.evidence[:8]} for f in ctx.findings]}
            self._relay(w.status(False))
            return
        work = new_workspace()
        try:
            self.result = run_inner(work, "env", ["inner-netwatch", "--work", work, "--root-pid", str(os.getpid())],
                                    self._relay, self.stop_ev, out_name="netwatch.json", wall=48 * 3600)
        finally:
            remove_workspace(work)

    def start(self) -> None:
        self.thread.start()

    def stop(self, timeout: float = 45) -> dict | None:
        self.stop_ev.set()
        self.thread.join(timeout)
        return self.result


def run_file_scan(paths: list[str], opts, cancel: "Cancel", live: "LiveWatch | None" = None,
                  quiet: bool = False) -> dict:
    """Files/folders in place – inside the read-only `scan` sandbox. `live`: new files the Mega live watch
    reports while this runs are scanned too; `quiet`: a follow-up pass (no stage/progress events)."""
    from .sandbox import new_workspace, remove_workspace, run_inner
    if _sandbox_disabled():
        return _run_file_scan_direct(paths, opts)
    work = new_workspace()
    relay = _relay(False)
    if quiet:
        def relay(ev: dict, _inner=relay) -> None:      # noqa: E306
            if ev.get("ev") not in ("stage", "progress"):
                _inner(ev)
    try:
        if not quiet:
            stage("sandbox", "Uruchamianie sandboksa (dysk tylko do odczytu, bez sieci)…")
        job = {"paths": paths, "level": opts.level, "ai": opts.defer_ai, "exclude": opts.exclude,
               "max_file_size": opts.max_file_size, "file_timeout": opts.file_timeout, "follow": live is not None,
               "collect_cloud": opts.collect_cloud}
        jp = os.path.join(work, "in", "job.json")
        with open(jp, "w") as fh:
            json.dump(job, fh)
        if live is not None:
            live.attach(os.path.join(work, "in", "extra.jsonl"))
        report = None
        try:
            report = run_inner(work, "scan", ["inner-scan", "--work", work, "--job", jp], relay, cancel.event,
                               wall=48 * 3600)
        finally:
            if live is not None:
                live.detach((report or {}).get("extra_scanned"))
        if report is None:
            report = _empty_report(cancelled=cancel.set)
        report["sandbox_verified"] = _read_selfcheck(work, "scan")
        if cancel.set:
            report["cancelled"] = True
        return report
    finally:
        remove_workspace(work)


def _run_file_scan_direct(paths: list[str], opts) -> dict:
    """Debug fallback (CERBER_NO_SANDBOX=1): same scan without isolation."""
    from .scanner import load_engines, scan_paths
    stage("load", "Ładowanie baz sygnatur (7 mln wzorców)…")
    bundle = load_engines(opts, log)
    found: list[dict] = []

    def on_result(r: dict) -> None:
        found.append(r)
        emit({"ev": "finding", "item": public_result(r)})

    try:
        return scan_paths(paths, opts, log=log, engines_bundle=bundle, progress=False, on_result=on_result,
                          on_progress=lambda p: emit({"ev": "progress", **p}))
    except KeyboardInterrupt:
        rep = _empty_report(cancelled=True)
        rep["results"] = found
        return rep


def _isolation(*kinds: str, verified: list[str] | None = None) -> dict:
    from .sandbox import ISOLATION
    items: list[str] = []
    for k in kinds:
        items += [x for x in ISOLATION[k] if x not in items]
    return {"mode": "readonly" if "scan" in kinds else kinds[0], "isolation": items, "verified": verified or []}


DETONATE_MAX = 8          # scripts run per scan (each takes ~5–10 s: own disk image + sealed sandbox)


def run_behavior_step(report: dict, cancel: "Cancel", base: str | None = None, sandboxed: bool = False) -> None:
    """Suspicious/obfuscated shell and Python scripts found by the static scan are run for a few seconds in
    a sealed sandbox (cerber/detonate.py: no network, fake home with bait files, nothing but the interpreter
    and data tools may run). What they try to do can only raise a verdict, never lower it."""
    from . import detonate
    todo = []
    for r in report.get("results", []):
        path = r.get("path") or ""
        try:
            kind = detonate.eligible(r, path) if os.path.isfile(path) else None
        except Exception:  # noqa: BLE001
            kind = None
        if kind:
            todo.append((r, kind))
    if not todo or cancel.set or report.get("cancelled"):
        return
    todo.sort(key=lambda t: -(t[0].get("score") or 0))
    if len(todo) > DETONATE_MAX:
        log(f"Analiza zachowania: {len(todo)} skryptów kwalifikuje się, uruchamiam {DETONATE_MAX} najgroźniejszych")
        todo = todo[:DETONATE_MAX]
    stage("behavior", f"Analiza zachowania: {len(todo)} podejrzanych skryptów w zamkniętym sandboksie…")
    for i, (r, kind) in enumerate(todo):
        if cancel.set:
            break
        emit({"ev": "progress", "stage": "behavior", "done": i, "total": len(todo),
              "current": r.get("display_path") or os.path.basename(r["path"])})
        try:
            det = detonate.detonate_file(r["path"], kind, timeout=15, emit=emit, cancel=cancel.event)
        except Exception as exc:  # noqa: BLE001 - a failed detonation must not fail the scan
            log(f"Analiza zachowania nie powiodła się dla {os.path.basename(r['path'])}: {exc!r}")
            continue
        if not det or not det.get("ran"):
            continue
        r["detonation"] = det
        r["detections"] = list(r.get("detections") or []) + list(det.get("detections") or [])
        r["verdict"] = worst(r["verdict"], det.get("verdict") or "CLEAN")
        r["score"] = max(r.get("score") or 0, det.get("score") or 0)
        emit({"ev": "finding", "item": public_result(r, base, sandboxed=sandboxed)})      # updated in place
    emit({"ev": "progress", "stage": "behavior", "done": len(todo), "total": len(todo)})
    counts = {v: 0 for v in VERDICT_ORDER}
    for r in report.get("results", []):
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    counts["CLEAN"] = max(0, (report.get("files") or 0) - sum(n for k, n in counts.items() if k != "CLEAN"))
    report["counts"] = counts


def run_ai_step(report: dict, opts) -> None:
    from .scanner import run_ai
    from .engines.ai import wants_ai
    todo = [r for r in report.get("results", []) if r.get("ai_context") and wants_ai(r, opts.ai_all)]
    if todo:
        stage("ai", f"Analiza AI ({len(todo)} plików w szarej strefie)…")
        prev = opts.ai
        opts.ai = True
        try:
            run_ai(report, opts, log)
        except KeyboardInterrupt:
            log("AI przerwane")
        opts.ai = prev
        counts = {v: 0 for v in VERDICT_ORDER}
        counts["CLEAN"] = report.get("files", 0) - len(report["results"])
        for r in report["results"]:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        report["counts"] = counts
    for r in report.get("results", []):
        r.pop("ai_context", None)


def _empty_report(cancelled: bool = False) -> dict:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    return {"started": now, "finished": now, "seconds": 0, "files": 0, "bytes": 0, "objects": 0,
            "counts": {k: 0 for k in VERDICT_ORDER}, "results": [], "patterns_total": 0, "databases": {},
            "skipped_count": 0, "errors": [], "cancelled": cancelled}


def finish(mode: str, level: str, title: str, report: dict, t0: float, started: str, *, results: list[dict],
           env: dict | None = None, network: dict | None = None, sandbox: dict | None = None,
           repo: dict | None = None, extra: dict | None = None) -> None:
    from .report import write_html
    from .scanner import save_json
    stage("report", "Zapisywanie raportu…")
    counts = report.get("counts") or {k: 0 for k in VERDICT_ORDER}
    file_verdict = worst(*[k for k, v in counts.items() if v])
    env_verdict = worst(*[ENV_TO_VERDICT.get(f["severity"], "CLEAN") for f in (env or {}).get("findings", [])])
    url_verdict = ((extra or {}).get("url") or {}).get("ioc_verdict", "CLEAN")
    verdict = worst(file_verdict, env_verdict, url_verdict)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = os.path.join(config.REPORTS, f"gui-{stamp}")
    full = dict(report)
    full.update({"mode": mode, "level": level, "title": title, "verdict": verdict, "network": network,
                 "sandbox": sandbox, "repo": repo, **(extra or {})})
    if env is not None:
        full["environment"] = env.get("_raw")
    jp = hp = None
    try:
        os.makedirs(config.REPORTS, exist_ok=True)
        jp = save_json({k: v for k, v in full.items() if k != "_raw"}, base + ".json")
        hp = write_html(full, base + ".html", env.get("_raw") if env else None)
    except Exception as exc:  # noqa: BLE001
        emit({"ev": "error", "fatal": False, "msg": f"Nie udało się zapisać raportu: {exc}"})
    summary = {
        "mode": mode, "level": level, "title": title, "started": started,
        "finished": time.strftime("%Y-%m-%d %H:%M:%S"), "seconds": round(time.time() - t0, 1),
        "cancelled": bool(report.get("cancelled")), "verdict": verdict,
        "files": report.get("files", 0), "bytes": report.get("bytes", 0), "objects": report.get("objects", 0),
        "patterns_total": report.get("patterns_total", 0), "counts": counts, "results": results,
        "skipped": report.get("skipped_count", 0), "cloud_only": report.get("cloud_only", 0),
        "cloud_fetch": report.get("cloud_fetch"),
        "errors": (report.get("errors") or [])[:50],
        "report_html": hp, "report_json": jp, "sandbox": sandbox, "repo": repo,
        "environment": {k: v for k, v in env.items() if not k.startswith("_")} if env else None,
        "network": network, **(extra or {}),
    }
    try:
        with open(os.path.join(config.REPORTS, INDEX), "a") as fh:
            fh.write(json.dumps({"id": f"gui-{stamp}", "mode": mode, "level": level, "title": title,
                                 "verdict": verdict, "started": started, "files": summary["files"],
                                 "report_html": hp, "report_json": jp}, ensure_ascii=False) + "\n")
    except OSError:
        pass
    emit({"ev": "done", "summary": summary})


# ------------------------------------------------------------------ commands

def cmd_info(_a) -> int:
    out = {"ev": "info", "missing": []}
    try:
        with open(os.path.join(config.CLAMAV_COMPILED, "meta.json")) as fh:
            m = json.load(fh)
        out["clamav_signatures"] = m.get("signatures", 0)
        out["db_built"] = m.get("built")
    except (OSError, ValueError):
        out["missing"].append("clamav")
    try:
        with open(config.YARA_META) as fh:
            y = json.load(fh)
        out["yara_rules"] = y.get("rules") if isinstance(y.get("rules"), int) else len(y.get("rules") or [])
    except (OSError, ValueError):
        out["missing"].append("yara")
    for key, db, table in (("file_hashes", config.HASHDB, "file"), ("section_hashes", config.HASHDB, "section"),
                           ("ioc_indicators", config.IOCDB, "ioc")):
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            out[key] = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            con.close()
        except sqlite3.Error:
            out[key] = 0
            if key != "section_hashes":
                out["missing"].append(key)
    out["patterns_total"] = sum(out.get(k) or 0 for k in ("clamav_signatures", "yara_rules", "file_hashes",
                                                           "section_hashes", "ioc_indicators"))
    try:
        from .llm import find_default_model
        mp = find_default_model()
        out["ai_model"] = os.path.basename(mp) if mp else None
    except Exception:  # noqa: BLE001
        out["ai_model"] = None
    try:
        from .ai_install import FILE, PART, SIZE, llama_server
        out["ai_installable"] = True
        out["ai_model_size"] = SIZE
        out["ai_download_partial"] = os.path.getsize(PART) if os.path.exists(PART) else 0
        out["ai_model_recommended"] = FILE
        out["ai_upgrade_available"] = bool(out.get("ai_model")) and out["ai_model"] != FILE \
            and not os.environ.get("CERBER_LLM_MODEL")
        out["llama_server"] = bool(llama_server())
    except Exception:  # noqa: BLE001
        out["ai_installable"] = False
    emit(out)
    return 0


def cmd_scan(a) -> int:
    t0, started = time.time(), time.strftime("%Y-%m-%d %H:%M:%S")
    paths = [os.path.abspath(os.path.expanduser(p)) for p in a.args]
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        emit({"ev": "error", "fatal": True, "msg": f"Nie ma takiej ścieżki: {missing[0]}"})
        return 1
    cancel = Cancel()
    SCAN_ROOTS[:] = paths
    opts = make_opts("deep", a.ai)
    opts.defer_ai = a.ai
    report = run_file_scan(paths, opts, cancel)
    run_behavior_step(report, cancel)
    if not report.get("cancelled"):
        run_ai_step(report, opts)
    title = os.path.basename(paths[0].rstrip("/")) or paths[0] if len(paths) == 1 else f"{len(paths)} elementów"
    finish("scan", "deep", title, report, t0, started, results=[public_result(r) for r in report["results"]],
           sandbox=_isolation("scan", verified=report.get("sandbox_verified")))
    return 130 if report.get("cancelled") else 0


def _sandbox_flow(mode: str, title: str, input_path: str, work: str, a, t0: float, started: str,
                  repo: dict | None, cancel: "Cancel", extra: dict | None = None, unpack_top: bool = False,
                  net_verified: list[str] | None = None) -> int:
    from .sandbox import ISOLATION, run_sandboxed
    args = ["--level", "deep"] + (["--ai"] if a.ai else []) + (["--unpack-top"] if unpack_top else [])
    stage("sandbox", "Uruchamianie izolowanego sandboksa…")
    log("Izolacja: " + "; ".join(ISOLATION["strict"][:4]))
    report = run_sandboxed(work, input_path, args, _relay(True), cancel.event)
    if report is None:
        report = _empty_report(cancelled=cancel.set)
        sb = {"isolation": ISOLATION["strict"], "limits_hit": [], "extracted_files": 0, "extracted_bytes": 0,
              "depth": 0, "tree": []}
    else:
        sb = report.pop("sandbox", None) or {}
    if mode in ("github", "huggingface", "url"):
        sb["isolation"] = ISOLATION["net"] + [x for x in sb.get("isolation", []) if x not in ISOLATION["net"]]
        sb["verified"] = list(dict.fromkeys((net_verified or []) + (sb.get("verified") or [])))
    base = report.get("base")
    run_behavior_step(report, cancel, base, sandboxed=True)
    if a.ai and not report.get("cancelled"):
        run_ai_step(report, make_opts("deep", True))
    results = [public_result(r, base, sandboxed=True) for r in report.get("results", [])]
    for r in report.get("results", []):
        if base and r["path"].startswith(base):
            r["path"] = os.path.relpath(r["path"], base)
    finish(mode, "deep", title, report, t0, started, results=results, sandbox=sb, repo=repo, extra=extra)
    return 130 if report.get("cancelled") else 0


def cmd_sandbox(a) -> int:
    from .sandbox import new_workspace, remove_workspace
    t0, started = time.time(), time.strftime("%Y-%m-%d %H:%M:%S")
    path = os.path.realpath(os.path.expanduser(a.args[0]))
    if not os.path.isfile(path):
        emit({"ev": "error", "fatal": True, "msg": f"To nie jest plik: {path}"})
        return 1
    cancel = Cancel()
    work = new_workspace()
    try:
        return _sandbox_flow("sandbox", os.path.basename(path), path, work, a, t0, started, None, cancel)
    finally:
        remove_workspace(work)


def _fetch_in_sandbox(kind: str, url: str, work: str, cancel: "Cancel") -> dict | None:
    from .sandbox import run_inner
    stage("download", "Łączenie (pobieranie w sandboksie)…")
    data = run_inner(work, "net", ["inner-fetch", "--work", work, "--kind", kind, "--url", url], _relay(True),
                     cancel.event, out_name="fetch.json", wall=3 * 3600)
    if data is None:
        return None
    data["verified"] = _read_selfcheck(work, "net")
    if not data.get("ok"):
        if not data.get("cancelled"):
            emit({"ev": "error", "fatal": True, "msg": data.get("error") or "pobieranie nie powiodło się"})
        return None
    return data


def _remote(mode: str, a) -> int:
    from .sandbox import new_workspace, remove_workspace
    t0, started = time.time(), time.strftime("%Y-%m-%d %H:%M:%S")
    cancel = Cancel()
    work = new_workspace()
    try:
        data = _fetch_in_sandbox(mode, a.args[0], work, cancel)
        if data is None:
            if cancel.set:
                finish(mode, "deep", a.args[0], _empty_report(cancelled=True), t0, started, results=[])
                return 130
            return 1
        repo = data["info"]
        title = f"{repo['owner']}/{repo['name']}"
        return _sandbox_flow(mode, title, data["input"], work, a, t0, started, repo, cancel,
                             net_verified=data.get("verified"))
    finally:
        remove_workspace(work)


def cmd_github(a) -> int:
    return _remote("github", a)


def cmd_huggingface(a) -> int:
    return _remote("huggingface", a)


def cmd_url(a) -> int:
    from .sandbox import new_workspace, remove_workspace
    t0, started = time.time(), time.strftime("%Y-%m-%d %H:%M:%S")
    cancel = Cancel()
    work = new_workspace()
    try:
        data = _fetch_in_sandbox("url", a.args[0], work, cancel)
        if data is None:
            if cancel.set:
                finish("url", "deep", a.args[0], _empty_report(cancelled=True), t0, started, results=[])
                return 130
            return 1
        info = data["info"]
        title = info.get("domain") or a.args[0]
        return _sandbox_flow("url", title, data["input"], work, a, t0, started, None, cancel,
                             extra={"url": info}, unpack_top=True, net_verified=data.get("verified"))
    finally:
        remove_workspace(work)


def running_executables() -> list[str]:
    import subprocess
    try:
        out = subprocess.run(["/bin/ps", "-axo", "comm="], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    exes = set()
    for line in out.splitlines():
        p = line.strip()
        if p.startswith("/") and not p.startswith(APPLE_PREFIXES) and os.path.isfile(p):
            exes.add(os.path.realpath(p))
    return sorted(exes)


def _env_scan(level: str, cancel: "Cancel") -> tuple[dict | None, dict | None]:
    from .sandbox import new_workspace, remove_workspace, run_inner
    # Mega: the inner process switches to the "network" stage when the network audit modules start (they run last)
    stage("env", "Środowisko systemu (autostart, procesy, rozszerzenia, zabezpieczenia)…")
    if _sandbox_disabled():
        return _env_scan_direct(level)
    work = new_workspace()
    deep = None
    try:
        # launchd / kernel queries the sandbox must not reach: run them here with fixed arguments
        from .envscan.util import PRECOMPUTED_COMMANDS, precomputed_key
        from .envscan.util import run as env_run
        pre = os.path.join(work, "in", "precomputed")
        os.makedirs(pre, mode=0o700, exist_ok=True)
        if level == "mega":
            # /usr/bin/log refuses to run in any sandbox and keychains are denied there: system log history
            # (XProtect, Gatekeeper, logins…) and the public certificates are read here, in the background,
            # while the sandboxed scan runs; the sandboxed collectors wait for the files
            from .envscan.netaudit_deep import start_precompute
            deep = start_precompute(pre)
        for argv in PRECOMPUTED_COMMANDS:
            if os.path.exists(argv[0]):
                r = env_run(list(argv), timeout=60)
                with open(os.path.join(pre, precomputed_key(list(argv)) + ".json"), "w") as fh:
                    json.dump({"rc": r.rc, "out": r.out, "err": r.err, "timed_out": r.timed_out,
                               "missing": r.missing}, fh)
        os.environ["CERBER_PRECOMPUTED"] = pre
        data = run_inner(work, "env", ["inner-env", "--work", work, "--level", level], _relay(False), cancel.event,
                         out_name="env.json", wall=1800)
        os.environ.pop("CERBER_PRECOMPUTED", None)
        verified = _read_selfcheck(work, "env")
    finally:
        if deep is not None:
            deep.cancel()
        remove_workspace(work)
    if data is None:
        return None, None
    env = {"findings": data["findings"], "posture": data["posture"], "limitations": data["limitations"],
           "targets": len(data["targets"]), "_raw": data["raw"], "_targets": data["targets"], "_verified": verified}
    return env, data.get("network")


def _env_scan_direct(level: str) -> tuple[dict, dict | None]:
    from .cli import _env_to_dict
    from .envscan import scan_environment
    options: dict = {"deep": True} if level == "mega" else {"deep": True, "skip": _netaudit_collectors()}
    from .sandbox import NETWORK_STAGE_PL
    seen = set()

    def on_module(name: str) -> None:
        if name.startswith("netaudit") and not seen:
            seen.add(name)
            stage("network", NETWORK_STAGE_PL)

    rep = scan_environment(options, progress=lambda m: log(f"środowisko: {m}"), on_module=on_module)
    findings = [{"category": f.category, "title": f.title, "location": f.location, "severity": f.severity,
                 "score": f.detection.score, "description": f.detection.description,
                 "evidence": f.detection.evidence[:8]} for f in rep.findings]
    env = {"findings": findings, "posture": json.loads(json.dumps(rep.posture, default=str)),
           "limitations": list(rep.limitations), "targets": len(rep.targets), "_raw": _env_to_dict(rep),
           "_targets": list(rep.targets)}
    net = rep.inventory.get("network_audit") if level == "mega" else None
    return env, json.loads(json.dumps(net, default=str)) if net else None


def cmd_laptop(a) -> int:
    t0, started = time.time(), time.strftime("%Y-%m-%d %H:%M:%S")
    level = a.level
    cancel = Cancel()
    env = network = None
    if level in ("deep", "mega"):
        try:
            env, network = _env_scan(level, cancel)
        except Exception as exc:  # noqa: BLE001
            emit({"ev": "error", "fatal": False, "msg": f"Skan środowiska nie powiódł się: {exc!r}"})
        if cancel.set:
            finish("laptop", level, "Cały laptop", _empty_report(cancelled=True), t0, started, results=[],
                   env=env, network=network)
            return 130
    if level == "quick":
        paths = [os.path.normpath(os.path.expanduser(p)) for p in QUICK_LOCATIONS]
        procs = running_executables()
        log(f"Szybki skan: {len(paths)} typowych miejsc + {len(procs)} plików uruchomionych programów")
        paths += [p for p in procs if not any(p.startswith(q + "/") for q in paths)]
        title = "Najważniejsze miejsca"
    else:
        paths = list(LAPTOP_ROOTS)
        title = "Cały laptop"
    paths = [p for p in paths if os.path.exists(p)]
    if env:
        for t in env.pop("_targets", []):
            if not any(t == p or t.startswith(p.rstrip("/") + "/") for p in paths):
                paths.append(t)
    SCAN_ROOTS[:] = paths
    opts = make_opts(level, a.ai)
    root = config.ROOT.rstrip("/")
    # Cerber's own signature databases, rules, reports, quarantine and test samples contain malware patterns
    home = os.path.expanduser("~")
    opts.exclude = [root, root + "/*", config.HOME.rstrip("/") + "/*", home + "/Library/Keychains*",
                    "/Library/Keychains*"]
    live = None
    if level == "mega" and not cancel.set:
        live = LiveWatch()
        live.start()
        log("Monitor sieci i zachowania działa na żywo do końca skanu (co 5 s)")
    report = run_file_scan(paths, opts, cancel, live=live)
    if live is not None:
        _scan_live_leftovers(live, report, opts, cancel)
    fetched = run_cloud_step(report, opts, cancel) if level == "mega" else []
    if level in ("deep", "mega"):
        run_behavior_step(report, cancel)
    if not report.get("cancelled") and opts.defer_ai:
        run_ai_step(report, opts)
    if fetched:                                 # after the behaviour step, which still reads the files
        cloud_give_back(report, fetched)
    if live is not None:
        env, network = _merge_live(live, env, network)
    if env is not None and not report.get("cancelled"):
        run_correlation(report, env, network)
    for r in report.get("results", []):
        r.pop("ai_context", None)
    kinds = ("scan", "env") if env is not None else ("scan",)
    verified = list(report.get("sandbox_verified") or [])
    for v in (env or {}).get("_verified", []):
        if v not in verified:
            verified.append(v)
    finish("laptop", level, f"{title} · {LEVEL_PL[level]}", report, t0, started,
           results=[public_result(r) for r in report["results"]], env=env, network=network,
           sandbox=_isolation(*kinds, verified=verified))
    return 130 if report.get("cancelled") else 0


def run_correlation(report: dict, env: dict, network: dict | None) -> None:
    """Deep / Mega: judge every program as a whole – process + connections/ports + autostart + its files
    (cerber/correlate.py). Adds "correlation" environment findings and marks the program's file so the results
    list offers quarantine."""
    from .correlate import correlate, escalate_results
    try:
        cor = correlate(env.get("_raw"), network, report.get("results") or [])
    except Exception as exc:  # noqa: BLE001 - a bug here must not lose the scan
        emit({"ev": "error", "fatal": False, "msg": f"Analiza powiązań nie powiodła się: {exc!r}"})
        return
    before = {r.get("path"): r.get("verdict") for r in report.get("results") or []}
    changed = escalate_results(report.setdefault("results", []), cor["escalate"])
    counts = report.setdefault("counts", {k: 0 for k in VERDICT_ORDER})
    for r in report["results"]:
        old, new = before.get(r.get("path"), "CLEAN"), r.get("verdict")
        if old != new:
            counts[old] = max(0, counts.get(old, 0) - 1)
            counts[new] = counts.get(new, 0) + 1
    env["findings"] = list(env.get("findings") or []) + cor["findings"]
    if isinstance(env.get("_raw"), dict):
        env["_raw"]["findings"] = list(env["_raw"].get("findings") or []) + cor["findings_raw"]
        env["_raw"]["cases"] = cor["cases"]
    env["cases"] = cor["cases"]
    bad = sum(1 for c in cor["cases"] if c["severity"] in ("suspicious", "malicious"))
    log(f"Powiązania proces–sieć–autostart–pliki: {len(cor['cases'])} programów z kilkoma sygnałami naraz"
        + (f", {bad} podejrzanych lub groźnych" if bad else "") + (f", {changed} plików oznaczonych" if changed else ""))


def run_cloud_step(report: dict, opts, cancel: "Cancel") -> list[str]:
    """Mega: programs, scripts, installers, archives and active documents kept only in iCloud Drive (or another
    cloud drive) are downloaded, scanned in the sandbox like everything else, and – once the scan is over – handed
    back to the cloud (cerber/cloudfetch.py). Photos, videos and plain documents stay in the cloud. → downloaded"""
    from . import cloudfetch
    from .scanner import merge_reports
    files = report.pop("cloud_candidates", None) or []
    dirs = report.pop("cloud_dirs", None) or []
    if cancel.set or report.get("cancelled") or not (files or dirs):
        return []
    stage("cloud", "Pliki tylko w chmurze: pobieranie programów, skryptów, instalatorów i archiwów do skanu…")

    def progress(done: int, total: int, current: str) -> None:
        emit({"ev": "progress", "stage": "cloud", "done": done, "total": total, "current": current})

    try:
        got = cloudfetch.fetch(files, dirs, cancel.event, progress, log,
                               max_file=min(opts.max_file_size, cloudfetch.FETCH_MAX_FILE))
    except Exception as exc:  # noqa: BLE001 - the cloud is a bonus, never a reason to fail the scan
        log(f"Pobieranie plików z chmury nie powiodło się: {exc!r}")
        return []
    info = got["stats"]
    paths = got["fetched"] + got["local"]
    if paths and not cancel.set:
        log(f"Skanowanie {len(paths)} plików z chmury…")
        SCAN_ROOTS.extend(p for p in paths if p not in SCAN_ROOTS)
        sub = run_file_scan(paths, opts, cancel, quiet=True)
        sub.pop("cloud_candidates", None)
        sub.pop("cloud_dirs", None)
        if sub.get("cancelled"):
            report["cancelled"] = True
        merge_reports(report, sub)
        info["scanned"] = sub.get("files", 0)
    report["cloud_only"] = max(0, (report.get("cloud_only") or 0) - info["fetched"])
    report["cloud_fetch"] = info
    return got["fetched"]


def cloud_give_back(report: dict, fetched: list[str]) -> None:
    """Downloaded cloud files go back to the cloud – except flagged ones, left on disk for the user to act on."""
    from .cloudfetch import evict
    flagged = {r["path"] for r in report.get("results", []) if r.get("verdict") != "CLEAN"}
    report["cloud_fetch"]["kept"] = len([p for p in fetched if p in flagged])
    report["cloud_fetch"]["evicted"] = evict([p for p in fetched if p not in flagged], log)


def _scan_live_leftovers(live: LiveWatch, report: dict, opts, cancel: "Cancel") -> None:
    """New files/programs from the live watch that the main scan did not pick up any more."""
    from .scanner import merge_reports
    if cancel.set or report.get("cancelled"):
        return
    paths = [p for p in live.pending() if os.path.exists(p)]
    if not paths:
        return
    log(f"Skanowanie {len(paths)} nowych plików i programów z ostatnich minut skanu…")
    SCAN_ROOTS.extend(p for p in paths if p not in SCAN_ROOTS)
    sub = run_file_scan(paths, opts, cancel, quiet=True)
    live.mark_scanned(paths)
    if sub.get("cancelled"):
        report["cancelled"] = True
    merge_reports(report, sub)


def _merge_live(live: LiveWatch, env: dict | None, network: dict | None) -> tuple[dict | None, dict | None]:
    mon = live.stop()
    if not mon:
        return env, network
    findings = mon.pop("findings", None) or []
    mon["targets_scanned"] = len(live.scanned)
    left = live.pending()
    if left:
        mon["limitations"] = list(mon.get("limitations") or []) + [
            f"{len(left)} nowych plików pojawiło się po zakończeniu skanowania i nie zostało sprawdzonych "
            f"(np. {left[0]}) – uruchom skan jeszcze raz albo przeskanuj je osobno"]
    network = dict(network or {})
    network["monitor"] = mon
    if findings:
        if env is None:
            env = {"findings": [], "posture": {}, "limitations": [], "targets": 0, "_raw": None}
        env["findings"] = list(env.get("findings") or []) + findings
    return env, network


def cmd_quarantine(a) -> int:
    from .quarantine import quarantine_file
    path = os.path.abspath(a.args[0])
    if not os.path.isfile(path):
        emit({"ev": "error", "fatal": True, "msg": f"To nie jest plik: {path}"})
        return 1
    try:
        qid = quarantine_file(path, {"verdict": "MALICIOUS"})
    except OSError as exc:
        emit({"ev": "error", "fatal": True, "msg": f"Nie można przenieść do kwarantanny: {exc.strerror or exc} "
                                                   "(plik może należeć do systemu/administratora)"})
        return 1
    emit({"ev": "quarantined", "path": path, "id": qid})
    return 0


def cmd_ai_install(_a) -> int:
    from .ai_install import FILE, LABEL, SIZE, InstallError, install, installed, llama_server
    cancel = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: cancel.set())
    signal.signal(signal.SIGTERM, lambda *_: cancel.set())
    if installed():
        emit({"ev": "ai_installed", "model": FILE, "path": installed(), "llama_server": llama_server()})
        return 0
    stage("download", f"Pobieranie modelu AI ({LABEL}, {SIZE / 1e9:.1f} GB)…")
    try:
        path = install(emit, cancel)
    except InstallError as exc:
        emit({"ev": "error", "fatal": True, "msg": f"Instalacja modelu AI: {exc}"})
        return 130 if cancel.is_set() else 1
    server = llama_server()
    if not server:
        emit({"ev": "error", "fatal": False, "msg": "Model pobrany, ale brakuje silnika llama-server – "
                                                    "zainstaluj go: brew install llama.cpp"})
    emit({"ev": "ai_installed", "model": FILE, "path": path, "llama_server": server})
    return 0


def cmd_history(_a) -> int:
    items = []
    try:
        with open(os.path.join(config.REPORTS, INDEX)) as fh:
            for line in fh:
                try:
                    it = json.loads(line)
                except ValueError:
                    continue
                if it.get("report_json") and os.path.exists(it["report_json"]):
                    items.append(it)
    except OSError:
        pass
    emit({"ev": "history", "items": list(reversed(items))[:300]})
    return 0


COMMANDS = {"info": cmd_info, "scan": cmd_scan, "sandbox": cmd_sandbox, "github": cmd_github,
            "huggingface": cmd_huggingface, "laptop": cmd_laptop, "quarantine": cmd_quarantine,
            "history": cmd_history, "ai-install": cmd_ai_install, "url": cmd_url}


def cmd_iphone(a) -> int:
    """iPhone over the cable / a local backup (cerber/iphone.py): devices | scan [UDID] [--make-backup] | backup PATH."""
    from .iphone import gui_command
    return gui_command(a, emit)


COMMANDS["iphone"] = cmd_iphone


def main(argv: list[str] | None = None) -> int:
    global emit
    ap = argparse.ArgumentParser(prog="cerber.gui_backend")
    ap.add_argument("command", choices=sorted(COMMANDS))
    ap.add_argument("args", nargs="*")
    ap.add_argument("--level", default="deep", choices=["quick", "patterns", "deep", "mega"])
    ap.add_argument("--ai", action="store_true")
    ap.add_argument("--make-backup", action="store_true", help="iphone scan: create a fresh backup first")
    a = ap.parse_args(argv)
    # the app cancels with SIGINT; a parent may have started us with SIGINT ignored (Python keeps that)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    emit = Emitter()
    config.ensure_dirs()
    if a.command in ("scan", "sandbox", "github", "huggingface", "url", "laptop"):
        from .sandbox import cleanup_stale
        cleanup_stale()
        # never download iCloud/File Provider placeholders while scanning (inherited by every child process)
        from .dataless import never_materialize
        never_materialize()
    if a.command in ("scan", "sandbox", "github", "huggingface", "url", "quarantine") and not a.args:
        emit({"ev": "error", "fatal": True, "msg": "Brak argumentu (ścieżki lub adresu)"})
        return 1
    try:
        rc = COMMANDS[a.command](a)
    except KeyboardInterrupt:
        emit({"ev": "error", "fatal": True, "msg": "Przerwano"})
        rc = 130
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc()
        emit({"ev": "error", "fatal": True, "msg": f"Błąd wewnętrzny: {exc!r}"})
        rc = 1
    sys.stderr.flush()
    os._exit(rc)        # skip tearing down gigabytes of signature objects


if __name__ == "__main__":
    main()

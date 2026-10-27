"""Correlation: a program is judged as a whole – its process(es), connections and open ports, what starts it, and
the files of its package – instead of every piece on its own.

One weak hint (an ad-hoc signature, an odd folder, a connection on port 8443, a LaunchAgent, a YARA "INFO") is
normal on a real Mac and must not raise an alarm. Several independent hints about the same program are not:
an unsigned helper in a random ~/Library folder that a LaunchAgent keeps alive and that talks to a public IP on
an unusual port is a backdoor even if no signature knows it. Likewise files that are harmless one by one can be
dangerous together (a plist + a script + a binary of one "package").

Dimensions per program (0–100 each): file (scan results of the program and its package), origin (signature,
download, location, name), process (command line, parent chain, injection), network (IOC, unusual ports,
listening, beaconing, uploads), persistence (LaunchAgents/Daemons, helpers, login items).
total = strongest dimension + half of the other dimensions that say something (≥ 10), capped at 100.
Trusted origin (Apple / App Store / Developer ID) divides everything except IOC hits and file detections by 4:
Chrome on port 5228 or Steam listening for LAN games is not news. Severity: malicious needs ≥ 80 with at least
two independent dimensions (or an IOC / malicious file); suspicious ≥ 35; low ≥ 15.

Input is Cerber's own JSON (env scan inventory + findings, network audit, live monitor, file results);
pure data processing, runs in the backend after the file scan.
"""
from __future__ import annotations

import os
import re
from collections import defaultdict

from .envscan.patterns import classify_path, is_apple_path
from .envscan.provenance import TRUSTED, bundle_of, name_signals, origin_signals

DIMS = ("file", "origin", "process", "network", "persistence")
DIM_PL = {"file": "pliki", "origin": "pochodzenie", "process": "proces", "network": "sieć", "persistence": "autostart"}
VERDICT_SCORE = {"MALICIOUS": 85, "PUA": 40, "SUSPICIOUS": 40, "INFO": 8, "CLEAN": 0}
GENERIC_DIRS = re.compile(r"^(?:/Users/[^/]+/(?:Downloads|Desktop|Documents)|/Applications|/usr/local/bin|"
                          r"/opt/homebrew/bin|/private/tmp|/tmp|/Users/Shared|/Library/LaunchAgents|"
                          r"/Library/LaunchDaemons|/Users/[^/]+/Library/LaunchAgents|/Library/PrivilegedHelperTools)$")
_EV_RX = re.compile(r"^(\S+) \[\+(-?\d+)\]")
_ORIGIN_SIG = re.compile(r"\.(?:Name\.|DownloadedUnsigned|FromMessenger|Fresh|BrokenSignature|DeletedWhileRunning)")
BACKDOOR_HINT = {4444, 4445, 1337, 31337, 6666, 6667, 6697, 5555, 9001, 9050, 1080, 3333, 14444, 45700}
MAX_CASES = 60


def _unit_key(path: str) -> str:
    return bundle_of(path) or path


def _package_dir(path: str) -> str | None:
    """Folder that forms one package with a loose program (e.g. ~/Library/Application Support/Foo/)."""
    d = os.path.dirname(path)
    if not d or GENERIC_DIRS.match(d) or is_apple_path(d + "/") or classify_path(d + "/x").has("pkgmgr"):
        return None
    if d.count("/") < 4:                                  # /Users/x/foo is too broad
        return None
    return d


def _signal_parts(f: dict) -> list[tuple[str, int]]:
    """(signal name, score) pairs of a raw env finding (detection.evidence lines "name [+n]: …")."""
    det = f.get("detection") or {}
    out = []
    for line in det.get("evidence") or []:
        m = _EV_RX.match(str(line))
        if m:
            out.append((m.group(1), int(m.group(2))))
    if not out and det.get("score"):
        out.append((det.get("name") or "?", int(det["score"])))
    return out


class Unit:
    def __init__(self, key: str):
        self.key = key
        self.exe: str | None = None
        self.name = os.path.basename(key)
        self.pids: list[int] = []
        self.origin: dict | None = None
        self.dims: dict[str, float] = defaultdict(float)
        self.reasons: dict[str, list[str]] = defaultdict(list)
        self.files: dict[str, dict] = {}
        self.connections: list[str] = []
        self.listening: list[str] = []
        self.persistence: list[str] = []
        self.ioc = False

    def add(self, dim: str, score: float, reason: str, combine: str = "max") -> None:
        if score <= 0:
            return
        if combine == "sum":
            self.dims[dim] = min(100.0, self.dims[dim] + score)
        else:
            self.dims[dim] = max(self.dims[dim], score)
        if reason and reason not in self.reasons[dim] and len(self.reasons[dim]) < 6:
            self.reasons[dim].append(reason)

    @property
    def trust(self) -> str:
        return (self.origin or {}).get("trust") or "unknown"

    def judged(self) -> dict:
        factor = 0.25 if self.trust in TRUSTED else 0.5 if self.trust in ("pkgmgr", "local_build") else 1.0
        dims = {}
        for d in DIMS:
            v = self.dims.get(d, 0.0)
            if d != "file" and not (d == "network" and self.ioc):
                v *= factor
            dims[d] = round(v)
        ranked = sorted(dims.values(), reverse=True)
        total = min(100, ranked[0] + 0.5 * sum(v for v in ranked[1:] if v >= 10))
        strong = [d for d, v in dims.items() if v >= 15]
        if (total >= 80 and len(strong) >= 2) or dims["file"] >= 80 or (self.ioc and dims["network"] >= 60):
            sev = "malicious"
        elif total >= 35:
            sev = "suspicious"
        elif total >= 15:
            sev = "low"
        else:
            sev = "info"
        return {"score": round(total), "severity": sev, "dims": dims, "strong": strong}


def correlate(env_raw: dict | None, network: dict | None, results: list[dict], home: str | None = None) -> dict:
    """→ {"cases": [...], "findings_raw": [...], "findings": [...], "escalate": [{path, score, verdict, why}]}"""
    home = home or os.path.expanduser("~")
    inv = (env_raw or {}).get("inventory") or {}
    units: dict[str, Unit] = {}

    def unit_for(path: str | None, create: bool = True) -> Unit | None:
        if not path or not path.startswith("/") or is_apple_path(path):
            return None
        key = _unit_key(path)
        u = units.get(key)
        if u is None and create:
            u = units[key] = Unit(key)
        if u is not None and u.exe is None and not path.endswith(".plist"):
            u.exe = path
        return u

    # ---- processes + their origin (inventory) and process findings
    for e in inv.get("processes") or []:
        exe = e.get("exe")
        if not exe or not e.get("origin"):
            continue
        u = unit_for(exe)
        if u is None:
            continue
        u.exe, u.origin = exe, e["origin"]
        u.name = e.get("name") or u.name
        u.pids += [p for p in e.get("pids") or [] if p not in u.pids][:20]
        o = e["origin"]
        trusted = o.get("trust") in TRUSTED
        for s in origin_signals(o, "Corr", "program"):
            u.add("origin", s.score, s.description, "sum")
        for nm in {e.get("name") or "", os.path.basename(exe), os.path.basename(o.get("bundle") or "")} - {""}:
            for s in name_signals(nm, "Corr", "nazwa", trusted=trusted, untrusted=o.get("trust") == "untrusted"):
                u.add("origin", s.score, s.description, "sum")
        if o.get("trust") == "untrusted" and not o.get("download"):
            u.add("origin", 10, f"pochodzenie: {o.get('label') or 'nieznane'}")
    pid_unit: dict[int, Unit] = {p: u for u in units.values() for p in u.pids}
    for f in (env_raw or {}).get("findings") or []:
        cat, det = f.get("category"), (f.get("details") or {})
        exe = det.get("exe") or (f.get("location") if str(f.get("location", "")).startswith("/") else None)
        pid = det.get("pid")
        u = (unit_for(exe, create=False) if exe else None) or (pid_unit.get(pid) if pid else None)
        if cat == "process":
            if u is None and exe:
                u = unit_for(exe)
            if u is None:
                continue
            score = sum(sc for name, sc in _signal_parts(f) if not _ORIGIN_SIG.search(name) and sc > 0)
            u.add("process", score, f.get("title") or "")
        elif cat in ("network", "network_live", "netaudit", "remote", "traffic") and u is not None:
            score = (f.get("detection") or {}).get("score") or 0
            if any("Ioc" in n for n, _ in _signal_parts(f)):
                u.ioc = True
            u.add("network", score, f.get("title") or "")
        elif cat in ("launchd", "login_items", "persistence", "plugins", "cron") and exe:
            u = u or unit_for(exe)
            if u is not None:
                u.add("persistence", (f.get("detection") or {}).get("score") or 0, f.get("title") or "")

    # ---- persistence inventory: what starts which program
    for it in (inv.get("launchd") or []):
        prog = it.get("program")
        u = unit_for(prog) if prog and not is_apple_path(prog) else None
        if u is None:
            continue
        keep = it.get("run_at_load") or it.get("keep_alive")
        desc = f"uruchamiany automatycznie przez {os.path.basename(it.get('plist') or '?')}" + (
            " przy każdym logowaniu" if keep else "")
        u.persistence.append(it.get("plist") or "")
        u.add("persistence", 15 if keep else 8, desc)
        u.files.setdefault(it.get("plist") or "", {"path": it.get("plist"), "verdict": "INFO", "score": 0,
                                                   "role": "autostart"})
    for it in inv.get("privileged_helpers") or []:
        u = unit_for(it.get("path"), create=False)
        if u is not None:
            u.add("persistence", 12, "zainstalowany jako narzędzie uprzywilejowane (działa jako root)")

    # ---- network
    net = network or {}
    for c in net.get("connections") or []:
        u = unit_for(c.get("exe"), create=False)
        if u is None:
            continue
        ep = f"{c.get('remote')}:{c.get('port')}"
        if len(u.connections) < 12:
            u.connections.append(ep + (f" ({c['host']})" if c.get("host") else ""))
        if c.get("ioc"):
            u.ioc = True
            u.add("network", 85, f"połączenie z adresem z listy zagrożeń: {ep}")
        elif c.get("public"):
            port = c.get("port") or 0
            if port in BACKDOOR_HINT:
                u.add("network", 35, f"połączenie na porcie typowym dla backdoorów/koparek: {ep}")
            elif port not in (80, 443, 53, 853, 993, 995, 465, 587, 22, 5223, 5228) and port < 49152:
                u.add("network", 15, f"połączenie z Internetem na nietypowym porcie: {ep}")
            else:
                u.add("network", 3, "")
    for l in net.get("listening") or []:
        u = unit_for(l.get("exe"), create=False)
        if u is None or l.get("exposure") == "localhost":
            continue
        u.listening.append(f"{l.get('port')}" + (f" ({l['service']})" if l.get("service") else ""))
        port = l.get("port") or 0
        u.add("network", 30 if port in BACKDOOR_HINT else 12,
              f"przyjmuje połączenia z sieci na porcie {port}")
    for t in net.get("traffic") or []:
        u = unit_for(t.get("exe"), create=False)
        if u is not None and (t.get("bytes_out") or 0) >= 50 << 20 and (t.get("bytes_out") or 0) > (t.get("bytes_in") or 0):
            u.add("network", 25, f"wysłał {round(t['bytes_out'] / (1 << 20))} MB (więcej niż pobrał)")
    for ev in ((net.get("monitor") or {}).get("events") or []):
        u = unit_for(ev.get("exe"), create=False)
        if u is not None and ev.get("severity") not in ("info", None):
            if "zagrożeń" in (ev.get("title") or ""):
                u.ioc = True
            dim = "persistence" if ev.get("kind") == "autostart" else "process" if ev.get("kind") == "process" \
                else "network"
            u.add(dim, ev.get("score") or 0, ev.get("title") or "")

    # ---- files: the program, its bundle and its package folder
    pkg_units: dict[str, Unit] = {}
    for u in units.values():
        if u.exe and not u.key.endswith(".app"):
            d = _package_dir(u.exe)
            if d:
                pkg_units.setdefault(d, u)
    file_groups: dict[str, list[dict]] = defaultdict(list)
    for r in results or []:
        path = r.get("path") or ""
        if not path.startswith("/"):
            continue
        u = units.get(_unit_key(path)) or pkg_units.get(os.path.dirname(path))
        if u is None:
            for key, uu in units.items():
                if path in uu.files:
                    u = uu
                    break
        if u is None:
            # files without a running program: group by bundle / package folder ("razem groźne")
            g = bundle_of(path) or _package_dir(path)
            if g:
                file_groups[g].append(r)
            continue
        u.files[path] = {"path": path, "verdict": r.get("verdict"), "score": r.get("score", 0),
                         "primary": r.get("primary")}
    for u in units.values():
        _file_dim(u)
    for g, rs in file_groups.items():
        if len(rs) < 2:
            continue
        u = units.setdefault(g, Unit(g))
        for r in rs:
            u.files[r["path"]] = {"path": r["path"], "verdict": r.get("verdict"), "score": r.get("score", 0),
                                  "primary": r.get("primary")}
        _file_dim(u)
        u.exe = u.exe or rs[0]["path"]

    # ---- judge
    cases, findings_raw, findings, escalate = [], [], [], []
    for u in units.values():
        j = u.judged()
        if j["severity"] == "info" or (len(j["strong"]) < 2 and not _package_effect(u) and not u.ioc):
            continue
        if u.trust in TRUSTED and not u.ioc and j["dims"]["file"] < 80:
            continue
        title = _title(u, j)
        why = [f"{DIM_PL[d]}: {r}" for d in DIMS for r in u.reasons.get(d, []) if j["dims"][d] >= 3][:14]
        case = {"key": u.key, "exe": u.exe, "name": u.name, "severity": j["severity"], "score": j["score"],
                "dims": j["dims"], "trust": u.trust, "origin": (u.origin or {}).get("label"),
                "pids": u.pids[:10], "connections": u.connections[:12], "listening": u.listening[:8],
                "persistence": u.persistence[:6], "files": list(u.files.values())[:30], "reasons": why}
        cases.append(case)
        desc = ("kilka niezależnych sygnałów dotyczy tego samego programu: "
                + ", ".join(f"{DIM_PL[d]} {j['dims'][d]}" for d in DIMS if j["dims"][d] >= 10))
        conf = "HIGH" if j["severity"] == "malicious" else "MEDIUM"
        findings_raw.append({"category": "correlation", "title": title, "location": u.key, "severity": j["severity"],
                             "detection": {"name": "Heur:Corr.Program", "engine": "correlation", "confidence": conf,
                                           "score": j["score"], "description": desc, "evidence": why, "pua": False},
                             "details": case})
        findings.append({"category": "correlation", "title": title, "location": u.key, "severity": j["severity"],
                         "score": j["score"], "description": desc, "evidence": why[:8]})
        if j["severity"] in ("suspicious", "malicious") and u.exe and os.path.isfile(u.exe) and u.trust not in TRUSTED:
            escalate.append({"path": u.exe, "score": j["score"],
                             "verdict": "MALICIOUS" if j["severity"] == "malicious" else "SUSPICIOUS",
                             "why": desc, "reasons": why})
    order = {"malicious": 0, "suspicious": 1, "low": 2}
    idx = sorted(range(len(cases)), key=lambda i: (order[cases[i]["severity"]], -cases[i]["score"]))[:MAX_CASES]
    return {"cases": [cases[i] for i in idx], "findings_raw": [findings_raw[i] for i in idx],
            "findings": [findings[i] for i in idx], "escalate": escalate}


def _file_dim(u: Unit) -> None:
    flagged = [f for f in u.files.values() if f.get("verdict") not in (None, "CLEAN")]
    if not flagged:
        return
    best = max(flagged, key=lambda f: (VERDICT_SCORE.get(f["verdict"], 0), f.get("score") or 0))
    base = max(VERDICT_SCORE.get(best["verdict"], 0), min(80, best.get("score") or 0) if best["verdict"] != "INFO"
               else min(12, best.get("score") or 0))
    u.add("file", base, f"{os.path.basename(best['path'])}: {best.get('primary') or best['verdict']}")
    # several weak files of one package add up ("each harmless, together not")
    weak = [f for f in flagged if f is not best]
    if weak:
        extra = min(30, sum(min(15, (f.get("score") or 0) * 0.5) for f in weak))
        u.add("file", min(90, u.dims["file"] + extra), f"{len(flagged)} oznaczonych plików w jednym pakiecie")


def _package_effect(u: Unit) -> bool:
    flagged = [f for f in u.files.values() if f.get("verdict") not in (None, "CLEAN")]
    return len(flagged) >= 2 and u.dims.get("file", 0) >= 35


def _title(u: Unit, j: dict) -> str:
    what = {"malicious": "Groźny program", "suspicious": "Podejrzany program", "low": "Do sprawdzenia"}[j["severity"]]
    parts = [DIM_PL[d] for d in DIMS if j["dims"][d] >= 10]
    return f"{what}: {u.name} ({' + '.join(parts)})"


def escalate_results(results: list[dict], escalate: list[dict]) -> int:
    """Correlated programs get a detection on their file result (created if the file scan found nothing), so the
    results list shows them and offers "Do kwarantanny". Returns how many results changed."""
    by_path = {r.get("path"): r for r in results}
    order = ["CLEAN", "INFO", "SUSPICIOUS", "PUA", "MALICIOUS"]
    n = 0
    for e in escalate:
        det = {"name": "Heur:Corr.Program", "engine": "correlation",
               "confidence": "HIGH" if e["verdict"] == "MALICIOUS" else "MEDIUM", "score": e["score"],
               "description": e["why"], "evidence": e["reasons"][:8], "object": e["path"], "pua": False}
        r = by_path.get(e["path"])
        if r is None:
            try:
                size = os.path.getsize(e["path"])
            except OSError:
                continue
            r = {"path": e["path"], "verdict": "CLEAN", "score": 0, "primary": None, "size": size, "ftype": None,
                 "sha256": None, "detections": [], "errors": [], "meta": {}}
            results.append(r)
            by_path[e["path"]] = r
        if any(d.get("name") == "Heur:Corr.Program" for d in r.get("detections") or []):
            continue
        r.setdefault("detections", []).append(det)
        r["score"] = (r.get("score") or 0) + e["score"]
        if order.index(e["verdict"]) > order.index(r.get("verdict") or "CLEAN"):
            r["verdict"] = e["verdict"]
            r["primary"] = det["name"]
        n += 1
    return n

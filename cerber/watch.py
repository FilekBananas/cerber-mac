"""Background protection: watch the places installed software lands in and scan every new item.

macOS gives ordinary programs no "before install" hook (Endpoint Security needs an Apple-granted
entitlement), so Cerber watches the install locations instead:

  ~/Downloads, ~/Desktop            new downloads (partial .crdownload/.download/.part files are ignored)
  /Applications, ~/Applications     new or replaced apps (drag-and-drop, App Store, Sparkle updates)
  LaunchAgents/Daemons, helpers     new autostart items (plus the programs they point to)
  /var/db/receipts                  finished .pkg installs (every installed executable is scanned)
  /opt/homebrew/bin, /usr/local/bin new command line tools (brew, npm -g …)
  browser Extensions folders        new browser extensions

Directory changes come from kqueue (stdlib, no extra dependencies), with a periodic re-diff as a
safety net. An item is scanned once it stops changing. The watcher itself is small; the scan
engines (~2.6 GB, ~15 s to load) live in a worker process that starts on the first job and exits
after IDLE seconds without work, so memory is only used while there is something to scan.

Opt-in (--net): network & remote-access guard (NetGuard below). envscan.netwatch in guard mode runs in
the `env` sandbox and checks every 10 s who connects where, open ports, inbound connections, remote
logins, remote-control tools and tunnels, new privacy permissions (screen recording, accessibility …);
every 5 min this process reads the unified log (/usr/bin/log refuses to run in a sandbox) and hands it
to the sandboxed watch: SSH / screen-sharing logins, password guessing, admin rights, XProtect. Nothing
is sent anywhere; a daily report goes to reports/siec-YYYYMMDD.html.
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import os
import plistlib
import queue
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field

from . import config

LABEL = "pl.cerber.watch"
PLIST_PATH = os.path.expanduser(f"~/Library/LaunchAgents/{LABEL}.plist")
LOG_DIR = os.environ.get("CERBER_LOG_DIR") or os.path.expanduser("~/Library/Logs/Cerber")
LOG_PATH = os.path.join(LOG_DIR, "watch.log")

TICK = 1.0
STABLE_FILE = 4.0          # seconds without change before a file is scanned
STABLE_DIR = 8.0           # bundles are copied file by file – wait a bit longer
REOPEN_SECS = 60           # retry folders that are missing or not yet allowed (TCC)
RESCAN_SECS = 300          # full re-diff in case an event was missed
IDLE_SECS = 600            # worker exits after this long without work
ANNOUNCE_AFTER = 3.0       # "checking …" notification only for scans slower than this
MAX_PKG_FILES = 5000
MAX_WALK = 50000

PARTIAL_SUFFIXES = (".download", ".crdownload", ".part", ".partial", ".opdownload", ".tmp", ".temp", ".aria2",
                    ".!qb", ".!ut", ".sb-", ".swp")
IGNORE_NAMES = {".DS_Store", ".localized", "Icon\r", ".com.apple.timemachine.supported", ".Trashes"}
INSTALLER_EXT = (".dmg", ".pkg", ".mpkg", ".app", ".zip", ".command", ".tool", ".sh", ".jar", ".tgz", ".tar.gz",
                 ".7z", ".rar", ".iso", ".xip", ".scpt", ".applescript", ".terminal", ".webloc", ".py", ".js")
PKG_SCRIPT_EXT = (".dylib", ".so", ".sh", ".py", ".pl", ".rb", ".js", ".command", ".scpt", ".jar", ".kext")
ALWAYS_REPORT = {"app", "persistence", "receipt", "extension"}   # say "clean" too, not only problems
KIND_PL = {"download": "pobrane", "app": "aplikacja", "persistence": "autostart", "receipt": "instalacja .pkg",
           "binary": "narzędzie CLI", "extension": "rozszerzenie przeglądarki", "network": "sieć"}
VERDICT_PL = {"MALICIOUS": "ZŁOŚLIWY", "PUA": "NIECHCIANY (PUA)", "SUSPICIOUS": "PODEJRZANY", "INFO": "INFO",
              "CLEAN": "CZYSTY"}


# ------------------------------------------------------------------ logging / notifications

def _log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, file=sys.stderr, flush=True)
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 5 << 20:
            os.replace(LOG_PATH, LOG_PATH + ".1")
        with open(LOG_PATH, "a") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def _as(s: str) -> str:
    """AppleScript string literal."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


_APP_OUT = None          # set in --app mode: JSON events for Cerber.app on stdout


def app_event(obj: dict) -> None:
    if _APP_OUT is not None:
        try:
            _APP_OUT.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
            _APP_OUT.flush()
        except (OSError, ValueError):
            pass


class Notifier:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def notify(self, title: str, msg: str, subtitle: str = "", sound: str | None = None) -> None:
        _log(f"[powiadomienie] {title} · {subtitle} · {msg}")
        if _APP_OUT is not None:
            app_event({"ev": "watch_notice", "title": title, "subtitle": subtitle, "msg": msg,
                       "level": "error" if sound == "Basso" else "warning" if sound else "info"})
            return
        if not self.enabled:
            return
        # file and process names reach these texts: they are passed as `argv` items, never spliced into the
        # AppleScript source (no quoting to get wrong, no `" & do shell script "…` possible)
        line = "display notification (item 1 of argv) with title (item 2 of argv)"
        args = [msg[:230], title[:120]]
        if subtitle:
            line += " subtitle (item 3 of argv)"
            args.append(subtitle[:120])
        if sound:
            line += f" sound name (item {len(args) + 1} of argv)"
            args.append(sound[:40])
        try:
            subprocess.Popen(self._osascript(line, args), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"})
        except (OSError, ValueError):
            pass

    @staticmethod
    def _osascript(line: str, args: list[str]) -> list[str]:
        clean = [str(a).replace("\x00", "") for a in args]
        return ["/usr/bin/osascript", "-e", "on run argv", "-e", line, "-e", "end run", "--", *clean]

    def alert(self, title: str, msg: str, report: str | None) -> None:
        """Modal alert for confirmed malware; 'Pokaż raport' opens the HTML report."""
        if _APP_OUT is not None:
            app_event({"ev": "watch_alert", "title": title, "msg": msg, "report": report})
            return
        if not self.enabled:
            return

        def run() -> None:
            ok = report if (isinstance(report, str) and report.startswith("/") and report.endswith(".html")
                            and os.path.isfile(report)) else None
            buttons = '{"OK", "Pokaż raport"}' if ok else '{"OK"}'
            line = (f"display alert (item 1 of argv) message (item 2 of argv) as critical buttons {buttons} "
                    f"default button \"OK\" giving up after 900")
            try:
                r = subprocess.run(self._osascript(line, [title[:200], msg[:900]]), capture_output=True, text=True,
                                   timeout=1000, stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"})
                if ok and "Pokaż raport" in r.stdout:
                    subprocess.run(["/usr/bin/open", ok], timeout=30, stdin=subprocess.DEVNULL)
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
        threading.Thread(target=run, daemon=True).start()


# ------------------------------------------------------------------ watched places

@dataclass
class Spot:
    kind: str
    path: str
    fd: int = -1
    snap: dict = field(default_factory=dict)      # name -> (inode, mode)
    error: str = ""


def browser_extension_dirs() -> list[str]:
    base = os.path.expanduser("~/Library/Application Support")
    out = []
    for vendor in ("Google/Chrome", "Google/Chrome Beta", "BraveSoftware/Brave-Browser", "Microsoft Edge", "Chromium",
                   "Vivaldi", "Arc/User Data", "Opera Software/Opera Stable"):
        for prof in glob.glob(os.path.join(base, vendor, "*", "Extensions")):
            out.append(prof)
        if os.path.isdir(os.path.join(base, vendor, "Extensions")):
            out.append(os.path.join(base, vendor, "Extensions"))
    out += glob.glob(os.path.join(base, "Firefox", "Profiles", "*", "extensions"))
    return sorted(set(out))


def default_spots() -> list[tuple[str, str]]:
    h = os.path.expanduser
    spots = [("download", h("~/Downloads")), ("download", h("~/Desktop")),
             ("app", "/Applications"), ("app", h("~/Applications")),
             ("persistence", h("~/Library/LaunchAgents")), ("persistence", "/Library/LaunchAgents"),
             ("persistence", "/Library/LaunchDaemons"), ("persistence", "/Library/PrivilegedHelperTools"),
             ("receipt", "/var/db/receipts"),
             ("binary", "/opt/homebrew/bin"), ("binary", "/usr/local/bin")]
    spots += [("extension", p) for p in browser_extension_dirs()]
    return spots


def _listdir(path: str) -> dict:
    out = {}
    with os.scandir(path) as it:
        for e in it:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            out[e.name] = (st.st_ino, st.st_mode)
    return out


def _wanted(kind: str, name: str, mode: int) -> bool:
    if name in IGNORE_NAMES:
        return False
    low = name.lower()
    if kind == "download":
        if name.startswith((".", "~$")) or low.endswith(PARTIAL_SUFFIXES) or ".sb-" in low:
            return False
        return stat.S_ISREG(mode) or stat.S_ISDIR(mode)
    if kind == "receipt":
        return low.endswith(".plist") and not low.startswith("com.apple.")
    if kind == "binary":
        return stat.S_ISREG(mode) or stat.S_ISLNK(mode)
    if kind == "persistence" and name == f"{LABEL}.plist":
        return False
    return stat.S_ISREG(mode) or stat.S_ISDIR(mode)


def _signature(path: str) -> tuple | None:
    """Changes while the item is still being written/copied."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISDIR(st.st_mode):
        return (st.st_size, st.st_mtime_ns)
    n = size = 0
    newest = st.st_mtime_ns
    for root, dirs, files in os.walk(path):
        for f in files:
            try:
                s = os.lstat(os.path.join(root, f))
            except OSError:
                continue
            n += 1
            size += s.st_size
            newest = max(newest, s.st_mtime_ns)
        if n >= MAX_WALK:
            break
    return (n, size, newest)


# ------------------------------------------------------------------ jobs

@dataclass
class Pending:
    kind: str
    path: str
    first: float
    sig: tuple | None = None
    since: float = 0.0
    next_check: float = 0.0
    quiet: bool = False           # re-check of an item already reported
    note: str = ""


@dataclass
class Job:
    id: int
    kind: str
    path: str                     # the item that appeared (what the user sees in the notification)
    paths: list[str]              # what the worker scans
    note: str = ""                # extra context for the notification (autostart label/program, pkg id)
    sig: tuple | None = None
    started: float = 0.0
    attempts: int = 0
    quiet: bool = False
    announced: bool = False

    @property
    def name(self) -> str:
        base = os.path.basename(self.path)
        return base[:-len(".plist")] if self.kind == "receipt" else base


def pkg_files(pkgid: str) -> tuple[list[str], int]:
    """Executables, libraries, scripts and launchd plists installed by a .pkg."""
    try:
        info = plistlib.loads(subprocess.run(["pkgutil", "--pkg-info-plist", pkgid], capture_output=True,
                                             timeout=60).stdout)
        listing = subprocess.run(["pkgutil", "--files", pkgid, "--only-files"], capture_output=True, text=True,
                                 timeout=120).stdout.splitlines()
    except (OSError, subprocess.SubprocessError, plistlib.InvalidFileException, ValueError):
        return [], 0
    base = os.path.join(info.get("volume", "/"), str(info.get("install-location", "")).lstrip("/"))
    out = []
    for rel in listing:
        p = os.path.join(base, rel)
        low = p.lower()
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
            continue
        if st.st_mode & 0o111 or low.endswith(PKG_SCRIPT_EXT) or \
                ("/launch" in low and low.endswith(".plist")) or "/privilegedhelpertools/" in low:
            out.append(p)
    return out[:MAX_PKG_FILES], len(out)


def persistence_context(path: str) -> tuple[str, list[str]]:
    """'label → program' plus the files a launchd plist would run."""
    try:
        with open(path, "rb") as fh:
            d = plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return "", []
    try:
        from .envscan.launchd_rules import analyze_plist, scope_for_path
        pa = analyze_plist(d, path, scope_for_path(path), os.path.expanduser("~"))
        extra = [p for p in pa.paths if os.path.isfile(p)]
        job = pa.job.job if pa.job else None
        note = f"{job.label or '?'} → {job.program or '?'}" if job else ""
        return note, extra[:20]
    except Exception:  # noqa: BLE001
        return "", []


# ------------------------------------------------------------------ worker (heavy, on demand)

class WorkerClient:
    def __init__(self, args: list[str], results: queue.Queue):
        self.args = args
        self.results = results
        self.proc: subprocess.Popen | None = None
        self.inflight: dict[int, Job] = {}
        self.last_activity = time.time()
        self.ready = False

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def _start(self) -> None:
        from .sandbox import _limits, build_profile, new_workspace, python_env, workspace_noexec
        _log("Uruchamiam proces skanujący w sandboksie (ładowanie baz sygnatur) …")
        app_event({"ev": "watch_worker", "state": "loading"})
        self.ready = False
        self.work = new_workspace()
        profile = build_profile(self.work, None, "scan")
        with open(os.path.join(self.work, "sandbox-scan.sb"), "w") as fh:
            fh.write(profile)
        # same interpreter hardening as sandbox.run_inner: sys.path without the project root, no user site, .pyc
        # only from the sealed tree; the profile travels inline (-p) – the copy above is for reference only
        # (anything running as the user can write to the workspace before sandbox-exec would read a file)
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.path.join(self.work, "home"),
               "TMPDIR": os.path.join(self.work, "tmp"), **python_env(), "LANG": "pl_PL.UTF-8",
               "CERBER_HOME": config.HOME, "CERBER_DISABLE_TOOLS": "hdiutil", "CERBER_SANDBOX": "scan",
               "CERBER_REAL_HOME": os.path.expanduser("~"), "CERBER_WORK": self.work,
               "CERBER_NOEXEC": "1" if workspace_noexec(self.work) else "0"}
        cmd = ["/usr/bin/sandbox-exec", "-p", profile, os.path.join(config.ROOT, ".venv", "bin", "python"),
               "-m", "cerber", "watch", "run", "--worker-mode"] + self.args
        self.proc = subprocess.Popen(cmd, cwd=self.work, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=None, text=True, bufsize=1, preexec_fn=_limits)
        proc = self.proc

        def reader() -> None:
            for line in proc.stdout:
                try:
                    msg = json.loads(line)
                except (ValueError, RecursionError):
                    _log(f"worker: {line.rstrip()[:300]}")
                    continue
                if isinstance(msg, dict) and "eof" not in msg:      # end of stream is the parent's own marker
                    self.results.put(msg)
            self.results.put({"eof": True, "rc": proc.wait(), "pid": proc.pid})
        threading.Thread(target=reader, daemon=True).start()

    def submit(self, job: Job) -> None:
        if not self.running:
            self._start()
        self.inflight[job.id] = job
        job.started = time.time()
        job.attempts += 1
        self.last_activity = time.time()
        try:
            self.proc.stdin.write(json.dumps({"id": job.id, "paths": job.paths}) + "\n")
            self.proc.stdin.flush()
        except (OSError, ValueError):
            _log("worker: nie można wysłać zadania – restart przy następnej próbie")

    def maybe_stop_idle(self, idle: float) -> None:
        if self.running and not self.inflight and time.time() - self.last_activity > idle:
            _log(f"Brak pracy od {idle:.0f} s – zamykam proces skanujący (zwalniam pamięć)")
            self.stop()

    def stop(self) -> None:
        from .sandbox import remove_workspace
        if self.proc:
            try:
                self.proc.stdin.close()
                self.proc.wait(timeout=30)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)       # nothing from the sandbox may linger
            except (ProcessLookupError, PermissionError):
                pass
            self.proc = None
            app_event({"ev": "watch_worker", "state": "stopped"})
        if getattr(self, "work", None):
            remove_workspace(self.work)
            self.work = None
        self.ready = False


def run_worker(a) -> int:
    """Worker side (inside the read-only `scan` sandbox): load engines once, then scan JSON-line jobs from
    stdin until it closes. Reports and quarantine are done by the (unsandboxed) watcher."""
    from .scanner import ScanOptions, iter_files, load_engines, scan_paths, total_patterns

    proto = os.fdopen(os.dup(1), "w", buffering=1)
    os.dup2(2, 1)                       # stray prints must not corrupt the protocol channel
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    def send(obj: dict) -> None:
        proto.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
        proto.flush()

    if os.environ.get("CERBER_SANDBOX") == "scan" and os.environ.get("CERBER_WORK"):
        from .sandbox import harden
        verified = harden("scan", os.environ["CERBER_WORK"],
                          lambda ev: send({"sandbox": ev}) if ev.get("ev") != "log" else None)
        send({"sandbox_verified": verified})

    def wlog(msg: str) -> None:
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S')}   [skaner] {msg}", file=sys.stderr, flush=True)

    opts = ScanOptions(deep=True, level=a.level, quarantine=False,
                       workers=a.workers or max(2, (os.cpu_count() or 4) // 2))
    bundle = load_engines(opts, wlog)
    info = bundle[2]
    send({"ready": True, "load_seconds": info.get("load_seconds"), "patterns": total_patterns(info),
          "missing": info.get("missing", [])})
    seen: dict[str, tuple] = {}         # path -> (size, mtime, inode) of files already scanned clean or not
    for line in sys.stdin:
        try:
            job = json.loads(line)
        except ValueError:
            continue
        t0 = time.time()
        skipped: list[str] = []
        files = list(iter_files(job["paths"], opts, skipped))
        todo = []
        for f in files:
            try:
                st = os.stat(f)
            except OSError:
                continue
            key = (st.st_size, st.st_mtime_ns, st.st_ino)
            if seen.get(f) != key:
                todo.append(f)
                seen[f] = key
        if len(seen) > 300000:
            seen.clear()
        report = scan_paths(todo, opts, log=wlog, engines_bundle=bundle, progress=False) if todo else None
        if report:
            for r in report.get("results", []):
                r.pop("ai_context", None)
                r.pop("tree", None)
        flagged = [r for r in (report or {}).get("results", []) if r["verdict"] != "INFO"]
        send({"id": job["id"], "files": len(files), "scanned": len(todo), "seconds": round(time.time() - t0, 1),
              "counts": (report or {}).get("counts", {}), "timeouts": (report or {}).get("timeouts", 0),
              "unreadable": len(skipped), "report_data": report if flagged else None,
              "flagged": [{"path": r["path"], "verdict": r["verdict"], "primary": r.get("primary"),
                           "score": r.get("score", 0)} for r in flagged[:50]]})
    proto.flush()
    sys.stderr.flush()
    os._exit(0)                         # tearing down ~2.6 GB of signature objects takes seconds


# ------------------------------------------------------------------ network & remote-access guard (opt-in)

NET_LOG_EVERY = 300.0        # unified log read every 5 min
NET_LOG_FIRST = 900.0        # very first start: the last 15 min
NET_LOG_MAX_BACK = 86400.0   # after a break (Mac off, Cerber closed): at most one day back
NET_STATE = os.path.join(LOG_DIR, "netguard-state.json")
NET_NOTIFY_MAX = 6           # notifications per 10 min; the rest only in the feed and the report
NET_REPORT_EVENTS = 2000
NET_STATUS_EVERY = 30.0
NET_ALARM = ("suspicious", "pua", "malicious")
NET_SEVERITIES = ("info", "low", "suspicious", "pua", "malicious")
NET_ITEM_KEYS = ("id", "time", "kind", "severity", "score", "title", "detail", "process", "pid", "exe", "remote",
                 "host", "signer", "target")
NET_ITEM_TAGS = ("confidence", "attack", "trust")                  # short machine-readable words
NET_ITEM_LISTS = {"evidence": (8, 300), "signals": (12, 120)}     # key -> (max items, max chars per item)
NET_CONFIDENCE = ("high", "medium", "low")
NET_STAT_KEYS = ("polls", "connections_new", "public_new", "listening_new", "inbound", "sessions_new",
                 "processes_remote", "uploaded_bytes", "alerts")


def net_report_paths(day: str | None = None) -> tuple[str, str]:
    stem = os.path.join(config.REPORTS, f"siec-{day or time.strftime('%Y%m%d')}")
    return stem + ".json", stem + ".html"


def clean_net_item(item: dict) -> dict:
    """An event from the sandboxed watch: only known keys, plain types, bounded lengths."""
    out: dict = {}
    for k in NET_ITEM_KEYS:
        v = item.get(k)
        if k in ("score", "pid"):
            out[k] = int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) \
                else None
        else:
            out[k] = str(v)[:600] if v is not None else None
    for k in NET_ITEM_TAGS:
        v = item.get(k)
        out[k] = v[:40] if isinstance(v, str) and v.isascii() and v.replace("_", "").isalnum() else None
    for k, (n, size) in NET_ITEM_LISTS.items():
        v = item.get(k)
        out[k] = [x[:size] for x in v[:n] if isinstance(x, str) and x] if isinstance(v, list) else []
    out["ioc"] = item.get("ioc") is True
    if out["severity"] not in NET_SEVERITIES:
        out["severity"] = "info"
    if out["confidence"] not in NET_CONFIDENCE:
        out["confidence"] = None
    out["date"] = time.strftime("%Y-%m-%d")
    return out


def clean_net_status(ev: dict) -> dict:
    st: dict = {k: int(ev[k]) for k in NET_STAT_KEYS
                if isinstance(ev.get(k), (int, float)) and not isinstance(ev.get(k), bool)
                and math.isfinite(ev[k])}
    for k in ("since", "log_checked"):
        if isinstance(ev.get(k), str):
            st[k] = ev[k][:40]
    if isinstance(ev.get("interval_s"), (int, float)):
        st["interval_s"] = float(ev["interval_s"])
    st["permissions"] = bool(ev.get("permissions"))
    st["limitations"] = [str(x)[:300] for x in (ev.get("limitations") or [])[:20] if isinstance(x, str)]
    return st


def query_log(start: float, end: float, timeout: float = 120.0, procs: list | None = None) -> dict:
    """Unified-log batch for the sandboxed watch (fixed argv, no shell, read-only)."""
    from .envscan.netaudit_deep import _PRIV_PRED, _SEC_PRED, LOG

    def fmt(t: float) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))

    texts, errors = [], []
    for pred in (_SEC_PRED, _PRIV_PRED):
        argv = [LOG, "show", "--style", "ndjson", "--no-backtrace", "--start", fmt(start), "--end", fmt(end),
                "--predicate", pred]
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True)
        except OSError as exc:
            errors.append(f"nie można uruchomić {LOG}: {exc.strerror or exc}")
            continue
        if procs is not None:
            procs.append(proc)
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            errors.append("przekroczono limit czasu odczytu dziennika")
        finally:
            if procs is not None and proc in procs:
                procs.remove(proc)
        if proc.returncode not in (0, None) and not out:
            errors.append((err or "").strip()[:200] or f"log show: kod {proc.returncode}")
            continue
        texts.append(out[:32 << 20])
    if not texts:
        return {"from": fmt(start), "to": fmt(end), "error": "; ".join(errors) or "brak danych"}
    return {"from": fmt(start), "to": fmt(end), "texts": texts}


class NetGuard:
    """The network & remote-access watch next to the file watch. Events → Cerber.app (`watch_net`,
    `watch_net_status`), notifications for alarms, the daily report; programs it raises an alarm about are
    put into `targets` for the file scan."""

    def __init__(self, notifier: "Notifier", targets: queue.Queue):
        self.notifier = notifier
        self.targets = targets
        self.stop_ev = threading.Event()
        self.lock = threading.Lock()
        self.inbox: str | None = None
        self.log_procs: list = []
        self.status: dict = {}
        self.events: list[dict] = []
        self.day = time.strftime("%Y%m%d")
        self.started = time.strftime("%Y-%m-%d %H:%M:%S")
        self.dirty = False
        self.last_write = 0.0
        self.last_status = 0.0
        self.notified: list[float] = []
        self.restarts: list[float] = []
        self.n_batch = 0
        self.threads: list[threading.Thread] = []
        self._load_day()

    # --- report
    def _load_day(self) -> None:
        jp, _ = net_report_paths(self.day)
        try:
            with open(jp) as fh:
                old = json.load(fh)
            self.events = [e for e in old.get("events") or [] if isinstance(e, dict)][:NET_REPORT_EVENTS]
            self.started = str(old.get("started") or self.started)
        except (OSError, ValueError, AttributeError):
            pass

    @property
    def report(self) -> str:
        return net_report_paths(self.day)[1]

    def flush(self, force: bool = False) -> None:
        with self.lock:
            if not (self.dirty or force):
                return
            data = {"mode": "netguard", "date": f"{self.day[:4]}-{self.day[4:6]}-{self.day[6:]}",
                    "started": self.started, "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": dict(self.status), "events": list(self.events)}
            self.dirty = False
            self.last_write = time.time()
        jp, hp = net_report_paths(self.day)
        try:
            from .report import write_netguard_html
            os.makedirs(config.REPORTS, exist_ok=True)
            tmp = jp + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(data, fh, ensure_ascii=False, default=str)
            os.replace(tmp, jp)
            write_netguard_html(data, hp)
        except Exception as exc:  # noqa: BLE001
            _log(f"Nadzór sieci: nie udało się zapisać raportu: {exc!r}")

    def _roll_day(self) -> None:
        today = time.strftime("%Y%m%d")
        if today != self.day:
            self.flush(force=True)
            with self.lock:
                self.day, self.events = today, []
                self.started = time.strftime("%Y-%m-%d %H:%M:%S")

    def tick(self) -> None:
        """Called by the watcher's main loop about once a second."""
        self._roll_day()
        now = time.time()
        if (self.dirty and now - self.last_write >= 10) or now - self.last_write >= 300:
            self.flush(force=True)

    # --- events from the sandboxed watch
    def relay(self, ev: dict) -> None:
        kind = ev.get("ev")
        if kind == "net_event" and isinstance(ev.get("item"), dict):
            self._on_event(clean_net_item(ev["item"]))
        elif kind == "net_status":
            self._on_status(ev)
        elif kind == "watch_target":
            p, why = ev.get("path"), str(ev.get("reason") or "")[:200]
            if isinstance(p, str) and p.startswith("/") and "\n" not in p and len(p) < 4096:
                self.targets.put((p, why))
        elif kind == "sandbox_violation":
            self.notifier.notify("Cerber – sandbox", "Samosprawdzenie sandboksa nadzoru sieci nie powiodło się – "
                                 "nadzór sieci wstrzymany", subtitle="; ".join(ev.get("problems") or [])[:200],
                                 sound="Basso")
        elif kind in ("error", "log") and ev.get("msg"):
            _log(f"Nadzór sieci: {str(ev['msg'])[:500]}")

    def _on_event(self, item: dict) -> None:
        with self.lock:
            self.events.insert(0, item)
            del self.events[NET_REPORT_EVENTS:]
            self.dirty = True
        app_event({"ev": "watch_net", "item": item, "report": self.report})
        sev = item["severity"]
        if sev != "info":
            _log(f"Sieć [{sev}] {item['title']} · {item.get('detail') or ''}")
        if sev in NET_ALARM:
            now = time.time()
            self.notified = [t for t in self.notified if now - t < 600]
            if len(self.notified) < NET_NOTIFY_MAX:
                self.notified.append(now)
                self.notifier.notify("Cerber ⛔ sieć i zdalny dostęp" if sev == "malicious"
                                     else "Cerber ⚠️ sieć i zdalny dostęp", item.get("detail") or "",
                                     subtitle=item["title"], sound="Basso" if sev == "malicious" else "Submarine")
            if sev in ("malicious", "suspicious"):
                self.last_write = 0.0            # alarms reach the report within a second

    def _on_status(self, ev: dict) -> None:
        st = clean_net_status(ev)
        with self.lock:
            first = not self.status
            self.status = st
        now = time.time()
        if first or now - self.last_status >= NET_STATUS_EVERY:
            self.last_status = now
            app_event({"ev": "watch_net_status", "active": True, **st, "report": self.report})

    # --- threads
    def start(self) -> None:
        for target, name in ((self._run, "cerber-netguard"), (self._log_loop, "cerber-netguard-log")):
            t = threading.Thread(target=target, daemon=True, name=name)
            t.start()
            self.threads.append(t)
        _log("Nadzór sieci i zdalnego dostępu: włączony")

    def stop(self, timeout: float = 30) -> None:
        self.stop_ev.set()
        for p in list(self.log_procs):
            try:
                p.kill()
            except OSError:
                pass
        for t in self.threads:
            t.join(timeout)
        self.flush(force=True)
        app_event({"ev": "watch_net_status", "active": False, **self.status, "report": self.report})

    def _run(self) -> None:
        while not self.stop_ev.is_set():
            t0 = time.time()
            try:
                if os.environ.get("CERBER_NO_SANDBOX") == "1":
                    self._run_direct()
                else:
                    self._run_sandboxed()
            except Exception as exc:  # noqa: BLE001
                _log(f"Nadzór sieci: błąd {exc!r}")
            if self.stop_ev.is_set():
                break
            now = time.time()
            self.restarts = [t for t in self.restarts if now - t < 3600] + [now]
            if len(self.restarts) > 5:
                _log("Nadzór sieci: proces kończył się zbyt często – zatrzymany do ponownego włączenia ochrony")
                self.notifier.notify("Cerber – nadzór sieci", "Nadzór sieci zatrzymał się po kilku błędach. Wyłącz i "
                                     "włącz ochronę w tle, aby spróbować ponownie.", sound="Basso")
                app_event({"ev": "watch_net_status", "active": False, **self.status, "report": self.report,
                           "error": "nadzór sieci zatrzymał się po kilku błędach"})
                return
            _log(f"Nadzór sieci: proces zakończył się po {now - t0:.0f} s – ponowne uruchomienie za 30 s")
            self.stop_ev.wait(30)

    def _run_sandboxed(self) -> None:
        from .sandbox import new_workspace, remove_workspace, run_inner
        work = new_workspace()
        inbox = os.path.join(work, "in", "syslog")
        os.makedirs(inbox, mode=0o700, exist_ok=True)
        self.inbox = inbox
        try:
            run_inner(work, "env", ["inner-netwatch", "--work", work, "--root-pid", str(os.getpid()), "--guard",
                                    "--inbox", inbox], self.relay, self.stop_ev, out_name="netwatch.json",
                      wall=7 * 86400, track_every=10.0)
        finally:
            self.inbox = None
            remove_workspace(work)

    def _run_direct(self) -> None:
        """CERBER_NO_SANDBOX=1 (tests, debugging)."""
        from .envscan.netwatch import NetWatch
        from .envscan.util import EnvContext
        inbox = tempfile.mkdtemp(prefix="cerber-netguard-")
        self.inbox = inbox
        try:
            w = NetWatch(EnvContext({"deep": True}), self.relay, root_pid=os.getpid(), guard=True, inbox=inbox)
            w.loop(self.stop_ev)
        finally:
            self.inbox = None
            shutil.rmtree(inbox, ignore_errors=True)

    def _since(self) -> float:
        now = time.time()
        try:
            with open(NET_STATE) as fh:
                t = float(json.load(fh).get("log_to"))
            return min(max(t, now - NET_LOG_MAX_BACK), now)
        except (OSError, ValueError, TypeError, AttributeError):
            return now - NET_LOG_FIRST

    @staticmethod
    def _save_since(t: float) -> None:
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            with open(NET_STATE + ".tmp", "w") as fh:
                json.dump({"log_to": t}, fh)
            os.replace(NET_STATE + ".tmp", NET_STATE)
        except OSError:
            pass

    def _log_loop(self) -> None:
        since = self._since()
        delay = 20.0                                     # let the sandboxed watch take its first snapshot
        while not self.stop_ev.wait(delay):
            delay = NET_LOG_EVERY
            inbox = self.inbox
            end = time.time() - 5
            if not inbox or end - since < 30:
                delay = 15.0 if not inbox else delay
                continue
            batch = query_log(since, end, procs=self.log_procs)
            if self.stop_ev.is_set():
                return
            self.n_batch += 1
            path = os.path.join(inbox, f"{self.n_batch:08d}.json")
            try:
                with open(path + ".part", "w") as fh:
                    json.dump(batch, fh, ensure_ascii=False)
                os.replace(path + ".part", path)
            except OSError:
                continue                                  # workspace gone (restart): same window next time
            if "error" not in batch:
                since = end
                self._save_since(end)
            else:
                _log(f"Nadzór sieci: dziennik systemowy – {batch['error']}")


# ------------------------------------------------------------------ watcher (light, always on)

class Watcher:
    def __init__(self, a):
        self.a = a
        self.notifier = Notifier(not a.no_notify)
        self.kq = select.kqueue()
        self.spots: list[Spot] = []
        self.by_fd: dict[int, Spot] = {}
        self.pending: dict[str, Pending] = {}
        self.results: queue.Queue = queue.Queue()
        wargs = ["--level", a.level]
        if a.workers:
            wargs += ["--workers", str(a.workers)]
        self.worker = WorkerClient(wargs, self.results)
        self.next_id = 0
        self.stop = False
        self.warned_missing = False
        self.net_targets: queue.Queue = queue.Queue()
        self.net = NetGuard(self.notifier, self.net_targets) if getattr(a, "net", False) else None

    # --- spots
    def _spot_list(self) -> list[tuple[str, str]]:
        if self.a.spot:
            return [tuple(s.split(":", 1)) for s in self.a.spot]
        return default_spots()

    def refresh_spots(self) -> None:
        known = {(s.kind, s.path) for s in self.spots}
        for kind, path in self._spot_list():
            if (kind, path) not in known:
                self.spots.append(Spot(kind, os.path.abspath(os.path.expanduser(path))))
        for s in self.spots:
            if s.fd < 0:
                self._open(s)

    def _open(self, s: Spot) -> None:
        if not os.path.isdir(s.path):
            s.error = "brak katalogu"
            return
        try:
            snap = _listdir(s.path)
            fd = os.open(s.path, os.O_EVTONLY)
        except OSError as exc:
            if s.error != str(exc.strerror):
                _log(f"Nie mogę obserwować {s.path}: {exc.strerror} (ponowię za {REOPEN_SECS} s; "
                     "jeśli to brak zgody macOS – zezwól Pythonowi na dostęp lub daj mu Pełny dostęp do dysku)")
            s.error = str(exc.strerror)
            return
        ev = select.kevent(fd, filter=select.KQ_FILTER_VNODE, flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                           fflags=select.KQ_NOTE_WRITE | select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME
                           | select.KQ_NOTE_REVOKE)
        self.kq.control([ev], 0)
        first = not s.snap and s.error not in ("reopen", "brak katalogu")
        if not first:                       # folder came back: diff against what we knew
            self._diff(s, snap)
        s.snap = snap
        s.fd = fd
        self.by_fd[fd] = s
        s.error = ""
        _log(f"Obserwuję [{KIND_PL.get(s.kind, s.kind)}] {s.path}")

    def _close(self, s: Spot) -> None:
        if s.fd >= 0:
            self.by_fd.pop(s.fd, None)
            try:
                os.close(s.fd)
            except OSError:
                pass
        s.fd = -1
        s.error = "reopen"

    def _diff(self, s: Spot, new: dict | None = None) -> None:
        if new is None:
            try:
                new = _listdir(s.path)
            except OSError:
                self._close(s)
                return
        for name, (ino, mode) in new.items():
            old = s.snap.get(name)
            if old is not None and old[0] == ino:
                continue
            if _wanted(s.kind, name, mode):
                self._enqueue(s.kind, os.path.join(s.path, name))
        s.snap = new

    def _enqueue(self, kind: str, path: str, quiet: bool = False, note: str = "") -> None:
        if kind == "binary":
            path = os.path.realpath(path)
            if not os.path.isfile(path):
                return
        if path in self.pending:
            return
        now = time.time()
        self.pending[path] = Pending(kind, path, now, since=now, next_check=now, quiet=quiet, note=note)
        app_event({"ev": "watch_new", "kind": kind, "kind_pl": KIND_PL.get(kind, kind), "path": path,
                   "name": os.path.basename(path)})
        _log(f"Nowe [{KIND_PL.get(kind, kind)}]: {path}")

    # --- stability → jobs
    def _tick_pending(self) -> None:
        now = time.time()
        for path, p in list(self.pending.items()):
            if now < p.next_check:
                continue
            t0 = time.time()
            sig = _signature(path)
            cost = time.time() - t0
            p.next_check = now + max(TICK, cost * 20)
            if sig is None or sig[0] == 0:          # vanished (temp file) or still an empty placeholder
                if sig is None or now - p.first > 3600:
                    del self.pending[path]
                continue
            if sig != p.sig:
                p.sig, p.since = sig, now
                continue
            wait = STABLE_DIR if os.path.isdir(path) else STABLE_FILE
            if now - p.since >= wait:
                del self.pending[path]
                self._dispatch(p)

    def _dispatch(self, p: Pending) -> None:
        paths, note = [p.path], p.note
        if p.kind == "receipt":
            pkgid = os.path.basename(p.path)[:-len(".plist")]
            files, total = pkg_files(pkgid)
            if not files:
                _log(f"Pakiet {pkgid}: brak plików wykonywalnych do sprawdzenia")
                return
            paths = files
            note = f"{pkgid} · {total} plików wykonywalnych" + (f" (sprawdzam pierwsze {len(files)})"
                                                                 if total > len(files) else "")
        elif p.kind == "persistence" and p.path.endswith(".plist"):
            note, extra = persistence_context(p.path)
            paths += [x for x in extra if x not in paths]
        self.next_id += 1
        job = Job(self.next_id, p.kind, p.path, paths, note, p.sig, quiet=p.quiet)
        app_event({"ev": "watch_scanning", "kind": p.kind, "kind_pl": KIND_PL.get(p.kind, p.kind), "path": p.path,
                   "name": job.name, "note": note})
        self.worker.submit(job)

    def _wants_clean_report(self, job: Job) -> bool:
        return not job.quiet and (job.kind in ALWAYS_REPORT or
                                  (job.kind == "download" and job.name.lower().endswith(INSTALLER_EXT)))

    def _announce_slow(self) -> None:
        """'Checking …' only when the verdict is not there within a few seconds."""
        now = time.time()
        for job in self.worker.inflight.values():
            if not job.announced and now - job.started > ANNOUNCE_AFTER and self._wants_clean_report(job):
                job.announced = True
                wait = "" if self.worker.ready else " (ładowanie baz ~15 s)"
                self.notifier.notify("Cerber", f"{job.name}{wait}",
                                     subtitle=f"Sprawdzam: {KIND_PL.get(job.kind, job.kind)} …")

    # --- results
    def _handle_results(self) -> None:
        while True:
            try:
                r = self.results.get_nowait()
            except queue.Empty:
                return
            if "sandbox_verified" in r:
                app_event({"ev": "watch_sandbox", "verified": r["sandbox_verified"]})
                continue
            if "sandbox" in r:
                ev = r["sandbox"]
                if ev.get("ev") == "sandbox_violation":
                    self.notifier.notify("Cerber – sandbox", "Samosprawdzenie sandboksa nie powiodło się – skanowanie "
                                         "w tle wstrzymane", subtitle="; ".join(ev.get("problems", []))[:200],
                                         sound="Basso")
                continue
            if r.get("ready"):
                self.worker.ready = True
                app_event({"ev": "watch_worker", "state": "ready", "patterns": r.get("patterns")})
                _log(f"Proces skanujący gotowy: {r.get('patterns', 0):,} wzorców, bazy w {r.get('load_seconds')} s")
                if r.get("missing") and not self.warned_missing:
                    self.warned_missing = True
                    self.notifier.notify("Cerber – brak baz", "Uruchom: ./cerber.sh update",
                                         subtitle=", ".join(r["missing"]), sound="Basso")
                continue
            if r.get("eof"):
                lost = list(self.worker.inflight.values())
                self.worker.inflight.clear()
                if self.worker.proc is not None and self.worker.proc.pid == r.get("pid"):
                    self.worker.proc = None
                if lost:
                    _log(f"Proces skanujący zakończył się (kod {r.get('rc')}) w trakcie {len(lost)} zadań")
                for j in lost:
                    if j.attempts < 2:
                        self.worker.submit(j)
                    else:
                        _log(f"BŁĄD: nie udało się sprawdzić {j.path} (proces skanujący padł {j.attempts}×)")
                        self.notifier.notify("Cerber – błąd", f"Nie udało się sprawdzić: {j.name}", sound="Basso")
                continue
            job = self.worker.inflight.pop(r.get("id"), None)
            self.worker.last_activity = time.time()
            if job is None:
                continue
            self._report(job, r)
            if job.sig is not None and os.path.isdir(job.path) and _signature(job.path) != job.sig:
                self._enqueue(job.kind, job.path, quiet=True)   # bundle still changed while we scanned it

    def _persist(self, job: Job, r: dict) -> None:
        """Reports and quarantine happen here, outside the sandbox, and only for paths of this job."""
        data = r.pop("report_data", None)
        if not data:
            return
        from .report import write_html
        from .scanner import save_json
        roots = [os.path.realpath(p) for p in job.paths]

        def inside(p: str) -> bool:
            rp = os.path.realpath(p)
            return any(rp == q or rp.startswith(q.rstrip("/") + "/") for q in roots)

        if auto_quarantine(self.a):
            from .quarantine import quarantine_file
            for res in data.get("results", []):
                if res.get("verdict") == "MALICIOUS" and os.path.isfile(res["path"]) and inside(res["path"]):
                    try:
                        res["quarantined"] = quarantine_file(res["path"], res)
                    except OSError as exc:
                        res["quarantine_error"] = str(exc.strerror or exc)
        q = {res["path"]: res for res in data.get("results", [])}
        for f in r.get("flagged") or []:
            src = q.get(f["path"], {})
            f["quarantined"] = src.get("quarantined")
            f["quarantine_error"] = src.get("quarantine_error")
        try:
            os.makedirs(config.REPORTS, exist_ok=True)
            stem = os.path.join(config.REPORTS, f"watch-{time.strftime('%Y%m%d-%H%M%S')}-{job.id}")
            data.update({"mode": "watch", "title": job.name})
            save_json(data, stem + ".json")
            r["report"] = write_html(data, stem + ".html", None)
        except Exception as exc:  # noqa: BLE001
            _log(f"Nie udało się zapisać raportu: {exc!r}")

    def _report(self, job: Job, r: dict) -> None:
        self._persist(job, r)
        name = job.name
        kind = KIND_PL.get(job.kind, job.kind)
        flagged = r.get("flagged") or []
        worst_v = max((f["verdict"] for f in flagged), default="CLEAN",
                      key=["CLEAN", "INFO", "SUSPICIOUS", "PUA", "MALICIOUS"].index)
        app_event({"ev": "watch_result", "kind": job.kind, "kind_pl": kind, "path": job.path, "name": name,
                   "note": job.note, "verdict": worst_v, "files": r.get("files", 0), "scanned": r.get("scanned", 0),
                   "seconds": r.get("seconds"), "flagged": flagged, "report": r.get("report"),
                   "time": time.strftime("%Y-%m-%d %H:%M:%S")})
        extra = f" · {job.note}" if job.note else ""
        if not flagged:
            _log(f"CZYSTY [{kind}] {job.path}{extra} ({r.get('files', 0)} plików, "
                 f"{r.get('scanned', 0)} nowych, {r.get('seconds')} s)")
            if self._wants_clean_report(job) and (r.get("scanned") or job.announced):
                what = f"{job.note}\n" if job.kind == "persistence" and job.note else ""
                self.notifier.notify("Cerber ✅ czysty", f"{what}{name} · {r.get('files', 0)} plików",
                                     subtitle=f"{kind}: nic nie znaleziono")
            return
        order = ["INFO", "SUSPICIOUS", "PUA", "MALICIOUS"]
        worst = max(flagged, key=lambda f: (order.index(f["verdict"]), f.get("score", 0)))
        v = worst["verdict"]
        q = [f for f in flagged if f.get("quarantined")]
        for f in flagged:
            _log(f"{VERDICT_PL[f['verdict']]} [{kind}] {f['path']} · {f.get('primary')} · wynik {f.get('score')}"
                 + (f" · kwarantanna {f['quarantined']}" if f.get("quarantined") else "")
                 + (f" · kwarantanna nieudana: {f['quarantine_error']}" if f.get("quarantine_error") else ""))
        _log(f"Raport: {r.get('report')}")
        where = os.path.basename(worst["path"]) if worst["path"] != job.path else name
        msg = f"{where}: {worst.get('primary') or '?'}"
        if len(flagged) > 1:
            msg += f" (+{len(flagged) - 1} innych)"
        if q:
            msg += f" · {len(q)} w kwarantannie"
        if job.kind == "persistence" and job.note:
            msg = f"{job.note}\n{msg}"
        if v == "MALICIOUS":
            self.notifier.notify(f"Cerber ⛔ {VERDICT_PL[v]}", msg, subtitle=f"{kind}: {name}", sound="Basso")
            body = (f"{msg}\n\nMiejsce: {job.path}\n"
                    + ("Plik przeniesiono do kwarantanny (./cerber.sh quarantine list).\n" if q else
                       "Plik NIE został przeniesiony – usuń go ręcznie albo użyj ./cerber.sh scan --quarantine.\n")
                    + "Nie otwieraj go ani nie instaluj.")
            self.notifier.alert(f"Cerber: wykryto złośliwe oprogramowanie", body, r.get("report"))
        else:
            self.notifier.notify(f"Cerber ⚠️ {VERDICT_PL[v]}", msg, subtitle=f"{kind}: {name}", sound="Submarine")

    # --- main loop
    def run(self) -> int:
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "stop", True))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "stop", True))
        _log(f"Cerber watch start (pid {os.getpid()}) · kwarantanna złośliwych: "
             f"{'włączona' if auto_quarantine(self.a) else 'wyłączona'} · AI: {'tak' if self.a.ai else 'nie'} · "
             f"nadzór sieci: {'tak' if self.net else 'nie'}")
        self.refresh_spots()
        app_event({"ev": "watch_ready", "level": self.a.level, "quarantine": auto_quarantine(self.a),
                   "net": self.net is not None, "net_report": self.net.report if self.net else None,
                   "spots": [{"kind": s.kind, "kind_pl": KIND_PL.get(s.kind, s.kind), "path": s.path,
                              "ok": s.fd >= 0, "error": s.error or None} for s in self.spots]})
        if _APP_OUT is not None:
            def watch_parent() -> None:            # Cerber.app closed our stdin (quit/crash) → stop too
                try:
                    while sys.stdin.read(1):
                        pass
                except (OSError, ValueError):
                    pass
                self.stop = True
            threading.Thread(target=watch_parent, daemon=True).start()
        if self.net is not None:
            self.net.start()
        last_reopen = last_rescan = time.time()
        while not self.stop:
            try:
                events = self.kq.control(None, 64, TICK)
            except InterruptedError:
                events = []
            for ev in events:
                s = self.by_fd.get(ev.ident)
                if s is None:
                    continue
                if ev.fflags & (select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME | select.KQ_NOTE_REVOKE):
                    _log(f"Katalog {s.path} zniknął/przeniesiony – ponowię obserwację")
                    self._close(s)
                    continue
                self._diff(s)
            now = time.time()
            if now - last_reopen > REOPEN_SECS:
                last_reopen = now
                self.refresh_spots()
            if now - last_rescan > RESCAN_SECS:
                last_rescan = now
                for s in self.spots:
                    if s.fd >= 0:
                        self._diff(s)
            self._tick_net()
            self._tick_pending()
            self._handle_results()
            self._announce_slow()
            self.worker.maybe_stop_idle(self.a.idle)
        _log("Cerber watch – zatrzymano")
        if self.net is not None:
            self.net.stop()
        self.worker.stop()
        return 0

    def _tick_net(self) -> None:
        """Programs the network guard raised an alarm about (and new programs in /tmp, /Users/Shared) → file scan."""
        if self.net is None:
            return
        self.net.tick()
        for _ in range(50):
            try:
                path, why = self.net_targets.get_nowait()
            except queue.Empty:
                return
            if os.path.exists(path):
                self._enqueue("network", path, quiet=True, note=why)


# ------------------------------------------------------------------ launchd integration

def _launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["launchctl", *args], capture_output=True, text=True)


def install(a) -> int:
    py = os.path.join(config.ROOT, ".venv", "bin", "python")
    if not os.path.exists(py):
        py = sys.executable
    args = [py, "-m", "cerber", "watch", "run"]
    if auto_quarantine(a):
        args.append("--quarantine")
    if a.ai:
        args.append("--ai")
    if getattr(a, "net", False):
        args.append("--net")
    if a.workers:
        args += ["--workers", str(a.workers)]
    if a.idle != IDLE_SECS:
        args += ["--idle", str(a.idle)]
    os.makedirs(LOG_DIR, exist_ok=True)
    plist = {
        "Label": LABEL,
        "ProgramArguments": args,
        "WorkingDirectory": config.ROOT,
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 30,
        "Nice": 5,
        "ProcessType": "Standard",
        "EnvironmentVariables": {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                                 "PYTHONUNBUFFERED": "1"},
        "StandardOutPath": os.path.join(LOG_DIR, "watch.out.log"),
        "StandardErrorPath": os.path.join(LOG_DIR, "watch.out.log"),
    }
    domain = f"gui/{os.getuid()}"
    _launchctl("bootout", f"{domain}/{LABEL}")
    os.makedirs(os.path.dirname(PLIST_PATH), exist_ok=True)
    with open(PLIST_PATH, "wb") as fh:
        plistlib.dump(plist, fh)
    r = _launchctl("bootstrap", domain, PLIST_PATH)
    if r.returncode != 0:
        print(f"launchctl bootstrap nie powiódł się: {r.stderr.strip()}")
        return 1
    print(f"Ochrona w tle WŁĄCZONA ({LABEL}) – startuje teraz i przy każdym logowaniu.")
    print("  Pilnuje: Pobrane, Biurko, Aplikacje, autostart (LaunchAgents/Daemons), instalacje .pkg,")
    print("           brew/npm (/opt/homebrew/bin), rozszerzenia przeglądarek.")
    print(f"  Złośliwe pliki: {'automatycznie do kwarantanny' if auto_quarantine(a) else 'tylko powiadomienie'}.")
    if getattr(a, "net", False):
        print("  Nadzór sieci i zdalnego dostępu: włączony (raport dzienny: reports/siec-RRRRMMDD.html).")
    print("  macOS może zapytać, czy „python3.14” może mieć dostęp do Pobranych i Biurka – kliknij Zezwól.")
    print("  Powiadomienia pokazują się jako „Edytor skryptów” – jeśli ich nie widać, włącz je w")
    print("  Ustawieniach systemowych → Powiadomienia.")
    print(f"  Dziennik: {LOG_PATH}   ·   stan: ./cerber.sh watch status   ·   wyłącz: ./cerber.sh watch uninstall")
    return 0


def uninstall(_a) -> int:
    _launchctl("bootout", f"gui/{os.getuid()}/{LABEL}")
    if os.path.exists(PLIST_PATH):
        os.remove(PLIST_PATH)
        print("Ochrona w tle WYŁĄCZONA (usunięto agenta startowego).")
    else:
        print("Ochrona w tle nie była zainstalowana.")
    return 0


def status(_a) -> int:
    r = _launchctl("print", f"gui/{os.getuid()}/{LABEL}")
    if r.returncode != 0:
        print("Ochrona w tle: WYŁĄCZONA" + (" (plik agenta istnieje, ale nie jest załadowany)"
                                           if os.path.exists(PLIST_PATH) else "") + " → ./cerber.sh watch install")
    else:
        st = pid = ""
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("state ="):
                st = line.split("=", 1)[1].strip()
            elif line.startswith("pid ="):
                pid = line.split("=", 1)[1].strip()
        print(f"Ochrona w tle: WŁĄCZONA · stan: {st or '?'}" + (f" · pid {pid}" if pid else ""))
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, errors="replace") as fh:
            lines = fh.readlines()[-25:]
        print(f"\nOstatnie wpisy ({LOG_PATH}):")
        for line in lines:
            print("  " + line.rstrip())
    return 0


def auto_quarantine(a) -> bool:
    """Off unless asked for: the user decides what goes to quarantine (owner's rule, 2026-10-09)."""
    return bool(getattr(a, "quarantine", False)) and not getattr(a, "no_quarantine", False)


def add_parser(sub) -> None:
    p = sub.add_parser("watch", help="ochrona w tle: automatycznie skanuj to, co pobierasz i instalujesz")
    p.add_argument("action", nargs="?", default="status", choices=["install", "uninstall", "status", "run"],
                   help="install = włącz przy logowaniu, uninstall = wyłącz, status, run = na pierwszym planie")
    p.add_argument("--quarantine", action="store_true",
                   help="złośliwe pliki od razu przenoś do kwarantanny (domyślnie tylko zgłaszaj)")
    p.add_argument("--no-quarantine", action="store_true", help=argparse.SUPPRESS)   # the old default, kept
    p.add_argument("--ai", action="store_true", help="analiza szarej strefy lokalnym modelem AI")
    p.add_argument("--net", action="store_true",
                   help="nadzór sieci i zdalnego dostępu: połączenia, otwarte porty, logowania zdalne, programy do "
                        "zdalnego sterowania, nowe uprawnienia (nagrywanie ekranu, dostępność), dziennik systemowy")
    p.add_argument("--workers", type=int, default=0, help="procesy skanujące (domyślnie połowa rdzeni)")
    p.add_argument("--idle", type=int, default=IDLE_SECS, help="po ilu s bez pracy zwolnić pamięć baz")
    p.add_argument("--level", default="quick", choices=["quick", "deep"],
                   help="głębokość skanu nowych plików (domyślnie: quick – jak szybki skan laptopa)")
    p.add_argument("--app", action="store_true", help=argparse.SUPPRESS)   # JSON events for Cerber.app
    p.add_argument("--no-notify", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--spot", action="append", help=argparse.SUPPRESS)      # KIND:PATH, for tests
    p.add_argument("--worker-mode", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(fn=main)


def main(a) -> int:
    global _APP_OUT
    if a.worker_mode:
        return run_worker(a)
    if a.app:
        _APP_OUT = os.fdopen(os.dup(1), "w", buffering=1, encoding="utf-8")
        os.dup2(2, 1)
        from .sandbox import cleanup_stale
        cleanup_stale()
        return Watcher(a).run()
    if a.action == "install":
        return install(a)
    if a.action == "uninstall":
        return uninstall(a)
    if a.action == "status":
        return status(a)
    return Watcher(a).run()

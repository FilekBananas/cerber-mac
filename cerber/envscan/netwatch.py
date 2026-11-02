"""Live network & behaviour watch for the rest of a Mega scan session.

The thorough audit (netaudit) runs once at the start. Afterwards this module polls every few seconds and judges
only what is NEW compared with its first snapshot:

* outgoing connections – known C2/malware addresses (IOC), scripts / unsigned programs on unusual ports,
  programs from odd places, regular "beaconing" (the same program calling the same address at a fixed interval);
* listening ports and inbound connections – someone connecting to this Mac (SSH, screen sharing, remote tools);
* login sessions (`who`), newly started remote-control tools and tunnels, new processes (full process heuristics
  of the environment scan, applied to the new processes only);
* new autostart entries (LaunchAgents/Daemons, helper tools) and changed shell start-up files;
* new files in Downloads/Desktop/Shared/tmp (handed to the file scanner as targets);
* a changed MAC address of the default gateway (ARP spoofing) and large uploads during the session (nettop);
* attacks in progress (envscan.live, existing processes too, re-checked on a budget): remote shells (a shell /
  interpreter whose stdin/stdout is a TCP connection), browser passwords / cookies, the login keychain, wallet
  data or a messenger session held open by a program that does not own them, and stealer staging folders /
  archives appearing in /tmp, /Users/Shared or $TMPDIR (copies of those stores collected for upload).

Every event item carries, besides the classic keys, `confidence` (high = malicious: act; medium; low), `attack`
(remote_shell, credential_theft, c2, download_exec, injection, masquerade, suspicious_chain, deleted_exe, miner or
None), `evidence` (short Polish lines), `signals` (names), `target` (the file to quarantine – an untrusted program or
the script an interpreter runs, never an Apple file or an interpreter), `trust` (provenance tier of `exe`) and
`ioc` (True for a threat-list address).

Guard mode (``guard=True``, background protection with the "network & remote access" option on, runs for days):
slower polls, no reverse DNS, Downloads/Desktop/autostart folders are left to the file watch (cerber.watch), files
are handed over only for alarms, memory is trimmed every hour, and two more checks run: the unified log (written
into ``inbox`` by the unsandboxed parent – /usr/bin/log refuses to run in a sandbox – and analysed here with
netaudit_deep.analyze_syslog: remote logins, screen sharing, password guessing, admin rights, privacy prompts,
XProtect) and new privacy permissions (screen recording, accessibility, input monitoring … in TCC.db).

Read-only, no sudo; runs inside the `env` sandbox. Polish texts for the user, English keys.
Events go to `emit` as {"ev": "net_event"} / {"ev": "net_status"} / {"ev": "watch_target"} (the last one is
consumed by the backend: new files it should scan before the session ends).
"""
from __future__ import annotations

import json
import os
import plistlib
import queue
import re
import socket
import statistics
import threading
import time
from typing import Callable

from ..core import Confidence
from .model import LOW_SCORE, Signal, combine, severity_of
from .netaudit import (BENIGN_UPLOADERS, GB, MB, SCRIPT_NAMES, _base, _ioc_lookup, build_connections,
                       build_listening, classify_tunnel, exfil_signals, exposure_of, fmt_bytes, format_ioc,
                       is_loopback, is_public_ip, is_shared_ip, match_remote_tool, normalize_ip, odd_location,
                       parse_netstat, parse_nettop, parse_who, script_connection_signals, service_for, signer_label)
from .files import stealer_archive, stealer_artifacts
from .live import (LiveSweep, ancestry, culprit_ancestor, event_meta, is_cerber_process, names_from_evidence,
                   user_temp_dir)
from .netaudit_deep import TCC_SENSITIVE, TCC_SPY
from .network import BACKDOOR_PORTS
from .patterns import classify_path, interpreter_of, is_apple_path, redact
from .provenance import TRUSTED, dev_context, name_signals, origin, origin_signals, quarantine_events, script_of
from .util import EnvContext, run

LW = "Heur:Env.Live"
POLL_S = 5.0
SLOW_S = 30.0                       # nettop sample, gateway MAC
WHO_S = 10.0
MAX_EVENTS = 300
MAX_PUBLIC = 300
MAX_TARGETS = 500
MAX_NEW_PIDS = 400                  # per poll: a build or a scan may start hundreds of short-lived processes
INFO_PER_MIN = 20                   # harmless events shown per minute (the rest is only counted)
GROUP_MAX = 3                       # events of one kind per program/port (the rest is only counted)

REMOTE_PORTS = {22: "Zdalne logowanie (SSH)", 3283: "Apple Remote Desktop", 5900: "Udostępnianie ekranu (VNC)",
                3389: "Pulpit zdalny (RDP)", 5938: "TeamViewer", 6568: "AnyDesk", 7070: "AnyDesk",
                4000: "NoMachine (NX)", 3031: "Zdalne zdarzenia Apple", 23: "Telnet"}
REMOTE_PORTS.update({p: "RustDesk" for p in range(21115, 21120)})
REMOTE_PORTS.update({p: "Serwer VNC (dodatkowy ekran)" for p in range(5901, 5910)})
# AirPlay, Bonjour, Kerberos, iPhone sync: Apple's own LAN chatter
QUIET_PORTS = {53, 67, 88, 137, 138, 5000, 5353, 7000, 62078}

WATCH_DIRS = ["~/Downloads", "~/Desktop", "/Users/Shared", "/private/tmp"]
EXEC_ONLY_DIRS = {"/private/tmp", "/Users/Shared"}      # noisy places: only programs/scripts/installers count
PARTIAL_EXT = (".crdownload", ".download", ".part", ".partial", ".tmp", ".opdownload", ".aria2")
INTERESTING_EXT = (".app", ".dmg", ".pkg", ".mpkg", ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".xz", ".iso",
                   ".command", ".sh", ".py", ".scpt", ".applescript", ".jar", ".js", ".terminal", ".tool",
                   ".dylib", ".so", ".bundle", ".plugin", ".workflow")
PERSIST_DIRS = ["~/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons",
                "/Library/PrivilegedHelperTools", "/Library/StartupItems", "~/Library/StartupItems"]
RC_FILES = ["~/.zshrc", "~/.zprofile", "~/.zshenv", "~/.zlogin", "~/.bashrc", "~/.bash_profile", "~/.profile",
            "~/.config/fish/config.fish"]
RC_BAD = re.compile(r"(?i)\b(curl|wget|base64|osascript|eval|nc|ncat|socat|/dev/tcp|python[0-9.]*\s+-c|"
                    r"launchctl|xattr\s+-[dc]|chmod\s+\+x|nohup|DYLD_INSERT_LIBRARIES)\b")
UPLOAD_STEPS = (100 * MB, 500 * MB, 2 * GB, 10 * GB)

DIM_OF_KIND = {"process": "process", "connection": "network", "inbound": "network", "listen": "network",
               "traffic": "network", "autostart": "persistence", "permission": "permission"}

# guard mode (background protection)
GUARD_POLL_S = 10.0
GUARD_SLOW_S = 120.0
GUARD_WATCH_DIRS = ["/Users/Shared", "/private/tmp"]          # Downloads/Desktop: the file watch has them
GUARD_PERSIST_DIRS = ["/Library/StartupItems", "~/Library/StartupItems"]   # the rest: the file watch
GUARD_TARGET_SCORE = 25             # hand a program to the file scan only after an alarm about it
HOUSEKEEP_S = 3600.0
PERM_S = 300.0
LOG_KEEP_S = 3600.0                 # unified-log events kept for aggregation (password guessing over an hour)
LOG_KEEP_MAX = 5000
# live attack evidence (envscan.live): candidates re-checked every … s, at most … s / probes per poll
LIVE_RECHECK_S = 30.0
GUARD_LIVE_RECHECK_S = 90.0
LIVE_BUDGET_S = 0.3
GUARD_LIVE_BUDGET_S = 0.15
LIVE_MAX_PROBES = 80
GUARD_LIVE_MAX_PROBES = 40
STAGING_WALKS = (0.0, 8.0, 40.0)    # a new temp folder is searched for copied passwords at these ages (s)
STAGING_MAX = 300                   # new temp folders followed at once
STAGING_SKIP = re.compile(r"^(?:cerber-|claude-|com\.apple\.|BlobRegistryFiles-|TemporaryItems$|\.)")
TCC_USER_DB = "~/Library/Application Support/com.apple.TCC/TCC.db"
TCC_SYSTEM_DB = "/Library/Application Support/com.apple.TCC/TCC.db"


def _now() -> str:
    return time.strftime("%H:%M:%S")


def _expand(paths: list[str], home: str) -> list[str]:
    return [os.path.join(home, p[2:]) if p.startswith("~/") else p for p in paths]


def beacon_interval(times: list[float], min_hits: int = 5) -> float | None:
    """Median interval (s) when connection start times are strikingly regular, else None."""
    if len(times) < min_hits:
        return None
    gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
    if len(gaps) < min_hits - 1:
        return None
    med = statistics.median(gaps)
    if not 8 <= med <= 900:
        return None
    mean = statistics.fmean(gaps)
    cv = statistics.pstdev(gaps) / mean if mean else 1.0
    return med if cv < 0.25 else None


def rc_new_lines(old: str, new: str) -> list[str]:
    before = set(old.splitlines())
    return [ln for ln in new.splitlines() if ln.strip() and ln not in before]


def is_partial(name: str) -> bool:
    return name.lower().endswith(PARTIAL_EXT) or name.startswith(".")


def looks_executable(path: str, st: os.stat_result | None = None) -> bool:
    """Programs, scripts and installers (cheap: extension, exec bit, first bytes)."""
    if path.lower().endswith(INTERESTING_EXT):
        return True
    try:
        st = st or os.lstat(path)
        if st.st_mode & 0o111 and not os.path.isdir(path):
            return True
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return head[:2] == b"#!" or head in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


class NetWatch:
    def __init__(self, ctx: EnvContext, emit: Callable[[dict], None], root_pid: int | None = None,
                 poll_s: float | None = None, slow_s: float | None = None, guard: bool = False,
                 inbox: str | None = None):
        self.ctx = ctx
        self.emit = emit
        self.root_pid = root_pid
        self.guard = guard
        self.inbox = inbox
        self.poll_s = poll_s if poll_s is not None else (GUARD_POLL_S if guard else POLL_S)
        self.slow_s = slow_s if slow_s is not None else (GUARD_SLOW_S if guard else SLOW_S)
        self.watch_dirs = GUARD_WATCH_DIRS if guard else WATCH_DIRS
        self.persist_dirs = GUARD_PERSIST_DIRS if guard else PERSIST_DIRS
        self.home = ctx.homes[0].home if ctx.homes else os.path.expanduser("~")
        self.look = _ioc_lookup(ctx)
        self.started = time.time()
        self.started_s = time.strftime("%Y-%m-%d %H:%M:%S")
        self.me = os.getpid()
        self.baseline = False
        # process cache
        self.procs: dict[int, dict] = {}
        self.cerber: dict[int, bool] = {}
        self.sign_cache: dict[str, tuple] = {}
        # seen state
        self.listen_keys: set[tuple] = set()
        self.conn_keys: set[tuple] = set()
        self.sock_keys: set[tuple] = set()
        self.inbound_keys: set[tuple] = set()
        self.session_keys: set[tuple] = set()
        self.beacon_times: dict[tuple, list[float]] = {}
        self.beacon_done: set[tuple] = set()
        self.dir_state: dict[str, dict[str, tuple]] = {}
        self.pending_files: dict[str, tuple] = {}
        self.persist_state: dict[str, dict[str, tuple]] = {}
        self.rc_state: dict[str, tuple] = {}
        self.gateway: tuple | None = None
        self.tx0: dict[int, tuple[int, int]] = {}
        self.tx_last: dict[int, dict] = {}
        self.tx_step: dict[int, int] = {}
        self.tx_box: dict = {}
        self.tx_thread: threading.Thread | None = None
        self.last_slow = 0.0
        self.last_who = 0.0
        # results
        self.events: list[dict] = []
        self.new_public: list[dict] = []
        self.targets: dict[str, str] = {}
        self.limitations: list[str] = []
        self.info_window: list[float] = []
        self.suppressed = 0
        self.similar = 0
        self.group_n: dict[str, int] = {}
        self.n_event = 0
        self.stats = {"connections_new": 0, "public_new": 0, "listening_new": 0, "inbound": 0, "sessions_new": 0,
                      "processes_remote": 0, "uploaded_bytes": 0, "alerts": 0}
        self.polls = 0
        self.alarmed: dict[str, int] = {}          # exe/path -> best score of an event about it
        self.origin_cache: dict[str, dict] = {}     # exe -> provenance (trust tier, download, location …)
        self.exe_dims: dict[str, dict[str, int]] = {}   # exe -> {process|network|persistence|permission: score}
        self.exe_combined: dict[str, int] = {}
        self._qevents: dict | None = None
        # guard mode
        self.last_housekeep = time.time()
        self.last_perm = 0.0
        self.tcc: set[tuple] | None = None
        self.log_raw: list[dict] = []
        self.log_seen: set[tuple] = set()
        self.log_checked: str | None = None
        # live attack evidence (remote shells, secret stores held open) and stealer staging folders
        self.cerber_any: dict[int, bool] = {}
        self.live = LiveSweep(self.home, self._origin, self._ours,
                              recheck_s=GUARD_LIVE_RECHECK_S if guard else LIVE_RECHECK_S,
                              budget_s=GUARD_LIVE_BUDGET_S if guard else LIVE_BUDGET_S,
                              max_probes=GUARD_LIVE_MAX_PROBES if guard else LIVE_MAX_PROBES, prefix=LW,
                              trust_hint=lambda exe: (self.origin_cache.get(exe) or {}).get("trust"))
        self.tmpdir = user_temp_dir()
        self.staging_roots = [self.tmpdir] if self.tmpdir else []
        self.staging_state: dict[str, set[str]] = {}
        self.staging_watch: dict[str, dict] = {}       # new temp folder / zip -> {"first", "walks", "strict"}
        self.staging_done: set[str] = set()
        # reverse DNS of new public peers, off the polling thread (never in guard mode: no network chatter)
        self.hosts: dict[str, str | None] = {}
        self.dns_q: queue.Queue = queue.Queue()
        if not guard:
            threading.Thread(target=self._dns_worker, daemon=True, name="cerber-live-dns").start()

    # ------------------------------------------------------------------ helpers

    def _dns_worker(self) -> None:
        while True:
            ip = self.dns_q.get()
            try:
                host = socket.gethostbyaddr(ip)[0].rstrip(".")
            except Exception:  # noqa: BLE001
                host = None
            self.hosts[ip] = host

    def _resolve(self, ip: str) -> None:
        if self.guard:
            return
        if ip not in self.hosts:
            self.hosts[ip] = None
            self.dns_q.put(ip)

    def _sign(self, exe: str | None):
        if not exe:
            return None, None
        if exe not in self.sign_cache:
            if is_apple_path(exe):
                self.sign_cache[exe] = ("Apple", None)
            elif not os.path.exists(exe):
                self.sign_cache[exe] = ("plik nie istnieje", None)
            else:
                si = self.ctx.sign(exe)
                self.sign_cache[exe] = (signer_label(si), si)
        return self.sign_cache[exe]

    def _origin(self, exe: str | None) -> dict:
        """Provenance of a program (cached): trust tier apple/appstore/devid/pkgmgr/local_build/unknown/untrusted."""
        if not exe:
            return {"trust": "unknown", "label": ""}
        o = self.origin_cache.get(exe)
        if o is None:
            if self._qevents is None:
                self._qevents = quarantine_events(self.home)
            _label, si = self._sign(exe)
            o = origin(exe, si, self.home, qevents=self._qevents)
            if len(self.origin_cache) > 5000:
                self.origin_cache.clear()
            self.origin_cache[exe] = o
        return o

    def _dev(self, exe: str | None, pid: int | None) -> bool:
        """Homebrew tool, local build, or an interpreter running a project / package script."""
        _label, si = self._sign(exe)
        return dev_context(exe, (self.procs.get(pid) or {}).get("cmdline") if pid else None, si, self.home)

    def _status(self, exe: str | None) -> str | None:
        label, si = self._sign(exe)
        if si is not None:
            return si.status
        return "apple" if label == "Apple" else None

    def _proc(self, pid: int | None) -> dict:
        if pid is None:
            return {}
        info = self.procs.get(pid)
        if info is None:
            info = self._fetch(pid) or {}
            if info:
                self.procs[pid] = info
        return info

    @staticmethod
    def _fetch(pid: int) -> dict | None:
        try:
            import psutil
            p = psutil.Process(pid)
            return p.as_dict(attrs=["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"], ad_value=None)
        except Exception:  # noqa: BLE001 - gone / not permitted
            return None

    def _is_cerber(self, pid: int | None) -> bool:
        """Processes started by Cerber itself (this backend: scanner, sandboxes, codesign, AI server …)."""
        if pid is None or pid <= 1:
            return False
        if pid in self.cerber:
            return self.cerber[pid]
        chain, cur, res = [], pid, False
        for _ in range(40):
            if cur in self.cerber:
                res = self.cerber[cur]
                break
            if cur in (self.me, self.root_pid):
                res = True
                break
            chain.append(cur)
            ppid = self._proc(cur).get("ppid")
            if not ppid or ppid <= 1 or ppid == cur:
                break
            cur = ppid
        for c in chain:
            self.cerber[c] = res
        return res

    def _ours(self, pid: int) -> bool:
        """Cerber itself – this watch's lineage and any other Cerber process (a scan reads every file)."""
        return pid == self.me or self._is_cerber(pid) or is_cerber_process(pid, self.procs, self.cerber_any)

    def _auto_target(self, exe: str | None, pid: int | None = None) -> str | None:
        """The file to quarantine for an event about `exe`: never an Apple file or an interpreter – for an
        interpreter it is the script the process runs (when it is a file)."""
        if not exe or not exe.startswith("/"):
            return None
        if interpreter_of(exe):
            sp = script_of((self.procs.get(pid) or {}).get("cmdline")) if pid else None
            return sp if sp and not is_apple_path(sp) and os.path.isfile(sp) else None
        return None if is_apple_path(exe) else exe

    def _event(self, kind: str, title: str, detail: str, signals: list[Signal] | None = None,
               location: str | None = None, extra: dict | None = None, finding: bool = True,
               group: str | None = None, names: list[tuple[str, int]] | None = None,
               attack: str | None = None) -> dict | None:
        """One event. Besides the classic keys every item carries (additive, for the active defense):
        confidence high/medium/low (high = malicious: act), attack (remote_shell, credential_theft, c2, …),
        evidence (short Polish lines), signals (names), target (file to quarantine: an untrusted program or the
        script – never Apple's files or an interpreter), trust (provenance tier of exe) and ioc (threat-list hit)."""
        if group is not None:                      # e.g. a torrent client: report the first few peers, count the rest
            n = self.group_n.get(group, 0)
            self.group_n[group] = n + 1
            if n >= GROUP_MAX:
                self.similar += 1
                return None
        det = combine(signals) if signals else None
        score = det.score if det is not None else 0
        sev = severity_of(det) if det is not None and score > 0 else "info"
        x0 = (extra or {}).get("exe")
        if x0 and score > self.alarmed.get(x0, 0):
            self.alarmed[x0] = score
        if sev == "info":
            now = time.time()
            self.info_window = [t for t in self.info_window if now - t < 60]
            if len(self.info_window) >= INFO_PER_MIN:
                self.suppressed += 1
                return None
            self.info_window.append(now)
        title, detail = self._w(title), self._w(detail)
        self.n_event += 1
        x = dict(extra or {})
        item = {"id": f"ne-{self.n_event}", "time": _now(), "kind": kind, "severity": sev, "score": score,
                "title": title, "detail": detail, "process": x.get("process"), "pid": x.get("pid"),
                "exe": x.get("exe"), "remote": x.get("remote"), "host": x.get("host"), "signer": x.get("signer")}
        meta = event_meta(signals, names)
        if attack:
            meta["attack"] = attack
        target = x["target"] if "target" in x else self._auto_target(x0, x.get("pid"))
        item.update(meta, target=target, trust=self._trust(x0),
                    ioc=any(s.name.endswith(".IocConnection") for s in signals or []))
        if sev not in ("info",):
            self.stats["alerts"] += 1
        if finding and signals and score >= 10:
            self.ctx.add_finding("network_live", title, location or f"{kind} {item['time']}", signals,
                                 {**x, "time": item["time"], "kind": kind, "attack": meta["attack"],
                                  "confidence": meta["confidence"], "target": target})
        if len(self.events) < MAX_EVENTS:
            self.events.append(item)
        self.emit({"ev": "net_event", "item": item})
        ck = target if ("target" in x or (x0 and interpreter_of(x0))) else x0   # a script, not its interpreter
        if ck and score >= 10 and kind in DIM_OF_KIND and not interpreter_of(ck):
            self._correlate(ck, DIM_OF_KIND[kind], score, x)
        return item

    def _trust(self, exe: str | None) -> str | None:
        if not exe or not exe.startswith("/"):
            return None
        try:
            return self._origin(exe).get("trust")
        except Exception:  # noqa: BLE001
            return None

    def _correlate(self, exe: str, dim: str, score: int, extra: dict) -> None:
        """Several independent signals about ONE program (origin, its connections, ports, autostart, permissions)
        are reported together – each alone is usually harmless, together they are not."""
        dims = self.exe_dims.setdefault(exe, {})
        dims[dim] = max(dims.get(dim, 0), score)
        if len(self.exe_dims) > 2000:
            self.exe_dims.clear()
        strong = {d: v for d, v in dims.items() if v >= 15}
        if len(strong) < 2:
            return
        ranked = sorted(strong.values(), reverse=True)
        combined = min(100, ranked[0] + sum(ranked[1:]) // 2)
        if combined < self.exe_combined.get(exe, 0) + 10:
            return
        self.exe_combined[exe] = combined
        names = {"process": "pochodzenie/proces", "network": "sieć", "persistence": "autostart",
                 "permission": "uprawnienia"}
        conf = Confidence.HIGH if combined >= 80 and len(strong) >= 3 else Confidence.MEDIUM
        what = " + ".join(names[d] for d in strong)
        self._event("correlation", f"Kilka sygnałów naraz: {os.path.basename(exe)} ({what})",
                    "ten sam program: " + ", ".join(f"{names[d]} {v}" for d, v in strong.items())
                    + " – osobno zwykle niegroźne, razem wymagają sprawdzenia",
                    [Signal(f"{LW}.Correlated", combined, conf, f"niezależne sygnały o jednym programie: {what}",
                            [exe])], exe, {k: extra.get(k) for k in ("process", "pid", "signer")} | {"exe": exe})
        self._target(exe, "program z kilkoma sygnałami naraz", force=True)

    def _w(self, text: str) -> str:
        """Scan wording → background-protection wording."""
        if not self.guard or not text:
            return text
        return (text.replace("zostanie przeskanowany przed końcem skanu", "zostanie sprawdzony w tle")
                .replace(" w trakcie skanu", " przed chwilą").replace("w trakcie skanu ", "przed chwilą "))

    def _target(self, path: str | None, reason: str, force: bool = False) -> None:
        """A file for the file scan. Guard mode: only right after an alarm about it (or `force`)."""
        if self.guard and not force and self.alarmed.get(path or "", 0) < GUARD_TARGET_SCORE:
            return
        if not path or path in self.targets or len(self.targets) >= MAX_TARGETS:
            return
        if not os.path.exists(path) or is_apple_path(path):
            return
        reason = self._w(reason)
        self.targets[path] = reason
        self.emit({"ev": "watch_target", "path": path, "reason": reason})

    # ------------------------------------------------------------------ collectors

    def _sockets(self) -> list[dict]:
        socks: list[dict] = []
        for proto in ("tcp", "udp"):
            r = run(["/usr/sbin/netstat", "-anvl", "-p", proto], timeout=15)
            if r.ok:
                socks += parse_netstat(r.out)
        return socks

    def _new_pids(self) -> list[int]:
        try:
            import psutil
            pids = psutil.pids()
        except Exception:  # noqa: BLE001
            return []
        alive = set(pids)
        for pid in [p for p in self.procs if p not in alive]:
            self.procs.pop(pid, None)
            self.cerber.pop(pid, None)
        new = [p for p in pids if p not in self.procs]
        out = []
        for pid in new[:MAX_NEW_PIDS if self.baseline else len(new)]:
            info = self._fetch(pid)
            if info:
                self.procs[pid] = info
                out.append(pid)
        return out

    # ------------------------------------------------------------------ poll

    def poll(self) -> None:
        self.polls += 1
        new_pids = self._new_pids()
        socks = self._sockets()
        procs = self.procs
        listening = build_listening(socks, procs)
        conns = build_connections(socks, procs)
        listen_ports = {s["lport"] for s in socks if s.get("state") == "LISTEN" and s.get("lport")}
        inbound = [s for s in socks if s.get("state") == "ESTABLISHED" and s.get("lport") in listen_ports
                   and s.get("remote") not in ("*", "") and not is_loopback(s.get("remote", ""))]
        now = time.time()
        if not self.baseline:
            self._baseline(listening, conns, socks, inbound)
            return
        self._check_processes(new_pids)
        self._check_live()
        self._check_listening(listening)
        self._check_connections(conns, socks, now)
        self._check_inbound(inbound)
        if now - self.last_who >= WHO_S:
            self.last_who = now
            self._check_sessions()
        self._check_persistence()
        self._check_files()
        if now - self.last_slow >= self.slow_s:
            self.last_slow = now
            self._check_gateway()
            self._check_traffic()
        if self.guard:
            self._check_log_inbox()
            if now - self.last_perm >= PERM_S:
                self.last_perm = now
                self._check_permissions()
            if now - self.last_housekeep >= HOUSEKEEP_S:
                self.last_housekeep = now
                self.housekeep()

    def _baseline(self, listening, conns, socks, inbound) -> None:
        for d in listening:
            self.listen_keys.add((d["proto"][:3], d["port"], d.get("pid")))
        for c in conns:
            self.conn_keys.add((c["exe"] or c["process"], c["remote"], c["port"]))
        for s in socks:
            self.sock_keys.add((s.get("pid"), s.get("lport"), s.get("remote"), s.get("rport")))
        for s in inbound:
            self.inbound_keys.add((normalize_ip(s["remote"]), s.get("lport"), s.get("pid")))
        r = run(["/usr/bin/who"], timeout=10)
        for x in parse_who(r.out) if r.ok else []:
            self.session_keys.add((x["user"], x["tty"], x["from"], x["since"]))
        for d in _expand(self.watch_dirs, self.home):
            self.dir_state[d] = self._listdir(d)
        for d in _expand(self.persist_dirs, self.home):
            self.persist_state[d] = self._listdir(d)
        for f in _expand(RC_FILES, self.home):
            self.rc_state[f] = self._rc(f)
        for d in self.staging_roots:
            self.staging_state[d] = set(self._listdir(d))
        self.gateway = self._gateway_now()
        self.last_who = self.last_slow = time.time()
        self._start_nettop()
        if self.guard:
            self.last_perm = time.time()
            self.tcc = self._tcc_grants()
            if self.tcc is None:
                self._check_permissions()               # records the limitation
        self.baseline = True

    # ---- processes

    def _check_processes(self, new_pids: list[int]) -> None:
        fresh = [p for p in new_pids if not self._is_cerber(p) and p != self.me]
        if not fresh:
            return
        judge: dict[int, dict] = {}
        for pid in fresh:
            info = self.procs.get(pid) or {}
            name, exe = info.get("name") or "", info.get("exe") or ""
            tun = classify_tunnel(info.get("cmdline"), name, exe or None)
            if tun and not tun.get("info"):
                self.stats["processes_remote"] += 1
                self._event("process", f"Uruchomiono tunel: {tun['name']}", tun["detail"],
                            [Signal(f"{LW}.Tunnel", tun["score"], Confidence.MEDIUM, tun["detail"],
                                    [tun.get("evidence") or exe or name])],
                            f"pid {pid}", {"process": name, "pid": pid, "exe": exe or None})
                self._target(exe, "tunel uruchomiony w trakcie skanu")
            if exe and not is_apple_path(exe):
                tool = match_remote_tool(f"{name} {exe}")
                if tool and self._sign(exe)[0] != "Apple":
                    self.stats["processes_remote"] += 1
                    self._event("process", f"Uruchomiono program do zdalnego dostępu: {tool[1]}",
                                "program pozwalający sterować tym Makiem na odległość wystartował w trakcie skanu",
                                [Signal(f"{LW}.RemoteTool", 30, Confidence.MEDIUM,
                                        f"{tool[1]} uruchomiony w trakcie skanu", [exe])],
                                f"pid {pid}", {"process": name, "pid": pid, "exe": exe, "signer": self._sign(exe)[0]})
                o = self._origin(exe)
                if o["trust"] in ("untrusted", "unknown"):
                    untrusted = o["trust"] == "untrusted"
                    odd = odd_location(exe, self.home)
                    sigs = origin_signals(o, LW, "program")
                    seen = set()
                    for nm in (name, os.path.basename(exe), os.path.basename(o.get("bundle") or "")):
                        if nm and nm.lower() not in seen:
                            seen.add(nm.lower())
                            sigs += name_signals(nm, LW, "nazwa programu", untrusted=untrusted)
                    if odd and untrusted:
                        sigs.append(Signal(f"{LW}.OddLocationProcess", 25, Confidence.MEDIUM,
                                           f"program uruchomiony z nietypowego miejsca ({', '.join(odd)})", [exe]))
                    if sigs:
                        self._event("process", f"Nowy program niepewnego pochodzenia: {os.path.basename(exe)}",
                                    (o.get("label") or "bez zaufanego podpisu")
                                    + (f"; miejsce: {', '.join(odd)}" if odd else ""),
                                    sigs, f"pid {pid}", {"process": name, "pid": pid, "exe": exe,
                                                         "signer": self._sign(exe)[0]})
                    if untrusted:
                        self._target(exe, "program niepewnego pochodzenia", force=True)
                self._target(exe, "program uruchomiony w trakcie skanu")
            judge[pid] = info
        self._process_heuristics(judge)

    def _process_heuristics(self, judge: dict[int, dict]) -> None:
        """The environment scan's process heuristics, applied to the new processes only."""
        if not judge:
            return
        from .processes import collect_processes
        scratch = EnvContext({"deep": True, "codesign": True})
        scratch.codesign = self.ctx.codesign
        known = dict(judge)
        for info in judge.values():                     # parents give the parent/child checks their context
            pp = info.get("ppid")
            if pp and pp not in known and self.procs.get(pp):
                known[pp] = self.procs[pp]
        scratch._procs = known  # type: ignore[attr-defined]
        try:
            collect_processes(scratch)
        except Exception as exc:  # noqa: BLE001
            self._limit(f"heurystyki procesów nie zadziałały dla nowych procesów: {exc!r}")
            return
        new_exes = {i.get("exe") for i in judge.values() if i.get("exe")}
        for f in scratch.findings:
            loc = f.location
            pid = int(loc[4:]) if loc.startswith("pid ") and loc[4:].isdigit() else None
            if not ((pid is not None and pid in judge) or loc in new_exes):
                continue
            info = judge.get(pid) or next((i for i in judge.values() if i.get("exe") == loc), {})
            d = f.detection
            if self.guard and d.score < 35 and self._origin(info.get("exe")).get("trust") not in ("untrusted",):
                continue                    # a shell or a build tool starting is not news in background protection
            sigs = [Signal(f"{LW}.Process", d.score, d.confidence, d.description, list(d.evidence or [])[:5])]
            self._event("process", f"Nowy proces: {f.title}", d.description, sigs, f"pid {pid}" if pid else loc,
                        {"process": info.get("name"), "pid": info.get("pid"), "exe": info.get("exe")},
                        names=names_from_evidence(d.evidence))

    # ---- live attack evidence (envscan.live): remote shells, secret stores held open

    def _check_live(self) -> None:
        try:
            hits = self.live.run(self.procs)
        except Exception as exc:  # noqa: BLE001 - never let it break the watch
            self._limit(f"sprawdzanie aktywnych ataków (zdalne powłoki, dostęp do haseł) nie zadziałało: {exc!r}")
            return
        self.stats["live_checked"] = self.live.stats["probed"]
        for h in hits:
            exe = h.get("exe")
            extra = {"process": h.get("name"), "pid": h["pid"], "exe": exe, "target": h.get("target"),
                     "signer": self._sign(exe)[0] if exe else None}
            if h.get("peer"):
                extra["remote"] = h["peer"]
            self._event("process", h["title"], h["detail"], h["signals"], f"pid {h['pid']}", extra,
                        attack=h["attack"])
            if h.get("target"):
                self._target(h["target"], "program lub skrypt aktywnego ataku", force=True)

    def _stage(self, path: str, strict: bool, now: float) -> None:
        """Follow a new temp folder / zip for a while: a stealer fills its staging folder over seconds."""
        if path in self.staging_watch or path in self.staging_done or len(self.staging_watch) >= STAGING_MAX:
            return
        if not (path.lower().endswith(".zip") or os.path.isdir(path)) or os.path.islink(path):
            return
        self.staging_watch[path] = {"first": now, "walks": 0, "strict": strict}

    def _check_staging(self, now: float) -> None:
        for d in self.staging_roots:                                  # $TMPDIR: only folder names, no events
            try:
                cur = set(os.listdir(d))
            except OSError:
                continue
            old = self.staging_state.get(d)
            self.staging_state[d] = cur
            if old is None:
                continue
            for name in cur - old:
                if not STAGING_SKIP.match(name):
                    self._stage(os.path.join(d, name), True, now)
        t0 = time.monotonic()
        home_lib = self.home + "/Library/"
        for path, st in list(self.staging_watch.items()):
            if st["walks"] >= len(STAGING_WALKS) or not os.path.lexists(path):
                self.staging_watch.pop(path, None)
                continue
            if now - st["first"] < STAGING_WALKS[st["walks"]] or time.monotonic() - t0 > 0.15:
                continue
            st["walks"] += 1
            label = "folderze tymczasowym użytkownika ($TMPDIR)" if st["strict"] else os.path.dirname(path)
            if path.lower().endswith(".zip"):
                hits = stealer_archive(path, st["strict"])
            else:
                hits = stealer_artifacts(path, 4, label, home_lib, group_by_root=True, max_entries=1500, zips=True,
                                         strict=st["strict"])
            hits = [h for h in hits if h["kind"] != "archive_name"]
            if hits:
                self.staging_watch.pop(path, None)
                self.staging_done.add(path)
                self._staging_event(hits[0], path)

    def _staging_event(self, hit: dict, path: str) -> None:
        names = set(hit.get("names") or [])
        strong = len(names) >= 3 or (bool(names & {"login.keychain-db", "login.keychain"}) and len(names) >= 2)
        base = hit["signals"][0]
        archive = hit["kind"] == "archive"
        sig = Signal(f"{LW}.StealerArchive" if archive else f"{LW}.StealerStaging", 85 if strong else 60,
                     Confidence.HIGH, base.description + " – pojawiły się przed chwilą (kradzież w toku)",
                     list(base.evidence)[:8])
        who = self._who_uses(hit["path"])
        extra: dict = {"exe": None, "target": hit["path"]}
        detail = ("skopiowane: " + ", ".join(hit.get("artefacts") or [])[:300]
                  + " – tak złodziej haseł (stealer) zbiera dane przed wysłaniem")
        if who:
            extra.update(process=who.get("name"), pid=who.get("pid"), exe=who.get("exe"),
                         signer=self._sign(who.get("exe"))[0] if who.get("exe") else None)
            detail += f"; zbiera je: {who.get('name')} (pid {who.get('pid')})"
        short = hit["path"].replace(self.home, "~", 1)
        self._event("file", ("Archiwum ze skradzionymi danymi logowania: " if archive else
                             "Dane logowania skopiowane do folderu tymczasowego: ") + short,
                    detail, [sig], hit["path"], extra, attack="credential_theft")
        self._target(hit["path"], "folder przygotowawczy stealera", force=True)

    def _who_uses(self, path: str) -> dict | None:
        """Which candidate process works in / has files open in a staging folder (the program to stop)."""
        try:
            import psutil
        except ImportError:
            return None
        prefix = path.rstrip("/") + "/"
        t0 = time.monotonic()
        for (pid, _ct), st in list(self.live.state.items()):
            if st.get("skip"):
                continue
            if time.monotonic() - t0 > 0.25:
                break
            try:
                p = psutil.Process(pid)
                cwd = p.cwd() or ""
                used = (cwd + "/").startswith(prefix) or cwd == path or \
                    any(f.path == path or f.path.startswith(prefix) for f in p.open_files())
            except Exception:  # noqa: BLE001
                continue
            if not used:
                continue
            info = self.procs.get(pid) or {"pid": pid}
            cul = culprit_ancestor(ancestry(pid, self.procs), self._origin, self.home)
            return cul[0] if cul and not interpreter_of(info.get("exe") or "") and \
                is_apple_path(info.get("exe") or "") else info
        return None

    # ---- listening sockets

    def _check_listening(self, listening: list[dict]) -> None:
        for d in listening:
            key = (d["proto"][:3], d["port"], d.get("pid"))      # pid: the name may not be known yet
            if key in self.listen_keys:
                continue
            self.listen_keys.add(key)
            if d["exposure"] == "localhost" or self._is_cerber(d.get("pid")):
                continue
            exe, name, port = d.get("exe"), d["process"], d.get("port")
            if exe and is_apple_path(exe) and port not in REMOTE_PORTS and _base(exe or name) not in SCRIPT_NAMES:
                continue                                  # AirPlay, Handoff, sharing daemons (not Apple's python/nc)
            self.stats["listening_new"] += 1
            label, si = self._sign(exe)
            base = _base(exe or name)
            svc = d.get("service") or service_for(port, name, exe)
            where = "z całej sieci (wszystkie interfejsy)" if d["exposure"] == "all" else f"na adresie {d['address']}"
            sigs: list[Signal] = []
            if base in ("nc", "ncat", "netcat", "socat"):
                sigs.append(Signal(f"{LW}.NetcatListen", 45, Confidence.MEDIUM,
                                   f"{base} zaczął nasłuchiwać na porcie {port} – typowa zdalna powłoka", [f"{port}"]))
            if port in BACKDOOR_PORTS:
                sigs.append(Signal(f"{LW}.BackdoorPort", 40, Confidence.MEDIUM,
                                   f"nowy port typowy dla backdoorów: {port}", [f"{name}:{port}"]))
            if port in REMOTE_PORTS or (svc and match_remote_tool(svc)):
                sigs.append(Signal(f"{LW}.RemoteServiceListen", 30, Confidence.MEDIUM,
                                   f"w trakcie skanu zaczęła nasłuchiwać usługa zdalnego dostępu: "
                                   f"{svc or REMOTE_PORTS.get(port)}", [f"{name}:{port}"]))
            status = si.status if si is not None else None
            if status in ("adhoc", "unsigned", "other") and not self._dev(exe, d.get("pid")):
                sigs.append(Signal(f"{LW}.UnsignedListen", 20, Confidence.LOW,
                                   "program bez zaufanego podpisu otworzył port dostępny z sieci", [exe or name]))
            self._event("listen", f"Nowy otwarty port: {name} na porcie {port}" + (f" ({svc})" if svc else ""),
                        f"dostępny {where}", sigs, f"port {port}",
                        {"process": name, "pid": d.get("pid"), "exe": exe, "remote": f"{d['address']}:{port}",
                         "signer": label}, finding=bool(sigs), group=f"listen:{exe or name}")
            self._target(exe, "program, który otworzył port w trakcie skanu")

    # ---- outgoing connections

    def _check_connections(self, conns: list[dict], socks: list[dict], now: float) -> None:
        # beaconing: a new socket instance (new local port) to the same peer counts as one more call
        for s in socks:
            if s.get("state") == "LISTEN" or not s.get("rport") or not is_public_ip(s.get("remote", "")):
                continue
            k = (s.get("pid"), s.get("lport"), s.get("remote"), s.get("rport"))
            if k in self.sock_keys:
                continue
            self.sock_keys.add(k)
            info = self._proc(s.get("pid"))
            who = info.get("exe") or info.get("name") or s.get("pname") or ""
            bk = (who, normalize_ip(s["remote"]))
            if bk in self.beacon_done:
                continue
            times = self.beacon_times.setdefault(bk, [])
            times.append(now)
            del times[:-12]
            iv = beacon_interval(times)
            if iv is not None:
                self._beacon(bk, iv, s, info)
        if len(self.sock_keys) > 200_000:
            self.sock_keys.clear()
        for c in conns:
            key = (c["exe"] or c["process"], c["remote"], c["port"])
            if key in self.conn_keys:
                continue
            self.conn_keys.add(key)
            if self._is_cerber(c.get("pid")):
                continue
            self.stats["connections_new"] += 1
            if not c["public"]:
                continue
            self.stats["public_new"] += 1
            self._resolve(c["remote"])
            label, si = self._sign(c["exe"])
            if len(self.new_public) < MAX_PUBLIC:
                self.new_public.append({"time": _now(), "process": c["process"], "pid": c["pid"], "exe": c["exe"],
                                        "remote": c["remote"], "port": c["port"], "host": None, "signer": label})
            extra = {"process": c["process"], "pid": c["pid"], "exe": c["exe"],
                     "remote": f"{c['remote']}:{c['port']}", "host": self.hosts.get(c["remote"]), "signer": label}
            threat = self.look(c["remote"]) if self.look else None
            if threat:
                ioc = format_ioc(threat)
                if is_shared_ip(c["remote"]):
                    sig = Signal(f"{LW}.IocConnectionShared", 20, Confidence.LOW,
                                 f"połączenie z adresem z listy zagrożeń ({ioc}), ale to adres współdzielony przez "
                                 "sieć CDN – samo trafienie nie dowodzi infekcji", [c["remote"]])
                else:
                    sig = Signal(f"{LW}.IocConnection", 85 if threat.startswith("ThreatFox") else 80, Confidence.HIGH,
                                 f"nowe połączenie z adresem znanym z listy zagrożeń: {ioc}",
                                 [f"{c['remote']}:{c['port']}", c["exe"] or c["process"]])
                self._event("connection", f"Połączenie z adresem z listy zagrożeń: {c['process']} → {c['remote']}",
                            ioc, [sig], f"pid {c['pid']} → {c['remote']}", extra)
                self._target(c["exe"], "proces połączony z adresem z listy zagrożeń")
                continue
            exe = c["exe"]
            if exe and is_apple_path(exe) and _base(exe) not in SCRIPT_NAMES:
                continue
            status = si.status if si is not None else ("apple" if label == "Apple" else None)
            pkg = self._dev(exe, c.get("pid"))
            sigs = script_connection_signals(exe, c["process"], status, pkg, [c])
            odd = odd_location(exe, self.home) if exe and not pkg else []
            if odd and status not in ("apple", "appstore", "devid") and self._origin(exe)["trust"] not in TRUSTED:
                sigs.append(Signal(f"{LW}.OddLocationOnline", 30, Confidence.MEDIUM,
                                   f"program z nietypowego miejsca ({', '.join(odd)}) łączy się z Internetem",
                                   [exe, f"{c['remote']}:{c['port']}"]))
            if sigs:
                self._event("connection", f"Podejrzane połączenie wychodzące: {c['process']} → {c['remote']}:{c['port']}",
                            "; ".join(s.description for s in sigs[:2]), sigs, f"pid {c['pid']} → {c['remote']}", extra,
                            group=f"conn:{exe or c['process']}")
                self._target(exe, "proces z podejrzanym połączeniem")

    def _beacon(self, bk: tuple, iv: float, s: dict, info: dict) -> None:
        exe = info.get("exe")
        name = info.get("name") or s.get("pname") or "?"
        if self._is_cerber(s.get("pid")):
            return
        status = self._status(exe)
        script = _base(exe or name) in SCRIPT_NAMES
        pkg = self._dev(exe, s.get("pid"))
        if (not script and status in ("apple", "appstore", "devid")) or pkg:
            return                                          # signed apps and dev tools poll servers all the time
        self.beacon_done.add(bk)
        remote = normalize_ip(s["remote"])
        self._resolve(remote)
        self._event("connection", f"Regularne połączenia (beaconing): {name} → {remote}",
                    f"łączy się z tym samym adresem co ~{iv:.0f} s – tak zachowują się programy sterowane zdalnie "
                    "(serwer C2)",
                    [Signal(f"{LW}.Beaconing", 35, Confidence.MEDIUM,
                            f"{'skrypt' if script else 'program bez zaufanego podpisu'} łączy się z {remote} "
                            f"regularnie co ~{iv:.0f} s", [f"{remote}:{s.get('rport')}", exe or name])],
                    f"pid {s.get('pid')} → {remote}",
                    {"process": name, "pid": s.get("pid"), "exe": exe, "remote": f"{remote}:{s.get('rport')}",
                     "host": self.hosts.get(remote), "signer": self._sign(exe)[0]})
        self._target(exe, "proces łączący się regularnie z tym samym adresem")

    # ---- inbound connections

    def _check_inbound(self, inbound: list[dict]) -> None:
        for s in inbound:
            remote = normalize_ip(s["remote"])
            key = (remote, s.get("lport"), s.get("pid"))
            if key in self.inbound_keys:
                continue
            self.inbound_keys.add(key)
            port = s.get("lport")
            info = self._proc(s.get("pid"))
            name, exe = info.get("name") or s.get("pname") or "?", info.get("exe")
            if port in QUIET_PORTS or self._is_cerber(s.get("pid")):
                continue
            public = is_public_ip(remote)
            svc = REMOTE_PORTS.get(port) or service_for(port, name, exe)
            remote_svc = port in REMOTE_PORTS or bool(svc and match_remote_tool(svc))
            if not remote_svc and not public and exe and is_apple_path(exe):
                continue                                    # Handoff, AirDrop, Continuity between your own devices
            self.stats["inbound"] += 1
            self._resolve(remote)
            sigs: list[Signal] = []
            if remote_svc:
                sigs.append(Signal(f"{LW}.InboundRemote", 55 if public else 45, Confidence.MEDIUM,
                                   f"ktoś połączył się z tym Makiem przez {svc} z adresu {remote}"
                                   + (" (z Internetu)" if public else " (z sieci lokalnej)"), [f"{remote} → :{port}"]))
                title = f"Ktoś połączył się z Twoim Makiem: {svc} z {remote}"
            elif public:
                sigs.append(Signal(f"{LW}.InboundPublic", 20, Confidence.LOW,
                                   f"połączenie przychodzące z Internetu do {name} (port {port})", [f"{remote} → :{port}"]))
                title = f"Połączenie przychodzące z Internetu: {remote} → {name}:{port}"
            else:
                title = f"Połączenie przychodzące z sieci lokalnej: {remote} → {name}:{port}"
            self._event("inbound", title, svc or f"port {port}", sigs, f"{remote} → :{port}",
                        {"process": name, "pid": s.get("pid"), "exe": exe, "remote": f"{remote}:{s.get('rport')}",
                         "host": self.hosts.get(remote), "signer": self._sign(exe)[0] if exe else None},
                        finding=bool(sigs), group=None if remote_svc else f"in:{exe or name}:{port}")

    # ---- sessions

    def _check_sessions(self) -> None:
        r = run(["/usr/bin/who"], timeout=10)
        if not r.ok:
            return
        for x in parse_who(r.out):
            key = (x["user"], x["tty"], x["from"], x["since"])
            if key in self.session_keys:
                continue
            self.session_keys.add(key)
            if not x["from"]:
                if x["tty"] == "console":
                    self.stats["sessions_new"] += 1
                    self._event("session", f"Nowa sesja na tym Macu: {x['user']}", "zalogowano przy komputerze", None,
                                extra={"process": "loginwindow"})
                continue                                        # a new Terminal tab (ttys…), not a login
            self.stats["sessions_new"] += 1
            self._event("session", f"Nowe zdalne logowanie: {x['user']} z {x['from']}",
                        f"terminal {x['tty']}, od {x['since'] or '?'}",
                        [Signal(f"{LW}.RemoteLogin", 50, Confidence.MEDIUM,
                                f"w trakcie skanu ktoś zalogował się zdalnie jako {x['user']} z {x['from']}",
                                [f"{x['user']}@{x['tty']} z {x['from']}"])],
                        f"sesja {x['tty']}", {"remote": x["from"]})

    # ---- autostart & shell start-up files

    @staticmethod
    def _listdir(d: str) -> dict[str, tuple]:
        out = {}
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    out[e.name] = (st.st_size, st.st_mtime_ns, st.st_mode)
        except OSError:
            pass
        return out

    @staticmethod
    def _rc(path: str) -> tuple:
        try:
            st = os.stat(path)
        except OSError:
            return (None, "")
        try:
            with open(path, errors="replace") as fh:
                body = fh.read(256 << 10)
        except OSError:
            body = ""
        return (st.st_mtime_ns, body)

    def _check_persistence(self) -> None:
        for d, old in self.persist_state.items():
            cur = self._listdir(d)
            if cur == old:
                continue
            self.persist_state[d] = cur
            for name, meta in cur.items():
                if old.get(name) == meta:
                    continue
                path = os.path.join(d, name)
                self._judge_autostart(path, added=name not in old)
        for f, (mt, body) in list(self.rc_state.items()):
            new = self._rc(f)
            if new[0] == mt:
                continue
            self.rc_state[f] = new
            if new[0] is None:
                continue
            lines = rc_new_lines(body, new[1])
            bad = [ln.strip()[:200] for ln in lines if RC_BAD.search(ln)]
            short = "~/" + os.path.relpath(f, self.home)
            if bad:
                self._event("autostart", f"Zmieniono plik startowy powłoki: {short}",
                            f"dopisano polecenia uruchamiane przy każdym otwarciu Terminala: {bad[0]}",
                            [Signal(f"{LW}.ShellRcModified", 40, Confidence.MEDIUM,
                                    f"w trakcie skanu do {short} dopisano podejrzane polecenia", bad[:5])],
                            f, {"exe": f})
            elif lines:
                self._event("autostart", f"Zmieniono plik startowy powłoki: {short}",
                            f"dopisano {len(lines)} " + ("linię" if len(lines) == 1 else "linie" if 2 <= len(lines) % 10 <= 4
                                                         and not 12 <= len(lines) % 100 <= 14 else "linii"),
                            None, extra={"exe": f})

    def _judge_autostart(self, path: str, added: bool) -> None:
        is_plist = path.endswith(".plist")
        prog, args, run_at_load = None, [], False
        if is_plist:
            try:
                with open(path, "rb") as fh:
                    pl = plistlib.load(fh)
                if isinstance(pl, dict):
                    args = [str(a) for a in (pl.get("ProgramArguments") or [])]
                    prog = pl.get("Program") or (args[0] if args else None)
                    run_at_load = bool(pl.get("RunAtLoad") or pl.get("KeepAlive"))
            except Exception:  # noqa: BLE001
                pass
        else:
            prog = path
        sigs = [Signal(f"{LW}.NewAutostart", 15, Confidence.LOW,
                       "w trakcie skanu pojawił się nowy element autostartu" if added
                       else "w trakcie skanu zmieniono element autostartu", [path])]
        label, si = self._sign(prog) if prog else (None, None)
        if prog:
            status = si.status if si is not None else ("apple" if label == "Apple" else None)
            if status in ("adhoc", "unsigned", "other") and not classify_path(prog).has("pkgmgr"):
                sigs.append(Signal(f"{LW}.AutostartUnsigned", 30, Confidence.MEDIUM,
                                   "autostart uruchamia program bez zaufanego podpisu", [prog]))
            odd = odd_location(prog, self.home)
            if odd:
                sigs.append(Signal(f"{LW}.AutostartOddLocation", 25, Confidence.MEDIUM,
                                   f"autostart uruchamia program z nietypowego miejsca ({', '.join(odd)})", [prog]))
            text = " ".join(args)
            if _base(prog) in SCRIPT_NAMES and RC_BAD.search(text):
                sigs.append(Signal(f"{LW}.AutostartScript", 35, Confidence.MEDIUM,
                                   "autostart uruchamia skrypt pobierający lub dekodujący polecenia",
                                   [redact(text, 200)]))
        where = path.replace(self.home, "~", 1)
        self._event("autostart", f"{'Nowy' if added else 'Zmieniony'} element autostartu: {os.path.basename(path)}",
                    (f"uruchamia {prog}" if prog else where) + (" przy starcie" if run_at_load else ""), sigs, path,
                    {"exe": prog or path, "signer": label})
        self._target(path, "nowy element autostartu")
        if prog and prog != path:
            self._target(prog, "program uruchamiany przez nowy autostart")

    # ---- new files

    def _check_files(self) -> None:
        now = time.time()
        for d, old in self.dir_state.items():
            cur = self._listdir(d)
            if cur != old:
                self.dir_state[d] = cur
                for name, meta in cur.items():
                    if name not in old and not is_partial(name):
                        self.pending_files[os.path.join(d, name)] = meta
                    if name not in old and not name.startswith(("cerber-", "claude-")):
                        self._stage(os.path.join(d, name), False, now)      # hidden folders included
            if len(self.pending_files) > 5000:
                self.pending_files.clear()
        self._check_staging(now)
        # report a file once it stopped growing (seen twice with the same size and time)
        for path, meta in list(self.pending_files.items()):
            d = os.path.dirname(path)
            now_meta = self.dir_state.get(d, {}).get(os.path.basename(path))
            if now_meta is None:
                self.pending_files.pop(path, None)
                continue
            if now_meta != meta:
                self.pending_files[path] = now_meta
                continue
            self.pending_files.pop(path, None)
            if d in EXEC_ONLY_DIRS and not looks_executable(path):
                continue
            if "/claude-" in path or os.path.basename(path).startswith("cerber-"):
                continue
            short = path.replace(self.home, "~", 1)
            self._event("file", f"Nowy plik: {os.path.basename(path)}", f"pojawił się w {os.path.dirname(short)} – "
                        "zostanie przeskanowany przed końcem skanu", None, extra={"exe": path}, finding=False)
            self._target(path, "nowy plik w trakcie skanu", force=True)

    # ---- gateway (ARP spoofing)

    @staticmethod
    def _gateway_now() -> tuple | None:
        r = run(["/sbin/route", "-n", "get", "default"], timeout=5)
        if not r.ok:
            return None
        gw = re.search(r"gateway:\s*(\S+)", r.out)
        iface = re.search(r"interface:\s*(\S+)", r.out)
        if not gw:
            return None
        ip = gw.group(1)
        a = run(["/usr/sbin/arp", "-n", ip], timeout=5)
        mac = re.search(r" at ((?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})", a.out or "", re.I) if a.ok else None
        return ip, iface.group(1) if iface else "", mac.group(1).lower() if mac else None

    def _check_gateway(self) -> None:
        cur = self._gateway_now()
        if cur is None or self.gateway is None:
            self.gateway = cur or self.gateway
            return
        ip, iface, mac = cur
        oip, oiface, omac = self.gateway
        if ip == oip and iface == oiface and mac and omac and mac != omac:
            self._event("gateway", f"Zmienił się adres sprzętowy routera ({ip})",
                        f"było {omac}, jest {mac} – inne urządzenie w sieci może podszywać się pod router i "
                        "przechwytywać ruch (ARP spoofing)",
                        [Signal(f"{LW}.GatewayMacChanged", 40, Confidence.MEDIUM,
                                "adres MAC bramy domyślnej zmienił się bez zmiany sieci", [ip, omac, mac])],
                        f"brama {ip}", {"remote": ip})
        self.gateway = cur

    # ---- traffic (nettop)

    def _start_nettop(self) -> None:
        def go() -> None:
            self.tx_box["r"] = run(["/usr/bin/nettop", "-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out"], timeout=25)
        self.tx_box.pop("r", None)
        self.tx_thread = threading.Thread(target=go, daemon=True, name="cerber-live-nettop")
        self.tx_thread.start()

    def _check_traffic(self) -> None:
        if self.tx_thread is not None and self.tx_thread.is_alive():
            return
        r = self.tx_box.get("r")
        rows = parse_nettop(r.out) if r is not None and r.ok else []
        first = not self.tx0
        for row in rows:
            pid = row["pid"]
            out, inn = row["bytes_out"], row["bytes_in"]
            if first:
                self.tx0[pid] = (out, inn)
                continue
            b_out, b_in = self.tx0.get(pid, (0, 0))      # started during the session: everything counts
            d_out, d_in = max(0, out - b_out), max(0, inn - b_in)
            self.tx_last[pid] = {"process": row["name"], "pid": pid, "bytes_out": d_out, "bytes_in": d_in}
            step = sum(1 for s in UPLOAD_STEPS if d_out >= s)
            if step <= self.tx_step.get(pid, 0):
                continue
            self.tx_step[pid] = step
            info = self._proc(pid)
            exe = info.get("exe")
            if self._is_cerber(pid) or not exe:
                continue
            label, si = self._sign(exe)
            status = si.status if si is not None else ("apple" if label == "Apple" else None)
            self.tx_last[pid].update(process=info.get("name") or row["name"], exe=exe, signer=label)
            sigs = exfil_signals(exe, d_out, d_in, status or "error", label or "", self.home) if status else []
            if sigs:
                det = combine(sigs)
                title = ("Możliwy wyciek danych" if det is not None and det.score >= 10 else "Duża wysyłka danych") \
                    + (" od włączenia ochrony" if self.guard else " w trakcie skanu")
                self._event("traffic", f"{title}: {info.get('name') or row['name']} wysłał {fmt_bytes(d_out)}",
                            f"pobrał {fmt_bytes(d_in)}", sigs, f"pid {pid} (ruch na żywo)",
                            {"process": info.get("name") or row["name"], "pid": pid, "exe": exe, "signer": label})
                self._target(exe, "proces wysyłający dużo danych w trakcie skanu")
            elif d_out >= GB and not BENIGN_UPLOADERS.search(exe):
                self._event("traffic", f"Duża wysyłka: {info.get('name') or row['name']} wysłał {fmt_bytes(d_out)}",
                            f"podpis: {label}; zwykle synchronizacja lub kopia zapasowa", None,
                            extra={"process": info.get("name"), "pid": pid, "exe": exe, "signer": label})
        if rows:
            self.stats["uploaded_bytes"] = sum(v["bytes_out"] for v in self.tx_last.values())
        elif r is not None and not self.tx0:
            self._limit("nettop nie zwrócił danych – wysyłki danych w trakcie skanu nie są mierzone")
        self._start_nettop()

    # ---- guard mode: unified log (queried by the unsandboxed parent), privacy permissions, housekeeping

    def _check_log_inbox(self) -> None:
        """Batches `{"from", "to", "texts": [ndjson, …]}` (or `{"error"}`) the parent wrote into `inbox`."""
        if not self.inbox:
            return
        try:
            names = sorted(n for n in os.listdir(self.inbox) if n.endswith(".json"))
        except OSError:
            return
        fresh = False
        for n in names[:20]:
            path = os.path.join(self.inbox, n)
            try:
                with open(path) as fh:
                    batch = json.load(fh)
            except (OSError, ValueError):
                batch = None
            try:
                os.remove(path)
            except OSError:
                pass
            if not isinstance(batch, dict):
                continue
            if batch.get("error"):
                self._limit(f"dziennik systemowy: {str(batch['error'])[:200]}")
                continue
            from .netaudit_deep import parse_log_ndjson
            for text in batch.get("texts") or []:
                self.log_raw += parse_log_ndjson(str(text))
            self.log_checked = str(batch.get("to") or "")[:19] or time.strftime("%Y-%m-%d %H:%M:%S")
            fresh = True
        if fresh:
            self._judge_log()

    def _judge_log(self) -> None:
        """Analyse the last hour (password guessing spans several batches); report only what was not reported."""
        from .netaudit_deep import analyze_syslog
        cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - LOG_KEEP_S))
        uniq = {(e.get("time"), e.get("process"), e.get("pid"), e.get("message")): e for e in self.log_raw
                if e.get("time", "") >= cutoff}                 # overlapping batches count once
        self.log_raw = sorted(uniq.values(), key=lambda e: e["time"])
        del self.log_raw[:-LOG_KEEP_MAX]
        for e in sorted(analyze_syslog(self.log_raw, self.home, keep_score=True)["events"], key=lambda e: e["time"]):
            score = int(e.get("score") or 0)
            remote_ok = e["category"] in ("remote_login", "screen_sharing") and \
                e["title"].startswith(("Zalogowano", "Połączenie udostępniania"))
            if score < LOW_SCORE and not remote_ok:
                continue                                  # XProtect "no threats", single typos, ordinary prompts
            key = (e["category"], e["title"], e["time"])
            if key in self.log_seen:
                continue
            self.log_seen.add(key)
            conf = (Confidence.HIGH if e["severity"] == "malicious" else
                    Confidence.MEDIUM if score >= LOW_SCORE else Confidence.LOW)
            sigs = [Signal(f"{LW}.Log.{e['category']}", score, conf, e["title"], [e["time"]])] if score else None
            when = e["time"][11:19]
            self._event("log", e["title"], f"{e['detail']} · wpis w dzienniku o {when}" if e["detail"] else
                        f"wpis w dzienniku o {when}", sigs, f"dziennik systemowy {e['time']}",
                        {"process": e.get("process") or None}, group=f"log:{e['category']}:{e['title'][:60]}")

    def _tcc_grants(self) -> set[tuple] | None:
        """(service, client, client_type) of granted permissions that let a program watch or steer this Mac;
        None when no TCC database is readable (no Full Disk Access)."""
        import sqlite3
        out: set[tuple] = set()
        readable = False
        for db in (os.path.join(self.home, TCC_USER_DB[2:]), TCC_SYSTEM_DB):
            if not os.path.exists(db):
                continue
            try:
                con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
                try:
                    rows = con.execute("SELECT service, client, client_type, auth_value FROM access").fetchall()
                finally:
                    con.close()
            except sqlite3.Error:
                continue
            readable = True
            for service, client, ctype, auth in rows:
                client = str(client)
                if service not in TCC_SPY or auth != 2 or client.startswith("com.apple."):
                    continue
                if ctype == 1 and is_apple_path(client):
                    continue
                out.add((service, client, int(ctype or 0)))
        return out if readable else None

    def _check_permissions(self) -> None:
        cur = self._tcc_grants()
        if cur is None:
            self._limit("nowe uprawnienia (nagrywanie ekranu, dostępność, odczyt klawiatury) nie są śledzone – "
                        "Cerber nie ma Pełnego dostępu do dysku")
            return
        if self.tcc is None:
            self.tcc = cur
            return
        new = sorted(cur - self.tcc)
        self.tcc = cur
        for service, client, ctype in new[:20]:
            label = TCC_SENSITIVE.get(service, service)
            path = client if ctype == 1 else None
            name = os.path.basename(client) if path else client
            sigs = [Signal(f"{LW}.NewPermission", 15, Confidence.LOW,
                           f"{name} dostał uprawnienie „{label}”", [client])]
            tool = match_remote_tool(client)
            steer = service in ("kTCCServiceScreenCapture", "kTCCServiceAccessibility", "kTCCServicePostEvent",
                                "kTCCServiceListenEvent")
            if tool and steer:
                sigs.append(Signal(f"{LW}.RemoteToolPermission", 25, Confidence.MEDIUM,
                                   f"program do zdalnego dostępu ({tool[1]}) może teraz "
                                   + ("widzieć ekran" if service == "kTCCServiceScreenCapture"
                                      else "sterować myszą i klawiaturą"), [client]))
            label_s = None
            if path:
                label_s, _si = self._sign(path)
                status = self._status(path)
                odd = odd_location(path, self.home)
                if odd and status not in ("apple", "appstore", "devid"):
                    sigs.append(Signal(f"{LW}.NewPermissionOddLocation", 35, Confidence.MEDIUM,
                                       f"program bez zaufanego podpisu z nietypowego miejsca ({', '.join(odd)}) "
                                       f"dostał uprawnienie „{label}”", [path]))
                elif _base(path) in SCRIPT_NAMES:
                    sigs.append(Signal(f"{LW}.NewPermissionScript", 25, Confidence.MEDIUM,
                                       f"interpreter skryptów dostał uprawnienie „{label}” – każdy skrypt uruchomiony "
                                       "nim ma teraz ten dostęp", [path]))
            self._event("permission", f"Nowe uprawnienie: {name} – {label}",
                        "macOS pozwolił temu programowi " + {
                            "kTCCServiceScreenCapture": "nagrywać i udostępniać ekran",
                            "kTCCServiceAccessibility": "sterować komputerem (Dostępność)",
                            "kTCCServiceListenEvent": "odczytywać naciśnięcia klawiszy",
                            "kTCCServicePostEvent": "symulować klawiaturę i mysz",
                            "kTCCServiceSystemPolicyAllFiles": "czytać wszystkie pliki (Pełny dostęp do dysku)",
                            "kTCCServiceMicrophone": "używać mikrofonu",
                            "kTCCServiceCamera": "używać kamery"}.get(service, f"„{label}”")
                        + " – jeśli to nie Ty, cofnij to w Ustawieniach → Prywatność i ochrona",
                        sigs, client, {"process": name, "exe": path, "signer": label_s})
            self._target(path, "program z nowym uprawnieniem prywatności")

    def housekeep(self) -> None:
        """Guard mode runs for days: forget per-hour details, keep what is needed to notice NEW things."""
        now = time.time()
        self.origin_cache.clear()
        self._qevents = None
        self.group_n.clear()
        self.alarmed.clear()
        self.exe_dims.clear()
        self.exe_combined.clear()
        self.cerber_any.clear()
        if len(self.staging_done) > 5_000:
            self.staging_done.clear()
        self.targets.clear()
        self.ctx.findings.clear()
        self.events.clear()
        self.new_public.clear()
        self.suppressed = self.similar = 0
        self.beacon_times = {k: v for k, v in self.beacon_times.items() if v and now - v[-1] < 3600}
        for name, cap in (("conn_keys", 50_000), ("listen_keys", 20_000), ("inbound_keys", 20_000),
                          ("session_keys", 5_000), ("beacon_done", 5_000)):
            if len(getattr(self, name)) > cap:
                getattr(self, name).clear()
        if len(self.sign_cache) > 5_000:
            self.sign_cache.clear()
        cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 2 * LOG_KEEP_S))
        self.log_seen = {k for k in self.log_seen if k[2] >= cutoff}
        if len(self.limitations) > 20:
            del self.limitations[:-20]

    # ------------------------------------------------------------------ status / summary

    def _limit(self, msg: str) -> None:
        msg = self._w(msg)
        if msg not in self.limitations:
            self.limitations.append(msg)

    def status(self, active: bool = True) -> dict:
        st = {"ev": "net_status", "active": active, "since": self.started_s, "polls": self.polls,
              "interval_s": self.poll_s, **self.stats}
        if self.guard:
            st.update(guard=True, log_checked=self.log_checked, permissions=self.tcc is not None,
                      limitations=list(self.limitations))
        return st

    def summary(self) -> dict:
        for c in self.new_public:
            c["host"] = self.hosts.get(c["remote"])
        for e in self.events:
            ip = (e.get("remote") or "").rsplit(":", 1)[0]
            if not e.get("host") and ip in self.hosts:
                e["host"] = self.hosts[ip]
        uploads = sorted((v for v in self.tx_last.values() if v["bytes_out"] > 0),
                         key=lambda v: -v["bytes_out"])[:15]
        lim = list(self.limitations)
        if self.similar:
            lim.append(f"pominięto {self.similar} podobnych zdarzeń (po {GROUP_MAX} na program)")
        if self.suppressed:
            lim.append(f"pominięto {self.suppressed} niegroźnych zdarzeń (limit {INFO_PER_MIN} na minutę)")
        lim.append("monitor sprawdza stan co kilka sekund – bardzo krótkie połączenia (poniżej ~5 s) mogą zostać "
                   "niezauważone; zawartości szyfrowanego ruchu (HTTPS) nie da się podejrzeć")
        return {"started": self.started_s, "ended": time.strftime("%Y-%m-%d %H:%M:%S"),
                "seconds": round(time.time() - self.started), "polls": self.polls, "interval_s": self.poll_s,
                "stats": dict(self.stats), "events": self.events, "new_public": self.new_public,
                "uploads": uploads, "targets": [{"path": p, "reason": r} for p, r in self.targets.items()],
                "limitations": lim}

    def loop(self, stop: threading.Event | None = None) -> None:
        """Poll until `stop` is set or KeyboardInterrupt (the sandbox runner sends SIGINT)."""
        while stop is None or not stop.is_set():
            t0 = time.monotonic()
            try:
                self.poll()
            except KeyboardInterrupt:
                raise
            except Exception as exc:  # noqa: BLE001 - one broken poll must not end the watch
                self._limit(f"błąd monitora: {exc!r}")
            self.emit(self.status(True))
            left = self.poll_s - (time.monotonic() - t0)
            if stop is not None:
                if stop.wait(max(0.2, left)):
                    break
            else:
                time.sleep(max(0.2, left))

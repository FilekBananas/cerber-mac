"""Deep network & behaviour audit (the "Mega" laptop level): system log history, local network, trusted roots.

Three collectors add keys to ``ctx.inventory["network_audit"]`` (the dict of netaudit._audit):

* ``netaudit_syslog`` -> ``["syslog"]``: macOS unified log history (``log show``, read-only, no sudo):
  XProtect Remediator results and XProtect/Gatekeeper malware blocks, Gatekeeper blocks and user overrides,
  remote logins (sshd accepted / failed / invalid users, screen sharing), failed authorizations (wrong
  password at unlock or in admin dialogs), admin rights obtained by non-Apple programs, new Background Task
  Management items (login items / launch agents), privacy (TCC) permission prompts.
* ``netaudit_lan`` -> ``["lan"]``: default gateway, ARP table (the gateway's MAC used by another IP = possible
  ARP spoofing), current Wi-Fi security (open / WEP), IPv6 routers.
* ``netaudit_certs`` -> ``["certificates"]``: root certificates explicitly trusted by the user / admin
  (``security dump-trust-settings``) parsed with ``cryptography``: HTTPS-interception tools, adware CAs, fake
  copies of public CAs, corporate / school inspection, local development CAs.

Cost (measured on macOS 26, 10 cores): the 7-day security query ~9 s, the 1-day privacy query ~12 s, run in
parallel. Predicates use subsystem / category / formatString and ``process == "x" OR …``; never
``process IN {…}`` (≈150 s CPU) and never ``eventMessage CONTAINS`` without a subsystem (minutes).
macOS keeps Default-level messages only until its log store (~500 MB) wraps – on a busy Mac less than a
day – so ``window.persist_since`` reports how far back the detailed history really goes.

Sandbox: ``/usr/bin/log`` refuses to run in ANY sandbox ("Cannot run while sandboxed") and the env profile
denies reading keychain files. The unsandboxed parent therefore runs ``PRECOMPUTE`` (fixed argv) through
``start_precompute(dir)`` in background threads; the sandboxed collectors read the results from
``$CERBER_PRECOMPUTED`` (``<sha1(argv)>.json`` like util.PRECOMPUTED_COMMANDS) and wait for the pending
ones. Without them the collectors degrade and record a limitation.

Inventory shapes (keys English, texts Polish; severities: malicious | suspicious | low | info):

    syslog = {"window": {"from", "to",                        # security query window ("YYYY-MM-DD HH:MM")
                         "days": {"security": 7.0, "privacy": 0.5},
                         "persist_since", "special_since"},   # oldest log file: real reach of the history
              "events": [{"time", "category", "title", "detail", "severity", "process"}],   # ≤ 200, worst first
              "counts": {"xprotect_scans", "xprotect_detections", "xprotect_blocks", "gatekeeper_blocks",
                         "gatekeeper_overrides", "ssh_accepted", "ssh_failed", "screen_sharing_ok",
                         "screen_sharing_failed", "auth_failures", "privileged_authorizations", "new_login_items",
                         "privacy_prompts", "events_total"},
              "available": bool, "reason": str | None}
        event categories: xprotect | gatekeeper | remote_login | screen_sharing | login_failure |
                          authorization | persistence | privacy
    lan = {"gateway": {"ip", "mac", "interface", "mac_randomized"},
           "wifi": {"interface", "connected", "security", "security_level", "security_label", "ssid", "source"},
           "dhcp": {"dhcp_server", "router", "dns", "domain", "router_arp_verified"},
           "arp_entries": int, "arp_suspicious": [{"mac", "ips", "reason"}], "arp_multi_ip": [{"mac", "interface", "ips"}],
           "ipv6_routers": [{"router", "interface", "pref", "expire"}]}
        security_level: open | wep | wpa | wpa2 | wpa3 | enterprise | owe | unknown
    certificates = [{"name", "domain" (user|admin), "trust" (all|ssl|other|deny|unspecified), "policies",
                     "subject", "issuer", "not_before", "not_after", "expired", "is_ca", "self_signed", "sha256",
                     "kind", "tool", "risk", "explanation"}]
        kind: interception_tool | adware | impersonation | enterprise | antivirus_filter | dev | unknown |
              system_duplicate | distrusted
Findings: categories "syslog", "lan" and "certs".

Read-only by design: query commands with timeouts and without a shell, never sudo, no network access.
Texts shown to the user are Polish; keys are English.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import os
import re
import subprocess
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from ..core import Confidence
from .model import LOW_SCORE, MALICIOUS_SCORE, SUSPICIOUS_SCORE, Signal
from .netaudit import _audit, _pl, is_public_ip, odd_location
from .patterns import classify_path, is_apple_path, redact
from .util import CmdResult, EnvContext, precomputed_key, run

SL = "Heur:Env.SysLog"
LN = "Heur:Env.Lan"
CT = "Heur:Env.Certs"
LOG = "/usr/bin/log"
SECURITY = "/usr/bin/security"
MAX_EVENTS = 200
LOG_STORE = "/private/var/db/diagnostics"
MANIFEST = "netaudit_deep.pending.json"

# --------------------------------------------------------------------------- unified log queries

SSH_PROCS = ("sshd", "sshd-session", "sshd-auth")
_SEC_PRED = (
    'category == "XPEvent.structured"'
    ' OR (subsystem BEGINSWITH "com.apple.syspolicy" AND (formatString CONTAINS "alware"'
    ' OR formatString CONTAINS "Gatekeeper rejection" OR formatString BEGINSWITH "Prompting user about"'
    ' OR formatString BEGINSWITH "Adding user intent" OR formatString CONTAINS "override"'
    ' OR formatString BEGINSWITH "Blocking " OR formatString BEGINSWITH "Marking item blocked"'
    ' OR formatString BEGINSWITH "Displaying XProtect blocked prompt"))'
    ' OR (subsystem == "com.apple.backgroundtaskmanagement" AND (formatString BEGINSWITH "registerLaunchItem: result="'
    ' OR formatString BEGINSWITH "addItem: %{public}@"))'
    ' OR (subsystem == "com.apple.Authorization" AND (formatString BEGINSWITH "Failed to authorize right"'
    ' OR formatString BEGINSWITH "Succeeded authorizing right"))'
    + "".join(f' OR process == "{p}"' for p in SSH_PROCS + ("screensharingd",))
)
_PRIV_PRED = 'subsystem == "com.apple.TCC" AND formatString BEGINSWITH "AUTHREQ_PROMPTING"'
# key -> (window, predicate, timeout s, window in days for the report)
LOG_QUERIES: dict[str, tuple[str, str, float, float]] = {
    "security": ("7d", _SEC_PRED, 75.0, 7.0),
    "privacy": ("12h", _PRIV_PRED, 45.0, 0.5),     # tccd is very chatty: ~1 s CPU per hour of history
}


def log_argv(window: str, predicate: str) -> list[str]:
    return [LOG, "show", "--style", "ndjson", "--no-backtrace", "--last", window, "--predicate", predicate]


CERT_ARGV = [SECURITY, "find-certificate", "-a", "-Z", "-p"]
TRUST_ARGV = {"user": [SECURITY, "dump-trust-settings"], "admin": [SECURITY, "dump-trust-settings", "-d"]}
SYSTEM_ROOTS = "/System/Library/Keychains/SystemRootCertificates.keychain"
ROOTS_ARGV = [SECURITY, "find-certificate", "-a", "-Z", SYSTEM_ROOTS]
ANCHORS = "/System/Library/Security/Certificates.bundle/Contents/Resources/Anchors"

# what the unsandboxed parent runs for the Mega level (argv, timeout). It starts with the env scan and runs in
# the background while the other collectors work, so the log queries get a more generous timeout there.
PRECOMPUTE: list[tuple[list[str], float]] = (
    [(log_argv(w, p), t * 2.4 if k == "security" else t * 2) for k, (w, p, t, _) in LOG_QUERIES.items()]
    + [(CERT_ARGV, 30.0)] + [(a, 20.0) for a in TRUST_ARGV.values()]
)


class _Precompute:
    """Handle returned by start_precompute(): join() waits, cancel() kills the running commands."""

    def __init__(self) -> None:
        self.threads: list[threading.Thread] = []
        self.procs: list[subprocess.Popen] = []
        self.lock = threading.Lock()
        self.cancelled = False

    def join(self, timeout: float | None = None) -> None:
        end = None if timeout is None else time.monotonic() + timeout
        for t in self.threads:
            t.join(None if end is None else max(0.0, end - time.monotonic()))

    def cancel(self) -> None:
        with self.lock:
            self.cancelled = True
            procs = list(self.procs)
        for p in procs:
            try:
                p.kill()
            except OSError:
                pass


def _write_json(path: str, data: dict) -> None:
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with open(tmp, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, path)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


def start_precompute(pre_dir: str, commands: list[tuple[list[str], float]] | None = None) -> _Precompute:
    """Run PRECOMPUTE in background threads of the UNSANDBOXED parent (Mega level only).

    Usage in the parent, before starting the sandboxed env scan with CERBER_PRECOMPUTED=pre_dir:
        h = netaudit_deep.start_precompute(pre_dir)
        try: run_inner(...)
        finally: h.cancel()
    Results land as <precomputed_key(argv)>.json ({rc, out, err, timed_out, missing}); a manifest lists the
    pending keys so the sandboxed collectors know what to wait for (and until when)."""
    cmds = list(commands if commands is not None else PRECOMPUTE)
    h = _Precompute()
    os.makedirs(pre_dir, exist_ok=True)
    deadline = time.time() + max((t for _, t in cmds), default=0) + 15
    _write_json(os.path.join(pre_dir, MANIFEST), {"keys": [precomputed_key(a) for a, _ in cmds], "deadline": deadline})

    def one(argv: list[str], timeout: float) -> None:
        out_path = os.path.join(pre_dir, precomputed_key(argv) + ".json")
        res = {"rc": None, "out": "", "err": "", "timed_out": False, "missing": False}
        try:
            with h.lock:
                if h.cancelled:
                    return
                p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                     env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"},
                                     close_fds=True)
                h.procs.append(p)
            try:
                out, err = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                p.kill()
                out, err = p.communicate()
                res["timed_out"] = True
            res.update(rc=None if res["timed_out"] else p.returncode, out=out.decode("utf-8", "replace"),
                       err=err.decode("utf-8", "replace"))
        except OSError as e:
            res.update(missing=True, err=f"{type(e).__name__}: {e}")
        _write_json(out_path, res)

    for argv, timeout in cmds:
        t = threading.Thread(target=one, args=(list(argv), float(timeout)), daemon=True, name="cerber-precompute")
        t.start()
        h.threads.append(t)
    return h


def _precomputed(argv: list[str], max_wait: float = 120.0) -> CmdResult | None:
    """Result prepared by the parent (start_precompute); waits while the manifest lists it as pending."""
    pre = os.environ.get("CERBER_PRECOMPUTED")
    if not pre:
        return None
    key = precomputed_key(argv)
    path = os.path.join(pre, key + ".json")
    deadline = None
    while True:
        if os.path.exists(path):
            try:
                with open(path) as fh:
                    d = json.load(fh)
                return CmdResult(list(argv), d.get("rc"), d.get("out", ""), d.get("err", ""),
                                 timed_out=d.get("timed_out", False), missing=d.get("missing", False))
            except (OSError, ValueError):
                return None
        if deadline is None:
            try:
                with open(os.path.join(pre, MANIFEST)) as fh:
                    man = json.load(fh)
            except (OSError, ValueError):
                return None
            if key not in (man.get("keys") or []):
                return None
            deadline = min(float(man.get("deadline") or 0), time.time() + max_wait)
        if time.time() >= deadline:
            return None
        time.sleep(0.25)


def _cmd(argv: list[str], timeout: float, max_wait: float = 120.0) -> CmdResult:
    r = _precomputed(argv, max_wait)
    return r if r is not None else run(argv, timeout=timeout)


def _sandbox_refused(r: CmdResult) -> bool:
    return "cannot run while sandboxed" in (r.err + r.out[:200]).lower()


# --------------------------------------------------------------------------- log parsing (pure)

def parse_log_ndjson(text: str) -> list[dict]:
    """`log show --style ndjson` -> [{time, process, pid, subsystem, category, format, message, level}]."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict) or "eventMessage" not in d or d.get("eventType", "logEvent") != "logEvent":
            continue
        out.append({"time": str(d.get("timestamp") or "")[:19],
                    "process": os.path.basename(str(d.get("processImagePath") or "")),
                    "pid": d.get("processID"), "subsystem": d.get("subsystem") or "",
                    "category": d.get("category") or "", "format": d.get("formatString") or "",
                    "message": str(d.get("eventMessage") or ""), "level": d.get("messageType") or ""})
    return out


def _private(s: str | None) -> str:
    s = (s or "").strip()
    return "nazwa ukryta przez macOS" if not s or s in ("<private>", "(null)") else redact(s, 200)


_PST = re.compile(r"PST: \(path: [^)]*\), \(team: (\(null\)|[^)]*)\), \(id: (\(null\)|[^)]*)\), "
                  r"\(bundle_id: (\(null\)|[^)]*)\)")


def _subject_of(msg: str) -> str:
    """The program a Gatekeeper / XProtect line is about (identifier, path or 'hidden')."""
    m = _PST.search(msg)
    if m:
        team, ident, bundle = (x if x not in ("(null)", "NOT_A_BUNDLE") else "" for x in m.groups())
        name = bundle or ident
        return (name + (f" (zespół {team})" if team else "")) if name else "nazwa ukryta przez macOS"
    tail = msg.split(": ", 1)[1] if ": " in msg else ""
    tail = re.split(r",\s*(?:trashed URL is|\d)", tail)[0]
    return _private(tail)


# XProtect Remediator: status messages of a clean run
XPR_CLEAN = {"NoThreatDetected", "Success"}
XP_REMOVED = ("Successfully moved malware to trash", "Successfully moved scripted malware to trash")
XP_BLOCKED = ("Attempting to move malware to trash", "Error moving malware to trash", "Error moving scripted malware",
              "Staged malware", "Recorded malware block", "Terminating process due to Malware rejection",
              "Displaying XProtect blocked prompt", "Unable to create URL for staging malware")
GK_BLOCK = ("Prompting user about blocked executable", "Prompting user about blocking library",
            "Terminating process due to Gatekeeper rejection", "Terminated process due to Gatekeeper rejection",
            "Marking item blocked", "Blocking package", "Blocking %@ with PID", "Non-notarized kext blocked")
GK_OVERRIDE = ("Adding user intent", "Attempt to add gatekeeper persistent identifier override",
               "Allow script exec for %@ due to override", "Updating flags on pre-existing cache entry to indicate override")

_SSH_ACCEPT = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port (\d+)")
_SSH_FAIL = re.compile(r"Failed (\S+) for (?:invalid user )?(\S*) from (\S+) port (\d+)")
_SSH_INVALID = re.compile(r"Invalid user (\S*) from (\S+) port (\d+)")
_SSH_PAM = re.compile(r"(?i)PAM: authentication (?:error|failure) for (?:illegal user )?(\S+) from (\S+)")
_SSH_MAX = re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(\S*) from (\S+) port")
_VNC_USER = re.compile(r"User Name: (.*?)\s*(?:::|$)")
_VNC_ADDR = re.compile(r"Viewer Address: ([^\s:]+(?::[0-9a-fA-F:.]+)?)")
_AUTH_RX = re.compile(r"(Failed to authorize|Succeeded authorizing) right '([^']*)' by client '([^']*)' \[(\d+)\] for "
                      r"authorization created by '([^']*)' \[(\d+)\] \(([0-9A-Fa-f]+),(\d+)\)(?: \((-?\d+)\))?")
_TCC_RX = re.compile(r"AUTHREQ_PROMPTING: msgID=([^,]*), service=(\w+), subject=(.*)")

ERR_AUTH_DENIED = -60005       # wrong password / not allowed
LOGIN_RIGHTS = re.compile(r"^(system\.login\.|use-login-window-ui|authenticate-|system\.privilege\.admin$|"
                          r"system\.preferences|system\.services\.directory\.configure|system\.install\.)")
PRIV_RIGHTS = re.compile(r"^(system\.privilege\.(admin|taskport)|com\.apple\.ServiceManagement\.(blesshelper|daemons\.modify)|"
                         r"system\.install\.(root\.user|software)|config\.modify\.|system\.preferences\.security|"
                         r"com\.apple\.security\.assessment\.update|system\.keychain\.modify)")
SCRIPT_CLIENTS = {"osascript", "python", "python3", "perl", "ruby", "bash", "sh", "zsh", "node", "AppleScript Runner",
                  "Script Editor", "osacompile", "curl"}

TCC_SENSITIVE = {
    "kTCCServiceScreenCapture": "Nagrywanie ekranu",
    "kTCCServiceAccessibility": "Dostępność (sterowanie komputerem)",
    "kTCCServiceListenEvent": "Monitorowanie wprowadzania (odczyt klawiatury)",
    "kTCCServicePostEvent": "Symulowanie klawiatury i myszy",
    "kTCCServiceSystemPolicyAllFiles": "Pełny dostęp do dysku",
    "kTCCServiceMicrophone": "Mikrofon",
    "kTCCServiceCamera": "Kamera",
    "kTCCServiceAppleEvents": "Automatyzacja (sterowanie innymi aplikacjami)",
    "kTCCServiceSystemPolicyDocumentsFolder": "Folder Dokumenty",
    "kTCCServiceSystemPolicyDesktopFolder": "Folder Biurko",
    "kTCCServiceSystemPolicyDownloadsFolder": "Folder Pobrane",
    "kTCCServiceEndpointSecurityClient": "Rozszerzenie bezpieczeństwa (Endpoint Security)",
}
TCC_SPY = {"kTCCServiceScreenCapture", "kTCCServiceAccessibility", "kTCCServiceListenEvent", "kTCCServicePostEvent",
           "kTCCServiceSystemPolicyAllFiles", "kTCCServiceMicrophone", "kTCCServiceCamera"}

BTM_SKIP_TYPES = {"spotlight", "quicklook", "dock tile plugin", "screen saver", "developer", "curated"}


def parse_btm_item(desc: str) -> dict:
    """BTM item description 'uuid=…, name=…, type=…, disposition=[…], identifier=…, url=…'."""
    d: dict = {}
    for key in ("uuid", "name", "type", "identifier"):
        m = re.search(rf"(?:^|, ){key}=(.*?)(?=, (?:uuid|name|type|disposition|identifier|url)=|$)", desc)
        if m:
            d[key] = m.group(1).strip()
    m = re.search(r"disposition=\[([^\]]*)\]", desc)
    if m:
        d["disposition"] = m.group(1)
    m = re.search(r"url=(.*)$", desc)
    if m:
        url = m.group(1).strip()
        rel, _, base = url.partition(" -- ")
        path = ""
        if base:
            path = urllib.parse.unquote(urllib.parse.urlparse(base).path).rstrip("/") + "/" + urllib.parse.unquote(rel)
        elif url.startswith("file://"):
            path = urllib.parse.unquote(urllib.parse.urlparse(url).path)
        elif url not in ("(null)", "<private>"):
            path = url
        d["path"] = path.rstrip("/") or None
    return d


def _host_scope(addr: str) -> str:
    try:
        a = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return "unknown"
    if a.is_loopback:
        return "local"
    return "public" if is_public_ip(str(a)) else "lan"


def _sev(score: int, conf: Confidence = Confidence.MEDIUM) -> str:
    if score >= MALICIOUS_SCORE and conf >= Confidence.HIGH:
        return "malicious"
    if score >= SUSPICIOUS_SCORE:
        return "suspicious"
    if score >= LOW_SCORE:
        return "low"
    return "info"


def _ev(time_: str, category: str, title: str, detail: str, score: int, conf: Confidence = Confidence.MEDIUM,
        process: str = "") -> dict:
    return {"time": time_, "category": category, "title": title, "detail": detail, "severity": _sev(score, conf),
            "process": process, "_score": score}


def analyze_syslog(raw: list[dict], home: str | None = None, keep_score: bool = False) -> dict:
    """Pure analysis of parsed log events. Returns {"events", "counts", "findings"} where findings are
    (title, location, [Signal], details) tuples ready for ctx.add_finding("syslog", …). `keep_score`: events
    also carry their "score" (the background network guard decides with it what to report)."""
    counts = {k: 0 for k in ("xprotect_scans", "xprotect_detections", "xprotect_blocks", "gatekeeper_blocks",
                             "gatekeeper_overrides", "ssh_accepted", "ssh_failed", "screen_sharing_ok",
                             "screen_sharing_failed", "auth_failures", "privileged_authorizations",
                             "new_login_items", "privacy_prompts")}
    events: list[dict] = []
    findings: list[tuple] = []
    seen: set = set()
    ssh_fail: dict[str, list[dict]] = {}
    ssh_ok: list[dict] = []
    vnc_fail: dict[str, list[dict]] = {}
    vnc_ok: list[dict] = []
    auth_fail: list[dict] = []
    priv_auth: dict[str, dict] = {}
    xpr_hits: list[dict] = []
    xp_incidents: list[dict] = []
    gk_blocks: list[dict] = []
    gk_overrides: list[dict] = []
    btm_items: dict[str, dict] = {}
    tcc: dict[tuple, dict] = {}
    xpr_last = ""
    xpr_plugins: set[str] = set()

    for e in raw:
        fmt, msg, proc, t = e.get("format", ""), e.get("message", ""), e.get("process", ""), e.get("time", "")
        sub = e.get("subsystem", "")
        # ---- XProtect Remediator scan results
        if e.get("category") == "XPEvent.structured":
            try:
                j = json.loads(msg)
            except ValueError:
                continue
            if not isinstance(j, dict):
                continue
            status = str(j.get("status_message") or "")
            caused = j.get("caused_by") or []
            plugin = re.sub(r"^XProtectRemediator", "", proc) or proc or "XProtect"
            if status in XPR_CLEAN and not caused:
                counts["xprotect_scans"] += 1
                xpr_last = max(xpr_last, t)
                xpr_plugins.add(plugin)
                continue
            if caused or (re.search(r"(?i)threat|remediat|malware|infect|quarantin|detect", status)
                          and status != "NoThreatDetected"):
                remediated = bool(re.search(r"(?i)remediat|removed|deleted|quarantined", status)) \
                    and not re.search(r"(?i)fail|unable|error|not ", status)
                what = [redact(json.dumps(c, ensure_ascii=False) if not isinstance(c, str) else c, 200)
                        for c in caused[:5]]
                xpr_hits.append({"time": t, "plugin": plugin, "status": status, "remediated": remediated,
                                 "caused_by": what})
            continue
        # ---- XProtect (syspolicyd) malware blocks / removals
        if sub.startswith("com.apple.syspolicy"):
            if fmt.startswith(XP_REMOVED) or fmt.startswith(XP_BLOCKED):
                removed = fmt.startswith(XP_REMOVED)
                inc = xp_incidents[-1] if xp_incidents else None
                ts = _ts(t)
                if inc is None or ts is None or inc["_ts"] is None or abs(ts - inc["_ts"]) > 120:
                    inc = {"time": t, "_ts": ts, "removed": False, "subjects": [], "lines": 0}
                    xp_incidents.append(inc)
                inc["removed"] |= removed
                inc["lines"] += 1
                subj = _subject_of(msg)
                if subj not in inc["subjects"] and len(inc["subjects"]) < 5:
                    inc["subjects"].append(subj)
                continue
            if fmt.startswith(GK_BLOCK) or fmt.startswith(GK_OVERRIDE):
                override = fmt.startswith(GK_OVERRIDE)
                subj = _subject_of(msg)
                key = ("gk", override, subj, t[:16])
                if key in seen:
                    continue
                seen.add(key)
                (gk_overrides if override else gk_blocks).append({"time": t, "subject": subj})
            continue
        # ---- Background Task Management: new login items / launch agents
        if sub == "com.apple.backgroundtaskmanagement":
            m = re.search(r"new item=(.*)$", msg) if fmt.startswith("registerLaunchItem: result=") else \
                re.match(r"addItem: (.*) uid=(\d+)$", msg)
            if not m or m.group(1).strip() in ("(null)", ""):
                continue
            item = parse_btm_item(m.group(1))
            typ = (item.get("type") or "").lower()
            ident = item.get("identifier") or item.get("name") or item.get("path") or "?"
            path = item.get("path") or ""
            apple_name = bool(re.match(r"^(?:\d+\.)?com\.apple\.", ident))
            if typ in BTM_SKIP_TYPES or (apple_name and (not path or is_apple_path(path)
                                                          or path.startswith(("/Applications/", "/System/")))):
                continue
            item["apple_name"] = apple_name
            item["time"] = t
            btm_items.setdefault(ident, item)
            continue
        # ---- admin authorizations / failed passwords (authd)
        if sub == "com.apple.Authorization":
            m = _AUTH_RX.search(msg)
            if not m:
                continue
            ok = m.group(1).startswith("Succeeded")
            right, client, creator = m.group(2), m.group(3), m.group(5)
            code = int(m.group(9)) if m.group(9) else None
            if not ok:
                if code == ERR_AUTH_DENIED and LOGIN_RIGHTS.match(right):
                    auth_fail.append({"time": t, "right": right, "client": client})
                continue
            if PRIV_RIGHTS.match(right):
                who = creator if creator and not is_apple_path(creator) else client
                if is_apple_path(who) and os.path.basename(who) not in SCRIPT_CLIENTS:
                    continue
                cur = priv_auth.setdefault(who, {"client": who, "rights": [], "first": t, "last": t, "count": 0})
                cur["count"] += 1
                cur["last"] = t
                if right not in cur["rights"]:
                    cur["rights"].append(right)
            continue
        # ---- privacy permission prompts (TCC)
        if sub == "com.apple.TCC":
            m = _TCC_RX.search(msg)
            if not m or m.group(2) not in TCC_SENSITIVE:
                continue
            subj = m.group(3)
            ident = (re.search(r"identifier=([^,}]+)", subj) or re.search(r"Sub:\{([^}]+)\}", subj))
            path = re.search(r"binary_path=([^,}]+)", subj)
            key = (m.group(2), ident.group(1) if ident else "?")
            if key[1].startswith("pl.cerber"):
                continue                      # Cerber's own prompts (scanning Desktop / Downloads …)
            tcc.setdefault(key, {"time": t, "service": m.group(2), "client": key[1],
                                 "path": path.group(1).strip() if path else None})
            continue
        # ---- remote logins: sshd / screen sharing
        if proc in SSH_PROCS:
            if (m := _SSH_ACCEPT.search(msg)):
                ssh_ok.append({"time": t, "method": m.group(1), "user": m.group(2), "from": m.group(3)})
            elif (m := _SSH_FAIL.search(msg)):
                if m.group(1) != "none":
                    ssh_fail.setdefault(m.group(3), []).append({"time": t, "user": m.group(2)})
            elif (m := _SSH_INVALID.search(msg)) or (m := _SSH_MAX.search(msg)):
                ssh_fail.setdefault(m.group(2), []).append({"time": t, "user": m.group(1)})
            elif (m := _SSH_PAM.search(msg)):
                ssh_fail.setdefault(m.group(2), []).append({"time": t, "user": m.group(1)})
            continue
        if proc == "screensharingd":
            addr = (_VNC_ADDR.search(msg) or [None, "?"])[1]
            user = ((_VNC_USER.search(msg) or [None, ""])[1] or "").strip()
            if re.search(r"Authentication: SUCCEEDED", msg):
                vnc_ok.append({"time": t, "from": addr, "user": user})
            elif re.search(r"(?i)Authentication: FAILED|authentication or authorization failure", msg):
                vnc_fail.setdefault(addr, []).append({"time": t, "user": user})

    # ================================================================ events & findings
    # XProtect Remediator
    for h in xpr_hits:
        counts["xprotect_detections"] += 1
        score = 70 if h["remediated"] else 85
        conf = Confidence.MEDIUM if h["remediated"] else Confidence.HIGH
        title = f"XProtect Remediator {'usunął' if h['remediated'] else 'wykrył'} zagrożenie: {h['plugin']}"
        detail = (f"Wbudowany antywirus Apple (moduł {h['plugin']}) zgłosił: {h['status']}"
                  + (f"; elementy: {', '.join(h['caused_by'][:3])}" if h["caused_by"] else ""))
        events.append(_ev(h["time"], "xprotect", title, detail, score, conf, "XProtectRemediator" + h["plugin"]))
        findings.append((title, f"XProtect Remediator {h['plugin']} ({h['time']})",
                         [Signal(f"{SL}.XProtectRemediator", score, conf,
                                 ("Apple XProtect Remediator znalazł i usunął złośliwe oprogramowanie – komputer był "
                                  "zainfekowany; sprawdź, skąd pochodziło i zmień hasła"
                                  if h["remediated"] else
                                  "Apple XProtect Remediator wykrył złośliwe oprogramowanie na tym Macu"),
                                 [h["time"], h["status"]] + h["caused_by"][:3])],
                         {"time": h["time"], "plugin": h["plugin"], "status": h["status"],
                          "remediated": h["remediated"], "caused_by": h["caused_by"]}))
    if xpr_last and not xpr_hits:
        n = counts["xprotect_scans"]
        events.append(_ev(xpr_last, "xprotect", "XProtect Remediator: skanowanie bez wykryć",
                          f"{n} {_pl(n, 'wynik', 'wyniki', 'wyników')} skanowania ({len(xpr_plugins)} "
                          f"{_pl(len(xpr_plugins), 'moduł', 'moduły', 'modułów')} wykrywania) – żadnego zagrożenia; "
                          "ostatnio", 0, process="XProtectRemediator"))
        events[-1]["detail"] += f" {xpr_last}"
    # XProtect blocks at launch (syspolicyd)
    for inc in xp_incidents:
        counts["xprotect_blocks"] += 1
        subj = ", ".join(inc["subjects"]) or "nazwa ukryta przez macOS"
        title = "XProtect zablokował złośliwy program" + (" i przeniósł go do Kosza" if inc["removed"] else "")
        events.append(_ev(inc["time"], "xprotect", title, f"Plik: {subj}. Wbudowany antywirus Apple rozpoznał "
                          "złośliwe oprogramowanie przy próbie otwarcia.", 60, process="syspolicyd"))
        findings.append((title, f"XProtect ({inc['time']})",
                         [Signal(f"{SL}.XProtectBlocked", 60, Confidence.MEDIUM,
                                 "XProtect (antywirus Apple) rozpoznał złośliwy plik przy próbie uruchomienia – "
                                 "sprawdź, skąd pochodził, i usuń go także z Pobranych / Kosza",
                                 [inc["time"], subj])],
                         {"time": inc["time"], "subjects": inc["subjects"], "moved_to_trash": inc["removed"]}))
    # Gatekeeper
    for b in gk_blocks:
        counts["gatekeeper_blocks"] += 1
        events.append(_ev(b["time"], "gatekeeper", "Gatekeeper zablokował otwarcie programu",
                          f"Program: {b['subject']} (brak podpisu lub notaryzacji Apple)", 8, process="syspolicyd"))
    for o in gk_overrides:
        counts["gatekeeper_overrides"] += 1
        events.append(_ev(o["time"], "gatekeeper", "Otwarto program mimo ostrzeżenia Gatekeeper",
                          f"Program: {o['subject']} – użytkownik zezwolił na uruchomienie niepodpisanego lub "
                          "nienotaryzowanego programu", 15, process="syspolicyd"))
    if gk_overrides:
        n = len(gk_overrides)
        findings.append((f"Otwarto {n} {_pl(n, 'program', 'programy', 'programów')} mimo ostrzeżenia Gatekeeper",
                         "Gatekeeper (syspolicyd)",
                         [Signal(f"{SL}.GatekeeperOverride", 15, Confidence.LOW,
                                 "ktoś zezwolił na uruchomienie programu, który Gatekeeper zablokował (brak podpisu lub "
                                 "notaryzacji) – tak instaluje się wiele złośliwych programów; upewnij się, że to Ty",
                                 [f"{o['time']} {o['subject']}" for o in gk_overrides[:5]])],
                         {"overrides": gk_overrides[:50]}))
    if gk_blocks:
        n = len(gk_blocks)
        findings.append((f"Gatekeeper zablokował {n} {_pl(n, 'program', 'programy', 'programów')}",
                         "Gatekeeper (syspolicyd)",
                         [Signal(f"{SL}.GatekeeperBlock", 5, Confidence.LOW,
                                 "Gatekeeper nie pozwolił otworzyć programu bez podpisu / notaryzacji (ochrona zadziałała)",
                                 [f"{b['time']} {b['subject']}" for b in gk_blocks[:5]])],
                         {"blocks": gk_blocks[:50]}))
    # SSH
    for ok in ssh_ok:
        counts["ssh_accepted"] += 1
        scope = _host_scope(ok["from"])
        prior = len(ssh_fail.get(ok["from"], []))
        score = 80 if prior >= 10 else (25 if scope == "public" else 3)
        conf = Confidence.HIGH if prior >= 10 else Confidence.MEDIUM
        events.append(_ev(ok["time"], "remote_login", f"Zalogowano przez SSH: {ok['user']} z {ok['from']}",
                          f"metoda: {ok['method']}; adres {'w Internecie' if scope == 'public' else 'w sieci lokalnej'}"
                          + (f"; wcześniej {prior} nieudanych prób z tego adresu" if prior else ""), score, conf, "sshd"))
        if score >= 10:
            findings.append(("Udane logowanie SSH po serii nieudanych prób – możliwe odgadnięcie hasła"
                             if prior >= 10 else f"Logowanie SSH z Internetu: {ok['user']} z {ok['from']}",
                             f"ssh {ok['user']}@{ok['from']}",
                             [Signal(f"{SL}.SshLogin{'AfterBruteForce' if prior >= 10 else 'Public'}", score, conf,
                                     (f"po {prior} nieudanych próbach z {ok['from']} nastąpiło udane logowanie – ktoś "
                                      "mógł odgadnąć hasło; zmień hasło i wyłącz Zdalne logowanie"
                                      if prior >= 10 else
                                      f"udane logowanie przez SSH z adresu w Internecie ({ok['from']})"),
                                     [f"{ok['time']} {ok['user']} {ok['method']} z {ok['from']}"])],
                             dict(ok, failures_before=prior)))
    for addr, fails in sorted(ssh_fail.items(), key=lambda kv: -len(kv[1])):
        n = len(fails)
        counts["ssh_failed"] += n
        scope = _host_scope(addr)
        users = sorted({f["user"] for f in fails if f["user"]})[:8]
        score = (45 if scope == "public" else 40) if n >= 10 else (10 if n >= 3 and scope == "public" else 3)
        events.append(_ev(fails[-1]["time"], "remote_login",
                          f"{n} {_pl(n, 'nieudana próba', 'nieudane próby', 'nieudanych prób')} logowania SSH z {addr}",
                          f"konta: {', '.join(users) or '?'}; od {fails[0]['time']} do {fails[-1]['time']}", score,
                          process="sshd"))
        if score >= 10:
            findings.append((f"Próby włamania przez SSH: {n} nieudanych logowań z {addr}" if n >= 10 else
                             f"Nieudane logowania SSH z {addr}", f"ssh z {addr}",
                             [Signal(f"{SL}.SshBruteForce" if n >= 10 else f"{SL}.SshFailures", score, Confidence.MEDIUM,
                                     (f"{n} nieudanych prób logowania przez SSH z jednego adresu – ktoś zgaduje hasła "
                                      "(atak słownikowy); wyłącz Zdalne logowanie lub używaj tylko kluczy"
                                      if n >= 10 else f"{n} nieudane próby logowania przez SSH z Internetu"),
                                     [f"{addr}: {n}× ({', '.join(users[:4])})"])],
                             {"from": addr, "attempts": n, "users": users, "first": fails[0]["time"],
                              "last": fails[-1]["time"]}))
    total_fail_hosts = [a for a, f in ssh_fail.items() if len(f) < 10]
    spread = sum(len(ssh_fail[a]) for a in total_fail_hosts)
    if spread >= 30 and len(total_fail_hosts) >= 3:
        findings.append(("Rozproszone próby włamania przez SSH z wielu adresów", "ssh (wiele adresów)",
                         [Signal(f"{SL}.SshDistributedBruteForce", 40, Confidence.MEDIUM,
                                 f"{spread} nieudanych logowań SSH z {len(total_fail_hosts)} adresów – zautomatyzowany "
                                 "atak na hasła", sorted(total_fail_hosts)[:5])],
                         {"attempts": spread, "hosts": sorted(total_fail_hosts)[:50]}))
    # Screen sharing
    for ok in vnc_ok:
        counts["screen_sharing_ok"] += 1
        scope = _host_scope(ok["from"])
        prior = len(vnc_fail.get(ok["from"], []))
        score = 70 if prior >= 5 else (30 if scope == "public" else 3)
        events.append(_ev(ok["time"], "screen_sharing", f"Połączenie udostępniania ekranu z {ok['from']}",
                          f"użytkownik: {ok['user'] or '?'}" + (f"; wcześniej {prior} nieudanych prób" if prior else ""),
                          score, process="screensharingd"))
        if score >= 10:
            findings.append((f"Zdalny podgląd ekranu z {ok['from']}", f"screensharing z {ok['from']}",
                             [Signal(f"{SL}.ScreenSharingLogin", score, Confidence.MEDIUM,
                                     f"ktoś połączył się z ekranem tego Maca z {ok['from']}"
                                     + (f" po {prior} nieudanych próbach" if prior else " (adres w Internecie)"),
                                     [f"{ok['time']} {ok['user']}"])], dict(ok, failures_before=prior)))
    for addr, fails in vnc_fail.items():
        n = len(fails)
        counts["screen_sharing_failed"] += n
        score = 40 if n >= 5 else 5
        events.append(_ev(fails[-1]["time"], "screen_sharing",
                          f"{n} {_pl(n, 'nieudana próba', 'nieudane próby', 'nieudanych prób')} połączenia z ekranem z {addr}",
                          f"od {fails[0]['time']} do {fails[-1]['time']}", score, process="screensharingd"))
        if n >= 5:
            findings.append((f"Próby odgadnięcia hasła do udostępniania ekranu z {addr}", f"screensharing z {addr}",
                             [Signal(f"{SL}.ScreenSharingBruteForce", 40, Confidence.MEDIUM,
                                     f"{n} nieudanych prób połączenia z ekranem tego Maca", [addr])],
                             {"from": addr, "attempts": n}))
    # failed passwords (unlock / admin dialogs)
    if auth_fail:
        n = len(auth_fail)
        counts["auth_failures"] = n
        unlock = [a for a in auth_fail if a["right"].startswith(("system.login.", "use-login-window-ui"))]
        days = {a["time"][:10] for a in auth_fail}
        burst = max((sum(1 for a in auth_fail if a["time"][:13] == h) for h in {a["time"][:13] for a in auth_fail}),
                    default=0)
        score = 35 if burst >= 10 else (12 if n >= 3 else 3)
        for a in auth_fail[-20:]:
            events.append(_ev(a["time"], "login_failure",
                              "Błędne hasło przy odblokowaniu Maca" if a in unlock else "Odmowa autoryzacji (błędne hasło)",
                              f"uprawnienie: {a['right']}; program: {os.path.basename(a['client'])}", min(score, 12),
                              process="authd"))
        findings.append((f"{n} {_pl(n, 'nieudana próba', 'nieudane próby', 'nieudanych prób')} podania hasła"
                         + (" (odblokowanie ekranu)" if unlock else ""), "authd (autoryzacja)",
                         [Signal(f"{SL}.FailedPasswords", score, Confidence.MEDIUM if score >= 12 else Confidence.LOW,
                                 (f"aż {burst} błędnych haseł w ciągu godziny – ktoś mógł próbować dostać się do tego Maca"
                                  if burst >= 10 else
                                  "kilka błędnych haseł przy odblokowaniu lub w oknie administratora – zwykle pomyłka, "
                                  "ale sprawdź, czy to Ty" if n >= 3 else "pojedyncza pomyłka w haśle"),
                                 [f"{a['time']} {a['right']}" for a in auth_fail[-5:]])],
                         {"attempts": n, "unlock_attempts": len(unlock), "days": sorted(days),
                          "max_per_hour": burst}))
    # admin rights for non-Apple programs
    for who, a in sorted(priv_auth.items()):
        counts["privileged_authorizations"] += a["count"]
        base = os.path.basename(who.rstrip("/"))
        odd = odd_location(who, home) if who.startswith("/") else []
        script = base in SCRIPT_CLIENTS or re.match(r"python[\d.]*$", base) is not None
        score = 35 if odd else (20 if script else 3)
        detail = (f"uprawnienia: {', '.join(a['rights'][:4])}; {a['count']}×, ostatnio {a['last']}"
                  + (f"; nietypowe miejsce: {', '.join(odd)}" if odd else ""))
        events.append(_ev(a["last"], "authorization", f"Uprawnienia administratora dla: {base or who}", detail, score,
                          process="authd"))
        if score >= 10:
            findings.append((f"Program {'z nietypowego miejsca' if odd else 'skryptowy'} uzyskał uprawnienia "
                             f"administratora: {base}", who,
                             [Signal(f"{SL}.PrivilegedAuth{'OddLocation' if odd else 'Script'}", score, Confidence.MEDIUM,
                                     (f"program z nietypowego miejsca ({', '.join(odd)}) uzyskał uprawnienia "
                                      "administratora po podaniu hasła" if odd else
                                      f"interpreter skryptów '{base}' uzyskał uprawnienia administratora – złośliwe "
                                      "skrypty proszą tak o hasło; upewnij się, że to Ty uruchamiałeś instalator/skrypt"),
                                     [who] + a["rights"][:3])], dict(a)))
    # new login items / launch agents
    odd_items, launchd_items = [], []
    for ident, it in btm_items.items():
        counts["new_login_items"] += 1
        path = it.get("path") or ""
        typ = (it.get("type") or "").lower()
        odd = odd_location(path, home) if path.startswith("/") else []
        pi = classify_path(path, home) if path.startswith("/") else None
        if pi is not None and pi.has("tmp", "shared", "hidden", "random_appsupport", "random_library", "trash", "volume"):
            odd = odd or ["nietypowy katalog"]
        if it.get("apple_name") and path and not is_apple_path(path):
            odd = odd + ["nazwa podszywa się pod Apple (com.apple…) poza katalogami systemu"]
        legacy = "legacy" in typ or "daemon" in typ or "agent" in typ
        score = 35 if odd else (10 if legacy else 3)
        if odd:
            odd_items.append(it)
        elif legacy:
            launchd_items.append(it)
        events.append(_ev(it["time"], "persistence", f"Nowy element autostartu: {it.get('name') or ident}",
                          f"typ: {it.get('type') or '?'}; identyfikator: {ident}"
                          + (f"; plik: {path}" if path else "") + (f"; nietypowe miejsce: {', '.join(odd)}" if odd else ""),
                          score, process="backgroundtaskmanagementd"))
    if btm_items:
        sigs = []
        if odd_items:
            sigs.append(Signal(f"{SL}.NewPersistenceOdd", 35, Confidence.MEDIUM,
                               "niedawno dodany element autostartu uruchamia program z nietypowego miejsca",
                               [i.get("path") or i.get("identifier") or "?" for i in odd_items[:5]]))
        if launchd_items:
            sigs.append(Signal(f"{SL}.NewLaunchItem", 10, Confidence.LOW,
                               "niedawno dodano usługę uruchamianą w tle (LaunchAgent / LaunchDaemon) – sprawdź, czy "
                               "pochodzi z zainstalowanego przez Ciebie programu",
                               [f"{i['time']} {i.get('name') or i.get('identifier')}" for i in launchd_items[:5]]))
        sigs.append(Signal(f"{SL}.NewLoginItem", 3, Confidence.LOW, "niedawno dodane elementy autostartu",
                           [f"{i['time']} {i.get('name') or i.get('identifier')}" for i in list(btm_items.values())[:5]]))
        n = len(btm_items)
        findings.append((f"Nowe elementy autostartu w ostatnich dniach: {n}", "Background Task Management",
                         sigs, {"items": list(btm_items.values())[:50]}))
    # privacy prompts
    spy = []
    for (service, client), p in sorted(tcc.items(), key=lambda kv: kv[1]["time"]):
        counts["privacy_prompts"] += 1
        path = p["path"] or ""
        base = os.path.basename(path)
        odd = odd_location(path, home) if path.startswith("/") else []
        script = base in SCRIPT_CLIENTS or bool(re.match(r"python[\d.]*$", base))
        sensitive = service in TCC_SPY or service == "kTCCServiceAppleEvents"
        score = 35 if (odd and service in TCC_SPY) else (20 if (odd or script) and sensitive else 0)
        events.append(_ev(p["time"], "privacy", f"{client} prosi o dostęp: {TCC_SENSITIVE[service]}",
                          (f"program: {path}" if path else "") + (f"; nietypowe miejsce: {', '.join(odd)}" if odd else ""),
                          score, process="tccd"))
        if score:
            spy.append((p, score, odd, script))
    for p, score, odd, script in spy:
        findings.append((f"{os.path.basename(p['path'] or p['client'])} prosi o dostęp: {TCC_SENSITIVE[p['service']]}",
                         p["path"] or p["client"],
                         [Signal(f"{SL}.PrivacyPrompt{'OddLocation' if odd else 'Script'}", score, Confidence.MEDIUM,
                                 (f"program z nietypowego miejsca ({', '.join(odd)}) prosił o uprawnienie "
                                  f"„{TCC_SENSITIVE[p['service']]}” – tak zachowuje się oprogramowanie szpiegujące"
                                  if odd else
                                  f"skrypt ({os.path.basename(p['path'] or '')}) prosił o uprawnienie "
                                  f"„{TCC_SENSITIVE[p['service']]}” – programy kradnące dane często tak robią; "
                                  "odmów, jeśli nie wiesz, skąd ta prośba"),
                                 [p["time"], p["client"], p["path"] or ""])], dict(p)))

    events.sort(key=lambda e: e["time"], reverse=True)
    events.sort(key=lambda e: {"malicious": 0, "suspicious": 1, "low": 2, "info": 3}[e["severity"]])
    for e in events:
        score = e.pop("_score", 0)
        if keep_score:
            e["score"] = score
    return {"events": events, "counts": counts, "findings": findings}


def _ts(t: str) -> float | None:
    try:
        return time.mktime(time.strptime(t[:19], "%Y-%m-%d %H:%M:%S"))
    except (ValueError, OverflowError):
        return None


def log_store_since(root: str = LOG_STORE) -> dict:
    """How far back the unified log really goes: oldest file of the Persist (Default level) and Special stores."""
    out: dict = {}
    for name in ("Persist", "Special"):
        d = os.path.join(root, name)
        oldest = None
        try:
            with os.scandir(d) as it:
                for e in it:
                    if not e.name.endswith(".tracev3"):
                        continue
                    try:
                        st = e.stat()
                    except OSError:
                        continue
                    t = getattr(st, "st_birthtime", None) or st.st_mtime
                    oldest = t if oldest is None else min(oldest, t)
        except OSError:
            pass
        out[name.lower() + "_since"] = (time.strftime("%Y-%m-%d %H:%M", time.localtime(oldest))
                                        if oldest is not None else None)
    return out


# --------------------------------------------------------------------------- collector: syslog

def collect_syslog(ctx: EnvContext) -> None:
    ctx.progress("audyt dziennika systemowego (XProtect, Gatekeeper, logowania, autostart)")
    audit = _audit(ctx)
    home = ctx.homes[0].home if ctx.homes else None
    now = time.time()
    info = {"window": {"from": time.strftime("%Y-%m-%d %H:%M", time.localtime(now - 7 * 86400)),
                       "to": time.strftime("%Y-%m-%d %H:%M", time.localtime(now)),
                       "days": {k: v[3] for k, v in LOG_QUERIES.items()}},
            "events": [], "counts": {}, "available": False, "reason": None}
    info["window"].update(log_store_since(ctx.options.get("log_store", LOG_STORE)))
    audit["syslog"] = info
    if not os.path.exists(LOG):
        info["reason"] = "brak narzędzia /usr/bin/log"
        ctx.limit("Historia dziennika systemowego niedostępna (brak /usr/bin/log)")
        return

    queries = {k: (log_argv(w, p), float(ctx.options.get("syslog_timeout", t))) for k, (w, p, t, _) in LOG_QUERIES.items()}
    with ThreadPoolExecutor(max_workers=len(queries)) as ex:
        futs = {k: ex.submit(_cmd, argv, t, float(ctx.options.get("syslog_wait", 90))) for k, (argv, t) in queries.items()}
        results = {k: f.result() for k, f in futs.items()}

    raw: list[dict] = []
    ok_any = False
    reasons = []
    labels = {"security": "zdarzenia bezpieczeństwa (7 dni)", "privacy": "prośby o uprawnienia prywatności (12 godzin)"}
    for k, r in results.items():
        if _sandbox_refused(r):
            reasons.append("narzędzie log nie działa w sandboksie – historię musi odczytać proces nadrzędny Cerbera")
            continue
        if r.missing:
            reasons.append(f"{labels[k]}: nie udało się uruchomić polecenia log")
            continue
        evs = parse_log_ndjson(r.out)
        if r.timed_out:
            last = evs[-1]["time"] if evs else None
            ctx.limit(f"Dziennik systemowy: przekroczono limit czasu dla zapytania „{labels[k]}” – "
                      + (f"przeanalizowano tylko wpisy do {last}" if last else "brak wyników"))
        elif r.rc not in (0, None):
            reasons.append(f"{labels[k]}: log show zakończył się błędem ({(r.err or '').strip()[:120]})")
            continue
        ok_any = ok_any or bool(evs) or (r.rc == 0)
        raw += evs
    if not ok_any:
        info["reason"] = "; ".join(dict.fromkeys(reasons)) or "brak danych"
        ctx.limit(f"Historia dziennika systemowego niedostępna: {info['reason']}")
        return
    raw.sort(key=lambda e: e["time"])
    res = analyze_syslog(raw, home)
    info["available"] = True
    info["reason"] = "; ".join(dict.fromkeys(reasons)) or None
    info["events"] = res["events"][:MAX_EVENTS]
    info["counts"] = dict(res["counts"], events_total=len(res["events"]))
    for title, location, sigs, details in res["findings"]:
        ctx.add_finding("syslog", title, location, sigs, details)
    since = info["window"].get("persist_since")
    if since and since > info["window"]["from"]:
        ctx.limit(f"macOS przechowuje szczegółowe wpisy dziennika systemowego tylko od {since} (starsze zostały "
                  "nadpisane) – logowania, autoryzacje i nowe elementy autostartu sprzed tej chwili nie są widoczne")
    ctx.limit("Dziennik systemowy: macOS ukrywa część szczegółów (nazwy plików i programów) jako <private>; "
              "polecenia sudo nie są zapisywane w dzienniku dostępnym bez uprawnień roota")


# --------------------------------------------------------------------------- LAN (pure parsers)

def normalize_mac(mac: str) -> str:
    parts = (mac or "").lower().split(":")
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9a-f]{1,2}", p) for p in parts):
        return (mac or "").lower()
    return ":".join(p.zfill(2) for p in parts)


def mac_is_local(mac: str) -> bool:
    """Locally administered (randomised / virtual) MAC address."""
    try:
        return bool(int(normalize_mac(mac).split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def parse_route_get(text: str) -> dict:
    gw = re.search(r"^\s*gateway:\s*(\S+)", text or "", re.M)
    iface = re.search(r"^\s*interface:\s*(\S+)", text or "", re.M)
    return {"gateway": gw.group(1) if gw else None, "interface": iface.group(1) if iface else None}


_ARP_RX = re.compile(r"^\S+ \(([^)]+)\) at (\S+) on (\S+)(.*)$")


def parse_arp(text: str) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        m = _ARP_RX.match(line.strip())
        if not m:
            continue
        mac = m.group(2)
        incomplete = mac.startswith("(")
        out.append({"ip": m.group(1), "mac": None if incomplete else normalize_mac(mac), "interface": m.group(3),
                    "permanent": "permanent" in m.group(4), "incomplete": incomplete})
    return out


def _is_group_mac(mac: str) -> bool:
    try:
        return mac == "ff:ff:ff:ff:ff:ff" or bool(int(mac.split(":")[0], 16) & 0x01)
    except (ValueError, IndexError):
        return True


def analyze_arp(entries: list[dict], gateway: str | None, interface: str | None = None) -> dict:
    """Gateway MAC, other IPs answering with it (ARP spoofing indicator) and MACs used by several IPs."""
    usable = [e for e in entries if e["mac"] and not _is_group_mac(e["mac"]) and not e["permanent"]]
    gw = next((e for e in usable if e["ip"] == gateway and (interface is None or e["interface"] == interface)), None)
    by_mac: dict[tuple, list[str]] = {}
    for e in usable:
        by_mac.setdefault((e["mac"], e["interface"]), []).append(e["ip"])
    shared = []
    if gw:
        shared = sorted(ip for ip in by_mac.get((gw["mac"], gw["interface"]), []) if ip != gateway)
    multi = [{"mac": m, "interface": i, "ips": sorted(ips)} for (m, i), ips in by_mac.items()
             if len(ips) > 1 and not (gw and m == gw["mac"])]
    return {"gateway_mac": gw["mac"] if gw else None, "gateway_interface": gw["interface"] if gw else interface,
            "gateway_shared_with": shared, "multi_ip_macs": sorted(multi, key=lambda d: -len(d["ips"]))[:20],
            "entries": len(entries)}


def parse_ipconfig_summary(text: str) -> dict:
    """`ipconfig getsummary <if>` (works without Location permission; SSID / BSSID are redacted)."""
    t = text or ""

    def top(key: str) -> str | None:
        m = re.search(rf"^\s{{2}}{key} : (.+)$", t, re.M)
        return m.group(1).strip() if m else None
    ssid = top("SSID")
    dns = re.search(r"domain_name_server \(ip_mult\): \{([^}]*)\}", t)
    dom = re.search(r"domain_name \(string\): (\S+)", t)
    srv = re.search(r"server_identifier \(ip\): (\S+)", t)
    router = re.search(r"^\s*Router : (\S+)", t, re.M)
    arpv = re.search(r"^\s*RouterARPVerified : (\S+)", t, re.M)
    return {"interface_type": top("InterfaceType"), "security": top("Security"),
            "ssid": None if not ssid or ssid == "<redacted>" else ssid,
            "link_active": (top("LinkStatusActive") or "").upper() == "TRUE",
            "router": router.group(1) if router else None,
            "router_arp_verified": (arpv.group(1).upper() == "TRUE") if arpv else None,
            "dhcp_server": srv.group(1) if srv else None,
            "dns": [x.strip() for x in dns.group(1).split(",") if x.strip()] if dns else [],
            "domain": dom.group(1) if dom else None}


_AIRPORT_SEC = {"none": "None", "wep": "WEP", "wpa_personal": "WPA_PSK", "wpa2_personal": "WPA2_PSK",
                "wpa3_personal": "WPA3_SAE", "wpa_enterprise": "WPA_Enterprise", "wpa2_enterprise": "WPA2_Enterprise",
                "wpa3_enterprise": "WPA3_Enterprise", "owe": "OWE", "dynamic_wep": "Dynamic_WEP",
                "wpa2_wpa3_personal": "WPA2_WPA3_PSK", "wpa_wpa2_personal": "WPA_WPA2_PSK"}


def parse_airport_json(text: str) -> dict:
    """`system_profiler SPAirPortDataType -json` -> current network of the first Wi-Fi interface."""
    try:
        d = json.loads(text or "")
    except ValueError:
        return {}
    for blk in d.get("SPAirPortDataType") or []:
        for itf in blk.get("spairport_airport_interfaces") or []:
            cur = itf.get("spairport_current_network_information")
            if not isinstance(cur, dict) or "spairport_security_mode" not in cur:
                continue
            mode = str(cur.get("spairport_security_mode", "")).replace("spairport_security_mode_", "")
            name = cur.get("_name")
            return {"interface": itf.get("_name"), "security": _AIRPORT_SEC.get(mode, mode),
                    "ssid": None if not name or name == "<redacted>" else name,
                    "phy_mode": cur.get("spairport_network_phymode"), "channel": cur.get("spairport_network_channel"),
                    "connected": itf.get("spairport_status_information") == "spairport_status_connected"}
    return {}


def classify_wifi_security(sec: str | None) -> tuple[str, str, int]:
    """(level, Polish label, score) for a Wi-Fi security mode."""
    s = (sec or "").upper().replace("-", "_")
    if not s:
        return "unknown", "nieznane", 0
    if "WEP" in s:
        return "wep", "WEP (przestarzałe szyfrowanie, łamane w kilka minut)", 30
    if s in ("NONE", "OPEN"):
        return "open", "brak – sieć otwarta, bez hasła i szyfrowania", 25
    if "OWE" in s:
        return "owe", "sieć otwarta z szyfrowaniem (OWE / Enhanced Open)", 0
    if "ENTERPRISE" in s or "8021X" in s or "EAP" in s:
        return "enterprise", "WPA Enterprise (logowanie kontem)", 0
    if "WPA3" in s:
        return "wpa3", "WPA3", 0
    if "WPA2" in s:
        return "wpa2", "WPA2", 0
    if "WPA" in s:
        return "wpa", "WPA (pierwsza wersja, przestarzała)", 10
    return "unknown", sec or "nieznane", 0


_NDP_RX = re.compile(r"^(\S+?)(?:%(\S+))?\s+if=(\S+?),.*?pref=(\S+?),\s*expire=(\S+)")
VIRTUAL_IF = re.compile(r"^(utun|awdl|llw|ipsec|bridge|gif|stf|anpi|ap\d|lo)")


def parse_ndp_routers(text: str) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        m = _NDP_RX.match(line.strip())
        if not m or VIRTUAL_IF.match(m.group(3)):
            continue
        out.append({"router": m.group(1), "interface": m.group(3), "pref": m.group(4), "expire": m.group(5)})
    return out


# --------------------------------------------------------------------------- collector: LAN

def collect_lan(ctx: EnvContext) -> None:
    ctx.progress("audyt sieci lokalnej (router, ARP, Wi-Fi)")
    audit = _audit(ctx)
    lan: dict = {"gateway": {"ip": None, "mac": None, "interface": None, "mac_randomized": None},
                 "wifi": {"interface": None, "connected": False, "security": None, "security_level": "unknown",
                          "security_label": None, "ssid": None, "source": None},
                 "dhcp": {}, "arp_entries": 0, "arp_suspicious": [], "arp_multi_ip": [], "ipv6_routers": []}
    audit["lan"] = lan
    r = run(["/sbin/route", "-n", "get", "default"], timeout=10)
    route = parse_route_get(r.out) if r.ok else {"gateway": None, "interface": None}
    if not r.ok:
        ctx.limit("Nie ustalono domyślnej bramy (route get default) – brak połączenia z siecią lub błąd polecenia")
    gw_ip, gw_if = route["gateway"], route["interface"]
    lan["gateway"].update(ip=gw_ip, interface=gw_if)

    # ---- ARP
    r = run(["/usr/sbin/arp", "-an"], timeout=15)
    if r.ok:
        entries = parse_arp(r.out)
        a = analyze_arp(entries, gw_ip, gw_if)
        lan["arp_entries"] = a["entries"]
        lan["gateway"].update(mac=a["gateway_mac"],
                              mac_randomized=mac_is_local(a["gateway_mac"]) if a["gateway_mac"] else None)
        lan["arp_multi_ip"] = a["multi_ip_macs"]
        if a["gateway_shared_with"]:
            shared = a["gateway_shared_with"]
            n = len(shared)
            many = n >= 5
            lan["arp_suspicious"].append({"mac": a["gateway_mac"], "ips": [gw_ip] + shared,
                                          "reason": "adres MAC routera używany także przez inne adresy IP"})
            ctx.add_finding("lan", "Możliwe podszywanie się pod router (ARP spoofing)" if not many else
                            "Router odpowiada za wiele adresów IP (proxy ARP)", f"brama {gw_ip}",
                            [Signal(f"{LN}.GatewayMacShared", 10 if many else 30, Confidence.LOW,
                                    (f"ten sam adres sprzętowy (MAC) co router ({gw_ip}) ma {n} "
                                     f"{_pl(n, 'inny adres', 'inne adresy', 'innych adresów')} IP – to typowe dla routerów "
                                     "z funkcją proxy ARP, rzadziej dla ataku" if many else
                                     f"adres sprzętowy (MAC) routera {gw_ip} ma też {', '.join(shared[:3])} – tak wygląda "
                                     "atak ARP spoofing (ktoś w sieci przechwytuje ruch), ale bywa też zwykłą konfiguracją "
                                     "routera; jeśli to sieć publiczna, korzystaj z VPN"),
                                    [f"{gw_ip} = {a['gateway_mac']}"] + shared[:5])],
                            {"gateway": gw_ip, "mac": a["gateway_mac"], "shared_with": shared})
    else:
        ctx.limit("Nie odczytano tablicy ARP (arp -an) – nie sprawdzono podszywania się pod router")

    # ---- Wi-Fi security of the active connection
    wifi = None
    for itf in dict.fromkeys(x for x in (gw_if, "en0", "en1") if x):
        r = run(["/usr/sbin/ipconfig", "getsummary", itf], timeout=10)
        if not r.ok or not r.out.strip():
            continue
        s = parse_ipconfig_summary(r.out)
        if itf == gw_if:
            lan["dhcp"] = {k: s[k] for k in ("dhcp_server", "router", "dns", "domain", "router_arp_verified")}
        if (s.get("interface_type") or "").lower() == "wifi" and s.get("link_active"):
            wifi = dict(s, interface=itf, source="ipconfig")
            break
    if wifi is not None and not wifi.get("security"):
        r = run(["/usr/sbin/system_profiler", "SPAirPortDataType", "-json"], timeout=30)
        ap = parse_airport_json(r.out) if r.ok else {}
        if ap.get("security"):
            wifi.update(security=ap["security"], source="system_profiler")
            wifi["ssid"] = wifi.get("ssid") or ap.get("ssid")
        elif r.timed_out:
            ctx.limit("system_profiler nie odpowiedział w czasie – nie ustalono zabezpieczeń sieci Wi-Fi")
    if wifi is not None:
        level, label, score = classify_wifi_security(wifi.get("security"))
        lan["wifi"] = {"interface": wifi["interface"], "connected": True, "security": wifi.get("security"),
                       "security_level": level, "security_label": label, "ssid": wifi.get("ssid"),
                       "source": wifi["source"]}
        if score:
            name = f"„{wifi['ssid']}”" if wifi.get("ssid") else "(nazwa sieci ukryta przez macOS)"
            title = {"open": "Połączenie z otwartą siecią Wi-Fi (bez szyfrowania)",
                     "wep": "Sieć Wi-Fi zabezpieczona przestarzałym WEP",
                     "wpa": "Sieć Wi-Fi zabezpieczona przestarzałym WPA"}[level]
            ctx.add_finding("lan", title, f"Wi-Fi {wifi['interface']} {name}",
                            [Signal(f"{LN}.Wifi.{level.capitalize()}", score, Confidence.MEDIUM,
                                    {"open": "w otwartej sieci każdy w pobliżu może podsłuchać nieszyfrowany ruch i "
                                             "podszyć się pod router; strony HTTPS są chronione, ale używaj VPN",
                                     "wep": "szyfrowanie WEP można złamać w kilka minut – ruch w tej sieci jest "
                                            "praktycznie jawny; zmień zabezpieczenia routera na WPA2/WPA3",
                                     "wpa": "WPA (TKIP) jest przestarzałe i podatne na ataki – ustaw w routerze WPA2 lub WPA3"
                                     }[level], [f"zabezpieczenia: {wifi.get('security')}"])],
                            {"interface": wifi["interface"], "security": wifi.get("security"), "ssid": wifi.get("ssid")})

    # ---- IPv6 routers (rogue router advertisements)
    r = run(["/usr/sbin/ndp", "-rn"], timeout=10)
    if r.ok:
        routers = parse_ndp_routers(r.out)
        lan["ipv6_routers"] = routers
        by_if: dict[str, set] = {}
        for x in routers:
            by_if.setdefault(x["interface"], set()).add(x["router"])
        for itf, rs in sorted(by_if.items()):
            if len(rs) > 1:
                ctx.add_finding("lan", f"Kilka routerów IPv6 w sieci ({itf})", f"IPv6 {itf}",
                                [Signal(f"{LN}.MultipleIPv6Routers", 15, Confidence.LOW,
                                        f"w sieci ogłasza się {len(rs)} routerów IPv6 – fałszywy router IPv6 to znany "
                                        "sposób przechwytywania ruchu (np. atak mitm6); w sieciach domowych zwykle "
                                        "jest jeden", sorted(rs)[:5])],
                                {"interface": itf, "routers": sorted(rs)})


# --------------------------------------------------------------------------- certificates (pure)

def parse_trust_settings(text: str) -> list[dict]:
    """`security dump-trust-settings [-d]` -> [{name, settings: [{policy, result, allowed_errors, …}]}]."""
    certs: list[dict] = []
    cur = None
    setting = None
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        m = re.match(r"^Cert \d+: (.*)$", line)
        if m:
            cur = {"name": m.group(1).strip(), "settings": [], "count": 0}
            certs.append(cur)
            setting = None
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+Number of trust settings : (\d+)", line)
        if m:
            cur["count"] = int(m.group(1))
            continue
        if re.match(r"^\s+Trust Setting \d+:", line):
            setting = {"policy": None, "result": None, "allowed_errors": [], "application": None,
                       "policy_string": None, "key_usage": None}
            cur["settings"].append(setting)
            continue
        m = re.match(r"^\s+(Policy OID|Application|Policy String|Allowed Error|Result Type|Key Usage)\s*:\s*(.*)$", line)
        if m and setting is not None:
            k, v = m.group(1), m.group(2).strip()
            if k == "Allowed Error":
                setting["allowed_errors"].append(v)
            else:
                setting[{"Policy OID": "policy", "Application": "application", "Policy String": "policy_string",
                         "Result Type": "result", "Key Usage": "key_usage"}[k]] = v
    return certs


def trust_scope(entry: dict) -> str:
    """all | ssl | other | deny | unspecified (macOS semantics: no settings = trusted for everything)."""
    sets = entry.get("settings") or []
    if not sets:
        return "all"
    trusting = []
    for s in sets:
        res = (s.get("result") or "kSecTrustSettingsResultTrustRoot")
        if "TrustRoot" in res or "TrustAsRoot" in res:
            trusting.append(s)
    if not trusting:
        return "deny" if any("Deny" in (s.get("result") or "") for s in sets) else "unspecified"
    pols = {(s.get("policy") or "").strip() for s in trusting}
    if "" in pols:
        return "all"
    if any(p in ("SSL", "Apple X509 Basic", "1.2.840.113635.100.1.3", "1.2.840.113635.100.1.2") or "SSL" in p
           or "TLS" in p for p in pols):
        return "ssl"
    return "other"


def parse_cert_dump(text: str) -> list[dict]:
    """`security find-certificate -a -Z -p` -> [{sha256, sha1, pem}]."""
    out = []
    cur: dict = {}
    pem: list[str] = []
    inpem = False
    for line in (text or "").splitlines():
        if line.startswith("SHA-256 hash:"):
            cur = {"sha256": line.split(":", 1)[1].strip().upper(), "sha1": None, "pem": None}
        elif line.startswith("SHA-1 hash:"):
            cur["sha1"] = line.split(":", 1)[1].strip().upper()
        elif line.startswith("-----BEGIN CERTIFICATE-----"):
            inpem, pem = True, [line]
        elif line.startswith("-----END CERTIFICATE-----") and inpem:
            pem.append(line)
            inpem = False
            cur["pem"] = "\n".join(pem) + "\n"
            out.append(cur)
            cur = {}
        elif inpem:
            pem.append(line)
    return out


def cert_details(pem: str) -> dict | None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except Exception:  # noqa: BLE001
        return None
    try:
        c = x509.load_pem_x509_certificate(pem.encode())
    except Exception:  # noqa: BLE001
        return None

    def attr(name, oid) -> str | None:
        try:
            v = name.get_attributes_for_oid(oid)
            return str(v[0].value) if v else None
        except Exception:  # noqa: BLE001
            return None
    is_ca = False
    try:
        is_ca = bool(c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except Exception:  # noqa: BLE001
        pass
    ekus: list[str] = []
    try:
        names = {ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth", ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth",
                 ExtendedKeyUsageOID.CODE_SIGNING: "codeSigning", ExtendedKeyUsageOID.EMAIL_PROTECTION: "emailProtection"}
        ekus = [names.get(o, o.dotted_string) for o in c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
    except Exception:  # noqa: BLE001
        pass
    nb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before.replace(tzinfo=_dt.timezone.utc)
    na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=_dt.timezone.utc)
    now = _dt.datetime.now(_dt.timezone.utc)
    try:
        subject, issuer = c.subject.rfc4514_string(), c.issuer.rfc4514_string()
    except Exception:  # noqa: BLE001
        subject = issuer = "?"
    return {"subject": subject, "issuer": issuer,
            "subject_cn": attr(c.subject, NameOID.COMMON_NAME), "subject_o": attr(c.subject, NameOID.ORGANIZATION_NAME),
            "subject_ou": attr(c.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
            "issuer_cn": attr(c.issuer, NameOID.COMMON_NAME), "issuer_o": attr(c.issuer, NameOID.ORGANIZATION_NAME),
            "not_before": nb.strftime("%Y-%m-%d"), "not_after": na.strftime("%Y-%m-%d"), "expired": na < now,
            "is_ca": is_ca, "self_signed": c.subject == c.issuer, "ekus": ekus,
            "sha256": c.fingerprint(hashes.SHA256()).hex().upper(), "serial": format(c.serial_number, "x")}


_I = re.IGNORECASE
INTERCEPTION_TOOLS = [(re.compile(rx, _I), name) for rx, name in (
    (r"mitmproxy", "mitmproxy"), (r"charles proxy|charlesproxy|xk72", "Charles Proxy"), (r"proxyman", "Proxyman"),
    (r"fiddler|do_not_trust_fiddler|telerik", "Fiddler"), (r"portswigger|\bburp\b", "Burp Suite"),
    (r"http ?toolkit", "HTTP Toolkit"), (r"surge generated|^surge\b", "Surge"), (r"quantumult", "Quantumult X"),
    (r"shadowrocket", "Shadowrocket"), (r"whistle", "Whistle"), (r"owasp zap|zed attack proxy|\bzap root", "OWASP ZAP"),
    (r"requestly", "Requestly"), (r"httpcanary|packet capture", "HttpCanary / Packet Capture"),
    (r"bettercap", "bettercap"), (r"\bproxie\b", "Proxie"), (r"rapidapi|\bpaw\b", "RapidAPI / Paw"),
    (r"\bmitm\b|man.in.the.middle", "narzędzie MITM"),
)]
ADWARE_CA = re.compile(r"superfish|edellroot|komodia|privdog|websearchpro|spigot|crossrider|genieo|vsearch|conduit|"
                       r"installmac|pirrit|mughthesec|wajam|sendori|browsefox|lenovo customer", _I)
AV_FILTER = re.compile(r"kaspersky|avast|\bavg\b|eset ssl|eset .*filter|bitdefender|norton|symantec|mcafee|sophos|"
                       r"trend ?micro|f-secure|withsecure|intego|avira|dr\.? ?web|emsisoft|malwarebytes|webroot|adguard|"
                       r"\bcerber\b|lulu|little ?snitch|1blocker|ghostery|nordvpn threat|surfshark", _I)
ENTERPRISE_CA = re.compile(r"zscaler|netskope|forcepoint|websense|fortinet|fortigate|palo ?alto|cisco|umbrella|opendns|"
                           r"blue ?coat|mcafee web gateway|skyhigh|check ?point|barracuda|sonicwall|watchguard|lightspeed|"
                           r"goguardian|securly|contentkeeper|iboss|cloudflare (?:for teams|gateway|zero trust)|menlo|"
                           r"cato networks|smoothwall|linewize|family ?zone|fortiguard|untangle|pfsense|opnsense|kerio|"
                           r"jamf|kandji|mosyle|intune|workspace ?one|airwatch|addigy|hexnode|microsoft.*device management|"
                           r"\bproxy\b.*\b(?:ca|root)\b|ssl inspection|ssl.?decrypt|tls inspection|\bdpi\b", _I)
DEV_CA = re.compile(r"mkcert|caddy local authority|\blocalhost\b|local ?dev|development ca|\bdev ca\b|orbstack|docker|"
                    r"minikube|\bk3d\b|\bvalet\b|laravel herd|\bherd\b|ddev|traefik|devcert|\blando\b|local by flywheel|"
                    r"smallstep|step ca|\.test\b|\.local\b|webpack|vite|expo|vmware|parallels|virtualbox|\butm\b", _I)
PUBLIC_CA = re.compile(r"comodo|sectigo|digicert|globalsign|let'?s ?encrypt|isrg root|geotrust|thawte|verisign|entrust|"
                       r"go ?daddy|starfield|usertrust|amazon root|microsoft (?:rsa|ecc) root|baltimore|quovadis|"
                       r"identrust|certum|buypass|actalis|ssl\.com|apple root|google trust|gts root|apple (?:worldwide|"
                       r"public)|t-telesec|swisssign|harica|hongkong post|secom|telia|d-trust", _I)


def classify_trusted_cert(name: str, details: dict | None, scope: str, domain: str,
                          system_root: bool = False) -> dict:
    """Kind, score and Polish explanation of one explicitly trusted certificate."""
    text = " ".join(x for x in (name, (details or {}).get("subject", ""), (details or {}).get("issuer", "")) if x)
    ssl = scope in ("all", "ssl")
    admin_bonus = 5 if domain == "admin" else 0
    where = "dla całego systemu (wszyscy użytkownicy)" if domain == "admin" else "dla Twojego konta"
    if scope in ("deny", "unspecified"):
        return {"kind": "distrusted", "score": 0,
                "explanation": "certyfikat oznaczono jako niezaufany lub bez rozstrzygnięcia – nie pozwala przechwytywać ruchu"}
    if system_root:
        return {"kind": "system_duplicate", "score": 0,
                "explanation": "to ten sam certyfikat, który jest wbudowany w macOS – dodatkowe zaufanie niczego nie zmienia"}
    if ADWARE_CA.search(text):
        return {"kind": "adware", "score": 70, "confidence": "high",
                "explanation": f"certyfikat znanego adware / oprogramowania przechwytującego ruch, zaufany {where} – "
                               "pozwala wstrzykiwać reklamy i podglądać szyfrowane strony; usuń go i program, który go dodał"}
    tool = next((n for rx, n in INTERCEPTION_TOOLS if rx.search(text)), None)
    if tool:
        score = (25 if ssl else 10) + admin_bonus
        if details and details.get("expired"):
            score = max(5, score // 2)
        return {"kind": "interception_tool", "tool": tool, "score": score,
                "explanation": f"certyfikat narzędzia do podglądania ruchu HTTPS ({tool}), zaufany {where}. Programiści "
                               "używają go do testów; jeśli to nie Ty go dodałeś, ktoś może czytać Twój ruch HTTPS "
                               "(hasła, wiadomości) – usuń go w Pęku kluczy"}
    if AV_FILTER.search(text):
        return {"kind": "antivirus_filter", "score": 3,
                "explanation": "certyfikat programu ochronnego / blokującego reklamy, który filtruje ruch HTTPS na tym Macu – "
                               "to normalne, jeśli używasz tego programu"}
    if ENTERPRISE_CA.search(text):
        return {"kind": "enterprise", "score": 10 if ssl else 3,
                "explanation": f"certyfikat systemu firmowego lub szkolnego (filtr treści / inspekcja HTTPS), zaufany {where} "
                               "– organizacja może odszyfrowywać ruch HTTPS. Na komputerze służbowym to normalne, na "
                               "prywatnym – usuń go, jeśli nie wiesz, skąd się wziął"}
    if DEV_CA.search(text):
        return {"kind": "dev", "score": 2,
                "explanation": "lokalny certyfikat deweloperski (np. mkcert, kontenery, maszyny wirtualne) – służy do HTTPS "
                               "na własnym komputerze"}
    if PUBLIC_CA.search(text):
        return {"kind": "impersonation", "score": 50 + admin_bonus if ssl else 15,
                "explanation": f"certyfikat podpisany nazwą znanego urzędu certyfikacji, ale NIE jest kopią certyfikatu "
                               f"wbudowanego w macOS, a jest zaufany {where} – złośliwe programy (np. OSX/Dok) podszywają "
                               "się tak pod prawdziwe urzędy, by przechwytywać HTTPS"}
    is_ca = (details or {}).get("is_ca")
    if ssl and (details is None or is_ca or (details or {}).get("self_signed")):
        return {"kind": "unknown", "score": 40 + admin_bonus,
                "explanation": f"nieznany certyfikat główny zaufany {where} dla połączeń HTTPS – kto go ma, może podszyć "
                               "się pod dowolną stronę i czytać Twój ruch; usuń go, jeśli nie wiesz, skąd się wziął"}
    return {"kind": "unknown", "score": 10,
            "explanation": f"certyfikat zaufany {where} do celów innych niż HTTPS (np. podpis kodu lub poczty)"}


# --------------------------------------------------------------------------- collector: certificates

def collect_certs(ctx: EnvContext) -> None:
    ctx.progress("audyt zaufanych certyfikatów (przechwytywanie HTTPS)")
    audit = _audit(ctx)
    audit["certificates"] = []
    entries: list[tuple[str, dict]] = []
    for domain, argv in TRUST_ARGV.items():
        r = _cmd(argv, 20, max_wait=60)
        if r.missing:
            ctx.limit("Brak narzędzia security – nie sprawdzono zaufanych certyfikatów")
            return
        if r.timed_out:
            ctx.limit(f"security dump-trust-settings ({domain}) nie odpowiedział w czasie")
            continue
        if "No Trust Settings were found" in r.err + r.out:
            continue
        if r.rc not in (0, None) and not r.out.strip():
            ctx.limit(f"Nie odczytano ustawień zaufania certyfikatów ({domain}): {(r.err or '').strip()[:120]}")
            continue
        entries += [(domain, e) for e in parse_trust_settings(r.out)]
    if not entries:
        return

    r = _cmd(CERT_ARGV, 30, max_wait=60)
    dump = parse_cert_dump(r.out) if r.ok else []
    infos = []
    for c in dump:
        d = cert_details(c["pem"]) if c.get("pem") else None
        if d:
            infos.append(d)
    if not infos:
        ctx.limit("Nie odczytano treści certyfikatów z pęku kluczy (w sandboksie pęk kluczy jest niedostępny) – "
                  "certyfikaty oceniono tylko po nazwie")

    def match(name: str) -> list[dict]:
        n = name.strip().lower()
        hits = [d for d in infos if (d.get("subject_cn") or "").strip().lower() == n]
        if not hits:
            hits = [d for d in infos if n in ((d.get("subject_o") or "").lower(), (d.get("subject_ou") or "").lower())]
        return hits

    roots: set[str] | None = None
    for domain, e in entries:
        scope = trust_scope(e)
        hits = match(e["name"])
        details = sorted(hits, key=lambda d: (not d["is_ca"], not d["self_signed"], d["expired"]))[0] if hits else None
        dup = False
        if details and PUBLIC_CA.search(e["name"] + " " + details.get("subject", "")):
            if roots is None:
                roots = system_root_hashes()
                if not roots:
                    rr = run(ROOTS_ARGV, timeout=20)
                    roots = {c["sha256"] for c in _sha_list(rr.out)} if rr.ok else set()
            dup = details["sha256"] in roots
        cls = classify_trusted_cert(e["name"], details, scope, domain, dup)
        policies = sorted({s.get("policy") or "wszystkie" for s in e["settings"]}) or ["wszystkie"]
        item = {"name": e["name"], "domain": domain, "trust": scope, "policies": policies,
                "subject": details and details["subject"], "issuer": details and details["issuer"],
                "not_before": details and details["not_before"], "not_after": details and details["not_after"],
                "expired": details and details["expired"], "is_ca": details and details["is_ca"],
                "self_signed": details and details["self_signed"], "sha256": details and details["sha256"],
                "kind": cls["kind"], "tool": cls.get("tool"), "risk": _sev(cls["score"]),
                "explanation": cls["explanation"]}
        audit["certificates"].append(item)
        if cls["score"] <= 0:
            continue
        conf = Confidence.HIGH if cls.get("confidence") == "high" else (Confidence.MEDIUM if cls["score"] >= 25
                                                                           else Confidence.LOW)
        title = {"interception_tool": f"Zaufany certyfikat narzędzia do podglądu HTTPS: {cls.get('tool')}",
                 "adware": f"Zaufany certyfikat adware: {e['name']}",
                 "impersonation": f"Certyfikat podszywający się pod urząd certyfikacji: {e['name']}",
                 "enterprise": f"Certyfikat firmowej/szkolnej inspekcji HTTPS: {e['name']}",
                 "antivirus_filter": f"Certyfikat filtra HTTPS programu ochronnego: {e['name']}",
                 "dev": f"Lokalny certyfikat deweloperski: {e['name']}",
                 }.get(cls["kind"], f"Nieznany zaufany certyfikat główny: {e['name']}")
        ctx.add_finding("certs", title, f"{'System' if domain == 'admin' else 'Użytkownik'}: {e['name']}",
                        [Signal(f"{CT}.{cls['kind'].title().replace('_', '')}", cls["score"], conf, cls["explanation"],
                                [x for x in (e["name"], item["sha256"] and f"SHA-256 {item['sha256']}",
                                             f"zaufanie: {scope}") if x])], item)
    order = {"malicious": 0, "suspicious": 1, "low": 2, "info": 3}
    audit["certificates"].sort(key=lambda c: (order.get(c["risk"], 9), c["name"].lower()))


def system_root_hashes(anchors: str = ANCHORS) -> set[str]:
    """SHA-256 of the root certificates built into macOS (readable files, also inside the sandbox)."""
    import hashlib
    out: set[str] = set()
    try:
        names = os.listdir(anchors)
    except OSError:
        return out
    for n in names:
        try:
            with open(os.path.join(anchors, n), "rb") as fh:
                data = fh.read(1 << 20)
        except OSError:
            continue
        if data.startswith(b"-----BEGIN"):
            import base64
            try:
                data = base64.b64decode("".join(re.findall(r"^[A-Za-z0-9+/=]+$", data.decode("ascii", "replace"), re.M)))
            except ValueError:
                continue
        out.add(hashlib.sha256(data).hexdigest().upper())
    return out


def _sha_list(text: str) -> list[dict]:
    return [{"sha256": m.group(1).upper()} for m in re.finditer(r"^SHA-256 hash: ([0-9A-Fa-f]+)", text or "", re.M)]

"""Behavioural analysis ("detonation") of suspicious shell/Python scripts.

Static analysis already flags scripts; for shell (sh/bash/zsh) and Python scripts that look
suspicious or obfuscated we additionally *run* them for a few seconds inside a maximally
locked-down macOS Seatbelt sandbox and record what they TRY to do, so hidden stages and intent
are revealed (download-and-execute, credential theft, persistence, exfiltration, Gatekeeper /
quarantine bypass, fake password prompts, reverse shells).

Only scripts are executed — never Mach-O binaries or .app bundles (deliberately: too risky on
the user's real Mac). The script itself is never *exec*'d from disk: we exec a trusted
interpreter (/bin/bash, /bin/zsh, /bin/sh or the venv Python) and hand it the copied script as
*data*, so the kernel's noexec workspace volume and the Seatbelt `process-exec` allow-list both
stay intact.

Layers of containment (see also cerber/sandbox.py, whose workspace/volume/kill machinery we reuse):

1. Workspace on a dedicated disk-image volume mounted noexec,nosuid,nodev (sandbox.new_workspace).
2. Seatbelt profile, deny-by-default: no network at all, no mach services, no AppleEvents, no
   IOKit; writes only inside the workspace; reads only of the system, the interpreter and the
   copied script and a FAKE home full of bait; `process-exec` only of the interpreters plus a
   handful of pure *data* tools (cat/base64/tr/…). Everything a dropper actually reaches for
   (curl, wget, osascript, security, launchctl, xattr, spctl, chmod, cp, zip, sqlite3, nc, ssh,
   any other python…) is DENIED, so the attempt fails but stays visible in the trace.
3. Resource limits (setrlimit): CPU, file size, open files, no cores, and RLIMIT_NPROC capped so
   fork bombs die; a wall-clock watchdog kills the whole process group and every tracked
   descendant afterwards.
4. Three independent observation channels, none of which the payload can silently defeat:
     * the macOS unified log (kernel `Sandbox:` deny/allow lines, tagged per run) — tamper-proof,
       records every denied syscall and every read of a bait file;
     * for shell: bash xtrace (SHELLOPTS=xtrace, inherited by child shells and `| sh`, `eval`,
       `$(...)`, `base64|bash`), captured on stderr — reveals the real commands incl. decoded ones;
     * for python: a sys.addaudithook installed BEFORE the script runs, logging compile (decoded
       exec() sources), open, subprocess, socket.connect/getaddrinfo, dlopen, file ops as JSON.

Decoded stages (python compile sources, shell lines produced by eval/pipes/base64) are re-scanned
with the static engine stack (analyzers + IOC) so their detections are reported too.
"""
from __future__ import annotations

import json
import os
import re
import resource
import signal
import subprocess
import sys
import threading
import time
import uuid
from typing import Callable

from . import config
from .sandbox import _kill_tracked, _killpg, new_workspace, remove_workspace

# --------------------------------------------------------------------------- tunables / limits
WALL_SECONDS = 15                 # default wall-clock budget (configurable per call)
CPU_SECONDS = 10                  # RLIMIT_CPU
FSIZE_BYTES = 10 << 20            # RLIMIT_FSIZE – a single written file
NOFILE = 64                       # RLIMIT_NOFILE
NPROC_HEADROOM = 50               # RLIMIT_NPROC = (this uid's current process count) + this
MAX_SCRIPT_BYTES = 1 << 20       # eligibility: scripts up to 1 MB are detonated
MAX_CAPTURE = 2 << 20            # bytes kept from each capture channel (stdout/stderr/audit log)
MAX_LOG_LINES = 20000             # kernel-log lines parsed at most
MAX_COMMANDS = 2000               # xtrace / audit command lines kept
LOG_SETTLE = 1.6                  # seconds to wait for the unified log to flush after the run

# interpreters we are willing to exec (resolved lazily, realpath)
SHELL_BINARIES = {"sh": "/bin/sh", "bash": "/bin/bash", "zsh": "/bin/zsh"}

# pure data tools: no network, no persistence, no credential surface – safe to let a script run so
# that decode/transform chains (base64 -d | bash, gunzip | sh, openssl enc -d …) actually unfold
# and get traced. Everything NOT here is denied by default and the attempt is recorded.
DATA_TOOLS = ["cat", "echo", "printf", "base64", "xxd", "tr", "sed", "awk", "cut", "rev", "head",
              "tail", "grep", "sort", "uniq", "wc", "gzip", "gunzip", "zcat", "openssl", "sleep",
              "true", "false", "test", "[", "expr", "od", "hexdump", "basename", "dirname",
              "uname", "sw_vers", "whoami", "id", "date"]
_TOOL_DIRS = ("/bin", "/usr/bin", "/usr/sbin")

SHELL_EXTS = {"sh", "bash", "zsh", "command", "tool"}
PY_EXTS = {"py", "pyw"}

# Detection *names* (from the real analyzers – scripts_shell/_python/_macos, ioc, embedded_blobs,
# scripts_common layer signals) that mark a script as worth detonating even when the overall
# verdict is only INFO. Matched as case-insensitive substrings of the detection name.
BEHAVIOUR_NAME_HINTS = (
    "obfusc", "multilayerencoding", "decodedexecutable", "scriptencoded", "packed", "shellcode",
    "downloadexec", "download", "pipetoshell", "decodepipe", "dropper", "installhook",
    "evalsubshell", "dynexec", "decodeexec", "reverseshell", "revshell", "namedpipeshell",
    "devtcp", "credentialexfil", "keychain", "browser", "macstealer", "stealer", "exfil",
    "passwordprompt", "fakepassword", "removequarantine", "disablegatekeeper", "persist",
    "launchctl", "crontab", "loginitems", "admin", "sudonopasswd", "marshalpickle", "embedded",
    "ioc:", "wallet", "backdoor", "c2",
)


# --------------------------------------------------------------------------- helpers
def _real(path: str) -> str:
    return os.path.realpath(path)


def _resolve_tools() -> list[str]:
    """Realpaths of the data tools that exist on this Mac (deduplicated)."""
    found: list[str] = []
    seen: set[str] = set()
    for name in DATA_TOOLS:
        for d in _TOOL_DIRS:
            p = os.path.join(d, name)
            if os.path.exists(p):
                rp = _real(p)
                if rp not in seen:
                    seen.add(rp)
                    found.append(rp)
                break
    return found


def _python_execs() -> list[str]:
    """Every binary path the venv python may turn into (venv symlink -> Cellar -> Python.app)."""
    out: list[str] = []
    seen: set[str] = set()
    venv = os.path.join(config.ROOT, ".venv")
    base = _real(sys.base_prefix)
    cands = [
        _real(sys.executable),
        os.path.join(venv, "bin/python"), os.path.join(venv, "bin/python3"),
        os.path.join(venv, "bin/python3.14"),
        os.path.join(base, "Resources/Python.app/Contents/MacOS/Python"),
        os.path.join(base, "bin/python3"), os.path.join(base, "bin/python3.14"),
    ]
    for c in cands:
        if os.path.exists(c):
            rp = _real(c)
            if rp not in seen:
                seen.add(rp)
                out.append(rp)
        elif c.endswith("/MacOS/Python"):          # may be reached via a non-realpath path
            out.append(c)
    return out


def _q(path: str) -> str:
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _first_line(data: bytes) -> str:
    return data[:512].split(b"\n", 1)[0].decode("utf-8", "replace")


def _shebang_kind(data: bytes) -> str | None:
    line = _first_line(data)
    if not line.startswith("#!"):
        return None
    low = line.lower()
    # e.g. #!/bin/bash, #!/usr/bin/env zsh, #!/usr/bin/python3
    if "python" in low:
        return "python"
    for name in ("zsh", "bash", "dash", "sh"):
        if re.search(rf"\b{name}\b", low):
            return "zsh" if name == "zsh" else "bash" if name in ("bash", "dash") else "sh"
    return None


def _looks_binary(data: bytes) -> bool:
    head = data[:4]
    # Mach-O (thin + fat/universal), PE, ELF, compiled AppleScript, Java, …
    if head in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf") or head[:2] in (b"MZ", b"PK") \
            or head == b"\x7fELF":
        return True
    return b"\x00" in data[:4096]


# --------------------------------------------------------------------------- eligibility
def eligible(result: dict, path: str) -> str | None:
    """Return the interpreter kind ("sh","bash","zsh","python") to detonate `path` with, or None.

    A script is eligible when it is a shell or Python script (by shebang or extension), textual,
    at most 1 MB, AND either the static verdict is SUSPICIOUS/MALICIOUS/PUA or at least one
    detection name indicates obfuscation / download-exec / dropper / stealer behaviour. Mach-O
    binaries and app bundles are never eligible.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(MAX_SCRIPT_BYTES + 1)
    except OSError:
        return None
    if len(head) > MAX_SCRIPT_BYTES or not head.strip():
        return None
    if _looks_binary(head):
        return None
    ext = path.rsplit(".", 1)[-1].lower() if "." in os.path.basename(path) else ""
    kind = _shebang_kind(head)
    if kind is None:
        if ext in PY_EXTS:
            kind = "python"
        elif ext in SHELL_EXTS:
            kind = "bash"               # default shell dialect when only an extension says so
        else:
            return None
    # a shebang python with a .sh extension (or vice-versa) trusts the shebang
    if kind == "python" and ext in SHELL_EXTS:
        kind = "bash"
    verdict = (result or {}).get("verdict", "CLEAN")
    if verdict in ("SUSPICIOUS", "MALICIOUS", "PUA"):
        return kind
    for d in (result or {}).get("detections", []) or []:
        name = str(d.get("name", "")).lower()
        if any(h in name for h in BEHAVIOUR_NAME_HINTS):
            return kind
    return None


# --------------------------------------------------------------------------- Seatbelt profile
#: sentinels in the profile that detonate_file replaces with this run's unique unified-log tags
DENYTAG_TOKEN = "__CERBER_DENYTAG__"
BAITTAG_TOKEN = "__CERBER_BAITTAG__"


def build_profile(work: str, script: str, kind: str) -> str:
    """Build the deny-by-default SBPL profile for detonating `script` (already inside `work`).

    The profile embeds two sentinel tokens (DENYTAG_TOKEN on the default-deny message, BAITTAG_TOKEN
    on the fake-home report message); detonate_file replaces them with per-run tags so this run's
    kernel `Sandbox:` log lines can be told apart from everyone else's. `script` is read by the
    interpreter as data – it is never itself exec'd (the workspace is also process-exec-denied).
    """
    work = _real(work)
    home = os.path.join(work, "home")
    runp = os.path.join(work, "run")
    tmp = os.path.join(work, "tmp")
    out = os.path.join(work, "out")

    if kind == "python":
        execs = _python_execs()
    else:
        # a shell may legitimately re-exec sh/bash/zsh (`| sh`, `bash -c`, `exec zsh`) – allow all
        # three real interpreters, plus the data tools, and nothing else.
        execs = [_real(p) for p in SHELL_BINARIES.values() if os.path.exists(p)]
    execs += _resolve_tools()
    # dedupe, keep order
    seen: set[str] = set()
    execs = [e for e in execs if not (e in seen or seen.add(e))]

    # read-only system surface the interpreter needs to start and resolve commands.
    # Proven by experiment: without /usr/lib + /System (dyld shared cache, system frameworks) and a
    # readable "/" the interpreter aborts (SIGABRT). /usr/share carries locale/terminfo. The venv /
    # python framework dirs are needed only for the Python interpreter but are harmless for shells.
    venv = os.path.join(config.ROOT, ".venv")
    reads = ["/usr/lib", "/System", "/usr/share", "/private/etc/localtime",
             "/private/var/db/timezone"]
    if kind == "python":
        reads += [venv, _real(sys.base_prefix), "/opt/homebrew/Cellar/python@3.14",
                  "/opt/homebrew/opt/python@3.14"]

    lines = [
        "(version 1)",
        # the deny-default message is tagged so we can filter THIS run's denials out of the log
        f'(deny default (with message "{DENYTAG_TOKEN}"))',
        "(allow process-fork)",                         # bash/sh fork for every external command
        "(allow process-exec " + " ".join(f"(literal {_q(e)})" for e in execs) + ")",
        "(allow signal (target same-sandbox))",         # job control / kill within the sandbox only
        "(allow sysctl-read)",                          # harmless; silences interpreter start noise
        "(allow ipc-posix-sem)",
        "(allow ipc-posix-shm-read-data ipc-posix-shm-write-data ipc-posix-shm-write-create"
        " ipc-posix-shm-write-unlink)",
        "(allow file-read-metadata)",
        '(allow file-read* (literal "/") (literal "/dev/null") (literal "/dev/zero")'
        ' (literal "/dev/urandom") (literal "/dev/random") (literal "/dev/fd") (subpath "/dev/fd")'
        ' (literal "/dev/tty"))',
        "(allow file-read* " + " ".join(f"(subpath {_q(p)})" for p in reads if os.path.exists(p))
        + " " + " ".join(f"(literal {_q(e)})" for e in execs) + ")",
        # the workspace itself: read+write for run/tmp/out (script + captures live here)
        f"(allow file-read* file-write* (subpath {_q(runp)}) (subpath {_q(tmp)}) (subpath {_q(out)}))",
        # /dev/null etc. must be writable for the near-universal `2>/dev/null` / `>/dev/null` idiom
        '(allow file-write-data file-ioctl (literal "/dev/null") (literal "/dev/dtracehelper"))',
        # the FAKE home: full read+write, but every access is REPORTED (tagged) so a read of a bait
        # file is visible in the log as credential-access behaviour.
        f'(allow file-read* file-write* (subpath {_q(home)}) (with report) (with message "{BAITTAG_TOKEN}"))',
        "(deny appleevent-send)",
        # ---- defence-in-depth deny rules (kept even though deny-default already covers them) ----
        f"(deny process-exec (subpath {_q(work)}))",    # nothing stored in the workspace may run
        '(deny mach-lookup (global-name-prefix "com.apple.tccd")'
        ' (global-name-prefix "com.apple.pasteboard") (global-name-prefix "com.apple.windowserver")'
        ' (global-name-prefix "com.apple.coreservices.appleevents")'
        ' (global-name-prefix "com.apple.security.keychain")'
        ' (global-name-prefix "com.apple.securityd") (global-name-prefix "com.apple.authd")'
        ' (global-name-prefix "com.apple.SecurityAgent")'
        ' (global-name-prefix "com.apple.CoreAuthentication")'
        ' (global-name-prefix "com.apple.locationd") (global-name-prefix "com.apple.cmio")'
        ' (global-name-prefix "com.apple.audio") (global-name-prefix "com.apple.screencapture"))',
        f'(deny file-read-data (subpath {_q(os.path.expanduser("~/Library/Keychains"))})'
        ' (subpath "/Library/Keychains") (subpath "/private/var/db/SystemKey"))',
        f'(deny file-write* (subpath {_q(config.ROOT)}) (subpath {_q(os.path.expanduser("~"))})'
        ' (subpath "/Applications") (subpath "/Library") (subpath "/usr/local") (subpath "/opt"))',
        # absolutely no network of any kind (no exceptions): neither remote connects nor DNS,
        # nor listening sockets.
        "(deny network*)",
        "(deny network-outbound)",
        "(deny network-bind network-inbound)",
    ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- python audit wrapper
def _py_wrapper_source() -> str:
    """Source of the in-sandbox wrapper: installs an audit hook BEFORE running the target (runpy).

    The hook only *records* (Seatbelt is what actually enforces); it logs JSON lines to
    CERBER_AUDIT_LOG. It is armed right before run_path so the interpreter's own start-up compiles
    (importlib/runpy) don't pollute the decoded-stage capture. The hook is appended once and cannot
    be removed in CPython; a payload that tried to spawn a fresh un-hooked python is blocked by
    Seatbelt (process-exec of any other interpreter is denied) rather than by the hook.
    """
    return r'''import sys, os, json, runpy
_CAP = 200000
_LIMIT = 4_000_000
_w = [0]
_armed = [False]
try:
    _log = open(os.environ["CERBER_AUDIT_LOG"], "w", buffering=1)
except OSError:
    _log = None
def _rec(obj):
    if _log is None or _w[0] > _LIMIT:
        return
    try:
        s = json.dumps(obj, default=str)[:20000]
    except Exception:
        return
    _w[0] += len(s)
    try:
        _log.write(s + "\n"); _log.flush()
    except OSError:
        pass
def _hook(event, args):
    try:
        if event == "compile":
            if not _armed[0]:
                return
            src = args[0]
            if isinstance(src, (bytes, bytearray)):
                src = bytes(src).decode("utf-8", "replace")
            if isinstance(src, str) and src.strip():
                _rec({"ev": "compile", "src": src[:_CAP]})
        elif event == "exec":
            _rec({"ev": "exec"})
        elif event == "open":
            _rec({"ev": "open", "path": str(args[0]), "mode": str(args[1])})
        elif event in ("os.listdir", "os.scandir"):
            _rec({"ev": event, "path": str(args[0])})
        elif event in ("subprocess.Popen", "os.exec", "os.posix_spawn", "os.spawn", "os.system",
                       "pty.spawn"):
            _rec({"ev": event, "args": [str(a)[:400] for a in args]})
        elif event == "socket.connect":
            _rec({"ev": "socket.connect", "addr": str(args[1])[:200]})
        elif event == "socket.getaddrinfo":
            _rec({"ev": "socket.getaddrinfo", "host": str(args[0]), "port": str(args[1])})
        elif event in ("urllib.Request",):
            _rec({"ev": "urllib.Request", "url": str(args[0])[:400]})
        elif event == "ctypes.dlopen":
            _rec({"ev": "ctypes.dlopen", "name": str(args[0])[:200]})
        elif event in ("os.remove", "os.rename", "os.unlink", "os.chmod"):
            _rec({"ev": event, "args": [str(a)[:200] for a in args]})
        elif event in ("shutil.copyfile", "shutil.copymode", "shutil.copystat", "shutil.copytree",
                       "shutil.move", "shutil.rmtree"):
            _rec({"ev": event, "args": [str(a)[:200] for a in args[:2]]})
    except Exception:
        pass
sys.addaudithook(_hook)
_target = os.environ["CERBER_TARGET"]
# make the target believe it runs as a normal module from its own dir
sys.argv = [_target]
_armed[0] = True
try:
    runpy.run_path(_target, run_name="__main__")
except SystemExit:
    pass
except BaseException as exc:  # noqa: BLE001 - record, never crash the wrapper
    sys.stderr.write("CERBER_SCRIPT_EXC: %r\n" % (exc,))
'''


# --------------------------------------------------------------------------- resource limits
def _limits(nproc_cap: int) -> Callable[[], None]:
    def preexec() -> None:
        os.setsid()
        os.umask(0o077)
        try:
            os.nice(5)
        except OSError:
            pass
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (FSIZE_BYTES, FSIZE_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (NOFILE, NOFILE))
        except (ValueError, OSError):
            pass
        try:
            # RLIMIT_NPROC counts ALL processes of this real uid (not just this group), so the cap
            # must be current usage + headroom or the interpreter itself can't fork. A fork bomb is
            # then stopped once it reaches the headroom.
            resource.setrlimit(resource.RLIMIT_NPROC, (nproc_cap, nproc_cap))
        except (ValueError, OSError):
            pass
    return preexec


def _pgid_members(pgid: int) -> list[int]:
    """PIDs still alive in process group `pgid` (the sandbox's group leader is sandbox-exec)."""
    try:
        out = subprocess.run(["/bin/ps", "-axo", "pid=,pgid="], capture_output=True, text=True,
                             timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    members = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            if int(parts[1]) == pgid and int(parts[0]) != os.getpid():
                members.append(int(parts[0]))
    return members


def _uid_proc_count() -> int:
    try:
        out = subprocess.run(["/bin/ps", "-axo", "uid="], capture_output=True, text=True,
                             timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return 400
    me = str(os.getuid())
    return sum(1 for tok in out.split() if tok == me)


# --------------------------------------------------------------------------- bait home
_BAIT_FILES = {
    "login.keychain-db": b"\x6b\x79\x63\x68fake-keychain-blob\x00",
    "Library/Keychains/login.keychain-db": b"fake login keychain",
    "Library/Application Support/Google/Chrome/Default/Login Data": b"SQLite format 3\x00fake-chrome-logins",
    "Library/Application Support/Google/Chrome/Default/Cookies": b"SQLite format 3\x00fake-chrome-cookies",
    "Library/Application Support/Google/Chrome/Local State": b'{"os_crypt":{"encrypted_key":"ZmFrZQ=="}}',
    "Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data": b"SQLite format 3\x00fake-brave",
    "Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies": b"SQLite format 3\x00fake",
    "Library/Application Support/Microsoft Edge/Default/Login Data": b"SQLite format 3\x00fake-edge",
    "Library/Application Support/Firefox/Profiles/x.default/logins.json": b'{"logins":[{"u":"fake"}]}',
    "Library/Application Support/Firefox/Profiles/x.default/key4.db": b"SQLite format 3\x00fake-key4",
    "Library/Cookies/Cookies.binarycookies": b"cook\x00\x00\x00fake-safari-cookies",
    "Library/Application Support/Exodus/exodus.wallet/seed.seco": b"fake exodus seed",
    "Library/Application Support/Electrum/wallets/default_wallet": b'{"seed":"fake electrum"}',
    "Library/Application Support/atomic/Local Storage/leveldb/000003.log": b"fake atomic wallet",
    # MetaMask / Phantom browser-extension stores under real extension ids
    "Library/Application Support/Google/Chrome/Default/Local Extension Settings/"
    "nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log": b"fake metamask vault",
    "Library/Application Support/Google/Chrome/Default/Local Extension Settings/"
    "bfnaelmomeimhlpmgjnjophhpkkoljpa/000003.log": b"fake phantom vault",
    ".ssh/id_rsa": b"-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----\n",
    ".ssh/id_ed25519": b"-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZTI=\n-----END OPENSSH PRIVATE KEY-----\n",
    ".aws/credentials": b"[default]\naws_access_key_id=AKIAFAKE\naws_secret_access_key=fakefakefake\n",
    "Library/Application Support/Telegram Desktop/tdata/key_datas": b"fake telegram tdata",
    "Library/Group Containers/group.com.apple.notes/NoteStore.sqlite": b"SQLite format 3\x00fake-notes",
    ".bash_history": b"ls\ncd ~\n",
    ".zsh_history": b": 0:0;ls\n",
}
# basenames (lower-cased) that count as a credential-access bait when read
_BAIT_HINTS = ("keychain", "login data", "cookies", "local state", "logins.json", "key4.db",
               "binarycookies", "id_rsa", "id_ed25519", "credentials", "wallet", "seco",
               "leveldb", "tdata", "key_datas", "notestore", "seed", "exodus", "electrum",
               "metamask", "phantom", "000003.log")


def _build_home(home: str) -> None:
    for rel, data in _BAIT_FILES.items():
        p = os.path.join(home, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        try:
            with open(p, "wb") as fh:
                fh.write(data)
        except OSError:
            pass


# --------------------------------------------------------------------------- unified-log reader
_DENY_RX = re.compile(r"Sandbox:\s+(\S+?)\((\d+)\)\s+deny\(\d+\)\s+(\S+)\s*(.*)")
_BAIT_RX = re.compile(r"Sandbox:\s+(\S+?)\((\d+)\)\s+allow\s+file-read\S*\s+(/\S.*)")


class _LogStream:
    """Live capture of THIS run's kernel `Sandbox:` lines via `log stream`.

    `log show` has to index the whole requested time window (~10 s per call here), so instead we
    start a `log stream` filtered to our two per-run tags BEFORE the sandbox runs and parse its
    buffered output afterwards. This is the tamper-proof channel: a payload inside the sandbox
    cannot suppress kernel denial/report lines. warmup() must be awaited before the run so no early
    event is missed.
    """

    def __init__(self, denytag: str, baittag: str):
        self.denytag = denytag
        self.baittag = baittag
        self._buf: list[str] = []
        self._proc: subprocess.Popen | None = None
        pred = f'eventMessage CONTAINS "{denytag}" OR eventMessage CONTAINS "{baittag}"'
        try:
            self._proc = subprocess.Popen(
                ["/usr/bin/log", "stream", "--style", "ndjson", "--predicate", pred],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except (OSError, subprocess.SubprocessError):
            self._proc = None
            return
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self) -> None:
        try:
            for line in self._proc.stdout:            # type: ignore[union-attr]
                self._buf.append(line)
                if len(self._buf) > MAX_LOG_LINES:
                    del self._buf[: MAX_LOG_LINES // 4]
        except (OSError, ValueError):
            pass

    @property
    def ok(self) -> bool:
        return self._proc is not None

    def stop(self) -> tuple[list[dict], list[str]]:
        if self._proc is None:
            return [], []
        try:
            self._proc.terminate()
            self._proc.wait(timeout=1.5)
        except (OSError, subprocess.SubprocessError):
            try:
                self._proc.kill()
            except OSError:
                pass
        try:
            if self._proc.stdout:
                self._proc.stdout.close()
        except (OSError, ValueError):
            pass
        denials: list[dict] = []
        baits: list[str] = []
        for line in self._buf:
            line = line.strip().rstrip(",")
            if not line or line[0] != "{":
                continue
            try:
                msg = json.loads(line).get("eventMessage", "")
            except ValueError:
                continue
            first = msg.split("\n", 1)[0]
            if self.denytag in msg:
                m = _DENY_RX.search(first)
                if m:
                    denials.append({"proc": m.group(1), "pid": m.group(2), "op": m.group(3),
                                    "detail": m.group(4).strip()})
            elif self.baittag in msg:
                m = _BAIT_RX.search(first)
                if m:
                    baits.append(m.group(3).strip())
        return denials, baits


# --------------------------------------------------------------------------- xtrace / audit parse
_XTRACE_RX = re.compile(r"^\++\[\d+:\d*\]\s?(.*)$")


def _parse_xtrace(stderr: str) -> tuple[list[str], list[str]]:
    """(commands, errors) from bash xtrace. PS4 is '+[pid:line] '."""
    cmds: list[str] = []
    errs: list[str] = []
    for line in stderr.splitlines():
        m = _XTRACE_RX.match(line)
        if m:
            cmd = m.group(1).strip()
            if cmd and cmd not in cmds[-1:]:
                cmds.append(cmd)
                if len(cmds) >= MAX_COMMANDS:
                    break
        elif "Operation not permitted" in line or "command not found" in line:
            errs.append(line.strip()[:200])
    return cmds, errs


def _parse_audit(path: str) -> list[dict]:
    events: list[dict] = []
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                if len(events) >= MAX_COMMANDS:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return events


# --------------------------------------------------------------------------- IOC + targets
_URL_RX = re.compile(r"https?://[^\s'\"|>)<`]+", re.I)
_IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DEVTCP_RX = re.compile(r"/dev/(?:tcp|udp)/([0-9a-zA-Z.\-]+)/(\d+)")
_HOST_IN_URL = re.compile(r"https?://([^/:\s]+)")


def _classify_target(value: str) -> str:
    return "ip" if _IP_RX.fullmatch(value) else "domain"


def _ioc_lookup(ioc, kind: str, value: str) -> str | None:
    if ioc is None:
        return None
    try:
        return ioc.lookup(kind, value)
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- static re-scan
_STAGE_PIPE = None
_STAGE_LOCK = threading.Lock()


def _stage_pipeline():
    """A lightweight Pipeline for re-scanning decoded stages: all analyzers + the (fast, sqlite)
    IOC service, but NOT the heavy ClamAV/YARA engines – those take minutes to load and the parent
    already ran them against the original file."""
    global _STAGE_PIPE
    with _STAGE_LOCK:
        if _STAGE_PIPE is None:
            from .analyzers import load_all
            from .engines.ioc_fuzzy import IocService
            from .pipeline import Pipeline
            svc = type("Services", (), {})()
            svc.ioc = IocService(config.IOCDB) if os.path.exists(config.IOCDB) else None
            _STAGE_PIPE = Pipeline(engines=[], analyzers=load_all(), services=svc,
                                   options={"deep": True, "macos": False})
        return _STAGE_PIPE


def _scan_stage(source: bytes, lang_hint: str) -> list[dict]:
    """Return scanner-shaped detection dicts for one decoded stage."""
    from .core import ScanObject
    try:
        pipe = _stage_pipeline()
        name = "stage.py" if lang_hint == "python" else "stage.sh"
        root = pipe.scan_bytes(source, f"detonate>>decoded/{name}")
    except Exception:  # noqa: BLE001
        return []
    dets = []
    for o in root.iter_tree():
        if not isinstance(o, ScanObject):
            continue
        for d in o.detections:
            x = d.to_dict()
            x["object"] = o.display_path
            dets.append(x)
    return dets


# --------------------------------------------------------------------------- behaviour model
def _sev(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 25:
        return "medium"
    if score >= 10:
        return "low"
    return "info"


class _Behaviours:
    """Accumulates behaviours keyed by id; merges evidence and keeps the max score."""

    def __init__(self) -> None:
        self._by_id: dict[str, dict] = {}

    def add(self, bid: str, title: str, detail: str, score: int, evidence) -> None:
        if isinstance(evidence, str):
            evidence = [evidence]
        ev = [e[:300] for e in (evidence or []) if e][:12]
        cur = self._by_id.get(bid)
        if cur is None:
            self._by_id[bid] = {"id": bid, "title": title, "detail": detail, "score": score,
                                "severity": _sev(score), "evidence": ev}
        else:
            cur["score"] = max(cur["score"], score)
            cur["severity"] = _sev(cur["score"])
            for e in ev:
                if e not in cur["evidence"] and len(cur["evidence"]) < 12:
                    cur["evidence"].append(e)

    def list(self) -> list[dict]:
        return sorted(self._by_id.values(), key=lambda b: b["score"], reverse=True)


# behaviour catalogue: id -> (Polish title, Polish description template). Scores are assigned at
# detection time. English ids, Polish user-facing text (matches the rest of Cerber).
_B = {
    "download_exec": ("Pobranie i uruchomienie kodu", "Skrypt pobiera zdalną treść i od razu ją wykonuje."),
    "fetch_remote": ("Pobieranie z adresu URL/IP", "Skrypt próbuje pobrać dane ze zdalnego adresu."),
    "persistence": ("Utrwalanie w systemie", "Skrypt instaluje mechanizm automatycznego startu (LaunchAgent/Daemon, cron, login item, pliki rc)."),
    "credential_access": ("Dostęp do poświadczeń", "Skrypt sięga po hasła, klucze lub dane logowania (pęk kluczy, przeglądarki, SSH, portfele)."),
    "fake_prompt": ("Fałszywe pytanie o hasło", "Skrypt wyświetla podrobione okno z prośbą o hasło (osascript, ukryta odpowiedź)."),
    "gatekeeper_bypass": ("Omijanie Gatekeepera/kwarantanny", "Skrypt usuwa atrybut kwarantanny lub wyłącza Gatekeeper/SIP."),
    "exfiltration": ("Wyprowadzanie danych", "Skrypt próbuje wysłać zebrane dane lub archiwa na zewnątrz."),
    "anti_analysis": ("Wykrywanie analizy / zwłoka", "Skrypt sprawdza, czy działa w maszynie wirtualnej/sandboksie, albo długo zwleka."),
    "privilege_escalation": ("Podniesienie uprawnień", "Skrypt próbuje uzyskać uprawnienia administratora (sudo, „with administrator privileges”)."),
    "self_deletion": ("Samousuwanie", "Skrypt usuwa sam siebie, aby zatrzeć ślady."),
    "chmod_payload": ("Nadanie praw wykonywania", "Skrypt nadaje prawa wykonywania pobranemu plikowi."),
    "reverse_shell": ("Powłoka zwrotna", "Skrypt nawiązuje połączenie zwrotne dające zdalną powłokę."),
    "process_launch": ("Uruchamianie narzędzi systemowych", "Skrypt próbuje uruchomić zewnętrzne narzędzia (zablokowane w sandboksie)."),
}


def _b(beh: _Behaviours, bid: str, score: int, evidence) -> None:
    title, detail = _B[bid]
    beh.add(bid, title, detail, score, evidence)


# patterns over the combined command corpus (shell xtrace + python audit arg strings)
def _analyze_commands(corpus_lines: list[str], beh: _Behaviours) -> None:
    joined = "\n".join(corpus_lines)
    low = joined.lower()

    def near(cmd: str) -> list[str]:
        return [l for l in corpus_lines if cmd in l.lower()][:4]

    # download tools
    if re.search(r"\b(curl|wget|fetch)\b", low):
        for l in corpus_lines:
            if re.search(r"\b(curl|wget|fetch)\b", l.lower()) and ("http" in l.lower() or _IP_RX.search(l)):
                _b(beh, "fetch_remote", 25, l)
    # download + execute (pipe to interpreter)
    if re.search(r"\|\s*(sudo\s+)?(bash|sh|zsh|python[0-9.]*|perl|ruby)\b", low) and \
            re.search(r"\b(curl|wget|fetch)\b", low):
        _b(beh, "download_exec", 40, near("curl") + near("wget"))
    if re.search(r"base64\s+(-d|-D|--decode)\b", low) and \
            re.search(r"\|\s*(bash|sh|zsh|python[0-9.]*)\b", low):
        _b(beh, "download_exec", 35, [l for l in corpus_lines if "base64" in l.lower()][:4])
    # persistence
    if re.search(r"launchctl\s+(load|bootstrap|enable)\b", low) or "launchagents" in low or \
            "launchdaemons" in low or re.search(r"\bcrontab\b", low) or "loginitems" in low or \
            re.search(r"(\.bashrc|\.zshrc|\.zprofile|\.bash_profile|\.profile)", low):
        _b(beh, "persistence", 30, near("launchctl") + near("crontab") +
           [l for l in corpus_lines if "launchagent" in l.lower() or "zshrc" in l.lower()][:3])
    # credential tools
    if re.search(r"security\s+(find-generic-password|find-internet-password|dump-keychain|unlock-keychain)", low):
        _b(beh, "credential_access", 35, near("security"))
    if re.search(r"\bsqlite3\b", low) and ("login data" in low or "cookies" in low):
        _b(beh, "credential_access", 30, near("sqlite3"))
    if re.search(r"\bdscl\b.*(-authonly|read.*password)", low):
        _b(beh, "credential_access", 30, near("dscl"))
    # copying / reading credential stores by path (even when cp/cat itself is blocked, the attempt is visible)
    cred_rx = re.compile(r"\b(cp|cat|ditto|zip|tar|scp|rsync|base64|xxd|open|head|sqlite3)\b[^\n]*"
                         r"(keychains|login data|cookies|key4\.db|logins\.json|\.ssh/id_|local extension settings|"
                         r"exodus|electrum|atomic/|wallet|\.aws/credentials|tdata|notestore)")
    cred = [l for l in corpus_lines if cred_rx.search(l.lower())]
    if cred:
        _b(beh, "credential_access", 30, cred[:4])
    # fake password prompt
    if "osascript" in low and "display dialog" in low and ("hidden answer" in low or "password" in low):
        _b(beh, "fake_prompt", 30, near("osascript"))
    # gatekeeper / quarantine
    if re.search(r"xattr\b[^\n]*(-d|-c)r?\b[^\n]*com\.apple\.quarantine", low) or \
            re.search(r"xattr\s+-c", low):
        _b(beh, "gatekeeper_bypass", 25, near("xattr"))
    if "spctl" in low and ("--master-disable" in low or "--add" in low or "--disable" in low):
        _b(beh, "gatekeeper_bypass", 35, near("spctl"))
    if "csrutil" in low and "disable" in low:
        _b(beh, "gatekeeper_bypass", 35, near("csrutil"))
    # exfiltration – curl upload flags are CASE-SENSITIVE (-F form vs -f fail), so match the
    # original-case corpus, not the lower-cased one
    if re.search(r"curl\b[^\n]*(?:-F|--form|-d\b|--data|-T|--upload-file)[^\n]*https?://", joined):
        _b(beh, "exfiltration", 35, [l for l in corpus_lines if "curl" in l.lower() and
           re.search(r"-F|--form|--data|--upload|-T ", l)][:4])
    if re.search(r"\b(scp|rsync)\b\s+[^\n]*@[\w.\-]+:", low):
        _b(beh, "exfiltration", 25, near("scp") + near("rsync"))
    if re.search(r"\b(zip\s+-r|ditto\s+-c|tar\s+-?c)", low) and \
            re.search(r"(library|keychain|wallet|\.ssh|cookies|login data)", low):
        _b(beh, "exfiltration", 20, near("zip") + near("ditto") + near("tar"))
    # privilege escalation
    if re.search(r"\bsudo\b", low) or "with administrator privileges" in low or "nopasswd" in low:
        _b(beh, "privilege_escalation", 25, near("sudo") +
           [l for l in corpus_lines if "administrator privileges" in l.lower()][:3])
    # self-deletion
    if re.search(r"\brm\b[^\n]*(\$0|\"\$0\"|'\$0'|\bthis_?file|\${BASH_SOURCE)", low):
        _b(beh, "self_deletion", 20, [l for l in corpus_lines if "rm " in l.lower()][:4])
    # chmod +x of a payload
    if re.search(r"chmod\s+[0-7]*\+?x", low) or re.search(r"chmod\s+\d*7\d*", low):
        _b(beh, "chmod_payload", 15, near("chmod"))
    # reverse shell
    if _DEVTCP_RX.search(joined) or re.search(r"\b(nc|ncat|netcat)\b[^\n]*-e", low) or \
            re.search(r"bash\s+-i\b", low) or "mkfifo" in low:
        _b(beh, "reverse_shell", 45, [l for l in corpus_lines if "/dev/tcp" in l.lower() or
           "mkfifo" in l.lower() or re.search(r"\bnc\b", l.lower())][:4])
    # anti-analysis
    if re.search(r"sysctl[^\n]*(hw\.model|machdep\.cpu|vmm)", low) or \
            re.search(r"(ioreg[^\n]*(vmware|virtualbox|parallels|qemu))", low) or \
            re.search(r"\bsleep\s+(\d{3,})", low):
        _b(beh, "anti_analysis", 15, [l for l in corpus_lines if "sysctl" in l.lower() or
           "ioreg" in l.lower() or re.search(r"sleep\s+\d{3,}", l.lower())][:4])


def _analyze_denials(denials: list[dict], beh: _Behaviours) -> None:
    """Denied exec of a sensitive tool is itself an attempt worth reporting."""
    tools = {}
    for d in denials:
        if d["op"].startswith("process-exec"):
            name = os.path.basename(d["detail"].split()[0]) if d["detail"] else ""
            if name:
                tools[name] = tools.get(name, 0) + 1
    sens = {"curl", "wget", "osascript", "security", "launchctl", "spctl", "xattr", "sqlite3",
            "nc", "ncat", "ssh", "scp", "chmod", "sudo", "csrutil", "ditto", "zip", "python",
            "python3", "perl", "ruby", "node", "defaults", "crontab", "profiles", "dscl"}
    hit = sorted(t for t in tools if t in sens)
    if hit:
        _b(beh, "process_launch", 15, [f"próba uruchomienia: {t}" for t in hit])


def _analyze_bait(bait_paths: list[str], py_opens: list[str], beh: _Behaviours,
                  home: str = "") -> list[str]:
    def pretty(p: str) -> str:
        return "~" + p[len(home):] if home and p.startswith(home) else p
    reads = []
    for p in list(bait_paths) + list(py_opens):
        low = p.lower()
        if any(h in low for h in _BAIT_HINTS):
            reads.append(pretty(p))
    reads = sorted(set(reads))
    if reads:
        _b(beh, "credential_access", 35, reads)
    return reads


# --------------------------------------------------------------------------- main entry
def detonate_file(path: str, kind: str, timeout: int = WALL_SECONDS,
                  emit: Callable[[dict], None] | None = None,
                  cancel: "threading.Event | None" = None) -> dict:
    """Detonate `path` (kind: sh|bash|zsh|python) in a sealed sandbox and return a behaviour report.

    Safe to call from the parent process (gui_backend) outside any sandbox: it spawns sandbox-exec
    itself. Always runs inside a fresh noexec workspace which is always removed.
    """
    emit = emit or (lambda ev: None)
    t_start = time.time()
    result: dict = {
        "ran": False, "kind": kind, "seconds": 0.0, "exit_code": None, "timed_out": False,
        "killed_processes": 0, "behaviors": [], "commands": [], "network": [], "files_read": [],
        "files_written": [], "stages": [], "score": 0, "verdict": "CLEAN", "detections": [],
        "limitations": [],
    }
    if kind not in ("sh", "bash", "zsh", "python"):
        result["limitations"].append(f"nieobsługiwany interpreter: {kind}")
        return result
    try:
        with open(path, "rb") as fh:
            script_bytes = fh.read(MAX_SCRIPT_BYTES + 1)
    except OSError as exc:
        result["limitations"].append(f"nie można odczytać skryptu: {exc}")
        return result
    if len(script_bytes) > MAX_SCRIPT_BYTES:
        result["limitations"].append("skrypt większy niż 1 MB – nie detonuję")
        return result

    denytag = "CERBDENY" + uuid.uuid4().hex[:16]
    baittag = "CERBBAIT" + uuid.uuid4().hex[:16]
    work = new_workspace()
    beh = _Behaviours()
    logstream: "_LogStream | None" = None
    try:
        runp = os.path.join(work, "run")
        home = os.path.join(work, "home")
        out = os.path.join(work, "out")
        os.makedirs(runp, mode=0o700, exist_ok=True)   # new_workspace makes in/x/tmp/home/out, not run
        os.makedirs(out, mode=0o700, exist_ok=True)
        _build_home(home)
        script_name = "script.py" if kind == "python" else "script.sh"
        script_path = os.path.join(runp, script_name)
        with open(script_path, "wb") as fh:
            fh.write(script_bytes)
        audit_log = os.path.join(out, "pyaudit.log")
        if kind == "python":
            with open(os.path.join(runp, "_wrapper.py"), "w") as fh:
                fh.write(_py_wrapper_source())

        profile = build_profile(work, script_path, kind) \
            .replace(DENYTAG_TOKEN, denytag).replace(BAITTAG_TOKEN, baittag)
        prof_path = os.path.join(work, "detonate.sb")
        with open(prof_path, "w") as fh:
            fh.write(profile)

        env = {"PATH": "/usr/bin:/bin", "HOME": home, "CFFIXED_USER_HOME": home,
               "TMPDIR": os.path.join(work, "tmp"), "LANG": "en_US.UTF-8",
               "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "PYTHONUNBUFFERED": "1"}
        if kind in ("sh", "bash"):
            # xtrace exported so child shells and `| sh` / `bash -c` / `eval` / `$(...)` inherit it
            env["SHELLOPTS"] = "xtrace"
            env["PS4"] = "+[$$:${LINENO}] "
            interp = SHELL_BINARIES["bash"] if kind == "bash" else SHELL_BINARIES["sh"]
            inner = [interp, script_name]
        elif kind == "zsh":
            interp = SHELL_BINARIES["zsh"]
            inner = [interp, "-x", script_name]
            result["limitations"].append(
                "zsh nie dziedziczy xtrace przez zmienną środowiska – śledzony jest tylko proces "
                "główny (potoki do podpowłok zsz nie są prześledzone); dane z logu jądra i baitów "
                "są pełne")
        else:
            env["CERBER_AUDIT_LOG"] = audit_log
            env["CERBER_TARGET"] = script_path
            inner = [_real(sys.executable), "-I", "_wrapper.py"]

        cmd = ["/usr/bin/sandbox-exec", "-f", prof_path] + inner
        nproc_cap = _uid_proc_count() + NPROC_HEADROOM
        emit({"ev": "log", "msg": f"Detonacja ({kind}) w sandboksie, limit {timeout}s…"})

        # start the kernel-log capture BEFORE the run and let it warm up so no early event is missed
        logstream = _LogStream(denytag, baittag)
        if logstream.ok:
            time.sleep(1.0)
        else:
            result["limitations"].append("nie udało się uruchomić podglądu logu jądra (log stream)")

        proc = subprocess.Popen(cmd, cwd=runp, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                preexec_fn=_limits(nproc_cap))
        out_buf: list[str] = []
        err_buf: list[str] = []

        def drain(stream, buf) -> None:
            try:
                for line in stream:
                    buf.append(line)
                    if sum(len(x) for x in buf) > MAX_CAPTURE:
                        del buf[: len(buf) // 2]
            except (OSError, ValueError):
                pass
        th_out = threading.Thread(target=drain, args=(proc.stdout, out_buf), daemon=True)
        th_err = threading.Thread(target=drain, args=(proc.stderr, err_buf), daemon=True)
        th_out.start()
        th_err.start()

        tracked: dict[int, str] = {}
        state = {"why": None}

        def _track() -> None:
            try:
                ps = subprocess.run(["/bin/ps", "-axo", "pid=,ppid=,lstart="], capture_output=True,
                                    text=True, timeout=10).stdout
            except (OSError, subprocess.SubprocessError):
                return
            rows = {}
            for line in ps.splitlines():
                parts = line.split(None, 2)
                if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
                    rows[int(parts[0])] = (int(parts[1]), parts[2])
            known = {proc.pid} | set(tracked)
            changed = True
            while changed:
                changed = False
                for pid, (ppid, start) in rows.items():
                    if ppid in known and pid not in known:
                        known.add(pid)
                        tracked[pid] = start
                        changed = True

        def killer() -> None:
            t0 = time.time()
            last = 0.0
            while proc.poll() is None:
                if time.time() - last > 1.5:
                    last = time.time()
                    _track()
                if cancel is not None and cancel.is_set() and state["why"] is None:
                    state["why"] = "cancel"
                    _killpg(proc, signal.SIGINT)
                    t = time.time()
                    while proc.poll() is None and time.time() - t < 5:
                        time.sleep(0.2)
                    _killpg(proc, signal.SIGKILL)
                if time.time() - t0 > timeout and state["why"] is None:
                    state["why"] = "timeout"
                    _killpg(proc, signal.SIGKILL)
                time.sleep(0.3)
        th_kill = threading.Thread(target=killer, daemon=True)
        th_kill.start()

        rc = proc.wait()
        # Nothing started inside may outlive the job. Backgrounded children can be orphaned
        # (reparented to launchd) faster than the tracker samples, but orphaning does NOT change
        # their process-group id, so killing the whole group repeatedly reaps them; _kill_tracked
        # additionally catches any descendant that escaped the group via its own setsid().
        killed = 0
        for _ in range(8):
            _killpg(proc, signal.SIGKILL)
            group = _pgid_members(proc.pid)
            if not group:
                break
            killed = max(killed, len(group))
            time.sleep(0.2)
        _track()
        _kill_tracked(tracked)
        killed = max(killed, len(tracked))
        th_out.join(timeout=2)
        th_err.join(timeout=2)
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        result["ran"] = True
        result["exit_code"] = rc
        result["timed_out"] = state["why"] == "timeout"
        result["killed_processes"] = killed
        if state["why"] == "cancel":
            result["limitations"].append("detonacja przerwana przez użytkownika")

        # ---- collect the three observation channels ----
        time.sleep(LOG_SETTLE)              # let the kernel log flush into the stream
        denials, bait_reads = logstream.stop()
        stderr_text = "".join(err_buf)[:MAX_CAPTURE]

        commands: list[str] = []
        py_opens: list[str] = []
        network: list[dict] = []
        files_written: list[str] = []
        stages: list[dict] = []

        if kind in ("sh", "bash", "zsh"):
            cmds, xerrs = _parse_xtrace(stderr_text)
            commands = cmds
            # each shell line can be a decoded stage (eval/pipe/base64 output) – rescan the corpus
            if cmds:
                dets = _scan_stage("\n".join(cmds).encode("utf-8", "replace"), "shell")
                if dets:
                    stages.append({"source_preview": "\n".join(cmds)[:1500], "detections": dets})
        else:
            events = _parse_audit(audit_log)
            for ev in events:
                kindev = ev.get("ev")
                if kindev == "compile":
                    src = ev.get("src", "")
                    dets = _scan_stage(src.encode("utf-8", "replace"), "python")
                    stages.append({"source_preview": src[:1500], "detections": dets})
                    commands.append(f"<compile {len(src)}B>")
                elif kindev == "open":
                    py_opens.append(ev.get("path", ""))
                elif kindev in ("os.remove", "os.rename", "os.unlink", "os.chmod", "shutil.move",
                                "shutil.copyfile", "shutil.copytree", "shutil.rmtree"):
                    commands.append(f"{kindev}({', '.join(ev.get('args', []))})")
                elif kindev in ("subprocess.Popen", "os.system", "os.posix_spawn", "os.exec",
                                "os.spawn", "pty.spawn"):
                    commands.append(f"{kindev}: {' '.join(ev.get('args', []))}")
                elif kindev == "socket.connect":
                    addr = ev.get("addr", "")
                    mip = _IP_RX.search(addr)
                    mport = re.search(r"(\d+)\)?\s*$", addr)
                    if mip:
                        network.append({"target": mip.group(0), "kind": "ip",
                                        "port": mport.group(1) if mport else None, "ioc": None})
                elif kindev == "socket.getaddrinfo":
                    host = ev.get("host", "")
                    if host and host not in ("", "None"):
                        network.append({"target": host, "kind": _classify_target(host),
                                        "port": ev.get("port"), "ioc": None})
                elif kindev == "urllib.Request":
                    url = ev.get("url", "")
                    mh = _HOST_IN_URL.search(url)
                    if mh:
                        network.append({"target": mh.group(1), "kind": _classify_target(mh.group(1)),
                                        "url": url[:300], "ioc": None})
                elif kindev == "ctypes.dlopen":
                    commands.append(f"dlopen: {ev.get('name', '')}")

        # ---- URLs / IPs mentioned in the script, the executed trace and the denials ----
        # The raw script text is included because bash xtrace splits a pipeline into separate lines
        # (hiding `curl … | bash`), and a denied-exec curl never reaches the trace at all.
        script_text = script_bytes.decode("utf-8", "replace")
        corpus = commands + [d["detail"] for d in denials]
        beh_corpus = script_text.splitlines() + corpus
        for line in beh_corpus:
            for url in _URL_RX.findall(line):
                host = _HOST_IN_URL.search(url)
                if host:
                    network.append({"target": host.group(1), "kind": _classify_target(host.group(1)),
                                    "url": url[:300], "ioc": None})
            for m in _DEVTCP_RX.finditer(line):
                network.append({"target": m.group(1), "kind": _classify_target(m.group(1)),
                                "port": m.group(2), "ioc": None})
        # network-outbound denials carry the port the payload tried to reach
        for d in denials:
            if d["op"].startswith("network") and ":" in d["detail"]:
                mip = _IP_RX.search(d["detail"])
                if mip:
                    network.append({"target": mip.group(0), "kind": "ip", "ioc": None,
                                    "port": d["detail"].rsplit(":", 1)[-1]})

        # dedupe network targets, IOC-check them against the local DB
        ioc = _stage_pipeline().services.ioc
        seen_net: set[tuple] = set()
        net_final: list[dict] = []
        for n in network:
            key = (n.get("target"), n.get("port"), n.get("url"))
            if key in seen_net:
                continue
            seen_net.add(key)
            tgt = n.get("target", "")
            n["ioc"] = (_ioc_lookup(ioc, "url", n["url"]) if n.get("url") else None) \
                or _ioc_lookup(ioc, n["kind"], tgt)
            net_final.append(n)

        # ---- files written: workspace writes outside run/ are only the capture logs; report
        # home writes (bait tampering) and any /tmp etc. the payload tried.  bash writes show up in
        # denials (file-write* outside workspace) + successful home writes aren't separately logged,
        # so we surface the write denials as attempts.
        for d in denials:
            if d["op"].startswith("file-write"):
                files_written.append(d["detail"])

        files_read = _analyze_bait(bait_reads, py_opens, beh, home=_real(home))

        # ---- behaviours from every channel ----
        # beh_corpus = raw script + executed/decoded trace + denials. The dynamic trace and denials
        # supply the ground truth (what actually ran, what was blocked, which bait was read); the
        # raw script restores pipelines that bash xtrace splits across lines.
        _analyze_commands(beh_corpus, beh)
        _analyze_denials(denials, beh)
        for n in net_final:
            _b(beh, "fetch_remote", 25, [n.get("url") or f"{n['target']}:{n.get('port') or ''}"])
            if n.get("ioc"):
                _b(beh, "fetch_remote", 60, [f"{n['target']} → znany wskaźnik zagrożenia: {n['ioc']}"])
        # reverse-shell from python audit (socket.connect wired to a shell is caught by stage rescan)
        for s in stages:
            for det in s["detections"]:
                nm = det.get("name", "").lower()
                if "reverseshell" in nm or "revshell" in nm:
                    _b(beh, "reverse_shell", 45, [det.get("description", "")])

        # ---- fold stage detections into the report as "Behav:" detections ----
        detections: list[dict] = []
        for s in stages:
            for det in s["detections"]:
                d2 = dict(det)
                d2["name"] = "Behav:Stage." + det.get("name", "").split(":", 1)[-1]
                detections.append(d2)

        behaviours = beh.list()
        # synthesize one Behav: detection per behaviour so they flow through the normal result shape
        _ID2DET = {
            "download_exec": "Script.DownloadExec", "fetch_remote": "Script.FetchRemote",
            "persistence": "Script.Persistence", "credential_access": "Script.CredentialAccess",
            "fake_prompt": "Script.FakePasswordPrompt", "gatekeeper_bypass": "Script.GatekeeperBypass",
            "exfiltration": "Script.Exfiltration", "anti_analysis": "Script.AntiAnalysis",
            "privilege_escalation": "Script.PrivilegeEscalation", "self_deletion": "Script.SelfDeletion",
            "chmod_payload": "Script.ChmodPayload", "reverse_shell": "Script.ReverseShell",
            "process_launch": "Script.ProcessLaunch",
        }
        for b in behaviours:
            from .core import Confidence
            conf = (Confidence.HIGH if b["score"] >= 45 else Confidence.MEDIUM if b["score"] >= 25
                    else Confidence.LOW)
            detections.append({
                "name": "Behav:" + _ID2DET.get(b["id"], b["id"]),
                "engine": "detonate", "confidence": conf.name, "score": b["score"],
                "description": b["detail"], "evidence": b["evidence"][:20], "offset": None,
                "pua": False, "object": f"detonate:{os.path.basename(path)}",
            })

        total = sum(b["score"] for b in behaviours)
        ids = {b["id"] for b in behaviours}
        ioc_hit = any(n.get("ioc") for n in net_final)
        # MALICIOUS when the dynamic evidence shows an unambiguous attack chain, not just a high
        # sum: a reverse shell, a download-and-execute, a credential-theft-then-exfiltrate chain,
        # a confirmed threat-intel hit, or any single very strong behaviour.
        malicious = (
            total >= 80 and len(ids) >= 2
            or "reverse_shell" in ids
            or "download_exec" in ids
            or ("credential_access" in ids and "exfiltration" in ids)
            or ioc_hit
            or any(b["score"] >= 60 for b in behaviours)
        )
        verdict = "MALICIOUS" if malicious else "SUSPICIOUS" if (total >= 25 or ids) else "CLEAN"

        result.update({
            "behaviors": behaviours, "commands": commands[:MAX_COMMANDS], "network": net_final,
            "files_read": files_read, "files_written": sorted(set(files_written))[:60],
            "stages": stages, "score": total, "verdict": verdict, "detections": detections,
        })
        if kind == "python" and not os.path.exists(audit_log):
            result["limitations"].append("log audytu Pythona pusty – skrypt mógł zakończyć się przed startem")
        if not denials and not commands:
            result["limitations"].append(
                "brak zdarzeń z logu jądra i śladu wykonania – możliwe, że skrypt nic nie wykonał "
                "albo system nie zdążył zapisać logu")
        emit({"ev": "log", "msg": f"Detonacja zakończona: {verdict}, zachowań: {len(behaviours)}"})
    except Exception as exc:  # noqa: BLE001 - never let detonation crash the caller
        result["limitations"].append(f"błąd detonacji: {exc!r}")
    finally:
        if logstream is not None and logstream._proc is not None and logstream._proc.poll() is None:
            try:
                logstream._proc.kill()
            except OSError:
                pass
        remove_workspace(work)
        result["seconds"] = round(time.time() - t_start, 2)
    return result

"""Infrastructure for the live-environment collectors.

* run(): subprocess with timeout, no shell, stable C locale, never raises
* CodesignCache: `codesign -dv` classification (Apple / App Store / Developer ID /
  ad-hoc / unsigned) cached per (path, mtime, size), batch prefetch in threads
* read-only helpers: plist loading, Mach-O sniffing, xattr (via libc), home dirs
* EnvContext: what collectors write into (findings, targets, inventory, limitations)
"""
from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import plistlib
import pwd
import re
import stat
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from ..core import Confidence
from .model import EnvFinding, Signal, combine, jsonable
from .patterns import classify_path, is_apple_path, is_location_signal

ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/usr/libexec", "LC_ALL": "C", "LANG": "C"}
MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")


# --------------------------------------------------------------------------- subprocess

@dataclass
class CmdResult:
    argv: list
    rc: int | None
    out: str
    err: str
    timed_out: bool = False
    missing: bool = False
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.rc == 0

    @property
    def text(self) -> str:
        return self.out + ("\n" + self.err if self.err else "")


# Commands that cannot run inside Cerber's sandbox (they need launchd / kernel services the sandbox denies)
# are executed by the unsandboxed parent with these exact arguments and handed in as files.
PRECOMPUTED_COMMANDS = (("/bin/launchctl", "list"), ("/usr/bin/kmutil", "showloaded", "--list-only"),
                        ("/usr/sbin/kextstat", "-l"))


def precomputed_key(argv) -> str:
    import hashlib
    return hashlib.sha1("\0".join(argv).encode()).hexdigest()


def run(argv: list[str], timeout: float = 20.0, env: dict | None = None) -> CmdResult:
    """Run a read-only command. Never uses a shell; returns instead of raising."""
    pre = os.environ.get("CERBER_PRECOMPUTED")
    if pre and tuple(argv) in PRECOMPUTED_COMMANDS:
        try:
            with open(os.path.join(pre, precomputed_key(argv) + ".json")) as fh:
                d = json.load(fh)
            return CmdResult(argv, d.get("rc"), d.get("out", ""), d.get("err", ""), timed_out=d.get("timed_out", False),
                             missing=d.get("missing", False))
        except (OSError, ValueError):
            pass
    t0 = time.monotonic()
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout, env=env or ENV,
                           stdin=subprocess.DEVNULL, check=False, close_fds=True)
        return CmdResult(argv, p.returncode, p.stdout.decode("utf-8", "replace"),
                         p.stderr.decode("utf-8", "replace"), seconds=time.monotonic() - t0)
    except subprocess.TimeoutExpired as e:
        return CmdResult(argv, None, (e.stdout or b"").decode("utf-8", "replace"),
                         (e.stderr or b"").decode("utf-8", "replace"), timed_out=True,
                         seconds=time.monotonic() - t0)
    except FileNotFoundError:
        return CmdResult(argv, None, "", "command not found", missing=True)
    except OSError as e:
        return CmdResult(argv, None, "", f"{type(e).__name__}: {e}", missing=True)


# --------------------------------------------------------------------------- files

def read_bytes(path: str, limit: int = 4 << 20) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


def read_text(path: str, limit: int = 1 << 20) -> str | None:
    b = read_bytes(path, limit)
    return None if b is None else b.decode("utf-8", "replace")


def load_plist(path: str, limit: int = 8 << 20) -> tuple[Any, str | None]:
    """(data, error). error is 'unreadable' for permission problems."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except PermissionError:
        return None, "unreadable"
    except OSError as e:
        return None, f"unreadable: {e.strerror}"
    if len(data) > limit:
        return None, "too large"
    if not data.strip():
        return None, "empty file"
    try:
        return plistlib.loads(data), None
    except Exception as e:  # noqa: BLE001 - InvalidFileException, ExpatError, ValueError...
        return None, f"parse error: {type(e).__name__}"


def is_macho(path: str) -> bool:
    b = read_bytes(path, 4)
    return bool(b) and b[:4] in MACHO_MAGICS


def file_kind(path: str) -> str:
    """macho | script | bundle | other | missing"""
    try:
        st = os.stat(path)
    except OSError:
        return "missing"
    if stat.S_ISDIR(st.st_mode):
        return "bundle" if path.rstrip("/").endswith((".app", ".bundle", ".plugin", ".kext", ".appex", ".xpc",
                                                     ".framework", ".mdimporter", ".qlgenerator", ".prefPane",
                                                     ".saver", ".driver", ".dsplug", ".systemextension")) else "dir"
    b = read_bytes(path, 4) or b""
    if b[:4] in MACHO_MAGICS:
        return "macho"
    if b[:2] == b"#!":
        return "script"
    return "other"


def lstat_info(path: str) -> dict:
    try:
        st = os.lstat(path)
    except OSError:
        return {}
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    return {"mode": oct(stat.S_IMODE(st.st_mode)), "owner": owner, "uid": st.st_uid, "size": st.st_size,
            "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
            "mtime_epoch": int(st.st_mtime), "symlink": stat.S_ISLNK(st.st_mode)}


def bundle_executable(bundle: str) -> str | None:
    """Main executable of an .app/.bundle/.plugin etc."""
    for info in (os.path.join(bundle, "Contents", "Info.plist"), os.path.join(bundle, "Info.plist")):
        d, err = load_plist(info, 1 << 20)
        if isinstance(d, dict) and isinstance(d.get("CFBundleExecutable"), str):
            for base in (os.path.join(bundle, "Contents", "MacOS"), bundle):
                cand = os.path.join(base, d["CFBundleExecutable"])
                if os.path.isfile(cand):
                    return cand
    return None


def bundle_of(path: str) -> str | None:
    m = re.match(r"^(.*?\.(?:app|bundle|plugin|appex|xpc|kext|systemextension|mdimporter|qlgenerator|prefPane|saver|driver))(?:/|$)", path)
    return m.group(1) if m else None


# --- extended attributes (read-only, via libc; Python's os.getxattr is Linux-only)
_libc = None


def _libc_handle():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c") or "/usr/lib/libSystem.B.dylib", use_errno=True)
        _libc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_uint32, ctypes.c_int]
        _libc.getxattr.restype = ctypes.c_ssize_t
    return _libc


XATTR_NOFOLLOW = 0x0001


def get_xattr(path: str, name: str, follow: bool = False) -> bytes | None:
    try:
        libc = _libc_handle()
        p, n = os.fsencode(path), name.encode()
        opts = 0 if follow else XATTR_NOFOLLOW
        size = libc.getxattr(p, n, None, 0, 0, opts)
        if size <= 0:
            return None
        buf = ctypes.create_string_buffer(size)
        got = libc.getxattr(p, n, buf, size, 0, opts)
        return buf.raw[:got] if got > 0 else None
    except Exception:  # noqa: BLE001
        return None


def quarantine_info(path: str) -> dict | None:
    """Parse com.apple.quarantine: flags;hex-time;agent;uuid."""
    raw = get_xattr(path, "com.apple.quarantine")
    if raw is None:
        return None
    parts = raw.decode("utf-8", "replace").split(";")
    info: dict[str, Any] = {"flags": parts[0] if parts else ""}
    if len(parts) > 1:
        try:
            ts = int(parts[1], 16)
            info["time"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
            info["epoch"] = ts
        except ValueError:
            pass
    if len(parts) > 2:
        info["agent"] = parts[2]
    try:
        flags = int(info["flags"], 16)
        info["user_approved"] = bool(flags & 0x40)
    except (ValueError, KeyError):
        pass
    return info


# --------------------------------------------------------------------------- codesign

APPSTORE_AUTH = ("Apple Mac OS Application Signing", "Apple iPhone OS Application Signing", "TestFlight Beta Distribution")
DEV_AUTH = ("Apple Development:", "Mac Developer:", "Apple Distribution:", "3rd Party Mac Developer Application:",
            "iPhone Developer:", "iPhone Distribution:")


@dataclass
class SignInfo:
    path: str
    status: str                 # apple | appstore | devid | development | adhoc | unsigned | notcode | missing | other | error
    authority: str = ""
    team_id: str = ""
    identifier: str = ""
    flags: str = ""
    platform: bool = False
    runtime: bool = False
    executable: str = ""
    error: str = ""
    verified: bool | None = None
    verify_error: str = ""

    @property
    def is_apple(self) -> bool:
        return self.status == "apple"

    @property
    def trusted(self) -> bool:
        return self.status in ("apple", "appstore", "devid")

    @property
    def weak(self) -> bool:
        return self.status in ("adhoc", "unsigned", "development", "other")

    @property
    def signer(self) -> str:
        if self.status == "apple":
            return "Apple"
        if self.status == "appstore":
            return f"Mac App Store ({self.team_id or '?'})"
        if self.status == "devid":
            name = self.authority.split(":", 1)[-1].strip()
            return f"Developer ID: {name}"
        if self.status == "development":
            return f"development certificate ({self.authority})"
        return {"adhoc": "ad-hoc (no identity)", "unsigned": "unsigned", "notcode": "not code",
                "missing": "missing", "other": f"other ({self.authority})"}.get(self.status, self.status)

    def to_dict(self) -> dict:
        d = {"status": self.status, "signer": self.signer, "team_id": self.team_id or None,
             "identifier": self.identifier or None, "hardened_runtime": self.runtime}
        if self.verified is not None:
            d["verified"] = self.verified
            if self.verify_error:
                d["verify_error"] = self.verify_error
        return d


def parse_codesign(path: str, text: str) -> SignInfo:
    low = text.lower()
    if "no such file or directory" in low:
        return SignInfo(path, "missing", error="missing")
    if "code object is not signed at all" in low:
        return SignInfo(path, "unsigned")
    auths = re.findall(r"^Authority=(.*)$", text, re.M)
    team = (re.search(r"^TeamIdentifier=(.*)$", text, re.M) or [None, ""])[1]
    ident = (re.search(r"^Identifier=(.*)$", text, re.M) or [None, ""])[1]
    flags = (re.search(r"flags=(0x[0-9a-f]+(?:\([^)]*\))?)", text) or [None, ""])[1]
    exe = (re.search(r"^Executable=(.*)$", text, re.M) or [None, ""])[1]
    platform = bool(re.search(r"^Platform identifier=", text, re.M))
    info = SignInfo(path, "other", authority=auths[0] if auths else "", team_id="" if team == "not set" else team,
                    identifier=ident, flags=flags, platform=platform, runtime="runtime" in flags, executable=exe)
    if "Signature=adhoc" in text or "(adhoc" in flags or ",adhoc" in flags:
        info.status = "adhoc"
    elif auths:
        a = auths[0]
        if a == "Software Signing" or (platform and "Apple" in " ".join(auths)):
            info.status = "apple"
        elif a.startswith(APPSTORE_AUTH):
            info.status = "appstore"
        elif a.startswith("Developer ID Application:"):
            info.status = "devid"
        elif a.startswith(DEV_AUTH):
            info.status = "development"
        else:
            info.status = "other"
    elif "Identifier=" in text:
        info.status = "other"
    else:
        info.status = "error"
        info.error = text.strip().splitlines()[-1][:200] if text.strip() else "no output"
    return info


class CodesignCache:
    def __init__(self, enabled: bool = True, timeout: float = 15.0, workers: int = 8):
        self.enabled = enabled
        self.timeout = timeout
        self.workers = workers
        self._cache: dict[tuple, SignInfo] = {}
        self._vcache: dict[tuple, tuple[bool | None, str]] = {}
        self._lock = threading.Lock()
        self.calls = 0
        self.timeouts = 0

    @staticmethod
    def _key(path: str) -> tuple:
        try:
            st = os.stat(path)
            return (os.path.realpath(path), int(st.st_mtime), st.st_size)
        except OSError:
            return (path, 0, -1)

    def info(self, path: str) -> SignInfo:
        if not path:
            return SignInfo(path, "missing")
        key = self._key(path)
        with self._lock:
            hit = self._cache.get(key)
        if hit is not None:
            return hit
        if key[2] == -1:
            res = SignInfo(path, "missing")
        else:
            kind = file_kind(path)
            if kind in ("script", "other"):
                res = SignInfo(path, "notcode")
            elif not self.enabled:
                res = SignInfo(path, "error", error="codesign disabled")
            else:
                r = run(["/usr/bin/codesign", "-dv", "--verbose=2", path], timeout=self.timeout)
                with self._lock:
                    self.calls += 1
                    if r.timed_out:
                        self.timeouts += 1
                if r.timed_out:
                    res = SignInfo(path, "error", error="codesign timed out")
                elif r.missing:
                    res = SignInfo(path, "error", error="codesign not available")
                else:
                    res = parse_codesign(path, r.err + "\n" + r.out)
        with self._lock:
            self._cache[key] = res
        return res

    def prefetch(self, paths: Iterable[str]) -> None:
        todo = []
        seen = set()
        for p in paths:
            if p and p not in seen:
                seen.add(p)
                todo.append(p)
        if not todo:
            return
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            list(ex.map(self.info, todo))

    def verify(self, path: str, timeout: float = 45.0) -> tuple[bool | None, str]:
        """codesign --verify (signature + sealed resources integrity). (None, reason) if unknown."""
        if not self.enabled or not path:
            return None, "disabled"
        key = self._key(path)
        with self._lock:
            hit = self._vcache.get(key)
        if hit is not None:
            return hit
        r = run(["/usr/bin/codesign", "--verify", "--no-strict", path], timeout=timeout)
        if r.timed_out:
            res: tuple[bool | None, str] = (None, "verification timed out")
        elif r.missing:
            res = (None, "codesign not available")
        elif r.rc == 0:
            res = (True, "")
        else:
            msg = (r.err or r.out).strip().splitlines()
            res = (False, msg[-1][:200] if msg else f"rc={r.rc}")
        with self._lock:
            self._vcache[key] = res
        return res


# --------------------------------------------------------------------------- users

@dataclass
class UserHome:
    name: str
    uid: int
    home: str


def target_homes(is_root: bool) -> list[UserHome]:
    """Current user; when root: every real account with a home under /Users (plus root)."""
    if not is_root:
        pw = pwd.getpwuid(os.getuid())
        home = pw.pw_dir if os.path.isdir(pw.pw_dir) else os.path.expanduser("~")
        return [UserHome(pw.pw_name, pw.pw_uid, home)]
    homes: list[UserHome] = []
    seen = set()
    for pw in pwd.getpwall():
        if (pw.pw_uid >= 500 and pw.pw_dir.startswith("/Users/") and os.path.isdir(pw.pw_dir)) \
                or pw.pw_uid == 0:
            real = os.path.realpath(pw.pw_dir)
            if real in seen or not os.path.isdir(real):
                continue
            seen.add(real)
            homes.append(UserHome(pw.pw_name, pw.pw_uid, pw.pw_dir))
    return homes


# --------------------------------------------------------------------------- context

TRUSTED_DAMPING = 0.4


class EnvContext:
    def __init__(self, options: dict | None = None, progress: Callable[[str], None] | None = None):
        self.options = dict(options or {})
        self._progress = progress
        self.is_root = os.geteuid() == 0
        self.uid = os.getuid()
        self.homes = self.options.get("homes_override") or target_homes(self.is_root)
        self.codesign = CodesignCache(enabled=self.options.get("codesign", True),
                                      timeout=float(self.options.get("codesign_timeout", 15)))
        self.timeout = float(self.options.get("timeout", 20))
        self.findings: list[EnvFinding] = []
        self.targets: dict[str, dict] = {}
        self.inventory: dict[str, Any] = {}
        self.posture: dict[str, Any] = {}
        self.limitations: list[str] = []
        self.timing: dict[str, float] = {}
        self.fda: bool | None = None
        self._lock = threading.RLock()
        self._finding_keys: set[tuple] = set()

    # -- reporting helpers
    def progress(self, msg: str) -> None:
        if self._progress:
            try:
                self._progress(msg)
            except Exception:  # noqa: BLE001
                pass

    def limit(self, msg: str) -> None:
        with self._lock:
            if msg not in self.limitations:
                self.limitations.append(msg)

    def inv(self, key: str) -> list:
        with self._lock:
            return self.inventory.setdefault(key, [])

    def add_target(self, path: str | None, reason: str, priority: int = 0) -> None:
        """priority: 0 = routine, 1 = referenced by persistence, 2 = flagged."""
        if not path or not path.startswith("/"):
            return
        path = os.path.normpath(path)
        if is_apple_path(path):
            return  # sealed system volume / SIP-protected Apple locations
        with self._lock:
            cur = self.targets.get(path)
            if cur is None:
                self.targets[path] = {"path": path, "reason": reason, "priority": priority}
            elif priority > cur["priority"]:
                cur["priority"] = priority
                cur["reason"] = reason

    def add_finding(self, category: str, title: str, location: str, signals: list[Signal],
                    details: dict | None = None, min_score: int = 0, allow_zero: bool = False) -> EnvFinding | None:
        """Merge signals into one finding. Items with no scoring signal are skipped unless allow_zero."""
        if not signals:
            return None
        det = combine(signals, engine="env")
        if det is None:
            return None
        if det.score < min_score or (det.score == 0 and not allow_zero):
            return None
        key = (category, location, det.name)
        with self._lock:
            if key in self._finding_keys:
                return None
            self._finding_keys.add(key)
            f = EnvFinding(category, title, location, det, jsonable(details or {}))
            self.findings.append(f)
        return f

    # -- signing helpers
    def sign(self, path: str) -> SignInfo:
        return self.codesign.info(path)

    def signing_signals(self, exe: str, prefix: str, what: str = "program", sev: float = 1.0,
                        info: SignInfo | None = None) -> list[Signal]:
        """Signals for weak/absent code signatures (package-manager paths are exempt)."""
        info = info or self.sign(exe)
        pi = classify_path(exe)
        if pi.has("apple") or info.trusted:
            return []
        pkg = pi.has("pkgmgr")
        out: list[Signal] = []
        if info.status == "unsigned":
            out.append(Signal(f"{prefix}.Unsigned", 5 if pkg else int(25 * sev), Confidence.LOW if pkg else Confidence.MEDIUM,
                              f"{what}: brak podpisu kodu", [exe]))
        elif info.status == "adhoc":
            out.append(Signal(f"{prefix}.AdhocSigned", 0 if pkg else int(15 * sev), Confidence.LOW,
                              f"{what}: podpisany tylko ad-hoc (bez tożsamości dewelopera)", [exe]))
        elif info.status == "development":
            out.append(Signal(f"{prefix}.DevSigned", 0 if pkg else int(10 * sev), Confidence.LOW,
                              f"{what}: podpisany certyfikatem deweloperskim", [info.authority]))
        elif info.status == "other":
            out.append(Signal(f"{prefix}.UnknownSigner", int(15 * sev), Confidence.LOW,
                              f"{what}: podpisany przez nieznany urząd", [info.authority or "?"]))
        return out

    @staticmethod
    def dampen_trusted(signals: list[Signal], info: SignInfo | None, only_path: str | None = None) -> list[Signal]:
        """A valid Apple/Developer-ID/App-Store signature makes location oddities much less alarming.

        only_path: dampen only signals whose first evidence item is that path (the signed binary),
        so e.g. `/bin/bash /Users/Shared/.x.sh` keeps the full weight for the script location."""
        if not info or not info.trusted:
            return signals
        out = []
        for s in signals:
            if is_location_signal(s) and (only_path is None or (s.evidence and s.evidence[0] == only_path)):
                out.append(s.scaled(TRUSTED_DAMPING, f"program podpisany przez {info.signer}"))
            else:
                out.append(s)
        return out


def home_of(ctx: EnvContext) -> str:
    return ctx.homes[0].home if ctx.homes else os.path.expanduser("~")


def safe_listdir(path: str) -> tuple[list[str], str | None]:
    try:
        return sorted(os.listdir(path)), None
    except FileNotFoundError:
        return [], "missing"
    except PermissionError:
        return [], "denied"
    except OSError as e:
        return [], e.strerror or "error"


def mtime_days(path: str) -> float | None:
    try:
        return (time.time() - os.lstat(path).st_mtime) / 86400.0
    except OSError:
        return None


def world_writable(path: str) -> bool:
    try:
        return bool(os.stat(path).st_mode & stat.S_IWOTH)
    except OSError:
        return False


def apple_or_trusted(ctx: EnvContext, path: str) -> SignInfo | None:
    if is_apple_path(path):
        return None
    return ctx.sign(path)

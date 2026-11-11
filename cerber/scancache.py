"""Persistent "already scanned and clean" memory, modelled on clamd's clean-file cache and Santa's decision cache.

A laptop scan at the quick / patterns level remembers every file it found CLEAN. The next scan skips such a file
while it is provably unchanged and nothing that could change its verdict has changed. Targeted scans (a file,
folder, archive, link or repository) and the deep / mega levels never use the cache.

Identity of a file
    (st_dev, st_ino, st_size, st_mtime_ns, st_ctime_ns) plus its real path. mtime can be set back by anyone
    (`touch -t`), ctime cannot be set from user space: every write, chmod/chown, xattr change, rename or new hard
    link bumps it. "Same identity" therefore means "same bytes at the same place", without reading the file.

Context fingerprint (16 bytes, stored in every row and compared on lookup)
    12 bytes "base": SHA-256 over Cerber's own code (the .py files of the cerber/ package, hashed once per
    process), the Python version and installed packages (mtime of site-packages), size / mtime / inode of every
    file in db/compiled (ClamAV, YARA, hash and IOC databases, ML hint, calibration: load_engines() reads nothing
    else, so its `info` dict is a function of these files) plus the calibration file and 7-Zip / UPX.
    4 bytes "options": scan level and max_file_size. Any change means no row matches and everything is scanned
    again. The PARENT computes the fingerprint itself, before the scan, and again after it: if the databases
    changed while the scan ran, nothing from that scan is remembered.

Trust split. The scanner child runs in the read-only `scan` sandbox and reads hostile files, so it might be
compromised and must never write trusted state:
    * the CHILD only READS the cache (loaded once, before workers fork; the HMAC of a row is checked lazily, on a
      hit) and lists the identities of the files it found CLEAN in a side file in its workspace
      (out/clean-ids.jsonl, see Recorder);
    * the UNSANDBOXED PARENT (gui_backend / cli) merges that list (merge()): it re-lstats every path and keeps a
      row only when the identity still matches, the path is canonical (no symlink on the way), lies under what was
      asked to be scanned and passes cache_eligible(), for which the parent reads the first bytes itself to reject
      Mach-O programs and scripts. Only the parent writes the cache and computes HMACs. A compromised child can at
      worst get files it claims are clean skipped later, and only files outside the always-scanned places below.

Never cached (cache_eligible() is the one place with these rules):
    * anything in infection hotspots: Downloads, Desktop, Mail Downloads, /tmp, /private/tmp, /private/var/folders,
      /private/var/tmp, /Users/Shared, /Volumes (other file systems, where inode and ctime cannot be trusted), and
      LaunchAgents, LaunchDaemons, PrivilegedHelperTools and StartupItems folders;
    * Mach-O programs, scripts (shebang or script extension) and executable files outside /Applications and /System;
    * any result other than CLEAN without detections, errors, timeouts or partial scans (result_cacheable()).
Rows expire after 30 days.

Tamper protection, and its honest limit
    Every row carries an HMAC-SHA256 over (path, identity, fingerprint, verdict, timestamp) under a 32-byte random
    key in scancache/key (file 0600, directory 0700). Rows with a bad HMAC are ignored (and counted). That stops
    generic tampering: a stray or malicious program editing rows, truncating or swapping the file, or replaying a
    row onto another file. It does NOT stop a targeted attack by a program running as the same user: such a
    program can read the key and mint valid rows. That is why the exclusions above exist. The places and file
    kinds malware uses to persist are always scanned, whatever the cache says. Rows also expire, and every update
    of the signatures or of Cerber invalidates all of them. `cerber cache clear` deletes the key and all rows.

Storage: one compact binary file, not SQLite
    scancache/rows.bin is a 36-byte header plus fixed 104-byte records. It is append-only and compacted (atomic
    rename) once a day, when it has doubled, or when Cerber's code or databases changed. Why not SQLite in WAL
    mode: the sandboxed reader cannot write anything, and WAL readers need a writable -shm file (immutable=1 would
    silently ignore the WAL). The child also loads every row into a dict at once, so an index buys nothing. Fixed
    records need no parsing or escaping and load in about a second per million rows. A torn append is harmless:
    a partial record is ignored and a garbled one fails its HMAC. The path is stored only as a keyed 64-bit hash,
    so the file does not list the user's file names. Writers serialise on flock(); readers never lock, because
    compaction replaces the file atomically. Memory in the child is about 200 bytes per remembered file.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import itertools
import json
import os
import stat
import struct
import sys
import sysconfig
import tempfile
import time
from typing import Callable, Iterable, Iterator

from . import config
from .dataless import is_dataless

CACHE_LEVELS = ("quick", "patterns")          # laptop-scan levels that use the cache by default
MAX_AGE = 30 * 86400                          # rows expire after 30 days
FUTURE_SLACK = 86400                          # a row "from the future" (clock set back, forged) is ignored
COMPACT_EVERY = 86400
COMPACT_SLACK = 50_000
MAX_ROWS = 5_000_000
MAX_SIDE_ROWS = 5_000_000
MAX_SIDE_LINE = 8192
SIDE_NAME = "clean-ids.jsonl"                 # side file written by the scanner child into <work>/out/
ROWS_NAME = "rows.bin"
KEY_NAME = "key"
LOCK_NAME = "lock"

MAGIC = b"CERBSCAN"
VERSION = 1
CLEAN = 0                                     # verdict code; only CLEAN is ever stored
HEADER = struct.Struct("<8sIIII12s")          # magic, version, record size, compacted at, rows then, base fp then
# index (keyed hash of the path), dev, ino, size, mtime_ns, ctime_ns, fingerprint, timestamp, verdict, HMAC
REC = struct.Struct("<QqQqqq16sIB3x32s")
VAL = struct.Struct("<qQqqq16sIB3x32s")       # REC without the index (what the lookup dict holds)
# offsets inside REC: fingerprint 48..64 (base 48..60, options 60..64), timestamp 64..68, verdict 68
_BASE, _OPT, _TS, _VERDICT = slice(48, 60), slice(60, 64), slice(64, 68), 68
_IDENT = struct.Struct("<qQqqq")

# ------------------------------------------------------------------ the rules: what may be cached at all

HOTSPOT_PREFIXES = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/var/folders/",
                    "/private/var/folders/", "/users/shared/", "/volumes/", "/system/volumes/")
HOTSPOT_DIRS = frozenset({"downloads", "desktop", "mail downloads", "launchagents", "launchdaemons",
                          "privilegedhelpertools", "startupitems"})
PROGRAM_HOMES = ("/applications/", "/system/")
SCRIPT_EXT = (".sh", ".bash", ".zsh", ".csh", ".tcsh", ".ksh", ".fish", ".command", ".tool", ".py", ".pyw", ".pyc",
              ".pl", ".pm", ".rb", ".php", ".js", ".mjs", ".cjs", ".jxa", ".scpt", ".applescript", ".osa", ".lua",
              ".tcl", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".hta", ".jar", ".swift")
MACHO_MAGIC = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
               b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")


def _norm(path: str) -> str:
    """Lower-case (APFS is case-insensitive: /users/x/DOWNLOADS is ~/Downloads) and without the Data-volume alias."""
    p = path.lower()
    if p.startswith("/system/volumes/data/"):
        p = p[len("/system/volumes/data"):]
    return p


def in_hotspot(path: str) -> bool:
    """Infection hotspots: files here are always scanned, whatever the cache says."""
    p = _norm(path)
    if p.startswith(HOTSPOT_PREFIXES):
        return True
    return not HOTSPOT_DIRS.isdisjoint(p.split("/")[:-1])


def cache_eligible(path: str, st_mode: int, head: bytes | None = None) -> bool:
    """May a CLEAN verdict for this file be remembered (and used)? `head`: the file's first bytes. None means
    "content not inspected": used on lookup, where the row was inspected when it was written and the unchanged
    ctime proves the content is the same. The parent always passes the bytes when it stores a row outside the
    program homes (see merge())."""
    if in_hotspot(path):
        return False
    p = _norm(path)
    if p.startswith(PROGRAM_HOMES):
        return True
    if st_mode & 0o111 or p.endswith(SCRIPT_EXT):
        return False
    if head is not None and (head[:4] in MACHO_MAGIC or head[:2] == b"#!"):
        return False
    return True


def program_home(path: str) -> bool:
    return not in_hotspot(path) and _norm(path).startswith(PROGRAM_HOMES)


def result_cacheable(r: dict) -> bool:
    """Only a complete CLEAN scan without a single detection, error or timeout is remembered."""
    return (r.get("verdict") == "CLEAN" and not r.get("detections") and not r.get("errors")
            and not r.get("timeout") and not r.get("unreadable"))


def enabled_for(level: str) -> bool:
    return level in CACHE_LEVELS


# ------------------------------------------------------------------ context fingerprint

_CODE: dict[str, bytes] = {}


def code_hash(pkg: str | None = None) -> bytes:
    """SHA-256 over the .py files of the cerber package (once per process)."""
    pkg = pkg or os.path.dirname(os.path.realpath(__file__))
    if pkg not in _CODE:
        h = hashlib.sha256()
        for d, dirs, files in os.walk(pkg):
            dirs[:] = sorted(x for x in dirs if x != "__pycache__")
            for f in sorted(files):
                if f.endswith(".py"):
                    p = os.path.join(d, f)
                    h.update(os.fsencode(os.path.relpath(p, pkg)) + b"\0")
                    try:
                        with open(p, "rb") as fh:
                            h.update(hashlib.sha256(fh.read()).digest())
                    except OSError:
                        h.update(b"?")
        _CODE[pkg] = h.digest()
    return _CODE[pkg]


def _stat_sig(path: str | None) -> bytes:
    if not path:
        return b"-;"
    try:
        st = os.stat(path)
    except OSError:
        return b"-;"
    return f"{st.st_size}:{st.st_mtime_ns}:{st.st_ino};".encode()


def base_fingerprint() -> bytes:
    """12 bytes: Cerber's code, Python + packages, the signature databases, the calibration, 7-Zip / UPX."""
    h = hashlib.sha256(b"cerber-scancache-context-1\0")
    h.update(code_hash())
    h.update(sys.version.encode() + b"\0")
    try:
        h.update(_stat_sig(sysconfig.get_paths().get("purelib")))
    except (KeyError, OSError):
        h.update(b"?")
    for d, dirs, files in os.walk(config.COMPILED):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(d, f)
            h.update(os.fsencode(os.path.relpath(p, config.COMPILED)) + b"=" + _stat_sig(p))
    h.update(b"calibration=" + _stat_sig(config.FP_CALIBRATION))
    tools = config.tools()
    for name in ("7z", "upx"):
        t = tools.get(name)
        h.update(f"{name}={os.path.realpath(t) if t else '-'}".encode() + _stat_sig(t))
    return h.digest()[:12]


def options_fingerprint(opts) -> bytes:
    """4 bytes: the scan options that change what a file scan does."""
    d = {"level": opts.level, "patterns_only": bool(opts.patterns_only), "max_file_size": int(opts.max_file_size),
         "deep": bool(opts.deep), "macos": bool(opts.macos_checks)}
    return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).digest()[:4]


def context_fingerprint(opts) -> bytes:
    return base_fingerprint() + options_fingerprint(opts)


# ------------------------------------------------------------------ key and row codec

def _dir_ok(d: str) -> bool:
    try:
        st = os.lstat(d)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o077


def _load_keys(create: bool) -> tuple[bytes, bytes] | None:
    """(HMAC key, path-index key) derived from the 32-byte master key; None when there is no trustworthy key.
    create=True (parent only) makes the private dir and a new random key when missing."""
    d = config.SCAN_CACHE_DIR
    path = os.path.join(d, KEY_NAME)
    if create:
        config.private_dir(d)
        if not os.path.lexists(path):
            fd, tmp = tempfile.mkstemp(dir=d, prefix="key.", suffix=".tmp")
            try:
                os.write(fd, os.urandom(32))
                os.close(fd)
                try:
                    os.link(tmp, path)             # never replaces a key another process created meanwhile
                except FileExistsError:
                    pass
            finally:
                os.unlink(tmp)
    if not _dir_ok(d):
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077 or st.st_size != 32:
            return None
        master = os.read(fd, 64)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(master) != 32:
        return None
    return (hmac.digest(master, b"cerber-scancache mac", "sha256"),
            hmac.digest(master, b"cerber-scancache index", "sha256"))


def _index(kidx: bytes, raw_path: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(raw_path, digest_size=8, key=kidx).digest(), "little")


def _mac(kmac: bytes, raw_path: bytes, ident: tuple, fp: bytes, verdict: int, ts: int) -> bytes:
    msg = (b"cerber-scancache-1\0" + raw_path + b"\0" + _IDENT.pack(*ident) + fp + bytes((verdict,))
           + ts.to_bytes(4, "little"))
    return hmac.digest(kmac, msg, "sha256")


def identity(st) -> tuple[int, int, int, int, int]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def pack_row(keys: tuple[bytes, bytes], path: str, ident: tuple, fp: bytes, ts: int) -> bytes:
    raw = os.fsencode(path)
    return REC.pack(_index(keys[1], raw), *ident, fp, ts, CLEAN, _mac(keys[0], raw, ident, fp, CLEAN, ts))


def _open_regular(path: str) -> int | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if stat.S_ISREG(os.fstat(fd).st_mode):
            return fd
    except OSError:
        pass
    os.close(fd)
    return None


def _read_rows_file(path: str) -> tuple[tuple | None, bytes]:
    """(header, aligned record area) of rows.bin; (None, b"") when missing or not ours."""
    fd = _open_regular(path)
    if fd is None:
        return None, b""
    with os.fdopen(fd, "rb") as fh:
        hdr = _parse_header(fh.read(HEADER.size))
        if hdr is None:
            return None, b""
        blob = fh.read()
    return hdr, blob[:len(blob) - len(blob) % REC.size]


def _parse_header(raw: bytes) -> tuple | None:
    if len(raw) != HEADER.size:
        return None
    hdr = HEADER.unpack(raw)
    if hdr[0] != MAGIC or hdr[1] != VERSION or hdr[2] != REC.size:
        return None
    return hdr


# ------------------------------------------------------------------ child side: lookup + recording

class Lookup:
    """All rows of this context, loaded once. hit(path, st) is True when the file may be skipped."""

    def __init__(self, fp: bytes, now: float | None = None):
        self.fp = fp
        self.hits = 0
        self.bad = 0
        self.rows: dict[int, bytes] = {}
        self._keys = _load_keys(create=False)
        if self._keys is None:
            return
        _hdr, blob = _read_rows_file(os.path.join(config.SCAN_CACHE_DIR, ROWS_NAME))
        now_i = int(time.time() if now is None else now)
        lo, hi = now_i - MAX_AGE, now_i + FUTURE_SLACK
        rows = self.rows
        size = REC.size
        for off in range(0, len(blob), size):
            if blob[off + 48:off + 64] != fp or blob[off + _VERDICT] != CLEAN:
                continue
            ts = int.from_bytes(blob[off + 64:off + 68], "little")
            if lo <= ts <= hi:
                rows[int.from_bytes(blob[off:off + 8], "little")] = blob[off + 8:off + size]      # later rows win

    def __len__(self) -> int:
        return len(self.rows)

    def hit(self, path: str, st) -> bool:
        if not self.rows:
            return False
        raw = os.fsencode(path)
        val = self.rows.get(_index(self._keys[1], raw))
        if val is None:
            return False
        dev, ino, size, mt, ct, fp, ts, verdict, mac = VAL.unpack(val)
        ident = (dev, ino, size, mt, ct)
        if ident != identity(st) or not stat.S_ISREG(st.st_mode) or not cache_eligible(path, st.st_mode):
            return False
        if not hmac.compare_digest(mac, _mac(self._keys[0], raw, ident, fp, verdict, ts)):
            self.bad += 1
            return False
        self.hits += 1
        return True


class Recorder:
    """Child side: identities (taken right before scanning) of files found CLEAN, as JSON Lines
    [path, dev, ino, size, mtime_ns, ctime_ns], for the parent to verify and merge. Never trusted by itself."""

    def __init__(self, path: str):
        self.path = path
        self.count = 0
        self.fh = open(path, "a", encoding="ascii")

    def add(self, path: str, ident) -> None:
        if self.fh is None or self.count >= MAX_SIDE_ROWS or in_hotspot(path):
            return
        self.fh.write(json.dumps([path, *ident]) + "\n")
        self.count += 1

    def close(self) -> None:
        if self.fh is not None:
            self.fh.close()
            self.fh = None


# ------------------------------------------------------------------ parent side: verify + merge

def read_side(path: str) -> Iterator[tuple[str, tuple]]:
    """Rows of a side file written by an untrusted child: bounded, type-checked, anything odd skipped."""
    fd = _open_regular(path)
    if fd is None:
        return
    with os.fdopen(fd, "rb") as fh:
        for _ in range(MAX_SIDE_ROWS):
            line = fh.readline(MAX_SIDE_LINE)
            if not line:
                break
            if not line.endswith(b"\n"):
                continue
            try:
                row = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if (isinstance(row, list) and len(row) == 6 and isinstance(row[0], str)
                    and all(type(x) is int for x in row[1:])):
                yield row[0], tuple(row[1:])


def _norm_roots(roots: Iterable[str] | None) -> list[str] | None:
    if roots is None:
        return None
    return [os.path.abspath(os.path.expanduser(r)).rstrip("/") or "/" for r in roots]


def _under(path: str, roots: list[str] | None) -> bool:
    if roots is None:
        return True
    return any(r == "/" or path == r or path.startswith(r + "/") for r in roots)


def _read_head(path: str, ident: tuple) -> bytes | None:
    """First bytes of the file, only if the opened file is still the one with this identity."""
    fd = _open_regular(path)
    if fd is None:
        return None
    try:
        if identity(os.fstat(fd)) != ident:
            return None
        return os.read(fd, 8)
    except OSError:
        return None
    finally:
        os.close(fd)


def verify_on_disk(path: str, ident: tuple, roots: list[str] | None, real_dirs: dict[str, str]) -> bool:
    """The parent's check of one row from the child: still the same file, canonical path, eligible."""
    if not path.startswith("/") or "\x00" in path or len(path) > 4096 or not _under(path, roots):
        return False
    try:
        st = os.lstat(path)
    except (OSError, ValueError):
        return False
    if not stat.S_ISREG(st.st_mode) or is_dataless(st) or identity(st) != ident:
        return False
    d = os.path.dirname(path)
    real = real_dirs.get(d)
    if real is None:
        real = real_dirs[d] = os.path.realpath(d)
    if real != d or not cache_eligible(path, st.st_mode):
        return False
    if program_home(path):
        return True
    head = _read_head(path, ident)
    return head is not None and cache_eligible(path, st.st_mode, head)


@contextlib.contextmanager
def _locked(d: str):
    fd = os.open(os.path.join(d, LOCK_NAME), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def merge(side_path: str, fp: bytes, roots: Iterable[str] | None = None, now: float | None = None) -> int:
    """Parent only: verify the child's rows against the disk and store the survivors. Returns how many."""
    now_i = int(time.time() if now is None else now)
    nroots = _norm_roots(roots)
    pending: dict[str, tuple] = {}
    for path, ident in read_side(side_path):
        pending[path] = ident
    if not pending:
        return 0
    keys = _load_keys(create=True)
    if keys is None:
        raise OSError("klucz pamięci skanów ma złe uprawnienia")
    real_dirs: dict[str, str] = {}
    rows = [pack_row(keys, p, ident, fp, now_i) for p, ident in pending.items()
            if verify_on_disk(p, ident, nroots, real_dirs)]
    if rows:
        _store(rows, fp, now_i)
    return len(rows)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _store(new: list[bytes], fp: bytes, now: int) -> None:
    d = config.private_dir(config.SCAN_CACHE_DIR)
    path = os.path.join(d, ROWS_NAME)
    with _locked(d):
        try:
            fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:                         # missing, or a symlink / something else planted there
            fd = None
        if fd is not None:
            try:
                st = os.fstat(fd)
                hdr = _parse_header(os.pread(fd, HEADER.size, 0))
                body = st.st_size - HEADER.size
                if (stat.S_ISREG(st.st_mode) and hdr is not None and body >= 0 and body % REC.size == 0
                        and not _compaction_due(hdr, body // REC.size + len(new), fp, now)):
                    _write_all(fd, b"".join(new))
                    return
            except OSError:
                pass
            finally:
                os.close(fd)
        _compact(d, path, new, fp, now)


def _compaction_due(hdr: tuple, rows: int, fp: bytes, now: int) -> bool:
    _magic, _ver, _size, compacted_at, rows_then, base = hdr
    return (base != fp[:12] or now - compacted_at > COMPACT_EVERY or compacted_at > now + FUTURE_SLACK
            or rows > 2 * rows_then + COMPACT_SLACK)


def _compact(d: str, path: str, new: list[bytes], fp: bytes, now: int) -> None:
    """Rewrite rows.bin: only this code/database generation, not expired, newest row per (file, options)."""
    _hdr, blob = _read_rows_file(path)
    base = fp[:12]
    lo, hi = now - MAX_AGE, now + FUTURE_SLACK
    keep: dict[bytes, bytes] = {}
    size = REC.size
    for rec in itertools.chain((blob[off:off + size] for off in range(0, len(blob), size)), new):
        if rec[_BASE] != base:
            continue
        ts = int.from_bytes(rec[_TS], "little")
        if lo <= ts <= hi:
            keep[rec[:8] + rec[_OPT]] = rec          # later rows win
    blob = b""
    vals = list(keep.values())
    keep.clear()
    if len(vals) > MAX_ROWS:
        vals.sort(key=lambda r: int.from_bytes(r[_TS], "little"))
        vals = vals[-MAX_ROWS:]
    fd, tmp = tempfile.mkstemp(dir=d, prefix="rows.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(HEADER.pack(MAGIC, VERSION, REC.size, now, len(vals), base))
            fh.write(b"".join(vals))
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    _sweep_leftovers(d, now)


def _sweep_leftovers(d: str, now: int) -> None:
    """Temporary / side files of crashed runs (older than a day)."""
    try:
        names = os.listdir(d)
    except OSError:
        return
    for n in names:
        if n.endswith(".tmp") or (n.startswith("side-") and n.endswith(".jsonl")):
            p = os.path.join(d, n)
            with contextlib.suppress(OSError):
                if now - os.lstat(p).st_mtime > 86400:
                    os.unlink(p)


class ParentSession:
    """Parent side of one cached scan: computes the fingerprint (never taken from the child), hands it to the
    scanner, then checks it again and merges the verified rows."""

    def __init__(self, opts, roots: Iterable[str]):
        self.opts = opts
        self.roots = list(roots)
        self.fp = context_fingerprint(opts)

    @property
    def fp_hex(self) -> str:
        return self.fp.hex()

    def local_side_file(self) -> str:
        """For in-process scans (CLI, CERBER_NO_SANDBOX): a private side file in the cache dir."""
        d = config.private_dir(config.SCAN_CACHE_DIR)
        fd, path = tempfile.mkstemp(dir=d, prefix="side-", suffix=".jsonl")
        os.close(fd)
        return path

    def merge(self, side_path: str, log: Callable[[str], None] | None = None) -> int:
        log = log or (lambda _m: None)
        try:
            if context_fingerprint(self.opts) != self.fp:
                log("Pamięć skanów: bazy sygnatur lub Cerber zmieniły się w trakcie skanu – wyników nie zapamiętano")
                return 0
            n = merge(side_path, self.fp, self.roots)
        except Exception as exc:  # noqa: BLE001 - the memory is a speed-up; it must never fail a scan
            log(f"Pamięć skanów: nie udało się zapisać ({exc})")
            return 0
        if n:
            log(f"Pamięć skanów: zapamiętano {n:,} czystych plików – kolejny skan pominie je, jeśli się nie zmienią")
        return n


# ------------------------------------------------------------------ maintenance (cerber cache info | clear)

def info(now: float | None = None) -> dict:
    now_i = int(time.time() if now is None else now)
    d = config.SCAN_CACHE_DIR
    path = os.path.join(d, ROWS_NAME)
    hdr, blob = _read_rows_file(path)
    out = {"dir": d, "rows": 0, "live": 0, "bytes": 0, "oldest": None, "newest": None, "contexts": 0,
           "key": os.path.isfile(os.path.join(d, KEY_NAME)), "compacted": hdr[3] if hdr else None}
    try:
        out["bytes"] = sum(os.lstat(os.path.join(d, n)).st_size for n in os.listdir(d))
    except OSError:
        pass
    size = REC.size
    stamps = [int.from_bytes(blob[off + 64:off + 68], "little") for off in range(0, len(blob), size)]
    out["rows"] = len(stamps)
    if stamps:
        out["oldest"], out["newest"] = min(stamps), max(stamps)
        out["live"] = sum(1 for ts in stamps if now_i - MAX_AGE <= ts <= now_i + FUTURE_SLACK)
        out["contexts"] = len({blob[off + 48:off + 64] for off in range(0, len(blob), size)})
    return out


def clear() -> int:
    """Delete everything in the private cache dir (rows, key, lock, leftovers). Returns how many entries."""
    import shutil
    d = config.SCAN_CACHE_DIR
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        return 0
    if not stat.S_ISDIR(st.st_mode):
        raise OSError(f"{d} nie jest katalogiem (dowiązanie?) – odmowa")
    n = 0
    for name in os.listdir(d):
        p = os.path.join(d, name)
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p, ignore_errors=True)
        else:
            os.unlink(p)
        n += 1
    return n

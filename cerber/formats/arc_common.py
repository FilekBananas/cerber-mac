"""Shared helpers for the container/archive extractors (cerber.analyzers.archives).

Nothing in here ever executes extracted content.  Everything read from an
archive is bounded by a Budget (total bytes + wall-clock) and by
ctx.limits.max_child_size.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import unicodedata
from typing import Any, Iterator

from ..core import Confidence, Detection, ScanContext, ScanObject

# passwords tried on encrypted members (malware-sample conventions first)
PASSWORDS = ["infected", "malware", "virus", "password", "123456", "1234"]
EXTRA_PASSWORDS = ["12345", "111111", "abc123", "qwerty"]

CHUNK = 1 << 20
# a member whose compression ratio exceeds max_ratio is only read up to this many bytes
BOMB_READ_CAP = 32 << 20
# all ratio-suspicious members of one archive together may only contribute this many bytes
BOMB_TOTAL_CAP = 64 << 20
# ratio checks only apply above this size (tiny highly-compressible files are normal)
RATIO_MIN_SIZE = 32 << 20

NATIVE_EXEC_EXT = {
    "exe", "dll", "scr", "com", "pif", "cpl", "ocx", "sys", "drv", "efi", "msi", "msp", "mst", "application",
    "gadget", "app", "command", "workflow", "action", "pkg", "mpkg", "dmg", "deb", "rpm", "apk", "ipa", "appx",
    "msix", "xll", "wll", "dylib", "bundle", "kext", "jar", "class", "elf", "bin", "run",
}
SCRIPT_EXT = {
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1", "psd1", "bat", "cmd", "sh", "bash", "zsh", "csh", "ksh",
    "py", "pyw", "pl", "rb", "php", "applescript", "scpt", "scptd", "osa", "hta", "lnk", "url", "scf", "reg",
    "inf", "jnlp", "sct", "wsc", "chm", "vb", "mjs", "cjs", "ws",
}
DISKIMAGE_EXT = {"iso", "img", "vhd", "vhdx", "dmg", "udf", "wim"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "bz2", "xz", "z", "cab", "arj", "lzh", "ace", "tar", "zst", "lz"}
# extensions that make good decoys in a double extension ("invoice.pdf.exe")
DECOY_EXT = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "bmp", "tif",
    "tiff", "mp3", "mp4", "avi", "mov", "wav", "csv", "odt", "ods", "jpe", "heic", "webp", "mkv", "docm",
    "xlsm", "zip", "rar", "7z", "pages", "numbers", "key",
}
DANGEROUS_FINAL = (NATIVE_EXEC_EXT | SCRIPT_EXT) - {"class", "bin", "run", "elf", "chm", "inf", "sct", "wsc"}

_BIDI = set("‪‫‬‭‮⁦⁧⁨⁩")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def ext_of(name: str) -> str:
    base = name.rstrip("/").rsplit("/", 1)[-1].rsplit("\\", 1)[-1].strip().lower()
    return base.rsplit(".", 1)[-1].strip() if "." in base else ""


def looks_executable_name(name: str) -> bool:
    e = ext_of(name)
    return e in NATIVE_EXEC_EXT or e in SCRIPT_EXT


def vis(text: str) -> str:
    """Make invisible/format characters (RTLO...) visible in evidence strings."""
    if text.isascii() and text.isprintable():
        return text
    out = []
    for ch in text:
        if ch in _BIDI or ord(ch) < 32 or ord(ch) == 127 or unicodedata.category(ch) in ("Cf", "Cc"):
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def clean_name(name: str, backslash: bool = False, max_len: int = 300) -> str:
    """Display name for a child object (never contains '>>' or control chars)."""
    if backslash:
        name = name.replace("\\", "/")
    name = _CTRL_RE.sub("?", name)
    name = name.replace(">>", "> >")
    while name.startswith("./"):
        name = name[2:]
    name = name.lstrip("/")
    name = re.sub(r"/{2,}", "/", name)
    if not name:
        name = "unnamed"
    if len(name) > max_len:
        name = name[:40] + "..." + name[-(max_len - 43):]
    return name


def name_findings(name: str, area: str = "Archive", zip_like: bool = True) -> list[tuple[str, Confidence, int, str]]:
    """Static checks on a member/attachment name.

    Returns (detection name, confidence, score, description) tuples.
    """
    out: list[tuple[str, Confidence, int, str]] = []
    norm = name.replace("\\", "/")
    parts = [p for p in norm.split("/")]
    if any(p == ".." for p in parts):
        out.append((f"Heur:{area}.PathTraversal", Confidence.MEDIUM, 30,
                    "member path contains '..' (path traversal / zip-slip)"))
    if norm.startswith("/") or re.match(r"^[A-Za-z]:[/\\]", name) or name.startswith("\\"):
        if zip_like:
            out.append((f"Heur:{area}.AbsolutePath", Confidence.LOW, 15, "member has an absolute path"))
    if any(ch in _BIDI for ch in name):
        out.append((f"Heur:{area}.RTLOName", Confidence.HIGH, 40,
                    "file name contains a Unicode bidirectional override (used to disguise the extension)"))
    if "\x00" in name:
        out.append((f"Heur:{area}.NullInName", Confidence.MEDIUM, 30,
                    "file name contains a NUL byte (hides the real extension from some tools)"))
    # double extension / decoy: "invoice.pdf.exe", "photo.jpg.app/", "invoice.pdf      .exe"
    comps = [c for c in norm.rstrip("/").split("/") if c]
    for ci, comp in enumerate(comps[-6:]):
        is_last = ci == len(comps[-6:]) - 1
        segs = [x.strip() for x in comp.split(".")]
        if len(segs) >= 3:
            last, prev = segs[-1].lower(), segs[-2].lower()
            if prev in DECOY_EXT and (last in DANGEROUS_FINAL if is_last else last in ("app",)):
                out.append((f"Heur:{area}.DoubleExtension", Confidence.MEDIUM, 30,
                            f"double extension '.{prev}.{last}' disguises an executable/script"))
                break
        if is_last:
            m = re.search(r"\S\s{4,}\.([A-Za-z0-9]{1,6})$", comp)
            if m and m.group(1).lower() in DANGEROUS_FINAL:
                out.append((f"Heur:{area}.DoubleExtension", Confidence.MEDIUM, 30,
                            "file name padded with spaces to hide an executable extension"))
    return out


class BudgetExceeded(Exception):
    pass


class Budget:
    """Total-bytes and wall-clock guard for one archive."""

    def __init__(self, ctx: ScanContext, seconds: float | None = None):
        self.ctx = ctx
        self.limit = max(0, ctx.limits.max_total_extracted - ctx.total_extracted)
        self.used = 0
        secs = seconds if seconds is not None else float(ctx.options.get("archive_timeout", 240))
        self.deadline = time.monotonic() + secs
        self.reason = ""

    def shrink(self, limit: int) -> None:
        self.limit = min(self.limit, limit)

    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def time_left(self) -> float:
        return max(1.0, self.deadline - time.monotonic())

    def charge(self, n: int) -> None:
        self.used += n
        if self.used > self.limit:
            self.reason = "total extraction size limit"
            raise BudgetExceeded(self.reason)
        if time.monotonic() > self.deadline:
            self.reason = "extraction time limit"
            raise BudgetExceeded(self.reason)

    def check_time(self) -> None:
        if time.monotonic() > self.deadline:
            self.reason = "extraction time limit"
            raise BudgetExceeded(self.reason)


class Sink:
    """Collects children/detections/metadata for one container object."""

    MAX_SKIPPED = 100

    def __init__(self, obj: ScanObject, ctx: ScanContext, fmt: str, area: str = "Archive",
                 seconds: float | None = None):
        self.obj = obj
        self.ctx = ctx
        self.fmt = fmt
        self.area = area
        self.members = 0
        self.encrypted = False
        self.skipped: list[str] = []
        self.skipped_count = 0
        self.added = 0
        self.appledouble = 0
        self.extra: dict[str, Any] = {}
        self.symlinks: dict[str, str] = {}
        self.bomb_bytes = 0
        self.prefix = ""            # prepended to child names (streamed sub-containers)
        self.budget = Budget(ctx, seconds)
        self._flagged_names: set[tuple[str, str]] = set()

    # -- bookkeeping -------------------------------------------------
    def skip(self, name: str, reason: str) -> None:
        self.skipped_count += 1
        if len(self.skipped) < self.MAX_SKIPPED:
            self.skipped.append(f"{vis(name)[:120]}: {reason}")

    def flag(self, name: str, conf: Confidence, score: int, desc: str, evidence: list[str] | None = None) -> None:
        for d in self.obj.detections:
            if d.name == name and d.engine == "heuristic" and score > d.score:
                d.score, d.confidence, d.description = score, max(conf, d.confidence), desc   # keep the stronger finding
        self.ctx.detect(self.obj, Detection(name, "heuristic", conf, score, desc, list(evidence or [])))

    def bomb_allowance(self, cap: int) -> int:
        """Read cap for a member with an absurd compression ratio (0 = do not read it at all)."""
        return max(0, min(cap, BOMB_READ_CAP, BOMB_TOTAL_CAP - self.bomb_bytes))

    def bomb(self, desc: str, evidence: list[str] | None = None, score: int = 40) -> None:
        """Heur:Archive.Bomb. 40 when limits were actually hit; callers pass a lower score for ratio-only
        suspicion (legitimate model/weight files can compress 1000:1 too)."""
        self.flag("Heur:Archive.Bomb", Confidence.MEDIUM, score, desc, evidence)

    def finish(self) -> None:
        meta = {"format": self.fmt, "members": self.members, "encrypted": self.encrypted,
                "skipped": self.skipped}
        if self.skipped_count > len(self.skipped):
            meta["skipped_count"] = self.skipped_count
        if self.appledouble:
            meta["appledouble_skipped"] = self.appledouble
        meta.update(self.extra)
        prev = self.obj.meta.get("archive")
        if isinstance(prev, dict) and prev.get("format") != self.fmt:
            meta["previous"] = prev
        self.obj.meta["archive"] = meta

    # -- name checks -------------------------------------------------
    def check_name(self, name: str, zip_like: bool = True) -> None:
        for det, conf, score, desc in name_findings(name, self.area, zip_like):
            self.flag(det, conf, score, desc, [vis(name)[:200]])
        # a member written "through" an earlier escaping symlink
        if self.symlinks:
            norm = name.replace("\\", "/")
            for link in self.symlinks:
                if norm.startswith(link.rstrip("/") + "/"):
                    self.flag(f"Heur:{self.area}.SymlinkTraversal", Confidence.HIGH, 40,
                              "member is written through a symlink that points outside the archive root",
                              [f"{vis(link)} -> {vis(self.symlinks[link])}", vis(name)])
                    break

    def note_symlink(self, name: str, target: str) -> None:
        base = name.replace("\\", "/").rstrip("/")
        d = base.rsplit("/", 1)[0] if "/" in base else ""
        tnorm = target.replace("\\", "/")
        if tnorm.startswith("/") or re.match(r"^[A-Za-z]:", tnorm):
            escapes = True
        else:
            import posixpath
            joined = posixpath.normpath(posixpath.join(d, tnorm))
            escapes = joined == ".." or joined.startswith("../")
        if escapes and self.fmt not in ("dmg", "iso", "hfs", "apfs", "udf", "squashfs", "wim", "vhd", "msi"):
            self.symlinks[base] = target
            self.flag(f"Heur:{self.area}.SymlinkEscape", Confidence.INFO, 0,
                      "symlink points outside the archive root", [f"{vis(base)} -> {vis(target)[:200]}"])

    # -- adding children ----------------------------------------------
    def limit_reached(self) -> bool:
        return self.ctx.child_count >= self.ctx.limits.max_children

    def add(self, name: str, data: bytes, member_meta: dict[str, Any] | None = None,
            backslash: bool = False) -> ScanObject | None:
        if not data:
            return None
        base = name.rsplit("/", 1)[-1]
        if base.startswith("._") and len(data) <= 4096 and data[:4] == b"\x00\x05\x16\x07":
            self.appledouble += 1        # AppleDouble resource-fork sidecar, nothing to scan
            return None
        name = self.prefix + name
        meta = {"member": dict(member_meta or {}, path=vis(name)[:300])}
        return self.ctx.add_child(self.obj, data, clean_name(name, backslash), "member", meta)


def read_capped(fp, cap: int, budget: Budget | None = None) -> tuple[bytes, bool]:
    """Read at most `cap` bytes from a file-like object in chunks.

    Returns (data, truncated).  Every chunk is charged to the budget so a
    hostile stream is cut off as soon as the archive-wide limit is hit.
    """
    parts: list[bytes] = []
    n = 0
    while n < cap:
        b = fp.read(min(CHUNK, cap - n))
        if not b:
            return b"".join(parts), False
        parts.append(b)
        n += len(b)
        if budget is not None:
            budget.charge(len(b))
    more = fp.read(1)
    return b"".join(parts), bool(more)


def ratio_suspicious(size: int, csize: int, max_ratio: int) -> bool:
    return size >= RATIO_MIN_SIZE and size > max_ratio * max(csize, 1)


# ---------------------------------------------------------------------------
# passwords
# ---------------------------------------------------------------------------
_PW_RE = re.compile(
    r"(?i)(?:pass(?:word|wd|code|phrase)?|pwd|has[lł]o|пароль|passwort|mot de passe|contrase[nñ]a)"
    r"\s*(?:for\s+(?:the\s+)?(?:archive|zip|file|attachment|document)\s*)?(?:is|to open|are)?\s*[:=\-–]?\s*"
    r"[\"'“”«»(\[]?([A-Za-z0-9!@#$%^&*_.+\-]{3,40})")
_PW_STOP = {"protected", "the", "is", "and", "for", "you", "your", "will", "was", "are", "not", "this", "that",
            "with", "from", "have", "must", "please", "zip", "file", "archive", "attached", "below", "above",
            "reset", "manager", "field", "here", "enter", "number", "expires", "expired", "recovery"}


def harvest_passwords(text: str, limit: int = 6) -> list[str]:
    out: list[str] = []
    for m in _PW_RE.finditer(text[:20000]):
        cand = m.group(1).strip(".,;:")
        if len(cand) >= 3 and cand.lower() not in _PW_STOP and cand not in out:
            out.append(cand)
            if len(out) >= limit:
                break
    return out


def candidate_passwords(obj: ScanObject) -> list[str]:
    """Hints collected from enclosing containers/e-mails first, then the common list."""
    pws: list[str] = []
    o: ScanObject | None = obj
    while o is not None:
        for p in o.meta.get("archive_passwords", []) or []:
            if p not in pws:
                pws.append(p)
        o = o.parent
    for p in PASSWORDS + EXTRA_PASSWORDS:
        if p not in pws:
            pws.append(p)
    return pws


def note_password_hints(sink: Sink, member_name: str, data: bytes) -> None:
    """Remember 'password: xyz' style hints from small text members for sibling encrypted archives."""
    if len(data) > 8192:
        return
    ext = ext_of(member_name)
    if ext not in ("txt", "md", "rtf", "html", "htm", "text", "log", "readme", "eml", "nfo", ""):
        return
    if b"\x00" in data[:512]:
        return
    hints = harvest_passwords(data.decode("utf-8", "replace"))
    if hints:
        cur = sink.obj.meta.setdefault("archive_passwords", [])
        for h in hints:
            if h not in cur:
                cur.append(h)


# ---------------------------------------------------------------------------
# subprocess + temp directories
# ---------------------------------------------------------------------------
def run_tool(args: list[str], timeout: float, cwd: str | None = None,
             stdin_data: bytes | None = None) -> tuple[int, str, str]:
    """Run an external tool with an argument list. rc == -999 on timeout, -998 when it can't start."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin:/opt/homebrew/bin"), "LANG": "en_US.UTF-8",
           "LC_ALL": "en_US.UTF-8", "HOME": os.environ.get("HOME", "/tmp"),
           "TMPDIR": os.environ.get("TMPDIR", "/tmp")}
    try:
        cp = subprocess.run(args, capture_output=True, timeout=timeout, cwd=cwd, env=env,
                            input=stdin_data if stdin_data is not None else None,
                            stdin=None if stdin_data is not None else subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return -999, "", "timeout"
    except (OSError, ValueError) as exc:
        return -998, "", repr(exc)
    return cp.returncode, cp.stdout.decode("utf-8", "replace"), cp.stderr.decode("utf-8", "replace")


def safe_rmtree(path: str | None) -> None:
    if not path or not os.path.exists(path):
        return

    def _fix(func, p, exc):  # noqa: ANN001
        try:
            os.chmod(p, 0o700)
            os.chmod(os.path.dirname(p), 0o700)
            func(p)
        except Exception:  # noqa: BLE001
            pass

    # make every directory traversable first (archives can contain mode 000 dirs)
    for dp, dns, _fns in os.walk(path, followlinks=False):
        try:
            os.chmod(dp, 0o700)
        except OSError:
            pass
    try:
        shutil.rmtree(path, onexc=_fix)
    except TypeError:  # python < 3.12
        shutil.rmtree(path, onerror=lambda f, p, e: _fix(f, p, e))
    except Exception:  # noqa: BLE001
        shutil.rmtree(path, ignore_errors=True)


def make_workdir(ctx: ScanContext, prefix: str = "x-") -> str:
    """Fresh private sub-directory of the scan's tempdir."""
    return tempfile.mkdtemp(prefix=prefix, dir=ctx.tempdir())


def walk_tree(root: str) -> Iterator[tuple[str, str, str, os.stat_result]]:
    """Yield (kind, relpath, abspath, lstat) for everything under root without following symlinks.

    kind is 'file', 'link' or 'special'.  Unreadable directories are chmod'ed (they belong to our tempdir).
    """
    stack = [""]
    while stack:
        rel = stack.pop()
        d = os.path.join(root, rel) if rel else root
        try:
            entries = list(os.scandir(d))
        except PermissionError:
            try:
                os.chmod(d, 0o700)
                entries = list(os.scandir(d))
            except OSError:
                continue
        except OSError:
            continue
        entries.sort(key=lambda e: e.name)
        dirs: list[str] = []
        for e in entries:
            r = f"{rel}/{e.name}" if rel else e.name
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                yield "link", r, e.path, st
            elif stat.S_ISDIR(st.st_mode):
                dirs.append(r)
            elif stat.S_ISREG(st.st_mode):
                yield "file", r, e.path, st
            else:
                yield "special", r, e.path, st
        stack.extend(reversed(dirs))


def read_regular_file(path: str, cap: int) -> tuple[bytes | None, bool]:
    """Read a regular file without following symlinks. Returns (data or None, truncated)."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        try:
            fd = os.open(path, flags)
        except PermissionError:
            os.chmod(path, 0o600)
            fd = os.open(path, flags)
    except OSError:
        return None, False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, False
        parts: list[bytes] = []
        n = 0
        while n < cap:
            b = os.read(fd, min(CHUNK, cap - n))
            if not b:
                return b"".join(parts), False
            parts.append(b)
            n += len(b)
        return b"".join(parts), bool(os.read(fd, 1))
    except OSError:
        return None, False
    finally:
        os.close(fd)


def dir_free_bytes(path: str) -> int:
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return 1 << 62


def report_encryption(sink: Sink, unopened: list[str], password: str | None, any_encrypted: bool = True) -> None:
    """Common detections for encrypted archives / members."""
    if not (any_encrypted or unopened):
        return
    sink.encrypted = True
    if unopened:
        ev = [vis(n)[:160] for n in unopened[:8]]
        sink.flag("Heur:Archive.Encrypted", Confidence.INFO, 5,
                  f"{len(unopened)} encrypted member(s) could not be decrypted with common passwords "
                  "(content not scanned)", ev)
        execs = [n for n in unopened if looks_executable_name(n)]
        if execs:
            sink.flag("Heur:Archive.EncryptedExecutable", Confidence.MEDIUM, 30,
                      "encrypted archive member that looks like an executable/script (content hidden from scanners)",
                      [vis(n)[:160] for n in execs[:8]])
    if password:
        sink.extra["password_used"] = password
        sink.flag("Heur:Archive.Encrypted", Confidence.LOW, 10,
                  "encrypted archive opened with a guessed/common password", [f"password: {password!r}"])

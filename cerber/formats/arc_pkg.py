"""Pure-python readers for tar, cpio, ar/deb, rpm and xar (macOS flat .pkg / .xip) containers.

Every reader is bounded: sizes are checked *before* reading, reads are charged to the archive Budget, and
nothing is written to disk.
"""
from __future__ import annotations

import io
import posixpath
import re
import struct
import tarfile
import zlib
from dataclasses import dataclass, field
from typing import Iterator

from ..core import Confidence
from .arc_common import (BOMB_READ_CAP, Budget, BudgetExceeded, Sink, note_password_hints, ratio_suspicious,
                         read_capped, vis)
from .arc_stream import DecompStream, make_adapter

S_IFMT = 0o170000
S_IFREG = 0o100000
S_IFDIR = 0o040000
S_IFLNK = 0o120000


def fix_name(name: str) -> str:
    """Undo surrogate escapes produced by tarfile for non-UTF-8 names."""
    try:
        return name.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeError:
        return name.encode("utf-8", "replace").decode("utf-8", "replace")


def _mode_bits(mode: int) -> int:
    return mode & 0o7777


# ---------------------------------------------------------------------------
# tar
# ---------------------------------------------------------------------------
def looks_like_tar(head: bytes) -> bool:
    if len(head) < 512:
        return False
    if head[257:262] == b"ustar":
        return True
    field_ = head[148:156].split(b"\x00")[0].strip()
    if not field_:
        return False
    try:
        stored = int(field_, 8)
    except ValueError:
        return False
    calc = sum(head[:148]) + 256 + sum(head[156:512])
    return calc == stored


def extract_tar(fp, sink: Sink, charge: bool) -> None:
    """Extract every regular member of a tar stream. `charge`: charge reads to the budget (False when the
    file-like object is a DecompStream that already charges)."""
    ctx = sink.ctx
    limits = ctx.limits
    try:
        tf = tarfile.open(fileobj=fp, mode="r|", ignore_zeros=True, errorlevel=0)
    except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
        sink.obj.errors.append(f"tar: cannot open: {exc}")
        return
    try:
        for ti in tf:
            if sink.limit_reached():
                sink.skip("*", "max children reached")
                break
            name = fix_name(ti.name)
            if ti.isdir():
                continue
            sink.members += 1
            sink.check_name(name, zip_like=False)
            if ti.issym() or ti.islnk():
                link = fix_name(ti.linkname)
                if ti.issym():
                    sink.note_symlink(name, link)
                elif ".." in link.replace("\\", "/").split("/"):
                    sink.note_symlink(name, link)
                continue
            if not ti.isreg():
                sink.skip(name, f"special file type {ti.type!r}")
                continue
            if ti.size == 0:
                continue
            if ti.size > limits.max_child_size:
                sink.skip(name, f"too large ({ti.size} bytes)")
                continue
            fobj = tf.extractfile(ti)
            if fobj is None:
                continue
            data, trunc = read_capped(fobj, min(ti.size, limits.max_child_size), sink.budget if charge else None)
            note_password_hints(sink, name, data)
            sink.add(name, data, {"size": ti.size, "mode": _mode_bits(ti.mode), "mtime": int(ti.mtime or 0),
                                  "truncated": trunc})
    except BudgetExceeded:
        raise
    except (tarfile.TarError, EOFError, OSError, zlib.error, ValueError) as exc:
        sink.obj.errors.append(f"tar: {type(exc).__name__}: {exc}")
    finally:
        try:
            tf.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# cpio
# ---------------------------------------------------------------------------
class _R:
    def __init__(self, fp):
        self.fp = fp
        self.pos = 0
        self.back = b""

    def read(self, n: int) -> bytes:
        out = b""
        if self.back:
            out, self.back = self.back[:n], self.back[n:]
        if len(out) < n:
            out += self.fp.read(n - len(out))
        self.pos += len(out)
        return out

    def unread(self, b: bytes) -> None:
        self.back = b + self.back
        self.pos -= len(b)

    def skip(self, n: int) -> None:
        while n > 0:
            b = self.read(min(n, 1 << 20))
            if not b:
                return
            n -= len(b)


@dataclass
class CpioEntry:
    name: str
    mode: int
    size: int
    nlink: int
    mtime: int
    _r: _R = field(repr=False, default=None)  # type: ignore[assignment]
    remaining: int = 0

    @property
    def is_file(self) -> bool:
        return self.mode & S_IFMT == S_IFREG

    @property
    def is_dir(self) -> bool:
        return self.mode & S_IFMT == S_IFDIR

    @property
    def is_link(self) -> bool:
        return self.mode & S_IFMT == S_IFLNK

    def read(self, n: int) -> bytes:
        n = min(n, self.remaining)
        b = self._r.read(n)
        self.remaining -= len(b)
        return b


_CPIO_MAGICS = (b"070701", b"070702", b"070707")


def _cpio_magic_ok(b: bytes) -> bool:
    return b[:6] in _CPIO_MAGICS or b[:2] in (b"\xc7\x71", b"\x71\xc7")


def iter_cpio(fp) -> Iterator[CpioEntry]:
    """Yield entries of a (possibly concatenated) cpio archive; the consumer must read or ignore the data
    of an entry before advancing the generator."""
    r = _R(fp)
    while True:
        magic = r.read(6)
        if len(magic) < 6:
            return
        if magic in (b"070701", b"070702"):
            rest = r.read(104)
            if len(rest) < 104:
                raise ValueError("cpio: truncated header")
            try:
                v = [int(rest[i:i + 8], 16) for i in range(0, 104, 8)]
            except ValueError:
                raise ValueError("cpio: bad newc header") from None
            _ino, mode, _uid, _gid, nlink, mtime, fsize, _a, _b, _c, _d, nsize, _chk = v
            hdr_len, align = 110, 4
        elif magic == b"070707":
            rest = r.read(70)
            if len(rest) < 70:
                raise ValueError("cpio: truncated header")
            try:
                mode = int(rest[12:18], 8)
                nlink = int(rest[30:36], 8)
                mtime = int(rest[42:53], 8)
                nsize = int(rest[53:59], 8)
                fsize = int(rest[59:70], 8)
            except ValueError:
                raise ValueError("cpio: bad odc header") from None
            hdr_len, align = 76, 1
        elif magic[:2] in (b"\xc7\x71", b"\x71\xc7"):
            rest = r.read(20)
            if len(rest) < 20:
                raise ValueError("cpio: truncated header")
            fmt = "<" if magic[:2] == b"\xc7\x71" else ">"
            vals = struct.unpack(fmt + "13H", magic + rest)
            # magic dev ino mode uid gid nlink rdev mtime(hi,lo) namesize filesize(hi,lo)
            mode, nlink = vals[3], vals[6]
            mtime = (vals[8] << 16) | vals[9]
            nsize = vals[10]
            fsize = (vals[11] << 16) | vals[12]
            hdr_len, align = 26, 2
        else:
            # NUL padding after the trailer? skip zeros and look for a new archive
            if magic.strip(b"\x00") == b"":
                more = r.read(1 << 16)
                stripped = more.lstrip(b"\x00")
                if not stripped:
                    if len(more) < (1 << 16):
                        return
                    continue
                r.unread(stripped)
                continue
            raise ValueError(f"cpio: bad magic {magic!r}")
        if nsize > 65536 or nsize == 0:
            raise ValueError("cpio: bad name size")
        raw_name = r.read(nsize)
        if len(raw_name) < nsize:
            raise ValueError("cpio: truncated name")
        pad = (-(hdr_len + nsize)) % align if align > 1 else 0
        if pad:
            r.skip(pad)
        name = raw_name.split(b"\x00", 1)[0].decode("utf-8", "replace")
        if name == "TRAILER!!!":
            # look for a concatenated archive after padding
            more = r.read(1 << 16)
            stripped = more.lstrip(b"\x00")
            if stripped and _cpio_magic_ok(stripped[:6]):
                r.unread(stripped)
                continue
            if len(more) == (1 << 16):
                # skip further padding blocks
                while True:
                    more = r.read(1 << 16)
                    stripped = more.lstrip(b"\x00")
                    if stripped:
                        if _cpio_magic_ok(stripped[:6]):
                            r.unread(stripped)
                            break
                        return
                    if len(more) < (1 << 16):
                        return
                continue
            return
        e = CpioEntry(name, mode, fsize, nlink, mtime, r, fsize)
        yield e
        r.skip(e.remaining)
        dpad = (-fsize) % align if align > 1 else 0
        if dpad:
            r.skip(dpad)


def extract_cpio(fp, sink: Sink, charge: bool) -> None:
    limits = sink.ctx.limits
    try:
        for e in iter_cpio(fp):
            if sink.limit_reached():
                sink.skip("*", "max children reached")
                break
            if e.is_dir:
                continue
            sink.members += 1
            sink.check_name(e.name, zip_like=False)
            if e.is_link:
                tgt = e.read(4096).decode("utf-8", "replace")
                sink.note_symlink(e.name, tgt)
                continue
            if not e.is_file or e.size == 0:
                continue
            if e.size > limits.max_child_size:
                sink.skip(e.name, f"too large ({e.size} bytes)")
                continue
            data, trunc = read_capped(_EntryIO(e), e.size, sink.budget if charge else None)
            note_password_hints(sink, e.name, data)
            sink.add(e.name, data, {"size": e.size, "mode": _mode_bits(e.mode), "mtime": e.mtime})
    except BudgetExceeded:
        raise
    except (ValueError, OSError, EOFError, zlib.error) as exc:
        sink.obj.errors.append(f"cpio: {exc}")


class _EntryIO:
    def __init__(self, e: CpioEntry):
        self.e = e

    def read(self, n: int) -> bytes:
        return self.e.read(n)


# ---------------------------------------------------------------------------
# ar / deb / static libraries
# ---------------------------------------------------------------------------
def iter_ar(data: bytes) -> Iterator[tuple[str, int, int]]:
    pos = 8
    n = len(data)
    longnames = b""
    while pos + 60 <= n:
        hdr = data[pos:pos + 60]
        if hdr[58:60] != b"`\n":
            raise ValueError("ar: bad member header")
        rawname = hdr[:16].decode("latin1")
        try:
            size = int(hdr[48:58].strip() or b"0")
        except ValueError:
            raise ValueError("ar: bad size") from None
        body = pos + 60
        end = body + size
        name = rawname.rstrip()
        if name.startswith("#1/") and name[3:].isdigit():
            nl = int(name[3:])
            fname = data[body:body + nl].split(b"\x00", 1)[0].decode("utf-8", "replace")
            yield_body, yield_size = body + nl, max(0, size - nl)
        elif name == "//":
            longnames = data[body:end]
            pos = end + (end & 1)
            continue
        elif name.startswith("/") and name[1:].isdigit() and longnames:
            idx = int(name[1:])
            e = longnames.find(b"\n", idx)
            fname = longnames[idx:e if e >= 0 else None].decode("utf-8", "replace").rstrip("/")
            yield_body, yield_size = body, size
        else:
            fname = name.rstrip("/") if name != "/" else "/"
            yield_body, yield_size = body, size
        if fname not in ("/", "//", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64", "__.SYMDEF_64 SORTED"):
            yield fname, yield_body, yield_size
        pos = end + (end & 1)


def extract_ar(data: bytes, sink: Sink) -> None:
    limits = sink.ctx.limits
    try:
        for name, off, size in iter_ar(data):
            if sink.limit_reached():
                sink.skip("*", "max children reached")
                break
            sink.members += 1
            sink.check_name(name, zip_like=False)
            if size == 0:
                continue
            if size > limits.max_child_size:
                sink.skip(name, f"too large ({size} bytes)")
                continue
            sink.budget.charge(size)
            sink.add(name, data[off:off + size], {"size": size})
    except BudgetExceeded:
        raise
    except ValueError as exc:
        sink.obj.errors.append(str(exc))


# ---------------------------------------------------------------------------
# rpm
# ---------------------------------------------------------------------------
_RPM_SCRIPTS = {
    1023: "%pre", 1024: "%post", 1025: "%preun", 1026: "%postun", 1079: "%verifyscript", 1151: "%pretrans",
    1152: "%posttrans", 5065: "%preuntrans", 5066: "%postuntrans", 1065: "%triggerscripts",
    5067: "%sysusers", 5068: "%triggerprein",
}
_RPM_PROGS = {1085: "%pre", 1086: "%post", 1087: "%preun", 1088: "%postun", 1153: "%pretrans", 1154: "%posttrans"}


def _rpm_header(data: bytes, pos: int):
    if data[pos:pos + 3] != b"\x8e\xad\xe8":
        raise ValueError("rpm: bad header magic")
    nindex, hsize = struct.unpack(">II", data[pos + 8:pos + 16])
    if nindex > 65536 or hsize > (64 << 20):
        raise ValueError("rpm: absurd header size")
    ipos = pos + 16
    spos = ipos + 16 * nindex
    store = data[spos:spos + hsize]
    entries = {}
    for i in range(nindex):
        tag, typ, off, cnt = struct.unpack(">IIII", data[ipos + 16 * i:ipos + 16 * i + 16])
        entries[tag] = (typ, off, cnt)
    return entries, store, spos + hsize


def _rpm_strings(store: bytes, typ: int, off: int, cnt: int) -> list[bytes]:
    out = []
    p = off
    n = 1 if typ == 6 else cnt
    for _ in range(min(n, 4096)):
        e = store.find(b"\x00", p)
        if e < 0:
            break
        out.append(store[p:e])
        p = e + 1
    return out


def extract_rpm(data: bytes, sink: Sink) -> None:
    try:
        sig_entries, _store, sig_end = _rpm_header(data, 96)
        pos = (sig_end + 7) & ~7
        entries, store, hdr_end = _rpm_header(data, pos)
    except (ValueError, struct.error) as exc:
        sink.obj.errors.append(f"rpm: {exc}")
        return
    info = {}
    for tag, key in ((1000, "name"), (1001, "version"), (1002, "release"), (1125, "payload_compressor")):
        if tag in entries:
            typ, off, cnt = entries[tag]
            if typ in (6, 8, 9):
                s = _rpm_strings(store, typ, off, cnt)
                if s:
                    info[key] = s[0].decode("utf-8", "replace")
    sink.extra["rpm"] = info
    # scriptlets are the interesting part of an rpm
    for tag, label in _RPM_SCRIPTS.items():
        if tag not in entries:
            continue
        typ, off, cnt = entries[tag]
        if typ not in (6, 8, 9):
            continue
        for i, s in enumerate(_rpm_strings(store, typ, off, cnt)):
            if not s.strip():
                continue
            sink.members += 1
            sink.add(f"scripts/{label}" + (f".{i}" if i else ""), s, {"size": len(s)})
    payload = data[hdr_end:]
    if payload:
        sink.members += 1
        comp = info.get("payload_compressor", "")
        ext = {"gzip": "cpio.gz", "xz": "cpio.xz", "bzip2": "cpio.bz2", "zstd": "cpio.zst", "lzma": "cpio.lzma"}.get(comp, "cpio")
        sink.add(f"payload.{ext}", payload, {"size": len(payload)})


# ---------------------------------------------------------------------------
# xar (macOS flat packages)
# ---------------------------------------------------------------------------
@dataclass
class XarEntry:
    path: str
    type: str
    offset: int = 0
    length: int = 0
    size: int = 0
    style: str = "application/octet-stream"
    link: str = ""
    has_data: bool = False


def parse_xar(data: bytes) -> tuple[list[XarEntry], int, str]:
    """Returns (entries, heap_offset, toc_xml)."""
    if len(data) < 28 or data[:4] != b"xar!":
        raise ValueError("xar: bad magic")
    hsize, _ver, clen, ulen, _alg = struct.unpack(">HHQQI", data[4:28])
    if clen > (256 << 20) or ulen > (512 << 20) or hsize < 28:
        raise ValueError("xar: absurd TOC size")
    comp = data[hsize:hsize + clen]
    if len(comp) < clen:
        raise ValueError("xar: truncated TOC")
    d = zlib.decompressobj()
    toc = d.decompress(comp, ulen + 1024)
    if b"<!DOCTYPE" in toc[:4096] or b"<!ENTITY" in toc[:65536]:
        raise ValueError("xar: TOC with DOCTYPE/ENTITY rejected")
    import xml.etree.ElementTree as ET
    root = ET.fromstring(toc)
    tocel = root.find("toc")
    if tocel is None:
        raise ValueError("xar: no toc")
    entries: list[XarEntry] = []

    def walk(el, prefix: str, depth: int) -> None:
        if depth > 64:
            return
        for f in el.findall("file"):
            nm = (f.findtext("name") or "").strip()
            path = f"{prefix}/{nm}" if prefix else nm
            typ = (f.findtext("type") or "file").strip()
            e = XarEntry(path, typ)
            dt = f.find("data")
            if dt is not None:
                try:
                    e.offset = int(dt.findtext("offset") or 0)
                    e.length = int(dt.findtext("length") or 0)
                    e.size = int(dt.findtext("size") or 0)
                except ValueError:
                    pass
                enc = dt.find("encoding")
                if enc is not None:
                    e.style = enc.get("style", e.style)
                e.has_data = True
            ln = f.find("link")
            if ln is not None:
                e.link = (ln.text or "").strip()
            entries.append(e)
            walk(f, path, depth + 1)

    walk(tocel, "", 0)
    return entries, hsize + clen, toc.decode("utf-8", "replace")


_STYLE_KIND = {
    "application/x-gzip": "zlib", "application/gzip": "zlib", "application/x-bzip2": "bzip2",
    "application/x-lzma": "lzma_auto", "application/x-xz": "xz", "application/octet-stream": None,
}

_SYS_RUN_RE = re.compile(r"system\s*\.\s*run(?:Once)?\s*\(", re.I)


def check_distribution(sink: Sink, path: str, data: bytes) -> None:
    text = data.decode("utf-8", "replace")
    if "<script" not in text.lower() and "script=" not in text.lower():
        return
    hits = [m.start() for m in _SYS_RUN_RE.finditer(text)]
    if hits:
        ev = [re.sub(r"\s+", " ", text[max(0, h - 40):h + 120]) for h in hits[:5]]
        sink.flag("Heur:PKG.InstallerJS.SystemRun", Confidence.MEDIUM, 30,
                  "Distribution InstallerJS calls system.run/system.runOnce (executes a program while the installer "
                  "evaluates its script)", ev)
    sink.extra.setdefault("pkg", {})["distribution_scripts"] = True


def _decode_xar(raw: bytes, style: str, cap: int, sink: Sink) -> tuple[bytes, bool, bool]:
    """Returns (data, truncated, bomb)."""
    kind = _STYLE_KIND.get(style, None)
    if kind is None:
        return raw[:cap], len(raw) > cap, False
    ad = make_adapter(kind, raw)
    if ad is None:
        return raw[:cap], False, False
    st = DecompStream(ad, cap, sink.budget, sink.ctx.limits.max_ratio)
    out = st.read()
    return out, st.truncated, st.bomb


def _stream_oversize(sink: Sink, e: XarEntry, raw: memoryview) -> bool:
    """A Payload too big to be a child: decode the compressed cpio/tar stream in place (zero copy)."""
    from .arc_stream import kind_from_magic
    kind = kind_from_magic(bytes(raw[:16]))
    if kind is None or _STYLE_KIND.get(e.style, None) is not None:
        return False
    ad = make_adapter(kind, raw)
    if ad is None:
        return False
    st = DecompStream(ad, max(1, sink.budget.remaining()), sink.budget, sink.ctx.limits.max_ratio)
    head = st.peek(1024)
    if _cpio_magic_ok(head[:6]):
        fn = extract_cpio
    elif looks_like_tar(head[:512]):
        fn = extract_tar
    else:
        return False
    sink.prefix = e.path + "/"
    try:
        fn(st, sink, False)
    finally:
        sink.prefix = ""
    if st.bomb:
        sink.bomb("decompression bomb (ratio guard) in xar payload", [vis(e.path)])
    elif st.budget_hit and sink.budget.reason.startswith("total"):
        sink.bomb("xar payload exceeds the total extraction limit", [vis(e.path)])
    sink.extra.setdefault("pkg", {}).setdefault("streamed_payloads", []).append(e.path)
    return True


def extract_xar(data: bytes, sink: Sink) -> bool:
    """Returns False when the container cannot be parsed (caller may fall back to 7zz)."""
    ctx = sink.ctx
    limits = ctx.limits
    try:
        entries, heap, _toc = parse_xar(data)
    except Exception as exc:  # noqa: BLE001 - struct/zlib/xml errors
        sink.obj.errors.append(f"xar: {exc}")
        return False
    has_scripts = False
    comps: list[str] = []
    for e in entries:
        if e.type == "directory":
            continue
        base = e.path.rsplit("/", 1)[-1]
        if base in ("Scripts", "Payload", "PackageInfo", "Distribution", "Bom"):
            sink.extra.setdefault("pkg", {}).setdefault("parts", []).append(e.path)
        if base == "Scripts":
            has_scripts = True
        if base == "Payload" and "/" in e.path:
            comps.append(e.path.rsplit("/", 1)[0])
        if sink.limit_reached():
            sink.skip("*", "max children reached")
            break
        sink.members += 1
        sink.check_name(e.path, zip_like=False)
        if e.type in ("symlink", "hardlink"):
            if e.link:
                sink.note_symlink(e.path, e.link)
            continue
        if not e.has_data or e.length <= 0:
            continue
        if heap + e.offset + e.length > len(data) or e.offset < 0:
            sink.skip(e.path, "data outside archive")
            continue
        if e.size > limits.max_child_size:
            if _stream_oversize(sink, e, memoryview(data)[heap + e.offset:heap + e.offset + e.length]):
                continue
            sink.skip(e.path, f"too large ({e.size} bytes)")
            if ratio_suspicious(e.size, e.length, limits.max_ratio):
                sink.bomb("xar member with absurd compression ratio", [vis(e.path)], score=25)
            continue
        raw = data[heap + e.offset:heap + e.offset + e.length]
        cap = limits.max_child_size
        if ratio_suspicious(e.size, e.length, limits.max_ratio):
            sink.bomb("xar member with absurd compression ratio", [vis(e.path)], score=25)
            cap = sink.bomb_allowance(cap)
            if cap <= 0:
                sink.skip(e.path, "absurd compression ratio, not read")
                continue
        content, trunc, bomb = _decode_xar(raw, e.style, cap, sink)
        if bomb:
            sink.bomb("decompression bomb (ratio guard) in xar member", [vis(e.path)])
        if not content:
            continue
        if base == "Distribution" or e.path.lower().endswith(".dist"):
            check_distribution(sink, e.path, content)
        sink.add(e.path, content, {"size": e.size, "encoding": e.style, "truncated": trunc})
    pk = sink.extra.setdefault("pkg", {})
    pk["has_scripts"] = has_scripts
    if comps:
        pk["components"] = comps[:50]
    return True

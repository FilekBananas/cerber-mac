"""Container / archive extraction (order 10, runs before every content analyzer).

Everything that can be unpacked is handed back through ctx.add_child so all engines scan every member.
Formats: zip family (zip/jar/apk/crx/vsix/ooxml/odf/whl), tar and single-stream gzip/bzip2/xz/lzma/zstd/lz4/lzip,
pbzx, 7z/rar/cab/iso/wim/vhd/chm/msi/dmg/NSIS/SFX (7zz, hdiutil for dmg as a fallback), xar/pkg (pure python),
cpio, ar/deb, rpm, e-mail (.eml/.emlx/mbox).

Detections (engine "heuristic"):
    Heur:Archive.Bomb          25-50  ratio-only suspicion (25), limits actually hit / ratio guard (40), overlapping members (50)
    Heur:Archive.Encrypted        5-10 encrypted content that could not be opened (5) / opened with a guessed password (10)
    Heur:Archive.EncryptedExecutable 30 unopenable encrypted member that looks like an executable/script
    Heur:Archive.PathTraversal     30  '..' in a member path
    Heur:Archive.AbsolutePath      15  absolute member path (zip-like formats)
    Heur:Archive.RTLOName          40  Unicode bidi override in a member name
    Heur:Archive.DoubleExtension   30  invoice.pdf.exe / .jpg.app/ ...
    Heur:Archive.NullInName        30  NUL byte in a member name
    Heur:Archive.Malformed         10  broken central directory / damaged member (content recovered)
    Heur:Archive.BadCRC            10  member with bad CRC whose content was recovered
    Heur:Archive.HiddenEntries     15  zip local entries not listed in the central directory
    Heur:Archive.TrailingData      10  data appended after the end of a compressed stream
    Heur:Archive.DeepNesting       25  nesting deeper than Limits.max_depth
    Heur:Archive.SymlinkEscape      0  symlink pointing outside the archive (info)
    Heur:Archive.SymlinkTraversal  40  member written through an escaping symlink
    Heur:PKG.InstallerJS.SystemRun 30  Distribution InstallerJS calls system.run/runOnce
    Heur:Email.ExecutableAttachment 30, Heur:Email.DiskImageAttachment 15, Heur:Email.HtmlAttachment 5,
    Heur:Email.ArchivedExecutable 20, Heur:Email.DoubleExtension 30, Heur:Email.RTLOName 40, ...
"""
from __future__ import annotations

import io
import struct
import weakref

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from ..formats.arc_cli import cli_extract, hdiutil_extract, prepare_input, py7zr_extract
from ..formats.arc_common import (BudgetExceeded, Sink, report_encryption, safe_rmtree, vis)
from ..formats.arc_mail import MBOX_SPLIT, extract_email
from ..formats.arc_pkg import (_cpio_magic_ok, extract_ar, extract_cpio, extract_rpm, extract_tar, extract_xar,
                               looks_like_tar)
from ..formats.arc_stream import DecompStream, make_adapter
from ..formats.arc_zip import extract_zip

from . import register

ZIP_TYPES = {"zip", "jar", "apk", "crx_zip", "vsix", "ooxml", "odf", "whl", "crx"}
STREAM_TYPES = {"gzip": "gzip", "bzip2": "bzip2", "xz": "xz", "zstd": "zstd", "lzma": "lzma", "lz4": "lz4",
                "lzip": "lzip"}
CLI_TYPES = {"rar": "rar", "7z": "7z", "cab": "cab", "iso": "iso", "wim": "wim", "vhd": "vhd", "vmdk": "vmdk",
             "qcow": "qcow", "chm": "chm"}
SFX_SIGS = (b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"MSCF")
NSIS_SIG = b"\xef\xbe\xad\xdeNullsoftInst"
OVERLAY_WINDOW = 64 << 10

_DECOMP_SUFFIX = ((".tgz", ".tar"), (".tbz2", ".tar"), (".tbz", ".tar"), (".txz", ".tar"), (".tzst", ".tar"),
                  (".gz", ""), (".bz2", ""), (".xz", ""), (".zst", ""), (".lzma", ""), (".lz4", ""), (".lz", ""),
                  (".z", ""))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _u16(d: bytes, o: int, e: str = "<") -> int:
    return struct.unpack_from(e + "H", d, o)[0]


def _u32(d: bytes, o: int, e: str = "<") -> int:
    return struct.unpack_from(e + "I", d, o)[0]


def _u64(d: bytes, o: int, e: str = "<") -> int:
    return struct.unpack_from(e + "Q", d, o)[0]


def _pe_overlay(d: bytes) -> int | None:
    try:
        if d[:2] != b"MZ" or len(d) < 0x40:
            return None
        lf = _u32(d, 0x3C)
        if lf + 24 > len(d) or d[lf:lf + 4] != b"PE\x00\x00":
            return None
        nsec = _u16(d, lf + 6)
        optsz = _u16(d, lf + 20)
        sec = lf + 24 + optsz
        end = 0
        for i in range(min(nsec, 96)):
            o = sec + 40 * i
            if o + 40 > len(d):
                break
            end = max(end, _u32(d, o + 20) + _u32(d, o + 16))
        return end if 0 < end < len(d) else None
    except struct.error:
        return None


def _elf_end(d: bytes) -> int | None:
    try:
        if d[:4] != b"\x7fELF" or len(d) < 64:
            return None
        e = "<" if d[5] == 1 else ">"
        if d[4] == 2:
            phoff, shoff = _u64(d, 0x20, e), _u64(d, 0x28, e)
            phent, phnum, shent, shnum = _u16(d, 0x36, e), _u16(d, 0x38, e), _u16(d, 0x3A, e), _u16(d, 0x3C, e)
            po, ps = 8, 0x20
            rd = _u64
        else:
            phoff, shoff = _u32(d, 0x1C, e), _u32(d, 0x20, e)
            phent, phnum, shent, shnum = _u16(d, 0x2A, e), _u16(d, 0x2C, e), _u16(d, 0x2E, e), _u16(d, 0x30, e)
            po, ps = 4, 0x10
            rd = _u32
        end = shoff + shent * shnum
        for i in range(min(phnum, 256)):
            o = phoff + i * phent
            if o + phent > len(d):
                break
            end = max(end, rd(d, o + po, e) + rd(d, o + ps, e))
        return end if 0 < end < len(d) else None
    except struct.error:
        return None


def _find_overlay_archive(d: bytes, ft: str) -> tuple[int, str] | None:
    """(offset, kind) of an archive signature near the start of a PE/ELF overlay, or NSIS marker."""
    ov = _pe_overlay(d) if ft in ("pe", "dos") else _elf_end(d) if ft == "elf" else None
    if ov is None:
        return None
    win = d[ov:ov + OVERLAY_WINDOW]
    best: tuple[int, str] | None = None
    for sig in SFX_SIGS:
        j = win.find(sig)
        if j >= 0 and (best is None or j < best[0]):
            best = (ov + j, sig[:4].decode("latin1"))
    if best:
        return best
    if ft in ("pe", "dos"):
        j = d.find(NSIS_SIG, ov, ov + (4 << 20))
        if j >= 0:
            return ov, "nsis"
    return None


_PAYLOAD_SIGS = ((b"\x1f\x8b\x08", "gzip"), (b"\xfd7zXZ\x00", "xz"), (b"BZh", "bzip2"), (b"PK\x03\x04", "zip"),
                 (b"7z\xbc\xaf\x27\x1c", "7z"), (b"\x28\xb5\x2f\xfd", "zstd"))


def _script_payload(d: bytes) -> tuple[int, str] | None:
    """Shell-script installers (makeself & co) carry a compressed archive after the script text."""
    if len(d) < 2048 or d[:2] != b"#!":
        return None
    window = d[:1 << 20]
    best: tuple[int, str] | None = None
    for sig, label in _PAYLOAD_SIGS:
        j = window.find(b"\n" + sig)
        while j >= 0:
            off = j + 1
            if label == "bzip2" and window[off + 4:off + 10] != b"1AY&SY":
                j = window.find(b"\n" + sig, j + 1)
                continue
            head = window[:off]
            bad = sum(1 for b in head[:8192] if b < 9 or (13 < b < 32 and b != 27))
            if bad < 0.02 * max(1, len(head[:8192])):
                if best is None or off < best[0]:
                    best = (off, label)
            break
    return best


def _decompressed_name(obj: ScanObject) -> str:
    n = obj.name or "content"
    low = n.lower()
    for suf, repl in _DECOMP_SUFFIX:
        if low.endswith(suf) and len(n) > len(suf):
            return n[:-len(suf)] + repl
    return n + ".out"


def _looks_mbox(d: bytes) -> bool:
    return d[:5] == b"From " and MBOX_SPLIT.match(d) is not None


# ---------------------------------------------------------------------------
# analyzer
# ---------------------------------------------------------------------------
@register
class ArchiveExtractor(Analyzer):
    name = "archives"
    order = 10

    def __init__(self) -> None:
        self._cache: tuple[weakref.ref, str, tuple[str, str] | None] | None = None

    # -- classification ---------------------------------------------------
    def _classify(self, obj: ScanObject) -> tuple[str, str] | None:
        """(handler, label) or None. The last result is cached (applies() and analyze() both ask)."""
        c = self._cache
        if c is not None and c[0]() is obj and c[1] == obj.ftype:
            return c[2]
        res = self._classify_uncached(obj)
        try:
            self._cache = (weakref.ref(obj), obj.ftype, res)
        except TypeError:
            self._cache = None
        return res

    def _classify_uncached(self, obj: ScanObject) -> tuple[str, str] | None:
        ft, d = obj.ftype, obj.data
        if not d:
            return None
        # UDIF disk images have no magic at offset 0 (the 'koly' trailer is the only marker) and may start
        # with what looks like an xz/gzip/zlib stream
        if len(d) >= 512 and d[-512:-508] == b"koly" and ft not in ("pe", "elf", "macho", "macho_fat"):
            return "dmg", "dmg"
        if ft in ZIP_TYPES:
            return "zip", ft
        if ft in STREAM_TYPES:
            return "stream", STREAM_TYPES[ft]
        if ft == "tar":
            return "tar", "tar"
        if ft == "cpio":
            return "cpio", "cpio"
        if ft == "ar":
            return "ar", "ar"
        if ft == "rpm":
            return "rpm", "rpm"
        if ft == "xar":
            return "xar", "xar"
        if ft == "dmg":
            return "dmg", "dmg"
        if ft in CLI_TYPES:
            return "cli", CLI_TYPES[ft]
        if ft == "email":
            if d[:5] == b"From " and not _looks_mbox(d) and obj.extension not in ("eml", "mbox", "mbx", "emlx"):
                return None            # plain text that merely starts with "From "
            return "email", "eml"
        if ft == "ole2" and ("MSI" in obj.fdesc or obj.extension in ("msi", "msp", "msm")):
            return "cli", "msi"
        if ft in ("pe", "dos", "elf"):
            hit = _find_overlay_archive(d, ft)
            if hit:
                return "sfx", hit[1]
            return None
        if ft in ("script", "shell") or (ft in ("python", "perl", "ruby") and d[:2] == b"#!"):
            hit = _script_payload(d)
            if hit:
                return "scriptpayload", hit[1]
            return None
        if ft in ("binary", "unknown", "text", "empty"):
            head = d[:16]
            if head[:4] == b"Cr24":
                return "zip", "crx"
            if head[:4] == b"pbzx":
                return "stream", "pbzx"
            if head[:4] == b"hsqs":
                return "cli", "squashfs"
            if len(d) > 0x200 and d[32:36] == b"NXSB":
                return "cli", "apfs"
            if len(d) > 0x600 and d[1024:1026] in (b"H+", b"HX"):
                return "cli", "hfs"
            if len(d) >= 512 and looks_like_tar(d[:512]):
                return "tar", "tar"
            ext = obj.extension
            if ext in ("eml", "emlx", "mbox", "mbx") and len(d) > 20:
                return "email", "eml"
            if ext == "arj" and head[:2] == b"\x60\xea":
                return "cli", "arj"
            if ext in ("lzh", "lha") and d[2:5] in (b"-lh", b"-lz"):
                return "cli", "lzh"
        return None

    def applies(self, obj: ScanObject) -> bool:
        try:
            return self._classify(obj) is not None
        except Exception:  # noqa: BLE001
            return False

    # -- driver -------------------------------------------------------------
    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        kind = self._classify(obj)
        if not kind:
            return
        handler, label = kind
        if handler == "email":
            return  # handled by EmailExtractor
        limits = ctx.limits
        if obj.depth >= limits.max_depth:
            obj.errors.append("max depth reached, archive not unpacked")
            ctx.detect(obj, Detection(
                "Heur:Archive.DeepNesting", "heuristic", Confidence.MEDIUM, 25,
                f"archives nested deeper than {limits.max_depth} levels (evasion or bomb)"))
            obj.meta["archive"] = {"format": label, "members": 0, "encrypted": False, "skipped": ["depth limit"]}
            return
        sink = Sink(obj, ctx, label)
        tool = ctx.tool("7z")
        try:
            getattr(self, "_do_" + handler)(obj, ctx, sink, tool, label)
        except BudgetExceeded as exc:
            if "size" in str(exc):
                sink.bomb("extraction exceeded the total size limit (possible decompression bomb)",
                          [f"{ctx.limits.max_total_extracted} bytes"])
            obj.errors.append(f"archives: {exc}")
        except MemoryError:
            obj.errors.append("archives: out of memory while unpacking")
        except RecursionError:
            obj.errors.append("archives: recursion limit while unpacking")
        except Exception as exc:  # noqa: BLE001 - analyzers never raise
            obj.errors.append(f"archives[{handler}]: {type(exc).__name__}: {exc}")
        finally:
            sink.finish()

    # -- handlers -------------------------------------------------------------
    def _do_zip(self, obj, ctx, sink, tool, label):
        ok = extract_zip(obj, ctx, sink, obj.data, tool)
        if not ok and tool and ctx.deep and sink.added == 0:
            self._cli(obj, ctx, sink, tool, "zip")

    def _do_tar(self, obj, ctx, sink, tool, label):
        extract_tar(io.BytesIO(obj.data), sink, charge=True)

    def _do_cpio(self, obj, ctx, sink, tool, label):
        extract_cpio(io.BytesIO(obj.data), sink, charge=True)

    def _do_ar(self, obj, ctx, sink, tool, label):
        extract_ar(obj.data, sink)

    def _do_rpm(self, obj, ctx, sink, tool, label):
        extract_rpm(obj.data, sink)
        if sink.added == 0 and tool and ctx.deep:
            self._cli(obj, ctx, sink, tool, "rpm")

    def _do_xar(self, obj, ctx, sink, tool, label):
        if not extract_xar(obj.data, sink) and tool and ctx.deep:
            self._cli(obj, ctx, sink, tool, "xar")

    def _do_stream(self, obj, ctx, sink, tool, label):
        limits = ctx.limits
        ad = make_adapter(label, obj.data)
        if ad is None:
            if tool and ctx.deep and label in ("zstd", "lz4", "lzip"):
                self._cli(obj, ctx, sink, tool, label)
            else:
                obj.errors.append(f"no decoder available for {label}")
            return
        st = DecompStream(ad, limits.max_child_size, sink.budget, limits.max_ratio)
        head = st.peek(1024)
        if not head:
            if st.error:
                obj.errors.append(f"{label}: {st.error}")
            return
        inner = None
        if looks_like_tar(head[:512]):
            inner = "tar"
        elif _cpio_magic_ok(head[:6]):
            inner = "cpio"
        if inner:
            sink.fmt = f"{label}+{inner}"
            st.set_cap(max(1, sink.budget.remaining()))
            (extract_tar if inner == "tar" else extract_cpio)(st, sink, charge=False)
        else:
            data = st.read()
            if data:
                sink.members += 1
                c = sink.add(_decompressed_name(obj), data, {"size": len(data), "truncated": st.truncated})
                del c
        self._stream_verdicts(obj, ctx, sink, st, ad)

    def _stream_verdicts(self, obj, ctx, sink, st, ad) -> None:
        if st.bomb or (st.truncated and not st.budget_hit and st.ratio_exceeded()):
            sink.bomb("decompression bomb: output/input ratio exceeds the limit",
                      [f"{st.out_total} bytes from ~{max(1, st.consumed_before_stop)} compressed bytes"])
        elif st.budget_hit:
            if sink.budget.reason.startswith("total"):
                sink.bomb("decompressed data exceeds the total extraction limit")
            else:
                obj.errors.append("decompression stopped: time limit")
        elif st.truncated:
            sink.skip("*", f"output truncated at {st.hard_cap} bytes")
            obj.errors.append(f"decompressed content truncated at {st.hard_cap} bytes")
        if st.error:
            obj.errors.append(f"{sink.fmt}: {st.error}")
        if not (st.truncated or st.error):
            try:
                tail = ad.trailing()
            except Exception:  # noqa: BLE001
                tail = b""
            if len(tail) >= 16 and tail.strip(b"\x00"):
                sink.flag("Heur:Archive.TrailingData", Confidence.LOW, 10,
                          "data appended after the end of the compressed stream",
                          [f"{len(tail)} trailing bytes"])
                sink.add("trailing-data", tail, {"size": len(tail)})

    def _do_dmg(self, obj, ctx, sink, tool, label):
        d = obj.data
        if d[:8] == b"encrcdsa" or d[-8:] == b"cdsaencr" or d[:8] == b"cdsaencr":
            sink.encrypted = True
            report_encryption(sink, ["<encrypted disk image>"], None)
            return
        done = False
        if tool:
            done = self._cli(obj, ctx, sink, tool, "dmg")
        hdi = ctx.tool("hdiutil")
        if not done and hdi and ctx.deep:
            path, dd = prepare_input(ctx, obj, "dmg")
            try:
                if hdiutil_extract(ctx, sink, hdi, path):
                    sink.extra["tool"] = "hdiutil"
            finally:
                safe_rmtree(dd)

    def _do_cli(self, obj, ctx, sink, tool, label):
        if tool:
            ok = self._cli(obj, ctx, sink, tool, label)
            if not ok and label == "7z" and sink.added == 0 and not sink.encrypted:
                self._py7zr(obj, ctx, sink)
        elif label == "7z":
            if not self._py7zr(obj, ctx, sink):
                obj.errors.append("7z: no extractor available (install 7zz)")
        else:
            obj.errors.append(f"{label}: 7zz not available, archive not unpacked")

    def _py7zr(self, obj, ctx, sink) -> bool:
        opened = py7zr_extract(ctx, sink, obj.data)
        if opened and sink.encrypted:
            pw = sink.extra.get("password_used")
            report_encryption(sink, [] if pw else ["<encrypted 7z content>"], pw)
        return opened

    def _do_sfx(self, obj, ctx, sink, tool, label):
        hit = _find_overlay_archive(obj.data, obj.ftype)
        if not hit:
            return
        off, sig = hit
        sink.extra["sfx"] = {"overlay_offset": off, "signature": sig}
        done = False
        if tool and ctx.deep:
            done = self._cli(obj, ctx, sink, tool, "exe", accept_non_container=False)
        if not done and sig != "nsis":
            # let the normal pipeline identify and unpack the embedded archive
            c = ctx.add_child(obj, obj.data[off:], f"overlay@{off:#x}", "slice", {"overlay_offset": off})
            if c is not None:
                sink.added += 1
                sink.members += 1

    def _do_scriptpayload(self, obj, ctx, sink, tool, label):
        hit = _script_payload(obj.data)
        if not hit:
            return
        off, kind = hit
        sink.fmt = f"script+{kind}"
        sink.extra["script_payload"] = {"offset": off, "kind": kind}
        c = ctx.add_child(obj, obj.data[off:], f"payload@{off:#x}", "slice", {"payload_offset": off})
        if c is not None:
            sink.added += 1
            sink.members += 1

    # -- shared CLI path ---------------------------------------------------------
    def _cli(self, obj: ScanObject, ctx: ScanContext, sink: Sink, tool: str, ext: str,
             accept_non_container: bool = False) -> bool:
        """Run 7zz on the object. Returns True when the archive could be opened (even if empty)."""
        path, d = prepare_input(ctx, obj, ext)
        try:
            res = cli_extract(ctx, sink, tool, path, accept_non_container=accept_non_container)
        finally:
            safe_rmtree(d)
        if res.type:
            sink.extra["type"] = res.type
        sink.extra["tool"] = "7zz"
        if res.needs_password or res.unopened_encrypted or res.password or sink.encrypted:
            unopened = list(res.unopened_encrypted)
            if res.needs_password and not unopened:
                unopened = ["<encrypted content>"]
            report_encryption(sink, unopened, res.password)
        if not res.ok and res.error and not res.needs_password and not res.non_container:
            obj.errors.append(f"7zz: {res.error}")
        return res.ok and not res.non_container


@register
class EmailExtractor(Analyzer):
    name = "email_extract"
    order = 10

    def applies(self, obj: ScanObject) -> bool:
        try:
            d = obj.data
            if not d:
                return False
            if obj.ftype == "email":
                if d[:5] == b"From " and not _looks_mbox(d) and obj.extension not in ("eml", "mbox", "mbx", "emlx"):
                    return False
                return True
            return obj.ftype in ("binary", "unknown", "text", "html") and obj.extension in (
                "eml", "emlx", "mbox", "mbx") and len(d) > 20
        except Exception:  # noqa: BLE001
            return False

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        if obj.depth >= ctx.limits.max_depth:
            obj.errors.append("max depth reached, e-mail not unpacked")
            return
        sink = Sink(obj, ctx, "eml", area="Email")
        try:
            extract_email(obj, ctx, sink, ctx.tool("7z") if ctx.deep else None)
        except BudgetExceeded as exc:
            obj.errors.append(f"email: {exc}")
        except MemoryError:
            obj.errors.append("email: out of memory")
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"email: {type(exc).__name__}: {exc}")
        finally:
            sink.finish()

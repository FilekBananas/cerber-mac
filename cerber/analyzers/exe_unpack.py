"""Executable unpacking / carving (runs before the format heuristics).

Analyzer "exe_unpack" (order 15) for ftype pe / elf / macho / macho_fat:
  * Mach-O universal (fat/fat64)  -> every slice as child kind="slice" named "slice/<arch>"
  * UPX (PE/ELF/Mach-O)           -> `upx -d` on a temp copy -> child "upx-unpacked" (kind "decoded")
  * PE overlay                    -> child "overlay" (skipped when the archive analyzer already
                                     unpacked an SFX/NSIS overlay or when it is a PyInstaller archive)
  * ELF / Mach-O appended data    -> child "overlay"
  * PE resources                  -> RCDATA/custom/HTML resources holding executables, archives,
                                     documents or scripts -> "rsrc/<type>/<name>"
  * .NET manifest resources       -> executables / archives -> "dotnet-res/<n>"
  * Authenticode padding          -> data hidden after the PKCS#7 blob -> "cert-padding"
  * PyInstaller                   -> CArchive TOC entries (zlib) + PYZ modules (non-stdlib) as .pyc children
  * carving                       -> PE (MZ+PE), ELF, Mach-O, fat headers at non-zero offsets (validated,
                                     exact extent from headers) -> "carved/<kind>@<off>"
  * base64 PE                     -> "TVqQAAMAAAAEAAAA..." runs (also reversed / UTF-16) decoded -> "b64-pe@<off>"

Detections (<Area> = PE | ELF | MachO):
    Heur:<Area>.Packed.UPX                  10 (MachO 20)  UPX packed (unpacked copy is scanned)
    Heur:<Area>.Packed.UPX.Modified         35  UPX packed but upx refuses to unpack (tampered headers)
    Heur:MachO.Fat.Malformed                15  slice outside the file / overlapping / not Mach-O
    Heur:MachO.Fat.TrailingData             10  data appended after the last slice
    Heur:PE.Overlay.Executable              15  overlay starts with an executable
    Heur:PE.Overlay.AfterSignature          15  data appended after the Authenticode certificate table (GUI/console apps)
    Heur:ELF.Overlay / Heur:MachO.Overlay  5/10  data appended after the image
    Heur:PE.Resource.EmbeddedExecutable  10/25  executable in resources (25 when hidden in icon/bitmap/etc.)
    Heur:PE.Resource.EncryptedBlob           5  large near-random resource of unknown type
    Heur:PE.DotNet.EmbeddedExecutable       10  executable in a .NET manifest resource
    Heur:<Area>.EmbeddedExecutable        5/10  executable carved at a non-zero offset (10 cross-platform; not
                                                for Apple platform binaries, .NET single-file, Dart/Bun/Node/Deno)
    Heur:<Area>.EmbeddedBase64PE         20/30  base64 (30: reversed base64) encoded PE inside the binary
    Heur:<Area>.PyInstaller.EncryptedPYZ    10  PyInstaller PYZ entries encrypted (--key)
"""
from __future__ import annotations

import base64
import os
import re
import struct
import subprocess
import sys
import zlib

from ..core import Analyzer, Confidence, ScanContext, ScanObject

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover
    yara = None
from ..filetype import ARCHIVE_TYPES, DOCUMENT_TYPES, EXECUTABLE_TYPES, identify_bytes
from . import register
from .exe_elf import elf_extent, elf_valid_at
from .exe_macho import MH_MAGIC, MachO, arch_name, macho_extent, macho_valid_at, parse_codesig
from .exe_misc import PYC_MAGIC_FOR_VERSION, det, sampled_entropy
from .exe_pe import cert_padding, data_dir, load_pe, security_dir, section_name

AREA = {"pe": "PE", "elf": "ELF", "macho": "MachO", "macho_fat": "MachO"}
CARVE_LIMIT = 256 << 20
MAX_CARVED = 24
MIN_CARVE = 8192            # smaller "executables" are packer/linker stubs, not payloads
RUNTIME_CONTAINERS = ((b"Dart SDK version: ", "Dart AOT"), (b"/$bunfs/", "Bun"), (b"NODE_SEA_BLOB", "Node SEA"),
                      (b"pkg/prelude/bootstrap.js", "pkg"), (b"d3n0l4nd", "Deno"))
DOTNET_BUNDLE_SIG = bytes.fromhex("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae")
MAX_RSRC_CHILDREN = 64
MAX_PYI_ENTRIES = 600
MAX_PYZ_CHILDREN = 300
UPX_TIMEOUT = 120
SCRIPTISH = {"script", "shell", "python", "powershell", "vbs", "javascript", "batch", "applescript", "hta", "php",
             "perl", "ruby", "lnk"}
RT_NAMES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT",
            9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION",
            17: "DLGINCLUDE", 19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST"}
STANDARD_RT = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 14, 16, 17, 19, 20, 21, 22, 24}
PE_MACHINES = {0x14C, 0x8664, 0xAA64, 0x1C0, 0x1C4, 0x200, 0xEBC, 0x5064, 0xA641, 0x166, 0x169, 0x1A2, 0x1A6, 0x1F0}
COOKIE = b"MEI\x0c\x0b\x0a\x0b\x0e"
B64_MZ = (b"TVqQAAMAAAAEAAAA", b"TVpQAAIAAAAEAA8A", b"TVoAAAAAAAAAAAAA", b"TVqAAAEAAAAEABAA", b"TVpBUlVIieVIgewg")
B64_RE = re.compile(rb"[A-Za-z0-9+/=\r\n]{64,}")
B64W_RE = re.compile(rb"(?:[A-Za-z0-9+/=]\x00){64,}")
_B64_TAIL_RE = re.compile(rb"[A-Za-z0-9+/=\r\n]*\Z")
COMMON_PKGS = {
    "requests", "urllib3", "certifi", "charset_normalizer", "chardet", "idna", "six", "setuptools", "pkg_resources",
    "_distutils_hack", "packaging", "pyparsing", "PyInstaller", "pyi_splash", "cryptography", "cffi", "_cffi_backend",
    "pycparser", "OpenSSL", "attr", "attrs", "dateutil", "pytz", "yaml", "_yaml", "numpy", "pandas", "PIL", "psutil",
    "colorama", "click", "jinja2", "markupsafe", "win32com", "pywintypes", "pythoncom", "win32ctypes",
    "typing_extensions", "zipp", "importlib_metadata", "importlib_resources", "more_itertools", "jaraco",
    "platformdirs", "backports", "simplejson", "websocket", "websockets", "aiohttp", "multidict", "yarl", "frozenlist",
    "aiosignal", "async_timeout", "Crypto", "Cryptodome", "nacl", "bcrypt", "paramiko", "google", "grpc", "pydantic",
    "pydantic_core", "sqlalchemy", "bs4", "soupsieve", "lxml", "html5lib", "tqdm", "rich", "pygments", "docutils", "wx",
    "PyQt5", "PyQt6", "PySide2", "PySide6", "sip", "shiboken2", "shiboken6", "matplotlib", "scipy", "sklearn", "cv2",
    "pygame", "kivy", "altgraph", "macholib", "keyring", "anyio", "sniffio", "h11", "httpx", "httpcore", "tomli",
    "tomllib", "wheel", "pip", "win32", "win32api", "win32con", "pywin32_system32", "_pyinstaller_hooks_contrib",
    "markdown_it", "mdurl", "exceptiongroup", "pyi_rth_inspect", "ctypes", "pkgutil", "customtkinter", "darkdetect",
    "PIL._imaging", "gi", "objc", "Foundation", "AppKit", "CoreFoundation", "Quartz",
}
_STDLIB = set(getattr(sys, "stdlib_module_names", ()))


# ---------------------------------------------------------------------------
# PE helpers for carving
# ---------------------------------------------------------------------------
def pe_valid_at(d: bytes, off: int) -> bool:
    if d[off:off + 2] != b"MZ" or off + 0x40 > len(d):
        return False
    lf = struct.unpack_from("<I", d, off + 0x3C)[0]
    if lf < 4 or lf > 0x2000:
        return False
    p = off + lf
    if p + 24 + 2 > len(d) or d[p:p + 4] != b"PE\x00\x00":
        return False
    machine, nsec = struct.unpack_from("<HH", d, p + 4)
    opt_size = struct.unpack_from("<H", d, p + 20)[0]
    magic = struct.unpack_from("<H", d, p + 24)[0]
    return machine in PE_MACHINES and 0 < nsec <= 96 and opt_size >= 0x60 and magic in (0x10B, 0x20B)


def pe_extent(d: bytes, off: int) -> int:
    lf = struct.unpack_from("<I", d, off + 0x3C)[0]
    p = off + lf
    nsec = struct.unpack_from("<H", d, p + 6)[0]
    opt_size = struct.unpack_from("<H", d, p + 20)[0]
    magic = struct.unpack_from("<H", d, p + 24)[0]
    opt = p + 24
    end = lf + 24 + opt_size + 40 * nsec
    try:
        end = max(end, struct.unpack_from("<I", d, opt + 60)[0])  # SizeOfHeaders
        so = opt + opt_size
        for i in range(min(nsec, 96)):
            q = so + 40 * i
            if q + 40 > len(d):
                break
            rsz, roff = struct.unpack_from("<II", d, q + 16)
            if rsz and roff < (1 << 31):
                end = max(end, roff + rsz)
        sec_idx = opt + (0x80 if magic == 0x10B else 0x90)
        if sec_idx + 8 <= len(d):
            coff, csz = struct.unpack_from("<II", d, sec_idx)
            if coff and csz and coff < (1 << 31) and coff >= end - 0x10000:
                end = max(end, coff + csz)
    except struct.error:
        pass
    return end


def fat_valid_at(d: bytes, off: int) -> int:
    """Extent of a plausible embedded fat binary (0 if not plausible)."""
    if len(d) - off < 64:
        return 0
    magic = d[off:off + 4]
    if magic not in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        return 0
    n = struct.unpack_from(">I", d, off + 4)[0]
    if not 1 <= n <= 8:
        return 0
    is64 = magic[3] == 0xBF
    ent = 32 if is64 else 20
    end = 0
    for i in range(n):
        p = off + 8 + i * ent
        if is64:
            cpu, _sub, so, sz, al = struct.unpack_from(">iiQQI", d, p)
        else:
            cpu, _sub, so, sz, al = struct.unpack_from(">iiIII", d, p)
        if (cpu & 0xFFFFFFFF) not in (7, 0x01000007, 12, 0x0100000C, 0x0200000C, 18, 0x01000012) or al > 16 or \
                so < 8 + n * ent or sz == 0:
            return 0
        if d[off + so:off + so + 4] not in MH_MAGIC:
            return 0
        end = max(end, so + sz)
    return end


_MAGICS = [(b"MZ", "pe"), (b"\x7fELF", "elf"), (b"\xcf\xfa\xed\xfe", "macho"), (b"\xce\xfa\xed\xfe", "macho"),
           (b"\xfe\xed\xfa\xce", "macho"), (b"\xfe\xed\xfa\xcf", "macho"), (b"\xca\xfe\xba\xbe", "fat"),
           (b"\xca\xfe\xba\xbf", "fat")]
_MAGIC_RULES = None
MAX_MAGIC_HITS = 20000


def _magic_rules():
    global _MAGIC_RULES
    if _MAGIC_RULES is None:
        _MAGIC_RULES = False
        if yara is not None:
            try:
                src = "rule m { strings: " + " ".join(
                    f"$s{i} = {{ {m.hex(' ')} }}" for i, (m, _k) in enumerate(_MAGICS)) + " condition: any of them }"
                _MAGIC_RULES = yara.compile(source=src)
            except Exception:  # noqa: BLE001
                _MAGIC_RULES = False
    return _MAGIC_RULES


def _magic_hits(d: bytes, lim: int) -> list[tuple[int, str]]:
    """Offsets (>0, < lim) of executable magics, sorted. One YARA pass instead of 8 find() sweeps."""
    rules = _magic_rules()
    hits: list[tuple[int, str]] = []
    if rules:
        try:
            buf = d if len(d) <= lim else d[:lim]
            for m in rules.match(data=buf, timeout=120):
                for sm in m.strings:
                    kind = _MAGICS[int(sm.identifier[2:])][1]
                    for inst in sm.instances[:MAX_MAGIC_HITS]:
                        if inst.offset > 0:
                            hits.append((inst.offset, kind))
            hits.sort()
            return hits
        except Exception:  # noqa: BLE001
            hits = []
    for magic, kind in _MAGICS:
        pos, n = d.find(magic, 1, lim), 0
        while pos >= 0 and n < MAX_MAGIC_HITS:
            hits.append((pos, kind))
            n += 1
            pos = d.find(magic, pos + 1, lim)
    hits.sort()
    return hits


def _apple_signed(d: bytes) -> bool:
    try:
        m = MachO(d)
        if not m.codesig:
            return False
        sig = parse_codesig(d, *m.codesig)
        return sig.get("state") == "apple" or bool(sig.get("platform"))
    except Exception:  # noqa: BLE001
        return False


def _elf_type(d: bytes, off: int) -> int:
    return struct.unpack_from("<H" if d[off + 5] == 1 else ">H", d, off + 16)[0]


def _macho_type(d: bytes, off: int) -> int:
    be = d[off:off + 4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf")
    return struct.unpack_from(">I" if be else "<I", d, off + 12)[0]


# ---------------------------------------------------------------------------
# tiny safe marshal reader (only the simple types used by PYZ tables of contents)
# ---------------------------------------------------------------------------
class _Marshal:
    def __init__(self, buf: bytes, pos: int, max_items: int = 400_000):
        self.b, self.p, self.refs, self.n, self.max = buf, pos, [], 0, max_items

    def _u32(self) -> int:
        v = struct.unpack_from("<I", self.b, self.p)[0]
        self.p += 4
        return v

    def read(self, depth: int = 0):
        if depth > 48:
            raise ValueError("marshal nesting too deep")
        self.n += 1
        if self.n > self.max:
            raise ValueError("marshal too many items")
        code = self.b[self.p]
        self.p += 1
        flag, t = code & 0x80, chr(code & 0x7F)
        idx = None
        if flag:
            idx = len(self.refs)
            self.refs.append(None)
        if t == "N" or t == "0":
            v = None
        elif t == "T":
            v = True
        elif t == "F":
            v = False
        elif t == "i":
            v = struct.unpack_from("<i", self.b, self.p)[0]
            self.p += 4
        elif t == "l":
            n = struct.unpack_from("<i", self.b, self.p)[0]
            self.p += 4
            v = 0
            for k in range(min(abs(n), 64)):
                v |= struct.unpack_from("<H", self.b, self.p + 2 * k)[0] << (15 * k)
            self.p += 2 * abs(n)
            v = -v if n < 0 else v
        elif t in "sutaA":
            n = self._u32()
            raw = self.b[self.p:self.p + n]
            self.p += n
            v = raw if t == "s" else raw.decode("utf-8" if t in "ut" else "latin-1", "replace")
        elif t in "zZ":
            n = self.b[self.p]
            self.p += 1
            v = self.b[self.p:self.p + n].decode("latin-1")
            self.p += n
        elif t in "()[<>":
            if t == ")":
                n = self.b[self.p]
                self.p += 1
            else:
                n = self._u32()
            lst: list = []
            if flag and t == "[":
                self.refs[idx] = lst
            for _ in range(min(n, 1_000_000)):
                lst.append(self.read(depth + 1))
            v = tuple(lst) if t in "()" else lst
        elif t == "{":
            dct: dict = {}
            if flag:
                self.refs[idx] = dct
            while self.b[self.p] != 0x30:
                k = self.read(depth + 1)
                dct[k if isinstance(k, (str, int, bytes, tuple)) else repr(k)] = self.read(depth + 1)
            self.p += 1
            v = dct
        elif t == "r":
            v = self.refs[self._u32()]
        elif t == "g":
            self.p += 8
            v = 0.0
        elif t == "y":
            self.p += 16
            v = 0.0
        else:
            raise ValueError(f"unsupported marshal type {t!r}")
        if flag and t not in "[{":
            self.refs[idx] = v
        return v


def _pyc_header(magic4: bytes) -> bytes:
    return magic4 + b"\x00" * 12


@register
class ExeUnpacker(Analyzer):
    name = "exe_unpack"
    order = 15

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype in AREA

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        if obj.ftype == "macho_fat":
            self._fat(obj, ctx)
            return
        area = AREA[obj.ftype]
        covered: list[tuple[int, int]] = []
        self._upx(obj, ctx, area)
        pyi = self._pyinstaller(obj, ctx, area)
        if obj.ftype == "pe":
            pe = load_pe(obj)
            if pe is not None:
                self._pe_overlay(obj, ctx, pe, covered, pyi)
                self._pe_resources(obj, ctx, pe, covered)
                self._dotnet_resources(obj, ctx, pe, covered)
        else:
            self._generic_overlay(obj, ctx, area, covered, pyi)
        if ctx.deep:
            self._carve(obj, ctx, area, covered, pyi)
            self._b64_pe(obj, ctx, area)

    # ------------------------------------------------------------------ fat
    def _fat(self, obj: ScanObject, ctx: ScanContext) -> None:
        d = obj.data
        is64 = d[:4] == b"\xca\xfe\xba\xbf"
        n = struct.unpack_from(">I", d, 4)[0] if len(d) >= 8 else 0
        ent = 32 if is64 else 20
        issues: list[str] = []
        slices: list[tuple[int, int, str]] = []
        if not 1 <= n <= 64:
            issues.append(f"nfat_arch={n}")
            n = 0
        for i in range(n):
            p = 8 + i * ent
            if p + ent > len(d):
                issues.append("fat header truncated")
                break
            if is64:
                cpu, sub, off, size, _al = struct.unpack_from(">iiQQI", d, p)
            else:
                cpu, sub, off, size, _al = struct.unpack_from(">iiIII", d, p)
            name = arch_name(cpu & 0xFFFFFFFF, sub)
            if off < 8 + n * ent or off >= len(d):
                issues.append(f"slice {name} at {off:#x} outside the file")
                continue
            if off + size > len(d):
                obj.errors.append(f"fat: slice {name} truncated")
                size = len(d) - off
            slices.append((off, size, name))
        srt = sorted(slices)
        for (o1, s1, n1), (o2, _s2, n2) in zip(srt, srt[1:]):
            if o1 + s1 > o2:
                issues.append(f"slices {n1} and {n2} overlap")
        names_seen: dict[str, int] = {}
        archs = []
        for off, size, name in slices:
            sub = d[off:off + size]
            if sub[:4] not in MH_MAGIC and sub[:8] != b"!<arch>\n":
                issues.append(f"slice {name} is not a Mach-O ({sub[:4].hex()})")
            k = names_seen.get(name, 0)
            names_seen[name] = k + 1
            label = f"slice/{name}" if not k else f"slice/{name}-{k}"
            archs.append(name)
            ctx.add_child(obj, sub, label, "slice", {"arch": name, "offset": off})
        obj.meta["macho_fat"] = {"archs": archs, "count": n}
        if issues:
            ctx.detect(obj, det("Heur:MachO.Fat.Malformed", Confidence.MEDIUM, 15,
                                "Inconsistent universal-binary header", issues[:5]))
        end = max((o + s for o, s, _ in slices), default=0)
        if end and len(d) - end >= 512:
            tail = d[end:]
            if tail.count(0) != len(tail):
                ctx.detect(obj, det("Heur:MachO.Fat.TrailingData", Confidence.LOW, 10,
                                    "Data appended after the last slice of a universal binary",
                                    [f"{len(tail)} bytes at {end:#x}"], offset=end))
                ctx.add_child(obj, tail, "fat-trailing-data", "stream", {"overlay_offset": end})

    # ------------------------------------------------------------------ UPX
    def _upx(self, obj: ScanObject, ctx: ScanContext, area: str) -> None:
        d = obj.data
        head, tail = d[:0x3000], d[-0x1000:]
        ev = []
        if obj.ftype == "pe":
            pe = load_pe(obj)
            if pe is not None:
                nm = [section_name(s).lower() for s in pe.sections]
                if any(x.startswith(("upx", ".upx")) for x in nm):
                    ev.append("UPX section names")
        if b"UPX!" in head:
            ev.append("UPX! header")
        if b"UPX!" in tail:
            ev.append("UPX! trailer")
        big = d[:0x40000]
        if b"$Info: This file is packed with the UPX" in big or b"$Info: This file is packed with the UPX" in d[-0x40000:]:
            ev.append("UPX $Info string")
        if b"PROT_EXEC|PROT_WRITE failed." in big:
            ev.append("UPX ELF stub")
        if not ev:
            return
        strong = len(ev) >= 2 or ev[0] in ("UPX section names", "UPX $Info string", "UPX ELF stub")
        base_score = 20 if area == "MachO" else 10
        tool = ctx.tool("upx")
        if not tool:
            if strong:
                ctx.detect(obj, det(f"Heur:{area}.Packed.UPX", Confidence.LOW, base_score, "UPX-packed executable", ev))
            obj.errors.append("upx: tool not available, not unpacked")
            return
        tmp = ctx.tempdir()
        src = os.path.join(tmp, f"upx-{obj.sha256[:16]}.bin")
        out = src + ".out"
        msg = ""
        ok = False
        try:
            with open(src, "wb") as fh:
                fh.write(d)
            r = subprocess.run([tool, "-d", "-q", "-q", "-o", out, src], capture_output=True, timeout=UPX_TIMEOUT)
            msg = (r.stdout + r.stderr).decode("utf-8", "replace").strip()
            ok = r.returncode == 0 and os.path.exists(out)
            if ok:
                with open(out, "rb") as fh:
                    data = fh.read(ctx.limits.max_child_size + 1)
                ctx.add_child(obj, data, "upx-unpacked", "decoded", {"unpacker": "upx"})
        except subprocess.TimeoutExpired:
            obj.errors.append("upx: timeout")
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"upx: {exc!r}")
        finally:
            for f in (src, out):
                try:
                    os.unlink(f)
                except OSError:
                    pass
        if ok:
            ctx.detect(obj, det(f"Heur:{area}.Packed.UPX", Confidence.LOW, base_score,
                                "UPX-packed executable (unpacked copy scanned)", ev))
            obj.meta.setdefault("unpack", {})["upx"] = "unpacked"
            return
        tampered = ("CantUnpackException" in msg or "checksum error" in msg or "corrupted" in msg
                    or "modified/hacked/protected" in msg or ("NotPackedException" in msg and strong))
        obj.meta.setdefault("unpack", {})["upx"] = msg[-200:]
        if tampered:
            ctx.detect(obj, det(f"Heur:{area}.Packed.UPX.Modified", Confidence.MEDIUM, 35,
                                "UPX-packed but the UPX headers were tampered with so it cannot be unpacked "
                                "(anti-unpacking trick common in malware)", ev + [msg[-160:]]))
        elif strong:
            ctx.detect(obj, det(f"Heur:{area}.Packed.UPX", Confidence.LOW, base_score, "UPX-packed executable", ev))
            if msg:
                obj.errors.append(f"upx: {msg[-200:]}")

    # ------------------------------------------------------------------ overlays
    def _pe_overlay(self, obj, ctx, pe, covered, pyi: bool) -> None:
        d = obj.data
        try:
            ov = pe.get_overlay_data_start_offset()
        except Exception:  # noqa: BLE001
            ov = None
        sec = security_dir(pe, len(d))
        if sec:
            pad = cert_padding(d, sec)
            if pad:
                off, ln = pad
                covered.append((off, ln))
                ctx.add_child(obj, d[off:off + ln], "cert-padding", "stream", {"offset": off})
        if ov is None:
            return
        after = b""
        if sec and sec[0] >= ov:
            body = d[ov:sec[0]]
            after = d[sec[0] + sec[1]:]
        else:
            body = d[ov:]
        blob = body + after if after else body
        if len(blob) < 64 or blob.count(0) == len(blob):
            return
        ft, fdesc = identify_bytes(blob[:65536])
        meta = {"offset": ov, "size": len(blob), "type": ft, "entropy": round(sampled_entropy(blob), 3)}
        obj.meta.setdefault("pe", {})["overlay"] = meta
        windows_app = pe.OPTIONAL_HEADER.Subsystem in (2, 3)
        if after and len(after) >= 64 and after.count(0) != len(after) and windows_app:
            ctx.detect(obj, det("Heur:PE.Overlay.AfterSignature", Confidence.MEDIUM, 15,
                                "Data appended after the Authenticode certificate table", [f"{len(after)} bytes"]))
        if ft in ("pe", "elf", "macho", "macho_fat", "dos"):
            ctx.detect(obj, det("Heur:PE.Overlay.Executable", Confidence.MEDIUM, 15,
                                "Overlay (data after the last section) is an executable", [fdesc]))
        if obj.meta.get("archive") or pyi:
            return  # SFX/NSIS handled by the archive analyzer; PyInstaller entries extracted separately
        covered.append((ov, len(body)))
        ctx.add_child(obj, blob, "overlay", "stream", {"overlay_offset": ov})

    def _generic_overlay(self, obj, ctx, area, covered, pyi: bool) -> None:
        d = obj.data
        ext = elf_extent(d) if obj.ftype == "elf" else macho_extent(d)
        if not ext or len(d) - ext < 512:
            return
        tail = d[ext:]
        if tail.count(0) == len(tail):
            return
        ft, fdesc = identify_bytes(tail[:65536])
        obj.meta.setdefault(obj.ftype if obj.ftype != "macho" else "macho", {})["overlay"] = {
            "offset": ext, "size": len(tail), "type": ft}
        if pyi or obj.meta.get("archive"):
            return
        ctx.detect(obj, det(f"Heur:{area}.Overlay", Confidence.LOW, 10 if area == "MachO" else 5,
                            "Data appended after the end of the image", [f"{len(tail)} bytes at {ext:#x} ({fdesc})"],
                            offset=ext))
        covered.append((ext, len(tail)))
        ctx.add_child(obj, tail, "overlay", "stream", {"overlay_offset": ext})

    # ------------------------------------------------------------------ PE resources
    def _pe_resources(self, obj, ctx, pe, covered) -> None:
        root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        if root is None:
            return
        d = obj.data
        added, total, seen = 0, 0, 0
        exe_std, exe_rc, blobs, extracted = [], [], [], []
        try:
            for t in root.entries[:512]:
                tid = t.id if t.name is None else None
                tname = str(t.name) if t.name is not None else RT_NAMES.get(t.id, str(t.id))
                if not hasattr(t, "directory"):
                    continue
                for n in t.directory.entries[:4096]:
                    nname = str(n.name) if n.name is not None else str(n.id)
                    if not hasattr(n, "directory"):
                        continue
                    for lang in n.directory.entries[:32]:
                        seen += 1
                        if seen > 20000 or added >= MAX_RSRC_CHILDREN:
                            raise StopIteration
                        de = getattr(lang, "data", None)
                        if de is None:
                            continue
                        rva, size = de.struct.OffsetToData, de.struct.Size
                        if size < 64:
                            continue
                        try:
                            off = pe.get_offset_from_rva(rva)
                        except Exception:  # noqa: BLE001
                            continue
                        if off is None or off >= len(d):
                            continue
                        size = min(size, len(d) - off)
                        head = d[off:off + min(size, 65536)]
                        ft, fdesc = identify_bytes(head)
                        label = f"rsrc/{tname}/{nname}"
                        is_exe = ft in EXECUTABLE_TYPES or ft == "dos"
                        interesting = is_exe or ft in ARCHIVE_TYPES or ft in DOCUMENT_TYPES or \
                            (ft in SCRIPTISH and (tid not in STANDARD_RT))
                        if tid in STANDARD_RT and not is_exe and ft not in ARCHIVE_TYPES:
                            continue
                        if not interesting:
                            if size >= 65536 and ft in ("binary", "unknown") and tid not in STANDARD_RT:
                                ent = sampled_entropy(d, off, off + size)
                                if ent >= 7.95:
                                    blobs.append(f"{label} ({size} B, H={ent:.2f})")
                            continue
                        if total + size > (256 << 20):
                            continue
                        c = ctx.add_child(obj, d[off:off + size], label, "stream",
                                          {"resource_type": tname, "resource_name": nname, "offset": off})
                        covered.append((off, size))
                        total += size
                        added += 1
                        extracted.append(f"{label} [{ft}]")
                        if is_exe:
                            (exe_std if tid in STANDARD_RT else exe_rc).append(f"{label} ({fdesc})")
                        del c
        except StopIteration:
            pass
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"pe resources: {exc!r}")
        if extracted:
            obj.meta.setdefault("pe", {})["extracted_resources"] = extracted[:64]
        if exe_std:
            ctx.detect(obj, det("Heur:PE.Resource.EmbeddedExecutable", Confidence.MEDIUM, 25,
                                "Executable hidden in an icon/bitmap/string/other standard resource", exe_std))
        elif exe_rc:
            ctx.detect(obj, det("Heur:PE.Resource.EmbeddedExecutable", Confidence.LOW, 10,
                                "Executable embedded in resources (dropper/installer)", exe_rc))
        if blobs:
            ctx.detect(obj, det("Heur:PE.Resource.EncryptedBlob", Confidence.LOW, 5,
                                "Large near-random resource of unknown type (encrypted payload?)", blobs))

    def _dotnet_resources(self, obj, ctx, pe, covered) -> None:
        rva, size = data_dir(pe, 14)
        if not rva or not size:
            return
        d = obj.data
        try:
            off = pe.get_offset_from_rva(rva)
            (_cb, _maj, _min, _md_rva, _md_sz, _flags, _ep, res_rva, res_size) = struct.unpack_from("<IHHIIIIII", d, off)
            if not res_rva or not res_size:
                return
            roff = pe.get_offset_from_rva(res_rva)
        except Exception:  # noqa: BLE001
            return
        if roff is None or roff >= len(d):
            return
        res_size = min(res_size, len(d) - roff)
        pos, idx, exe, kinds = 0, 0, [], {}
        while pos + 4 <= res_size and idx < 512:
            ln = struct.unpack_from("<I", d, roff + pos)[0]
            if ln == 0 or pos + 4 + ln > res_size:
                apos = (pos + 7) & ~7
                if apos != pos and apos + 4 <= res_size:
                    ln2 = struct.unpack_from("<I", d, roff + apos)[0]
                    if 0 < ln2 and apos + 4 + ln2 <= res_size:
                        pos = apos
                        continue
                break
            boff = roff + pos + 4
            head = d[boff:boff + min(ln, 65536)]
            ft, fdesc = identify_bytes(head)
            kinds[ft] = kinds.get(ft, 0) + 1
            if ft in EXECUTABLE_TYPES or ft == "dos" or ft in ARCHIVE_TYPES or ft in DOCUMENT_TYPES or ft in SCRIPTISH:
                ctx.add_child(obj, d[boff:boff + ln], f"dotnet-res/{idx}", "stream", {"offset": boff})
                covered.append((boff, ln))
                if ft in EXECUTABLE_TYPES or ft == "dos":
                    exe.append(f"resource #{idx} ({fdesc}, {ln} B)")
            pos += 4 + ln
            idx += 1
        obj.meta.setdefault("pe", {})["dotnet_resources"] = {"count": idx, "types": kinds}
        if exe:
            ctx.detect(obj, det("Heur:PE.DotNet.EmbeddedExecutable", Confidence.LOW, 10,
                                "Executable stored as a .NET manifest resource", exe))

    # ------------------------------------------------------------------ PyInstaller
    def _pyinstaller(self, obj: ScanObject, ctx: ScanContext, area: str) -> bool:
        d = obj.data
        pos = d.rfind(COOKIE)
        if pos < 0:
            return False
        try:
            if pos + 88 <= len(d):
                _m, pkglen, tocoff, toclen, pyvers, pylib = struct.unpack_from("!8sIIii64s", d, pos)
                clen = 88
                pylib_s = pylib.rstrip(b"\x00").decode("latin-1", "replace")
                if not pylib_s or "python" not in pylib_s.lower():
                    _m, pkglen, tocoff, toclen, pyvers = struct.unpack_from("!8siiii", d, pos)
                    clen, pylib_s = 24, ""
            else:
                _m, pkglen, tocoff, toclen, pyvers = struct.unpack_from("!8siiii", d, pos)
                clen, pylib_s = 24, ""
            start = pos + clen - pkglen
            if start < 0 or tocoff < 0 or toclen <= 0 or start + tocoff + toclen > len(d):
                obj.errors.append("pyinstaller: inconsistent cookie")
                return False
        except struct.error:
            return False
        major, minor = (pyvers // 100, pyvers % 100) if pyvers >= 100 else (pyvers // 10, pyvers % 10)
        info = {"python": f"{major}.{minor}", "pylib": pylib_s, "archive_offset": start, "entries": 0}
        obj.meta.setdefault("pyinstaller", info)
        toc = d[start + tocoff:start + tocoff + toclen]
        entries = []
        p = 0
        while p + 18 <= len(toc) and len(entries) < 20000:
            elen, eoff, dlen, ulen, cflag, tcode = struct.unpack_from("!IIIIBc", toc, p)
            if elen < 18 or p + elen > len(toc):
                break
            name = toc[p + 18:p + elen].rstrip(b"\x00").decode("utf-8", "replace")
            entries.append((name, eoff, dlen, ulen, cflag, tcode.decode("latin-1")))
            p += elen
        info["entries"] = len(entries)
        info["scripts"] = [e[0] for e in entries if e[5] == "s"][:40]
        pymagic = None
        pyz_entries = [e for e in entries if e[5] in ("z", "Z")]
        for name, eoff, dlen, ulen, cflag, tcode in pyz_entries[:4]:
            blob = d[start + eoff:start + eoff + dlen]
            if blob[:4] == b"PYZ\x00":
                pymagic = blob[4:8]
                self._pyz(obj, ctx, area, blob, name, info)
        if pymagic is None:
            m = PYC_MAGIC_FOR_VERSION.get(f"{major}.{minor}")
            pymagic = struct.pack("<H", m) + b"\r\n" if m else None
        n_added = 0
        for name, eoff, dlen, ulen, cflag, tcode in entries[:MAX_PYI_ENTRIES]:
            if tcode in ("z", "Z", "o", "d") or dlen <= 0:
                continue
            raw = d[start + eoff:start + eoff + dlen]
            if cflag == 1:
                try:
                    dec = zlib.decompressobj()
                    raw = dec.decompress(raw, ctx.limits.max_child_size)
                except zlib.error as exc:
                    obj.errors.append(f"pyinstaller: {name}: {exc}")
                    continue
            label = f"pyinstaller/{name}"
            if tcode in ("s", "m", "M") and raw[2:4] != b"\r\n":
                if pymagic is None:
                    continue
                raw = _pyc_header(pymagic) + raw
                label += ".pyc"
            meta = {"pyinstaller_type": tcode}
            if ctx.add_child(obj, raw, label, "member", meta) is not None:
                n_added += 1
        info["extracted"] = n_added
        return True

    def _pyz(self, obj, ctx, area, blob: bytes, name: str, info: dict) -> None:
        try:
            pymagic = blob[4:8]
            tocpos = struct.unpack_from("!i", blob, 8)[0]
            toc = _Marshal(blob, tocpos).read()
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"pyinstaller PYZ toc: {exc!r}")
            return
        items = list(toc.items()) if isinstance(toc, dict) else list(toc) if isinstance(toc, list) else []
        total = len(items)
        extracted, encrypted, tried = 0, 0, 0
        for it in items:
            if not (isinstance(it, (tuple, list)) and len(it) == 2):
                continue
            mod, val = it
            if not isinstance(mod, str) or not isinstance(val, (tuple, list)) or len(val) < 3:
                continue
            kind, pos, length = val[0], val[1], val[2]
            if not (isinstance(pos, int) and isinstance(length, int)) or pos < 0 or length <= 0:
                continue
            top = mod.split(".")[0]
            if top in _STDLIB or top in COMMON_PKGS or mod in COMMON_PKGS:
                continue
            if extracted >= MAX_PYZ_CHILDREN:
                break
            tried += 1
            raw = blob[pos:pos + length]
            try:
                code = zlib.decompressobj().decompress(raw, ctx.limits.max_child_size)
            except zlib.error:
                encrypted += 1
                continue
            is_data = kind == 2 and isinstance(kind, int) and not isinstance(kind, bool)
            data = code if is_data else _pyc_header(pymagic) + code
            if ctx.add_child(obj, data, f"pyz/{mod}" + ("" if is_data else ".pyc"), "member",
                             {"pyinstaller_type": "pyz"}) is not None:
                extracted += 1
        info["pyz"] = {"modules": total, "extracted": extracted, "encrypted": encrypted}
        if encrypted and encrypted >= max(1, tried // 2):
            ctx.detect(obj, det(f"Heur:{area}.PyInstaller.EncryptedPYZ", Confidence.LOW, 10,
                                "PyInstaller bundle with encrypted Python modules (hides code from analysis)",
                                [f"{encrypted}/{tried} modules not decompressible"]))

    # ------------------------------------------------------------------ carving
    def _carve(self, obj, ctx, area, covered, pyi: bool) -> None:
        d = obj.data
        lim = min(len(d), CARVE_LIMIT)
        ranges = list(covered)
        if pyi:
            info = obj.meta.get("pyinstaller") or {}
            st = info.get("archive_offset")
            if isinstance(st, int):
                ranges.append((st, len(d) - st))
        found: list[tuple[int, str, int]] = []

        def inside(p: int) -> bool:
            return any(a <= p < a + max(n, 1) for a, n in ranges)

        for pos, kind in _magic_hits(d, lim):
            if len(found) >= MAX_CARVED:
                break
            if inside(pos):
                continue
            ext = 0
            try:
                if kind == "pe" and pe_valid_at(d, pos):
                    ext = pe_extent(d, pos)
                elif kind == "elf" and elf_valid_at(d, pos) and _elf_type(d, pos) in (2, 3):
                    ext = elf_extent(d, pos)
                elif kind == "macho" and macho_valid_at(d, pos) and _macho_type(d, pos) in (2, 6, 8):
                    ext = macho_extent(d, pos)
                elif kind == "fat":
                    ext = fat_valid_at(d, pos)
            except (struct.error, ValueError, IndexError):
                ext = 0
            if ext >= MIN_CARVE:
                ext = min(ext, len(d) - pos)
                found.append((pos, kind, ext))
                ranges.append((pos, ext))
        if not found:
            return
        host_family = {"pe": "win", "elf": "lin", "macho": "mac"}[obj.ftype]
        cross = False
        ev = []
        for pos, kind, ext in sorted(found):
            fam = {"pe": "win", "elf": "lin", "macho": "mac", "fat": "mac"}[kind]
            cross |= fam != host_family
            ev.append(f"{kind}@{pos:#x} ({ext} B)")
            ctx.add_child(obj, d[pos:pos + ext], f"carved/{kind}@{pos:#x}", "stream", {"offset": pos, "carved": True})
        obj.meta.setdefault("carved", ev[:MAX_CARVED])
        if obj.ftype == "macho" and _apple_signed(d):
            return  # Apple platform binaries (e.g. PAR-packed perl tools) legitimately embed Mach-O files
        if d.find(DOTNET_BUNDLE_SIG) >= 0:
            obj.meta["dotnet_single_file_bundle"] = True
            return  # .NET single-file apphost: managed assemblies are stored inside by design
        for marker, what in RUNTIME_CONTAINERS:
            if d.find(marker, 0, lim) >= 0:
                obj.meta["runtime_container"] = what
                return  # runtimes that append/embed compiled programs or native add-ons
        ctx.detect(obj, det(f"Heur:{area}.EmbeddedExecutable", Confidence.LOW, 10 if cross else 5,
                            "Executable embedded inside the binary" + (" (different platform)" if cross else ""),
                            ev))

    def _b64_pe(self, obj, ctx, area) -> None:
        d = obj.data
        lim = min(len(d), 64 << 20)
        found = []
        for needle in B64_MZ:
            # plain ASCII base64 is handled by the generic embedded_blobs analyzer; here: UTF-16 and reversed
            p = d.find(b"\x00".join(bytes([c]) for c in needle), 0, lim)
            if p >= 0:
                found.append((p, True, False))
            rev = needle[::-1]
            p = d.find(rev, 0, lim)
            if p >= 0:
                found.append((p, False, True))
        n = 0
        for p, wide, rev in found[:8]:
            try:
                if rev:
                    # the reversed run ends at the needle; walk back to the start of the base64 run
                    w0 = max(0, p - (8 << 20))
                    mb = _B64_TAIL_RE.search(d, w0, p)
                    s = mb.start() if mb else p
                    m = B64_RE.match(d, s, min(len(d), p + len(needle) + 64))
                    run = m.group()[::-1] if m else b""
                elif wide:
                    m = B64W_RE.match(d, p, min(len(d), p + (64 << 20)))
                    run = m.group()[::2] if m else b""
                else:
                    m = B64_RE.match(d, p, min(len(d), p + (48 << 20)))
                    run = m.group() if m else b""
                run = run.replace(b"\r", b"").replace(b"\n", b"")
                run = run[:len(run) - len(run) % 4]
                raw = base64.b64decode(run, validate=False) if run else b""
            except Exception:  # noqa: BLE001
                continue
            if raw[:2] != b"MZ" or len(raw) < 512:
                continue
            ctx.add_child(obj, raw, f"b64-pe@{p:#x}", "decoded", {"offset": p, "reversed": rev})
            ctx.detect(obj, det(f"Heur:{area}.EmbeddedBase64PE" + (".Reversed" if rev else ""),
                                Confidence.MEDIUM if not rev else Confidence.HIGH, 30 if rev else 20,
                                "Base64-encoded Windows executable embedded in the binary"
                                + (" (reversed string)" if rev else ""), [f"offset {p:#x}, {len(raw)} bytes"]))
            n += 1
            if n >= 4:
                break

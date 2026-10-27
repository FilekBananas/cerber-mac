"""Content-based file type identification (magic bytes, never trusts the extension)."""
from __future__ import annotations

import re
import struct

from .core import ScanObject

# (offset, magic, type, description) – checked in order, first match wins
MAGICS: list[tuple[int, bytes, str, str]] = [
    (0, b"MZ", "pe", "DOS/Windows executable"),
    (0, b"\x7fELF", "elf", "ELF executable"),
    (0, b"\xfe\xed\xfa\xce", "macho", "Mach-O 32-bit (BE)"),
    (0, b"\xce\xfa\xed\xfe", "macho", "Mach-O 32-bit"),
    (0, b"\xfe\xed\xfa\xcf", "macho", "Mach-O 64-bit (BE)"),
    (0, b"\xcf\xfa\xed\xfe", "macho", "Mach-O 64-bit"),
    (0, b"\xbe\xba\xfe\xca", "macho_fat", "Mach-O universal (LE)"),
    (0, b"\xca\xfe\xba\xbf", "macho_fat", "Mach-O universal 64"),
    # 0xCAFEBABE is shared by Java class and Mach-O fat – resolved in _cafebabe()
    (0, b"dex\n", "dex", "Android DEX"),
    (0, b"PK\x03\x04", "zip", "ZIP archive"),
    (0, b"PK\x05\x06", "zip", "ZIP archive (empty)"),
    (0, b"PK\x07\x08", "zip", "ZIP archive (spanned)"),
    (0, b"Rar!\x1a\x07\x01\x00", "rar", "RAR5 archive"),
    (0, b"Rar!\x1a\x07\x00", "rar", "RAR4 archive"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
    (0, b"\x1f\x8b", "gzip", "gzip"),
    (0, b"BZh", "bzip2", "bzip2"),
    (0, b"\xfd7zXZ\x00", "xz", "xz"),
    (0, b"\x28\xb5\x2f\xfd", "zstd", "Zstandard"),
    (0, b"\x5d\x00\x00", "lzma", "LZMA (alone)"),
    (0, b"MSCF", "cab", "Microsoft Cabinet"),
    (0, b"ISc(", "cab", "InstallShield CAB"),
    (0, b"xar!", "xar", "XAR archive / macOS pkg"),
    (0, b"!<arch>\n", "ar", "ar archive / deb"),
    (0, b"070701", "cpio", "cpio (newc)"),
    (0, b"070707", "cpio", "cpio (odc)"),
    (0, b"\xc7\x71", "cpio", "cpio (binary)"),
    (0, b"%PDF", "pdf", "PDF document"),
    (0, b"{\\rt", "rtf", "RTF document"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2", "OLE2 compound document"),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", "lnk", "Windows shortcut"),
    (0, b"ITSF", "chm", "Compiled HTML Help"),
    (0, b"FWS", "swf", "Flash (uncompressed)"),
    (0, b"CWS", "swf", "Flash (zlib)"),
    (0, b"ZWS", "swf", "Flash (LZMA)"),
    (0, b"\x00asm", "wasm", "WebAssembly"),
    (0, b"SQLite format 3\x00", "sqlite", "SQLite database"),
    (0, b"bplist00", "bplist", "Binary property list"),
    (0, b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
    (0, b"\xff\xd8\xff", "jpeg", "JPEG image"),
    (0, b"GIF87a", "gif", "GIF image"),
    (0, b"GIF89a", "gif", "GIF image"),
    (0, b"BM", "bmp", "BMP image"),
    (0, b"II*\x00", "tiff", "TIFF image"),
    (0, b"MM\x00*", "tiff", "TIFF image"),
    (0, b"\x00\x00\x01\x00", "ico", "ICO image"),
    (0, b"8BPS", "psd", "Photoshop image"),
    (0, b"ID3", "mp3", "MP3 audio"),
    (0, b"OggS", "ogg", "Ogg"),
    (0, b"fLaC", "flac", "FLAC audio"),
    (0, b"\x1aE\xdf\xa3", "mkv", "Matroska/WebM"),
    (0, b"wOFF", "font", "WOFF font"),
    (0, b"wOF2", "font", "WOFF2 font"),
    (0, b"\x00\x01\x00\x00\x00", "font", "TrueType font"),
    (0, b"OTTO", "font", "OpenType font"),
    (0, b"-----BEGIN PGP", "pgp", "PGP armored"),
    (0, b"-----BEGIN ", "pem", "PEM"),
    (0, b"\x30\x82", "der", "DER / ASN.1"),
    (0, b"koly", "dmg", "DMG (trailer at start?)"),
    (0, b"\xed\xab\xee\xdb", "rpm", "RPM package"),
    (0, b"MSWIM\x00\x00\x00", "wim", "Windows imaging"),
    (0, b"vhdxfile", "vhd", "VHDX disk image"),
    (0, b"conectix", "vhd", "VHD disk image"),
    (0, b"KDMV", "vmdk", "VMware disk"),
    (0, b"QFI\xfb", "qcow", "QEMU disk"),
    (0, b"\x4c\x5a\x49\x50", "lzip", "lzip"),
    (0, b"\x04\x22\x4d\x18", "lz4", "LZ4"),
    (0, b"UPX!", "upx", "UPX stub"),
    (0, b"#!", "script", "Script with shebang"),
    (0, b"\xca\xfe\xd0\x0d", "java_pack", "Java pack200"),
    (0, b"\xac\xed\x00\x05", "java_ser", "Java serialized object"),
    (0, b"From ", "email", "mbox"),
    # machine-learning model formats (cerber/analyzers/models_ml.py)
    (0, b"GGUF", "gguf", "GGUF model (llama.cpp)"),
    (0, b"\x93NUMPY", "npy", "NumPy array (.npy)"),
    (0, b"\x89HDF\r\n\x1a\n", "hdf5", "HDF5 data (Keras/TF weights)"),
    (257, b"ustar", "tar", "tar archive"),
    (0x8001, b"CD001", "iso", "ISO 9660 image"),
    (0x8801, b"CD001", "iso", "ISO 9660 image"),
    (0x9001, b"CD001", "iso", "ISO 9660 image"),
    # HDF5 superblock after a user block
    (512, b"\x89HDF\r\n\x1a\n", "hdf5", "HDF5 data (user block)"),
    (1024, b"\x89HDF\r\n\x1a\n", "hdf5", "HDF5 data (user block)"),
    (2048, b"\x89HDF\r\n\x1a\n", "hdf5", "HDF5 data (user block)"),
]

# Python bytecode magic: 2 bytes version + b"\r\n"
_PYC_RE = re.compile(rb"^..\r\n", re.S)

_SCRIPT_HINTS: list[tuple[str, re.Pattern[bytes]]] = [
    ("html", re.compile(rb"(?i)^(<!doctype html|<html|<head|<body|<script|<iframe|<svg)")),
    ("hta", re.compile(rb"(?i)<hta:application")),
    ("plist", re.compile(rb"^(<\?xml[^>]{0,200}>[ \t\r\n]{0,64})?(<!DOCTYPE plist|<plist)")),
    ("xml", re.compile(rb"^<\?xml")),
    ("email", re.compile(rb"(?im)^(received|return-path|message-id|mime-version): ")),
    ("perl", re.compile(rb"(?m)^[ \t]*(use (?:strict|warnings|Socket|LWP::\w+|IO::Socket|File::\w+|Getopt::\w+|POSIX)\b[^\n]{0,80};|"
                        rb"my [\$@%]\w+[ \t]*=[^=]|sub \w+[ \t]*\{)")),
    ("powershell", re.compile(rb"(?i)(\$[a-z_]+[ \t]{0,8}=[^=]|invoke-expression|iex[ \t]{0,8}\(|new-object[ \t]+net\.webclient|\[system\.convert\]|-encodedcommand|\bparam[ \t]{0,8}\()")),
    ("vbs", re.compile(rb"(?im)^[ \t]*(dim |set [a-z_]+[ \t]*=[ \t]*createobject|wscript\.|sub [a-z_]+[ \t]*\(|on error resume next)")),
    ("javascript", re.compile(rb"(?i)(\bfunction[ \t]{0,8}\w{0,64}[ \t]{0,8}\(|\bvar[ \t]+\w{1,64}[ \t]{0,8}=|\blet[ \t]+\w{1,64}[ \t]{0,8}=|\bconst[ \t]+\w{1,64}[ \t]{0,8}=|\beval[ \t]{0,8}\(|=>[ \t]{0,8}\{|document\.|window\.)")),
    ("batch", re.compile(rb"(?im)^[ \t]*(@echo off|set /a|goto :|if exist|%comspec%|cmd(\.exe)? /c)")),
    ("applescript", re.compile(rb"(?i)(tell application|do shell script|display dialog|on run\b)")),
    ("python", re.compile(rb"(?m)^(import \w+|from [\w.]+ import|def \w+\(|class \w+[:(])")),
    ("php", re.compile(rb"(?i)<\?php")),
    ("shell", re.compile(rb"(?m)^(if \[|for \w+ in|export \w+=|\w+=\$\(|(sudo )?(curl|wget|chmod|launchctl) )")),
]

EXECUTABLE_TYPES = {"pe", "elf", "macho", "macho_fat", "dex", "java_class", "wasm", "pyc"}
ARCHIVE_TYPES = {"zip", "rar", "7z", "gzip", "bzip2", "xz", "zstd", "lzma", "cab", "xar", "ar",
                 "cpio", "tar", "iso", "dmg", "lz4", "lzip", "rpm", "wim", "vhd"}
DOCUMENT_TYPES = {"pdf", "rtf", "ole2", "ooxml", "odf", "chm"}
SCRIPT_TYPES = {"script", "shell", "python", "powershell", "vbs", "javascript", "batch", "applescript",
                "php", "html", "hta", "perl", "ruby", "text"}

SHEBANG_MAP = [
    (b"python", "python"), (b"bash", "shell"), (b"/sh", "shell"), (b"zsh", "shell"), (b"ksh", "shell"),
    (b"osascript", "applescript"), (b"perl", "perl"), (b"ruby", "ruby"), (b"node", "javascript"),
    (b"pwsh", "powershell"), (b"php", "php"),
]

# extension -> declared "family" used for extension/content mismatch checks
EXT_FAMILY = {
    "exe": "pe", "dll": "pe", "scr": "pe", "sys": "pe", "cpl": "pe", "ocx": "pe", "com": "pe", "efi": "pe",
    "pdf": "pdf", "doc": "ole2", "xls": "ole2", "ppt": "ole2", "msi": "ole2", "msg": "ole2",
    "docx": "ooxml", "docm": "ooxml", "xlsx": "ooxml", "xlsm": "ooxml", "pptx": "ooxml", "pptm": "ooxml",
    "jpg": "jpeg", "jpeg": "jpeg", "png": "png", "gif": "gif", "bmp": "bmp", "ico": "ico",
    "txt": "text", "csv": "text", "log": "text", "md": "text",
    "mp3": "mp3", "mp4": "mp4", "mov": "mp4", "zip": "zip", "rar": "rar", "7z": "7z",
    "gz": "gzip", "tgz": "gzip", "dmg": "dmg", "pkg": "xar", "iso": "iso", "rtf": "rtf",
}
# a benign-looking extension whose real content is one of these = masquerading
DANGEROUS_CONTENT = {"pe", "elf", "macho", "macho_fat", "script", "shell", "powershell", "vbs",
                     "javascript", "batch", "hta", "lnk", "applescript", "python"}


def _cafebabe(data: bytes) -> tuple[str, str]:
    # Java class: minor/major version, major >= 45 (0x2d). Mach-O fat: nfat_arch small (<= 20)
    if len(data) >= 8:
        n = struct.unpack(">I", data[4:8])[0]
        if n < 40:
            return "macho_fat", "Mach-O universal binary"
        return "java_class", "Java class file"
    return "unknown", ""


def _zip_subtype(data: bytes) -> tuple[str, str]:
    head = data[:65536]
    tail = data[-65536:] if len(data) > 65536 else b""
    blob = head + tail
    # ML model archives first: a torch archive folder named "*xl/" must not look like OOXML
    if b"data.pkl" in blob and (b"/version" in blob or b"/byteorder" in blob or b"/data/" in blob):
        return "zip", "PyTorch model archive"
    if b"config.json" in blob and (b"model.weights.h5" in blob or b"metadata.json" in blob) \
            and b"[Content_Types].xml" not in blob:
        return "zip", "Keras model archive"
    if b"[Content_Types].xml" in blob or b"word/" in blob or b"xl/" in blob or b"ppt/" in blob:
        if b"vbaProject.bin" in data:
            return "ooxml", "Office Open XML (with VBA project)"
        return "ooxml", "Office Open XML document"
    if b"mimetypeapplication/vnd.oasis.opendocument" in head:
        return "odf", "OpenDocument"
    if b"META-INF/MANIFEST.MF" in blob or b".class" in head:
        if b"AndroidManifest.xml" in blob or b"classes.dex" in blob:
            return "apk", "Android package"
        return "jar", "Java archive"
    if b"AndroidManifest.xml" in blob:
        return "apk", "Android package"
    if b"extension.vsixmanifest" in blob:
        return "vsix", "VS extension"
    if b"manifest.json" in head and (b"background" in blob or b"content_scripts" in blob):
        return "crx_zip", "Browser extension (zip)"
    return "zip", "ZIP archive"


def _is_text(data: bytes) -> bool:
    sample = data[:8192]
    if not sample:
        return False
    if b"\x00" in sample:
        # UTF-16LE text?
        if sample[:2] == b"\xff\xfe" or (len(sample) > 64 and sample[1::2].count(0) > len(sample) * 0.45):
            return True
        return False
    bad = sum(1 for b in sample if b < 9 or (13 < b < 32 and b != 27))
    return bad < len(sample) * 0.02


_SAFETENSORS_MAX_HEADER = 100 << 20     # the reference implementation refuses larger headers


def _is_safetensors(data: bytes) -> bool:
    """u64 LE header length + JSON object ('{"' or '{}'). Must run before MAGICS: the length bytes
    can collide with short magics (BM, II*, \\x00\\x01\\x00\\x00...)."""
    if len(data) < 10 or data[8:9] != b"{" or data[9:10] not in (b'"', b"}", b" "):
        return False
    n = struct.unpack_from("<Q", data, 0)[0]
    if not 2 <= n <= _SAFETENSORS_MAX_HEADER:
        return False
    if 8 + n <= len(data):
        last = data[8 + n - 1:8 + n]
        return last in (b"}", b" ")          # writers pad the header with spaces
    return True                              # truncated download: header continues past the end


class _LineCappedIO:
    """Minimal file object for pickletools argument readers: readline() never scans more than
    64 KiB (a stray 'c'/'S' opcode in binary data must not copy the rest of a huge buffer)."""
    __slots__ = ("_d", "_p", "_n")

    def __init__(self, data: bytes, pos: int = 0, end: int | None = None):
        self._d = data
        self._p = pos
        self._n = len(data) if end is None else min(end, len(data))

    def read(self, n: int = -1) -> bytes:
        p = self._p
        if n is None or n < 0:
            n = self._n - p
        e = min(self._n, p + n)
        self._p = e
        return self._d[p:e]

    def readline(self, limit: int = -1) -> bytes:
        p = self._p
        e = min(self._n, p + 65536)
        j = self._d.find(b"\n", p, e)
        e = j + 1 if j >= 0 else e
        self._p = e
        return self._d[p:e]

    def tell(self) -> int:
        return self._p

    def seek(self, pos: int) -> None:
        self._p = max(0, min(pos, self._n))


_P0_START = frozenset(b"(c]})NSVILFXUTKJMG")


def _is_pickle(data: bytes) -> bool:
    """Python pickle (any protocol): walk the first opcodes with pickletools' readers (no execution)."""
    b0 = data[0]
    if b0 == 0x80:
        if len(data) < 3 or not 2 <= data[1] <= 5:
            return False
        if data[1] >= 4 and data[2] == 0x95 and len(data) >= 11:
            return True                          # PROTO 4/5 + FRAME
    elif b0 not in _P0_START:
        return False
    import pickletools
    code2op = pickletools.code2op
    window = 4096
    f = _LineCappedIO(data, 0, window)
    n = 0
    try:
        while n < 64:
            code = f.read(1)
            op = code2op.get(code.decode("latin-1")) if code else None
            if op is None:
                break
            if op.arg is not None:
                op.arg.reader(f)
            n += 1
            if code == b".":
                # what follows a pickle: nothing, whitespace, or the next pickle (legacy torch / joblib);
                # "N.B. ..." is prose, not a pickled None
                nxt = data[f.tell():f.tell() + 1]
                return n >= 2 and (nxt in (b"", b"\n", b"\r", b" ", b"\t") or nxt[0] == 0x80
                                   or (n >= 3 and nxt[0] in _P0_START))
            if n >= 16:
                return True
    except Exception:  # noqa: BLE001 - malformed / cut by the probe window
        # an argument running past the probe window (big string/bytes) is fine for a protocol 2+ stream
        return b0 == 0x80 and n >= 1 and len(data) > window and f.tell() >= window
    return False


_ONNX_NEXT = frozenset(b"\x1a\x22\x28\x32\x3a")


def _is_onnx(data: bytes) -> bool:
    """ONNX ModelProto: ir_version varint (field 1) then a printable producer_name (field 2)."""
    if len(data) < 16 or data[0] != 0x08 or not 3 <= data[1] <= 15 or data[2] != 0x12:
        return False
    ln = data[3]
    if not 1 <= ln <= 64:
        return False
    name = data[4:4 + ln]
    if len(name) != ln or not all(0x20 <= c < 0x7f for c in name):
        return False
    return data[4 + ln:5 + ln] != b"" and data[4 + ln] in _ONNX_NEXT


def identify_bytes(data: bytes) -> tuple[str, str]:
    if not data:
        return "empty", "empty"
    if data[:4] == b"\xca\xfe\xba\xbe":
        return _cafebabe(data)
    if data[8:9] == b"{" and _is_safetensors(data):
        return "safetensors", "safetensors model weights"
    # DMG: "koly" trailer 512 bytes from the end (its data fork may start with gzip/bzip2/xz bytes)
    if len(data) >= 512 and data[-512:-508] == b"koly":
        return "dmg", "Apple disk image"
    for off, magic, t, desc in MAGICS:
        if data[off:off + len(magic)] == magic:
            if t == "zip":
                return _zip_subtype(data)
            if t == "pe":
                # a real PE has "PE\0\0" at e_lfanew; else just a DOS stub / MZ-prefixed junk
                if len(data) > 0x40:
                    lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
                    if lfanew < len(data) - 4 and data[lfanew:lfanew + 4] == b"PE\x00\x00":
                        return "pe", desc
                return "dos", "DOS/MZ executable"
            if t == "ole2":
                return "ole2", _ole_subtype(data)
            if t == "script":
                line = data[:128].split(b"\n", 1)[0]
                for needle, st in SHEBANG_MAP:
                    if needle in line:
                        return st, f"{st} script"
                return "script", "script (shebang)"
            if t == "lzma" and len(data) > 13:
                # LZMA-alone: props byte 0x5d and dict size plausible; weak – confirm size field
                usize = struct.unpack("<Q", data[5:13])[0]
                if not (usize == 0xFFFFFFFFFFFFFFFF or usize < (1 << 40)):
                    continue
            if t in ("bmp", "ico", "der", "font", "cpio") and len(data) < 32:
                continue
            return t, desc
    if (data[0] == 0x80 or data[0] in _P0_START) and _is_pickle(data):
        return "pickle", f"Python pickle (protocol {data[1] if data[0] == 0x80 else '0/1'})"
    if data[0] == 0x08 and _is_onnx(data):
        return "onnx", "ONNX model"
    # mp4/mov: ftyp box at 4
    if data[4:8] == b"ftyp":
        return "mp4", "MPEG-4 / QuickTime"
    if data[:4] == b"RIFF" and data[8:12] in (b"WEBP", b"WAVE", b"AVI "):
        return {b"WEBP": "webp", b"WAVE": "wav", b"AVI ": "avi"}[data[8:12]], "RIFF media"
    if len(data) >= 16 and _PYC_RE.match(data[:4]) and data[2:4] == b"\r\n" and data[1] in (0x0c, 0x0d, 0x0e):
        return "pyc", "Python bytecode"
    if _is_text(data):
        return _text_subtype(data)
    return "binary", "unknown binary data"


def _ole_subtype(data: bytes) -> str:
    blob = data[:1 << 20]
    for needle, desc in ((b"W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t", "Word 97-2003"),
                         (b"W\x00o\x00r\x00k\x00b\x00o\x00o\x00k", "Excel 97-2003"),
                         (b"P\x00o\x00w\x00e\x00r\x00P\x00o\x00i\x00n\x00t", "PowerPoint 97-2003"),
                         (b"\x84\x10\x0c\x00", "MSI installer"),
                         (b"_\x00_\x00s\x00u\x00b\x00s\x00t\x00g", "Outlook message")):
        if needle in blob:
            return f"OLE2 ({desc})"
    return "OLE2 compound document"


_ANCHORED = {"html", "plist", "xml"}


def _text_subtype(data: bytes) -> tuple[str, str]:
    sample = data[:16384]
    if sample[:2] == b"\xff\xfe":
        try:
            sample = sample.decode("utf-16-le", "ignore").encode("utf-8", "ignore")
        except Exception:
            pass
    head = sample.lstrip(b" \t\r\n\x0b\x0c\xef\xbb\xbf")[:4096]
    for t, rx in _SCRIPT_HINTS:
        if (rx.match(head) if t in _ANCHORED else rx.search(sample)):
            return t, f"{t} text"
    if head[:1] in (b"[", b"{") and re.search(rb'"[ \t]{0,8}:', sample[:4096]):
        return "json", "JSON"
    if re.match(rb"\[InternetShortcut\]", sample, re.I):
        return "url", "Internet shortcut"
    if re.match(rb"\[Desktop Entry\]", sample):
        return "desktop", "Desktop entry"
    return "text", "text"


def identify(obj: ScanObject) -> None:
    obj.ftype, obj.fdesc = identify_bytes(obj.data)


def is_executable(obj: ScanObject) -> bool:
    return obj.ftype in EXECUTABLE_TYPES


def is_textual(obj: ScanObject) -> bool:
    return obj.ftype in SCRIPT_TYPES or obj.ftype in ("json", "xml", "plist", "email", "url", "desktop")

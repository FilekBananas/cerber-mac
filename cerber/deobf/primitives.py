"""Low-level, bounded decoding primitives shared by every language decoder.

Nothing in this package ever executes, imports or unmarshals attacker data:
every transform is a pure byte/string manipulation with explicit size caps.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import lzma
import re
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field

from ..filetype import identify_bytes

MAX_DECODE_INPUT = 32 << 20        # never try to decode an encoded blob larger than this
MAX_INFLATE = 64 << 20             # decompression output cap


# --------------------------------------------------------------------------- budget

class Budget:
    """Shared bound for one deobfuscation run: wall time, produced bytes, produced layers."""

    def __init__(self, seconds: float = 3.0, max_bytes: int = 96 << 20, max_layers: int = 64,
                 max_depth: int = 6):
        self.deadline = time.monotonic() + seconds
        self.max_bytes = max_bytes
        self.max_layers = max_layers
        self.max_depth = max_depth
        self.used_bytes = 0
        self.layers = 0

    def expired(self) -> bool:
        return time.monotonic() > self.deadline or self.used_bytes > self.max_bytes \
            or self.layers >= self.max_layers

    def charge(self, n: int) -> bool:
        self.used_bytes += n
        return self.used_bytes <= self.max_bytes


@dataclass
class Layer:
    method: str                 # "ps-encodedcommand", "b64>gzip", ...
    data: bytes                 # decoded payload (text is utf-8 encoded)
    lang: str | None = None     # language hint for the child ("powershell", "shell", ...)
    kind: str = "text"          # text | binary
    ftype: str = ""             # identify_bytes() of the payload
    source: str = ""            # short excerpt of the encoded source (evidence)
    meta: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- text helpers

_PRINTABLE = frozenset(range(32, 127)) | {9, 10, 13}


def printable_ratio(data: bytes, sample: int = 8192) -> float:
    s = data[:sample]
    if not s:
        return 0.0
    # fast path via translate: delete printable bytes, count what is left
    rest = s.translate(None, bytes(_PRINTABLE))
    return 1.0 - len(rest) / len(s)


def is_utf16le_text(data: bytes) -> bool:
    if len(data) < 4:
        return False
    s = data[:4096]
    if s[:2] == b"\xff\xfe":
        return True
    odd = s[1::2]
    return odd.count(0) >= len(odd) * 0.9 and s[0::2].count(0) < len(odd) * 0.1


def bytes_to_text(data: bytes) -> str | None:
    """Decode bytes that are text (utf-8 / utf-16le / latin-1 fallback); None if binary."""
    if not data:
        return None
    if is_utf16le_text(data):
        try:
            t = data.decode("utf-16-le", "replace").lstrip("\ufeff")
        except Exception:
            return None
        return t if _text_ok(t) else None
    if data[:3] == b"\xef\xbb\xbf":
        data = data[3:]
    if printable_ratio(data) < 0.85:
        # utf-8 with many non-ascii letters (e.g. cyrillic comments) is still text
        try:
            t = data[:16384].decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not _text_ok(t):
            return None
    return data.decode("utf-8", "replace")


def _text_ok(t: str) -> bool:
    if not t:
        return False
    s = t[:8192]
    bad = sum(1 for ch in s if (ord(ch) < 32 and ch not in "\t\r\n") or ch == "\ufffd")
    if bad > len(s) * 0.05:
        return False
    letters = sum(1 for ch in s if ch.isalpha())
    return letters >= min(len(s) * 0.25, 3)


def excerpt(s: str | bytes, n: int = 120) -> str:
    if isinstance(s, bytes):
        s = s.decode("latin-1")
    s = s.replace("\r", " ").replace("\n", " ")
    return s if len(s) <= n else s[: n - 3] + "..."


# --------------------------------------------------------------------------- base64 / hex

_B64_STRIP = re.compile(r"[\s\\\"'`^+]")
_B64_OK = re.compile(r"^[A-Za-z0-9+/_\-]*={0,3}$")
_HEX_OK = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def b64decode_loose(s: str | bytes, strip: bool = True) -> bytes | None:
    """Decode std/urlsafe/padding-less base64. Returns None if it is not base64."""
    if isinstance(s, bytes):
        try:
            s = s.decode("ascii")
        except UnicodeDecodeError:
            return None
    if len(s) > MAX_DECODE_INPUT:
        return None
    if strip:
        s = re.sub(r"\s+", "", s)
    if not s or not _B64_OK.match(s):
        return None
    s = s.rstrip("=")
    if len(s) % 4 == 1:
        s = s[:-1]
    s += "=" * (-len(s) % 4)
    try:
        if "-" in s or "_" in s:
            return base64.urlsafe_b64decode(s)
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def looks_base64(s: str, min_len: int = 16) -> bool:
    if len(s) < min_len:
        return False
    t = s.strip().rstrip("=")
    if not t or not _B64_OK.match(t):
        return False
    # identifiers such as "ThisIsSomeName" are valid base64 alphabet but lack variety
    has_digit = any(c.isdigit() for c in t[:4096])
    has_upper = any(c.isupper() for c in t[:4096])
    has_lower = any(c.islower() for c in t[:4096])
    if len(set(t[:4096])) < 12:
        return False
    return (has_upper and has_lower) and (has_digit or len(t) >= 40 or s.endswith("="))


def hexdecode(s: str | bytes) -> bytes | None:
    if isinstance(s, bytes):
        s = s.decode("ascii", "ignore")
    s = re.sub(r"[\s,:]", "", s)
    if s[:2].lower() == "0x":
        s = s[2:]
    if len(s) > MAX_DECODE_INPUT or not _HEX_OK.match(s):
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        return None


def looks_hex(s: str, min_len: int = 32) -> bool:
    t = s.strip()
    return len(t) >= min_len and len(t) % 2 == 0 and bool(_HEX_OK.match(t)) \
        and any(c.isalpha() for c in t) and any(c.isdigit() for c in t)


# --------------------------------------------------------------------------- escapes

_ESC_RE = re.compile(r"\\(x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4}|[0-7]{1,3}|.)", re.S)
_SIMPLE_ESC = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "b": "\b", "f": "\f", "v": "\v",
               "a": "\a", "e": "\x1b"}


def unescape_backslash(s: str, octal: bool = True) -> str:
    """Resolve C/JS/Python style escapes: \\xNN \\uNNNN \\u{N} \\NNN \\n ..."""
    if "\\" not in s:
        return s

    def rep(m: re.Match) -> str:
        e = m.group(1)
        c = e[0]
        try:
            if c == "x":
                return chr(int(e[1:], 16))
            if c == "u":
                h = e[2:-1] if e[1:2] == "{" else e[1:]
                v = int(h, 16)
                return chr(v) if v <= 0x10FFFF else ""
            if c.isdigit() and octal and all(ch in "01234567" for ch in e):
                return chr(int(e, 8) & 0xFF) if len(e) > 1 or e != "0" else "\0"
        except ValueError:
            return m.group(0)
        return _SIMPLE_ESC.get(e, e)

    return _ESC_RE.sub(rep, s)


_PCT_U = re.compile(r"%u([0-9a-fA-F]{4})")


def js_unescape(s: str) -> str:
    """JavaScript unescape(): %XX and %uXXXX."""
    s = _PCT_U.sub(lambda m: chr(int(m.group(1), 16)), s)
    return urllib.parse.unquote(s, encoding="latin-1")


def url_unquote(s: str) -> str:
    try:
        return urllib.parse.unquote(s, errors="replace")
    except Exception:
        return s


def rot13(s: str) -> str:
    return codecs.encode(s, "rot13")


# --------------------------------------------------------------------------- compression

def inflate(data: bytes, wbits: int, limit: int = MAX_INFLATE) -> bytes | None:
    try:
        d = zlib.decompressobj(wbits)
        out = d.decompress(data, limit)
        if not out:
            return None
        return out
    except zlib.error:
        return None


def decompress_any(data: bytes, limit: int = MAX_INFLATE, raw_deflate: bool = False
                   ) -> tuple[str, bytes] | None:
    """Try gzip/zlib/bzip2/xz/lzma (and raw deflate when asked). Returns (method, data)."""
    if len(data) < 4:
        return None
    if data[:2] == b"\x1f\x8b":
        out = inflate(data, 16 + zlib.MAX_WBITS, limit)
        return ("gzip", out) if out else None
    if data[0] == 0x78 and data[1] in (0x01, 0x5E, 0x9C, 0xDA) and (data[0] * 256 + data[1]) % 31 == 0:
        out = inflate(data, zlib.MAX_WBITS, limit)
        if out:
            return "zlib", out
    if data[:3] == b"BZh":
        try:
            d = bz2.BZ2Decompressor()
            out = d.decompress(data, limit)
            return ("bzip2", out) if out else None
        except (OSError, ValueError, EOFError):
            return None
    if data[:6] == b"\xfd7zXZ\x00" or data[:3] == b"\x5d\x00\x00":
        try:
            d = lzma.LZMADecompressor()
            out = d.decompress(data, limit)
            return ("xz" if data[0] == 0xFD else "lzma", out) if out else None
        except (lzma.LZMAError, ValueError, EOFError):
            return None
    if raw_deflate:
        out = inflate(data, -15, limit)
        if out:
            return "deflate", out
    return None


# --------------------------------------------------------------------------- classification

TEXT_TYPES = {"script", "shell", "python", "powershell", "vbs", "javascript", "batch", "applescript",
              "php", "html", "hta", "perl", "ruby", "text", "json", "xml", "plist", "url", "desktop",
              "email"}
CODE_TYPES = {"script", "shell", "python", "powershell", "vbs", "javascript", "batch", "applescript",
              "php", "html", "hta", "perl", "ruby"}
BINARY_INTEREST = {"pe", "dos", "elf", "macho", "macho_fat", "dex", "java_class", "pyc", "wasm", "jar",
                   "apk", "zip", "rar", "7z", "cab", "xar", "ar", "cpio", "tar", "iso", "dmg", "rpm",
                   "wim", "vhd", "pdf", "rtf", "ole2", "ooxml", "odf", "chm", "lnk", "swf", "crx_zip",
                   "vsix", "bplist", "sqlite", "java_ser"}
COMPRESSED = {"gzip", "bzip2", "xz", "lzma", "zstd"}
# smallest decoded payload of an executable type worth handing back (headers alone are larger)
_MIN_BINARY = {t: 128 for t in ("pe", "dos", "elf", "macho", "macho_fat", "dex", "java_class", "pyc", "wasm")}

# keywords that make a decoded text "code" rather than random prose
_CODE_WORDS = re.compile(
    r"(?i)(\b(?:function|var|let|const|return|eval|exec|import|from|def|class|echo|curl|wget|chmod|"
    r"bash|sh|powershell|iex|invoke|new-object|createobject|wscript|shell|cmd|set|dim|sub|end|if|then|"
    r"else|fi|do|done|for|while|tell|osascript|python|perl|ruby|system|require|process|socket|http|"
    r"base64|decode|print|write-host|start-process|document|window|script|param|begin)\b|[;{}()$=|&<>])")


def looks_like_code(text: str) -> bool:
    s = text[:8192]
    if len(s.strip()) < 4:
        return False
    return len(_CODE_WORDS.findall(s)) >= max(2, len(s) // 400)


def classify(data: bytes, depth: int = 0, raw_deflate: bool = False
             ) -> tuple[str, str, bytes, str]:
    """Classify decoded bytes -> (kind, ftype, payload, chain).

    kind: "text" (payload is utf-8 text), "binary" (known interesting file type),
          "junk" (random bytes / nothing useful). Compressed data is unpacked.
    """
    if not data:
        return "junk", "empty", data, ""
    ft, _ = identify_bytes(data[:1 << 20])
    if ft in COMPRESSED or (raw_deflate and ft in ("binary", "unknown")) or \
            (data[:1] == b"\x78" and ft in ("binary", "unknown")):
        if depth < 4:
            r = decompress_any(data, raw_deflate=raw_deflate)
            if r:
                how, out = r
                kind, ft2, payload, chain = classify(out, depth + 1)
                if kind != "junk":
                    return kind, ft2, payload, how + (">" + chain if chain else "")
        if ft in COMPRESSED:
            return "binary", ft, data, ""
    if ft in BINARY_INTEREST:
        # a 20-byte "feedface..." / "MZ.." crypto test vector is not an executable
        if len(data) < _MIN_BINARY.get(ft, 22):
            return "junk", ft, data, ""
        return "binary", ft, data, ""
    if ft in TEXT_TYPES or ft in ("binary", "unknown"):
        t = bytes_to_text(data)
        if t is not None:
            enc = t.encode("utf-8", "replace")
            ft2, _ = identify_bytes(enc[:65536])
            return "text", ft2 if ft2 in TEXT_TYPES else "text", enc, "utf16" if is_utf16le_text(data) else ""
    return "junk", ft, data, ""


# --------------------------------------------------------------------------- numeric arrays

_NUM = re.compile(r"0x[0-9a-fA-F]{1,6}|&H[0-9a-fA-F]{1,6}|\d{1,7}")


def parse_int(tok: str) -> int | None:
    t = tok.strip()
    try:
        if t[:2].lower() == "0x":
            return int(t[2:], 16)
        if t[:2].lower() == "&h":
            return int(t[2:].rstrip("&"), 16)
        if t[:2].lower() == "0o":
            return int(t[2:], 8)
        return int(t)
    except ValueError:
        return None


def ints_to_text(nums: list[int]) -> str | None:
    if not nums or any(n < 0 or n > 0x10FFFF for n in nums):
        return None
    try:
        return "".join(chr(n) for n in nums)
    except (ValueError, OverflowError):
        return None


def ints_to_bytes(nums: list[int]) -> bytes | None:
    if not nums or any(n < 0 or n > 255 for n in nums):
        return None
    return bytes(nums)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    if len(key) == 1:
        k = key[0]
        return bytes(b ^ k for b in data) if len(data) < 4096 else \
            data.translate(bytes(i ^ k for i in range(256)))
    kl = len(key)
    return bytes(b ^ key[i % kl] for i, b in enumerate(data))

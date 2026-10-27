"""Tolerant PDF parser for malware analysis.

  * finds objects by scanning for "N G obj" (xref tables are not trusted), later revisions win
  * parses dictionaries/arrays/strings/names (#xx escapes are decoded and recorded)
  * extracts streams using /Length with an "endstream" fallback for lying lengths
  * decodes Flate/LZW/ASCIIHex/ASCII85/RunLength (+ PNG/TIFF predictors), chained filters
  * expands object streams (/ObjStm) and re-parses the objects they contain
  * standard security handler (RC4 40-128, AES-128, AES-256 R5/R6) with the empty user password
All loops are bounded; nothing here raises to the caller except ValueError from parse().
"""
from __future__ import annotations

import base64
import hashlib
import re
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any

MAX_OBJECTS = 250_000
MAX_DECODED = 64 << 20          # per stream
MAX_OBJ_TEXT = 1 << 20          # dictionary text parsed per object
MAX_DEPTH = 48


class Name(str):
    """PDF name (without the leading slash)."""


class PdfString(bytes):
    """PDF string (literal or hex)."""


@dataclass(frozen=True)
class Ref:
    num: int
    gen: int

    def __repr__(self) -> str:
        return f"{self.num} {self.gen} R"


@dataclass
class PdfObject:
    num: int
    gen: int
    value: Any
    offset: int
    raw_stream: bytes | None = None
    in_objstm: int | None = None       # number of the containing object stream
    _decoded: bytes | None = None
    decode_notes: list[str] = field(default_factory=list)

    @property
    def dict(self) -> dict:
        return self.value if isinstance(self.value, dict) else {}


# ============================================================================ lexer / parser

_WS = b"\x00\t\n\x0c\r "
_TOK = re.compile(rb"""(?x)
   (?P<ws>(?:[\x00\t\n\x0c\r ]+|%[^\r\n]*)+)
 | (?P<dstart><<) | (?P<dend>>>)
 | (?P<astart>\[) | (?P<aend>\])
 | (?P<name>/[^\x00\t\n\x0c\r ()<>\[\]{}/%]*)
 | (?P<num>[+-]?(?:\d+\.?\d*|\.\d+))(?![^\x00\t\n\x0c\r ()<>\[\]{}/%])
 | (?P<hex><[^<>]*>)
 | (?P<lstr>\()
 | (?P<kw>[^\x00\t\n\x0c\r ()<>\[\]{}/%]+)
 | (?P<other>.)
""", re.S)
_SPECIAL = re.compile(rb"[()\\]")
_ESC = re.compile(rb"\\(?:([nrtbf()\\])|([0-7]{1,3})|(\r\n|\r|\n)|(.))", re.S)
_ESC_MAP = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}
_HEXNAME = re.compile(rb"#([0-9A-Fa-f]{2})")
_NONHEX = re.compile(rb"[^0-9A-Fa-f]")

SUSPICIOUS_NAMES = {"JS", "JavaScript", "AA", "OpenAction", "Launch", "EmbeddedFile", "EmbeddedFiles", "URI",
                    "SubmitForm", "AcroForm", "XFA", "RichMedia", "ObjStm", "JBIG2Decode", "Encrypt", "GoToR",
                    "GoToE", "ImportData", "Filespec", "EF", "Names", "S", "Type", "Filter", "FlateDecode",
                    "ASCIIHexDecode", "ASCII85Decode", "Page", "Action", "Annot", "Colors", "Flash"}


def _unescape_literal(raw: bytes) -> bytes:
    if b"\\" not in raw:
        return raw

    def sub(m: re.Match) -> bytes:
        if m.group(1):
            return _ESC_MAP[m.group(1)]
        if m.group(2):
            return bytes([int(m.group(2), 8) & 0xFF])
        if m.group(3):
            return b""
        return m.group(4)
    return _ESC.sub(sub, raw)


class Lexer:
    def __init__(self, data: bytes, pos: int = 0, end: int | None = None, doc: "PDFDocument | None" = None):
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else end
        self.doc = doc

    def _tok(self):
        while self.pos < self.end:
            m = _TOK.match(self.data, self.pos, self.end)
            if not m:
                self.pos += 1
                continue
            kind = m.lastgroup
            self.pos = m.end()
            if kind == "ws":
                continue
            return kind, m
        return None, None

    def _literal(self) -> PdfString:
        depth = 1
        start = self.pos
        p = self.pos
        while depth and p < self.end:
            m = _SPECIAL.search(self.data, p, self.end)
            if not m:
                p = self.end
                break
            c = self.data[m.start()]
            if c == 0x5C:          # backslash: skip escaped char
                p = m.start() + 2
                continue
            depth += 1 if c == 0x28 else -1
            p = m.start() + 1
        raw = self.data[start:p - 1] if depth == 0 else self.data[start:p]
        self.pos = p
        return PdfString(_unescape_literal(raw))

    def _name(self, raw: bytes) -> Name:
        raw = raw[1:]
        if b"#" in raw:
            dec = _HEXNAME.sub(lambda m: bytes([int(m.group(1), 16)]), raw)
            name = Name(dec.decode("latin-1"))
            if self.doc is not None and dec != raw:
                self.doc.escaped_names.append((raw.decode("latin-1"), str(name)))
            return name
        return Name(raw.decode("latin-1"))

    def parse(self, depth: int = 0) -> Any:
        if depth > MAX_DEPTH:
            raise ValueError("nesting too deep")
        kind, m = self._tok()
        if kind is None:
            raise ValueError("unexpected end of data")
        if kind == "dstart":
            d: dict = {}
            while True:
                save = self.pos
                k2, m2 = self._tok()
                if k2 is None or k2 == "dend":
                    return d
                if k2 != "name":
                    if k2 == "aend":
                        continue
                    self.pos = save
                    try:
                        self.parse(depth + 1)       # skip junk value
                    except ValueError:
                        return d
                    continue
                key = self._name(m2.group())
                save = self.pos
                k3, _ = self._tok()
                if k3 == "dend":
                    d[str(key)] = None
                    return d
                self.pos = save
                d[str(key)] = self.parse(depth + 1)
        if kind == "astart":
            arr: list = []
            while True:
                save = self.pos
                k2, _ = self._tok()
                if k2 is None or k2 == "aend":
                    return arr
                if k2 == "dend":
                    return arr
                self.pos = save
                arr.append(self.parse(depth + 1))
                if len(arr) > 100_000:
                    return arr
        if kind == "name":
            return self._name(m.group())
        if kind == "num":
            txt = m.group()
            if b"." in txt:
                try:
                    return float(txt)
                except ValueError:
                    return 0.0
            val = int(txt)
            # object reference?  "num gen R"
            save = self.pos
            k2, m2 = self._tok()
            if k2 == "num" and b"." not in m2.group() and not m2.group().startswith((b"+", b"-")):
                k3, m3 = self._tok()
                if k3 == "kw" and m3.group() == b"R":
                    return Ref(val, int(m2.group()))
            self.pos = save
            return val
        if kind == "hex":
            h = _NONHEX.sub(b"", m.group()[1:-1])
            if len(h) & 1:
                h += b"0"
            return PdfString(bytes.fromhex(h.decode()))
        if kind == "lstr":
            return self._literal()
        if kind == "kw":
            w = m.group()
            if w == b"true":
                return True
            if w == b"false":
                return False
            if w == b"null":
                return None
            return ("kw", w.decode("latin-1"))
        if kind in ("dend", "aend"):
            return None
        return None


# ============================================================================ filters

def _flate(data: bytes, limit: int) -> tuple[bytes, str]:
    out = bytearray()
    note = ""
    for wbits in (15, -15):
        d = zlib.decompressobj(wbits)
        out = bytearray()
        try:
            pos = 0
            while pos < len(data) and len(out) < limit:
                chunk = data[pos:pos + 65536]
                pos += 65536
                out += d.decompress(chunk, limit - len(out))
                while d.unconsumed_tail and len(out) < limit:
                    out += d.decompress(d.unconsumed_tail, limit - len(out))
                if d.eof:
                    break
            if len(out) >= limit:
                note = "output truncated"
            return bytes(out), note
        except zlib.error as exc:
            note = f"flate error: {exc}"
            if out:
                return bytes(out), note + " (partial)"
            continue
    return bytes(out), note


def _lzw(data: bytes, limit: int, early: int = 1) -> bytes:
    out = bytearray()
    table = [bytes([i]) for i in range(256)] + [b"", b""]
    code_len = 9
    bitbuf = 0
    bits = 0
    prev = b""
    for byte in data:
        bitbuf = (bitbuf << 8) | byte
        bits += 8
        while bits >= code_len:
            bits -= code_len
            code = (bitbuf >> bits) & ((1 << code_len) - 1)
            bitbuf &= (1 << bits) - 1
            if code == 256:
                table = table[:258]
                code_len = 9
                prev = b""
                continue
            if code == 257:
                return bytes(out)
            if code < len(table):
                entry = table[code]
                if prev:
                    table.append(prev + entry[:1])
            elif prev:
                entry = prev + prev[:1]
                table.append(entry)
            else:
                return bytes(out)
            out += entry
            prev = entry
            if len(out) > limit:
                return bytes(out[:limit])
            n = len(table) + early
            if n >= 4096:
                code_len = 12
            elif n >= 2048:
                code_len = 12
            elif n >= 1024:
                code_len = 11
            elif n >= 512:
                code_len = 10
    return bytes(out)


def _a85(data: bytes) -> bytes:
    d = re.sub(rb"\s+", b"", data)
    if d.startswith(b"<~"):
        d = d[2:]
    end = d.find(b"~>")
    if end >= 0:
        d = d[:end]
    try:
        return base64.a85decode(d)
    except ValueError:
        # decode the valid prefix
        d = d[: len(d) - len(d) % 5]
        try:
            return base64.a85decode(d)
        except ValueError:
            return b""


def _ahx(data: bytes) -> tuple[bytes, bool]:
    end = data.find(b">")
    d = data[:end] if end >= 0 else data
    clean = re.sub(rb"[\x00\t\n\x0c\r ]", b"", d)
    h = _NONHEX.sub(b"", clean)
    junk = len(h) != len(clean)
    if len(h) & 1:
        h += b"0"
    return bytes.fromhex(h.decode()), junk


def _rle(data: bytes, limit: int) -> bytes:
    out = bytearray()
    i, n = 0, len(data)
    while i < n and len(out) < limit:
        L = data[i]
        if L == 128:
            break
        if L < 128:
            out += data[i + 1:i + 2 + L]
            i += L + 2
        else:
            if i + 1 < n:
                out += bytes([data[i + 1]]) * (257 - L)
            i += 2
    return bytes(out)


def _predictor(data: bytes, parms: dict) -> bytes:
    pred = parms.get("Predictor", 1) if isinstance(parms, dict) else 1
    if not isinstance(pred, int) or pred < 2:
        return data
    colors = parms.get("Colors", 1) or 1
    bpc = parms.get("BitsPerComponent", 8) or 8
    cols = parms.get("Columns", 1) or 1
    if not all(isinstance(v, int) and 0 < v < 1 << 20 for v in (colors, bpc, cols)):
        return data
    bpp = max(1, colors * bpc // 8)
    rowlen = (colors * bpc * cols + 7) // 8
    if pred == 2:
        if bpc != 8:
            return data
        out = bytearray(data)
        for r in range(0, len(out) - rowlen + 1, rowlen):
            for i in range(r + bpp, r + rowlen):
                out[i] = (out[i] + out[i - bpp]) & 0xFF
        return bytes(out)
    out = bytearray()
    prev = bytearray(rowlen)
    stride = rowlen + 1
    for r in range(0, len(data), stride):
        ft = data[r]
        row = bytearray(data[r + 1:r + stride])
        if len(row) < rowlen:
            row += bytes(rowlen - len(row))
        if ft == 1:
            for i in range(bpp, rowlen):
                row[i] = (row[i] + row[i - bpp]) & 0xFF
        elif ft == 2:
            row = bytearray((a + b) & 0xFF for a, b in zip(row, prev))
        elif ft == 3:
            for i in range(rowlen):
                left = row[i - bpp] if i >= bpp else 0
                row[i] = (row[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ft == 4:
            for i in range(rowlen):
                a = row[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                row[i] = (row[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 0xFF
        out += row
        prev = row
    return bytes(out)


FILTER_ALIASES = {"Fl": "FlateDecode", "AHx": "ASCIIHexDecode", "A85": "ASCII85Decode", "LZW": "LZWDecode",
                  "RL": "RunLengthDecode", "CCF": "CCITTFaxDecode", "DCT": "DCTDecode"}
IMAGE_FILTERS = {"DCTDecode", "JPXDecode", "JBIG2Decode", "CCITTFaxDecode"}


def decode_stream(raw: bytes, sdict: dict, limit: int = MAX_DECODED) -> tuple[bytes, list[str]]:
    notes: list[str] = []
    filters = sdict.get("Filter")
    parms = sdict.get("DecodeParms", sdict.get("DP"))
    if filters is None:
        return raw[:limit], notes
    if not isinstance(filters, list):
        filters = [filters]
    if not isinstance(parms, list):
        parms = [parms] * len(filters)
    data = raw
    if len(filters) >= 3:
        notes.append(f"{len(filters)} chained filters")
    for i, f in enumerate(filters[:8]):
        f = FILTER_ALIASES.get(str(f), str(f))
        p = parms[i] if i < len(parms) and isinstance(parms[i], dict) else {}
        if f == "FlateDecode":
            data, note = _flate(data, limit)
            if note:
                notes.append(note)
            data = _predictor(data, p) if len(data) <= (16 << 20) else data
        elif f == "LZWDecode":
            early = p.get("EarlyChange", 1) if isinstance(p.get("EarlyChange", 1), int) else 1
            data = _lzw(data[:8 << 20], limit, early)
            data = _predictor(data, p) if len(data) <= (16 << 20) else data
        elif f == "ASCIIHexDecode":
            data, junk = _ahx(data)
            if junk:
                notes.append("non-hex characters in ASCIIHex stream")
        elif f == "ASCII85Decode":
            data = _a85(data)
        elif f == "RunLengthDecode":
            data = _rle(data, limit)
        elif f == "Crypt":
            continue
        elif f in IMAGE_FILTERS:
            notes.append(f"stopped at image filter {f}")
            break
        else:
            notes.append(f"unsupported filter {f}")
            break
    return data[:limit], notes


# ============================================================================ encryption

_PAD = bytes.fromhex("28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A")


def _rc4(key: bytes, data: bytes) -> bytes:
    try:
        from Cryptodome.Cipher import ARC4  # type: ignore
        return ARC4.new(key).decrypt(data)
    except Exception:  # noqa: BLE001
        pass
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for k, b in enumerate(data[:4 << 20]):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[k] = b ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def _aes_cbc(key: bytes, iv: bytes, data: bytes, decrypt: bool = True) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    op = c.decryptor() if decrypt else c.encryptor()
    return op.update(data) + op.finalize()


def _unpad(data: bytes) -> bytes:
    if data and 1 <= data[-1] <= 16 and data.endswith(bytes([data[-1]]) * data[-1]):
        return data[:-data[-1]]
    return data


class SecurityHandler:
    def __init__(self, enc: dict, file_id: bytes):
        self.ok = False
        self.reason = ""
        self.v = enc.get("V", 0) if isinstance(enc.get("V", 0), int) else 0
        self.r = enc.get("R", 0) if isinstance(enc.get("R", 0), int) else 0
        self.aes = False
        self.identity_str = self.identity_stm = False
        self.key = b""
        o = bytes(enc.get("O") or b"")
        u = bytes(enc.get("U") or b"")
        p = enc.get("P", 0) if isinstance(enc.get("P", 0), int) else 0
        if str(enc.get("Filter", "Standard")) != "Standard":
            self.reason = f"unsupported security handler {enc.get('Filter')}"
            return
        cf = enc.get("CF") if isinstance(enc.get("CF"), dict) else {}
        stmf, strf = str(enc.get("StmF", "Identity")), str(enc.get("StrF", "Identity"))
        if self.v >= 4:
            self.identity_stm = stmf == "Identity"
            self.identity_str = strf == "Identity"
            cfm = ""
            for name in (stmf, strf):
                d = cf.get(name) if isinstance(cf, dict) else None
                if isinstance(d, dict):
                    cfm = str(d.get("CFM", cfm))
            self.aes = cfm in ("AESV2", "AESV3")
        try:
            if self.r >= 5:
                self._r6(enc, u)
            else:
                self._r4(enc, o, u, p, file_id)
        except Exception as exc:  # noqa: BLE001
            self.reason = f"key derivation failed: {exc}"

    def _r4(self, enc, o, u, p, file_id):
        length = enc.get("Length", 40) if isinstance(enc.get("Length", 40), int) else 40
        n = 5 if self.r == 2 else max(5, min(16, length // 8))
        h = hashlib.md5(_PAD + o[:32] + struct.pack("<i", p if p < 2**31 else p - 2**32) + file_id)
        if self.r >= 4 and enc.get("EncryptMetadata", True) is False:
            h.update(b"\xff\xff\xff\xff")
        key = h.digest()[:n]
        if self.r >= 3:
            for _ in range(50):
                key = hashlib.md5(key[:n]).digest()[:n]
        if self.r == 2:
            ok = _rc4(key, _PAD) == u[:32]
        else:
            x = hashlib.md5(_PAD + file_id).digest()
            for i in range(20):
                x = _rc4(bytes(b ^ i for b in key), x)
            ok = x[:16] == u[:16]
        if ok:
            self.key, self.ok = key, True
        else:
            self.reason = "document requires a user password"

    def _hash_2b(self, pw: bytes, salt: bytes, udata: bytes) -> bytes:
        k = hashlib.sha256(pw + salt + udata).digest()
        if self.r == 5:
            return k
        i = 0
        while True:
            k1 = (pw + k + udata) * 64
            e = _aes_cbc(k[:16], k[16:32], k1, decrypt=False)
            s = sum(e[:16]) % 3
            k = (hashlib.sha256, hashlib.sha384, hashlib.sha512)[s](e).digest()
            i += 1
            if i >= 64 and e[-1] <= i - 32:
                break
            if i > 2000:
                break
        return k[:32]

    def _r6(self, enc, u):
        ue = bytes(enc.get("UE") or b"")
        if len(u) < 48 or len(ue) < 32:
            self.reason = "malformed AES-256 encryption dictionary"
            return
        if self._hash_2b(b"", u[32:40], b"") != u[:32]:
            self.reason = "document requires a user password"
            return
        ik = self._hash_2b(b"", u[40:48], b"")
        self.key = _aes_cbc(ik, b"\x00" * 16, ue[:32])
        self.aes = True
        self.ok = True

    def _obj_key(self, num: int, gen: int) -> bytes:
        if self.r >= 5:
            return self.key
        k = self.key + struct.pack("<I", num)[:3] + struct.pack("<I", gen)[:2]
        if self.aes:
            k += b"sAlT"
        return hashlib.md5(k).digest()[:min(len(self.key) + 5, 16)]

    def decrypt(self, num: int, gen: int, data: bytes, is_string: bool = False) -> bytes:
        if not self.ok or not data:
            return data
        if (is_string and self.identity_str) or (not is_string and self.identity_stm):
            return data
        key = self._obj_key(num, gen)
        try:
            if self.aes:
                if len(data) < 32:
                    return data
                body = data[16:]
                body = body[: len(body) - len(body) % 16]
                return _unpad(_aes_cbc(key, data[:16], body))
            return _rc4(key, data)
        except Exception:  # noqa: BLE001
            return data


# ============================================================================ document

_OBJ_RE = re.compile(rb"(?<![0-9])(\d{1,10})[\x00\t\n\x0c\r ]+(\d{1,5})[\x00\t\n\x0c\r ]+obj(?![A-Za-z])")
_STREAM_RE = re.compile(rb"[\x00\t\n\x0c\r ]*(?:%[^\r\n]*[\r\n]+[\x00\t\n\x0c\r ]*)*stream(?:\r\n|\n|\r)?")
_ENDSTREAM_RE = re.compile(rb"(?:\r\n|\n|\r)?endstream")
_TRAILER_RE = re.compile(rb"trailer[\x00\t\n\x0c\r ]*<<")


@dataclass
class PDFDocument:
    data: bytes
    objects: dict[int, PdfObject] = field(default_factory=dict)
    trailers: list[dict] = field(default_factory=list)
    escaped_names: list[tuple[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    security: SecurityHandler | None = None
    encrypt_ref: Any = None
    objstm_count: int = 0
    objects_in_objstm: int = 0
    truncated: bool = False
    header_offset: int = 0
    version: str = ""

    # ---------------------------------------------------------------- access
    def resolve(self, v: Any, depth: int = 0) -> Any:
        while isinstance(v, Ref) and depth < 16:
            o = self.objects.get(v.num)
            v = o.value if o else None
            depth += 1
        return v

    def get_obj(self, v: Any) -> PdfObject | None:
        return self.objects.get(v.num) if isinstance(v, Ref) else None

    def string(self, v: Any, owner: PdfObject | None = None) -> bytes:
        """String value, decrypted with the owning object's key when needed."""
        if isinstance(v, Ref):
            owner = self.objects.get(v.num)
            v = owner.value if owner else None
        if isinstance(v, PdfString):
            if self.security and self.security.ok and owner is not None and owner.in_objstm is None:
                return self.security.decrypt(owner.num, owner.gen, bytes(v), is_string=True)
            return bytes(v)
        if isinstance(v, str):
            return v.encode("latin-1", "replace")
        return b""

    def stream(self, o: PdfObject | None, limit: int = MAX_DECODED) -> bytes:
        if o is None or o.raw_stream is None:
            return b""
        if o._decoded is not None:
            return o._decoded
        raw = o.raw_stream
        d = o.dict
        if self.security and self.security.ok and o.in_objstm is None and str(d.get("Type", "")) != "XRef":
            raw = self.security.decrypt(o.num, o.gen, raw)
        resolved = dict(d)
        for k in ("Filter", "DecodeParms", "DP"):
            if isinstance(resolved.get(k), Ref):
                resolved[k] = self.resolve(resolved[k])
        if isinstance(resolved.get("DecodeParms"), list):
            resolved["DecodeParms"] = [self.resolve(x) for x in resolved["DecodeParms"]]
        try:
            out, notes = decode_stream(raw, resolved, limit)
        except Exception as exc:  # noqa: BLE001
            out, notes = raw, [f"decode error: {exc!r}"]
        o.decode_notes = notes
        o._decoded = out
        return out

    def iter_dicts(self):
        for o in self.objects.values():
            if isinstance(o.value, dict):
                yield o, o.value

    # ---------------------------------------------------------------- parsing
    def _length(self, v: Any) -> int | None:
        if isinstance(v, int):
            return v
        if isinstance(v, Ref):
            o = self.objects.get(v.num)
            if o is not None and isinstance(o.value, int):
                return o.value
            # the length object may come later in the file: look it up directly
            m = re.search(rb"(?<![0-9])%d[\x00\t\n\x0c\r ]+%d[\x00\t\n\x0c\r ]+obj[\x00\t\n\x0c\r ]*(\d+)" % (v.num, v.gen),
                          self.data)
            if m:
                return int(m.group(1))
        return None

    def _parse_at(self, num: int, gen: int, pos: int, end: int, in_objstm: int | None = None) -> tuple[PdfObject, int]:
        lx = Lexer(self.data, pos, min(end, pos + MAX_OBJ_TEXT), self)
        try:
            val = lx.parse()
        except (ValueError, RecursionError) as exc:
            val = None
            self.errors.append(f"object {num} {gen}: {exc}")
        obj = PdfObject(num, gen, val, pos, in_objstm=in_objstm)
        after = lx.pos
        if isinstance(val, dict) and in_objstm is None:
            m = _STREAM_RE.match(self.data, after)
            if m and self.data[m.start():m.end()].strip().endswith(b"stream"):
                start = m.end()
                length = self._length(val.get("Length"))
                stop = None
                if length is not None and 0 <= length <= len(self.data) - start:
                    if _ENDSTREAM_RE.match(self.data, start + length) or \
                            self.data[start + length:start + length + 32].lstrip().startswith(b"endstream"):
                        stop = start + length
                if stop is None:
                    e = self.data.find(b"endstream", start)
                    stop = e if e >= 0 else len(self.data)
                    if stop > start and self.data[stop - 1:stop] == b"\n":
                        stop -= 1
                        if self.data[stop - 1:stop] == b"\r":
                            stop -= 1
                    elif stop > start and self.data[stop - 1:stop] == b"\r":
                        stop -= 1
                    if length is not None:
                        obj.decode_notes.append(f"/Length {length} does not match stream size {stop - start}")
                obj.raw_stream = self.data[start:stop]
                after = stop
        return obj, after

    def parse(self) -> None:
        data = self.data
        hdr = data.find(b"%PDF-", 0, 1024)
        self.header_offset = hdr
        if hdr >= 0:
            self.version = data[hdr + 5:hdr + 8].decode("latin-1", "replace")
        skip_until = 0
        count = 0
        for m in _OBJ_RE.finditer(data):
            if m.start() < skip_until:
                continue
            count += 1
            if count > MAX_OBJECTS:
                self.truncated = True
                self.errors.append(f"more than {MAX_OBJECTS} objects, rest ignored")
                break
            num, gen = int(m.group(1)), int(m.group(2))
            obj, after = self._parse_at(num, gen, m.end(), len(data))
            skip_until = after if obj.raw_stream is not None else m.end()
            self.objects[num] = obj
        for m in _TRAILER_RE.finditer(data):
            lx = Lexer(data, m.end() - 2, min(len(data), m.end() + 65536), self)
            try:
                t = lx.parse()
            except (ValueError, RecursionError):
                continue
            if isinstance(t, dict):
                self.trailers.append(t)
        for o, d in list(self.iter_dicts()):
            if str(d.get("Type", "")) == "XRef":
                self.trailers.append(d)
        self._setup_security()
        self._expand_objstm()

    def _setup_security(self) -> None:
        enc_ref, file_id = None, b""
        for t in self.trailers:
            if t.get("Encrypt") is not None:
                enc_ref = t.get("Encrypt")
            idv = t.get("ID")
            if isinstance(idv, list) and idv and isinstance(idv[0], (bytes, PdfString)):
                file_id = bytes(idv[0])
        if enc_ref is None:
            return
        self.encrypt_ref = enc_ref
        enc = self.resolve(enc_ref)
        if isinstance(enc, dict):
            self.security = SecurityHandler(enc, file_id)

    def _expand_objstm(self) -> None:
        for o in list(self.objects.values()):
            d = o.dict
            if str(d.get("Type", "")) != "ObjStm" or o.raw_stream is None:
                continue
            self.objstm_count += 1
            n, first = d.get("N"), d.get("First")
            if not isinstance(n, int) or not isinstance(first, int) or n <= 0 or first < 0:
                continue
            content = self.stream(o)
            if not content:
                continue
            head = Lexer(content, 0, min(first, len(content)))
            pairs = []
            try:
                for _ in range(min(n, 100_000)):
                    a = head.parse()
                    b = head.parse()
                    if not isinstance(a, int) or not isinstance(b, int):
                        break
                    pairs.append((a, b))
            except ValueError:
                pass
            sub = PDFDocument(content)
            sub.escaped_names = self.escaped_names
            for i, (num, off) in enumerate(pairs):
                start = first + off
                end = first + pairs[i + 1][1] if i + 1 < len(pairs) else len(content)
                if not (0 <= start < len(content)):
                    continue
                lx = Lexer(content, start, max(start, min(end, len(content))), self)
                try:
                    val = lx.parse()
                except (ValueError, RecursionError):
                    continue
                existing = self.objects.get(num)
                # an object stream entry is superseded by a later plain object definition only
                if existing is None or existing.in_objstm is not None or existing.offset < o.offset:
                    self.objects[num] = PdfObject(num, 0, val, start, in_objstm=o.num)
                    self.objects_in_objstm += 1


def parse(data: bytes) -> PDFDocument:
    doc = PDFDocument(data)
    doc.parse()
    return doc


# ============================================================================ JavaScript heuristics

JS_EXPLOITS = [
    (re.compile(r"util\.printf\s*\(", re.I), "util.printf (CVE-2008-2992)"),
    (re.compile(r"Collab\.collectEmailInfo", re.I), "Collab.collectEmailInfo (CVE-2007-5659)"),
    (re.compile(r"Collab\.getIcon", re.I), "Collab.getIcon (CVE-2009-0927)"),
    (re.compile(r"media\.newPlayer", re.I), "media.newPlayer (CVE-2009-4324)"),
    (re.compile(r"spell\.customDictionaryOpen", re.I), "spell.customDictionaryOpen (CVE-2009-1493)"),
    (re.compile(r"\.printSeps\s*\(", re.I), "printSeps (CVE-2010-4091)"),
    (re.compile(r"getAnnots\s*\(\s*\{?[^)]{0,80}\)\s*;?[\s\S]{0,400}?\.subject", re.I), "getAnnots payload staging"),
    (re.compile(r"app\.removeToolButton", re.I), "app.removeToolButton (CVE-2013-3346)"),
    (re.compile(r"\.syncAnnotScan\s*\(", re.I), "syncAnnotScan payload staging"),
]
JS_SPRAY = [
    re.compile(r"%u0c0c%u0c0c|%u0a0a%u0a0a|%u9090%u9090|%u0d0d%u0d0d", re.I),
    re.compile(r"\\x0c\\x0c\\x0c\\x0c|0x0c0c0c0c|\\u0c0c\\u0c0c", re.I),
    re.compile(r"while\s*\(\s*\w+\.length\s*<\s*0x[0-9a-f]{4,}|while\s*\(\s*\w+\.length\s*<\s*\d{5,}", re.I),
]
JS_OBFUSCATION = [
    (re.compile(r"\beval\s*\(", re.I), "eval"),
    (re.compile(r"\bunescape\s*\(", re.I), "unescape"),
    (re.compile(r"String\.fromCharCode", re.I), "String.fromCharCode"),
    (re.compile(r"\.replace\s*\(\s*/[^/]{1,40}/g\s*,\s*[\"']{2}\s*\)", re.I), "junk-stripping replace"),
    (re.compile(r"\bapp\.setTimeOut\s*\(", re.I), "app.setTimeOut"),
    (re.compile(r"\bthis\.info\.\w+|\bthis\.getField\s*\(", re.I), "code fetched from document fields"),
]
JS_ACTIONS = [
    (re.compile(r"exportDataObject\s*\([^)]*nLaunch\s*:\s*[12]", re.I | re.S), "exportDataObject with nLaunch (runs embedded file)"),
    (re.compile(r"\bapp\.launchURL\s*\(", re.I), "app.launchURL"),
    (re.compile(r"\bthis\.submitForm\s*\(", re.I), "submitForm"),
    (re.compile(r"\bapp\.openDoc\s*\(", re.I), "app.openDoc"),
    (re.compile(r"\bSOAP\.(connect|request)\b", re.I), "SOAP network access"),
    (re.compile(r"\bNet\.HTTP\.request\b", re.I), "Net.HTTP.request"),
]


def analyze_js(code: str) -> dict[str, list[str]]:
    res: dict[str, list[str]] = {"exploit": [], "spray": [], "obfuscation": [], "actions": []}
    for rx, desc in JS_EXPLOITS:
        if rx.search(code):
            res["exploit"].append(desc)
    for rx in JS_SPRAY:
        m = rx.search(code)
        if m:
            res["spray"].append(m.group()[:60])
    pct_u = code.count("%u")
    if pct_u >= 200:
        res["spray"].append(f"{pct_u} %u escapes")
    for rx, desc in JS_OBFUSCATION:
        if rx.search(code):
            res["obfuscation"].append(desc)
    longest = max((len(t) for t in re.findall(r"[^\s;,(){}\[\]]{2000,}", code[:4 << 20])), default=0)
    if longest:
        res["obfuscation"].append(f"{longest}-char token")
    for rx, desc in JS_ACTIONS:
        if rx.search(code):
            res["actions"].append(desc)
    return res

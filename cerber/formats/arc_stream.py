"""Incremental, bounded decompressors (gzip/zlib/bzip2/xz/lzma/zstd/lz4/lzip/pbzx).

Every decompressor is wrapped in an *adapter* exposing step() -> bytes | None; DecompStream turns an
adapter into a file-like object with a hard output cap, a wall-clock/total budget and a decompression
bomb guard (output/input ratio).  Nothing is ever expanded without limits.
"""
from __future__ import annotations

import bz2
import io
import lzma
import struct
import zlib
from typing import Callable

from .arc_common import BOMB_READ_CAP, Budget, BudgetExceeded

IN_CHUNK = 64 << 10
OUT_CHUNK = 1 << 20

XZ_MAGIC = b"\xfd7zXZ\x00"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


# ---------------------------------------------------------------------------
# adapters
# ---------------------------------------------------------------------------
class _Base:
    consumed_bytes = 0
    error: str | None = None
    done = False

    def step(self) -> bytes | None:  # pragma: no cover - interface
        raise NotImplementedError

    def consumed(self) -> int:
        return self.consumed_bytes

    def trailing(self) -> bytes:
        """Bytes after the end of the compressed stream(s), when the stream ended cleanly."""
        return b""


class ZlibAdapter(_Base):
    """zlib / gzip (with concatenated gzip members) / raw deflate."""

    def __init__(self, data: bytes, start: int = 0, wbits: int = 31, multi: bool = True):
        self.view = memoryview(data)
        self.n = len(data)
        self.pos = start
        self.wbits = wbits
        self.multi = multi and wbits in (31, 47)
        self.d = zlib.decompressobj(wbits)
        self.finished_clean = False
        self.truncated_input = False

    def consumed(self) -> int:
        return self.pos - len(self.d.unconsumed_tail)

    def step(self) -> bytes | None:
        while True:
            if self.done:
                return None
            if self.d.unconsumed_tail:
                data = self.d.unconsumed_tail
            elif self.pos < self.n:
                data = bytes(self.view[self.pos:self.pos + IN_CHUNK])
                self.pos += len(data)
            else:
                self.done = True
                self.truncated_input = not self.d.eof
                return None
            try:
                out = self.d.decompress(data, OUT_CHUNK)
            except zlib.error as exc:
                self.error = f"zlib: {exc}"
                self.done = True
                return None
            if self.d.eof:
                self.pos -= len(self.d.unused_data)
                self.finished_clean = True
                if self.multi and self.view[self.pos:self.pos + 2].tobytes() == b"\x1f\x8b":
                    self.d = zlib.decompressobj(self.wbits)
                    self.finished_clean = False
                else:
                    self.done = True
            if out:
                return out

    def trailing(self) -> bytes:
        if self.finished_clean:
            return bytes(self.view[self.pos:])
        return b""


class CodecAdapter(_Base):
    """bz2 / lzma / zstd style decompressors (decompress(data, max_length), needs_input, eof, unused_data)."""

    def __init__(self, data: bytes, factory: Callable[[], object], start: int = 0,
                 next_magic: bytes | None = None, header_skip: int = 0,
                 member_trailer: int = 0, member_factory: Callable[[bytes], tuple[object, int]] | None = None):
        self.view = memoryview(data)
        self.n = len(data)
        self.pos = start
        self.factory = factory
        self.next_magic = next_magic
        self.member_trailer = member_trailer
        self.member_factory = member_factory
        self.finished_clean = False
        self.truncated_input = False
        self._new_member()

    def consumed(self) -> int:
        return self.pos

    def _new_member(self) -> None:
        if self.member_factory is not None:
            try:
                self.d, hdr = self.member_factory(self.view[self.pos:self.pos + 16].tobytes())
            except Exception as exc:  # noqa: BLE001
                self.error = f"header: {exc}"
                self.done = True
                return
            self.pos += hdr
        else:
            self.d = self.factory()
        self.finished_clean = False

    def step(self) -> bytes | None:
        while True:
            if self.done:
                return None
            if self.d.eof:
                # (only reached via the eof branch below)
                self.done = True
                return None
            if self.d.needs_input:
                if self.pos >= self.n:
                    self.done = True
                    self.truncated_input = True
                    return None
                data = bytes(self.view[self.pos:self.pos + IN_CHUNK])
                self.pos += len(data)
            else:
                data = b""
            try:
                out = self.d.decompress(data, OUT_CHUNK)
            except EOFError:
                self.done = True
                return None
            except Exception as exc:  # noqa: BLE001  (OSError, lzma.LZMAError, zstd errors...)
                self.error = f"{type(self.d).__name__}: {exc}"
                self.done = True
                return None
            if self.d.eof:
                self.pos -= len(self.d.unused_data)
                self.pos = min(self.n, self.pos + self.member_trailer)
                self.finished_clean = True
                nm = self.next_magic
                if nm and self.view[self.pos:self.pos + len(nm)].tobytes() == nm:
                    self._new_member()
                # else: leave d.eof set, next loop iteration ends
                if self.d.eof:
                    self.done = True
            if out:
                return out

    def trailing(self) -> bytes:
        if self.finished_clean and self.pos < self.n:
            return bytes(self.view[self.pos:])
        return b""


class ReaderAdapter(_Base):
    """Wraps a file-like decompressor reader (e.g. zstandard's stream_reader)."""

    def __init__(self, reader, bio: io.BytesIO | None = None):
        self.reader = reader
        self.bio = bio

    def consumed(self) -> int:
        return self.bio.tell() if self.bio is not None else 0

    def step(self) -> bytes | None:
        if self.done:
            return None
        try:
            b = self.reader.read(OUT_CHUNK)
        except Exception as exc:  # noqa: BLE001
            self.error = f"{type(exc).__name__}: {exc}"
            self.done = True
            return None
        if not b:
            self.done = True
            return None
        return b


# ---- LZ4 (pure python fallback; used only when the lz4 package is missing) ----
def _lz4_block(src: bytes, work: bytearray, cap: int) -> None:
    i = 0
    n = len(src)
    while i < n:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        work += src[i:i + lit]
        i += lit
        if i >= n:
            break
        off = src[i] | (src[i + 1] << 8)
        i += 2
        if off == 0:
            raise ValueError("lz4: zero offset")
        ml = token & 15
        if ml == 15:
            while True:
                b = src[i]
                i += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        start = len(work) - off
        if start < 0:
            raise ValueError("lz4: bad offset")
        if off >= ml:
            work += work[start:start + ml]
        else:
            pat = bytes(work[start:])
            work += (pat * (ml // off + 1))[:ml]
        if len(work) > cap:
            raise ValueError("lz4: output cap")


class Lz4Adapter(_Base):
    MAGIC = b"\x04\x22\x4d\x18"

    def __init__(self, data: bytes, start: int = 0):
        self.data = data
        self.pos = start
        self.n = len(data)
        self.hist = bytearray()
        self.in_frame = False
        self.block_checksum = False
        self.content_checksum = False
        self.finished_clean = False

    def consumed(self) -> int:
        return self.pos

    def step(self) -> bytes | None:
        d = self.data
        while True:
            if self.done:
                return None
            try:
                if not self.in_frame:
                    if self.pos + 7 > self.n:
                        self.done = True
                        return None
                    magic = d[self.pos:self.pos + 4]
                    if magic == self.MAGIC:
                        flg = d[self.pos + 4]
                        if flg >> 6 != 1:
                            raise ValueError("lz4: bad frame version")
                        self.block_checksum = bool(flg & 0x10)
                        self.content_checksum = bool(flg & 0x04)
                        hlen = 4 + 2 + (8 if flg & 0x08 else 0) + (4 if flg & 0x01 else 0) + 1
                        self.pos += hlen
                        self.in_frame = True
                        self.hist = bytearray()
                    elif 0x184D2A50 <= struct.unpack("<I", magic)[0] <= 0x184D2A5F:
                        size = struct.unpack("<I", d[self.pos + 4:self.pos + 8])[0]
                        self.pos += 8 + size
                    else:
                        self.done = True
                        self.finished_clean = True
                        return None
                    continue
                if self.pos + 4 > self.n:
                    self.done = True
                    return None
                bsize = struct.unpack("<I", d[self.pos:self.pos + 4])[0]
                self.pos += 4
                if bsize == 0:
                    if self.content_checksum:
                        self.pos += 4
                    self.in_frame = False
                    continue
                raw = bool(bsize & 0x80000000)
                bsize &= 0x7FFFFFFF
                if bsize > (4 << 20) or self.pos + bsize > self.n:
                    raise ValueError("lz4: bad block size")
                blk = d[self.pos:self.pos + bsize]
                self.pos += bsize
                if self.block_checksum:
                    self.pos += 4
                if raw:
                    out = bytes(blk)
                    self.hist = (self.hist + blk)[-65536:]
                else:
                    work = bytearray(self.hist)
                    base = len(work)
                    _lz4_block(blk, work, base + (8 << 20))
                    out = bytes(work[base:])
                    self.hist = work[-65536:]
                if out:
                    return out
            except (ValueError, IndexError, struct.error) as exc:
                self.error = str(exc)
                self.done = True
                return None

    def trailing(self) -> bytes:
        return b""


class PbzxAdapter(_Base):
    """Apple pbzx: 'pbzx' + flags + [flags, length, xz chunk]*"""

    def __init__(self, data: bytes, start: int = 0):
        self.data = data
        self.n = len(data)
        self.pos = start + 12
        self.cur = None
        self.cur_input = b""
        self.finished_clean = False
        if self.n < start + 12 or data[start:start + 4] != b"pbzx":
            self.done = True
            self.error = "not pbzx"

    def consumed(self) -> int:
        return self.pos

    def step(self) -> bytes | None:
        while True:
            if self.done:
                return None
            if self.cur is not None:
                try:
                    out = self.cur.decompress(self.cur_input, OUT_CHUNK)
                except lzma.LZMAError as exc:
                    self.error = f"pbzx chunk: {exc}"
                    self.done = True
                    return None
                self.cur_input = b""
                if self.cur.eof or (not out and self.cur.needs_input):
                    self.cur = None
                if out:
                    return out
                continue
            if self.pos + 16 > self.n:
                self.done = True
                self.finished_clean = True
                return None
            _flags, length = struct.unpack(">QQ", self.data[self.pos:self.pos + 16])
            self.pos += 16
            if length == 0:
                self.done = True
                self.finished_clean = True
                return None
            chunk = self.data[self.pos:self.pos + length]
            self.pos += len(chunk)
            if chunk[:6] == XZ_MAGIC:
                self.cur = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
                self.cur_input = chunk
                continue
            if chunk:
                return chunk


# ---------------------------------------------------------------------------
# factory
# ---------------------------------------------------------------------------
def _lzip_member(head: bytes) -> tuple[object, int]:
    if head[:4] != b"LZIP" or len(head) < 6:
        raise ValueError("bad lzip header")
    b = head[5]
    base = 1 << (b & 0x1F)
    dict_size = base - (base // 16) * ((b >> 5) & 7)
    filt = [{"id": lzma.FILTER_LZMA1, "dict_size": max(4096, dict_size), "lc": 3, "lp": 0, "pb": 2}]
    return lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filt), 6


def make_adapter(kind: str, data: bytes, start: int = 0):
    """Return an adapter for kind in gzip|zlib|deflate|bzip2|xz|lzma|zstd|lz4|lzip|pbzx (None if unsupported)."""
    if kind == "gzip":
        return ZlibAdapter(data, start, 31)
    if kind == "zlib":
        return ZlibAdapter(data, start, 47)
    if kind == "deflate":
        return ZlibAdapter(data, start, -15, multi=False)
    if kind == "bzip2":
        return CodecAdapter(data, bz2.BZ2Decompressor, start, next_magic=b"BZh")
    if kind == "xz":
        return CodecAdapter(data, lambda: lzma.LZMADecompressor(format=lzma.FORMAT_XZ), start, next_magic=XZ_MAGIC)
    if kind == "lzma":
        return CodecAdapter(data, lambda: lzma.LZMADecompressor(format=lzma.FORMAT_ALONE), start)
    if kind == "lzma_auto":
        return CodecAdapter(data, lambda: lzma.LZMADecompressor(format=lzma.FORMAT_AUTO), start)
    if kind == "zstd":
        try:
            from compression import zstd  # python 3.14+
            return CodecAdapter(data, zstd.ZstdDecompressor, start, next_magic=ZSTD_MAGIC)
        except ImportError:
            try:
                import zstandard
                bio = io.BytesIO(data)
                bio.seek(start)
                rd = zstandard.ZstdDecompressor().stream_reader(bio, read_across_frames=True)
                return ReaderAdapter(rd, bio)
            except ImportError:
                return None
    if kind == "lz4":
        try:
            import lz4.frame  # type: ignore

            class _L4:
                def __init__(self):
                    self.d = lz4.frame.LZ4FrameDecompressor()

                @property
                def eof(self):
                    return self.d.eof

                @property
                def needs_input(self):
                    return self.d.needs_input

                @property
                def unused_data(self):
                    return self.d.unused_data or b""

                def decompress(self, data, max_length=-1):
                    return self.d.decompress(data, max_length=max_length)

            return CodecAdapter(data, _L4, start, next_magic=b"\x04\x22\x4d\x18")
        except ImportError:
            return Lz4Adapter(data, start)
    if kind == "lzip":
        return CodecAdapter(data, lambda: None, start, next_magic=b"LZIP", member_trailer=20,
                            member_factory=_lzip_member)
    if kind == "pbzx":
        return PbzxAdapter(data, start)
    return None


def kind_from_magic(head: bytes) -> str | None:
    """Compression kind for the first bytes of a stream (used for nested payloads)."""
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:3] == b"BZh":
        return "bzip2"
    if head[:6] == XZ_MAGIC:
        return "xz"
    if head[:4] == ZSTD_MAGIC:
        return "zstd"
    if head[:4] == b"pbzx":
        return "pbzx"
    if head[:4] == b"\x04\x22\x4d\x18":
        return "lz4"
    if head[:4] == b"LZIP":
        return "lzip"
    return None


# ---------------------------------------------------------------------------
# bounded file-like view over an adapter
# ---------------------------------------------------------------------------
class DecompStream:
    def __init__(self, adapter, hard_cap: int, budget: Budget | None = None, max_ratio: int = 250):
        self.adapter = adapter
        self.hard_cap = hard_cap
        self.budget = budget
        self.max_ratio = max_ratio
        self.buf = bytearray()
        self.out_total = 0
        self.eof = False
        self.truncated = False      # stopped by the hard cap
        self.bomb = False           # stopped by the ratio guard
        self.budget_hit = False
        self.consumed_before_stop = 0

    def set_cap(self, cap: int) -> None:
        self.hard_cap = cap

    @property
    def error(self) -> str | None:
        return self.adapter.error

    def _fill(self) -> None:
        if self.eof:
            return
        try:
            if self.budget is not None:
                self.budget.check_time()
            chunk = self.adapter.step()
            if chunk is None:
                self.eof = True
                return
            if self.budget is not None:
                self.budget.charge(len(chunk))
        except BudgetExceeded:
            self.budget_hit = True
            self.truncated = True
            self.eof = True
            return
        self.out_total += len(chunk)
        self.buf += chunk
        consumed = max(1, self.adapter.consumed())
        if self.out_total >= self.hard_cap:
            over = self.out_total - self.hard_cap
            if over > 0:
                del self.buf[-over:]
                self.out_total = self.hard_cap
            self.truncated = True
            self.eof = True
        elif self.out_total > BOMB_READ_CAP and self.out_total > self.max_ratio * consumed:
            self.bomb = True
            self.truncated = True
            self.eof = True
        if self.eof:
            self.consumed_before_stop = consumed

    def peek(self, n: int) -> bytes:
        while len(self.buf) < n and not self.eof:
            self._fill()
        return bytes(self.buf[:n])

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            while not self.eof:
                self._fill()
            out = bytes(self.buf)
            self.buf.clear()
            return out
        while len(self.buf) < n and not self.eof:
            self._fill()
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def readable(self) -> bool:
        return True

    def ratio_exceeded(self) -> bool:
        consumed = max(1, self.consumed_before_stop or self.adapter.consumed())
        return self.out_total > self.max_ratio * consumed

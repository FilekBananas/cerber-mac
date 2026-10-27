"""ZIP-family extraction (zip/jar/apk/crx/vsix/ooxml/odf/whl/...).

* members are read in chunks with per-member size/ratio checks *before* decompression;
* central directory problems fall back to carving local file headers;
* local headers that the central directory does not list are carved as "hidden entries";
* encrypted members are tried with common (and harvested) passwords - ZipCrypto in python for small members,
  AES/large members through 7zz.
"""
from __future__ import annotations

import bisect
import bz2
import io
import lzma
import struct
import warnings
import zipfile
import zlib
from typing import Any

from ..core import Confidence, ScanContext, ScanObject
from .arc_common import (BOMB_READ_CAP, Budget, BudgetExceeded, Sink, candidate_passwords, looks_executable_name,
                         note_password_hints, ratio_suspicious, read_capped, report_encryption, vis)

warnings.filterwarnings("ignore", message="Overlapped entries", category=UserWarning)

LOCAL_SIG = b"PK\x03\x04"
PY_DECRYPT_MAX = 8 << 20          # bigger ZipCrypto members go through 7zz (python decryption is slow)
MAX_HIDDEN = 64
MAX_SIG_SCAN = 200_000
CARVE_METHODS = (0, 8, 12)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def strip_crx(data: bytes) -> tuple[bytes, dict[str, Any] | None]:
    """Chrome extension (Cr24): drop the CRX2/CRX3 header, return the embedded zip."""
    if data[:4] != b"Cr24" or len(data) < 16:
        return data, None
    ver = struct.unpack("<I", data[4:8])[0]
    if ver == 3:
        start = 12 + struct.unpack("<I", data[8:12])[0]
    elif ver == 2:
        pk, sg = struct.unpack("<II", data[8:16])
        start = 16 + pk + sg
    else:
        return data, None
    if start > len(data):
        return data, None
    if data[start:start + 2] != b"PK":
        j = data.find(LOCAL_SIG, 12)
        if j < 0:
            return data, None
        start = j
    return data[start:], {"crx_version": ver, "crx_header_bytes": start}


def _decode_name(raw_name: str, flags: int) -> str:
    """zipfile decodes non-UTF-8-flagged names as cp437; many tools write UTF-8 without the flag."""
    if not (flags & 0x800):
        try:
            raw = raw_name.encode("cp437")
            if any(b >= 0x80 for b in raw):
                return raw.decode("utf-8")
        except UnicodeError:
            pass
    return raw_name


def inflate_raw(data: bytes, start: int, cap: int, max_ratio: int, wbits: int = -15):
    """Bounded raw-deflate. Returns (out, consumed, complete, truncated, bomb, error)."""
    d = zlib.decompressobj(wbits)
    view = memoryview(data)
    n = len(data)
    pos = start
    parts: list[bytes] = []
    total = 0
    trunc = bomb = False
    err = None
    while pos < n or d.unconsumed_tail:
        if d.unconsumed_tail:
            chunk = d.unconsumed_tail
        else:
            chunk = bytes(view[pos:pos + 65536])
            pos += len(chunk)
        try:
            out = d.decompress(chunk, 1 << 20)
        except zlib.error as exc:
            err = str(exc)
            break
        if out:
            parts.append(out)
            total += len(out)
        if d.eof:
            pos -= len(d.unused_data)
            break
        if total >= cap:
            trunc = True
            break
        consumed = pos - start - len(d.unconsumed_tail)
        if total > BOMB_READ_CAP and total > max_ratio * max(consumed, 1):
            bomb = trunc = True
            break
    out = b"".join(parts)
    if len(out) > cap:
        out, trunc = out[:cap], True
    return out, pos - start - len(d.unconsumed_tail), d.eof, trunc, bomb, err


def parse_local(data: bytes, i: int) -> dict[str, Any] | None:
    if i < 0 or i + 30 > len(data) or data[i:i + 4] != LOCAL_SIG:
        return None
    (_sig, ver, flags, method, _mt, _md, crc, csize, usize, nlen, elen) = struct.unpack_from("<4sHHHHHIIIHH", data, i)
    ds = i + 30 + nlen + elen
    if nlen == 0 or ds > len(data):
        return None
    if ver > 100 or method not in (0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 14, 18, 19, 93, 94, 95, 96, 97, 98, 99):
        return None
    raw = data[i + 30:i + 30 + nlen]
    if len(raw) < nlen:
        return None
    try:
        name = raw.decode("utf-8") if flags & 0x800 else raw.decode("cp437")
        if not (flags & 0x800):
            try:
                name = raw.decode("utf-8") if any(b >= 0x80 for b in raw) else name
            except UnicodeError:
                pass
    except UnicodeError:
        name = raw.decode("latin1")
    ctrl = sum(1 for ch in name if ord(ch) < 32 and ch not in "\t")
    if ctrl > max(1, len(name) // 10):
        return None
    extra = data[i + 30 + nlen:ds]
    if csize == 0xFFFFFFFF or usize == 0xFFFFFFFF:
        p = 0
        while p + 4 <= len(extra):
            hid, hsz = struct.unpack_from("<HH", extra, p)
            if hid == 1:
                body = extra[p + 4:p + 4 + hsz]
                q = 0
                if usize == 0xFFFFFFFF and len(body) >= q + 8:
                    usize = struct.unpack_from("<Q", body, q)[0]
                    q += 8
                if csize == 0xFFFFFFFF and len(body) >= q + 8:
                    csize = struct.unpack_from("<Q", body, q)[0]
                break
            p += 4 + hsz
    return {"off": i, "ver": ver, "flags": flags, "method": method, "crc": crc, "csize": csize, "usize": usize,
            "name": name, "ds": ds}


def _decode_payload(data: bytes, ds: int, method: int, csize: int, flags: int, cap: int, max_ratio: int,
                    sizes_known: bool):
    """Decode one member's data starting at ds. Returns (content|None, consumed|None, truncated, bomb, note)."""
    if method == 0:
        if sizes_known:
            return data[ds:ds + min(csize, cap)], csize, csize > cap, False, ""
        # stored with a data descriptor: run to the next signature
        ends = [j for j in (data.find(b"PK\x03\x04", ds), data.find(b"PK\x01\x02", ds), data.find(b"PK\x05\x06", ds))
                if j >= 0]
        end = min(ends) if ends else len(data)
        body = data[ds:end]
        if body[-16:-12] == b"PK\x07\x08":
            body = body[:-16]
        return body[:cap], len(body), len(body) > cap, False, ""
    if method == 8:
        out, consumed, complete, trunc, bomb, err = inflate_raw(data, ds, cap, max_ratio)
        note = "" if complete or trunc else (err or "truncated deflate stream")
        return out, consumed, trunc, bomb, note
    if method == 12:
        d = bz2.BZ2Decompressor()
        out = b""
        pos = ds
        parts = []
        total = 0
        try:
            while pos < len(data) and not d.eof:
                chunk = data[pos:pos + 65536]
                pos += len(chunk)
                piece = d.decompress(chunk, 1 << 20)
                while True:
                    if piece:
                        parts.append(piece)
                        total += len(piece)
                    if total >= cap or d.eof or d.needs_input:
                        break
                    piece = d.decompress(b"", 1 << 20)
                if total >= cap:
                    break
        except (OSError, EOFError, ValueError):
            pass
        out = b"".join(parts)[:cap]
        consumed = pos - ds - len(d.unused_data) if d.eof else None
        return out, consumed, total >= cap, False, ""
    return None, None, False, False, f"unsupported compression method {method}"


def carve_entries(data: bytes, sink: Sink, positions: list[int] | None = None, prefix: str = "") -> int:
    """Recover members by walking local file headers. Returns number of children added."""
    limits = sink.ctx.limits
    budget = sink.budget
    added = 0
    pos = 0
    n = len(data)
    iterator = iter(positions) if positions is not None else None
    guard = 0
    while True:
        if iterator is not None:
            i = next(iterator, -1)
        else:
            i = data.find(LOCAL_SIG, pos)
        if i < 0:
            break
        guard += 1
        if guard > MAX_SIG_SCAN:
            break
        if sink.limit_reached():
            sink.skip("*", "max children reached")
            break
        hdr = parse_local(data, i)
        if hdr is None:
            pos = i + 4
            continue
        name = hdr["name"]
        sink.members += 1
        sink.check_name(name)
        pos = i + 4
        if name.endswith("/"):
            pos = hdr["ds"]
            continue
        if hdr["flags"] & 1:
            sink.encrypted = True
            sink.skip(name, "encrypted (local header recovery)")
            pos = hdr["ds"] + (hdr["csize"] if not hdr["flags"] & 8 else 0)
            continue
        cap = min(limits.max_child_size, max(1, budget.remaining()))
        sizes_known = not (hdr["flags"] & 8) and (hdr["csize"] or hdr["usize"] == 0)
        if hdr["usize"] > limits.max_child_size and hdr["usize"] != 0xFFFFFFFF and sizes_known:
            sink.skip(name, f"too large ({hdr['usize']} bytes)")
            if ratio_suspicious(hdr["usize"], hdr["csize"], limits.max_ratio):
                sink.bomb("member with absurd compression ratio", [vis(name)], score=25)
            pos = hdr["ds"] + hdr["csize"]
            continue
        content, consumed, trunc, bomb, note = _decode_payload(data, hdr["ds"], hdr["method"], hdr["csize"],
                                                               hdr["flags"], cap, limits.max_ratio, sizes_known)
        if bomb:
            sink.bomb("decompression bomb (ratio guard) in recovered member", [vis(name)])
        if content is None:
            sink.skip(name, note or "unsupported")
            pos = hdr["ds"] + (hdr["csize"] if sizes_known else 0)
            continue
        if note:
            sink.skip(name, note)
        if consumed:
            pos = hdr["ds"] + consumed
        else:
            pos = hdr["ds"]
        budget.charge(len(content))
        if content:
            note_password_hints(sink, name, content)
            c = sink.add(prefix + name, content, {"size": hdr["usize"], "recovered": True, "truncated": trunc},
                         backslash=True)
            if c is not None:
                added += 1
        if positions is None and pos < i + 4:
            pos = i + 4
    return added


def raw_member(data: bytes, zi: zipfile.ZipInfo, cap: int, max_ratio: int):
    """Decode a member straight from its local header, ignoring CRC/size mismatches."""
    hdr = parse_local(data, zi.header_offset)
    if hdr is None:
        return None
    content, _c, trunc, bomb, note = _decode_payload(data, hdr["ds"], zi.compress_type, zi.compress_size, hdr["flags"],
                                                     cap, max_ratio, True)
    if content is None:
        return None
    return content, trunc, bomb


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
class _State:
    def __init__(self, candidates: list[str]):
        self.candidates = candidates
        self.pw: str | None = None
        self.enc_names: list[str] = []
        self.unopened: list[str] = []
        self.cli_names: set[str] = set()
        self.done_names: set[str] = set()
        self.unsupported: list[str] = []


def _try_decrypt(zf: zipfile.ZipFile, zi: zipfile.ZipInfo, cap: int, sink: Sink, st: _State):
    if zi.compress_type == 99 or zi.file_size > PY_DECRYPT_MAX:
        return None
    order = ([st.pw] if st.pw else []) + [p for p in st.candidates if p != st.pw]
    for pw in order:
        try:
            with zf.open(zi, pwd=pw.encode("utf-8")) as fp:
                data, trunc = read_capped(fp, cap, None)
        except RuntimeError:
            continue
        except (zipfile.BadZipFile, zlib.error, EOFError, OSError, lzma.LZMAError, ValueError, NotImplementedError,
                struct.error):
            continue
        st.pw = pw
        sink.budget.charge(len(data))
        return data, trunc
    return None


def _overlap_check(infos: list[zipfile.ZipInfo]) -> bool:
    spans = sorted((zi.header_offset, zi.compress_size) for zi in infos if not zi.is_dir())
    prev_end = -1
    prev_off = -1
    for off, cs in spans:
        if off == prev_off:
            return True
        if off < prev_end:
            return True
        prev_off = off
        prev_end = off + 30 + cs
    return False


def _covered_ranges(data: bytes, infos: list[zipfile.ZipInfo]) -> tuple[list[int], list[int]]:
    starts: list[int] = []
    ends: list[int] = []
    rng = []
    for zi in infos:
        o = zi.header_offset
        try:
            nlen, elen = struct.unpack_from("<HH", data, o + 26)
        except struct.error:
            continue
        end = o + 30 + nlen + elen + zi.compress_size + (24 if zi.flag_bits & 8 else 0)
        rng.append((o, end))
    rng.sort()
    for a, b in rng:
        if ends and a <= ends[-1]:
            ends[-1] = max(ends[-1], b)
        else:
            starts.append(a)
            ends.append(b)
    return starts, ends


def _find_hidden(data: bytes, infos: list[zipfile.ZipInfo]) -> list[int]:
    starts, ends = _covered_ranges(data, infos)
    hidden: list[int] = []
    i = -1
    guard = 0
    while len(hidden) < MAX_HIDDEN and guard < MAX_SIG_SCAN:
        i = data.find(LOCAL_SIG, i + 1)
        if i < 0:
            break
        guard += 1
        k = bisect.bisect_right(starts, i) - 1
        if k >= 0 and i < ends[k]:
            continue
        hidden.append(i)
    return hidden


def _read_member(zf, zi, cap, sink) -> tuple[bytes | None, bool, str]:
    """Returns (data, truncated, error)."""
    try:
        with zf.open(zi) as fp:
            data, trunc = read_capped(fp, cap, sink.budget)
        return data, trunc, ""
    except BudgetExceeded:
        raise
    except NotImplementedError as exc:
        return None, False, f"unsupported:{exc}"
    except (zipfile.BadZipFile, zlib.error, EOFError, OSError, lzma.LZMAError, ValueError, RuntimeError,
            struct.error, OverflowError) as exc:
        return None, False, str(exc) or type(exc).__name__


def extract_zip(obj: ScanObject, ctx: ScanContext, sink: Sink, data: bytes, tool: str | None = None) -> bool:
    """Extract a zip. Returns False when nothing could be parsed at all."""
    limits = ctx.limits
    budget = sink.budget
    data, crx = strip_crx(data)
    if crx:
        sink.extra.update(crx)
        sink.fmt = "crx"
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except Exception as exc:  # noqa: BLE001 - BadZipFile, struct.error, OverflowError, ...
        sink.extra["central_directory"] = "unreadable"
        sink.flag("Heur:Archive.Malformed", Confidence.LOW, 10,
                  "ZIP central directory missing or corrupt; members recovered from local file headers",
                  [str(exc)[:200]])
        n = carve_entries(data, sink)
        return n > 0
    st = _State(candidate_passwords(obj))
    if len(infos) > 2000:  # under a children cap the interesting members must come first
        infos = sorted(infos, key=lambda z: 0 if looks_executable_name(z.orig_filename) else 1)
    if _overlap_check(infos):
        sink.bomb("ZIP members overlap (shared compressed data: zip quine/bomb)", [f"{len(infos)} entries"], score=50)
        budget.shrink(256 << 20)

    try:
        for zi in infos:
            name = _decode_name(zi.orig_filename, zi.flag_bits)
            if zi.is_dir():
                sink.check_name(name)
                continue
            if sink.limit_reached():
                sink.skip("*", "max children reached")
                break
            budget.check_time()
            sink.members += 1
            sink.check_name(name)
            mode = (zi.external_attr >> 16) & 0o177777 if zi.create_system == 3 else 0
            is_link = (mode & 0o170000) == 0o120000
            fs, cs = zi.file_size, zi.compress_size
            if is_link:
                if 0 < fs <= 4096 and not zi.flag_bits & 1:
                    d, _t, err = _read_member(zf, zi, 4096, sink)
                    if d:
                        sink.note_symlink(name, d.decode("utf-8", "replace"))
                continue
            if fs == 0:
                continue
            if fs > limits.max_child_size:
                sink.skip(name, f"too large ({fs} bytes, {cs} compressed)")
                if ratio_suspicious(fs, cs, limits.max_ratio):
                    sink.bomb("member with absurd compression ratio (declared size exceeds limit)",
                              [f"{vis(name)}: {fs} bytes from {cs}"], score=25)
                continue
            cap = limits.max_child_size
            suspicious = ratio_suspicious(fs, cs, limits.max_ratio)
            if suspicious:
                sink.bomb("member with an absurd compression ratio (possible decompression bomb)",
                          [f"{vis(name)}: {fs} bytes from {cs}"], score=25)
                cap = sink.bomb_allowance(cap)
                if cap <= 0:
                    sink.skip(name, f"absurd compression ratio ({fs} bytes from {cs}), not read")
                    continue
            content: bytes | None = None
            trunc = False
            if zi.flag_bits & 1:
                st.enc_names.append(name)
                sink.encrypted = True
                res = _try_decrypt(zf, zi, cap, sink, st)
                if res is None:
                    if tool and ctx.deep:
                        st.cli_names.add(name)
                    else:
                        st.unopened.append(name)
                    continue
                content, trunc = res
            else:
                content, trunc, err = _read_member(zf, zi, cap, sink)
                if content is None:
                    if err.startswith("unsupported:"):
                        st.unsupported.append(name)
                        if tool and ctx.deep:
                            st.cli_names.add(name)
                        else:
                            sink.skip(name, err[len("unsupported:"):].strip()[:80])
                        continue
                    # damaged member: decode straight from the local header, ignoring the CRC
                    rm = raw_member(data, zi, cap, limits.max_ratio)
                    if rm is None:
                        sink.skip(name, f"unreadable ({err[:80]})")
                        sink.flag("Heur:Archive.Malformed", Confidence.LOW, 10, "damaged ZIP member",
                                  [f"{vis(name)}: {err[:120]}"])
                        continue
                    content, trunc, bomb = rm
                    budget.charge(len(content))
                    if bomb:
                        sink.bomb("decompression bomb (ratio guard) in damaged member", [vis(name)])
                    if "crc" in err.lower() or "size" in err.lower():
                        sink.flag("Heur:Archive.BadCRC", Confidence.LOW, 10,
                                  "member failed integrity checks but its content was recovered "
                                  "(corrupt CRC/size is used to evade scanners)", [f"{vis(name)}: {err[:120]}"])
                    else:
                        sink.flag("Heur:Archive.Malformed", Confidence.LOW, 10,
                                  "inconsistent ZIP headers; member recovered from its local header "
                                  "(parser-differential trick)", [f"{vis(name)}: {err[:120]}"])
            if not content:
                continue
            if suspicious:
                sink.bomb_bytes += len(content)
            st.done_names.add(name)
            note_password_hints(sink, name, content)
            sink.add(name, content, {"size": fs, "mode": mode & 0o7777 if mode else 0, "compressed": cs,
                                     "encrypted": bool(zi.flag_bits & 1), "truncated": trunc,
                                     "mtime": "%04d-%02d-%02d" % zi.date_time[:3]}, backslash=True)
        # hidden local entries not present in the central directory
        hidden = _find_hidden(data, infos)
        if hidden:
            n = carve_entries(data, sink, hidden, prefix="")
            sink.flag("Heur:Archive.HiddenEntries", Confidence.LOW, 15,
                      "ZIP contains local file entries that are not listed in the central directory "
                      "(hidden/appended content)", [f"{len(hidden)} unlisted local header(s), {n} recovered"])
            sink.extra["hidden_entries"] = len(hidden)
    finally:
        zf.close()

    # members python could not handle (AES, big ZipCrypto, deflate64...): 7zz
    if st.cli_names and tool:
        try:
            _cli_pass(obj, ctx, sink, tool, data, st)
        except BudgetExceeded:
            raise
    report_encryption(sink, st.unopened, st.pw, bool(st.enc_names))
    return True


def _cli_pass(obj: ScanObject, ctx: ScanContext, sink: Sink, tool: str, data: bytes, st: _State) -> None:
    from .arc_cli import cli_extract, prepare_input
    from .arc_common import safe_rmtree
    path, d = prepare_input(ctx, obj, "zip", data)
    try:
        res = cli_extract(ctx, sink, tool, path,
                          select=lambda e: (e.path in st.cli_names or (e.encrypted and e.path not in st.done_names)),
                          passwords=st.candidates, count_members=False)
        if res.password:
            st.pw = res.password
        st.unopened.extend(n for n in res.unopened_encrypted if n not in st.unopened)
        if res.needs_password and not res.unopened_encrypted:
            st.unopened.extend(n for n in st.cli_names if n in st.enc_names and n not in st.unopened)
        if not res.ok and res.error:
            for n in st.cli_names:
                sink.skip(n, f"7zz: {res.error[:100]}")
    finally:
        safe_rmtree(d)

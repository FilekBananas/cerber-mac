"""Language-independent decoders: encoded blobs, numeric arrays, PowerShell -EncodedCommand."""
from __future__ import annotations

import re

from .primitives import (Budget, Layer, b64decode_loose, bytes_to_text, classify, excerpt, hexdecode,
                         ints_to_bytes, looks_base64, looks_hex, looks_like_code, parse_int, xor_bytes)

# --------------------------------------------------------------------------- blob decoding


def decode_blob(s: str, budget: Budget, raw_deflate: bool = False, depth: int = 0,
                try_reverse: bool = True) -> tuple[str, str, str, bytes] | None:
    """Decode an encoded string (base64 / urlsafe / hex / reversed base64), unwrap nested
    encodings and compression. Returns (chain, kind, ftype, payload) or None."""
    if budget.expired() or depth > budget.max_depth:
        return None
    s = s.strip()
    cands: list[tuple[str, bytes]] = []
    if looks_hex(s, 16):
        d = hexdecode(s)
        if d:
            cands.append(("hex", d))
    if looks_base64(s, 12):
        d = b64decode_loose(s)
        if d:
            cands.append(("b64", d))
    if try_reverse and len(s) >= 16:
        r = s[::-1]
        if looks_base64(r, 16) and (r.endswith("=") or not looks_base64(s, 16)):
            d = b64decode_loose(r)
            if d:
                cands.append(("rev>b64", d))
    for how, data in cands:
        if not budget.charge(len(data)):
            return None
        kind, ftype, payload, chain = classify(data, raw_deflate=raw_deflate)
        if kind == "junk":
            continue
        full = how + (">" + chain if chain else "")
        if kind == "text":
            inner = unwrap_text(payload, budget, depth + 1)
            if inner:
                ichain, ikind, iftype, ipayload = inner
                return full + ">" + ichain, ikind, iftype, ipayload
            t = payload.decode("utf-8", "replace")
            if not looks_like_code(t) and len(t) < 24:
                continue
        return full, kind, ftype, payload
    return None


_WHOLE_B64 = re.compile(r"^[\sA-Za-z0-9+/_\-]{16,}={0,2}\s*$")
_WHOLE_HEX = re.compile(r"^\s*(?:[0-9a-fA-F]{2}[\s,:]?){8,}\s*$")


def unwrap_text(payload: bytes, budget: Budget, depth: int = 0) -> tuple[str, str, str, bytes] | None:
    """If a decoded text is itself nothing but an encoded blob, keep decoding."""
    if depth > budget.max_depth or len(payload) > 32 << 20:
        return None
    t = payload.decode("utf-8", "replace").strip()
    if len(t) < 16:
        return None
    if _WHOLE_B64.match(t) or _WHOLE_HEX.match(t):
        return decode_blob(re.sub(r"\s+", "", t), budget, depth=depth)
    return None


def classify_layer(method: str, data: bytes, budget: Budget, lang: str | None = None,
                   source: str = "", raw_deflate: bool = False, need_code: bool = True) -> Layer | None:
    """Classify raw decoded bytes into a Layer (or None when useless)."""
    if not data or not budget.charge(len(data)):
        return None
    kind, ftype, payload, chain = classify(data, raw_deflate=raw_deflate)
    if kind == "junk":
        return None
    if chain:
        method = f"{method}>{chain}"
    if kind == "text":
        inner = unwrap_text(payload, budget)
        if inner:
            ichain, kind, ftype, payload = inner
            method = f"{method}>{ichain}"
        if kind == "text":
            t = payload.decode("utf-8", "replace")
            if need_code and not looks_like_code(t):
                return None
    return Layer(method=method, data=payload, lang=lang if kind == "text" else None, kind=kind,
                 ftype=ftype, source=excerpt(source))


# --------------------------------------------------------------------------- PowerShell -EncodedCommand

_ENC_RX = re.compile(
    r"(?i)(?:^|[\s\"'(,;|&=^])[-/–—―](e[a-z]{0,13})\s*[\s:]\s*[\"']?([A-Za-z0-9+/]{16,}={0,2})")


def ps_encoded_commands(text: str, budget: Budget, limit: int = 16) -> list[Layer]:
    out: list[Layer] = []
    if "-e" not in text.lower() and "/e" not in text.lower() and "–e" not in text.lower():
        return out
    for m in _ENC_RX.finditer(text):
        flag = m.group(1).lower()
        if not ("encodedcommand".startswith(flag) or flag == "ec"):
            continue
        if budget.expired() or len(out) >= limit:
            break
        blob = m.group(2)
        data = b64decode_loose(blob)
        if not data:
            continue
        lay = classify_layer("ps-encodedcommand", data, budget, "powershell", m.group(0), need_code=False)
        if lay:
            out.append(lay)
    return out


# --------------------------------------------------------------------------- numeric arrays

_NUM_ARRAY = re.compile(
    r"(?<![\w.])((?:(?:0x[0-9a-fA-F]{1,4}|&H[0-9a-fA-F]{1,4}|\d{1,5})\s*[,;]\s*){15,}"
    r"(?:0x[0-9a-fA-F]{1,4}|&H[0-9a-fA-F]{1,4}|\d{1,5}))")
_KEY_OP = re.compile(r"(?i)(?:-bxor|\bxor\b|\^)\s*\(?\s*(0x[0-9a-f]{1,2}|&h[0-9a-f]{1,2}|\d{1,3})\b|"
                     r"(?:\)|\]|\b[a-z_]\w*)\s*-\s*(\d{1,3})\b")


def _mostly_printable(s: str) -> bool:
    if not s:
        return False
    ok = sum(1 for ch in s if 32 <= ord(ch) < 127 or ch in "\r\n\t")
    return ok >= len(s) * 0.97


def numeric_arrays(text: str, budget: Budget, lang: str | None, limit: int = 32,
                   min_items: int = 16) -> list[Layer]:
    """Arrays of character codes / bytes: 72,101,108 ... (optionally xor/offset encoded)."""
    out: list[Layer] = []
    if budget.expired():
        return out
    for m in _NUM_ARRAY.finditer(text):
        if len(out) >= limit or budget.expired():
            break
        toks = re.split(r"\s*[,;]\s*", m.group(1).strip())
        nums = [parse_int(t) for t in toks]
        if any(n is None for n in nums) or len(nums) < min_items:
            continue
        seq: list[int] = [n for n in nums if n is not None]
        tail = text[m.end():m.end() + 240]
        head = text[max(0, m.start() - 240):m.start()]
        variants: list[tuple[str, list[int]]] = [("chars", seq)]
        for km in _KEY_OP.finditer(head + " " + tail):
            if km.group(1):
                k = parse_int(km.group(1))
                if k:
                    variants.append((f"xor{k}", [n ^ k for n in seq]))
            elif km.group(2):
                k = int(km.group(2))
                if 0 < k < 256:
                    variants.append((f"sub{k}", [n - k for n in seq]))
                    variants.append((f"add{k}", [n + k for n in seq]))
            if len(variants) > 6:
                break
        for how, vals in variants:
            if all(9 <= v < 127 for v in vals):
                s = "".join(chr(v) for v in vals)
                if _mostly_printable(s) and looks_like_code(s):
                    out.append(Layer(f"charcodes-{how}", s.encode(), lang, "text", "text", excerpt(m.group(0))))
                    break
            b = ints_to_bytes(vals)
            if b and len(b) >= 64:
                lay = classify_layer(f"bytearray-{how}", b, budget, lang, m.group(0))
                if lay:
                    out.append(lay)
                    break
                if how == "chars" and b[:2] in (b"\xfc\xe8", b"\xfc\x48", b"\xfc\x31", b"\xd9\xeb"):
                    # classic metasploit / cobalt strike shellcode prologue
                    out.append(Layer("shellcode", b, None, "binary", "shellcode", excerpt(m.group(0))))
                    break
    return out


# --------------------------------------------------------------------------- encoded literals

def encoded_literals(literals, budget: Budget, lang: str | None, min_len: int = 16,
                     limit: int = 32, raw_deflate: bool = False) -> list[Layer]:
    """Try to decode every long string literal that looks like base64/hex."""
    out: list[Layer] = []
    seen: set[str] = set()
    for lit in literals:
        if len(out) >= limit or budget.expired():
            break
        v = lit.value.strip()
        if len(v) < min_len or v in seen:
            continue
        seen.add(v)
        if not (looks_base64(v, min_len) or looks_hex(v, min_len) or looks_base64(v[::-1], min_len)):
            continue
        r = decode_blob(v, budget, raw_deflate=raw_deflate)
        if not r:
            continue
        chain, kind, ftype, payload = r
        if kind == "text":
            t = payload.decode("utf-8", "replace")
            if not looks_like_code(t):
                continue
        out.append(Layer(chain, payload, lang if kind == "text" else None, kind, ftype, excerpt(v)))
    return out


def xor_try(data: bytes, keys: list[bytes], budget: Budget, lang: str | None, method: str,
            source: str = "") -> Layer | None:
    for k in keys[:8]:
        if budget.expired():
            return None
        x = xor_bytes(data[:8 << 20], k)
        lay = classify_layer(f"{method}>xor", x, budget, lang, source)
        if lay:
            return lay
    return None


def text_of(layer: Layer) -> str:
    return layer.data.decode("utf-8", "replace") if layer.kind == "text" else ""


__all__ = ["decode_blob", "unwrap_text", "classify_layer", "ps_encoded_commands", "numeric_arrays",
           "encoded_literals", "xor_try", "text_of", "bytes_to_text"]

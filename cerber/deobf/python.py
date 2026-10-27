"""Python de-obfuscation: base64/zlib/marshal/hex/rot13 layers, chr() folding, [::-1].

marshal/pickle payloads are NEVER loaded: marshal.loads on hostile input can crash the
interpreter and pickle executes code. We only scan their bytes for embedded strings.
"""
from __future__ import annotations

import re
import struct
from collections import Counter

from .chains import resolve
from .generic import classify_layer, encoded_literals, numeric_arrays
from .primitives import Budget, Layer, excerpt
from .textops import fold_concat, iter_literals, literal_map, quote, render_literals

LANG = "python"

_CHR = re.compile(r"\bchr\s*\(\s*(0x[0-9a-fA-F]{1,6}|\d{1,7})\s*\)")
_NUMLIST = r"((?:(?:0x[0-9a-fA-F]{1,6}|\d{1,7})\s*,\s*){0,200000}(?:0x[0-9a-fA-F]{1,6}|\d{1,7}))\s*,?\s*"
_JOIN_MAP = re.compile(r"""['"]{2}\s*\.\s*join\s*\(\s*(?:map\s*\(\s*chr\s*,\s*[\[(]\s*""" + _NUMLIST + r"""[\])]\s*\)|"""
                       r"""\[?\s*chr\s*\(\s*\w+\s*\)\s*for\s+\w+\s+in\s+[\[(]\s*""" + _NUMLIST.replace("(", "(?P<b>", 1) + r"""[\])]\s*\]?)\s*\)""")
_BYTES_LIST = re.compile(r"\bbytes(?:array)?\s*\(\s*\[\s*((?:(?:0x[0-9a-fA-F]{1,2}|\d{1,3})\s*,\s*){0,400000}(?:0x[0-9a-fA-F]{1,2}|\d{1,3}))\s*,?\s*\]\s*\)")
_REV = re.compile(r"\s*\[\s*::\s*-1\s*\]")


def normalize(text: str, stats: Counter, budget: Budget) -> str:
    t = text
    if "chr" in t:
        def rep_chr(m: re.Match) -> str:
            try:
                v = int(m.group(1), 0)
                stats["charcode"] += 1
                return quote(chr(v))
            except (ValueError, OverflowError):
                return m.group(0)
        t = _CHR.sub(rep_chr, t)

        def rep_join(m: re.Match) -> str:
            try:
                nums = m.group(1) or m.group("b")
                s = "".join(chr(int(x, 0)) for x in re.split(r"\s*,\s*", nums.strip()))
            except (ValueError, OverflowError):
                return m.group(0)
            stats["charcode"] += len(s)
            return quote(s)
        t = _JOIN_MAP.sub(rep_join, t)
    if "bytes" in t:
        def rep_bytes(m: re.Match) -> str:
            try:
                b = bytes(int(x, 0) for x in re.split(r"\s*,\s*", m.group(1).strip()))
                s = b.decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return m.group(0)
            if any(ord(c) < 9 for c in s):
                return m.group(0)
            stats["charcode"] += len(s)
            return quote(s)
        t = _BYTES_LIST.sub(rep_bytes, t)
    for _ in range(3):
        if budget.expired():
            break
        before = t
        t = fold_concat(t, LANG, stats)
        t = _reverse_literals(t, stats)
        if t == before:
            break
    return render_literals(t, LANG, stats)


def _reverse_literals(text: str, stats: Counter) -> str:
    if "::-1" not in text.replace(" ", ""):
        return text
    out: list[str] = []
    pos = 0
    for lit in iter_literals(text, LANG, min_len=2):
        m = _REV.match(text, lit.end)
        if not m:
            continue
        # keep base64-looking reversed literals for the chain resolver (value flows into b64decode)
        out.append(text[pos:lit.start])
        out.append(quote(lit.value[::-1]))
        pos = m.end()
        stats["reverse"] += 1
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


# --------------------------------------------------------------------------- marshal strings

_MARSHAL_STR_TYPES = {ord("a"), ord("A"), ord("u"), ord("t"), ord("s")}
_MARSHAL_SHORT = {ord("z"), ord("Z")}


def marshal_strings(data: bytes, limit: int = 4 << 20, min_len: int = 3) -> list[str]:
    """Heuristically walk a marshal stream and collect its string constants / names."""
    out: list[str] = []
    d = data[:limit]
    i = 0
    n = len(d)
    while i < n - 2:
        t = d[i] & 0x7F
        if t in _MARSHAL_SHORT:
            ln = d[i + 1]
            s = d[i + 2:i + 2 + ln]
            if ln >= min_len and len(s) == ln and all(32 <= c < 127 or c in (9, 10, 13) for c in s):
                out.append(s.decode("ascii"))
                i += 2 + ln
                continue
        elif t in _MARSHAL_STR_TYPES and i + 5 <= n:
            ln = struct.unpack_from("<I", d, i + 1)[0]
            if min_len <= ln <= n - i - 5 and ln < 1 << 20:
                s = d[i + 5:i + 5 + ln]
                if t == ord("s"):
                    ok = all(32 <= c < 127 or c in (9, 10, 13) for c in s)
                    txt = s.decode("latin-1") if ok else None
                else:
                    try:
                        txt = s.decode("utf-8")
                        ok = txt.isprintable() or all(ch.isprintable() or ch in "\t\r\n" for ch in txt)
                    except UnicodeDecodeError:
                        ok, txt = False, None
                if ok and txt:
                    out.append(txt)
                    i += 5 + ln
                    continue
        i += 1
        if len(out) > 100000:
            break
    return out


def _chain_layer(norm: str, start: int, end: int, value: bytes, budget: Budget, source: str) -> list[Layer]:
    r = resolve(norm, start, end, value)
    if not r:
        return []
    steps, data, sink, has_sink = r
    method = "py-" + ">".join(steps)
    if steps and steps[-1] in ("marshal", "pickle"):
        pre = steps[:-1]
        out = [Layer("py-" + ">".join(pre + [steps[-1] + "-raw"]), data, None, "binary", steps[-1], excerpt(source))]
        strs = marshal_strings(data) if steps[-1] == "marshal" else \
            [s.decode("latin-1") for s in re.findall(rb"[\x20-\x7e]{4,}", data[:4 << 20])]
        if strs:
            body = "\n".join(strs)
            out.append(Layer("py-" + ">".join(pre + [steps[-1] + "-strings"]), body.encode("utf-8", "replace"),
                             LANG, "text", "text", excerpt(source), {"strings_dump": steps[-1]}))
        return out
    lay = classify_layer(method, data, budget, sink or LANG, source, need_code=not has_sink)
    if lay:
        lay.meta["sink"] = bool(has_sink)
        return [lay]
    return []


def extract(raw: str, norm: str, budget: Budget) -> list[Layer]:
    layers: list[Layer] = []
    lits = list(iter_literals(norm, LANG, min_len=8))
    used: set[int] = set()
    for lit in lits:
        if budget.expired() or len(layers) > 48:
            break
        if len(lit.value) < 12:
            continue
        got = _chain_layer(norm, lit.start, lit.end, lit.value.encode("latin-1", "replace"), budget, lit.raw)
        if got:
            used.add(lit.start)
            layers += got
    # value passed through a variable: x = '...'; exec(b64decode(x))
    if not budget.expired():
        for name, val in list(literal_map(norm, LANG, min_len=24).items())[:64]:
            for m in re.finditer(r"\(\s*" + re.escape(name) + r"\s*\)", norm):
                got = _chain_layer(norm, m.start() + 1, m.end() - 1, val.encode("latin-1", "replace"), budget, val[:80])
                if got:
                    layers += got
                    break
    # exec('...code...') with a plain literal
    for lit in lits:
        if len(lit.value) >= 24 and re.search(r"\b(?:exec|eval|compile)\s*\(\s*$", norm[max(0, lit.start - 20):lit.start]):
            layers.append(Layer("py-exec-literal", lit.value.encode("utf-8", "replace"), LANG, "text", "python",
                                excerpt(lit.raw)))
    rest = [lit for lit in lits if lit.start not in used]
    layers += encoded_literals(rest, budget, LANG, min_len=40)
    layers += numeric_arrays(norm, budget, LANG)
    return layers

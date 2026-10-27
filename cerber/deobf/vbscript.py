"""VBScript normalisation and payload extraction."""
from __future__ import annotations

import re
from collections import Counter

from .generic import encoded_literals, numeric_arrays, ps_encoded_commands
from .javascript import safe_int_expr
from .primitives import Budget, Layer, excerpt
from .textops import fold_concat, iter_literals, quote
from .vbe import decode_encoded_blocks

LANG = "vbs"

_CHR = re.compile(r"(?i)\bchr[wb]?\s*\(\s*([0-9a-fA-F&hH+\-*\\\s()xor]{1,40}?)\s*\)")
_STRREV = re.compile(r"(?i)\bstrreverse\s*\(\s*$")
_REPLACE = re.compile(r"(?i)\breplace\s*\(\s*$")
_EXEC = re.compile(r"(?i)(?:\bexecute(?:global)?|\beval|\.run|\.exec|\.shellexecute|\bexecutestatement)\s*\(?\s*$")
_COMMA = re.compile(r"\s*,\s*")


def _vb_int(expr: str) -> int | None:
    e = expr.strip()
    e = re.sub(r"(?i)&h([0-9a-f]+)&?", lambda m: str(int(m.group(1), 16)), e)
    e = re.sub(r"(?i)\bxor\b", "^", e).replace("\\", "/")
    return safe_int_expr(e)


def _sub_chr(text: str, stats: Counter) -> str:
    if "chr" not in text.lower():
        return text

    def rep(m: re.Match) -> str:
        v = _vb_int(m.group(1))
        if v is None or not 0 <= v <= 0xFFFF:
            return m.group(0)
        stats["charcode"] += 1
        return quote(chr(v), LANG)
    return _CHR.sub(rep, text)


def _literal_funcs(text: str, stats: Counter) -> str:
    """StrReverse("..") and Replace("..", "a", "b") on literals."""
    low = text.lower()
    if "strreverse" not in low and "replace" not in low:
        return text
    lits = list(iter_literals(text, LANG))
    out: list[str] = []
    pos = 0
    i = 0
    while i < len(lits):
        lit = lits[i]
        pre = text[max(0, lit.start - 20):lit.start]
        m = _STRREV.search(pre)
        if m:
            cm = re.match(r"\s*\)", text[lit.end:])
            if cm:
                out.append(text[pos:lit.start - (len(pre) - m.start())])
                out.append(quote(lit.value[::-1], LANG))
                pos = lit.end + cm.end()
                stats["reverse"] += 1
                i += 1
                continue
        m = _REPLACE.search(pre)
        if m and i + 2 < len(lits) and _COMMA.fullmatch(text[lit.end:lits[i + 1].start]) \
                and _COMMA.fullmatch(text[lits[i + 1].end:lits[i + 2].start]):
            cm = re.match(r"\s*\)", text[lits[i + 2].end:])
            old = lits[i + 1].value
            if cm and old:
                out.append(text[pos:lit.start - (len(pre) - m.start())])
                out.append(quote(lit.value.replace(old, lits[i + 2].value), LANG))
                pos = lits[i + 2].end + cm.end()
                stats["replace"] += 1
                i += 3
                continue
        i += 1
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


def normalize(text: str, stats: Counter, budget: Budget) -> str:
    t = _sub_chr(text, stats)
    for _ in range(4):
        if budget.expired():
            break
        before = t
        t = fold_concat(t, LANG, stats)
        t = _literal_funcs(t, stats)
        if t == before:
            break
    return t


def extract(raw: str, norm: str, budget: Budget) -> list[Layer]:
    layers: list[Layer] = []
    layers += decode_encoded_blocks(raw, budget, LANG)
    layers += ps_encoded_commands(norm, budget)
    lits = list(iter_literals(norm, LANG, min_len=8))
    for lit in lits:
        if len(layers) > 48 or budget.expired():
            break
        pre = norm[max(0, lit.start - 40):lit.start]
        m = _EXEC.search(pre)
        if not m or len(lit.value) < 16:
            continue
        kw = m.group(0).lower()
        lang = LANG if ("execute" in kw or "eval" in kw) else "batch"
        layers.append(Layer(f"vbs-{'execute' if lang == LANG else 'run'}-literal",
                            lit.value.encode("utf-8", "replace"), lang, "text", lang, excerpt(lit.raw)))
    layers += encoded_literals(lits, budget, LANG, min_len=24)
    layers += numeric_arrays(norm, budget, LANG)
    return layers

"""PHP / Perl / Ruby de-obfuscation (decoder chains, chr() folding, variable indirection)."""
from __future__ import annotations

import re
from collections import Counter

from .chains import resolve
from .generic import classify_layer, encoded_literals, numeric_arrays
from .primitives import Budget, Layer, excerpt
from .textops import fold_concat, iter_literals, literal_map, quote, render_literals

_CHR = {
    "php": re.compile(r"(?i)\bchr\s*\(\s*(0x[0-9a-f]{1,4}|\d{1,5})\s*\)"),
    "perl": re.compile(r"\bchr\s*\(?\s*(0x[0-9a-fA-F]{1,4}|\d{1,5})\s*\)?"),
    "ruby": re.compile(r"\b(0x[0-9a-fA-F]{1,4}|\d{1,5})\.chr\b"),
}


def normalize(text: str, lang: str, stats: Counter, budget: Budget) -> str:
    t = text
    rx = _CHR.get(lang)
    if rx is not None and "chr" in t:
        def rep(m: re.Match) -> str:
            try:
                v = int(m.group(1), 0)
                stats["charcode"] += 1
                return quote(chr(v), lang)
            except (ValueError, OverflowError):
                return m.group(0)
        t = rx.sub(rep, t)
    for _ in range(3):
        if budget.expired():
            break
        before = t
        t = fold_concat(t, lang, stats)
        if t == before:
            break
    return render_literals(t, lang, stats)


def _chain(norm: str, start: int, end: int, value: bytes, lang: str, budget: Budget, src: str) -> Layer | None:
    r = resolve(norm, start, end, value)
    if not r:
        return None
    steps, data, sink, has_sink = r
    if steps[-1] in ("marshal", "pickle"):
        return None
    lay = classify_layer(f"{lang}-" + ">".join(steps), data, budget, sink or lang, src, need_code=not has_sink)
    if lay is not None:
        lay.meta["sink"] = bool(has_sink)
    return lay


def extract(raw: str, norm: str, lang: str, budget: Budget) -> list[Layer]:
    layers: list[Layer] = []
    lits = list(iter_literals(norm, lang, min_len=12))
    used: set[int] = set()
    for lit in lits:
        if budget.expired() or len(layers) > 48:
            break
        lay = _chain(norm, lit.start, lit.end, lit.value.encode("latin-1", "replace"), lang, budget, lit.raw)
        if lay:
            used.add(lit.start)
            layers.append(lay)
    if not budget.expired() and ("$" in norm or lang == "ruby"):
        for name, val in list(literal_map(norm, lang, min_len=24).items())[:64]:
            sigil = r"\$" if lang in ("php", "perl") else r"\b"
            for m in re.finditer(r"\(\s*" + sigil + re.escape(name) + r"\s*\)", norm):
                lay = _chain(norm, m.start() + 1, m.end() - 1, val.encode("latin-1", "replace"), lang, budget, val[:80])
                if lay:
                    layers.append(lay)
                    break
    # eval('<code>') with a plain literal
    for lit in lits:
        if len(lit.value) >= 24 and re.search(r"(?i)(?:\beval|\bassert|\bcreate_function\s*\([^)]{0,40},)\s*\(?\s*$",
                                             norm[max(0, lit.start - 60):lit.start]):
            layers.append(Layer(f"{lang}-eval-literal", lit.value.encode("utf-8", "replace"), lang, "text", lang,
                                excerpt(lit.raw)))
    rest = [lit for lit in lits if lit.start not in used]
    layers += encoded_literals(rest, budget, lang, min_len=40)
    layers += numeric_arrays(norm, budget, lang)
    return layers

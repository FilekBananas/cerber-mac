"""PowerShell normalisation and payload extraction (never executes anything)."""
from __future__ import annotations

import re
from collections import Counter

from .generic import classify_layer, encoded_literals, numeric_arrays, ps_encoded_commands, xor_try
from .primitives import Budget, Layer, b64decode_loose, bytes_to_text, excerpt
from .textops import fold_concat, iter_literals, literal_map, quote

LANG = "powershell"

_TICK = re.compile(r"`(?![nrt0abfv\"'`$\r\n])")
_CHAR = re.compile(r"(?i)\[char\][ \t]*\(?[ \t]*(0x[0-9a-f]{1,4}|\d{1,5})(?:[ \t]*\))?")
_CHAR_ARR = re.compile(r"(?i)\[char\[\]\]\s*\(\s*((?:(?:0x[0-9a-f]{1,4}|\d{1,5})\s*,\s*){0,4000}(?:0x[0-9a-f]{1,4}|\d{1,5}))\s*\)")
_FMT_SEP = re.compile(r"\s*-f\s*")
_ARG_SEP = re.compile(r"\s*,\s*")
_REV_IDX = re.compile(r"\s*\[\s*-1\s*\.\.\s*-?\(?\s*[\w$.:+\- ]{1,60}\)?\s*\]")
_JOIN_LIST = re.compile(r"(?i)-join\s*\(\s*$")
_REPLACE_M = re.compile(r"(?i)\s*\.replace\s*\(\s*$|\s*-c?replace\s*$")
_FROMB64 = re.compile(r"(?i)frombase64string\s*\(\s*")
_GETSTRING = re.compile(r"(?i)(?:\[(?:system\.)?text\.encoding\]::(\w+)|(?:new-object\s+)?(?:system\.)?text\.(\w+)encoding)\s*\)?\s*\.getstring\s*\(\s*(?:\[(?:system\.)?convert\]::)?frombase64string\s*\(\s*$")
_IEX_LIT = re.compile(r"(?i)(?:\biex\b|invoke-expression|\[scriptblock\]::create|\.invokecommand\.invokescript)\s*\(?\s*$")
_BXOR = re.compile(r"(?i)-bxor\s*\(?\s*(0x[0-9a-f]{1,2}|\d{1,3})\b")
_REGEX_META = re.compile(r"[\\.^$*+?{}\[\]|()]")


def _fmt(fmt: str, args: list[str]) -> str | None:
    def rep(m: re.Match) -> str:
        i = int(m.group(1))
        if i >= len(args):
            raise IndexError
        return args[i]
    try:
        return re.sub(r"\{(\d{1,3})(?:,[-\d]+)?(?::[^}]*)?\}", rep, fmt).replace("{{", "{").replace("}}", "}")
    except IndexError:
        return None


def _literal_ops(text: str, stats: Counter) -> str:
    """-f format operator, -join lists, reversal indexing, .Replace() on literals."""
    lits = list(iter_literals(text, LANG))
    if not lits:
        return text
    out: list[str] = []
    pos = 0
    i = 0
    n = len(lits)
    while i < n:
        lit = lits[i]
        # "{1}{0}" -f 'a','b'
        if "{" in lit.value and i + 1 < n and _FMT_SEP.fullmatch(text[lit.end:lits[i + 1].start]):
            args = [lits[i + 1].value]
            j = i + 1
            while j + 1 < n and _ARG_SEP.fullmatch(text[lits[j].end:lits[j + 1].start]) and len(args) < 200:
                j += 1
                args.append(lits[j].value)
            r = _fmt(lit.value, args)
            if r is not None:
                stats["format"] += 1
                out.append(text[pos:lit.start])
                out.append(quote(r, LANG))
                pos = lits[j].end
                i = j + 1
                continue
        # -join ('a','b','c')
        pre = text[max(0, lit.start - 20):lit.start]
        if _JOIN_LIST.search(pre) and i + 1 < n and _ARG_SEP.fullmatch(text[lit.end:lits[i + 1].start]):
            vals = [lit.value]
            j = i
            while j + 1 < n and _ARG_SEP.fullmatch(text[lits[j].end:lits[j + 1].start]) and len(vals) < 20000:
                j += 1
                vals.append(lits[j].value)
            stats["join"] += 1
            out.append(text[pos:lit.start])
            out.append(quote("".join(vals), LANG))
            pos = lits[j].end
            i = j + 1
            continue
        # 'txet'[-1..-4]  -> reversed
        m = _REV_IDX.match(text, lit.end)
        if m and len(lit.value) > 1:
            stats["reverse"] += 1
            out.append(text[pos:lit.start])
            out.append(quote(lit.value[::-1], LANG))
            pos = m.end()
            i += 1
            continue
        # 'xAyB'.Replace('x','') / -replace 'x',''
        if i + 2 < n:
            gap = text[lit.end:lits[i + 1].start]
            if _REPLACE_M.fullmatch(gap) and _ARG_SEP.fullmatch(text[lits[i + 1].end:lits[i + 2].start]):
                old, new = lits[i + 1].value, lits[i + 2].value
                is_regex = "-" in gap
                if old and (not is_regex or not _REGEX_META.search(old)):
                    stats["replace"] += 1
                    out.append(text[pos:lit.start])
                    out.append(quote(lit.value.replace(old, new), LANG))
                    end = lits[i + 2].end
                    if not is_regex and text[end:end + 12].lstrip().startswith(")"):
                        end = text.index(")", end) + 1
                    pos = end
                    i += 3
                    continue
        i += 1
    if pos == 0:
        return text
    out.append(text[pos:])
    return "".join(out)


def _inline_getstring(text: str, stats: Counter) -> str:
    """[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('...')) -> 'decoded'."""
    if "getstring" not in text.lower():
        return text
    lits = list(iter_literals(text, LANG, min_len=4))
    out: list[str] = []
    pos = 0
    for lit in lits:
        pre = text[max(0, lit.start - 160):lit.start]
        m = _GETSTRING.search(pre)
        if not m:
            continue
        data = b64decode_loose(lit.value)
        if not data:
            continue
        enc = (m.group(1) or m.group(2) or "").lower()
        try:
            s = data.decode("utf-16-le") if enc == "unicode" else data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if not s or len(s) > 4096 or any(ord(c) < 9 for c in s):
            continue
        close = re.match(r"\s*\)\s*\)", text[lit.end:])
        if not close:
            continue
        start = lit.start - (len(pre) - m.start())
        out.append(text[pos:start])
        out.append(quote(s, LANG))
        pos = lit.end + close.end()
        stats["b64inline"] += 1
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


def normalize(text: str, stats: Counter, budget: Budget) -> str:
    t = text
    n_ticks = t.count("`")
    if n_ticks:
        t2 = _TICK.sub("", t)
        removed = len(t) - len(t2)
        if removed:
            stats["backtick"] += removed
        t = t2
    t = _CHAR_ARR.sub(lambda m: _chars(m.group(1), stats), t)
    t = _CHAR.sub(lambda m: _chars(m.group(1), stats), t)
    for _ in range(4):
        if budget.expired():
            break
        before = t
        t = fold_concat(t, LANG, stats)
        t = _literal_ops(t, stats)
        t = _inline_getstring(t, stats)
        if t == before:
            break
    return t


def _chars(nums: str, stats: Counter) -> str:
    out = []
    for tok in re.split(r"\s*,\s*", nums.strip()):
        try:
            v = int(tok, 16) if tok.lower().startswith("0x") else int(tok)
            out.append(chr(v))
        except (ValueError, OverflowError):
            return nums
    stats["charcode"] += len(out)
    return quote("".join(out), LANG)


def extract(raw: str, norm: str, budget: Budget) -> list[Layer]:
    layers: list[Layer] = []
    layers += ps_encoded_commands(norm, budget)
    if norm != raw:
        layers += ps_encoded_commands(raw, budget)
    low = norm.lower()
    vars_ = literal_map(norm, LANG, min_len=16) if "$" in norm else {}
    xor_keys = [bytes([int(k, 16) if k.lower().startswith("0x") else int(k) & 0xFF])
                for k in dict.fromkeys(m.group(1) for m in _BXOR.finditer(norm))][:4]
    lits = list(iter_literals(norm, LANG, min_len=8))
    # FromBase64String(<literal>) / FromBase64String($var)
    if "frombase64string" in low:
        for m in _FROMB64.finditer(norm):
            if budget.expired() or len(layers) > 48:
                break
            rest = norm[m.end():m.end() + 16]
            blob = None
            vm = re.match(r"\$\{?([\w:]+)\}?\s*\)", rest)
            if vm:
                blob = vars_.get(vm.group(1).lower())
            else:
                for lit in lits:
                    if lit.start == m.end():
                        blob = lit.value
                        break
            if not blob:
                continue
            data = b64decode_loose(blob)
            if not data:
                continue
            ctx = low[max(0, m.start() - 400):m.end() + len(blob) + 400]
            deflate = "deflatestream" in ctx or "deflate" in ctx
            lay = classify_layer("ps-frombase64", data, budget, LANG, blob, raw_deflate=deflate, need_code=False)
            if lay is None and xor_keys:
                lay = xor_try(data, xor_keys, budget, LANG, "ps-frombase64", blob)
            if lay is None and len(data) >= 64:
                # still worth handing to the signature engines (shellcode, encrypted stage)
                lay = Layer("ps-frombase64-raw", data, None, "binary", "binary", excerpt(blob))
            if lay:
                layers.append(lay)
    # iex '<code>' / [ScriptBlock]::Create('<code>')
    for lit in lits:
        if len(lit.value) < 16:
            continue
        if _IEX_LIT.search(norm[max(0, lit.start - 40):lit.start]):
            layers.append(Layer("ps-iex-literal", lit.value.encode("utf-8", "replace"), LANG, "text", "powershell",
                                excerpt(lit.raw)))
    layers += encoded_literals(lits, budget, LANG, min_len=24)
    layers += numeric_arrays(norm, budget, LANG)
    return layers


def text_view(data: bytes) -> str | None:
    return bytes_to_text(data)

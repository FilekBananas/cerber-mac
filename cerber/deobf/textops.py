"""Language-aware text normalisation: comment stripping, string-literal tokenising and
constant folding of concatenated literals ('a'+'b', "a" & "b", 'a'.'b', ...).

All regexes here are linear (no nested unbounded quantifiers over overlapping classes).
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from .primitives import unescape_backslash

# --------------------------------------------------------------------------- comments

_HASH_LINE = re.compile(r"(?m)^[ \t]*#(?!!).*$")                 # shell/python/ruby/perl/ps
_SLASH_LINE = re.compile(r"(?m)^[ \t]*//.*$")                    # js/php
_VBS_LINE = re.compile(r"(?im)^[ \t]*(?:'|rem\b).*$")
_BAT_LINE = re.compile(r"(?im)^[ \t]*@?(?:rem\b|::).*$")
_AS_LINE = re.compile(r"(?m)^[ \t]*(?:--|#).*$")
_POD_OPEN = re.compile(r"^=(?:pod|head\d|over|item|begin|for|encoding)\b")


def _strip_line_blocks(text: str, is_open, is_close) -> str:
    """Line-based state machine (linear) for POD / =begin..=end blocks."""
    if "\n=" not in text and not text.startswith("="):
        return text
    out = []
    inside = False
    for line in text.splitlines(keepends=True):
        if not inside and is_open(line):
            inside = True
        if inside:
            out.append("\n" if line.endswith("\n") else "")
            if is_close(line):
                inside = False
            continue
        out.append(line)
    return "".join(out)


def _strip_blocks(text: str, start: str, end: str, line_start: bool = True, limit: int = 20000) -> str:
    """Remove start..end block comments. With line_start only blocks whose opener is the first
    non-blank token of a line are removed (avoids eating code after "image/*" strings)."""
    if start not in text:
        return text
    out = []
    pos = 0
    n = 0
    while n < limit:
        i = text.find(start, pos)
        if i < 0:
            break
        if line_start:
            ls = text.rfind("\n", 0, i) + 1
            if text[ls:i].strip():
                out.append(text[pos:i + len(start)])
                pos = i + len(start)
                n += 1
                continue
        j = text.find(end, i + len(start))
        if j < 0:
            break
        out.append(text[pos:i])
        # keep line structure so that line-based rules still line up
        out.append("\n" * text.count("\n", i, j))
        pos = j + len(end)
        n += 1
    out.append(text[pos:])
    return "".join(out)


def strip_comments(text: str, lang: str) -> str:
    """Drop comment-only lines/blocks. Code on the same line as a comment is kept."""
    try:
        if lang in ("shell", "python", "ruby", "perl"):
            first_nl = text.find("\n")
            head = text[:first_nl + 1] if text.startswith("#!") and first_nl > 0 else ""
            body = text[len(head):]
            if lang == "perl":
                body = _strip_line_blocks(body, lambda ln: bool(_POD_OPEN.match(ln)),
                                          lambda ln: ln.startswith("=cut"))
            if lang == "ruby":
                body = _strip_line_blocks(body, lambda ln: ln.startswith("=begin"),
                                          lambda ln: ln.startswith("=end"))
            return head + _HASH_LINE.sub("", body)
        if lang == "powershell":
            return _HASH_LINE.sub("", _strip_blocks(text, "<#", "#>"))
        if lang in ("javascript", "php"):
            t = _strip_blocks(text, "/*", "*/")
            t = _SLASH_LINE.sub("", t)
            if lang == "php":
                t = _HASH_LINE.sub("", t)
            return t
        if lang == "vbs":
            return _VBS_LINE.sub("", text)
        if lang == "batch":
            return _BAT_LINE.sub("", text)
        if lang == "applescript":
            return _AS_LINE.sub("", _strip_blocks(text, "(*", "*)"))
    except Exception:
        return text
    return text


# --------------------------------------------------------------------------- literals

@dataclass
class Lit:
    start: int
    end: int
    value: str
    quote: str
    raw: str


_LIT_RX: dict[str, re.Pattern[str]] = {
    "javascript": re.compile(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"|`(?:[^`\\]|\\.)*`", re.S),
    "powershell": re.compile(r"'(?:[^']|'')*'|\"(?:[^\"`]|`.|\"\")*\"", re.S),
    "vbs": re.compile(r"\"(?:[^\"\n]|\"\")*\""),
    "python": re.compile(r"(?i)(?:(?<![\w])[rbuf]{1,2})?(?:'''.*?'''|\"\"\".*?\"\"\"|'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\")", re.S),
    "php": re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", re.S),
    "perl": re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", re.S),
    "ruby": re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", re.S),
    "shell": re.compile(r"\$'(?:[^'\\]|\\.)*'|'[^']*'|\"(?:[^\"\\]|\\.)*\"", re.S),
    "applescript": re.compile(r"\"(?:[^\"\\]|\\.)*\""),
    "batch": re.compile(r"\"[^\"\n]*\""),
}
_LIT_RX["html"] = _LIT_RX["javascript"]

# operator between two literals that concatenates them
_CONCAT_SEP: dict[str, re.Pattern[str]] = {
    "javascript": re.compile(r"\s*\+\s*"),
    "powershell": re.compile(r"\s*\+\s*"),
    "python": re.compile(r"\s*\+?\s*"),
    "vbs": re.compile(r"\s*[&+]\s*(?:_\s*\r?\n\s*)?"),
    "php": re.compile(r"\s*\.\s*"),
    "perl": re.compile(r"\s*\.\s*"),
    "ruby": re.compile(r"\s*\+\s*"),
    "applescript": re.compile(r"\s*&\s*"),
    "shell": re.compile(r""),            # adjacency: 'cu'"rl" == curl
}
_CONCAT_SEP["html"] = _CONCAT_SEP["javascript"]


def _lit_value(raw: str, lang: str) -> tuple[str, str]:
    """Return (quote, unescaped value) for a literal token."""
    if lang == "python":
        m = re.match(r"(?i)[rbuf]*", raw)
        prefix = m.group(0).lower() if m else ""
        body = raw[len(prefix):]
        q = body[:3] if body[:3] in ("'''", '"""') else body[:1]
        inner = body[len(q):-len(q)] if len(body) >= 2 * len(q) else ""
        return q, inner if "r" in prefix else unescape_backslash(inner)
    if lang == "powershell":
        if raw.startswith("@'") or raw.startswith('@"'):
            inner = raw[2:-2].strip(" \t\r\n")
            return raw[1], inner
        q = raw[0]
        inner = raw[1:-1]
        if q == "'":
            return q, inner.replace("''", "'")
        inner = inner.replace('""', '"')
        if "`" in inner:
            inner = re.sub(r"`(.)", lambda m: {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}.get(m.group(1), m.group(1)), inner)
        return q, inner
    if lang == "vbs":
        return '"', raw[1:-1].replace('""', '"')
    if lang == "batch":
        return '"', raw[1:-1]
    if lang == "shell":
        if raw.startswith("$'"):
            return "'", unescape_backslash(raw[2:-1])
        if raw[0] == "'":
            return "'", raw[1:-1]
        return '"', re.sub(r"\\([\"\\$`])", r"\1", raw[1:-1])
    if lang == "php" or lang == "perl":
        if raw[0] == "'":
            return "'", raw[1:-1].replace("\\'", "'").replace("\\\\", "\\")
        return '"', unescape_backslash(raw[1:-1])
    # javascript / ruby / applescript / html
    return raw[0], unescape_backslash(raw[1:-1])


_PS_HERE_OPEN = re.compile(r"@(['\"])[ \t]*\r?\n")
_PS_HERE_CLOSE = re.compile(r"\n(['\"])@")


def _ps_here_strings(text: str) -> list[tuple[int, int]]:
    """Pair here-string openers/closers in linear time."""
    if "@'" not in text and '@"' not in text:
        return []
    opens = [(m.start(), m.group(1)) for m in _PS_HERE_OPEN.finditer(text)]
    if not opens:
        return []
    closes = {"'": [], '"': []}
    for m in _PS_HERE_CLOSE.finditer(text):
        closes[m.group(1)].append(m.end())
    idx = {"'": 0, '"': 0}
    spans = []
    last_end = -1
    for pos, q in opens:
        if pos < last_end:
            continue
        lst = closes[q]
        i = idx[q]
        while i < len(lst) and lst[i] <= pos + 3:
            i += 1
        idx[q] = i
        if i >= len(lst):
            continue
        spans.append((pos, lst[i]))
        last_end = lst[i]
    return spans


def _ps_tokens(text: str):
    spans = _ps_here_strings(text)
    rx = _LIT_RX["powershell"]
    pos = 0
    for s, e in spans + [(len(text), len(text))]:
        for m in rx.finditer(text, pos, s):
            yield m.start(), m.end(), m.group(0)
        if s < e:
            yield s, e, text[s:e]
        pos = e


_PY_QUOTED = re.compile(r"'''.*?'''|\"\"\".*?\"\"\"|'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"", re.S)
_PY_PREFIX = set("rbufRBUF")
_WORD = re.compile(r"\w")


def _py_tokens(text: str):
    """Same tokens as _LIT_RX["python"], ~5x faster: the quoted part starts with a quote (the regex engine
    can skip to it), the optional r/b/u/f prefix of 1–2 letters not preceded by a word character is
    attached afterwards – exactly the leftmost match the combined pattern would have produced."""
    prev_end = 0
    for m in _PY_QUOTED.finditer(text):
        s = m.start()
        start = s
        if s - 1 >= prev_end and text[s - 1] in _PY_PREFIX:
            if s - 2 >= prev_end and text[s - 2] in _PY_PREFIX:
                if s - 3 < 0 or not _WORD.match(text[s - 3]):
                    start = s - 2
            elif s - 2 < 0 or not _WORD.match(text[s - 2]):
                start = s - 1
        prev_end = m.end()
        yield start, m.end(), text[start:m.end()]


def iter_literals(text: str, lang: str, min_len: int = 0, limit: int = 200000):
    if lang == "powershell":
        toks = _ps_tokens(text)
    elif lang == "python":
        toks = _py_tokens(text)
    else:
        rx = _LIT_RX.get(lang) or _LIT_RX["javascript"]
        toks = ((m.start(), m.end(), m.group(0)) for m in rx.finditer(text))
    n = 0
    for start, end, raw in toks:
        if len(raw) - 2 < min_len:
            continue
        try:
            q, val = _lit_value(raw, lang)
        except Exception:
            continue
        yield Lit(start, end, val, q, raw)
        n += 1
        if n >= limit:
            return


def quote(value: str, lang: str = "javascript") -> str:
    """Render a value as a (re-tokenisable) literal of the given language."""
    if lang == "vbs" or lang == "batch":
        return '"' + value.replace('"', '""').replace("\n", " ") + '"'
    if lang == "powershell":
        return "'" + value.replace("'", "''") + "'"
    if lang == "shell":
        return "'" + value.replace("'", "'\\''") + "'"
    v = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return '"' + v + '"'


def fold_concat(text: str, lang: str, stats: Counter | None = None, max_len: int = 8 << 20) -> str:
    """Fold chains of literal concatenations into one literal."""
    if stats is None:
        stats = Counter()
    sep = _CONCAT_SEP.get(lang)
    if sep is None or len(text) > max_len:
        return text
    lits = list(iter_literals(text, lang))
    if len(lits) < 2:
        return text
    out: list[str] = []
    pos = 0
    i = 0
    n = len(lits)
    while i < n:
        j = i
        vals = [lits[i].value]
        while j + 1 < n:
            gap = text[lits[j].end:lits[j + 1].start]
            if len(gap) > 40 or not sep.fullmatch(gap):
                break
            if lang == "python" and not gap.strip() and "\n" in gap:
                break  # implicit concatenation across lines is rare in obfuscation, avoid noise
            if lang == "shell" and gap:
                break
            j += 1
            vals.append(lits[j].value)
        if j > i:
            stats["concat"] += j - i
            stats["concat_frag_len"] += sum(len(v) for v in vals)
            out.append(text[pos:lits[i].start])
            out.append(quote("".join(vals), lang))
            pos = lits[j].end
        i = j + 1
    out.append(text[pos:])
    return "".join(out)


def render_literals(text: str, lang: str, stats: Counter | None = None, max_len: int = 8 << 20) -> str:
    """Replace escaped literals by their decoded value (final, human/rule readable view)."""
    if len(text) > max_len or "\\" not in text and "`" not in text:
        return text
    out: list[str] = []
    pos = 0
    changed = 0
    for lit in iter_literals(text, lang):
        if "\\" not in lit.raw and "`" not in lit.raw:
            continue
        if lit.value == lit.raw[1:-1]:
            continue
        out.append(text[pos:lit.start])
        out.append(lit.quote + lit.value + lit.quote)
        pos = lit.end
        changed += 1
    if not changed:
        return text
    if stats is not None:
        stats["escapes"] += changed
    out.append(text[pos:])
    return "".join(out)


def literal_map(text: str, lang: str, min_len: int = 1, limit: int = 5000) -> dict[str, str]:
    """Very small constant propagation: `$x = 'lit'`, `x = "lit"`, `var x = 'lit'`,
    `Dim x: x = "lit"`, `x='lit'` (shell). Last assignment wins."""
    out: dict[str, str] = {}
    if lang == "powershell":
        rx = re.compile(r"\$\{?([\w:]{1,64})\}?\s*=\s*(?=['\"@])")
    elif lang == "shell":
        rx = re.compile(r"(?m)(?:^|[;&|]\s*|\bexport\s+|\blocal\s+|\breadonly\s+)([A-Za-z_]\w{0,63})=(?=['\"$]|[^\s;&|'\"$`()<>]{1,4096}(?:$|[\s;&|]))")
    elif lang == "vbs":
        rx = re.compile(r"(?im)(?:^|:)\s*(?:set\s+|const\s+)?([A-Za-z_]\w{0,63})\s*=\s*(?=\")")
    elif lang == "php" or lang == "perl":
        rx = re.compile(r"[$@]([A-Za-z_]\w{0,63})\s*=\s*(?=['\"])")
    else:
        rx = re.compile(r"(?:\b(?:var|let|const)\s+)?\b([A-Za-z_$][\w$]{0,63})\s*=\s*(?=[rRbBuUfF]{0,2}['\"`])")
    lrx = _LIT_RX.get(lang) or _LIT_RX["javascript"]
    bare = re.compile(r"[^\s;&|'\"$`()<>]{1,4096}")
    for m in rx.finditer(text):
        lm = lrx.match(text, m.end())
        if not lm and lang == "shell":
            bm = bare.match(text, m.end())
            if bm and len(bm.group(0)) >= min_len and len(out) < limit:
                out[m.group(1)] = bm.group(0)
            continue
        if not lm:
            continue
        # the literal must end the statement (no further concatenation/call)
        tail = text[lm.end():lm.end() + 3]
        if tail[:1] not in ("", "\n", "\r", ";", ")", " ", "\t", ",") or tail.lstrip(" \t")[:1] in ("+", ".", "&", "["):
            continue
        try:
            _, val = _lit_value(lm.group(0), lang)
        except Exception:
            continue
        if len(val) >= min_len:
            key = m.group(1).lower() if lang in ("powershell", "vbs") else m.group(1)
            out[key] = val
            if len(out) >= limit:
                break
    return out


def literal_at(text: str, pos: int, lang: str) -> Lit | None:
    """The string literal starting exactly at `pos` (after optional blanks), or None."""
    while pos < len(text) and text[pos] in " \t":
        pos += 1
    if lang == "powershell" and text.startswith(("@'", '@"'), pos):
        for s, e in _ps_here_strings(text[pos:pos + (4 << 20)]):
            if s == 0:
                raw = text[pos:pos + e]
                q, v = _lit_value(raw, lang)
                return Lit(pos, pos + e, v, q, raw)
            break
        return None
    rx = _LIT_RX.get(lang) or _LIT_RX["javascript"]
    m = rx.match(text, pos)
    if not m:
        return None
    try:
        q, v = _lit_value(m.group(0), lang)
    except Exception:
        return None
    return Lit(m.start(), m.end(), v, q, m.group(0))

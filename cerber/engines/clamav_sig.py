"""ClamAV body-signature language: hex patterns, offsets and PCRE subsignatures.

A hex signature is parsed into tokens, split into *segments* at unbounded
gaps (`*`, `{n-}`) and every segment is turned into a bounded Python bytes
regex. Matching a multi-segment pattern is a sequential search (segment i+1
must start after segment i ends + min gap), which avoids the catastrophic
backtracking a single `.*?` regex would have on large files.

The engine only verifies a pattern when the Aho-Corasick prefilter found its
*anchor* (the most selective literal run), so the regexes run rarely.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

INF = 1 << 60
ALNUM = b"A-Za-z0-9"


class SigError(ValueError):
    pass


# --------------------------------------------------------------------------- tokens
# token kinds: ("lit", bytes) ("any", n) ("nib_hi", v) ("nib_lo", v) ("gap", lo, hi)
#              ("alt", [bytes|regexfrag...], neg) ("bound", "B"|"L"|"W")

_HEX = set(b"0123456789abcdefABCDEF")


def tokenize(sig: str) -> list[tuple]:
    s = sig.strip()
    i, n = 0, len(s)
    toks: list[tuple] = []
    lit = bytearray()

    def flush():
        if lit:
            toks.append(("lit", bytes(lit)))
            lit.clear()

    while i < n:
        c = s[i]
        if c in "0123456789abcdefABCDEF?":
            if i + 1 >= n:
                raise SigError("odd hex length")
            a, b = s[i], s[i + 1]
            if a == "?" and b == "?":
                flush()
                toks.append(("any", 1))
            elif a == "?":
                if b not in "0123456789abcdefABCDEF":
                    raise SigError(f"bad nibble {a}{b}")
                flush()
                toks.append(("nib_lo", int(b, 16)))
            elif b == "?":
                if a not in "0123456789abcdefABCDEF":
                    raise SigError(f"bad nibble {a}{b}")
                flush()
                toks.append(("nib_hi", int(a, 16)))
            else:
                if a not in "0123456789abcdefABCDEF" or b not in "0123456789abcdefABCDEF":
                    raise SigError(f"bad hex {a}{b}")
                lit.append(int(a + b, 16))
            i += 2
        elif c == "*":
            flush()
            toks.append(("gap", 0, INF))
            i += 1
        elif c == "{" or c == "[":
            close = "}" if c == "{" else "]"
            j = s.find(close, i)
            if j < 0:
                raise SigError("unclosed jump")
            body = s[i + 1:j]
            flush()
            if "-" in body:
                lo_s, hi_s = body.split("-", 1)
                lo = int(lo_s) if lo_s else 0
                hi = int(hi_s) if hi_s else INF
            else:
                lo = hi = int(body)
            if lo > hi:
                raise SigError("bad jump range")
            toks.append(("gap", lo, hi))
            i = j + 1
        elif c == "(" or (c == "!" and i + 1 < n and s[i + 1] == "("):
            neg = c == "!"
            if neg:
                i += 1
            j = s.find(")", i)
            if j < 0:
                raise SigError("unclosed group")
            body = s[i + 1:j]
            flush()
            if body in ("B", "L", "W"):
                toks.append(("bound", body))
            else:
                alts = []
                for alt in body.split("|"):
                    if not alt or len(alt) % 2:
                        raise SigError("bad alternative")
                    alts.append(tokenize(alt))
                toks.append(("alt", alts, neg))
            i = j + 1
        elif c in " \t\r\n":
            i += 1
        else:
            raise SigError(f"unexpected {c!r}")
    flush()
    if not toks:
        raise SigError("empty")
    return toks


def widen(toks: list[tuple]) -> list[tuple]:
    """::w — every byte becomes byte + NUL (UTF-16LE of ASCII)."""
    out = []
    for t in toks:
        k = t[0]
        if k == "lit":
            out.append(("lit", bytes(b for ch in t[1] for b in (ch, 0))))
        elif k in ("any", "nib_hi", "nib_lo"):
            out.append(t)
            out.append(("lit", b"\x00"))
        elif k == "gap":
            out.append(("gap", t[1] * 2, t[2] * 2 if t[2] < INF else INF))
        elif k == "alt":
            out.append(("alt", [widen(a) for a in t[1]], t[2]))
        else:
            out.append(t)
    # merge adjacent literals
    merged: list[tuple] = []
    for t in out:
        if t[0] == "lit" and merged and merged[-1][0] == "lit":
            merged[-1] = ("lit", merged[-1][1] + t[1])
        else:
            merged.append(t)
    return merged


# --------------------------------------------------------------------------- regex building

def _esc(b: bytes) -> bytes:
    return b"".join(b"\\x%02x" % x for x in b)


def _tok_len(t: tuple) -> tuple[int, int]:
    k = t[0]
    if k == "lit":
        return len(t[1]), len(t[1])
    if k in ("any", "nib_hi", "nib_lo"):
        return 1, 1
    if k == "gap":
        return t[1], t[2]
    if k == "alt":
        lens = [_seq_len(a) for a in t[1]]
        return min(x[0] for x in lens), max(x[1] for x in lens)
    return 0, 0


def _seq_len(toks: list[tuple]) -> tuple[int, int]:
    lo = hi = 0
    for t in toks:
        a, b = _tok_len(t)
        lo += a
        hi = INF if (hi >= INF or b >= INF) else hi + b
    return lo, hi


def _rx(toks: list[tuple], pos_first: bool, pos_last: bool) -> bytes:
    parts = []
    last = len(toks) - 1
    for idx, t in enumerate(toks):
        k = t[0]
        if k == "lit":
            parts.append(_esc(t[1]))
        elif k == "any":
            parts.append(b"." if t[1] == 1 else b".{%d}" % t[1])
        elif k == "nib_hi":
            v = t[1] << 4
            parts.append(b"[\\x%02x-\\x%02x]" % (v, v | 0xF))
        elif k == "nib_lo":
            parts.append(b"[" + b"".join(b"\\x%02x" % ((h << 4) | t[1]) for h in range(16)) + b"]")
        elif k == "gap":
            lo, hi = t[1], t[2]
            parts.append(b".{%d,}" % lo if hi >= INF else (b".{%d}" % lo if lo == hi else b".{%d,%d}" % (lo, hi)))
        elif k == "alt":
            alts, neg = t[1], t[2]
            if not neg:
                parts.append(b"(?:" + b"|".join(_rx(a, False, False) for a in alts) + b")")
            else:
                lens = {_seq_len(a) for a in alts}
                if len(lens) != 1 or next(iter(lens))[0] != next(iter(lens))[1]:
                    raise SigError("negated alternatives of unequal length")
                ln = next(iter(lens))[0]
                if ln == 1 and all(a[0][0] == "lit" for a in alts):
                    parts.append(b"[^" + b"".join(_esc(a[0][1]) for a in alts) + b"]")
                else:
                    parts.append(b"(?!(?:" + b"|".join(_rx(a, False, False) for a in alts) + b"))" +
                                 (b"." if ln == 1 else b".{%d}" % ln))
        elif k == "bound":
            kind = t[1]
            at_start = idx == 0 and pos_first
            at_end = idx == last and pos_last
            if kind in ("B", "W"):
                if at_start:
                    parts.append(b"(?<![" + ALNUM + b"])")
                elif at_end:
                    parts.append(b"(?![" + ALNUM + b"])")
                else:
                    parts.append(b"(?:(?<![" + ALNUM + b"])|(?![" + ALNUM + b"]))")
            else:  # L
                if at_start:
                    parts.append(b"(?:(?<=[\\r\\n])|(?<![\\s\\S]))")
                else:
                    parts.append(b"(?=[\\r\\n]|(?![\\s\\S]))")
    return b"".join(parts)


# --------------------------------------------------------------------------- offsets

@dataclass(frozen=True)
class Offset:
    kind: str          # any | abs | ep | sec | last | se | eof
    base: int = 0      # n for abs/ep/sec/last/eof (eof: distance back from end)
    shift: int = 0     # ",m" maximum shift
    sec: int = 0       # section index for sec/se


_OFF_RE = re.compile(r"^(?:(EP)([+-]\d+)|S(\d+)\+(\d+)|(SL)\+(\d+)|SE(\d+)|(EOF)-(\d+)|(\d+))(?:,(\d+))?$")


def parse_offset(s: str) -> Offset:
    s = s.strip()
    if s in ("*", ""):
        return Offset("any")
    m = _OFF_RE.match(s)
    if not m:
        raise SigError(f"unsupported offset {s}")
    shift = int(m.group(11)) if m.group(11) else 0
    if m.group(1):
        return Offset("ep", int(m.group(2)), shift)
    if m.group(3):
        return Offset("sec", int(m.group(4)), shift, int(m.group(3)))
    if m.group(5):
        return Offset("last", int(m.group(6)), shift)
    if m.group(7):
        return Offset("se", 0, 0, int(m.group(7)))
    if m.group(8):
        return Offset("eof", int(m.group(9)), shift)
    return Offset("abs", int(m.group(10)), shift)


def resolve_offset(off: Offset, size: int, exe) -> tuple[int, int, int] | None:
    """-> (lo, hi, endpos) allowed pattern start range, or None when not applicable."""
    if off.kind == "any":
        return 0, size, size
    if off.kind == "abs":
        return off.base, off.base + off.shift, size
    if off.kind == "eof":
        lo = size - off.base
        return (lo, lo + off.shift, size) if lo >= 0 else None
    if exe is None:
        return None
    if off.kind == "ep":
        if exe.ep is None:
            return None
        lo = exe.ep + off.base
        return (lo, lo + off.shift, size) if lo >= 0 else None
    secs = exe.sections
    if off.kind == "sec":
        if off.sec >= len(secs):
            return None
        lo = secs[off.sec].raw_off + off.base
        return lo, lo + off.shift, size
    if off.kind == "last":
        if not secs:
            return None
        lo = secs[-1].raw_off + off.base
        return lo, lo + off.shift, size
    if off.kind == "se":
        if off.sec >= len(secs):
            return None
        s = secs[off.sec]
        return s.raw_off, s.raw_off + s.raw_size, min(size, s.raw_off + s.raw_size)
    return None


# --------------------------------------------------------------------------- compiled pattern

@dataclass
class Segment:
    rx: "re.Pattern[bytes] | None"
    min_len: int
    max_len: int
    gap_before: int    # minimal gap to the previous segment (unbounded max)


@dataclass
class Pattern:
    """A compiled hex pattern (one variant: ascii OR wide)."""
    segments: list[Segment]
    offset: Offset
    nocase: bool
    exact: bytes | None = None     # pure literal pattern without offset/boundaries
    anchor: bytes | None = None
    anchor_seg: int = 0
    pre_min: int = 0               # bytes from segment start to anchor start
    pre_max: int = 0
    fullword: bool = False
    _cache_key: int = field(default=0, repr=False)

    # --- matching -------------------------------------------------------------
    def _seq_search(self, view: bytes, start: int, end: int, first_lo: int | None = None,
                    first_hi: int | None = None) -> tuple[int, int] | None:
        """Sequential multi-segment search. Returns (start_of_first, end_of_last)."""
        pos = start
        seg0 = self.segments[0]
        while True:
            m = seg0.rx.search(view, pos, end)
            if not m:
                return None
            if first_hi is not None and m.start() > first_hi:
                return None
            s0, cur = m.start(), m.end()
            ok = True
            for seg in self.segments[1:]:
                m2 = seg.rx.search(view, cur + seg.gap_before, end)
                if not m2:
                    ok = False
                    break
                cur = m2.end()
            if ok:
                return s0, cur
            # later segments not found anywhere after this start -> no later start works either
            return None

    def count(self, view: bytes, exe, hits: list[int] | None, cap: int = 64) -> int:
        """Number of matches (capped). `hits` = anchor end positions (inclusive) or None."""
        size = len(view)
        rng = resolve_offset(self.offset, size, exe)
        if rng is None:
            return 0
        lo, hi, endpos = rng
        if self.offset.kind != "any":
            if lo > size:
                return 0
            if len(self.segments) == 1:
                rx = self.segments[0].rx
                if lo == hi:
                    return 1 if rx.match(view, lo, endpos) else 0
                m = rx.search(view, lo, min(endpos, hi + self.segments[0].max_len) if self.segments[0].max_len < INF else endpos)
                return 1 if (m and m.start() <= hi) else 0
            return 1 if self._seq_search(view, lo, endpos, lo, hi) else 0
        # floating pattern
        if len(self.segments) > 1 or hits is None or self.anchor is None:
            if len(self.segments) == 1:
                n = 0
                for _ in self.segments[0].rx.finditer(view):
                    n += 1
                    if n >= cap:
                        break
                return n
            n, pos = 0, 0
            while n < cap:
                r = self._seq_search(view, pos, size)
                if not r:
                    break
                n += 1
                pos = r[0] + 1
            return n
        seg = self.segments[0]
        alen = len(self.anchor)
        starts: set[int] = set()
        last_window_end = -1
        for e in hits:
            a = e - alen + 1                        # anchor start in view
            wlo = max(0, a - self.pre_max)
            if wlo < last_window_end and starts and max(starts) >= wlo:
                pass
            whi_start = a - self.pre_min           # latest possible pattern start
            if whi_start < 0:
                continue
            endp = min(size, whi_start + seg.max_len) if seg.max_len < INF else size
            m = seg.rx.search(view, wlo, endp)
            while m and m.start() <= whi_start:
                starts.add(m.start())
                if len(starts) >= cap:
                    return len(starts)
                m = seg.rx.search(view, m.start() + 1, endp)
            last_window_end = endp
        return len(starts)


def _literal_runs(toks: list[tuple]) -> list[tuple[int, bytes]]:
    """(token index, bytes) for every literal token (tokens are already merged)."""
    return [(i, t[1]) for i, t in enumerate(toks) if t[0] == "lit"]


_COMMON = [b"\x00\x00\x00\x00", b"\xff\xff\xff\xff", b"\x90\x90\x90\x90", b"\xcc\xcc\xcc\xcc",
           b"    ", b"\x20\x00\x20\x00", b"\x00\x00\x00\x01", b"\x01\x00\x00\x00"]


def anchor_score(b: bytes) -> float:
    if len(b) < 3:
        return -1
    distinct = len(set(b))
    score = min(len(b), 16) + distinct * 1.5
    zeros = b.count(0)
    score -= zeros * 0.6
    if distinct <= 1:
        score -= 12
    for c in _COMMON:
        if c in b:
            score -= 6
    return score


def best_window(b: bytes, maxlen: int = 16) -> bytes:
    if len(b) <= maxlen:
        return b
    best, best_s = b[:maxlen], -1e9
    step = 1 if len(b) < 512 else 4
    for i in range(0, len(b) - maxlen + 1, step):
        w = b[i:i + maxlen]
        s = anchor_score(w)
        if s > best_s:
            best, best_s = w, s
    return best


def compile_pattern(hexsig: str, offset: str = "*", nocase: bool = False, wide: bool = False,
                    fullword: bool = False, build_regex: bool = True) -> Pattern:
    toks = tokenize(hexsig)
    if wide:
        toks = widen(toks)
    if nocase:
        toks = [("lit", t[1].lower()) if t[0] == "lit" else t for t in toks]
    off = parse_offset(offset)
    if fullword:
        toks = [("bound", "B")] + toks + [("bound", "B")]
    # split into segments at unbounded gaps
    segs_toks: list[tuple[int, list[tuple]]] = []
    cur: list[tuple] = []
    gap_before = 0
    for t in toks:
        if t[0] == "gap" and t[2] >= INF:
            if cur:
                segs_toks.append((gap_before, cur))
                cur = []
                gap_before = t[1]
            else:
                gap_before += t[1]
            continue
        cur.append(t)
    if cur:
        segs_toks.append((gap_before, cur))
    if not segs_toks:
        raise SigError("pattern is only gaps")
    # leading gap of the first segment becomes part of it (".{n}" prefix)
    if segs_toks[0][0]:
        segs_toks[0] = (0, [("gap", segs_toks[0][0], segs_toks[0][0])] + segs_toks[0][1])
    flags = re.DOTALL | (re.IGNORECASE if nocase else 0)
    segments = []
    for si, (gb, st) in enumerate(segs_toks):
        lo, hi = _seq_len(st)
        rx = re.compile(_rx(st, si == 0, si == len(segs_toks) - 1), flags) if build_regex else None
        segments.append(Segment(rx, lo, hi, gb))
    pat = Pattern(segments, off, nocase, fullword=fullword)
    # exact literal?
    if len(toks) == 1 and toks[0][0] == "lit" and off.kind == "any" and not fullword:
        pat.exact = toks[0][1]
        pat.anchor = toks[0][1] if len(toks[0][1]) <= 64 else best_window(toks[0][1], 32)
        if pat.anchor is not toks[0][1] and pat.anchor != toks[0][1]:
            pat.exact = None      # long literal: anchor is a window, verify via regex
            idx = toks[0][1].find(pat.anchor)
            pat.pre_min = pat.pre_max = idx
        return pat
    # choose anchor among literal tokens of all segments
    best = None
    for si, (gb, st) in enumerate(segs_toks):
        pre_lo = pre_hi = 0
        for t in st:
            if t[0] == "lit":
                w = best_window(t[1])
                s = anchor_score(w)
                if best is None or s > best[0]:
                    k = t[1].find(w)
                    best = (s, w, si, pre_lo + k, (pre_hi + k) if pre_hi < INF else INF)
            a, b = _tok_len(t)
            pre_lo += a
            pre_hi = INF if (pre_hi >= INF or b >= INF) else pre_hi + b
    if best is not None and best[0] >= 2 and len(best[1]) >= 3:
        pat.anchor = best[1]
        pat.anchor_seg = best[2]
        pat.pre_min, pat.pre_max = best[3], best[4]
        if pat.pre_max >= INF:
            pat.pre_max = 1 << 20
    return pat


# --------------------------------------------------------------------------- PCRE subsigs

_PCRE_FLAGS = {"i": re.IGNORECASE, "s": re.DOTALL, "m": re.MULTILINE, "x": re.VERBOSE}


def compile_pcre(pattern: str, flags: str) -> "re.Pattern[bytes]":
    f = 0
    for ch in flags:
        f |= _PCRE_FLAGS.get(ch, 0)
    if "A" in flags:
        pattern = "(?:" + pattern + ")"
    pat = pattern.encode("latin-1")
    # PCRE syntax tweaks
    pat = pat.replace(b"(?<", b"(?P<") if b"(?<" in pat and not re.search(rb"\(\?<[=!]", pat) else pat
    try:
        return re.compile(pat, f)
    except re.error as exc:
        raise SigError(f"pcre: {exc}") from exc


def split_pcre_subsig(s: str) -> tuple[str, str, str, str] | None:
    """'[Offset:]Trigger/PCRE/Flags' -> (offset, trigger, pcre, flags)."""
    first = s.find("/")
    last = s.rfind("/")
    if first < 0 or last <= first:
        return None
    head, pcre, flags = s[:first], s[first + 1:last], s[last + 1:]
    if not re.fullmatch(r"[a-zA-Z]*", flags):
        return None
    offset = "*"
    trigger = head
    if ":" in head:
        offset, trigger = head.rsplit(":", 1)
    if not re.fullmatch(r"[0-9&|()=<>,]*", trigger):
        return None
    return offset, trigger, pcre, flags


# --------------------------------------------------------------------------- logical expressions

_TOK = re.compile(r"\d+|[&|()=<>,]")


def parse_expr(expr: str):
    toks = _TOK.findall(expr)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def primary():
        t = take()
        if t == "(":
            node = orexpr()
            if take() != ")":
                raise SigError("expected )")
        elif t.isdigit():
            node = ("sub", int(t))
        else:
            raise SigError(f"unexpected {t}")
        if peek() in ("=", ">", "<"):
            op = take()
            x = int(take())
            y = None
            if peek() == ",":
                take()
                y = int(take())
            node = ("cmp", op, x, y, node)
        return node

    def andexpr():
        node = primary()
        while peek() == "&":
            take()
            node = ("and", node, primary())
        return node

    def orexpr():
        node = andexpr()
        while peek() == "|":
            take()
            node = ("or", node, andexpr())
        return node

    tree = orexpr()
    if pos != len(toks):
        raise SigError("trailing tokens")
    return tree


def expr_needs_anchor(tree, anchored: dict[int, bool]) -> bool:
    """True when the expression can only be satisfied if at least one *anchored*
    subsignature matched – then the Aho-Corasick prefilter is a sound trigger."""
    def leaves(node, acc):
        if node[0] == "sub":
            acc.append(node[1])
        elif node[0] == "cmp":
            leaves(node[4], acc)
        else:
            leaves(node[1], acc)
            leaves(node[2], acc)
        return acc

    def needs(node) -> bool:
        k = node[0]
        if k == "sub":
            return anchored.get(node[1], False)
        if k == "cmp":
            _, op, x, _y, inner = node
            positive = (op == ">" ) or (op == "=" and x >= 1)
            if not positive:
                return False
            if inner[0] == "sub":
                return anchored.get(inner[1], False)
            return all(anchored.get(i, False) for i in leaves(inner, []))
        if k == "and":
            return needs(node[1]) or needs(node[2])
        return needs(node[1]) and needs(node[2])  # or

    return needs(tree)


def pcre_anchor(pattern: str, flags: str) -> tuple[bytes | None, bool]:
    """Longest mandatory literal of a PCRE (top-level sequence only) -> (anchor, nocase)."""
    import re._parser as sre_parse  # noqa: PLC0415
    import re._constants as C  # noqa: PLC0415
    nocase = "i" in flags
    try:
        parsed = sre_parse.parse(pattern, re.IGNORECASE if nocase else 0)
    except Exception:  # noqa: BLE001
        return None, nocase
    runs: list[bytes] = []
    cur = bytearray()

    def walk(seq):
        for op, av in seq:
            if op is C.LITERAL and av < 256:
                cur.append(av)
            elif op is C.SUBPATTERN and not any(o is C.BRANCH for o, _ in av[3]):
                walk(av[3])
            elif op in (C.MAX_REPEAT, C.MIN_REPEAT) and av[0] >= 1 and len(av[2]) == 1 and av[2][0][0] is C.LITERAL:
                cur.append(av[2][0][1])  # at least one occurrence
                runs.append(bytes(cur))
                cur.clear()
            elif op is C.AT:
                continue
            else:
                runs.append(bytes(cur))
                cur.clear()

    walk(parsed)
    runs.append(bytes(cur))
    best = None
    for r in runs:
        if nocase:
            r = r.lower()
        w = best_window(r)
        if len(w) >= 4 and (best is None or anchor_score(w) > anchor_score(best)):
            best = w
    return best, nocase

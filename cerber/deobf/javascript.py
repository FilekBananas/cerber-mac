"""JavaScript / JScript normalisation and payload extraction (never executes anything)."""
from __future__ import annotations

import ast
import re
from collections import Counter

from .generic import classify_layer, encoded_literals, numeric_arrays, ps_encoded_commands
from .primitives import Budget, Layer, b64decode_loose, excerpt, js_unescape, url_unquote
from .textops import fold_concat, iter_literals, quote, render_literals
from .vbe import decode_encoded_blocks

LANG = "javascript"

_FCC = re.compile(r"String\s*\.\s*fromCharCode\s*\(\s*([^()]{1,20000}?)\s*\)")
_FCC_APPLY = re.compile(r"String\s*\.\s*fromCharCode\s*\.\s*apply\s*\(\s*(?:null|this|String|undefined|0)\s*,\s*"
                        r"\[([^\[\]]{1,400000})\]\s*\)")
_FCC_SPREAD = re.compile(r"String\s*\.\s*fromCharCode\s*\(\s*\.\.\.\s*\[([^\[\]]{1,400000})\]\s*\)")
_DECODER_CALL = re.compile(r"(?:\b(unescape|decodeURIComponent|decodeURI|atob)|Buffer\s*\.\s*from)\s*\(\s*$")
_SINK = re.compile(r"(?:\beval|\bFunction|\bsetTimeout|\bsetInterval|\bexecScript|document\s*\.\s*write(?:ln)?|"
                   r"\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(\s*['\"]\w+['\"]\s*,)\s*\(?\s*$")
_PACKER = re.compile(r"\}\s*\(\s*(?=['\"])")
_PACKER_TAIL = re.compile(r"\s*,\s*(\d{1,3})\s*,\s*(\d{1,6})\s*,\s*(?=['\"])")
_OBF_ARR = re.compile(r"\b(_0x[0-9a-f]{3,8})\s*=\s*\[\s*(?=['\"])")
_OBF_ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
_STD_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_OBF_TR = str.maketrans(_OBF_ALPHA, _STD_ALPHA)
_B62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

_ARITH_OPS = (ast.Add, ast.Sub, ast.Mult, ast.BitXor, ast.Mod, ast.FloorDiv, ast.BitAnd, ast.BitOr,
              ast.LShift, ast.RShift)


def safe_int_expr(expr: str) -> int | None:
    """Evaluate a tiny constant integer expression like 0x41^0x12 or 100-3 (no names, no calls)."""
    e = expr.strip()
    if not e or len(e) > 80:
        return None
    if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", e):
        return int(e, 0) if not re.fullmatch(r"0\d+", e) else int(e)
    if not re.fullmatch(r"[0-9a-fA-Fx+\-*^%&|<>()\s/]+", e):
        return None
    try:
        tree = ast.parse(e.replace("/", "//"), mode="eval")
    except (SyntaxError, ValueError):
        return None

    def ev(n):
        if isinstance(n, ast.Expression):
            return ev(n.body)
        if isinstance(n, ast.Constant) and isinstance(n.value, int):
            return n.value
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.USub):
            return -ev(n.operand)
        if isinstance(n, ast.BinOp) and isinstance(n.op, _ARITH_OPS):
            a, b = ev(n.left), ev(n.right)
            if isinstance(n.op, (ast.LShift, ast.RShift)) and not 0 <= b < 32:
                raise ValueError
            if isinstance(n.op, (ast.Mod, ast.FloorDiv)) and b == 0:
                raise ValueError
            r = {ast.Add: a + b, ast.Sub: a - b, ast.Mult: a * b if abs(a) < 1 << 20 and abs(b) < 1 << 20 else 0,
                 ast.BitXor: a ^ b, ast.BitAnd: a & b, ast.BitOr: a | b}.get(type(n.op))
            if r is None:
                r = {ast.Mod: lambda: a % b, ast.FloorDiv: lambda: a // b,
                     ast.LShift: lambda: a << b, ast.RShift: lambda: a >> b}[type(n.op)]()
            return r
        raise ValueError
    try:
        v = ev(tree)
    except (ValueError, KeyError, RecursionError):
        return None
    return v if isinstance(v, int) else None


def _codes_to_str(args: str) -> str | None:
    parts = args.split(",")
    if len(parts) > 100000:
        return None
    out = []
    for p in parts:
        v = safe_int_expr(p)
        if v is None or not 0 <= v <= 0x10FFFF:
            return None
        out.append(chr(v))
    return "".join(out)


def _sub_fcc(text: str, stats: Counter) -> str:
    if "fromCharCode" not in text:
        return text

    def rep(m: re.Match) -> str:
        s = _codes_to_str(m.group(1))
        if s is None:
            return m.group(0)
        stats["charcode"] += len(s)
        return quote(s)
    text = _FCC_APPLY.sub(rep, text)
    text = _FCC_SPREAD.sub(rep, text)
    return _FCC.sub(rep, text)


def _sub_decoders(text: str, stats: Counter) -> str:
    """unescape('..') / decodeURIComponent('..') / atob('..') / Buffer.from('..','base64')."""
    low = text
    if not any(k in low for k in ("unescape", "decodeURI", "atob", "Buffer")):
        return text
    out: list[str] = []
    pos = 0
    for lit in iter_literals(text, LANG, min_len=2):
        pre = text[max(0, lit.start - 40):lit.start]
        m = _DECODER_CALL.search(pre)
        if not m:
            continue
        fn = m.group(1)
        post = text[lit.end:lit.end + 40]
        val = None
        cm = None
        if fn in ("unescape",):
            cm = re.match(r"\s*\)", post)
            val = js_unescape(lit.value)
        elif fn in ("decodeURIComponent", "decodeURI"):
            cm = re.match(r"\s*\)", post)
            val = url_unquote(lit.value)
        elif fn == "atob":
            cm = re.match(r"\s*\)", post)
            d = b64decode_loose(lit.value)
            val = _short_text(d)
        else:  # Buffer.from(x, 'base64'|'hex').toString()
            cm = re.match(r"\s*,\s*['\"](base64|hex|base64url)['\"]\s*\)(?:\s*\.\s*toString\s*\(\s*(?:['\"][\w-]+['\"])?\s*\))?", post)
            if cm:
                if cm.group(1) == "hex":
                    try:
                        d = bytes.fromhex(lit.value)
                    except ValueError:
                        d = None
                else:
                    d = b64decode_loose(lit.value)
                val = _short_text(d)
        if val is None or cm is None:
            continue
        stats["decode_" + (fn or "buffer")] += 1
        out.append(text[pos:lit.start - (len(pre) - m.start())])
        out.append(quote(val))
        pos = lit.end + cm.end()
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


def _short_text(d: bytes | None, limit: int = 65536) -> str | None:
    if not d or len(d) > limit:
        return None
    try:
        s = d.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 9 or 13 < ord(c) < 32 for c in s):
        return None
    return s


def _fold(text: str, stats: Counter, budget: Budget) -> str:
    """fromCharCode / decoder calls / concatenations folded into literals that stay
    re-tokenisable (every literal is emitted through quote(), escapes intact)."""
    t = text
    for _ in range(4):
        if budget.expired():
            break
        before = t
        t = _sub_fcc(t, stats)
        t = _sub_decoders(t, stats)
        t = fold_concat(t, LANG, stats)
        if t == before:
            break
    return t


def normalize_views(text: str, stats: Counter, budget: Budget) -> tuple[str, str]:
    """(folded, rendered). `rendered` (= normalize()) shows literals with their escapes
    decoded, which is what the rules read, but it can no longer be tokenised: a `\\"`
    inside a literal becomes a bare quote that ends the literal early. Anything that
    has to re-read literals (exec_commands) uses `folded`."""
    folded = _fold(text, stats, budget)
    return folded, render_literals(folded, LANG, stats)


def normalize(text: str, stats: Counter, budget: Budget) -> str:
    return normalize_views(text, stats, budget)[1]


# --------------------------------------------------------------------------- packer

def _unbase(word: str, radix: int) -> int | None:
    try:
        if radix <= 36:
            return int(word, radix)
        v = 0
        for ch in word:
            i = _B62.find(ch)
            if i < 0 or i >= radix:
                return None
            v = v * radix + i
        return v
    except ValueError:
        return None


def unpack_packer(text: str, budget: Budget, limit: int = 8) -> list[Layer]:
    """Dean Edwards P.A.C.K.E.R.: eval(function(p,a,c,k,e,d){...}('payload',62,99,'a|b'.split('|'),0,{}))"""
    out: list[Layer] = []
    if "function(p,a,c,k,e," not in text.replace(" ", ""):
        return out
    lits = list(iter_literals(text, LANG))
    starts = {lit.start: idx for idx, lit in enumerate(lits)}
    for m in _PACKER.finditer(text):
        if len(out) >= limit or budget.expired():
            break
        i = starts.get(m.end())
        if i is None or i + 1 >= len(lits):
            continue
        payload = lits[i]
        tm = _PACKER_TAIL.match(text, payload.end)
        if not tm:
            continue
        words_lit = lits[starts.get(tm.end(), -1)] if tm.end() in starts else None
        if words_lit is None or not re.match(r"\s*\.\s*split\s*\(\s*['\"]\|['\"]\s*\)", text[words_lit.end:words_lit.end + 20]):
            continue
        radix, count = int(tm.group(1)), int(tm.group(2))
        words = words_lit.value.split("|")
        if not 2 <= radix <= 62 or count > 200000:
            continue

        def rep(wm: re.Match) -> str:
            w = wm.group(0)
            idx = _unbase(w, radix)
            if idx is None or idx >= len(words) or not words[idx]:
                return w
            return words[idx]
        src = re.sub(r"\b\w+\b", rep, payload.value)
        out.append(Layer("js-packer", src.encode("utf-8", "replace"), LANG, "text", "javascript",
                         excerpt(text[m.start():m.start() + 80])))
    return out


# --------------------------------------------------------------------------- obfuscator.io

def _obf_b64(s: str) -> str | None:
    if len(s) < 4 or not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return None
    d = b64decode_loose(s.translate(_OBF_TR))
    if not d:
        return None
    try:
        r = d.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not r or sum(1 for c in r if c.isprintable()) < len(r) * 0.95:
        return None
    return r


def string_arrays(text: str, budget: Budget) -> list[Layer]:
    """obfuscator.io / javascript-obfuscator string tables -> one text layer with every string."""
    out: list[Layer] = []
    if "_0x" not in text:
        return out
    lits = None
    for m in _OBF_ARR.finditer(text):
        if budget.expired() or len(out) >= 4:
            break
        if lits is None:
            lits = list(iter_literals(text, LANG))
            starts = {lit.start: idx for idx, lit in enumerate(lits)}
        pos = re.match(r"\s*", text[m.end():]).end() + m.end()
        i = starts.get(pos)
        if i is None:
            continue
        vals = [lits[i].value]
        j = i
        while j + 1 < len(lits) and re.fullmatch(r"\s*,\s*", text[lits[j].end:lits[j + 1].start]) and len(vals) < 100000:
            j += 1
            vals.append(lits[j].value)
        if len(vals) < 5:
            continue
        decoded = []
        n_b64 = 0
        for v in vals:
            d = _obf_b64(v)
            if d is not None:
                n_b64 += 1
                decoded.append(d)
        lines = vals + (decoded if n_b64 >= len(vals) * 0.5 else [])
        body = "\n".join(lines)
        out.append(Layer("js-string-array", body.encode("utf-8", "replace"), LANG, "text", "javascript",
                         excerpt(text[m.start():m.start() + 100]), {"strings": len(vals)}))
    return out


# --------------------------------------------------------------------------- command lines

_CMD_CALL = re.compile(r"(?:\.\s*(?:Run|Exec|ShellExecute)|\b(?:execSync|execFileSync|execFile|exec|spawnSync|spawn))"
                       r"\s*\(\s*(?=['\"`])")
_CMD_LANG = (
    (re.compile(r"(?i)^\s*[\"']?(?:[a-z]:)?[\w\\/.$%() -]{0,120}?\b(?:powershell|pwsh)(?:\.exe)?[\"']?(?:\s|$)"),
     "powershell"),
    (re.compile(r"(?i)^\s*(?:[a-z]:)?[\w\\/.%]{0,80}?\b(?:cmd(?:\.exe)?\s+/[ckr]|mshta(?:\.exe)?\s|"
                r"(?:w|c)script(?:\.exe)?\s|rundll32(?:\.exe)?\s|regsvr32(?:\.exe)?\s|certutil(?:\.exe)?\s|"
                r"bitsadmin(?:\.exe)?\s)"), "batch"),
    (re.compile(r"(?i)^\s*(?:/usr)?(?:/bin/)?(?:(?:ba|z|k)?sh\s+-c\b|curl\s|wget\s|osascript\s)"), "shell"),
)
_ARGV_OPEN = re.compile(r"\s*,\s*\[\s*")
_ARGV_SEP = re.compile(r"\s*,\s*")


def exec_commands(norm: str, budget: Budget, limit: int = 16, max_calls: int = 400) -> list[Layer]:
    """Literal command lines handed to WSH .Run/.Exec or Node child_process -> interpreter layers.

    (A JScript/Node dropper that launches `powershell -c "IEX(...DownloadString...)"` would
    otherwise only be seen through the JavaScript rules.)"""
    out: list[Layer] = []
    for n, m in enumerate(_CMD_CALL.finditer(norm)):
        if n >= max_calls or len(out) >= limit or budget.expired():
            break
        window = norm[m.end():m.end() + 8192]
        lits = iter_literals(window, LANG)
        first = next(lits, None)
        if first is None or first.start != 0:
            continue
        cmd = first.value
        # spawn("powershell", ["-c", "..."]) / execFile("cmd.exe", ["/c", ...])
        am = _ARGV_OPEN.match(window, first.end)
        if am:
            args, pos = [], am.end()
            for lit in lits:
                if lit.start != pos or len(args) >= 64:
                    break
                args.append(lit.value)
                sm = _ARGV_SEP.match(window, lit.end)
                pos = sm.end() if sm else lit.end
            if args:
                cmd = " ".join([cmd] + args)
        if len(cmd) < 8:
            continue
        for rx, lang in _CMD_LANG:
            if rx.match(cmd):
                out.append(Layer("js-exec-command", cmd.encode("utf-8", "replace"), lang, "text", lang,
                                 excerpt(first.raw)))
                break
    return out


def extract(raw: str, norm: str, budget: Budget, folded: str | None = None) -> list[Layer]:
    """`folded` is the first half of normalize_views(raw); when a caller only has the
    rendered `norm`, it is recomputed (only if there is a command-launching call)."""
    layers: list[Layer] = []
    layers += decode_encoded_blocks(raw, budget, LANG)
    layers += unpack_packer(raw, budget)
    layers += string_arrays(raw, budget)
    layers += ps_encoded_commands(norm, budget)
    if folded is None:
        folded = _fold(raw, Counter(), budget) if _CMD_CALL.search(raw) else raw
    layers += exec_commands(folded, budget)
    lits = list(iter_literals(norm, LANG, min_len=12))
    for lit in lits:
        if len(layers) > 48 or budget.expired():
            break
        pre = norm[max(0, lit.start - 40):lit.start]
        m = _SINK.search(pre)
        if not m:
            continue
        sink = m.group(0)
        lang = "html" if ("write" in sink or "HTML" in sink) else LANG
        if len(lit.value) < 16:
            continue
        layers.append(Layer(f"js-{'docwrite' if lang == 'html' else 'eval'}-literal",
                            lit.value.encode("utf-8", "replace"), lang, "text", lang, excerpt(lit.raw)))
    layers += encoded_literals(lits, budget, LANG, min_len=32)
    layers += numeric_arrays(norm, budget, LANG)
    return layers


__all__ = ["normalize", "normalize_views", "extract", "safe_int_expr", "unpack_packer", "string_arrays"]

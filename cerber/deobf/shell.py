"""POSIX shell (sh/bash/zsh) de-obfuscation and payload extraction."""
from __future__ import annotations

import codecs
import re
from collections import Counter

from .generic import classify_layer, encoded_literals, numeric_arrays
from .primitives import Budget, Layer, b64decode_loose, decompress_any, excerpt, hexdecode, unescape_backslash
from .textops import fold_concat, iter_literals, literal_at, literal_map  # noqa: F401

LANG = "shell"

_EMPTY_Q = re.compile(r"(?<=[\w/.-])(?:''|\"\")(?=[\w/.-])")
_BSLASH_WORD = re.compile(r"(?<![\\\w])(?:[A-Za-z]\\){2,}[A-Za-z]+")
_QUOTED_FRAG = re.compile(r"(?<=[A-Za-z])'([A-Za-z0-9._/-]{1,30})'(?=[A-Za-z0-9._/-])|(?<=[A-Za-z])\"([A-Za-z0-9._/-]{1,30})\"(?=[A-Za-z0-9._/-])")
_VARREF = re.compile(r"\$\{([A-Za-z_]\w{0,63})\}|\$([A-Za-z_]\w{0,63})")
_VAR_END = re.compile(r"\$\{?[A-Za-z_]\w{0,63}\}?$")

# pipeline source: echo/printf <x> | ... ; or: <decoder> <<< <x>
_SRC = re.compile(r"(?:\becho|\bprintf)(?:\s+-[neE]{1,3})?\s+(?:--\s+)?"
                  r"(\$'(?:[^'\\]|\\.){1,8000000}'|'[^']{1,8000000}'|\"(?:[^\"\\]|\\.){1,8000000}\"|"
                  r"\$\{?\w{1,64}\}?|[A-Za-z0-9+/=_\\-]{8,8000000})\s*((?:\|[ \t]*[^|;&\n)`]{1,160}){1,8})")
_HERESTR = re.compile(r"((?:\b(?:base64|openssl|xxd|gunzip|zcat|rev|bash|sh|zsh|python3?|perl)\b[^|;&\n<]{0,60}))<<<\s*"
                      r"(\$'(?:[^'\\]|\\.){1,8000000}'|'[^']{1,8000000}'|\"(?:[^\"\\]|\\.){1,8000000}\"|\$\{?\w{1,64}\}?|\S{8,8000000})"
                      r"\s*((?:\|[ \t]*[^|;&\n)`]{1,160}){0,8})")
_HEREDOC = re.compile(r"(?:\b(base64|openssl|xxd|gunzip|zcat)\b[^\n<|]{0,60}|\bcat\s*)<<-?\s*['\"]?(\w{1,32})['\"]?[^\n]{0,200}\n")
_INTERP = re.compile(r"(?i)\b(osascript(?:\s+-l\s+(?:JavaScript|AppleScript))?|python[0-9.]*|perl|ruby|node|php|"
                     r"bash|sh|zsh|dash)\s+(?:-[a-zA-Z]{1,3}\s+){0,3}?(-e|-c|-r)\s+(?=['\"$])")
_PRINTF_ESC = re.compile(r"\\x[0-9a-fA-F]{2}|\\[0-7]{3}")

_SINKS = {"sh": "shell", "bash": "shell", "zsh": "shell", "dash": "shell", "ksh": "shell", "source": "shell",
          "eval": "shell", "python": "python", "python3": "python", "python2": "python", "perl": "perl",
          "ruby": "ruby", "node": "javascript", "osascript": "applescript", "php": "php"}


def normalize(text: str, stats: Counter, budget: Budget) -> str:
    t = text
    if "''" in t or '""' in t:
        t2 = _EMPTY_Q.sub("", t)
        if t2 != t:
            stats["emptyquote"] += 1
            t = t2
    if "\\" in t:
        t2 = _BSLASH_WORD.sub(lambda m: m.group(0).replace("\\", ""), t)
        if t2 != t:
            stats["backslash"] += 1
            t = t2
    t2 = _QUOTED_FRAG.sub(lambda m: m.group(1) or m.group(2), t)
    if t2 != t:
        stats["quotefrag"] += 1
        t = t2
    t = fold_concat(t, LANG, stats)
    # substitute short, single-use literal variables (a=cu; b=rl; $a$b ...)
    if "$" in t and not budget.expired():
        vars_ = {k: v for k, v in literal_map(t, LANG).items() if len(v) <= 64 and "$" not in v}
        if vars_:
            n = [0]
            adj = [0]
            src = t

            def rep(m: re.Match) -> str:
                name = m.group(1) or m.group(2)
                v = vars_.get(name)
                if v is None or n[0] > 5000:
                    return m.group(0)
                n[0] += 1
                # only fragments glued to another variable ($a$b, ${x}${y}) are obfuscation;
                # "$PAGER $file" is how every shell script uses variables
                s0, e0 = m.start(), m.end()
                if src.startswith("$", e0) or _VAR_END.search(src, max(0, s0 - 66), s0):
                    adj[0] += 1
                return v
            t2 = _VARREF.sub(rep, t)
            if n[0]:
                stats["varsubst"] += adj[0]
                stats["varsubst_plain"] += n[0] - adj[0]
                t = t2
    return t


def _unquote(tok: str, vars_: dict[str, str]) -> str | None:
    tok = tok.strip()
    if tok.startswith("$'") and tok.endswith("'"):
        return unescape_backslash(tok[2:-1])
    if tok[:1] == "'" and tok[-1:] == "'":
        return tok[1:-1]
    if tok[:1] == '"' and tok[-1:] == '"':
        inner = tok[1:-1]
        vm = re.fullmatch(r"\$\{?(\w+)\}?", inner)
        if vm:
            return vars_.get(vm.group(1))
        return re.sub(r"\\([\"\\$`])", r"\1", inner)
    vm = re.fullmatch(r"\$\{?(\w+)\}?", tok)
    if vm:
        return vars_.get(vm.group(1))
    return tok.replace("\\", "")


def _apply_stage(stage: str, data: bytes) -> tuple[str, bytes | None, str | None]:
    """Apply one pipeline stage. Returns (name, new_data or None when not a transform, sink_lang)."""
    s = stage.strip()
    words = s.split()
    if not words:
        return "", data, None
    cmd = words[0].rsplit("/", 1)[-1]
    low = s.lower()
    if cmd in ("sudo", "exec", "nohup", "command", "env") and len(words) > 1:
        return _apply_stage(" ".join(words[1:]), data)
    if cmd in ("base64", "b64", "gbase64") and re.search(r"(?:^|\s)(?:-d|-D|--decode|-di|-id)\b", s):
        return "b64", b64decode_loose(data), None
    if cmd == "openssl" and ("base64" in low or " -a" in low or "-base64" in low) and " -d" in low:
        return "b64", b64decode_loose(data), None
    if cmd == "xxd" and "-r" in low:
        return "hex", hexdecode(data.decode("latin-1")), None
    if cmd == "rev":
        lines = data.split(b"\n")
        return "rev", b"\n".join(ln[::-1] for ln in lines), None
    if cmd in ("gunzip", "zcat", "gzcat") or (cmd in ("gzip", "bzip2", "xz", "unxz", "bunzip2", "lzma") and
                                             ("-d" in words or "--decompress" in words or cmd.startswith("un"))):
        r = decompress_any(data)
        return (r[0], r[1], None) if r else ("decompress", None, None)
    if cmd == "tr" and ("n-za-m" in low or "N-ZA-M" in s):
        return "rot13", codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1"), None
    if cmd in _SINKS:
        lang = _SINKS[cmd]
        if cmd == "osascript" and "javascript" in low:
            lang = "javascript"
        return cmd, None, lang
    if cmd.startswith("python"):
        return cmd, None, "python"
    return cmd, None, None


def _run_pipeline(src: bytes, chain: str, budget: Budget, source: str, prefix_stage: str | None = None,
                  initial: list[str] | None = None) -> Layer | None:
    stages = [st for st in chain.split("|") if st.strip()]
    if prefix_stage:
        stages.insert(0, prefix_stage)
    data = src
    steps: list[str] = list(initial or [])
    sink = None
    for st in stages[:8]:
        name, out, lang = _apply_stage(st, data)
        if lang:
            sink = lang
            break
        if out is None:
            if steps:
                break
            return None
        if not out:
            return None
        data = out
        steps.append(name)
    if not steps or not budget.charge(len(data)):
        return None
    method = "sh-" + ">".join(steps)
    lay = classify_layer(method, data, budget, sink or LANG, source, need_code=False)
    if lay and sink:
        lay.meta["sink"] = sink
    return lay


def extract(raw: str, norm: str, budget: Budget) -> list[Layer]:
    layers: list[Layer] = []
    vars_ = literal_map(norm, LANG) if "$" in norm else {}
    low = norm.lower()
    if any(k in low for k in ("base64", "xxd", "openssl", "gunzip", "zcat", "rev", "tr ")):
        for m in _SRC.finditer(norm):
            if budget.expired() or len(layers) > 32:
                break
            val = _unquote(m.group(1), vars_)
            if not val or len(val) < 8:
                continue
            initial = None
            if "printf" in norm[m.start():m.start() + 7] or norm[m.start():m.end()].startswith("echo -e") \
                    or m.group(1).startswith("$'"):
                if len(_PRINTF_ESC.findall(m.group(1))) >= 4:
                    initial = ["escapes"]
                val = unescape_backslash(val)
            lay = _run_pipeline(val.encode("latin-1", "replace"), m.group(2), budget, m.group(0), initial=initial)
            if lay:
                layers.append(lay)
        for m in _HERESTR.finditer(norm):
            if budget.expired() or len(layers) > 32:
                break
            val = _unquote(m.group(2), vars_)
            if not val:
                continue
            lay = _run_pipeline(val.encode("latin-1", "replace"), m.group(3) or "", budget, m.group(0),
                                prefix_stage=m.group(1))
            if lay:
                layers.append(lay)
        # base64 -d <<EOF ... EOF   /  cat <<EOF | base64 -d
        for m in _HEREDOC.finditer(norm):
            if budget.expired() or len(layers) > 32:
                break
            term = m.group(2)
            end = norm.find("\n" + term, m.end() - 1)
            if end < 0:
                continue
            body = norm[m.end():end]
            first = norm[m.start():m.end()]
            if m.group(1):
                chain_prefix = first.split("<<")[0]
                rest = first.split("<<", 1)[1]
                pipe = rest[rest.find("|"):] if "|" in rest else ""
                lay = _run_pipeline(body.encode("latin-1", "replace"), pipe, budget, first, prefix_stage=chain_prefix)
            else:
                rest = first.split("<<", 1)[1]
                if "|" not in rest:
                    continue
                lay = _run_pipeline(body.encode("latin-1", "replace"), rest[rest.find("|"):], budget, first)
            if lay:
                layers.append(lay)
    # printf '\x63\x75\x72\x6c ...'
    if "printf" in low or "echo -e" in low or "$'" in norm:
        for lit in iter_literals(raw, LANG, min_len=16):
            if len(_PRINTF_ESC.findall(lit.raw)) >= 8:
                val = unescape_backslash(lit.raw[2:-1] if lit.raw.startswith("$'") else lit.raw[1:-1])
                lay = classify_layer("sh-escapes", val.encode("latin-1", "replace"), budget, LANG, lit.raw,
                                     need_code=False)
                if lay:
                    layers.append(lay)
    # interpreter one-liners: osascript -e '...', python -c '...', bash -c "..."
    for m in _INTERP.finditer(norm):
        if budget.expired() or len(layers) > 48:
            break
        lm = literal_at(norm, m.end(), LANG)
        if lm is None:
            continue
        val = lm.value
        if lm.raw.startswith('"'):
            vm = re.fullmatch(r"\$\{?(\w+)\}?", val.strip())
            if vm and vm.group(1) in vars_:
                val = vars_[vm.group(1)]
        if len(val) < 12:
            continue
        exe = m.group(1).lower()
        lang = "applescript" if exe.startswith("osascript") else _SINKS.get(exe.split()[0], "python" if exe.startswith("python") else LANG)
        if exe.startswith("osascript") and "javascript" in exe:
            lang = "javascript"
        # osascript -e 'a' -e 'b' -> join all -e parts
        if lang in ("applescript", "javascript") and exe.startswith("osascript"):
            parts = [val]
            p = lm.end
            while len(parts) < 200:
                pm = re.match(r"\s+-e\s+", norm[p:p + 64])
                if not pm:
                    break
                nxt = literal_at(norm, p + pm.end(), LANG)
                if nxt is None:
                    break
                parts.append(nxt.value)
                p = nxt.end
            val = "\n".join(parts)
        layers.append(Layer(f"sh-{exe.split()[0]}-inline", val.encode("utf-8", "replace"), lang, "text", lang,
                            excerpt(norm[m.start():m.start() + 120])))
    lits = list(iter_literals(norm, LANG, min_len=24))
    layers += encoded_literals(lits, budget, LANG, min_len=40)
    layers += numeric_arrays(norm, budget, None)
    return layers


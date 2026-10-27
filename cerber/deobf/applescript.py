"""AppleScript source normalisation, payload extraction and compiled-script (.scpt) decoding.

Compiled scripts ("FasdUAS" magic) keep string literals as UTF-16BE and commands as 8-byte
Apple Event codes (e.g. sysoexec = `do shell script`). We rebuild a pseudo-source made of
keywords and literals in file order so the AppleScript rules can run on it. Compiled JXA
("JsOsaDAS" magic) simply embeds the JavaScript source.
"""
from __future__ import annotations

import re
from collections import Counter

from .generic import encoded_literals
from .primitives import Budget, Layer, excerpt
from .textops import fold_concat, iter_literals, quote

LANG = "applescript"

EVENT_CODES = {
    b"sysoexec": "do shell script", b"sysodlog": "display dialog", b"sysodsct": "run script",
    b"sysontoc": "ASCII character", b"sysocton": "ASCII number", b"GURLGURL": "open location",
    b"aevtstvl": "set volume", b"coreclon": "duplicate", b"coredelo": "delete", b"coremove": "move",
    b"aevtquit": "quit", b"sysodisA": "display alert", b"sysonotf": "display notification",
    b"miscactv": "activate", b"aevtodoc": "open", b"JonsgClp": "the clipboard", b"JonspClp": "set the clipboard to",
    b"prcskprs": "keystroke", b"prcskcod": "key code", b"sysodela": "delay", b"rdwrread": "read",
    b"rdwrwrit": "write", b"rdwropen": "open for access", b"rdwrclos": "close access", b"sysosigt": "system info",
    b"earsffdr": "path to", b"sysoslct": "choose from list", b"sysostdf": "choose file", b"ascrcmnt": "log",
    b"sysorpth": "POSIX path", b"sysolocS": "localized string", b"syso gpt": "get volume settings",
    b"aevtrlgo": "log out", b"aevtrrst": "restart", b"aevtshut": "shut down", b"coresetd": "set",
    b"coregetd": "get", b"coreclos": "close", b"corecrel": "make new", b"aevtoapp": "run",
    b"sysoexcb": "do shell script",
}
PARAM_CODES = {
    b"htxt": "with hidden answer", b"dtxt": "default answer", b"givu": "giving up after", b"btns": "buttons",
    b"appr": "with title", b"disp": "with icon", b"mute": "output muted", b"badm": "with administrator privileges",
    b"RApw": "password", b"prmp": "with prompt",
}
_EVT_RX = re.compile(rb"(" + b"|".join(re.escape(k) for k in EVENT_CODES) + rb")")
_PARAM_RX = re.compile(rb"\n(" + b"|".join(re.escape(k) for k in PARAM_CODES) + rb")")
_U16 = re.compile(rb"(?:\x00[\x09\x0a\x0d\x20-\x7e]){3,}")
_ASCII = re.compile(rb"[\x20-\x7e]{6,}")


def is_compiled(data: bytes) -> bool:
    return data[:7] == b"FasdUAS" or data[:8] == b"JsOsaDAS"


def compiled_to_source(data: bytes, limit: int = 16 << 20) -> tuple[str, str]:
    """Return (lang, pseudo-source) for a compiled script."""
    d = data[:limit]
    if d[:8] == b"JsOsaDAS":
        # header "JsOsaDAS1.001.00" + UTF-8 JavaScript source, followed by a resource-ish trailer
        body = d[16:]
        end = body.find(b"jscr\xfa\xde\xde\xad")
        if end > 0:
            body = body[:end]
        return "javascript", body.decode("utf-8", "replace")
    tokens: list[tuple[int, str]] = []
    for m in _EVT_RX.finditer(d):
        tokens.append((m.start(), EVENT_CODES[m.group(1)]))
    for m in _PARAM_RX.finditer(d):
        tokens.append((m.start(), PARAM_CODES[m.group(1)]))
    for m in _U16.finditer(d):
        s = m.group(0).decode("utf-16-be", "replace")
        tokens.append((m.start(), quote(s, LANG)))
    for m in _ASCII.finditer(d):
        s = m.group(0)
        if s.startswith(b"FasdUAS"):
            continue
        tokens.append((m.start(), "-- " + s.decode("latin-1")))
    tokens.sort()
    lines: list[str] = []
    cur: list[str] = []
    for _, tok in tokens:
        if tok.startswith("-- "):
            if cur:
                lines.append(" ".join(cur))
                cur = []
            lines.append(tok)
            continue
        cur.append(tok)
        if tok.startswith('"'):
            lines.append(" ".join(cur))
            cur = []
    if cur:
        lines.append(" ".join(cur))
    return LANG, "\n".join(lines)


_ASCII_CHAR = re.compile(r"(?i)\(?\s*(?:ascii\s+character|character\s+id)\s+(\d{1,6})\s*\)?")
_CHAR_ID_LIST = re.compile(r"(?i)\(?\s*(?:string\s+id|character\s+id)\s+\{\s*((?:\d{1,6}\s*,\s*){0,100000}\d{1,6})\s*\}\s*(?:as\s+(?:text|string))?\s*\)?")
_DO_SHELL = re.compile(r"(?i)\bdo\s+shell\s+script\s*\(?\s*$")
_RUN_SCRIPT = re.compile(r"(?i)\brun\s+script\s*\(?\s*$")


def normalize(text: str, stats: Counter, budget: Budget) -> str:
    t = text
    low = t.lower()
    if "character" in low or "string id" in low:
        def rep_list(m: re.Match) -> str:
            try:
                s = "".join(chr(int(x)) for x in re.split(r"\s*,\s*", m.group(1).strip()))
            except (ValueError, OverflowError):
                return m.group(0)
            stats["charcode"] += len(s)
            return quote(s, LANG)
        t = _CHAR_ID_LIST.sub(rep_list, t)

        def rep(m: re.Match) -> str:
            try:
                v = int(m.group(1))
                stats["charcode"] += 1
                return quote(chr(v), LANG)
            except (ValueError, OverflowError):
                return m.group(0)
        t = _ASCII_CHAR.sub(rep, t)
    for _ in range(3):
        if budget.expired():
            break
        before = t
        t = fold_concat(t, LANG, stats)
        if t == before:
            break
    return t


def extract(raw: str, norm: str, budget: Budget) -> list[Layer]:
    layers: list[Layer] = []
    lits = list(iter_literals(norm, LANG, min_len=6))
    for lit in lits:
        if len(layers) > 48 or budget.expired():
            break
        pre = norm[max(0, lit.start - 30):lit.start]
        if _DO_SHELL.search(pre) and len(lit.value) >= 12:
            layers.append(Layer("as-do-shell-script", lit.value.encode("utf-8", "replace"), "shell", "text", "shell",
                                excerpt(lit.raw)))
        elif _RUN_SCRIPT.search(pre) and len(lit.value) >= 12:
            layers.append(Layer("as-run-script", lit.value.encode("utf-8", "replace"), LANG, "text", LANG,
                                excerpt(lit.raw)))
    layers += encoded_literals(lits, budget, LANG, min_len=32)
    return layers

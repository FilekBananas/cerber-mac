"""Windows batch (cmd.exe) de-obfuscation: caret escapes, `set` variable expansion with
substring/replace syntax (%v:~s,l% / %v:a=b% / !v!), environment-variable slicing."""
from __future__ import annotations

import re
from collections import Counter

from .generic import encoded_literals, numeric_arrays, ps_encoded_commands
from .primitives import Budget, Layer, excerpt
from .textops import iter_literals

LANG = "batch"

# default values of well-known Windows environment variables (used for %COMSPEC:~-7,1% tricks)
ENV_DEFAULTS = {
    "comspec": r"C:\WINDOWS\system32\cmd.exe", "windir": r"C:\WINDOWS", "systemroot": r"C:\WINDOWS",
    "systemdrive": "C:", "public": r"C:\Users\Public", "programdata": r"C:\ProgramData",
    "allusersprofile": r"C:\ProgramData", "programfiles": r"C:\Program Files",
    "programfiles(x86)": r"C:\Program Files (x86)", "commonprogramfiles": r"C:\Program Files\Common Files",
    "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC", "os": "Windows_NT",
    "processor_architecture": "AMD64", "userprofile": r"C:\Users\user", "appdata": r"C:\Users\user\AppData\Roaming",
    "localappdata": r"C:\Users\user\AppData\Local", "temp": r"C:\Users\user\AppData\Local\Temp",
    "tmp": r"C:\Users\user\AppData\Local\Temp", "homedrive": "C:", "homepath": r"\Users\user",
    "psmodulepath": r"C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules",
}

_CARET = re.compile(r"\^(.)")
_SET = re.compile(r'(?i)(?:^|[&(|]\s*|\bdo\s+)set\s+(?!/a\b)(?:/p\s+)?"?([^=\s"&|<>]{1,64})=([^\r\n]*?)"?\s*(?=$|&&?|\|\||\))',
                  re.M)
_VAR = re.compile(r"%([^%\s:]{1,64})(?::~(-?\d{1,5})(?:,(-?\d{1,5}))?|:([^%=]{1,64})=([^%]{0,64}))?%")
_DVAR = re.compile(r"!([^!\s:]{1,64})(?::~(-?\d{1,5})(?:,(-?\d{1,5}))?|:([^!=]{1,64})=([^!]{0,64}))?!")
_PS_CMD = re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,200}?\s[-/](?:c|command|co|com|comm|comma|comman)\s+"
                     r"(\"[^\"\r\n]{12,}\"|'[^'\r\n]{12,}'|[^\r\n]{12,})")
_MSHTA = re.compile(r"(?i)\bmshta(?:\.exe)?\s+[\"']?(vbscript|javascript):([^\r\n]{12,})")


def _slice(val: str, s: str | None, ln: str | None) -> str:
    start = int(s) if s else 0
    if start < 0:
        start = max(0, len(val) + start)
    if ln is None:
        return val[start:]
    n = int(ln)
    if n < 0:
        end = len(val) + n
        return val[start:end] if end > start else ""
    return val[start:start + n]


def _expand(line: str, env: dict[str, str], rx: re.Pattern[str], stats: Counter) -> str:
    def rep(m: re.Match) -> str:
        name = m.group(1).lower()
        val = env.get(name)
        if val is None:
            return m.group(0)
        stats["var"] += 1
        if m.group(2) is not None:
            return _slice(val, m.group(2), m.group(3))
        if m.group(4) is not None:
            old = m.group(4)
            new = m.group(5) or ""
            if old.startswith("*"):
                i = val.lower().find(old[1:].lower())
                return new + val[i + len(old) - 1:] if i >= 0 else val
            return re.sub(re.escape(old), lambda _m: new, val, flags=re.I)
        return val
    return rx.sub(rep, line)


def normalize(text: str, stats: Counter, budget: Budget) -> str:
    # carets: ^^ -> ^ ; ^x -> x (cmd removes them outside quotes)
    if "^" in text:
        t2 = _CARET.sub(lambda m: m.group(1) if m.group(1) not in "\r\n" else m.group(0), text)
        stats["caret"] += text.count("^") - t2.count("^")
        text = t2
    if "%" not in text and "!" not in text:
        return text
    env = dict(ENV_DEFAULTS)
    out = []
    lines = text.splitlines()
    if len(lines) > 20000:
        return text
    for line in lines:
        if budget.expired():
            out.append(line)
            continue
        if "%" in line:
            line = _expand(line, env, _VAR, stats)
        if "!" in line:
            line = _expand(line, env, _DVAR, stats)
        for m in _SET.finditer(line):
            name, val = m.group(1).lower(), m.group(2)
            if len(env) < 4000 and len(val) < 8192:
                env[name] = val
                stats["set"] += 1
        out.append(line)
    return "\n".join(out)


def extract(raw: str, norm: str, budget: Budget) -> list[Layer]:
    layers: list[Layer] = []
    layers += ps_encoded_commands(norm, budget)
    for m in _PS_CMD.finditer(norm):
        if len(layers) > 32 or budget.expired():
            break
        cmd = m.group(1).strip()
        if cmd[:1] in "\"'" and cmd[-1:] == cmd[:1]:
            cmd = cmd[1:-1]
        if len(cmd) >= 24:
            layers.append(Layer("bat-powershell-command", cmd.encode("utf-8", "replace"), "powershell", "text",
                                "powershell", excerpt(m.group(0))))
    for m in _MSHTA.finditer(norm):
        lang = "vbs" if m.group(1).lower() == "vbscript" else "javascript"
        layers.append(Layer("bat-mshta-inline", m.group(2).encode("utf-8", "replace"), lang, "text", lang,
                            excerpt(m.group(0))))
    lits = list(iter_literals(norm, LANG, min_len=24))
    layers += encoded_literals(lits, budget, LANG, min_len=40)
    layers += numeric_arrays(norm, budget, None)
    return layers

"""Shared helpers for the document analyzers (Office, RTF, PDF, LNK, OneNote)."""
from __future__ import annotations

import re

from ..filetype import identify_bytes

# file extensions that execute code when opened on Windows/macOS
EXEC_EXTENSIONS = {
    "exe", "scr", "com", "pif", "cpl", "dll", "ocx", "sys", "msi", "msp", "msc", "jar",
    "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "wsc", "sct", "hta", "ps1", "psm1",
    "psd1", "lnk", "url", "inf", "reg", "chm", "application", "gadget", "appref-ms", "iqy", "slk",
    "xll", "wll", "scf", "settingcontent-ms", "library-ms", "search-ms", "appx", "msix",
    "app", "command", "sh", "py", "applescript", "scpt", "pkg", "dmg", "workflow", "terminal",
}
SCRIPT_EXTENSIONS = {"bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "wsc", "sct", "hta",
                     "ps1", "psm1", "sh", "py", "applescript", "command", "iqy", "slk"}

# content types (cerber.filetype) that are code
EXEC_FTYPES = {"pe", "dos", "elf", "macho", "macho_fat", "dex", "java_class", "jar", "lnk"}
SCRIPT_FTYPES = {"script", "shell", "python", "powershell", "vbs", "javascript", "batch",
                 "applescript", "hta", "php"}

# Windows living-off-the-land binaries / interpreters commonly abused by document droppers
LOLBIN_RE = re.compile(
    r"(?i)\b(cmd(?:\.exe)?\s*/[ckr]|powershell(?:\.exe)?|pwsh(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|"
    r"regsvr32(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|"
    r"msiexec(?:\.exe)?|installutil(?:\.exe)?|regasm(?:\.exe)?|regsvcs(?:\.exe)?|msbuild(?:\.exe)?|"
    r"forfiles(?:\.exe)?|schtasks(?:\.exe)?|wmic(?:\.exe)?|curl(?:\.exe)?\s|wget\s|conhost(?:\.exe)?|"
    r"odbcconf(?:\.exe)?|cmstp(?:\.exe)?|hh(?:\.exe)?\s|explorer\.exe\s|msdt(?:\.exe)?|"
    r"/bin/(?:ba|z|k)?sh\b|osascript)"
)
DOWNLOAD_RE = re.compile(
    r"(?i)(https?://|\\\\[\w.\-]+@(?:ssl|\d+)\\|downloadstring|downloadfile|downloaddata|"
    r"invoke-webrequest|\biwr\b|\birm\b|invoke-restmethod|start-bitstransfer|net\.webclient|"
    r"urldownloadtofile|xmlhttp|winhttp|-urlcache|/transfer\b)"
)
ENCODED_PS_RE = re.compile(r"(?i)(?:^|\s)-e(?:nc(?:odedcommand)?|c)?\s+[A-Za-z0-9+/]{40,}={0,2}")
URL_RE = re.compile(rb"(?i)\b(?:https?|ftp)://[\x21-\x7e]{4,2000}")


def classify_payload(data: bytes, name: str = "") -> tuple[str, str]:
    """Return (ftype, reason) for an embedded blob; reason is "" when it is not code."""
    ftype, _ = identify_bytes(data[:1 << 20]) if data else ("empty", "")
    ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
    if ftype in EXEC_FTYPES:
        return ftype, f"{ftype} executable"
    if ext in EXEC_EXTENSIONS:
        return ftype, f".{ext} file"
    if ftype in SCRIPT_FTYPES:
        return ftype, f"{ftype} script"
    return ftype, ""


def safe_name(name: str, default: str = "object", limit: int = 120) -> str:
    """Sanitise an attacker-controlled name for use in a display path."""
    name = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(ch if 32 <= ord(ch) < 127 and ch not in '<>:"|?*' else "_" for ch in name).strip(" .")
    return (name or default)[:limit]


def utf16_strings(data: bytes, min_len: int = 4, limit: int = 2000) -> list[str]:
    out = []
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data):
        out.append(m.group().decode("utf-16-le", "replace"))
        if len(out) >= limit:
            break
    return out


def short(s: str | bytes, n: int = 200) -> str:
    if isinstance(s, bytes):
        s = s.decode("latin-1", "replace")
    s = s.replace("\r", "\\r").replace("\n", "\\n")
    return s if len(s) <= n else s[:n] + "..."

"""Windows scripting: batch (.bat/.cmd), VBScript/VBE (WSH), and .reg Run-key files.

These almost never appear on macOS, but the scanner judges Windows droppers found in
archives, email attachments and disk images the same way it judges native scripts.
"""
from __future__ import annotations

import re

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from . import register
from .scripts_common import R, make_script_analyzer

# --------------------------------------------------------------------------- batch
BATCH_RULES = [
    R("PowerShellDropper", r"powershell(?:\.exe)?\b[^\n]{0,120}(?:-enc(?:odedcommand)?|-e(?:c)?\s+[A-Za-z0-9+/]{40,}|"
      r"-w(?:indowstyle)?\s+hidden|downloadstring|iex)", 25,
      "Launches an encoded/hidden PowerShell payload", "exec,hidden", need="powershell"),
    R("Certutil", r"certutil(?:\.exe)?\b[^\n]{0,80}-urlcache", 30, "certutil downloader", "download,exec",
      need="certutil"),
    R("Bitsadmin", r"bitsadmin\b[^\n]{0,80}/transfer", 20, "bitsadmin downloader", "download",
      need="bitsadmin"),
    R("Mshta", r"mshta(?:\.exe)?\b[^\n]{0,80}(?:https?://|javascript:|vbscript:)", 30,
      "mshta executes remote/script content", "download,exec", need="mshta"),
    R("RunKey", r"reg(?:\.exe)?\s+add\b[^\n]{0,120}\\currentversion\\run", 20,
      "Registry Run-key persistence", "persist", need="reg add"),
    R("SchTasks", r"schtasks(?:\.exe)?\b[^\n]{0,80}/create", 15, "Scheduled-task persistence", "persist",
      need="schtasks"),
    R("WmicExec", r"wmic\b[^\n]{0,80}process\s+call\s+create", 20, "Process creation via WMIC",
      "exec", need="wmic"),
    R("ShadowDelete", r"vssadmin\b[^\n]{0,60}delete\s+shadows|wbadmin\b[^\n]{0,60}delete\s+catalog|"
      r"bcdedit\b[^\n]{0,60}recoveryenabled\s+no", 45,
      "Deletes shadow copies / disables recovery (ransomware)", "evasion", need="vssadmin|wbadmin|bcdedit"),
    R("Hidden", r"start\s+/(?:min|b)\b|attrib\b[^\n]{0,40}\+h", 5, "Hidden execution", "hidden",
      need="start /|attrib"),
]
make_script_analyzer("BatchAnalyzer", "batch", {"batch"}, "batch", BATCH_RULES)

# --------------------------------------------------------------------------- vbscript / WSH
VBS_RULES = [
    R("WshRun", r"createobject\s*\(\s*['\"]wscript\.shell['\"]\s*\)|\.run\s*\(|\.exec\s*\(|"
      r"shell(?:\.application)?['\"]?\s*\)[^\n]{0,40}shellexecute", 10,
      "Executes a command via WScript.Shell", "exec", need="wscript.shell|.run|.exec|shellexecute"),
    R("DynExec", r"\bexecute(?:global)?\s*\(?|\beval\s*\(", 10, "Dynamic code execution", "exec",
      need="execute|eval"),
    R("HttpDownload", r"createobject\s*\(\s*['\"](?:msxml2\.(?:xmlhttp|serverxmlhttp)|winhttp\.winhttprequest)",
      10, "HTTP download object", "download", need="msxml2|winhttp"),
    R("AdodbStream", r"createobject\s*\(\s*['\"]adodb\.stream['\"]\s*\)|\.savetofile\b", 15,
      "Writes a downloaded payload to disk (ADODB.Stream)", "download", need="adodb.stream|savetofile"),
    R("WmiObject", r"getobject\s*\(\s*['\"]winmgmts:", 10, "WMI object access", "exec", need="winmgmts"),
    R("Autorun", r"currentversion\\run|\.spawninstance_|win32_process", 15,
      "Persistence / process creation", "persist", need="\\run|spawninstance|win32_process"),
    R("PowerShell", r"powershell(?:\.exe)?\b[^\n]{0,120}(?:-enc|-w\s+hidden|downloadstring|iex)", 20,
      "Launches a hidden/encoded PowerShell payload", "exec,hidden", need="powershell"),
]
make_script_analyzer("VbsAnalyzer", "vbs", {"vbs"}, "vbs", VBS_RULES)

# --------------------------------------------------------------------------- .reg files
_REG_HEADER = re.compile(rb"(?i)^\s*Windows Registry Editor Version|^\s*REGEDIT4")
_REG_RUN = re.compile(r"(?i)\\(?:CurrentVersion\\Run(?:Once)?|Winlogon|Policies\\Explorer\\Run|"
                      r"Image File Execution Options)\]")
_REG_DEFENDER = re.compile(r"(?i)DisableAntiSpyware|DisableRealtimeMonitoring|DisableAntiVirus|"
                           r"\\Windows Defender[\\\"]")


@register
class RegAnalyzer(Analyzer):
    name = "reg"
    order = 56

    def applies(self, obj: ScanObject) -> bool:
        if obj.size < 24 or obj.size > (8 << 20):
            return False
        if obj.ftype not in ("text", "script"):
            return False
        return bool(_REG_HEADER.match(obj.data[:64]))

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        text = obj.text(8 << 20)
        if _REG_RUN.search(text):
            ctx.detect(obj, Detection("Heur:REG.RunKey", "heuristic", Confidence.MEDIUM, 20,
                                      "Registry file installs a Run/Winlogon autostart entry", pua=False))
        if _REG_DEFENDER.search(text):
            ctx.detect(obj, Detection("Heur:REG.DisableDefender", "heuristic", Confidence.HIGH, 40,
                                      "Registry file disables Windows Defender"))

"""Python detection rules and npm/Node package.json install-script analysis."""
from __future__ import annotations

import json
import re

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from . import register
from .scripts_common import R, emit, make_script_analyzer, scan_text, Hits

RULES = [
    R("DynExec", r"\bexec\s*\(|\beval\s*\(|\bcompile\s*\([^)]{0,80}exec", 0,
      "Dynamic code execution", "exec", need="exec|eval|compile"),
    R("DecodeExec",
      r"exec\s*\(\s*(?:base64|codecs|zlib|marshal)|(?:eval|exec)\s*\(\s*__import__|"
      r"(?:b64decode|b16decode|a85decode)\s*\([^\n]{0,80}\)\s*\)?\s*\)?\s*(?:#|$)?[^\n]{0,10}\bexec", 25,
      "Decodes a blob and executes it", "decode,exec", need="exec|eval"),
    R("MarshalPickle", r"marshal\.loads\s*\(|pickle\.loads\s*\(", 0,
      "marshal/pickle deserialization", "", need="marshal.loads|pickle.loads"),
    R("ShellCommand", r"os\.system\s*\(|subprocess\.(?:call|run|Popen|check_output)\s*\([^\n]{0,120}shell\s*=\s*True|"
      r"os\.popen\s*\(", 0, "Executes a shell command", "exec", need="os.system|subprocess|os.popen"),
    R("Download", r"requests\.get\s*\(|urllib\.request|urlopen\s*\(|urlretrieve\s*\(|httpx\.get", 0,
      "Downloads a remote resource", "download", need="requests|urllib|urlopen|urlretrieve|httpx"),
    R("ReverseShell",
      r"socket\.socket\s*\([^)]{0,80}\)[^\0]{0,300}?\bconnect\s*\([^\0]{0,400}?"
      r"(?:os\.dup2|pty\.spawn|/bin/sh|subprocess\.(?:call|run|Popen)|call\s*\(\s*\[?['\"]/bin)", 40,
      "Reverse-shell: socket connect wired to a shell", "exec,exfil", need="socket.socket"),
    R("ShellcodeCtypes", r"ctypes\b[^\n]{0,120}(?:VirtualAlloc|WriteProcessMemory)|"
      r"mmap\.mmap\s*\([^\n]{0,120}PROT_EXEC", 30, "Executable memory / shellcode loading via ctypes",
      "exec", need="ctypes|prot_exec"),
    R("KeychainBrowser",
      r"login\.keychain|Library/Application Support/(?:Google/Chrome|BraveSoftware|Firefox)/[^\n]{0,80}"
      r"(?:Cookies|Login Data|key4\.db|logins\.json)|Cookies\.binarycookies", 10,
      "Accesses keychain / browser credential stores", "cred,browser",
      need="keychain|chrome|brave|firefox|cookies.binarycookies"),
    R("Exfil", r"requests\.post\s*\(|smtplib\.SMTP|ftplib\.FTP", 0,
      "Uploads data to a remote endpoint", "exfil", need="requests.post|smtplib|ftplib"),
    R("Persist",
      r"(?:LaunchAgents|LaunchDaemons)/[^\n]{0,60}\.plist|crontab\s+-|com\.apple\.loginitems", 0,
      "Installs persistence", "persist", need="launchagent|launchdaemon|crontab|loginitems"),
]

make_script_analyzer("PythonAnalyzer", "python", {"python"}, "python", RULES, combos=[])


# --------------------------------------------------------------------------- npm / Node package.json

_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "preuninstall", "prepublish", "prepare")
_BAD_IN_HOOK = re.compile(
    r"(?i)\b(?:curl|wget|fetch)\b[^\n]{0,160}https?://|"           # download
    r"(?<!\|)\|(?!\|)\s*(?:sudo\s+)?(?:bash|sh|zsh|node|python[0-9.]*|perl|ruby)(?![\w.-])|"   # pipe (not ||) to interpreter
    r"base64\s+(?:-d|-D|--decode)|/dev/tcp/|"                       # decode / reverse shell
    r"python[0-9.]*\s+-c\b|powershell\b[^\n]{0,80}(?:-enc|-w\s+hidden|iex|downloadstring)|"
    r"node\s+-e\b[^\n]{0,200}(?:https?://|atob|child_process|Buffer\.from)|"
    r"require\s*\(\s*['\"]https?:|eval\s*\(\s*atob\s*\(")


@register
class NodePackageAnalyzer(Analyzer):
    name = "npm_pkg"
    order = 56

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype == "json" and obj.name.lower() == "package.json" and obj.size < (4 << 20)

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        try:
            doc = json.loads(obj.text(4 << 20))
        except Exception:
            return
        if not isinstance(doc, dict):
            return
        scripts = doc.get("scripts")
        if not isinstance(scripts, dict):
            return
        for hook in _INSTALL_HOOKS:
            cmd = scripts.get(hook)
            if not isinstance(cmd, str) or not cmd.strip():
                continue
            m = _BAD_IN_HOOK.search(cmd)
            if m:
                ctx.detect(obj, Detection(
                    "Heur:NPM.InstallHook", "heuristic", Confidence.HIGH, 40,
                    f"npm '{hook}' hook runs a suspicious command (download/exec/obfuscation)",
                    [f"{hook}: {cmd[:200]}"]))
            # feed the hook command to the shell analyzer regardless, so its rules run too
            ctx.add_child(obj, cmd.encode("utf-8", "replace"), f"npm/{hook}.sh", kind="decoded",
                          meta={"script_lang": "shell"})

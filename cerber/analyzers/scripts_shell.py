"""POSIX shell (bash/zsh/sh, macOS .command/.tool) detection rules.

Also carries the macOS-stealer behaviour combos, since those chains are usually shell scripts.
"""
from __future__ import annotations

from .scripts_common import COMBOS, C, R, make_script_analyzer

RULES = [
    # download + execute
    R("PipeToShell",
      r"(?:curl|wget|fetch)\b[^|\n<>]{0,300}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python[0-9.]*|perl|ruby)\b", 30,
      "Pipes a downloaded script straight into an interpreter", "download,exec",
      need="curl|wget|fetch"),
    R("Download", r"\b(?:curl|wget|fetch)\b[^\n]{0,200}\bhttps?://", 0,
      "Downloads a remote resource", "download", need="curl|wget|fetch"),
    R("DecodePipe",
      r"base64\s+(?:-d|-D|--decode)\b[^|\n]{0,120}\|\s*(?:bash|sh|zsh|python[0-9.]*|perl|ruby)\b|"
      r"\|\s*base64\s+(?:-d|-D|--decode)\b[^|\n]{0,80}\|\s*(?:bash|sh|zsh)\b", 35,
      "Decodes base64 and pipes it into a shell", "decode,exec", need="base64"),
    R("EvalSubshell", r"\beval\s+[\"']?\$\(|\beval\s+[\"']?`", 0,
      "eval of command substitution output", "exec", need="eval"),
    R("ReverseShellDevTcp", r"/dev/(?:tcp|udp)/[0-9a-z.\-]+/\d+", 45,
      "Reverse-shell redirection via /dev/tcp", "exec,exfil", need="/dev/tcp|/dev/udp"),
    R("NamedPipeShell", r"mkfifo\b[^\n]{0,120}(?:nc|ncat|netcat|/dev/tcp)|"
      r"(?:nc|ncat|netcat)\b[^\n]{0,60}-e\s+/?(?:bin/)?(?:sh|bash)", 40,
      "Backconnect shell via netcat / named pipe", "exec,exfil", need="mkfifo|nc |ncat|netcat"),
    # macOS evasion
    R("RemoveQuarantine", r"xattr\b[^\n]{0,80}?-d(?:r)?\s+com\.apple\.quarantine|xattr\s+-c(?:r)?\b", 20,
      "Strips the com.apple.quarantine attribute (Gatekeeper evasion)", "evasion",
      need="quarantine|xattr"),
    R("DisableGatekeeper", r"spctl\s+--master-disable|spctl\s+--(?:add|disable)\b|"
      r"csrutil\s+disable", 30, "Disables Gatekeeper / SIP", "evasion", need="spctl|csrutil"),
    R("SudoNoPasswd", r"echo\b[^\n]{0,60}\|\s*sudo\s+-S\b|NOPASSWD\s*:\s*ALL", 25,
      "Feeds a password to sudo / grants passwordless sudo", "evasion,cred", need="sudo|nopasswd"),
    # macOS credentials / keychain
    R("KeychainAccess", r"security\s+(?:find-generic-password|find-internet-password|dump-keychain|"
      r"unlock-keychain)|login\.keychain(?:-db)?", 25,
      "Reads macOS keychain secrets", "cred,keychain",
      need="security find|dump-keychain|unlock-keychain|login.keychain"),
    R("DsclAuth", r"dscl\s+\.\s+-authonly|dscl\s+\.\s+(?:-)?read[^\n]{0,40}password", 30,
      "Validates account passwords via dscl", "cred", need="dscl"),
    R("BrowserData", r"Library/Application Support/(?:Google/Chrome|BraveSoftware|Microsoft Edge|"
      r"Firefox)[^\n]{0,80}(?:Cookies|Login Data|Local State|key4\.db|logins\.json)|"
      r"/Cookies\.binarycookies|key4\.db|logins\.json", 0,
      "Accesses browser credential / cookie stores", "browser,cred",
      need="chrome|brave|edge|firefox|cookies.binarycookies|key4|logins.json"),
    # exfil / archive
    # scp needs a real "user@host:" destination (not an scp://user:pass@ URL in prose)
    R("Exfil", r"curl\b[^\n]{0,160}(?:-F\b|--form\b|-d\b|--data\b|-T\b|--upload-file\b)[^\n]{0,120}https?://|"
      r"\bscp\s[^\n]{0,120}\s[\w.-]{1,64}@[\w.-]{1,253}:", 5, "Uploads collected data to a remote endpoint", "exfil",
      need="curl|scp"),
    R("Archive", r"\bzip\s+-r\b|\bditto\s+-c\b|tar\s+-?c[zj]?f\b", 0,
      "Archives files before exfiltration", "archive", need="zip|ditto|tar"),
    R("PasswordPrompt",
      r"osascript\b[^\n]{0,160}display dialog[^\n]{0,160}(?:hidden answer|password)", 20,
      "Fake password prompt via osascript", "prompt,cred", need="osascript"),
    # persistence
    # /System/Library/Launch* is SIP-protected and only populated by Apple installers; "$3/Library/..."
    # is a pkg postinstall (re)loading the agent its own payload just installed on the target
    # volume (that plist is analysed on its own as part of the payload)
    R("LaunchctlPersist", r"launchctl\s+(?:load|bootstrap|enable)\b[^\n]{0,120}"
      r"(?<!System/)(?<!\$3/)(?<!\{3\}/)Library/Launch(?:Agents|Daemons)", 20,
      "Installs a LaunchAgent/Daemon", "persist", need="launchctl"),
    R("CrontabPersist", r"crontab\b[^\n]{0,40}(?:-|<)|\(crontab\s+-l", 15,
      "Cron-based persistence", "persist", need="crontab"),
    R("HiddenExec", r"nohup\b[^\n]{0,120}&\s*$|\bdisown\b|>\s*/dev/null\s+2>&1\s*&", 0,
      "Backgrounds execution / hides output", "hidden", need="nohup|disown|/dev/null"),
]

STEALER_COMBOS = [
    C("MacStealer", "prompt,exfil", 60, "macOS stealer chain: password prompt + credential/browser access + upload",
      "keychain,browser,cred", window=4000),
    C("KeychainExfil", "keychain,exfil", 45, "Reads keychain secrets and uploads them", window=4000),
    C("BrowserExfil", "browser,exfil", 40, "Steals browser data and uploads it", window=4000),
]

make_script_analyzer("ShellAnalyzer", "shell", {"shell", "script"}, "shell", RULES,
                     combos=STEALER_COMBOS + COMBOS)

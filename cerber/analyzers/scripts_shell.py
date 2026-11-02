"""POSIX shell (bash/zsh/sh, macOS .command/.tool) detection rules.

Also carries the macOS-stealer behaviour combos, since those chains are usually shell scripts.
"""
from __future__ import annotations

from .scripts_common import COMBOS, C, R, make_script_analyzer

# interpreters a downloaded/decoded payload is piped into
_INTERP = r"(?:bash|sh|zsh|python[0-9.]*|perl|ruby|node|php|osascript|osacompile)"

RULES = [
    # download + execute
    R("PipeToShell",
      r"(?:curl|wget|fetch)\b[^|\n<>]{0,300}\|\s*(?:sudo\s+)?" + _INTERP + r"\b", 30,
      "Pipes a downloaded script straight into an interpreter", "download,exec",
      need="curl|wget|fetch"),
    R("Download", r"\b(?:curl|wget|fetch)\b[^\n]{0,200}\bhttps?://", 0,
      "Downloads a remote resource", "download", need="curl|wget|fetch"),
    R("DecodePipe",
      # <decoder> ... | <interpreter>   and   ... | <decoder> ... | <interpreter>
      r"(?:base64|base32)\s+(?:-d|-D|--decode)\b[^|\n]{0,120}\|\s*" + _INTERP + r"\b|"
      r"\bxxd\s+(?:-r|-p\s+-r|-rp)\b[^|\n]{0,120}\|\s*" + _INTERP + r"\b|"
      r"\|\s*(?:base64|base32)\s+(?:-d|-D|--decode)\b[^|\n]{0,80}\|\s*(?:bash|sh|zsh|" + _INTERP + r")\b|"
      r"\|\s*xxd\s+(?:-r|-p\s+-r|-rp)\b[^|\n]{0,80}\|\s*" + _INTERP + r"\b|"
      r"openssl\s+(?:enc\s+)?[^|\n]{0,80}-d\b[^|\n]{0,120}\|\s*" + _INTERP + r"\b|"
      # decode -> decompress -> interpreter (xxd -r | gunzip | sh ; base64 -d | gzcat | bash)
      r"(?:base64|base32)\s+(?:-d|-D|--decode)\b[^|\n]{0,80}\|\s*(?:gunzip|gzcat|zcat|bunzip2|unxz|xz\s+-d)\b[^|\n]{0,40}"
      r"\|\s*" + _INTERP + r"\b|"
      r"\bxxd\s+(?:-r|-p\s+-r|-rp)\b[^|\n]{0,80}\|\s*(?:gunzip|gzcat|zcat|bunzip2|unxz|xz\s+-d)\b[^|\n]{0,40}"
      r"\|\s*" + _INTERP + r"\b", 35,
      "Decodes an encoded blob and pipes it into an interpreter", "decode,exec",
      need="base64|base32|xxd|openssl"),
    R("EvalDecode",
      # eval "$( ... base64|base32|xxd|gunzip|openssl -d ... )"  /  eval $(... | base64 -D)
      r"\beval\s+[\"']?\$\((?:[^()\n]|\([^()\n]{0,200}\)){0,400}?"
      r"(?:base64\s+-[dD]|base32\s+-d|xxd\s+-r|gunzip|gzcat|zcat|openssl\b[^)\n]{0,60}-d|\brev\b)", 35,
      "Decodes an encoded blob inside eval and runs it", "decode,exec", need="eval"),
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
    # macOS credentials / keychain.  Reading *other* apps' secrets is the stealer signal: dumping the whole
    # keychain, or `find-(generic|internet)-password` with -g/-w/-a (printing a secret by account across
    # services, incl. "<Browser> Safe Storage").  Apps managing their *own* item (`-s <service> -a <acct>`,
    # add/delete, a plain unlock) are not scored – that is what notarized installers/updaters do.
    R("KeychainDump",
      r"security\s+(?:[^\n]{0,40}\s)?dump-keychain|"
      # account-sweep flag clusters (-ga/-wa/-gaw…) or a browser/"Safe Storage" target: how stealers dump
      # other apps' secrets.  `-s <service> -a <acct> -w` (an app reading its own item) is deliberately excluded.
      r"security\b[^\n]{0,80}find-(?:generic|internet)-password\b[^\n]{0,20}-(?:[agw]*a[agw]*[gw]|[agw]*[gw][agw]*a)\b|"
      r"security\b[^\n]{0,120}find-(?:generic|internet)-password\b[^\n]{0,80}"
      r"(?:chrome|brave|edge|firefox|opera|vivaldi|safe\s+storage)", 25,
      "Reads macOS keychain secrets of other applications", "cred,keychain",
      need="dump-keychain|find-generic-password|find-internet-password"),
    R("KeychainAccess",
      r"security\s+(?:find-generic-password|find-internet-password|unlock-keychain)\b|login\.keychain(?:-db)?", 0,
      "Uses the macOS keychain", "keychain",
      need="security find|unlock-keychain|login.keychain"),
    R("DsclAuth", r"dscl\s+[./][^\n]{0,20}-authonly|dscl\s+\.\s+(?:-)?read[^\n]{0,40}password", 30,
      "Validates account passwords via dscl", "cred", need="dscl"),
    R("BrowserData", r"Library/Application Support/(?:Google/Chrome|BraveSoftware|Microsoft Edge|"
      r"Firefox)[^\n]{0,80}(?:Cookies|Login Data|Local State|key4\.db|logins\.json)|"
      r"/Cookies\.binarycookies|key4\.db|logins\.json", 0,
      "Accesses browser credential / cookie stores", "browser,cred,collect",
      need="chrome|brave|edge|firefox|cookies.binarycookies|key4|logins.json"),
    # sensitive local secrets (ssh/cloud/git credentials) – data-collection capability
    R("SensitiveFiles",
      r"(?:/\.ssh/(?:id_[a-z0-9]+|authorized_keys)|/\.aws/credentials|/\.config/gcloud|/\.kube/config|"
      r"/\.docker/config\.json|/\.netrc|/\.npmrc|/\.gnupg/|/\.config/git/credentials|\.gitconfig)\b", 0,
      "Reads local SSH / cloud / git credential files", "collect,cred",
      need=".ssh/|.aws/|gcloud|.kube/|.docker/|.netrc|.npmrc|.gnupg|credentials|.gitconfig"),
    R("WalletFiles",
      r"(?:Exodus/exodus\.wallet|Electrum/wallets|Coinomi/wallets|wallet\.dat|"
      r"Ledger\s+Live|Atomic/Local Storage|Keychains/login\.keychain)[^\n]{0,80}|"
      r"(?:nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa)", 0,
      "References crypto-wallet data stores / wallet extension IDs", "wallet,collect",
      need="wallet|exodus|electrum|coinomi|ledger|atomic|nkbihfbeo|bfnaelmome"),
    # exfil / archive
    # scp needs a real "user@host:" destination (not an scp://user:pass@ URL in prose)
    R("Exfil",
      r"curl\b[^\n]{0,200}(?:-F\b|--form\b|-d\b|--data\b|--data-binary\b|-T\b|--upload-file\b)[^\n]{0,160}https?://|"
      r"curl\b[^\n]{0,200}https?://[^\n]{0,160}(?:-F\b|--form\b|--data-binary\b|-T\b|--upload-file\b)|"
      r"\bscp\s[^\n]{0,120}\s[\w.-]{1,64}@[\w.-]{1,253}:", 5, "Uploads collected data to a remote endpoint", "exfil",
      need="curl|scp"),
    # uploading a private key / credential store / browser secret is, on its own, a strong stealer signal
    R("UploadSecretFile",
      r"(?:-F|--form|--data-binary|-T|--upload-file)\s*[\"']?[^\n\"']{0,40}"
      r"@[^\n\"']{0,120}(?:id_[a-z0-9]+|\.ssh/|\.aws/credentials|login\.keychain|key4\.db|logins\.json|"
      r"Login Data|Cookies\.binarycookies|\.wallet)\b", 35,
      "Uploads a private key / credential store to a remote endpoint", "exfil,collect",
      need="@"),
    R("Archive", r"\bzip\s+-[qr]{0,2}r\b|\bditto\s+-c\b|\bditto\s+-ck?\b|tar\s+-?c[zj]?f?\b", 0,
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
    # loginwindow LoginHook/LogoutHook is deprecated and almost only used by malware now
    R("LoginHook", r"defaults\s+write\b[^\n]{0,80}com\.apple\.loginwindow\b[^\n]{0,40}(?:Login|Logout)Hook", 35,
      "Installs a loginwindow LoginHook/LogoutHook (persistence)", "persist", need="loginwindow"),
    # DYLD_INSERT_LIBRARIES made persistent (launchctl setenv / written into a shell rc) = library injection
    R("DyldInjectPersist",
      r"launchctl\s+setenv\s+DYLD_INSERT_LIBRARIES\b|"
      r"DYLD_INSERT_LIBRARIES=[^\n]{0,120}>>\s*[^\n]{0,80}(?:\.zshrc|\.bashrc|\.bash_profile|\.zprofile|\.profile)|"
      r">>\s*[^\n]{0,80}(?:\.zshrc|\.bashrc|\.bash_profile|\.zprofile|\.profile)[^\n]{0,80}DYLD_INSERT_LIBRARIES", 35,
      "Persists a DYLD_INSERT_LIBRARIES library injection", "persist,evasion", need="dyld_insert_libraries"),
    R("HiddenExec", r"nohup\b[^\n]{0,120}&\s*$|\bdisown\b|>\s*/dev/null\s+2>&1\s*&", 0,
      "Backgrounds execution / hides output", "hidden", need="nohup|disown|/dev/null"),
    # a payload dropped into a temp / hidden location, made executable and run (loader last stage)
    R("Dropper",
      r"chmod\s+(?:\+x|[0-7]*[1357][0-7]{0,2})\s+[\"']?[^\n\"']{0,100}"
      r"(?:/tmp/|/private/tmp/|/var/tmp/|/users/shared/|/dev/shm/|/library/caches/|/\.[\w.][\w./-]{0,60})", 0,
      "Makes a file in a temp/hidden location executable", "dropper", need="chmod"),
]

STEALER_COMBOS = [
    C("MacStealer", "prompt,exfil", 60, "macOS stealer chain: password prompt + credential/browser access + upload",
      "keychain,browser,cred,collect,wallet", window=4000),
    C("KeychainExfil", "keychain,exfil", 45, "Reads keychain secrets and uploads them", window=4000),
    C("BrowserExfil", "browser,exfil", 40, "Steals browser data and uploads it", window=4000),
]

make_script_analyzer("ShellAnalyzer", "shell", {"shell", "script"}, "shell", RULES,
                     combos=STEALER_COMBOS + COMBOS)

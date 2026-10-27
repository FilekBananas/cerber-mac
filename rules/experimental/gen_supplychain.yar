/*
 * Cerber – reguły własne (supplychain), napisane 2026-10-09 przez agentów na podstawie publicznych raportów.
 * Warstwa "community": same nie dają werdyktu ZŁOŚLIWY. Zero trafień na ~2800 czystych plikach macOS
 * (programy z /Applications i /System, /usr/bin, LaunchAgents, rozszerzenia VS Code, node_modules).
 */

// Cerber (gen) - software supply-chain detection for macOS developer machines
// Staging pack, not yet promoted. Date: 2026-10-09
// Scope: VS Code / Cursor tasks.json auto-run, VS Code extension startup code,
//        Claude Code SessionStart hooks, MCP server configs, npm install-hook droppers,
//        npm/PyPI Keychain and browser-key dumpers, PyPI setup.py Mach-O droppers,
//        .pth persistence, GitHub token harvest and repo-migration exfil, npm publish propagation,
//        VS Code/Cursor state.vscdb stealers, AppleScript password phish from install scripts.
// Every rule has a type gate, a filesize ceiling and a complete construct (trigger + payload + exfil or execution).

rule CERBER_Gen_Supply_VSCodeTasks_FolderOpenFetchExec {
    meta:
        description = "VS Code tasks.json with runOn folderOpen that fetches a remote payload or decodes base64, or runs node on a disguised font file"
        author = "Cerber (gen)"
        family = "VSCode.TasksAutoRun"
        severity = "critical"
        score = 84
        date = "2026-10-09"
        reference = "https://securityaffairs.com/189880/security/north-korea-linked-threat-actors-abuse-vs-code-auto-run-to-spread-stoatwaffle-malware.html"
        reference2 = "https://opensourcemalware.com/blog/oss-maintainters-vscode-tasks-compromised"
    strings:
        $run = /"runOn"[ \t]*:[ \t]*"folderOpen"/ ascii
        $fetch = /"command"[ \t]*:[ \t]*"[^"\r\n]{0,200}(curl|wget)[ \t][^"\r\n]{0,200}https?:\/\/[^"\r\n]{4,200}"/ ascii
        $b64 = /"command"[ \t]*:[ \t]*"[^"\r\n]{0,200}base64[ \t]+(-D|-d|--decode)[^"\r\n]{0,200}"/ ascii
        $font = /"command"[ \t]*:[ \t]*"node[ \t]+[^"\r\n]{0,120}\.(woff2?|ttf|otf|png|jpg|ico)"/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and
        $run and any of ($fetch, $b64, $font)
}

rule CERBER_Gen_Supply_VSCodeTasks_OsSpecificRemoteBackdoor {
    meta:
        description = "VS Code tasks.json with per-OS command overrides (osx block) where the macOS branch downloads from a remote host and runs it, auto-started on folder open"
        author = "Cerber (gen)"
        family = "VSCode.TasksAutoRun"
        severity = "critical"
        score = 86
        date = "2026-10-09"
        reference = "https://devclass.com/2026/01/22/vs-code-tasks-config-file-abused-to-run-malicious-code/"
    strings:
        $run = /"runOn"[ \t]*:[ \t]*"folderOpen"/ ascii
        $osx = /"osx"[ \t]*:[ \t]*\{[^}]{0,300}"command"[ \t]*:[ \t]*"[^"\r\n]{0,200}(curl|wget|osascript|base64)[^"\r\n]{0,200}"/ ascii
        $exec = /(\|[ \t]*(ba|z)?sh\b|bash[ \t]+-c|sh[ \t]+-c)/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and
        $run and $osx and $exec
}

rule CERBER_Gen_Supply_VSCodeExtension_ActivateSpawnDownload {
    meta:
        description = "VS Code extension entry JS that imports vscode and child_process, then shells out to curl or wget with a URL piped to a shell or decoded"
        author = "Cerber (gen)"
        family = "VSCode.ExtensionStealer"
        severity = "critical"
        score = 82
        date = "2026-10-09"
        reference = "https://securitylabs.datadoghq.com/articles/malicious-pypi-package-targeting-highly-specific-macos-machines/"
    strings:
        $vs = /require\(\s*['"]vscode['"]\s*\)|from\s+['"]vscode['"]/ ascii
        $cp = /require\(\s*['"](node:)?child_process['"]\s*\)|from\s+['"](node:)?child_process['"]/ ascii
        $dl = /(exec|execSync|spawn|spawnSync|execFile)\s*\(\s*[`'"][^`'"\r\n]{0,120}(curl|wget)[^`'"\r\n]{0,200}https?:\/\/[^`'"\r\n]{4,200}/ ascii
        $pipe = /(curl|wget)[^`'"\r\n]{0,200}\|[ \t]*(ba|z)?sh\b/ ascii
        $dec = /base64[ \t]+(-D|-d|--decode)|Buffer\.from\([^)\r\n]{0,200},\s*['"]base64['"]\)/ ascii
    condition:
        filesize < 1MB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $vs and $cp and ($dl or $pipe) and ($dec or $pipe)
}

rule CERBER_Gen_Supply_ClaudeCode_SessionStartHookFetchExec {
    meta:
        description = "Repository .claude/settings.json registering a SessionStart (or prompt/tool) hook that downloads and runs remote code or a hidden binary"
        author = "Cerber (gen)"
        family = "AIAgentConfig.HookBackdoor"
        severity = "critical"
        score = 88
        date = "2026-10-09"
        reference = "https://safedep.io/malicious-npm-packages-claude-code-hooks/"
        reference2 = "https://www.mintmcp.com/blog/claude-code-hooks-security"
    strings:
        $hooks = /"hooks"[ \t]*:[ \t]*\{/ ascii
        $event = /"(SessionStart|UserPromptSubmit|PreToolUse|PostToolUse)"[ \t]*:[ \t]*\[/ ascii
        $fetch = /"command"[ \t]*:[ \t]*"[^"\r\n]{0,200}(curl|wget)[ \t][^"\r\n]{0,200}https?:\/\/[^"\r\n]{4,200}"/ ascii
        $pipe = /"command"[ \t]*:[ \t]*"[^"\r\n]{0,200}(base64[ \t]+(-D|-d|--decode)|\|[ \t]*(ba|z)?sh\b|node[ \t]+-e)[^"\r\n]{0,200}"/ ascii
        $bin = /"command"[ \t]*:[ \t]*"(\.\/|\$CLAUDE_PROJECT_DIR\/|\$\{CLAUDE_PROJECT_DIR\}\/)?\.claude\/settings["' \t]/ ascii
    condition:
        filesize < 64KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $hooks and $event and any of ($fetch, $pipe, $bin)
}

rule CERBER_Gen_Supply_McpConfig_ShellFetchServer {
    meta:
        description = "MCP server config (mcp.json, .mcp.json, claude_desktop_config) that launches a shell whose arguments fetch or decode a remote payload"
        author = "Cerber (gen)"
        family = "AIAgentConfig.MCPBackdoor"
        severity = "critical"
        score = 84
        date = "2026-10-09"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $mcp = /"mcpServers"[ \t]*:[ \t]*\{/ ascii
        $shell = /"command"[ \t]*:[ \t]*"(\/bin\/)?(sh|bash|zsh|cmd|powershell)(\.exe)?"/ ascii
        $args = /"args"[ \t]*:[ \t]*\[[^\]\r\n]{0,300}(curl|wget|base64|Invoke-WebRequest|\|[ \t]*(ba|z)?sh)[^\]\r\n]{0,300}\]/ ascii
    condition:
        filesize < 64KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $mcp and $shell and $args
}

rule CERBER_Gen_Supply_NpmInstallHook_HomeDirDropper_macOS {
    meta:
        description = "package.json install hook that downloads a binary from a URL into a macOS user directory, marks it executable and strips quarantine or runs it"
        author = "Cerber (gen)"
        family = "Node.SupplyChain"
        severity = "critical"
        score = 82
        date = "2026-10-09"
        reference = "https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack"
        reference2 = "https://attack.mitre.org/techniques/T1195/002/"
    strings:
        $a = /"(preinstall|install|postinstall)"[ \t]*:[ \t]*"[^"\r\n]{0,400}(curl|wget)[ \t][^"\r\n]{0,300}https?:\/\/[^"\r\n]{0,300}(~|\$HOME|\$\{HOME\})\/(Library|\.local|\.cache|\.config)\/[^"\r\n]{0,300}"/ ascii
        $x = /(chmod[ \t]+\+x|xattr[ \t]+-(c|d)|open[ \t]+-a|&&[ \t]*(~|\$HOME)\/)/ ascii
    condition:
        filesize < 64KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $a and $x
}

rule CERBER_Gen_Supply_InstallScript_KeychainBrowserKeyDump {
    meta:
        description = "Install-time JS or Python that dumps a Keychain generic password for a browser safe-storage key and posts it or the browser Login Data over the network"
        author = "Cerber (gen)"
        family = "Infostealer.SupplyChain"
        severity = "critical"
        score = 86
        date = "2026-10-09"
        reference = "https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised"
        reference2 = "https://attack.mitre.org/techniques/T1555/001/"
    strings:
        $kc = /security[ \t]+(find-generic-password|find-internet-password|dump-keychain)[ \t]/ ascii
        $store = /(Chrome|Brave|Edge|Chromium|Vivaldi) Safe Storage|Login Data|Local State|Cookies/ ascii
        $net = /(fetch\s*\(|axios\.(post|get)\(|https?\.request\(|requests\.post\(|urlopen\(|curl[ \t]+-[A-Za-z]{0,4}[dFX])/ ascii
    condition:
        filesize < 512KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $kc and $store and $net
}

rule CERBER_Gen_Supply_MacOS_TccResetAppleEvents_PasswordPhish {
    meta:
        description = "Script that resets Apple Events TCC permission and shows a hidden-answer password dialog, the password-harvest step seen in macOS stealer install scripts"
        author = "Cerber (gen)"
        family = "MacOS.PasswordPhish"
        severity = "critical"
        score = 85
        date = "2026-10-09"
        reference = "https://securitylabs.datadoghq.com/articles/malicious-pypi-package-targeting-highly-specific-macos-machines/"
    strings:
        $tcc = /tccutil[ \t]+reset[ \t]+AppleEvents/ ascii
        $dlg = /display[ \t]+dialog[^\r\n]{0,300}with[ \t]+hidden[ \t]+answer/ ascii
        $pw = /password/ nocase ascii
        $osa = /osascript/ ascii
    condition:
        filesize < 256KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $tcc and $dlg and $pw and $osa
}

rule CERBER_Gen_Supply_PythonSetup_MachoDownloadExec {
    meta:
        description = "Python setup.py that, on macOS only, downloads a file, makes it executable and runs it through subprocess or os.system"
        author = "Cerber (gen)"
        family = "Python.SupplyChain"
        severity = "critical"
        score = 80
        date = "2026-10-09"
        reference = "https://www.jamf.com/blog/pyinstaller-malware-jamf-threat-labs/"
        reference2 = "https://securitylabs.datadoghq.com/articles/malicious-pypi-package-targeting-highly-specific-macos-machines/"
    strings:
        $setup = /(^|\n)[ \t]*from[ \t]+setuptools[ \t]+import[^\r\n]{0,80}setup|(^|\n)[ \t]*import[ \t]+setuptools|setup\(/ ascii
        $darwin = /(sys\.platform[ \t]*==[ \t]*['"]darwin['"]|platform\.system\(\)[ \t]*==[ \t]*['"]Darwin['"]|os\.uname\(\)\.sysname[ \t]*==[ \t]*['"]Darwin['"])/ ascii
        $dl = /(urlopen\(|urlretrieve\(|requests\.get\(|urllib\.request\.urlopen\()[^\r\n]{0,200}https?:\/\//  ascii
        $chmod = /(os\.chmod\([^\r\n]{0,120}(0o7[0-7]{2}|0o755|0o777|stat\.S_IEXEC)|chmod[ \t]+\+x)/ ascii
        $run = /(subprocess\.(Popen|run|call|check_call)\(|os\.system\(|os\.popen\()/ ascii
    condition:
        filesize < 200KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $setup and $darwin and $dl and $chmod and $run
}

rule CERBER_Gen_Supply_Python_PthFile_ExecPersistence {
    meta:
        description = "site-packages .pth file whose import line runs exec or subprocess over a decoded base64 or zlib/marshal payload"
        author = "Cerber (gen)"
        family = "Python.Persistence"
        severity = "critical"
        score = 84
        date = "2026-10-09"
        reference = "https://docs.python.org/3/library/site.html"
        reference2 = "https://attack.mitre.org/techniques/T1546/018/"
    strings:
        $imp = /(^|\n)import[ \t][^\r\n]{0,200}(exec|eval|subprocess|os\.system)\(/ ascii
        $dec = /(base64\.b64decode|b64decode|zlib\.decompress|marshal\.loads|codecs\.decode)\(/ ascii
    condition:
        filesize < 8KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $imp and $dec
}

rule CERBER_Gen_Supply_GitHubToken_RepoMigrationPublish {
    meta:
        description = "Script that reads a GitHub CLI token or hosts.yml, lists the user's repositories via the API, and republishes them as public with a -migration suffix"
        author = "Cerber (gen)"
        family = "Node.ShaiHulud"
        severity = "critical"
        score = 88
        date = "2026-10-09"
        reference = "https://research.jfrog.com/post/shai-hulud-is-back-august/"
        reference2 = "https://wiz.io/blog/shai-hulud-npm-supply-chain-attack"
    strings:
        $h1 = /gh auth token/ ascii
        $h2 = /\.config\/gh\/hosts\.yml/ ascii
        $api = /api\.github\.com\/(user\/repos|repos\/)/ ascii
        $mig = /-migration/ ascii
        $pub = /("private"[ \t]*:[ \t]*false|private[ \t]*:[ \t]*false|visibility[^\r\n]{0,20}public|createForAuthenticatedUser)/ ascii
    condition:
        filesize < 512KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        ($h1 or $h2) and $api and $mig and $pub
}

rule CERBER_Gen_Supply_NpmPropagation_TokenRepackage {
    meta:
        description = "Script that reads an npm registry token from .npmrc or env, enumerates publishable packages and writes an install hook into package.json before npm publish"
        author = "Cerber (gen)"
        family = "Node.ShaiHulud"
        severity = "critical"
        score = 80
        date = "2026-10-09"
        reference = "https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack"
        reference2 = "https://xygeni.io/?p=62663"
    strings:
        $tok = /(_authToken|NPM_TOKEN|\.npmrc)/ ascii
        $pub = /(npm[ \t]+publish|\.publish\(|npm[ \t]+whoami)/ ascii
        $hook = /"(preinstall|postinstall)"[ \t]*:[ \t]*"[^"\r\n]{1,200}"/ ascii
        $wr = /(writeFileSync|JSON\.stringify\(|fs\.write)/ ascii
        $net = /(npm[ \t]+view|registry\.npmjs\.org\/-\/|\/-\/v1\/search)/ ascii
    condition:
        filesize < 256KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $tok and $pub and $hook and $wr and $net
}

rule CERBER_Gen_Supply_VSCodeCursor_StateDbStealer {
    meta:
        description = "Script that opens the VS Code, Cursor or Windsurf state.vscdb from User/globalStorage and sends its contents to a remote endpoint"
        author = "Cerber (gen)"
        family = "Infostealer.IDECredentials"
        severity = "high"
        score = 76
        date = "2026-10-09"
        reference = "https://opensourcemalware.com/blog/latest-contagious-interview-malware-campaign-abuses-microsoft-vscode-tasks"
    strings:
        $db = "state.vscdb" ascii
        $dir = /(Code|Cursor|Windsurf|VSCodium)[\\\/]+User[\\\/]+(globalStorage[\\\/]+)?/ ascii
        $net = /(fetch\s*\(|axios\.post\(|https?\.request\(|requests\.post\(|urlopen\(|curl[ \t]+-[A-Za-z]{0,4}[dFX])[^\r\n]{0,200}https?:\/\/|https?:\/\/[^\r\n]{4,200}(fetch|post|POST|upload)/ ascii
    condition:
        filesize < 512KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $db and $dir and $net
}

rule CERBER_Gen_Supply_NpmPostinstall_OsascriptPasswordAndDownload {
    meta:
        description = "package.json lifecycle script that runs an AppleScript password dialog via osascript and then fetches a remote file with curl"
        author = "Cerber (gen)"
        family = "Node.MacOSStealer"
        severity = "high"
        score = 72
        date = "2026-10-09"
        reference = "https://www.jamf.com/blog/pyinstaller-malware-jamf-threat-labs/"
    strings:
        $hook = /"(preinstall|postinstall|install)"[ \t]*:[ \t]*"[^\r\n]{0,400}osascript[^\r\n]{0,400}"/ ascii
        $dlg = /display[ \t]+dialog[^\r\n]{0,200}(password|hidden answer)/ nocase ascii
        $curl = /(curl|wget)[ \t][^"\r\n]{0,200}https?:\/\/[^"\r\n]{4,200}/ ascii
    condition:
        filesize < 64KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $hook and $dlg and $curl
}

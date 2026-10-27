/*
 * Cerber – reguły własne (persistence), napisane 2026-10-09 przez agentów na podstawie publicznych raportów.
 * Warstwa "community": same nie dają werdyktu ZŁOŚLIWY. Zero trafień na ~2800 czystych plikach macOS
 * (programy z /Applications i /System, /usr/bin, LaunchAgents, rozszerzenia VS Code, node_modules).
 */

/*
 * CERBER - macOS malicious persistence artefacts (generated staging pack)
 *
 * Scope: LaunchAgent / LaunchDaemon plists, emond rules, configuration profiles,
 *        shell start files (.zshenv, .zshrc, .bash_profile), crontab entries and
 *        AppleScript login-item creation.
 *
 * Gates (same policy as rules/custom/macos.yar):
 *   plist / profile / emond  : uint32be(0) == 0x3c3f786d  ("<?xm" -> "<?xml")
 *   script / rc / crontab    : first 8 bytes are text (uint8 in 9..126)
 *   every rule carries a filesize ceiling and encodes a complete malicious construct
 *   (download-and-run, decode-and-run, reverse shell, hidden-path launch ...), not a bare
 *   "LaunchAgent" keyword.
 *
 * Score meta: >= 75 -> CERTAIN, < 75 -> HIGH (behavioural).
 * Author: Cerber (gen) | Date: 2026-10-09
 */

// ============================================================================
// LaunchAgent / LaunchDaemon plists
// Reference: SentinelOne "how malware persists on macOS", SANS ISC diary 24230,
//            launchd.plist(5) man page
// ============================================================================

rule CERBER_Gen_Persist_LaunchAgent_Curl_Pipe_Shell {
    meta:
        description = "launchd plist whose ProgramArguments download a remote script and pipe it into a shell"
        author = "Cerber (gen)"
        family = "Generic.Persistence.Launchd"
        severity = "critical"
        score = 88
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/how-malware-persists-on-macos/"
    strings:
        $pa = "<key>ProgramArguments</key>" ascii
        $run = "<key>RunAtLoad</key>" ascii
        $keep = "<key>KeepAlive</key>" ascii
        $pipe = /(curl|wget)\s[^<]{0,300}\|\s*(ba|z)?sh[ \t\n<&;"']/ ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 64KB and $pa and ($run or $keep) and $pipe
}

rule CERBER_Gen_Persist_LaunchAgent_Base64_Decode_Exec {
    meta:
        description = "launchd plist decoding a base64 blob and executing it through a shell or python"
        author = "Cerber (gen)"
        family = "Generic.Persistence.Launchd"
        severity = "critical"
        score = 86
        date = "2026-10-09"
        reference = "https://socprime.com/active-threats/macos-stealers-observed-what-defenders-should-watch-for/"
    strings:
        $pa = "<key>ProgramArguments</key>" ascii
        $run = "<key>RunAtLoad</key>" ascii
        $keep = "<key>KeepAlive</key>" ascii
        $dec = /base64\s+(-d|-D|--decode)\s*\|\s*(ba|z)?sh[ \t\n<&;"']/ ascii
        $dec2 = /base64\s+(-d|-D|--decode)\s*\|\s*python3?/ ascii
        $dec3 = /\|\s*base64\s+(-d|-D|--decode)[^<]{0,60}\|\s*(ba|z)?sh/ ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 64KB and $pa and ($run or $keep) and 1 of ($dec*)
}

rule CERBER_Gen_Persist_LaunchAgent_Python_Exec_Blob {
    meta:
        description = "launchd plist running python -c with a base64 or exec/compile payload"
        author = "Cerber (gen)"
        family = "Generic.Persistence.Launchd"
        severity = "critical"
        score = 82
        date = "2026-10-09"
        reference = "https://isc.sans.edu/diary/24230"
    strings:
        $pa = "<key>ProgramArguments</key>" ascii
        $run = "<key>RunAtLoad</key>" ascii
        $keep = "<key>KeepAlive</key>" ascii
        $py = /python3?(\s+-c\s|<\/string>\s*<string>-c<\/string>\s*<string>)[^<]{0,200}(b64decode|base64|exec\s*\(|compile\s*\()/ ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 64KB and $pa and ($run or $keep) and $py
}

rule CERBER_Gen_Persist_LaunchAgent_Osascript_Shell_Download {
    meta:
        description = "launchd plist running osascript -e 'do shell script' that fetches or stages a payload"
        author = "Cerber (gen)"
        family = "Generic.Persistence.Launchd"
        severity = "critical"
        score = 84
        date = "2026-10-09"
        reference = "https://socprime.com/active-threats/macos-stealers-observed-what-defenders-should-watch-for/"
    strings:
        $pa = "<key>ProgramArguments</key>" ascii
        $run = "<key>RunAtLoad</key>" ascii
        $keep = "<key>KeepAlive</key>" ascii
        $as = /osascript(\s+-e\s|<\/string>\s*<string>-e<\/string>\s*<string>)[^<]{0,300}do shell script[^<]{0,300}(curl|wget|base64|\/tmp\/|\/Users\/Shared\/)/ ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 64KB and $pa and ($run or $keep) and $as
}

rule CERBER_Gen_Persist_LaunchAgent_Download_Chmod_Exec {
    meta:
        description = "launchd plist that downloads a file into a temp/shared folder, marks it executable and runs it"
        author = "Cerber (gen)"
        family = "Generic.Persistence.Launchd"
        severity = "critical"
        score = 84
        date = "2026-10-09"
        reference = "https://socprime.com/active-threats/macos-stealers-observed-what-defenders-should-watch-for/"
    strings:
        $pa = "<key>ProgramArguments</key>" ascii
        $dl = /(curl|wget)\s[^<]{0,200}(\/tmp\/|\/private\/var\/tmp\/|\/Users\/Shared\/)[^<]{0,200}chmod\s+\+x[^<]{0,200}(\/tmp\/|\/private\/var\/tmp\/|\/Users\/Shared\/)/ ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 64KB and $pa and $dl
}

rule CERBER_Gen_Persist_LaunchAgent_Reverse_Shell {
    meta:
        description = "launchd plist carrying a reverse shell (nc -e, bash /dev/tcp, python socket+dup2/pty)"
        author = "Cerber (gen)"
        family = "Generic.Persistence.Launchd"
        severity = "critical"
        score = 90
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/how-malware-persists-on-macos/"
    strings:
        $pa = "<key>ProgramArguments</key>" ascii
        $nc = /(nc|ncat|netcat)\s+(-e|-c)\s+\/bin\/(ba|z)?sh/ ascii
        $tcp = /bash\s+-i\s+>&\s*\/dev\/tcp\/[0-9A-Za-z.-]{4,}\/[0-9]{2,5}/ ascii
        $tcp2 = /\/dev\/tcp\/[0-9.]{7,15}\/[0-9]{2,5}/ ascii
        $py = /socket\.socket\([^<]{0,200}(pty\.spawn|os\.dup2)/ ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 64KB and $pa and 1 of ($nc, $tcp, $tcp2, $py)
}

rule CERBER_Gen_Persist_LaunchAgent_Hidden_Temp_Program {
    meta:
        description = "launchd job executing a dot-named binary or script in a shared temp folder, kept alive or run at load"
        author = "Cerber (gen)"
        family = "Generic.Persistence.Launchd"
        severity = "high"
        score = 72
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/how-malware-persists-on-macos/"
    strings:
        $run = "<key>RunAtLoad</key>" ascii
        $keep = "<key>KeepAlive</key>" ascii
        $tmp = /<string>(\/Users\/Shared|\/private\/var\/tmp|\/var\/tmp|\/private\/tmp|\/tmp)\/\.[A-Za-z0-9_.-]{2,}[^<]{0,200}<\/string>/ ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 32KB and ($run or $keep) and $tmp
}

rule CERBER_Gen_Persist_LaunchAgent_Dotfolder_Library_Program {
    meta:
        description = "launchd job executing a binary from a hidden dot-folder under ~/Library, run at load or kept alive"
        author = "Cerber (gen)"
        family = "Generic.Persistence.Launchd"
        severity = "high"
        score = 70
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/how-malware-persists-on-macos/"
    strings:
        $run = "<key>RunAtLoad</key>" ascii
        $keep = "<key>KeepAlive</key>" ascii
        $pa = "<key>ProgramArguments</key>" ascii
        $lib = /<string>(\/Users\/[^<\/]{1,64}|~|\$HOME)\/Library\/\.[A-Za-z0-9_-]{2,}\/[^<]{1,200}<\/string>/ ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 32KB and $pa and ($run or $keep) and $lib
}

rule CERBER_Gen_Persist_LaunchDaemon_AppSupport_Hidden_Root {
    meta:
        description = "root LaunchDaemon running from a hidden dot-folder inside /Library/Application Support, RunAtLoad true"
        author = "Cerber (gen)"
        family = "Generic.Persistence.Launchd"
        severity = "high"
        score = 76
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/how-malware-persists-on-macos/"
    strings:
        $run_true = /<key>RunAtLoad<\/key>\s*<true\/>/ ascii
        $pa = "<key>ProgramArguments</key>" ascii
        $app = /<string>\/Library\/Application Support\/\.[A-Za-z0-9_-]{3,}\/[^<]{1,200}<\/string>/ ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 32KB and $pa and $run_true and $app
}

// ============================================================================
// emond and configuration profiles
// ============================================================================

rule CERBER_Gen_Persist_Emond_Rule_Shell_Command {
    meta:
        description = "emond rule whose Command runs a downloader, interpreter or hidden-path binary"
        author = "Cerber (gen)"
        family = "Generic.Persistence.Emond"
        severity = "critical"
        score = 80
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/how-malware-persists-on-macos/"
    strings:
        $cmd = /<key>Command<\/key>\s*<string>[^<]{0,300}(curl|wget|base64|osascript|nc\s|python3?\s|\/tmp\/|\/Users\/Shared\/)/ ascii
        $ev = "<key>EventTypes</key>" ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 32KB and $ev and $cmd
}

rule CERBER_Gen_Persist_Profile_Root_CA_Proxy {
    meta:
        description = "configuration profile installing a root CA and a global HTTP proxy (traffic interception)"
        author = "Cerber (gen)"
        family = "Generic.Persistence.Profile"
        severity = "high"
        score = 66
        date = "2026-10-09"
        reference = "https://attack.mitre.org/techniques/T1176/"
    strings:
        $root = "com.apple.security.root" ascii
        $proxy = "com.apple.proxy.http.global" ascii
        $srv = "<key>ProxyServer</key>" ascii
        $pt = "<key>PayloadType</key>" ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 256KB and $pt and $root and $proxy and $srv
}

// ============================================================================
// Shell start files, crontab and login items (text)
// ============================================================================

rule CERBER_Gen_Persist_ShellRC_Background_Reverse_Shell {
    meta:
        description = "zshenv/zshrc/bash_profile line that starts a reverse shell in the background"
        author = "Cerber (gen)"
        family = "Generic.Persistence.ShellRC"
        severity = "critical"
        score = 90
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/how-malware-persists-on-macos/"
    strings:
        $tcp = /\/dev\/tcp\/[0-9A-Za-z.-]{4,}\/[0-9]{2,5}/ ascii
        $nc = /(nc|ncat|netcat)\s+(-e|-c)\s+\/bin\/(ba|z)?sh/ ascii
        $py = /socket\.socket\([^\n]{0,200}(pty\.spawn|os\.dup2)/ ascii
        $bg1 = /&[ \t]*\r?\n/ ascii
        $bg2 = "nohup" ascii
        $bg3 = "disown" ascii
        $bg4 = /&>\s*\/dev\/null\s*&/ ascii
        $bg5 = /&\)[ \t]*\r?\n/ ascii
    condition:
        for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127) and filesize < 32KB and
        1 of ($tcp, $nc, $py) and 1 of ($bg*)
}

rule CERBER_Gen_Persist_ShellRC_Background_Curl_Pipe {
    meta:
        description = "zshenv/zshrc/bash_profile line that downloads and pipes a script into a shell in the background"
        author = "Cerber (gen)"
        family = "Generic.Persistence.ShellRC"
        severity = "high"
        score = 75
        date = "2026-10-09"
        reference = "https://socprime.com/active-threats/macos-stealers-observed-what-defenders-should-watch-for/"
    strings:
        $pipe = /(curl|wget)\s[^\n]{0,300}\|\s*(ba|z)?sh[^\n]{0,40}&[ \t]*\r?\n/ ascii
        $nohup = /nohup\s+(ba|z)?sh\s+-c\s[^\n]{0,200}(curl|wget)/ ascii
    condition:
        for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127) and filesize < 32KB and 1 of ($pipe, $nohup)
}

rule CERBER_Gen_Persist_ShellRC_Base64_Eval {
    meta:
        description = "shell start file that evals a base64-decoded payload on every shell start"
        author = "Cerber (gen)"
        family = "Generic.Persistence.ShellRC"
        severity = "critical"
        score = 85
        date = "2026-10-09"
        reference = "https://attack.mitre.org/techniques/T1546/004/"
    strings:
        $ev1 = /eval\s+["']?\$\(\s*(echo|printf)\s+['"]?[A-Za-z0-9+\/=]{20,}['"]?\s*\|\s*base64\s+(-d|-D|--decode)/ ascii
        $ev2 = /eval\s+["']?\$\(\s*base64\s+(-d|-D|--decode)\s*<<</ ascii
        $ev3 = /eval\s+["']?\$\(\s*(echo|printf)\s+['"]?[A-Za-z0-9+\/=]{20,}['"]?\s*\|\s*base64\s+(-d|-D|--decode)\s*\|\s*(ba|z)?sh/ ascii
    condition:
        for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127) and filesize < 32KB and 1 of ($ev*)
}

rule CERBER_Gen_Persist_Crontab_Download_Pipe_Shell {
    meta:
        description = "crontab entry (five schedule fields) that downloads a script and pipes it into a shell"
        author = "Cerber (gen)"
        family = "Generic.Persistence.Cron"
        severity = "critical"
        score = 80
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/how-malware-persists-on-macos/"
    strings:
        $cron = /[\*0-9\/,\-]+[ \t]+[\*0-9\/,\-]+[ \t]+[\*0-9\/,\-]+[ \t]+[\*0-9\/,\-]+[ \t]+[\*0-9\/,\-]+[ \t]+[^\n]{0,200}(curl|wget)[^\n]{0,200}\|\s*(ba|z)?sh/ ascii
        $cron2 = /[\*0-9\/,\-]+[ \t]+[\*0-9\/,\-]+[ \t]+[\*0-9\/,\-]+[ \t]+[\*0-9\/,\-]+[ \t]+[\*0-9\/,\-]+[ \t]+[^\n]{0,200}base64\s+(-d|-D|--decode)[^\n]{0,80}\|\s*(ba|z)?sh/ ascii
    condition:
        for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127) and filesize < 32KB and 1 of ($cron*)
}

rule CERBER_Gen_Persist_LoginItem_Osascript_Hidden_Path {
    meta:
        description = "AppleScript that registers a hidden or temp-folder item as a login item through System Events"
        author = "Cerber (gen)"
        family = "Generic.Persistence.LoginItem"
        severity = "high"
        score = 78
        date = "2026-10-09"
        reference = "https://socprime.com/active-threats/macos-stealers-observed-what-defenders-should-watch-for/"
    strings:
        $se = "tell application \"System Events\"" ascii nocase
        $login = /make\s+login\s+item[^\n]{0,300}(\/Users\/Shared\/\.|\/tmp\/|\/private\/var\/tmp\/|\/\.[A-Za-z0-9_-]{3,}\/)/ ascii nocase
    condition:
        for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127) and filesize < 32KB and $se and $login
}

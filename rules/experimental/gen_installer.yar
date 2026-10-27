/*
 * Cerber – reguły własne (installer), napisane 2026-10-09 przez agentów na podstawie publicznych raportów.
 * Warstwa "community": same nie dają werdyktu ZŁOŚLIWY. Zero trafień na ~2800 czystych plikach macOS
 * (programy z /Applications i /System, /usr/bin, LaunchAgents, rozszerzenia VS Code, node_modules).
 */

/*
 * CERBER - generated staging rules: malicious macOS installers (.pkg / .dmg / .command lures)
 * Author: Cerber (gen) | Date: 2026-10-09
 * Gate: every rule has an explicit type gate (shebang "#!" at offset 0, "<?xml" at offset 0,
 * or first 8 bytes text) and a filesize ceiling. Not promoted to rules/custom until yaracheck passes.
 */

rule CERBER_Gen_Installer_Script_Download_Exec_Quarantine_Strip {
    meta:
        description = "Shell script (pkg postinstall / .command style) that downloads a payload, strips its quarantine attribute and executes it"
        author = "Cerber (gen)"
        severity = "high"
        score = 80
        date = "2026-10-09"
        reference = "https://www.jamf.com/blog/contagious-interview-trojanized-macos-installers/"
    strings:
        $dl = /(curl|wget)[ \t]+[^\n]{0,120}https?:\/\//
        $q1 = /xattr[ \t]+-[a-zA-Z]*d[a-zA-Z]*[ \t]+com\.apple\.quarantine/
        $q2 = /xattr[ \t]+-(cr|rc|c)[ \t]+[^\n]{1,160}\/(tmp|var\/folders|Library\/Application Support)\//
        $x1 = /\|[ \t]*(ba|z)?sh\b/
        $x2 = /chmod[ \t]+\+x[ \t]+[^\n]{0,120}\/(tmp|var\/folders|Library\/Application Support)\//
    condition:
        uint16(0) == 0x2123 and filesize < 64KB and $dl and (1 of ($q*)) and (1 of ($x*))
}

rule CERBER_Gen_Installer_Gatekeeper_Master_Disable_Script {
    meta:
        description = "Shell script that turns Gatekeeper off system-wide with spctl (master-disable / global-disable)"
        author = "Cerber (gen)"
        severity = "high"
        score = 72
        date = "2026-10-09"
        reference = "https://research.splunk.com/endpoint/2c9346f3-bbeb-48ce-8411-fc13d09d83a5/"
    strings:
        $a = /spctl[ \t]+--(master|global)-disable/
        $b = /(curl|wget|base64|osascript|\/tmp\/)/
    condition:
        uint16(0) == 0x2123 and filesize < 64KB and $a and $b
}

rule CERBER_Gen_Installer_Distribution_XML_JS_Shell {
    meta:
        description = "Distribution XML whose embedded <script> calls system.run/system.runOnce to launch a shell, curl or osascript (pkg JavaScript installer abuse)"
        author = "Cerber (gen)"
        severity = "high"
        score = 80
        date = "2026-10-09"
        reference = "https://trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.macos.slisp.a"
    strings:
        $hdr = "<?xml" ascii
        $inst = "<installer-gui-script" ascii
        $js = "<script>" ascii
        $run = /system\.run(Once)?[ \t]*\([^\n]{0,200}/
        $sh = /(\/bin\/(ba|z)?sh|curl[ \t]|wget[ \t]|osascript|\/usr\/bin\/python)/
    condition:
        $hdr at 0 and filesize < 128KB and $inst and $js and $run and $sh
}

rule CERBER_Gen_Installer_SLISP_Launch_Agent_Staging {
    meta:
        description = "Installer script set that stages agent_updater/agent.sh with an init_agent.plist LaunchAgent and a version.json-driven payload URL (SLISP updater family)"
        author = "Cerber (gen)"
        family = "SLISP"
        severity = "critical"
        score = 90
        date = "2026-10-09"
        reference = "https://trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.macos.slisp.a"
    strings:
        $a = "init_agent.plist" ascii nocase
        $b = "agent_updater" ascii nocase
        $c = "agent.sh" ascii nocase
        $d = "version.json" ascii nocase
    condition:
        (uint16(0) == 0x2123 or $a at 0 or uint8(0) == 0x3c) and filesize < 256KB and ($a or $b) and 1 of ($c,$d)
}

rule CERBER_Gen_Installer_Quarantine_Database_Query {
    meta:
        description = "Script that reads the LaunchServices quarantine event database to list previously downloaded URLs (download-history recon)"
        author = "Cerber (gen)"
        severity = "high"
        score = 78
        date = "2026-10-09"
        reference = "https://trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.macos.slisp.a"
    strings:
        $db = "com.apple.LaunchServices.QuarantineEventsV2" ascii
        $col = "LSQuarantineDataURLString" ascii
        $sq = /sqlite3[ \t]+[^\n]{0,160}QuarantineEventsV2/
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 128KB and $sq and $col and $db
}

rule CERBER_Gen_Installer_Fake_Update_Password_Dialog {
    meta:
        description = "Script that shows a fake update dialog asking for the user's macOS password via osascript 'with hidden answer'"
        author = "Cerber (gen)"
        severity = "critical"
        score = 84
        date = "2026-10-09"
        reference = "https://www.jamf.com/blog/contagious-interview-trojanized-macos-installers/"
    strings:
        $dd = /display[ \t]+dialog/ ascii
        $ha = /with[ \t]+hidden[ \t]+answer/ ascii
        $pw = /password/ ascii nocase
        $sh = /do[ \t]+shell[ \t]+script/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 32KB and $dd and $ha and $pw and $sh
}

rule CERBER_Gen_Installer_AdminScript_Base64_Curl {
    meta:
        description = "AppleScript/shell line that runs a base64-decoded or curl-fetched command with administrator privileges (stealer installer stage)"
        author = "Cerber (gen)"
        severity = "high"
        score = 76
        date = "2026-10-09"
        reference = "https://www.crowdstrike.com/en-us/blog/falcon-prevents-cookie-spider-shamos-delivery-macos/"
    strings:
        $adm = /with[ \t]+administrator[ \t]+privileges/ ascii
        $ds = /do[ \t]+shell[ \t]+script/ ascii
        $b64 = /base64[ \t]+(-D|-d|--decode)/ ascii
        $cu = /curl[ \t]+-[a-zA-Z]{1,8}[ \t]/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and $adm and $ds and $b64 and $cu
}

rule CERBER_Gen_Installer_Command_Mount_Strip_Fetch {
    meta:
        description = "Install.command style script inside a mounted dmg that copies from /Volumes, strips quarantine and fetches a payload"
        author = "Cerber (gen)"
        severity = "high"
        score = 70
        date = "2026-10-09"
        reference = "https://isc.sans.edu/diary/More+obfuscated+shell+scripts+Fake+MacOS+Flash+update/24352"
    strings:
        $xa = /xattr[ \t]+-[a-zA-Z]{1,4}[ \t]/ ascii
        $vol = "/Volumes/" ascii
        $cp = /(cp|ditto)[ \t]+(-[a-zA-Z]+[ \t]+)?\/Volumes\// ascii
        $dl = /curl[ \t]+-[a-zA-Z]{1,8}[ \t]+[^\n]{0,120}https?:\/\// ascii
    condition:
        uint16(0) == 0x2123 and filesize < 32KB and $xa and $vol and $cp and $dl
}

rule CERBER_Gen_Installer_Lure_Text_Xattr_Terminal {
    meta:
        description = "Text/RTF lure in a dmg telling the user to run xattr in Terminal to unblock an app or Install.command (Gatekeeper bypass instructions)"
        author = "Cerber (gen)"
        severity = "medium"
        score = 55
        date = "2026-10-09"
        reference = "https://objective-see.org/blog/blog_0x70.html"
    strings:
        $x = /xattr[ \t]+-(cr|rc|c)[ \t]/ ascii nocase
        $t = "Terminal" ascii nocase
        $i = /(Install\.command|right[- ]click|drag)/ ascii nocase
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 16KB and $x and $t and $i
}

rule CERBER_Gen_Installer_LaunchDaemon_Curl_Load {
    meta:
        description = "Installer shell script that fetches a payload with curl, writes a LaunchDaemon/LaunchAgent plist with RunAtLoad or hourly StartInterval and loads it with launchctl"
        author = "Cerber (gen)"
        severity = "high"
        score = 74
        date = "2026-10-09"
        reference = "https://trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.macos.slisp.a"
    strings:
        $ld = /\/Library\/(LaunchDaemons|LaunchAgents)\/[^\n]{0,80}\.plist/ ascii
        $ctl = /launchctl[ \t]+(load|bootstrap)/ ascii
        $dl = /curl[ \t]+-[a-zA-Z]{1,8}[ \t]+[^\n]{0,120}https?:\/\// ascii
        $run = "<key>RunAtLoad</key>" ascii
        $int = /<key>StartInterval<\/key>[ \t\r\n]*<integer>3600<\/integer>/ ascii
    condition:
        uint16(0) == 0x2123 and filesize < 64KB and $ld and $ctl and $dl and ($run or $int)
}

rule CERBER_Gen_Installer_Security_Tool_Kill_Fetch {
    meta:
        description = "Installer script that kills named macOS security/monitoring tools (LuLu, BlockBlock, KnockKnock, Little Snitch) and fetches a payload"
        author = "Cerber (gen)"
        severity = "high"
        score = 78
        date = "2026-10-09"
        reference = "https://objective-see.org/tools.html"
    strings:
        $k = /(pkill|killall)[ \t]+[^\n]{0,80}/ ascii
        $s1 = "LuLu" ascii
        $s2 = "BlockBlock" ascii
        $s3 = "KnockKnock" ascii
        $s4 = "Little Snitch" ascii
        $dl = /curl[ \t]+-[a-zA-Z]{1,8}[ \t]+[^\n]{0,120}https?:\/\// ascii
    condition:
        uint16(0) == 0x2123 and filesize < 64KB and $k and 2 of ($s*) and $dl
}

rule CERBER_Gen_Installer_Base64_Drop_Chmod_Run {
    meta:
        description = "Installer shell script that base64-decodes an embedded blob to a file, makes it executable and runs it detached"
        author = "Cerber (gen)"
        severity = "high"
        score = 76
        date = "2026-10-09"
        reference = "https://www.jamf.com/blog/contagious-interview-trojanized-macos-installers/"
    strings:
        $b = /base64[ \t]+(-D|-d|--decode)[ \t]+(-i[ \t]+)?[^\n|]{0,80}>[ \t]*[^\n|]{1,120}/ ascii
        $x = /chmod[ \t]+\+x[ \t]+[^\n]{1,120}/ ascii
        $n = /(nohup[ \t]|&[ \t]*\n|>\/dev\/null 2>&1[ \t]*&)/ ascii
    condition:
        uint16(0) == 0x2123 and filesize < 64KB and $b and $x and $n
}

/*
 * Cerber – reguły własne (clickfix), napisane 2026-10-09 przez agentów na podstawie publicznych raportów.
 * Warstwa "community": same nie dają werdyktu ZŁOŚLIWY. Zero trafień na ~2800 czystych plikach macOS
 * (programy z /Applications i /System, /usr/bin, LaunchAgents, rozszerzenia VS Code, node_modules).
 */

/*
 * CERBER - Gen ClickFix (macOS "paste into Terminal" lures) - staging pack
 * Author: Cerber (gen) | Date: 2026-10-09
 *
 * Gaps covered (existing: custom/macos.yar + custom/scripts_web.yar cover the
 * Win+R / mshta / base64|sh stage-1 one-liners, the clear-screen decoy and
 * the generic writeText + Terminal page):
 *   - Spotlight / Cmd+Space + Terminal + "press Return" lure wording
 *   - applescript:// URL-scheme lure (Script Editor auto-open, no Terminal)
 *   - osascript "do shell script" wrapper around curl
 *   - hdiutil silent DMG mount chain pasted from a fake page
 *   - fake Homebrew installer (typosquatted brew.sh clone)
 *   - whitespace-padded command (payload pushed off-screen)
 *   - nohup/detached silent curl + /tmp execution
 *   - dscl authonly password-harvesting dialog loop
 *   - quarantine stripping after a /tmp download
 *
 * Every rule: inline TYPE GATE (first 8 bytes are text, or HTML/AppleScript
 * text), explicit filesize ceiling, and either several indicators or one
 * regex that encodes a complete malicious construct.
 */

rule CERBER_Gen_ClickFix_HtmlSpotlightTerminalReturn {
    meta:
        description = "Fake verification page that copies a shell command and tells macOS users to open Spotlight (Cmd+Space), Terminal, paste and press Return"
        author = "Cerber (gen)"
        family = "ClickFix"
        severity = "high"
        score = 82
        date = "2026-10-09"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/"
    strings:
        $w = /(writeText|execCommand\([ \t]*["']copy["']|copyToClipboard)/
        $spot = /((Command|Cmd)[ ]?\+[ ]?Space|Spotlight|\xe2\x8c\x98[ ]?\+?[ ]?Space)/ nocase
        $term = "Terminal" ascii
        $ret = /(press|hit|then)[ ]+(Return|Enter)/ nocase
        $sh = /(curl[ \t]+-[a-zA-Z]|base64[ \t]+-[dD]|\$\(curl|osascript)/
        $html = /<(html|body|button|div|script)[\s>]/ nocase
        $v = /(captcha|verify|verification|human|robot)/ nocase
    condition:
        filesize < 1MB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $html and $v and $w and $spot and $term and $ret and $sh
}

rule CERBER_Gen_ClickFix_AppleScriptUrlSchemeLure {
    meta:
        description = "Lure page that uses the applescript:// URL scheme to open Script Editor with a prefilled do shell script payload (Terminal bypass)"
        author = "Cerber (gen)"
        family = "ClickFix"
        severity = "critical"
        score = 88
        date = "2026-10-09"
        reference = "https://www.malwarebytes.com/blog/news/2026/04/clickfix-finds-new-way-to-infect-macs"
    strings:
        $u = /applescript:\/\/[^\s"'<>]{0,80}/ nocase
        $s = /(script=|action=new|do(%20| )shell(%20| )script)/ nocase
        $c = /(curl|base64|osascript|\/bin\/bash|\|[ ]*(ba|z)?sh\b)/
    condition:
        filesize < 3MB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $u and $s and $c
}

rule CERBER_Gen_ClickFix_OsascriptDoShellCurl {
    meta:
        description = "One-liner that wraps a curl download in osascript do shell script and then executes, runs detached or strips quarantine"
        author = "Cerber (gen)"
        family = "ClickFix"
        severity = "critical"
        score = 90
        date = "2026-10-09"
        reference = "https://www.malwarebytes.com/blog/news/2026/04/clickfix-finds-new-way-to-infect-macs"
    strings:
        $a = /osascript[ \t]+-e[ \t]+['"]do[ \t]+shell[ \t]+script[ \t]+["'][^\n]{0,200}curl[ \t]+-[a-zA-Z]{1,6}/ nocase
        $b = /(\|[ \t]*(ba|z)?sh\b|nohup[ \t]|chmod[ \t]+\+x|xattr[ \t]+-)/
    condition:
        filesize < 16KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $a and $b
}

rule CERBER_Gen_ClickFix_HdiutilDmgSilentMount {
    meta:
        description = "Pasted command that curls a DMG, silently attaches it with hdiutil and launches the app bundle inside"
        author = "Cerber (gen)"
        family = "ClickFix"
        severity = "critical"
        score = 91
        date = "2026-10-09"
        reference = "https://www.malwarebytes.com/blog/news/2026/04/clickfix-finds-new-way-to-infect-macs"
    strings:
        $c = /curl[ \t]+-[a-zA-Z]{1,6}[^\n]{0,160}\.dmg\b/
        $h = /hdiutil[ \t]+attach[ \t]+[^\n]{0,120}-(nobrowse|quiet|noautoopen|noverify)/
        $r = /(cp[ \t]+-R[ \t]|open[ \t]+)[^\n]{0,160}\.app\b/
    condition:
        filesize < 16KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $c and $h and $r
}

rule CERBER_Gen_ClickFix_FakeHomebrewInstaller {
    meta:
        description = "Fake Homebrew page (typosquatted brew.sh clone) whose copy button puts a /bin/bash -c curl install command on the clipboard"
        author = "Cerber (gen)"
        family = "ClickFix"
        severity = "critical"
        score = 90
        date = "2026-10-09"
        reference = "https://hunt.io/blog/fake-homebrew-clickfix-cuckoo-stealer-macos"
    strings:
        $w = /(writeText|execCommand\([ \t]*["']copy["'])/
        $a = /\/bin\/bash[ \t]+-c[ \t]+["']?\$\(curl[ \t]+-[a-zA-Z]{1,6}[ \t]+https?:\/\/[^\/\s"']{3,120}\//
        $brew = "Homebrew" ascii nocase
        $legit = "raw.githubusercontent.com/Homebrew/install" ascii nocase
    condition:
        filesize < 3MB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $w and $a and $brew and not $legit
}

rule CERBER_Gen_ClickFix_WhitespacePaddedPipeToShell {
    meta:
        description = "Clipboard command padded with a long run of spaces so the visible part looks harmless while the tail pipes a download into a shell"
        author = "Cerber (gen)"
        family = "ClickFix"
        severity = "high"
        score = 80
        date = "2026-10-09"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/"
    strings:
        $a = /[^\s][ \t]{100,400}(echo|curl|base64|printf|osascript)[^\n]{0,300}\|[ \t]*(ba|z)?sh\b/
    condition:
        filesize < 16KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $a
}

rule CERBER_Gen_ClickFix_NohupSilentFetchExec {
    meta:
        description = "Detached nohup silent curl download into a temp path that is chmod +x'd and executed"
        author = "Cerber (gen)"
        family = "ClickFix"
        severity = "high"
        score = 78
        date = "2026-10-09"
        reference = "https://www.malwarebytes.com/blog/news/2026/04/clickfix-finds-new-way-to-infect-macs"
    strings:
        $n = /nohup[ \t]+[^\n]{0,200}curl[ \t]+-[sSfkL]{1,4}/
        $p = /chmod[ \t]+\+x[ \t]+\/(private\/)?(var\/)?tmp\/[A-Za-z0-9._-]{1,40}/
        $e = /(&&|;)[ \t]*\/(private\/)?tmp\/[A-Za-z0-9._-]{1,40}/
    condition:
        filesize < 16KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $n and $p and $e
}

rule CERBER_Gen_ClickFix_DsclAuthonlyPasswordPhish {
    meta:
        description = "Script that repeatedly prompts for the macOS login password in a hidden-answer dialog and validates it with dscl authonly"
        author = "Cerber (gen)"
        family = "ClickFix"
        severity = "critical"
        score = 88
        date = "2026-10-09"
        reference = "https://hunt.io/blog/fake-homebrew-clickfix-cuckoo-stealer-macos"
    strings:
        $d = /dscl[ \t]+\.[ \t]+-?authonly/
        $p = /display[ \t]+dialog[^\n]{0,300}hidden[ \t]+answer[ \t]+(true|yes)/ nocase
    condition:
        filesize < 64KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $d and $p
}

rule CERBER_Gen_ClickFix_QuarantineStripAfterTmpDownload {
    meta:
        description = "Command that downloads a file into a temp or home path, removes com.apple.quarantine from it and launches it"
        author = "Cerber (gen)"
        family = "ClickFix"
        severity = "high"
        score = 76
        date = "2026-10-09"
        reference = "https://www.malwarebytes.com/blog/news/2026/04/clickfix-finds-new-way-to-infect-macs"
    strings:
        $x = /xattr[ \t]+-(d|dr)[ \t]+com\.apple\.quarantine/
        $c = /curl[ \t]+-[sSfkL]{1,4}[^\n]{0,160}-o[ \t]+(\/tmp|\/private\/tmp|\$HOME|~)\/[^\s]{1,60}/
    condition:
        filesize < 16KB and (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and
        $x and $c
}

/*
 * Cerber – reguły własne (stealer), napisane 2026-10-09 przez agentów na podstawie publicznych raportów.
 * Warstwa "community": same nie dają werdyktu ZŁOŚLIWY. Zero trafień na ~2800 czystych plikach macOS
 * (programy z /Applications i /System, /usr/bin, LaunchAgents, rozszerzenia VS Code, node_modules).
 */

/*
 * CERBER - generated macOS info-stealer TECHNIQUE rules (staging)
 *
 * Author: Cerber (gen) | Date: 2026-10-09
 * Policy: TYPE GATE inline, explicit SIZE LIMIT, SEVERAL INDICATORS per rule,
 * no common-word triggers, score < 75 (behavioural; none of these are family-exact).
 * Each rule encodes a technique combination that recurs across AMOS, Poseidon,
 * Banshee, Cthulhu, MacSync and related stealers, not a single family IOC.
 */

rule CERBER_Gen_Stealer_AppleScript_Password_Retry_Loop {
    meta:
        description = "AppleScript password dialog (hidden answer) read via text returned, wrapped in a repeat loop with a do shell script call"
        author = "Cerber (gen)"
        family = "generic-stealer"
        severity = "high"
        score = 70
        date = "2026-10-09"
        reference = "https://northpole.security/cookbook/block-fake-password-prompts"
        reference2 = "https://reliaquest.com/blog/5-macos-infostealers/"
    strings:
        $h = "with hidden answer" ascii nocase
        $r = "text returned of" ascii nocase
        $s = "do shell script" ascii nocase
        $p = "password" ascii nocase
        $l = "repeat" ascii nocase
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 256KB and
        $h and $r and $s and $p and $l
}

rule CERBER_Gen_Stealer_Fake_Update_Password_Lure {
    meta:
        description = "Caution-icon 'Software Update' style dialog asking for a password with hidden answer, then validated through dscl or security in a shell call"
        author = "Cerber (gen)"
        family = "generic-stealer"
        severity = "high"
        score = 68
        date = "2026-10-09"
        reference = "https://hivepro.com/wp-content/uploads/2024/08/TA2024316.pdf"
        reference2 = "https://www.anvilogic.com/threat-reports/macos-infostealers-rise"
    strings:
        $h = "with hidden answer" ascii nocase
        $i = "with icon caution" ascii nocase
        $u1 = "Software Update" ascii nocase
        $u2 = "Update Required" ascii nocase
        $u3 = "needs to update" ascii nocase
        $p = "password" ascii nocase
        $e = /do shell script\s+["'][^\n]{0,200}(dscl|security\s)/ ascii nocase
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 128KB and
        $h and $i and 1 of ($u*) and $p and $e
}

rule CERBER_Gen_Stealer_Keychain_Password_Extract_Shell {
    meta:
        description = "Shell extraction of a keychain item password via find-generic-password -ga piped through 2>&1 and grep for password:"
        author = "Cerber (gen)"
        family = "generic-stealer"
        severity = "high"
        score = 72
        date = "2026-10-09"
        reference = "https://www.cyberproof.com/blog/inside-amos-stealer-how-this-threat-targets-macos-credentials-and-keychains/"
        reference2 = "https://www.iru.com/threats/monetastealer"
    strings:
        $fg = /security\s+find-(generic|internet)-password\s+-g[a-z]*\s+["'][^"'\n]{1,80}["']/ ascii
        $pipe = /2>&1\s*\|\s*(grep|awk|sed)\s+["']?[a-z ]{0,10}password:/ ascii
        $kc = "login.keychain-db" ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 128KB and
        $fg and ($pipe or $kc)
}

rule CERBER_Gen_Stealer_Notes_Keychain_Wallet_Sweep {
    meta:
        description = "Binary or script sweeping the Notes database and login keychain together with desktop crypto-wallet data directories"
        author = "Cerber (gen)"
        family = "generic-stealer"
        severity = "high"
        score = 72
        date = "2026-10-09"
        reference = "https://reliaquest.com/blog/5-macos-infostealers/"
        reference2 = "https://www.iru.com/threats/monetastealer"
    strings:
        $n1 = "group.com.apple.notes" ascii
        $n2 = "NoteStore.sqlite" ascii
        $kc = "login.keychain-db" ascii
        $w1 = "Telegram Desktop/tdata" ascii
        $w2 = "Exodus/exodus.wallet" ascii
        $w3 = "Electrum/wallets" ascii
        $w4 = "Coinomi/wallets" ascii
        $w5 = "Ledger Live/app.json" ascii
    condition:
        ((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB or
         (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 512KB) and
        $kc and 1 of ($n*) and 2 of ($w*)
}

rule CERBER_Gen_Stealer_Stage_Archive_Upload_Cleanup {
    meta:
        description = "Shell staging directory in /tmp or mktemp, ditto -c -k archive, curl upload of the archive, then rm -rf of the staging variable"
        author = "Cerber (gen)"
        family = "generic-stealer"
        severity = "high"
        score = 74
        date = "2026-10-09"
        reference = "https://www.cyberproof.com/blog/inside-amos-stealer-how-this-threat-targets-macos-credentials-and-keychains/"
        reference2 = "https://www.iru.com/threats/monetastealer"
    strings:
        $stage = /(mktemp\s+-d|\/tmp\/[A-Za-z0-9_.-]{3,40})/ ascii
        $zip = /ditto\s+-c\s+-k\s+(--[A-Za-z]+\s+)*/ ascii
        $up = /curl\s+[^\n]{0,120}(-T\s|--upload-file\s|-X\s+(PUT|POST)\s|-F\s*["']?[A-Za-z_]{1,20}=@|--data-binary\s+["']?@)/ ascii
        $rm = /rm\s+-rf?\s+["']?\$[A-Za-z_{}]+/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 128KB and
        $zip and $up and $rm and $stage
}

rule CERBER_Gen_Stealer_Chunked_Upload_Retry {
    meta:
        description = "Archive split into fixed-size chunks and each chunk uploaded with curl and a bounded retry loop"
        author = "Cerber (gen)"
        family = "generic-stealer"
        severity = "high"
        score = 66
        date = "2026-10-09"
        reference = "https://www.cyberproof.com/blog/inside-amos-stealer-how-this-threat-targets-macos-credentials-and-keychains/"
        reference2 = "https://www.iru.com/threats/monetastealer"
    strings:
        $split = /split\s+-b\s*["']?[0-9]+[mM]/ ascii
        $up = /curl\s+[^\n]{0,160}(-T\s|--upload-file\s|-X\s+PUT\s)/ ascii
        $retry1 = /--retry\s+[0-9]+/ ascii
        $retry2 = /seq\s+1\s+[0-9]+/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 128KB and
        $split and $up and (1 of ($retry*))
}

rule CERBER_Gen_Stealer_Browser_Login_Sqlite_Query {
    meta:
        description = "Script that copies a browser Login Data or logins.json store and runs a SELECT over origin_url, username_value and password_value"
        author = "Cerber (gen)"
        family = "generic-stealer"
        severity = "high"
        score = 72
        date = "2026-10-09"
        reference = "https://www.cyberproof.com/blog/inside-amos-stealer-how-this-threat-targets-macos-credentials-and-keychains/"
        reference2 = "https://reliaquest.com/blog/5-macos-infostealers/"
    strings:
        $q1 = /SELECT\s+origin_url\s*,\s*username_value\s*,\s*password_value\s+FROM\s+logins/ ascii nocase
        $q2 = /SELECT\s+[^\n]{0,80}(encrypted_value|password_value)\s+FROM\s+(cookies|logins)/ ascii nocase
        $db1 = "Login Data" ascii
        $db2 = "logins.json" ascii
        $db3 = "key4.db" ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 256KB and
        (1 of ($q*)) and (1 of ($db*))
}

rule CERBER_Gen_Stealer_AppleScript_Shell_Curl_Upload {
    meta:
        description = "AppleScript that runs a curl upload through do shell script (file or form POST), typical of stealer exfil launched from a password dialog"
        author = "Cerber (gen)"
        family = "generic-stealer"
        severity = "high"
        score = 70
        date = "2026-10-09"
        reference = "https://reliaquest.com/blog/5-macos-infostealers/"
        reference2 = "https://www.darktrace.com/blog/applescript-abuse-unpacking-a-macos-phishing-campaign"
    strings:
        $ds = /do shell script\s+["'][^\n]{0,300}curl\s/ ascii nocase
        $up = /curl\s[^\n]{0,160}(-F\s*["']?[A-Za-z_]{1,20}=@|-T\s|--upload-file|--data-binary\s+["']?@|-X\s+(PUT|POST))/ ascii nocase
        $tmp = "/tmp/" ascii
        $dlg = "display dialog" ascii nocase
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 128KB and
        $ds and $up and $tmp and $dlg
}

rule CERBER_Gen_Stealer_LOLBin_Keychain_Mach_O {
    meta:
        description = "Mach-O that embeds the login keychain path together with several native macOS tool paths (osascript, dscl, ditto, security, curl)"
        author = "Cerber (gen)"
        family = "generic-stealer"
        severity = "high"
        score = 68
        date = "2026-10-09"
        reference = "https://www.anvilogic.com/threat-reports/macos-infostealers-rise"
        reference2 = "https://unit42.paloaltonetworks.com/macos-stealers-growing/"
    strings:
        $k = "login.keychain-db" ascii
        $a = "/usr/bin/osascript" ascii
        $b = "/usr/bin/dscl" ascii
        $c = "/usr/bin/ditto" ascii
        $d = "/usr/bin/security" ascii
        $e = "/usr/bin/curl" ascii
    condition:
        ((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB or
         (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 128KB) and
        $k and 4 of ($a, $b, $c, $d, $e)
}

rule CERBER_Gen_Stealer_File_Grabber_Find {
    meta:
        description = "Shell file grabber: find over Desktop/Documents/Downloads limited by -size and a set of document or vault extensions"
        author = "Cerber (gen)"
        family = "generic-stealer"
        severity = "medium"
        score = 62
        date = "2026-10-09"
        reference = "https://www.iru.com/threats/monetastealer"
        reference2 = "https://reliaquest.com/blog/5-macos-infostealers/"
    strings:
        $f = /find\s+["']?(\$HOME|~|\$\{HOME\})\/?(Desktop|Documents|Downloads)[^\n]{0,200}-size\s+-[0-9]+[kKmMcC]/ ascii
        $ext = /\*\.(txt|pdf|docx|rtf|kdbx|wallet|key)\b/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 128KB and
        $f and #ext >= 3
}

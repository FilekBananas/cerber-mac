/*
 * Cerber – reguły własne (money), napisane 2026-10-09 przez agentów na podstawie publicznych raportów.
 * Warstwa "community": same nie dają werdyktu ZŁOŚLIWY. Zero trafień na ~2800 czystych plikach macOS
 * (programy z /Applications i /System, /usr/bin, LaunchAgents, rozszerzenia VS Code, node_modules).
 */

/*
 * CERBER - generated money-driven macOS rules (staging)
 * Author: Cerber (gen) | Date: 2026-10-09
 * Scope: ransomware builds, cryptominers, clipboard address swappers,
 * fake wallet apps that harvest seed phrases.
 * Policy: TYPE GATE + SIZE LIMIT + SEVERAL INDICATORS (see rules/custom/macos.yar header).
 * Score >= 75 family/IOC-exact, < 75 behavioural (legit XMRig, wallet apps are "suspicious").
 */

rule CERBER_Gen_Money_LockBit_macOS_Build {
    meta:
        description = "LockBit macOS (Linux/ESXi port) encryptor: --wholefile/--beginfile switches with ESXi and Apple config tokens"
        author = "Cerber (gen)"
        family = "LockBit"
        severity = "critical"
        score = 90
        reference = "https://www.bitdefender.com/blog/businessinsights/technical-advisory-why-lockbit-ransomware-on-macos-is-not-a-significant-threat-yet"
        date = "2026-10-09"
    strings:
        $a = "--wholefile" ascii
        $b = "--beginfile" ascii
        $c = "esxcfg-scsidevs" ascii
        $d = "vim-cmd" ascii
        $e = "apple_config" ascii
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and
        filesize < 4MB and $a and $b and 2 of ($c, $d, $e)
}

rule CERBER_Gen_Money_Ransom_OpenSSL_Find_Encrypt_Script {
    meta:
        description = "Shell script that walks a tree with find -exec openssl aes-256-cbc to encrypt user files in place"
        author = "Cerber (gen)"
        family = "GenericRansomware"
        severity = "high"
        score = 72
        date = "2026-10-09"
    strings:
        $enc = /find\s+[^\n]{0,200}-exec\s+openssl\s+enc\s+-aes-256-cbc/ ascii
        $del = /-exec\s+(rm|mv)\s+-f?\s*/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 32KB and
        $enc and $del
}

rule CERBER_Gen_Money_Ledger_Fake_App_Seed_Dialog {
    meta:
        description = "Fake Ledger Live app text prompting the user to enter seed phrases for account recovery"
        author = "Cerber (gen)"
        family = "FakeLedgerLive"
        severity = "critical"
        score = 92
        reference = "https://moonlock.com/malware-fake-ledger-apps"
        date = "2026-10-09"
    strings:
        $a = "Ledger Live encountered a critical error" ascii
        $b = "Seed phrases required for account recovery" ascii
    condition:
        ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) or
         (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20))) and
        filesize < 24MB and any of them
}

rule CERBER_Gen_Money_Wallet_Seed_Phish_Exfil_Script {
    meta:
        description = "AppleScript/shell prompt asking for a recovery or seed phrase in a dialog and posting the answer with curl"
        author = "Cerber (gen)"
        family = "WalletSeedPhish"
        severity = "high"
        score = 72
        reference = "https://moonlock.com/malware-fake-ledger-apps"
        date = "2026-10-09"
    strings:
        $dlg = /display\s+dialog/ nocase ascii
        $seed = /(recovery|seed|secret)\s+phrase/ nocase ascii
        $post = /curl\s+[^\n]{0,120}(-d\s|--data|-X\s*POST)/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and
        all of them
}

rule CERBER_Gen_Money_XMRig_Config_Json {
    meta:
        description = "XMRig-style JSON config with donate-level, a pools array and a host:port URL (a knowingly run miner is suspicious, not certain)"
        author = "Cerber (gen)"
        family = "CoinMiner"
        severity = "medium"
        score = 60
        reference = "https://xmrig.com/docs/miner/config"
        date = "2026-10-09"
    strings:
        $d = /"donate-level"\s*:\s*\d{1,3}/ ascii
        $p = /"pools"\s*:\s*\[/ ascii
        $u = /"url"\s*:\s*"[^"\s]{1,120}:\d{2,5}"/ ascii
        $w = /"user"\s*:\s*"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and
        $d and $p and $u and $w
}

rule CERBER_Gen_Money_CoinMiner_Pool_Domains_MachO {
    meta:
        description = "Mach-O carrying a stratum URL scheme and two or more well-known Monero pool domains (miner embedded in an app)"
        author = "Cerber (gen)"
        family = "CoinMiner"
        severity = "high"
        score = 70
        reference = "https://xmrig.com/docs/miner/config"
        date = "2026-10-09"
    strings:
        $s1 = "stratum+tcp://" ascii nocase
        $s2 = "stratum+ssl://" ascii nocase
        $p01 = "minexmr.com" ascii nocase
        $p02 = "supportxmr.com" ascii nocase
        $p03 = "nanopool.org" ascii nocase
        $p04 = "moneroocean.stream" ascii nocase
        $p05 = "2miners.com" ascii nocase
        $p06 = "hashvault.pro" ascii nocase
        $p07 = "c3pool.com" ascii nocase
        $p08 = "herominers.com" ascii nocase
        $p09 = "xmrpool.eu" ascii nocase
        $p10 = "monerohash.com" ascii nocase
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and
        filesize < 32MB and 1 of ($s*) and 2 of ($p*)
}

rule CERBER_Gen_Money_Hidden_Miner_LaunchAgent_Plist {
    meta:
        description = "LaunchAgent plist that starts and keeps alive a stratum miner at load (hidden persistence for a cracked-app miner)"
        author = "Cerber (gen)"
        family = "CoinMiner"
        severity = "high"
        score = 76
        reference = "https://xmrig.com/docs/miner/config"
        date = "2026-10-09"
    strings:
        $x = "<?xml" ascii
        $s = /stratum\+(tcp|ssl):\/\/[^<\s]{3,120}/ ascii
        $r = "<key>RunAtLoad</key>" ascii
        $k = "<key>KeepAlive</key>" ascii
    condition:
        uint8(0) == 0x3c and filesize < 16KB and $x at 0 and $s and $r and $k
}

rule CERBER_Gen_Money_Clipper_Pbpaste_Script {
    meta:
        description = "Shell/AppleScript loop that reads the clipboard with pbpaste, matches wallet address formats and rewrites it with pbcopy"
        author = "Cerber (gen)"
        family = "ClipboardHijacker"
        severity = "high"
        score = 70
        reference = "https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/"
        date = "2026-10-09"
    strings:
        $pb1 = "pbpaste" ascii
        $pb2 = "pbcopy" ascii
        $eth = /0x[0-9a-fA-F]{40}/ ascii
        $btc = /bc1[a-z0-9]{39,59}/ ascii
        $xmr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
        $loop = /(while\s+(true|:)|sleep\s+\d)/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and
        $pb1 and $pb2 and $loop and 1 of ($eth, $btc, $xmr)
}

rule CERBER_Gen_Money_Clipper_Pasteboard_MachO {
    meta:
        description = "Mach-O polling the general pasteboard by changeCount and embedding wallet address patterns (clipboard address swapper)"
        author = "Cerber (gen)"
        family = "ClipboardHijacker"
        severity = "high"
        score = 66
        reference = "https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/"
        date = "2026-10-09"
    strings:
        $pb1 = "generalPasteboard" ascii
        $pb2 = "changeCount" ascii
        $pb3 = "setString:forType:" ascii
        $eth = /0x[0-9a-fA-F]{40}/ ascii
        $btc = /bc1[a-z0-9]{39,59}/ ascii
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and
        filesize < 4MB and $pb1 and $pb2 and $pb3 and 1 of ($eth, $btc)
}

/*
 * CERBER - macOS YARA rules (precision-first rewrite)
 *
 * Policy for every rule in this file:
 *   1. TYPE GATE   - a cheap structural check on the first bytes, written inline in every rule
 *                    (no private rules, so per-rule positive coverage stays measurable):
 *                      Mach-O   uint32(0) == 0xfeedfacf / 0xfeedface / fat magic with nfat_arch < 20
 *                      script / plist / AppleScript / JS / py / decoded layer
 *                               first 8 bytes are text (uint8 in 9..126); "#!" and "<?xml" where
 *                               the construct is only meaningful in a shebang script or a plist.
 *                    Never "string somewhere inside any blob".
 *   2. SIZE LIMIT  - every rule has an explicit filesize ceiling that fits the artefact type
 *                    (a pasted command is a few KB, a stealer Mach-O a few MB). Disk images,
 *                    frameworks and bundled JS never qualify.
 *   3. SEVERAL INDICATORS - either a family-specific string set (public reports: Microsoft,
 *                    Huntress, Unit 42, Elastic, SentinelOne, Objective-See, ANY.RUN), or one
 *                    regex that itself encodes a complete malicious construct (for example
 *                    "curl $(echo <b64>|base64 -D)|zsh"), or IOC + execution context.
 *   4. No rule keys on common words ("socket", "connect", "alias", "at ", ".gitconfig",
 *      "sudoers", "keychain", "Chrome", "127.0.0.1", ...) - those matched man pages, VS Code,
 *      Xcode SDKs, container rootfs images and Chromium in the clean-file calibration.
 *
 * Apple XProtect (db/yara/xprotect) already covers the adware families (Adload, Bundlore,
 * Pirrit, Genieo, Shlayer ...), so this pack does not duplicate them.
 *
 * Score meta: >= 75 -> CERTAIN (family/IOC-exact), < 75 -> HIGH/suspicious (behavioural).
 * Author: Cerber | Rewritten: 2026-09-29
 */

// ============================================================================
// CLICKFIX (fake CAPTCHA / fake macOS utility -> paste into Terminal)
// Sources: Microsoft Security Blog 2026-05-06, Huntress, Unit 42, Objective-See
// ============================================================================

rule CERBER_MacOS_ClickFix_C2_Domains {
    meta:
        description = "ClickFix macOS loader/stager script that contacts a known campaign C2 domain"
        author = "Cerber"
        family = "ClickFix"
        severity = "critical"
        score = 94
        date = "2026-09-29"
    strings:
        $d01 = "rapidfilevault4.sbs" ascii nocase
        $d02 = "coco-fun2.com" ascii nocase
        $d03 = "nitlebuf.com" ascii nocase
        $d04 = "yablochnisok.com" ascii nocase
        $d05 = "mentaorb.com" ascii nocase
        $d06 = "seagalnssteavens.com" ascii nocase
        $d07 = "res2erch-sl0ut.com" ascii nocase
        $d08 = "filefastdata.com" ascii nocase
        $d09 = "metramon.com" ascii nocase
        $d10 = "octopixeldate.com" ascii nocase
        $d11 = "pewweepor092.com" ascii nocase
        $d12 = "0x666.info" ascii nocase
        $d13 = "honestly.ink" ascii nocase
        $d14 = "pla7ina.cfd" ascii nocase
        $d15 = "play67.cc" ascii nocase
        $d16 = "cauterizespray.icu" ascii nocase
        $d17 = "enslaveculprit.digital" ascii nocase
        $d18 = "resilientlimb.icu" ascii nocase
        $d19 = "svs-verificationdate.beer" ascii nocase
        $d20 = "laislivon.com" ascii nocase
        $d21 = "rvdownloads.com" ascii nocase
        $d22 = "t.me/ax03bot" ascii nocase
        $x1 = /curl\s+-[A-Za-z]/ ascii
        $x2 = /base64\s+(-D|-d|--decode)/ ascii
        $x3 = "osascript" ascii
        $x4 = /\|\s*(zsh|bash|sh)\b/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 256KB and
        1 of ($d*) and 1 of ($x*)
}

rule CERBER_MacOS_ClickFix_Loader_Artifacts {
    meta:
        description = "ClickFix macOS backdoor loader: /api/bot/heartbeat + .mainhelper/.agent/GoogleUpdate masquerade"
        author = "Cerber"
        family = "ClickFix"
        severity = "critical"
        score = 93
        date = "2026-09-29"
    strings:
        $hb = "/api/bot/heartbeat" ascii
        $m1 = ".mainhelper" ascii
        $m2 = /[\/~]\.agent\b/ ascii
        $m3 = "Application Support/Google/GoogleUpdate.app" ascii
        $m4 = "com.finder.helper.plist" ascii
        $m5 = "cis_blocked" ascii
    condition:
        ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) or (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20))) and filesize < 8MB and
        $hb and 2 of ($m*)
}

rule CERBER_MacOS_ClickFix_Hidden_URL_Stager {
    meta:
        description = "Terminal one-liner that hides its download URL in base64 and pipes the result to a shell (AMOS/MacSync ClickFix stage 1)"
        author = "Cerber"
        family = "ClickFix"
        severity = "critical"
        score = 92
        date = "2026-09-29"
    strings:
        $s1 = /curl\s+-[A-Za-z]{1,12}\s+["']?\$\(\s*echo\s+["'][A-Za-z0-9+\/=]{16,300}["']\s*\|\s*base64\s+(-D|-d|--decode)\s*\)["']?\s*\|\s*(zsh|bash|sh)\b/ ascii
        $s2 = /\$\(\s*curl\s+-[A-Za-z]{1,12}\s+\$\(\s*echo\s+["'][A-Za-z0-9+\/=]{16,300}["']\s*\|\s*base64\s+(-D|-d|--decode)\s*\)/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and any of them
}

rule CERBER_MacOS_ClickFix_Encoded_Command_Pipe {
    meta:
        description = "Long base64 blob decoded straight into zsh/bash next to a fake verification/clear-screen decoy (ClickFix paste command)"
        author = "Cerber"
        family = "ClickFix"
        severity = "high"
        score = 70
        date = "2026-09-29"
    strings:
        $pipe = /echo\s+["'][A-Za-z0-9+\/=]{80,}["']\s*\|\s*base64\s+(-D|-d|--decode)\s*\|\s*(zsh|bash|sh)\b/ ascii
        $decoy1 = /(^|\n)\s*clear\s*($|\n)/ ascii
        $decoy2 = /echo\s+["'][^\n"']{0,80}(Verification|verified|CAPTCHA|Human|Cloudflare|updat(e|ed|ing)|Installing|completed)[^\n"']{0,80}["']/ ascii nocase
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 16KB and $pipe and 1 of ($decoy*)
}

rule CERBER_MacOS_Base64_Gzip_Eval {
    meta:
        description = "Fileless loader: gzip+base64 heredoc/blob decoded with base64 -D | gunzip and evaluated"
        author = "Cerber"
        family = "ClickFix"
        severity = "high"
        score = 72
        date = "2026-09-29"
    strings:
        $chain = /base64\s+(-D|-d|--decode)[^\n]{0,60}\|\s*(gunzip|gzip\s+-d[a-z]*|zcat)/ ascii
        $exec = /(eval\s|\|\s*(zsh|bash|sh)\b|source\s+<\(|osascript)/ ascii
        $blob = /H4sI[A-Za-z0-9+\/=]{120,}/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 256KB and $chain and $exec and $blob
}

// ============================================================================
// MACSYNC STEALER (Huntress, Securelist, CloudSEK)
// ============================================================================

rule CERBER_MacOS_MacSync_Signature {
    meta:
        description = "MacSync stealer: osalogging.zip loot archive and companion staging/beacon strings"
        author = "Cerber"
        family = "MacSync"
        severity = "critical"
        score = 95
        date = "2026-09-29"
    strings:
        $s1 = "osalogging.zip" ascii
        $s2 = "MacSync Stealer" ascii
        $s3 = "/tmp/.kgrab.sh" ascii
        $s4 = "/tmp/.kpwd" ascii
        $s5 = "/tmp/macsync_" ascii
        $s6 = "Full Disk Access required!" ascii
        $s7 = "/dynamic?txd=" ascii
        $s8 = "buildtxd=" ascii
        $s9 = "/.local/.mpwd" ascii
    condition:
        ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) or (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20))) and filesize < 8MB and
        3 of ($s*)
}

rule CERBER_MacOS_MacSync_C2 {
    meta:
        description = "MacSync stealer C2 domain together with its payload-fetch URL paths"
        author = "Cerber"
        family = "MacSync"
        severity = "critical"
        score = 95
        date = "2026-09-29"
    strings:
        $d1 = "jmpbowl.xyz" ascii nocase
        $d2 = "agenticsora.com" ascii nocase
        $d3 = "malwareaudit.com" ascii nocase
        $d4 = "sdhomeinspectors.com" ascii nocase
        $d5 = "southcarolinacounselor.com" ascii nocase
        $p1 = "/dynamic?txd=" ascii
        $p2 = "/gate?buildtxd=" ascii
        $p3 = "/loader/agent/" ascii
        $p4 = "/loader/capture-agent/" ascii
        $p5 = /\/curl\/[A-Za-z0-9]{8,}/ ascii
    condition:
        ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) or (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20))) and filesize < 8MB and
        1 of ($d*) and 1 of ($p*)
}

// ============================================================================
// ATOMIC / AMOS AND OTHER APPLESCRIPT STEALERS (SentinelOne, SpyCloud, Objective-See)
// ============================================================================

rule CERBER_MacOS_AMOS_Password_Phish {
    meta:
        description = "AppleScript stealer: fake helper/System Preferences password dialog (hidden answer) validated with dscl -authonly"
        author = "Cerber"
        family = "Atomic/AMOS"
        severity = "critical"
        score = 94
        date = "2026-09-29"
    strings:
        $hidden = "with hidden answer" ascii nocase
        $d1 = "Required Application Helper" ascii nocase
        $d2 = "MacOS wants to access System Preferences" ascii nocase
        $d3 = "Application wants to install helper" ascii nocase
        $d4 = "Please enter device password" ascii nocase
        $d5 = "You entered invalid password" ascii nocase
        $dscl = /dscl\s+(\.|\/Local\/Default)\s+-?authonly/ ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 512KB)) and
        $hidden and 1 of ($d*) and $dscl
}

rule CERBER_MacOS_Stealer_Keychain_Dscl_Zip {
    meta:
        description = "Stealer chain: dscl -authonly password check + security find-generic-password + login.keychain-db + archive staging"
        author = "Cerber"
        family = "Atomic/AMOS"
        severity = "critical"
        score = 88
        date = "2026-09-29"
    strings:
        $dscl = /dscl\s+(\.|\/Local\/Default)\s+-?authonly/ ascii
        $sec = "find-generic-password" ascii
        $kc = "login.keychain-db" ascii
        $zip1 = "ditto -c -k" ascii
        $zip2 = /zip\s+-r[a-z]*\s/ ascii
        $curl = /curl\s+[^\n]{0,80}(-F\s*["']?[A-Za-z_]{1,20}=@|--form\s+["']?[A-Za-z_]{1,20}=@|--data-binary\s+["']?@|-d\s*["']?@|-T\s+|--upload-file\s+)/ ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 512KB)) and
        $dscl and $sec and $kc and (1 of ($zip*) or $curl)
}

rule CERBER_MacOS_Atomic_Wallet_Extension_Sweep {
    meta:
        description = "Stealer sweeping many crypto-wallet browser-extension IDs (MetaMask, Phantom, Coin98, Trust, Ronin, ...)"
        author = "Cerber"
        family = "Atomic/AMOS"
        severity = "critical"
        score = 93
        date = "2026-09-29"
    strings:
        $id01 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii   // MetaMask
        $id02 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii   // Phantom
        $id03 = "aeachknmotapmjnkwhknmclnlgetadgd" ascii   // Coin98
        $id04 = "egjidjbpglichdcondbcbdnbeeppieej" ascii   // Trust Wallet
        $id05 = "fnjhmkhhmkbjkkabndcnnogagogbneec" ascii   // Ronin
        $id06 = "fhbohimaelbohpjbbldcngcnapndodjp" ascii   // Binance Chain Wallet
        $id07 = "hnfanknocfeofbddgcijnmhnfnkdnaad" ascii   // Coinbase Wallet
        $id08 = "ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii   // TronLink
        $id09 = "aholpfdialjgjfhomihkjbmgjidlcdno" ascii   // Exodus Web3
        $id10 = "dmkamcknogkgcdfhhbddcghachkejeap" ascii   // Keplr
        $id11 = "afbcbjpbpfadlkmhmclhkeeodmamcflc" ascii   // Math Wallet
        $id12 = "ffnbelfdoeiohenkjibnmadjiehjhajb" ascii   // Yoroi
        $id13 = "hpglfhgfnhbgpjdenjgmdgoeiappafln" ascii   // Guarda
        $p1 = "Local Extension Settings" ascii
        $p2 = "/Default/Extensions" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 512KB)) and
        5 of ($id*) and 1 of ($p*)
}

rule CERBER_MacOS_Stealer_Wallet_Path_Sweep {
    meta:
        description = "Stealer sweeping several desktop-wallet data directories together with the login keychain"
        author = "Cerber"
        family = "Realst/AMOS"
        severity = "critical"
        score = 92
        date = "2026-09-29"
    strings:
        $kc = "login.keychain-db" ascii
        $w1 = "Exodus/exodus.wallet" ascii
        $w2 = "Electrum/wallets" ascii
        $w3 = "Coinomi/wallets" ascii
        $w4 = "atomic/Local Storage/leveldb" ascii
        $w5 = "Guarda/Local Storage/leveldb" ascii
        $w6 = "Bitcoin/wallet.dat" ascii
        $w7 = "Ledger Live/app.json" ascii
        $w8 = "Binance/app-store.json" ascii
        $w9 = "WalletWasabi" ascii
        $w10 = "Monero/wallets" ascii
        $w11 = "Telegram Desktop/tdata" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 512KB)) and
        $kc and 3 of ($w*)
}

rule CERBER_MacOS_Stealer_Browser_Data_Exfil {
    meta:
        description = "Script/binary that collects several browser credential stores and uploads an archive with curl"
        author = "Cerber"
        family = "Atomic/AMOS"
        severity = "high"
        score = 74
        date = "2026-09-29"
    strings:
        $b1 = "/Default/Login Data" ascii
        $b2 = "/Default/Cookies" ascii
        $b3 = "/Default/Web Data" ascii
        $b4 = "key4.db" ascii
        $b5 = "logins.json" ascii
        $b6 = "cookies.sqlite" ascii
        $b7 = "Cookies.binarycookies" ascii
        $b8 = "Chrome Safe Storage" ascii
        $z1 = "ditto -c -k" ascii
        $z2 = /zip\s+-r[a-z]*\s/ ascii
        $up = /curl\s+[^\n]{0,80}(-F\s*["']?[A-Za-z_]{1,20}=@|--form\s+["']?[A-Za-z_]{1,20}=@|--data-binary\s+["']?@|-d\s*["']?@|-T\s+|--upload-file\s+)/ ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 512KB)) and
        4 of ($b*) and 1 of ($z*) and $up
}

// ============================================================================
// DPRK "CONTAGIOUS INTERVIEW" (BeaverTail / InvisibleFerret / OtterCookie)
// ============================================================================

rule CERBER_MacOS_BeaverTail_C2_Lianxinxiao {
    meta:
        description = "BeaverTail JavaScript loader/stealer that talks to lianxinxiao.com"
        author = "Cerber"
        family = "BeaverTail"
        severity = "critical"
        score = 94
        date = "2026-09-29"
    strings:
        $c2 = "lianxinxiao.com" ascii nocase
        $j1 = /require\(\s*["'](child_process|os|fs|axios|request|form-data|socket\.io-client)["']\s*\)/ ascii
        $j2 = /(axios|fetch|http\.request|https\.request|XMLHttpRequest)\s*[.(]/ ascii
        $j3 = "os.platform()" ascii
        $j4 = "os.homedir()" ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 2MB and $c2 and 1 of ($j*)
}

rule CERBER_MacOS_InvisibleFerret_Backdoor {
    meta:
        description = "InvisibleFerret Python backdoor: ssh_* command handlers and known XOR key"
        author = "Cerber"
        family = "InvisibleFerret"
        severity = "critical"
        score = 93
        date = "2026-09-29"
    strings:
        $k = "G01d*8@(" ascii
        $s1 = "ssh_cmd" ascii
        $s2 = "ssh_upload" ascii
        $s3 = "ssh_kill" ascii
        $s4 = "ssh_any" ascii
        $s5 = "ssh_env" ascii
        $s6 = "ssh_clip" ascii
        $s7 = "ssh_run" ascii
        $s8 = "ssh_zcp" ascii
        $py = /(^|\n)\s*(import|from)\s+[a-z_]+/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 3MB and $py and
        (4 of ($s*) or ($k and 1 of ($s*)))
}

rule CERBER_MacOS_OtterCookie_JS {
    meta:
        description = "OtterCookie JavaScript backdoor: Socket.IO client with ss_* remote-command handlers"
        author = "Cerber"
        family = "OtterCookie"
        severity = "critical"
        score = 92
        date = "2026-09-29"
    strings:
        $sio = "socket.io" ascii
        $c1 = "ss_stop" ascii
        $c2 = "ss_upf" ascii
        $c3 = "ss_upd" ascii
        $c4 = "ss_del" ascii
        $c5 = "ss_dir" ascii
        $c6 = "ss_ip" ascii
        $c7 = "ss_inz" ascii
        $c8 = "ss_inf" ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 2MB and $sio and 3 of ($c*)
}

// ============================================================================
// RANSOMWARE (real macOS families only)
// ============================================================================

rule CERBER_MacOS_KeRanger_Ransomware {
    meta:
        description = "KeRanger ransomware (trojanised Transmission): kernel_* state files and decrypt note"
        author = "Cerber"
        family = "KeRanger"
        severity = "critical"
        score = 95
        date = "2026-09-29"
    strings:
        $a = ".kernel_pid" ascii
        $b = ".kernel_time" ascii
        $c = ".kernel_complete" ascii
        $d = "README_FOR_DECRYPT.txt" ascii
        $e = "kernel_service" ascii
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 10MB and 3 of them
}

rule CERBER_MacOS_EvilQuest_ThiefQuest {
    meta:
        description = "EvilQuest/ThiefQuest: build-tag string, questd persistence names and ransom note"
        author = "Cerber"
        family = "EvilQuest"
        severity = "critical"
        score = 95
        date = "2026-09-29"
    strings:
        $a = "toidievitceffe" ascii
        $b = "com.apple.questd" ascii
        $c = "AppQuest" ascii
        $d = "mixednkey" ascii
        $e = "READ_ME_NOW.txt" ascii
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 10MB and 2 of them
}

// ============================================================================
// RUSTBUCKET (BlueNoroff) PERSISTENCE (Elastic, Jamf)
// ============================================================================

rule CERBER_MacOS_RustBucket_Fake_Apple_Secd {
    meta:
        description = "RustBucket LaunchAgent: RunAtLoad plist executing ~/Library/Metadata/System Update"
        author = "Cerber"
        family = "RustBucket"
        severity = "critical"
        score = 93
        date = "2026-09-29"
    strings:
        $exec = "/Library/Metadata/System Update" ascii
        $args = "ProgramArguments" ascii
        $run = "RunAtLoad" ascii
        $label = "com.apple.systemupdate" ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 4KB and $exec and $args and ($run or $label)
}

// ============================================================================
// PERSISTENCE / DOWNLOADER CONSTRUCTS (behavioural, complete-construct regexes)
// ============================================================================

rule CERBER_MacOS_LaunchAgent_Curl_Bash {
    meta:
        description = "LaunchAgent/Daemon whose ProgramArguments download and pipe a script into a shell"
        author = "Cerber"
        family = "Persistence"
        severity = "critical"
        score = 90
        date = "2026-09-29"
    strings:
        $args = "ProgramArguments" ascii
        $dl = /<string>[^<]{0,300}(curl|wget)[^<]{0,300}\|\s*(ba|z)?sh\b[^<]{0,60}<\/string>/ ascii
        $b64 = /<string>[^<]{0,300}base64\s+(-D|-d|--decode)[^<]{0,200}\|\s*(ba|z)?sh\b[^<]{0,60}<\/string>/ ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 8KB and $args and ($dl or $b64)
}

rule CERBER_MacOS_LaunchAgent_Tmp_Exec {
    meta:
        description = "RunAtLoad LaunchAgent whose program is a binary in /tmp, /var/tmp or /Users/Shared"
        author = "Cerber"
        family = "Persistence"
        severity = "high"
        score = 70
        date = "2026-09-29"
    strings:
        $p1 = /<key>Program(Arguments)?<\/key>\s*(<array>\s*)?<string>(\/private)?(\/var)?\/tmp\/[^<]{1,200}<\/string>/ ascii
        $p2 = /<key>Program(Arguments)?<\/key>\s*(<array>\s*)?<string>\/Users\/Shared\/[^<]{1,200}<\/string>/ ascii
        $run = "<key>RunAtLoad</key>" ascii
        $keep = "<key>KeepAlive</key>" ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 8KB and 1 of ($p*) and ($run or $keep)
}

rule CERBER_MacOS_LaunchAgent_Sudo_Nopass {
    meta:
        description = "Shell dropper that grants itself passwordless sudo (NOPASSWD write to sudoers), fetches a payload into a temp/hidden path and installs launchd persistence"
        author = "Cerber"
        family = "Persistence"
        severity = "medium"
        score = 65
        date = "2026-09-29"
    strings:
        $sudo = /(echo|printf)\s[^\n]{0,120}NOPASSWD:\s*ALL[^\n]{0,20}(>>|\|\s*(sudo\s+)?tee(\s+-a)?)\s*["']?\/(private\/)?etc\/sudoers(\.d\/[A-Za-z0-9_.-]{1,40})?/ ascii
        $launchd = /(LaunchAgents|LaunchDaemons|launchctl\s+(load|bootstrap))/ ascii
        $dl = /(curl|wget)\s+[^\n]{0,120}https?:\/\/[^\n]{0,200}(-o|-O|>)\s*["']?((\/private)?\/(var\/)?tmp\/|\/Users\/Shared\/|~\/\.|\$HOME\/\.|\/Users\/[A-Za-z0-9_.-]+\/\.)/ ascii
    condition:
        uint16(0) == 0x2123 and filesize < 16KB and $sudo and $launchd and $dl
}

rule CERBER_MacOS_ZSH_RC_Modification {
    meta:
        description = "Script appends a download-and-execute / encoded payload line to a shell startup file"
        author = "Cerber"
        family = "Persistence"
        severity = "high"
        score = 72
        date = "2026-09-29"
    strings:
        $rc = /(echo|printf)\s+["'][^\n"']{0,300}((curl|wget)[^\n"']{0,200}\|\s*(ba|z)?sh|base64\s+(-D|-d|--decode)[^\n"']{0,120}\|\s*(ba|z)?sh|osascript\s+-e)[^\n"']{0,80}["']\s*>>\s*["']?(\$HOME|~|\/Users\/[A-Za-z0-9_.-]+)\/\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile)/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 16KB and $rc
}

rule CERBER_MacOS_Cron_Persistence {
    meta:
        description = "crontab -l; echo '<schedule> curl ... | sh' | crontab - style downloader persistence"
        author = "Cerber"
        family = "Persistence"
        severity = "high"
        score = 72
        date = "2026-09-29"
    strings:
        $ct = /crontab\s+-l[^\n]{0,60};\s*(echo|printf)\s/ ascii
        $dl = /(echo|printf)\s+["'][^"'\n]{0,80}\*[^"'\n]{0,160}(curl|wget)[^"'\n]{0,200}\|\s*(ba|z)?sh/ ascii
        $in = /\|\s*crontab\s+-/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 8KB and $ct and $dl and $in
}

rule CERBER_MacOS_Login_Hook_Persistence {
    meta:
        description = "defaults write com.apple.loginwindow Login/LogoutHook pointing to a temp, shared or hidden payload"
        author = "Cerber"
        family = "Persistence"
        severity = "high"
        score = 72
        date = "2026-09-29"
    strings:
        $h = /defaults\s+write\s+(\/var\/root\/Library\/Preferences\/)?com\.apple\.loginwindow\s+(Login|Logout)Hook\s+["']?((\/private)?\/(var\/)?tmp\/|\/Users\/Shared\/|[^\s"']{0,120}\/\.[A-Za-z0-9_])/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 8KB and $h
}

rule CERBER_MacOS_Dyld_Insert_Libraries_Tmp {
    meta:
        description = "Persistent DYLD_INSERT_LIBRARIES injection of a dylib from /tmp, /Users/Shared or a hidden path (rc-file append, launchctl setenv or LaunchAgent EnvironmentVariables)"
        author = "Cerber"
        family = "CodeInjection"
        severity = "high"
        score = 72
        date = "2026-09-29"
    strings:
        $rc = /(echo|printf)\s+["']?(export\s+)?DYLD_INSERT_LIBRARIES=["']?((\/private)?\/(var\/)?tmp\/|\/Users\/Shared\/|[^\s"'<]{0,120}\/\.[A-Za-z0-9_])[^\s"'<]{1,160}\.dylib[^\n]{0,20}>>\s*["']?(\$HOME|~|\/Users\/[A-Za-z0-9_.-]+)\/\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile)/ ascii
        $lc = /launchctl\s+setenv\s+DYLD_INSERT_LIBRARIES\s+["']?((\/private)?\/(var\/)?tmp\/|\/Users\/Shared\/|[^\s"'<]{0,120}\/\.[A-Za-z0-9_])[^\s"'<]{1,160}\.dylib/ ascii
        $pl = /<key>DYLD_INSERT_LIBRARIES<\/key>\s*<string>((\/private)?\/(var\/)?tmp\/|\/Users\/Shared\/|[^\s"'<]{0,120}\/\.[A-Za-z0-9_])[^<]{1,160}\.dylib<\/string>/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 16KB and any of them
}

// ============================================================================
// REVERSE SHELLS / BACKDOORS (classic complete constructs, script-typed only)
// ============================================================================

rule CERBER_MacOS_Bash_Reverse_Shell {
    meta:
        description = "bash reverse shell over /dev/tcp"
        author = "Cerber"
        family = "ReverseShell"
        severity = "critical"
        score = 85
        date = "2026-09-29"
    strings:
        $r1 = /(ba)?sh\s+-i\s+>&\s*\/dev\/(tcp|udp)\/[^\s\/]{1,100}\/[0-9]{1,5}\s+0>&1/ ascii
        $r2 = /exec\s+[0-9]<>\s*\/dev\/tcp\/[^\s\/]{1,100}\/[0-9]{1,5}[^\n]{0,80}cat\s+<&[0-9][^\n]{0,60}while\s+read/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 16KB and any of them
}

rule CERBER_MacOS_Reverse_Shell_Oneliners {
    meta:
        description = "Classic Perl / Ruby / PHP / netcat-fifo / Python one-liner reverse shells"
        author = "Cerber"
        family = "ReverseShell"
        severity = "critical"
        score = 85
        date = "2026-09-29"
    strings:
        $perl = /open\s*\(\s*STDIN\s*,\s*["']>&S["']\s*\)\s*;\s*open\s*\(\s*STDOUT\s*,\s*["']>&S["']\s*\)/ ascii
        $ruby = /\/bin\/sh -i <&%d >&%d 2>&%d/ ascii
        $php = /fsockopen\([^\n]{0,100}\)[^\n]{0,200}\/bin\/(ba)?sh\s+-i/ ascii
        $fifo = /mkfifo\s+[^\s;]{1,40}\s*;\s*(cat|nc)[^\n]{0,120}\/bin\/(ba)?sh\s+-i[^\n]{0,20}\|\s*nc\s+[^\s\n-][^\s\n]{0,99}\s+[0-9]{1,5}\s*>\s*\/tmp\// ascii
        $nc = /\bnc(at)?\s+[^\s\n-][^\s\n]{0,99}\s+[0-9]{1,5}\s+-e\s+\/bin\/(ba)?sh/ ascii
        $py = /socket\.socket\([^\n]{0,80}\)\s*;\s*[a-z]\.connect\(\([^\n]{0,80}\)\)\s*;\s*os\.dup2\([a-z]\.fileno\(\)\s*,\s*0\)/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 16KB and any of them
}

rule CERBER_MacOS_Python_PTY_Spawn {
    meta:
        description = "Python reverse shell: socket connect, dup2 onto the socket, pty.spawn(/bin/sh)"
        author = "Cerber"
        family = "ReverseShell"
        severity = "critical"
        score = 85
        date = "2026-09-29"
    strings:
        $sock = /socket\.socket\(/ ascii
        $conn = /\.connect\(\s*\(\s*["'][^"']{1,100}["']\s*,\s*[0-9]{1,5}\s*\)\s*\)/ ascii
        $dup = /os\.dup2\(\s*\w+\.fileno\(\)\s*,\s*[0-2]\s*\)/ ascii
        $pty = /pty\.spawn\(\s*["']\/bin\/(ba)?sh["']\s*\)/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 16KB and $sock and $conn and $dup and $pty
}

rule CERBER_MacOS_Python_Subprocess_Socket {
    meta:
        description = "Tiny Python remote-command loop: connect out, recv a command, run it with shell=True, send the output back"
        author = "Cerber"
        family = "Backdoor"
        severity = "high"
        score = 74
        date = "2026-09-29"
    strings:
        $con = /\.connect\(\s*\(\s*["'][^"']{3,100}["']\s*,\s*[0-9]{2,5}\s*\)\s*\)/ ascii
        $rcv = /\.recv\(\s*[0-9]{2,5}\s*\)/ ascii
        $run = /subprocess\.(Popen|check_output|getoutput|run)\([^\n]{0,100}shell\s*=\s*True/ ascii
        $snd = /\.send(all)?\(/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 8KB and all of them
}

rule CERBER_MacOS_Node_HTTP_RCE {
    meta:
        description = "Node.js web backdoor: HTTP server passing request data straight to child_process.exec"
        author = "Cerber"
        family = "Backdoor"
        severity = "high"
        score = 74
        date = "2026-09-29"
    strings:
        $http = /require\(\s*["']http["']\s*\)/ ascii
        $child = /require\(\s*["']child_process["']\s*\)|\{\s*exec(Sync)?\s*\}\s*=\s*require/ ascii
        $exec = /exec(Sync)?\(\s*(decodeURIComponent\(\s*)?(req\.(url|query|body)|url\.parse\([^)]{0,40}\)\.(query|pathname)|parsedUrl\.query|query\.[a-z]+)/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 16KB and all of them
}

// ============================================================================
// CREDENTIAL / KEY EXFILTRATION SCRIPTS
// ============================================================================

rule CERBER_MacOS_SSH_Key_Stealer {
    meta:
        description = "Script uploads a private SSH key with curl or pipes it to curl/nc"
        author = "Cerber"
        family = "Stealer"
        severity = "critical"
        score = 86
        date = "2026-09-29"
    strings:
        $u1 = /curl\s+[^\n]{0,150}(-d\s*@?|--data(-binary)?[= ]@?|-F\s*["']?[A-Za-z_]+=@|-T\s+|--upload-file\s+)["']?[^\s"']{0,40}\.ssh\/id_(rsa|ed25519|ecdsa|dsa)["'\s]/ ascii
        $u2 = /cat\s+[^\n|]{0,40}\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\s*\|\s*[^\n]{0,60}(curl|nc|netcat)\s/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 8KB and any of them
}

rule CERBER_MacOS_Credential_File_Sweep {
    meta:
        description = "Shell script that gathers many credential files (aws, ssh, kube, docker, npm, gcloud, azure ...) and uploads them"
        author = "Cerber"
        family = "Stealer"
        severity = "high"
        score = 74
        date = "2026-09-29"
    strings:
        $c1 = ".aws/credentials" ascii
        $c2 = ".ssh/id_rsa" ascii
        $c3 = ".kube/config" ascii
        $c4 = ".docker/config.json" ascii
        $c5 = ".npmrc" ascii
        $c6 = ".azure/accessTokens.json" ascii
        $c7 = "gcloud/legacy_credentials" ascii
        $c8 = ".git-credentials" ascii
        $c9 = ".netrc" ascii
        $up = /(curl\s+[^\n]{0,100}(-F\s*["']?[A-Za-z_]{1,20}=@|--form\s+["']?[A-Za-z_]{1,20}=@|--data-binary\s+["']?@|-d\s*["']?@|-T\s+|--upload-file\s+)|\bnc\s+[^\n]{1,60}<\s*[^\s]{1,80}\.(tgz|zip|tar))/ ascii
    condition:
        uint16(0) == 0x2123 and filesize < 16KB and 4 of ($c*) and $up
}

rule CERBER_MacOS_Discord_Webhook_Exfil {
    meta:
        description = "Script posts local secrets/files to a hard-coded Discord webhook"
        author = "Cerber"
        family = "Stealer"
        severity = "high"
        score = 74
        date = "2026-09-29"
    strings:
        $wh = /discord(app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9_\-]{60,80}/ ascii
        $s1 = "login.keychain" ascii
        $s2 = "Login Data" ascii
        $s3 = "Safe Storage" ascii
        $s4 = "wallet.dat" ascii
        $s5 = ".ssh/id_" ascii
        $s6 = "Cookies.binarycookies" ascii
        $up = /curl\s+[^\n]{0,120}(-F\s*["']?[A-Za-z_]{1,20}=@|--form\s+["']?[A-Za-z_]{1,20}=@|--data-binary\s+["']?@|-d\s*["']?@|-T\s+|--upload-file\s+)/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and $wh and $up and 1 of ($s*)
}

// ============================================================================
// ENCODED SHELL PAYLOADS (complete decode-and-execute constructs)
// ============================================================================

rule CERBER_MacOS_Shell_Hex_Decode {
    meta:
        description = "Long hex string decoded with xxd -p -r and piped straight into a shell (hex-staged payload)"
        author = "Cerber"
        family = "Loader"
        severity = "high"
        score = 72
        date = "2026-09-29"
    strings:
        $x = /(echo|printf)\s+["']?[0-9a-fA-F]{60,}["']?\s*\|\s*xxd\s+(-p\s+-r|-r\s+-p|-pr|-rp)\s*\|\s*(ba|z)?sh\b/ ascii
        $y = /xxd\s+(-p\s+-r|-r\s+-p|-pr|-rp)\s*<<<?\s*["']?[0-9a-fA-F]{60,}["']?\s*\|\s*(ba|z)?sh\b/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and any of them
}

rule CERBER_MacOS_Shell_Base32_Decode {
    meta:
        description = "Shell decodes a long base32 blob and pipes it into a shell"
        author = "Cerber"
        family = "Loader"
        severity = "high"
        score = 72
        date = "2026-09-29"
    strings:
        $b = /(echo|printf)\s+["']?[A-Z2-7=]{60,}["']?\s*\|\s*(g)?base32\s+(-d|--decode|-D)\s*\|\s*(ba|z)?sh\b/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 16KB and $b
}

// ============================================================================
// TOP macOS FAMILIES 2023-2026 (added 2026-10-07)
// Every string below was taken verbatim from the primary write-up named in `reference`.
// Mach-O gate = thin/fat Mach-O magic; text gate = first 8 bytes printable.
// ============================================================================

rule CERBER_MacOS_Banshee_Stealer {
    meta:
        description = "BANSHEE stealer: anti-analysis/log strings, AppleScript temp file and staging names"
        author = "Cerber"
        family = "Banshee"
        reference = "https://www.elastic.co/security-labs/beyond-the-wail"
        severity = "critical"
        score = 93
        date = "2026-10-07"
    strings:
        $s1 = "No debugging, VM, or Russian language detected" ascii
        $s2 = "Russian language detected!" ascii
        $s3 = "Data posted successfully" ascii
        $s4 = "/tmp/tempAppleScript" ascii
        $s5 = "password-entered" ascii
        $s6 = " is empty or does not exist, skipping." ascii
        $s7 = "system_info.json" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 1MB)) and
        3 of them
}

rule CERBER_MacOS_Cuckoo_Stealer {
    meta:
        description = "Cuckoo stealer/spyware: one of its published string-XOR keys, or loginscript LaunchAgent + ~/.local-<UUID>/pw.dat"
        author = "Cerber"
        family = "Cuckoo"
        reference = "https://www.sentinelone.com/blog/macos-cuckoo-stealer-ensuring-detection-and-defense-as-new-samples-rapidly-emerge/"
        severity = "critical"
        score = 94
        date = "2026-10-07"
    strings:
        $k01 = "0dhIscuDmR6xn3VMAG9ZYjBKC4VDeXGbyDyWjHM" ascii
        $k02 = "4E72G6aXPne5ejcUgAfae6khJB3c871V0QUmkI" ascii
        $k03 = "6neCM1yILp7V3BbMpgfgYYE6KY" ascii
        $k04 = "7ricF8bWO0eBNiKEravcj2iIXohSNt" ascii
        $k05 = "7Y9lGDAyEf9vxEmFgRqpDwYM52NFPbsUc" ascii
        $k06 = "GXMSjRLvCPrrFnc1xa3xvYd43DfM8" ascii
        $k07 = "HhvDDxmmfm7QuLH4rP63Fzn2eyW5BzuM3N" ascii
        $k08 = "Hnyl2YPkOMLTNOndVtQwON" ascii
        $k09 = "JB3k62Vtqymx09aJtnF9lZrCeIc" ascii
        $k10 = "JsGqCdROAT1VDpSnxrAyZY45uQvRFP" ascii
        $k11 = "LydNPzURb22Lxk4fxPkdd" ascii
        $k12 = "MTGpOAycVm9btlQyEa5xVQPiz" ascii
        $k13 = "Qmi5gstd6Oc27AJLXJQtEqGMxXzHUx" ascii
        $k14 = "QssogTgvuTaZzPYZQynw0d" ascii
        $k15 = "aZeTZw0X2lXM083cgmJQvnmCn9kmt" ascii
        $k16 = "coOwAdmPtzt5Ps9rvUGOMEeFYajX2nJaismV" ascii
        $k17 = "rzdbcSkVHXHefChUJQFGjAm12oinXwlyH2sHfiY" ascii
        $k18 = "vLiOnPSKZ1bqjlp1dwuDvmmeQ3QN" ascii
        $s1 = "com.user.loginscript" ascii
        $s2 = /\.local-[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/ ascii
        $s3 = "pw.dat" ascii fullword
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 16MB and
        (1 of ($k*) or ($s1 and ($s2 or $s3)))
}

rule CERBER_MacOS_Cthulhu_Stealer {
    meta:
        description = "Cthulhu stealer (Go): archive name, /Users/Shared/NW staging, C2 paths and wallet-checker functions"
        author = "Cerber"
        family = "Cthulhu"
        reference = "https://www.darktrace.com/blog/from-the-depths-analyzing-the-cthulhu-stealer-malware-for-macos"
        severity = "critical"
        score = 93
        date = "2026-10-07"
    strings:
        $a = "Cthulhu_Mac_OS_" ascii
        $s1 = "/Users/Shared/NW" ascii
        $s2 = "/autocheckbytes" ascii
        $s3 = "/notification_archive" ascii
        $s4 = "battlenetChecker" ascii
        $s5 = "daedalusChecker" ascii
        $s6 = "binanceChecker" ascii
        $s7 = "electrumChecker" ascii
        $s8 = "copyKeychainFile" ascii
        $s9 = "grabberA1" ascii
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 32MB and
        ($a or 3 of ($s*))
}

rule CERBER_MacOS_Poseidon_Odyssey_Stealer {
    meta:
        description = "Poseidon/Odyssey stealer: /tmp/lovemrtrump staging folder, /otherassets/ payload paths or odyssey C2 with AppleScript/shell staging"
        author = "Cerber"
        family = "Poseidon/Odyssey"
        reference = "https://www.cyfirma.com/research/odyssey-stealer-the-rebrand-of-poseidon-stealer/"
        severity = "critical"
        score = 92
        date = "2026-10-07"
    strings:
        $dir = "/tmp/lovemrtrump" ascii
        $p1 = "/otherassets/ledger.zip" ascii
        $p2 = "/otherassets/botnet" ascii
        $c1 = "odyssey1.to" ascii nocase
        $c2 = "odyssey-st.com" ascii nocase
        $x1 = "do shell script" ascii
        $x2 = /dscl\s+(\.|\/Local\/Default)\s+-?authonly/ ascii
        $x3 = "ditto -c -k" ascii
        $x4 = /curl\s+-[A-Za-z]/ ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 1MB)) and
        (($dir and 1 of ($x*)) or ($p1 and $p2) or (1 of ($c*) and 1 of ($p*, $x*)))
}

rule CERBER_MacOS_MacSync_Backdoor_2025 {
    meta:
        description = "MacSync (Mac.c) 2025+ loader/backdoor: SONOMAC1/AGNT1 magics, /v1/agent API, X-Upload-Token, .sysnotif-agent.log"
        author = "Cerber"
        family = "MacSync"
        reference = "https://securelist.com/macsync-new-version/121383/"
        severity = "critical"
        score = 94
        date = "2026-10-07"
    strings:
        $m1 = "SONOMAC1" ascii
        $m2 = "AGNT1" ascii fullword
        $m3 = "sn-dek-wrap-v1" ascii
        $s1 = ".sysnotif-agent.log" ascii
        $s2 = "/v1/agent/ping" ascii
        $s3 = "/v1/agent/refresh" ascii
        $s4 = "X-Upload-Token" ascii
        $s5 = "com.apple.finder.agent" ascii
        $s6 = "osalogging.zip" ascii
        $s7 = "daemon_function" ascii
        $c1 = "docsend.appstore.com.mx" ascii nocase
        $c2 = "apple03cloudstore.com" ascii nocase
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 2MB)) and
        (($m1 and 1 of ($s*, $c*)) or $m3 or 3 of ($m2, $s*, $c*) or (1 of ($c*) and 1 of ($s*)))
}

rule CERBER_MacOS_AMOS_Backdoor {
    meta:
        description = "Atomic Stealer (AMOS) backdoor: com.finder.helper daemon running ~/.agent/~/.helper, or its /api/tasks/ bot loop with the hidden-file set"
        author = "Cerber"
        family = "Atomic/AMOS"
        reference = "https://moonlock.com/amos-backdoor-persistent-access"
        severity = "critical"
        score = 93
        date = "2026-10-07"
    strings:
        $label = "com.finder.helper" ascii
        $h = /[\/~]\.helper\b/ ascii
        $a = /[\/~]\.agent\b/ ascii
        $u = /[\/~]\.username\b/ ascii
        $p = /[\/~]\.pass\b/ ascii
        $tasks = "/api/tasks/" ascii
        $join = "/api/join" ascii
        $bot = "botUrl" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 256KB)) and
        (($label and ($h or $a)) or ($tasks and 3 of ($h, $a, $u, $p, $join, $bot)))
}

rule CERBER_MacOS_AMOS_Hidden_AppSupport_Persistence {
    meta:
        description = "AMOS 2026 activity: AccountsHelper/mdworker_shared hidden in dot-com.apple folders of Application Support, or its stage= beacon set"
        author = "Cerber"
        family = "Atomic/AMOS"
        reference = "https://unit42.paloaltonetworks.com/atomic-macos-amos-stealer-activity/"
        severity = "critical"
        score = 92
        date = "2026-10-07"
    strings:
        $d1 = "Application Support/.com.apple.accountsd" ascii
        $d2 = "Application Support/.com.apple.metadata.mds" ascii
        $b1 = "AccountsHelper" ascii
        $b2 = "mdworker_shared" ascii
        $st1 = "stage=init_session" ascii
        $st2 = "stage=resolve_auth" ascii
        $st3 = "stage=local_data" ascii
        $st4 = "stage=messengers" ascii
        $st5 = "stage=wallets" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 512KB)) and
        (($d1 and $b1) or ($d2 and $b2) or 3 of ($st*))
}

// ---------------------------------------------------------------- DPRK

rule CERBER_MacOS_KandyKorn_SugarLoader {
    meta:
        description = "KandyKorn / SUGARLOADER / HLOADER (Lazarus REF7001): safari.ck config path, resp_* command handlers, HLOADER signing id, FinderTools C2"
        author = "Cerber"
        family = "KandyKorn"
        reference = "https://www.elastic.co/security-labs/elastic-catches-dprk-passing-out-kandykorn"
        severity = "critical"
        score = 95
        date = "2026-10-07"
    strings:
        $m1 = "/com.apple.safari.ck" ascii
        $m2 = "/chkupdate.XXX" ascii
        $m3 = "resp_file_dir" ascii
        $m4 = "resp_cfg_set" ascii
        $m5 = "resp_proc_kill" ascii
        $m6 = "HLOADER-5555494485b460f1e2343dffaef9b94d01136320" ascii
        $m7 = "/Users/Shared/.sld" ascii
        $py_c2 = "tp-globa.xyz" ascii nocase
        $py1 = /(^|\n)\s*(import|from)\s+[a-z_]+/ ascii
        $py2 = "/Users/Shared/" ascii
    condition:
        ((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 16MB and
         (2 of ($m*) or $m6)) or
        ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 1MB and $py_c2 and $py1 and $py2)
}

rule CERBER_MacOS_HiddenRisk_BlueNoroff {
    meta:
        description = "BlueNoroff Hidden Risk: zshenv-persistence marker /tmp/.zsh_init_success, cur1-agent UA, LessonOne dropper, DoPost/SaveAndExec backdoor"
        author = "Cerber"
        family = "HiddenRisk"
        reference = "https://www.sentinelone.com/labs/bluenoroff-hidden-risk-threat-actor-targets-macs-with-fake-crypto-news-and-novel-persistence/"
        severity = "critical"
        score = 93
        date = "2026-10-07"
    strings:
        $z = "/tmp/.zsh_init_success" ascii
        $ua = "cur1-agent" ascii
        $b = "Education.LessonOne" ascii
        $f1 = "SaveAndExec" ascii
        $f2 = "DoPost" ascii
        $f3 = "ProcessRequest" ascii
        $f4 = ".zshenv" ascii
        $msie = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)" ascii nocase
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 16MB and
        (($z and 1 of ($f*, $ua, $msie)) or ($ua and 2 of ($f*)) or ($b and ($ua or $msie or $f4)))
}

rule CERBER_MacOS_NimDoor_BlueNoroff {
    meta:
        description = "NimDoor (DPRK, Nim): injector/loader build names, GoogIe LLC/CoreKitAgent persistence, hard-coded crypto keys, cur1-request UA, fake Zoom SDK C2"
        author = "Cerber"
        family = "NimDoor"
        reference = "https://www.sentinelone.com/labs/macos-nimdoor-dprk-threat-actors-target-web3-and-crypto-platforms-with-nim-based-malware/"
        severity = "critical"
        score = 95
        date = "2026-10-07"
    strings:
        $n1 = "trojan1_arm64" ascii
        $n2 = "InjectWithDyldArm64" ascii
        $n3 = "user_startup_loader_arm64" ascii
        $n4 = "user_startup_main_arm64" ascii
        $n5 = "user_startup_installer_arm64" ascii
        $n6 = "root_startup_loader" ascii
        $p1 = "GoogIe LLC" ascii
        $p2 = "Library/CoreKit/CoreKitAgent" ascii
        $p3 = "Library/DnsService" ascii
        $k1 = "gift123$%^" ascii
        $k2 = "Ej7bx@YRG2uUhya#50Yt*ao" ascii
        $k3 = "3LZu5H$yF^FSwPu3SqbL*sK" ascii
        $k4 = "lZjJ7iuK2qcmMW6hacZOw62" ascii
        $ua = "cur1-request" ascii
        $c1 = "firstfromsep.online" ascii nocase
        $c2 = "dataupload.store" ascii nocase
        $c3 = "safeup.store" ascii nocase
        $c4 = "writeup.live" ascii nocase
        $c5 = /support\.us0[0-9]web-zoom\.[a-z]{2,8}/ ascii nocase
        $c6 = "Zook SDK Update" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 512KB)) and
        (1 of ($k*) or 2 of ($n*, $p*, $ua, $c*))
}

rule CERBER_MacOS_FlexibleFerret_Loader {
    meta:
        description = "FlexibleFerret (Contagious Interview) shell loader: macpatch.sh/CDrivers staging in /var/tmp, driver9990as7tpatch LaunchAgent, zynoracreative payload host"
        author = "Cerber"
        family = "FlexibleFerret"
        reference = "https://www.jamf.com/blog/flexibleferret-malware-continues-to-adapt/"
        severity = "critical"
        score = 93
        date = "2026-10-07"
    strings:
        $s1 = "/var/tmp/macpatch.sh" ascii
        $s2 = "/var/tmp/CDrivers" ascii
        $s3 = "com.driver9990as7tpatch" ascii
        $s4 = "drivfixer.sh" ascii
        $s5 = "MediaPatcher.app" ascii
        $s6 = "zynoracreative.com" ascii nocase
        $s7 = "drv-Arm64.patch" ascii
        $s8 = "drv-Intel.patch" ascii
        $s9 = "cdrivMac.sh" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 256KB)) and
        2 of them
}

rule CERBER_MacOS_BeaverTail_InvisibleFerret_Stager {
    meta:
        description = "BeaverTail stealer / InvisibleFerret loader: ~/.n2 payload folder, .npl/.sysinfo loaders, bundled .pyp Python, /pdown /client/ /uploads /keys C2 paths"
        author = "Cerber"
        family = "BeaverTail"
        reference = "https://www.esentire.com/blog/bored-beavertail-invisibleferret-yacht-club-a-lazarus-lure-pt-2"
        severity = "critical"
        score = 90
        date = "2026-10-07"
    strings:
        $f1 = /[\/'"`]\.n2[\/'"`]/ ascii
        $f2 = /[\/'"`]\.npl['"`]/ ascii
        $f3 = /[\/'"`]\.sysinfo['"`]/ ascii
        $f4 = /[\/'"`]\.pyp[\/'"`]/ ascii
        $f5 = /['"`\/]p\.zi['"`]/ ascii
        $u1 = /['"`]\/pdown['"`]/ ascii
        $u2 = /['"`]\/client\/['"`]/ ascii
        $u3 = /['"`]\/(brow|mclip|payload)\/['"`]/ ascii
        $u4 = /['"`]\/keys['"`]/ ascii
        $u5 = /['"`]\/uploads['"`]/ ascii
        $ctx1 = /require\(\s*["'](child_process|os|fs|path|request|axios)["']\s*\)/ ascii
        $ctx2 = /(^|\n)\s*(import|from)\s+(os|sys|subprocess|base64|requests|socket)\b/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 3MB and 1 of ($ctx*) and
        ((2 of ($f*) and 1 of ($u*)) or (1 of ($f*) and 3 of ($u*)))
}

rule CERBER_MacOS_RustDoor_Backdoor {
    meta:
        description = "RustDoor/ThiefBucket backdoor (Rust): lock_in_* persistence config keys, /gateway/ C2 API and known C2 domains"
        author = "Cerber"
        family = "RustDoor"
        reference = "https://www.bitdefender.com/en-au/blog/labs/new-macos-backdoor-written-in-rust-shows-possible-link-with-windows-ransomware-group"
        severity = "critical"
        score = 92
        date = "2026-10-07"
    strings:
        $l1 = "lock_in_cron" ascii
        $l2 = "lock_in_launch" ascii
        $l3 = "lock_in_rc" ascii
        $l4 = "lock_in_dock" ascii
        $g1 = "/gateway/register" ascii
        $g2 = "/gateway/report" ascii
        $g3 = "/gateway/task" ascii
        $g4 = "/tasks/upload_file" ascii
        $c1 = "maconlineoffice.com" ascii nocase
        $c2 = "serviceicloud.com" ascii nocase
        $c3 = "sarkerrentacars.com" ascii nocase
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB and
        (3 of ($l*) or 2 of ($g*) or (1 of ($c*) and 1 of ($l*, $g*)))
}

rule CERBER_MacOS_TodoSwift_Dropper {
    meta:
        description = "TodoSwift (BlueNoroff) dropper: GoogleMsgStatus.pdf decoy + NetMsgStatus stage 2 in /tmp, MS-Office-spoofing user agent, buy2x C2"
        author = "Cerber"
        family = "TodoSwift"
        reference = "https://www.iru.com/blog/todoswift-disguises-malware-download-behind-bitcoin-pdf"
        severity = "critical"
        score = 92
        date = "2026-10-07"
    strings:
        $s1 = "/tmp/GoogleMsgStatus.pdf" ascii
        $s2 = "/tmp/NetMsgStatus" ascii
        $s3 = "MasaMatsu.TodoTasks" ascii
        $s4 = "buy2x.com" ascii nocase
        $s5 = "like gecko ms-office;) compatible; chrome/125.0.0.0" ascii nocase
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 16MB and
        2 of them
}

// ---------------------------------------------------------------- other APT / backdoors

rule CERBER_MacOS_ChillyHell_Backdoor {
    meta:
        description = "ChillyHell modular backdoor (notarized): Welcome to Paradise reverse-shell banner, Module* classes, com.apple.qtop persistence"
        author = "Cerber"
        family = "ChillyHell"
        reference = "https://www.jamf.com/blog/chillyhell-a-modular-macos-backdoor/"
        severity = "critical"
        score = 94
        date = "2026-10-07"
    strings:
        $banner = "Welcome to Paradise!" ascii
        $m1 = "ModuleBackconnectShell" ascii
        $m2 = "ModuleSUBF" ascii
        $m3 = "ModuleUpdater" ascii
        $m4 = "ModuleLoader" ascii
        $q1 = "com.apple.qtop" ascii
        $q2 = "/usr/local/bin/qtop" ascii
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 16MB and
        (($banner and 1 of ($m*, $q*)) or ($m1 and $m2) or (1 of ($q*) and 2 of ($m*)))
}

rule CERBER_MacOS_PasivRobber_Spyware {
    meta:
        description = "PasivRobber spyware suite: /Library/protect/wsus install tree, com.apple.goed daemon, CDynAnalyzeService RPC methods"
        author = "Cerber"
        family = "PasivRobber"
        reference = "https://www.iru.com/threats/pasivrobber"
        severity = "critical"
        score = 92
        date = "2026-10-07"
    strings:
        $p1 = "/Library/protect/wsus" ascii
        $p2 = "com.apple.goed" ascii
        $p3 = "com.apple.goed/limit_version" ascii
        $r1 = "CDynAnalyzeService" ascii
        $r2 = "GetImPasswordInformations" ascii
        $r3 = "GetNetShareInfos" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 32MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 256KB)) and
        2 of them
}

rule CERBER_MacOS_ZuRu_Khepri {
    meta:
        description = "ZuRu (trojanised Termius/iTerm2) with modified Khepri beacon: xssooxxagent persistence, /tmp/.fseventsd payload, lock files, termius C2"
        author = "Cerber"
        family = "ZuRu"
        reference = "https://www.sentinelone.com/blog/macos-zuru-resurfaces-modified-khepri-c2-hides-inside-doctored-termius-app/"
        severity = "critical"
        score = 93
        date = "2026-10-07"
    strings:
        $s1 = "com.apple.xssooxxagent" ascii
        $s2 = "/tmp/.fseventsd" ascii
        $s3 = "beacon_arm64_x86_64" ascii
        $s4 = "my_unique_process.lock" ascii
        $s5 = "apple-local-ipc.sock.lock" ascii
        $s6 = "download.termius.info" ascii nocase
        $s7 = "termius.fun" ascii nocase
        $s8 = ".Termius Helper1" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 256KB)) and
        2 of them
}

rule CERBER_MacOS_XCSSET_2025_C2 {
    meta:
        description = "XCSSET 2025 variant: one of its .ru C2 domains inside an AppleScript/shell/Mach-O stage that runs osascript/osacompile/curl or hex-decodes"
        author = "Cerber"
        family = "XCSSET"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/03/11/new-xcsset-malware-adds-new-obfuscation-persistence-techniques-to-infect-xcode-projects/"
        severity = "critical"
        score = 92
        date = "2026-10-07"
    strings:
        $d01 = "bulknames.ru" ascii nocase
        $d02 = "castlenet.ru" ascii nocase
        $d03 = "chaoping.ru" ascii nocase
        $d04 = "devapple.ru" ascii nocase
        $d05 = "gigacells.ru" ascii nocase
        $d06 = "gizmodoc.ru" ascii nocase
        $d07 = "trixmate.ru" ascii nocase
        $d08 = "itoyads.ru" ascii nocase
        $d09 = "rigglejoy.ru" ascii nocase
        $d10 = "rutornet.ru" ascii nocase
        $d11 = "sigmate.ru" ascii nocase
        $d12 = "vivatads.ru" ascii nocase
        $d13 = "figmasol.ru" ascii nocase
        $x1 = "osascript" ascii
        $x2 = "osacompile" ascii
        $x3 = /curl\s+-[A-Za-z]/ ascii
        $x4 = /xxd\s+-p\s+-r|xxd\s+-r\s+-p/ ascii
        $x5 = ".zshrc_aliases" ascii
        $x6 = "PBXShellScriptBuildPhase" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 4MB)) and
        1 of ($d*) and 1 of ($x*)
}

rule CERBER_MacOS_LightSpy_Implant {
    meta:
        description = "LightSpy macOS implant: core/loader names, mac manifest/version configs and its AES key string"
        author = "Cerber"
        family = "LightSpy"
        reference = "https://threatfabric.com/blogs/lightspy-implant-for-macos"
        severity = "critical"
        score = 92
        date = "2026-10-07"
    strings:
        $s1 = "C40F0D27" ascii fullword
        $s2 = "96382741" ascii fullword
        $s3 = "macmanifest.json" ascii
        $s4 = "macversion.json" ascii
        $s5 = "3e2717e8b3873b29" ascii
        $s6 = "macircloader" ascii
        $s7 = "AppleAppLit" ascii
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 16MB and
        2 of them
}

rule CERBER_MacOS_SpectralBlur_Backdoor {
    meta:
        description = "SpectralBlur (DPRK) backdoor: its proc_* command-handler symbol set with xcrypt stream cipher"
        author = "Cerber"
        family = "SpectralBlur"
        reference = "https://objective-see.org/blog/blog_0x78.html"
        severity = "critical"
        score = 92
        date = "2026-10-07"
    strings:
        $x = "_xcrypt" ascii fullword
        $p1 = "_proc_hibernate" ascii fullword
        $p2 = "_proc_testconn" ascii fullword
        $p3 = "_proc_getcfg" ascii fullword
        $p4 = "_proc_setcfg" ascii fullword
        $p5 = "_proc_rmfile" ascii fullword
        $p6 = "_proc_download" ascii fullword
        $p7 = "_proc_shell" ascii fullword
        $p8 = "_openchannel" ascii fullword
        $p9 = "_mainprocess" ascii fullword
        $m = ".macshare" ascii
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 4MB and
        (($x and 5 of ($p*)) or ($m and 4 of ($p*)))
}

rule CERBER_MacOS_JokerSpy_Xcc_ShPy {
    meta:
        description = "JokerSpy: xcc TCC-permission checker (XProtectCheck project) or sh.py backdoor with its sar.dat config / influmarket C2"
        author = "Cerber"
        family = "JokerSpy"
        reference = "https://www.elastic.co/security-labs/inital-research-of-jokerspy"
        severity = "critical"
        score = 90
        date = "2026-10-07"
    strings:
        $x = "XProtectCheck" ascii
        $o1 = "ScreenRecording: " ascii
        $o2 = "Accessibility: " ascii
        $o3 = "kMDItemDisplayName = *TCC.db" ascii
        $o4 = "FullDiskAccess: " ascii
        $cfg = "Public/Safari/sar.dat" ascii
        $c2 = "influmarket.org" ascii nocase
        $py = /(^|\n)\s*(import|from)\s+[a-z_]+/ ascii
    condition:
        ((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 8MB and
         $x and 1 of ($o*)) or
        ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 1MB and $py and ($cfg or $c2))
}

rule CERBER_MacOS_CloudMensis_BadRAT {
    meta:
        description = "CloudMensis/BadRAT spy agent: its fake WindowServer and iTunesInfo/FaceTime-container paths plus Cloud* storage commands"
        author = "Cerber"
        family = "CloudMensis"
        reference = "https://www.welivesecurity.com/2022/07/19/i-see-what-you-did-there-look-cloudmensis-macos-spyware/"
        severity = "critical"
        score = 93
        date = "2026-10-07"
    strings:
        $p1 = "/Library/WebServer/share/httpd/manual/WindowServer" ascii
        $p2 = "com.apple.iTunesInfo29.plist" ascii
        $p3 = "Containers/com.apple.FaceTime/Data/Library/windowserver" ascii
        $p4 = "Containers/com.apple.Notes/Data/Library/.CFUserTextDecoding" ascii
        $p5 = "Resources_V3/.CrashRep" ascii
        $c1 = "CloudCmd" ascii fullword
        $c2 = "CloudShell" ascii fullword
        $c3 = "FlowEncrypt" ascii
        $c4 = "/Febrary/" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 16MB) or (uint32be(0) == 0x3c3f786d and filesize < 16KB)) and
        (2 of ($p*) or (1 of ($p*) and 1 of ($c*)) or 3 of ($c*))
}

rule CERBER_MacOS_ObjCShellz {
    meta:
        description = "ObjCShellz (BlueNoroff): tiny ProcessRequest shell with sendRequest/startTimer loop and its sdf/wsx JSON check-in"
        author = "Cerber"
        family = "ObjCShellz"
        reference = "https://www.jamf.com/blog/bluenoroff-strikes-again-with-new-macos-malware/"
        severity = "high"
        score = 80
        date = "2026-10-07"
    strings:
        $a = "ProcessRequest" ascii fullword
        $b = "sendRequest" ascii fullword
        $c = "startTimer" ascii fullword
        $d = "operatingSystemVersionString" ascii fullword
        $e = "wsx" ascii fullword
        $f = "sdf" ascii fullword
        $g = "swissborg.blog" ascii nocase
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 1MB and
        ($g or ($a and $b and $c and $d and $e and $f))
}

// ---------------------------------------------------------------- ransomware

rule CERBER_MacOS_Turtle_Ransomware {
    meta:
        description = "Turtle ransomware (Go): TURTLERANSv0 extension, hard-coded AES key and TurmiRansom build path"
        author = "Cerber"
        family = "Turtle"
        reference = "https://objective-see.org/blog/blog_0x76.html"
        severity = "critical"
        score = 95
        date = "2026-10-07"
    strings:
        $s1 = "TURTLERANSv0" ascii
        $s2 = "wugui123wugui123" ascii
        $s3 = "TurmiRansom" ascii
        $s4 = "en0cr0yp0tFile" ascii
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB and
        2 of them
}

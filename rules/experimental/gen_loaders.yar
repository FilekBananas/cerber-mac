/*
 * Cerber – reguły własne (loaders), napisane 2026-10-09 przez agentów na podstawie publicznych raportów.
 * Warstwa "community": same nie dają werdyktu ZŁOŚLIWY. Zero trafień na ~2800 czystych plikach macOS
 * (programy z /Applications i /System, /usr/bin, LaunchAgents, rozszerzenia VS Code, node_modules).
 */

/*
 * CERBER - generated loader rules (staging, not yet promoted)
 * Topic: obfuscated script loaders used by macOS malware.
 *
 * Same header policy as rules/custom/macos.yar:
 *   TYPE GATE  inline in every rule (text: first 8 bytes in 9..126; Mach-O: magic check)
 *   SIZE LIMIT explicit filesize ceiling per artefact type
 *   SEVERAL INDICATORS  at least two independent constructs, or one regex that encodes a complete construct
 * Score < 75 for every rule: these are behavioural loader constructs, not family IOCs.
 */

rule CERBER_Gen_Loader_JXA_ObjCNSTask_Exec {
    meta:
        description = "JXA loader using the ObjC bridge (ObjC.import Foundation) to build an NSTask or to fetch NSData and eval it"
        author = "Cerber (gen)"
        family = "GenericJXA"
        severity = "high"
        score = 70
        date = "2026-10-09"
        reference = "https://detection.fyi/sigmahq/sigma/macos/process_creation/proc_creation_macos_jxa_in_memory_execution/"
    strings:
        $imp  = /ObjC\.import\(\s*["']Foundation["']\s*\)/ ascii
        $task = /\$\.NSTask\.(alloc|new)/ ascii
        $data = /\$\.NSData\.(dataWithContentsOfURL|alloc)/ ascii
        $str  = /\$\.NSString\.alloc\.initWithDataEncoding/ ascii
        $ev   = /eval\(\s*ObjC\.unwrap\(/ ascii
        $url  = /\$\.NSURL\.URLWithString\(/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 128KB and
        $imp and (($task and ($data or $str)) or ($ev and ($url or $data)))
}

rule CERBER_Gen_Loader_JXA_RunScript_DoShellDecodePipe {
    meta:
        description = "JXA osascript that calls doShellScript with a base64, xxd or openssl decode piped straight into a shell"
        author = "Cerber (gen)"
        family = "GenericJXA"
        severity = "high"
        score = 72
        date = "2026-10-09"
        reference = "https://redcanary.com/blog/threat-detection/applescript"
    strings:
        $app = /Application\(\s*["'][A-Za-z ]{3,30}["']\s*\)/ ascii
        $dss = /doShellScript\(\s*["'][^"'\r\n]{0,300}(base64\s+(-D|-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d)[^"'\r\n]{0,300}\|\s*(ba|z)?sh\b/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and
        $app and $dss
}

rule CERBER_Gen_Loader_AppleScript_OsacompileDecodedDropper {
    meta:
        description = "Shell dropper that decodes a payload and pipes it into osacompile to produce a run-only compiled .scpt"
        author = "Cerber (gen)"
        family = "GenericAppleScriptDropper"
        severity = "high"
        score = 70
        date = "2026-10-09"
        reference = "https://redcanary.com/blog/threat-detection/applescript"
    strings:
        $dec = /(base64\s+(-D|-d|--decode)|xxd\s+-r\s+-p)[^\r\n]{0,200}\|\s*osacompile\b/ ascii
        $out = /osacompile\s+-o\s+[^\r\n]{0,160}\.scpt/ ascii
        $ch  = /chmod\s+\+x/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 128KB and
        $dec and ($out or $ch)
}

rule CERBER_Gen_Loader_Python_DecodeWriteChmodDropper {
    meta:
        description = "Python script that writes a zlib or base64 decoded blob to disk, chmods it and runs it (dropper stage)"
        author = "Cerber (gen)"
        family = "GenericPythonDropper"
        severity = "high"
        score = 72
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/coming-out-of-your-shell-from-shlayer-to-zshlayer/"
    strings:
        $w   = /open\([^\r\n]{0,120},\s*["'](wb|ab)["']\)\.write\(\s*(zlib|bz2|lzma|gzip)\.decompress\(\s*base64\.b64decode\(/ ascii
        $w2  = /open\([^\r\n]{0,120},\s*["']wb["']\)\.write\(\s*base64\.b64decode\(/ ascii
        $c   = /os\.chmod\([^\r\n]{0,120}0o?[67][0-7][0-7]/ ascii
        $run = /(subprocess\.(Popen|call|run|check_output)|os\.system|os\.execv[pe]?)\(/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 256KB and
        ($w or $w2) and $c and $run
}

rule CERBER_Gen_Loader_Python_MarshalDecodeDropChmod {
    meta:
        description = "Small Python loader that base64-decodes a marshal blob, writes it to a file and chmods it (marshal/pyarmor-style staging)"
        author = "Cerber (gen)"
        family = "GenericPythonLoader"
        severity = "high"
        score = 66
        date = "2026-10-09"
        reference = "https://www.jamf.com/blog/macsync-stealer-evolution-code-signed-swift-malware-analysis/"
    strings:
        $m = /marshal\.loads\(/ ascii
        $b = /base64\.b(64|85)decode\(/ ascii
        $w = /open\([^\r\n]{0,120},\s*["']wb["']\)/ ascii
        $c = /os\.chmod\(/ ascii
        $e = /exec\(|eval\(/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 32KB and
        $m and $b and $w and $c and $e
}

rule CERBER_Gen_Loader_Bash_RevBase64_EvalChain {
    meta:
        description = "Bash eval of a command substitution that reverses a string (rev) before base64 decoding it"
        author = "Cerber (gen)"
        family = "GenericShellLoader"
        severity = "high"
        score = 74
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/coming-out-of-your-shell-from-shlayer-to-zshlayer/"
    strings:
        $a = /eval\s+["']?\$\(\s*(echo|printf)\s+[^\r\n]{0,400}\|\s*rev\s*\|\s*base64\s+(-D|-d|--decode)/ ascii
        $b = /(echo|printf)\s+[^\r\n]{0,400}\|\s*rev\s*\|\s*base64\s+(-D|-d|--decode)[^\r\n]{0,80}\|\s*(ba|z)?sh\b/ ascii
    condition:
        (uint8(0) == 0x23 or (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127))) and filesize < 64KB and
        any of ($a, $b)
}

rule CERBER_Gen_Loader_Bash_OpensslDecPipeShell {
    meta:
        description = "openssl enc decryption whose plaintext is piped straight into bash or zsh (encrypted stage)"
        author = "Cerber (gen)"
        family = "GenericShellLoader"
        severity = "high"
        score = 72
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/coming-out-of-your-shell-from-shlayer-to-zshlayer/"
    strings:
        $a = /openssl\s+enc\s+-d\s+-[A-Za-z0-9-]{3,24}[^\r\n|]{0,200}\|\s*(ba|z)?sh\b/ ascii
        $b = /openssl\s+enc\s+-[A-Za-z0-9-]{3,24}\s+-d\s+[^\r\n|]{0,200}\|\s*(ba|z)?sh\b/ ascii
        $c = /openssl\s+enc\s+-d[^\r\n|]{0,200}\|\s*(ba|z)?sh\b/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and
        any of ($a, $b, $c)
}

rule CERBER_Gen_Loader_Bash_XxdDecompressShellChain {
    meta:
        description = "Hex-decoded blob piped through a decompressor into a shell (xxd -r -p | gunzip/xz | sh)"
        author = "Cerber (gen)"
        family = "GenericShellLoader"
        severity = "high"
        score = 72
        date = "2026-10-09"
        reference = "https://attack.mitre.org/software/S0402"
    strings:
        $a = /xxd\s+-r\s+-p[^\r\n]{0,120}\|\s*(gunzip|zcat|gzip\s+-d|bzcat|xz\s+-d|unxz|xzcat)\b[^\r\n]{0,120}\|\s*(ba|z)?sh\b/ ascii
        $b = /(base64\s+(-D|-d|--decode))[^\r\n]{0,120}\|\s*(gunzip|zcat|gzip\s+-d|bzcat|xz\s+-d|unxz)\b[^\r\n]{0,120}\|\s*(ba|z)?sh\b/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and
        any of ($a, $b)
}

rule CERBER_Gen_Loader_Swift_Macho_ZshDecodeDownload {
    meta:
        description = "Swift-built Mach-O that spawns /bin/zsh -c with base64 decoding and an HTTP URL (downloaded script runner)"
        author = "Cerber (gen)"
        family = "GenericSwiftLoader"
        severity = "high"
        score = 66
        date = "2026-10-09"
        reference = "https://www.jamf.com/blog/macsync-stealer-evolution-code-signed-swift-malware-analysis/"
    strings:
        $zsh  = "/bin/zsh" ascii
        $dashc = { 00 2D 63 00 }
        $b64  = /base64 (-D|-d|--decode)/ ascii
        $url  = /https?:\/\/[a-z0-9.-]{4,80}\// ascii
        $sw   = "libswiftCore" ascii
        $nt   = "NSTask" ascii
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and
        filesize < 3MB and $zsh and $dashc and $b64 and $url and ($sw or $nt)
}

rule CERBER_Gen_Loader_Electron_MainJs_RemoteEval {
    meta:
        description = "Electron main script (app.asar main.js) that loads a remote page or fetched code and evaluates it"
        author = "Cerber (gen)"
        family = "GenericElectronLoader"
        severity = "high"
        score = 70
        date = "2026-10-09"
        reference = "https://www.intego.com/mac-security-blog/osx-amos-hunting-c2s-in-trojanized-electron-asar-payloads/"
    strings:
        $el  = /require\(\s*["']electron["']\s*\)/ ascii
        $net = /(https?\.get|net\.request|fetch)\(\s*["'`]?(https?:\/\/|\$\{|[a-zA-Z_])/ ascii
        $ev  = /eval\(\s*(Buffer\.from|atob)\(/ ascii
        $url = /loadURL\(\s*["']https?:\/\// ascii
        $ex  = /executeJavaScript\(\s*(await\s+)?(fetch|res|body|data|response|code)/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 256KB and
        $el and ((($net and $ev)) or ($url and ($ev or $ex)) or ($ex and $net))
}

rule CERBER_Gen_Loader_Shell_AsarOverwrite {
    meta:
        description = "Shell script that downloads a file and writes it over an installed Electron app.asar (patched-asar stealer)"
        author = "Cerber (gen)"
        family = "GenericElectronLoader"
        severity = "high"
        score = 72
        date = "2026-10-09"
        reference = "https://www.intego.com/mac-security-blog/osx-amos-hunting-c2s-in-trojanized-electron-asar-payloads/"
    strings:
        $dl  = /(curl|wget)\s+[^\r\n]{0,200}(-o|-O|--output)\s+[^\r\n]{0,200}app\.asar/ ascii
        $cp  = /(cp|mv)\s+[^\r\n]{0,200}\s[^\r\n]{0,200}\/Contents\/Resources\/app\.asar/ ascii
        $ap  = "/Contents/Resources/app.asar" ascii
        $dl2 = /(curl|wget)\s+-[A-Za-z]*\s+https?:\/\/[^\s"']{4,200}/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and
        ($dl or ($cp and $dl2) or ($ap and $dl2 and $cp))
}

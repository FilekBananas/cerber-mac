/*
 * Cerber – reguły własne (c2), napisane 2026-10-09 przez agentów na podstawie publicznych raportów.
 * Warstwa "community": same nie dają werdyktu ZŁOŚLIWY. Zero trafień na ~2800 czystych plikach macOS
 * (programy z /Applications i /System, /usr/bin, LaunchAgents, rozszerzenia VS Code, node_modules).
 */

/*
 * CERBER - generated C2 / hacking-tool rules (staging)
 * Author: Cerber (gen) | Date: 2026-10-09
 *
 * Same policy as rules/custom/macos.yar: inline TYPE GATE (Mach-O magic or text
 * first bytes), explicit SIZE LIMIT, SEVERAL INDICATORS, no common words.
 * Score >= 75 -> CERTAIN (family-exact), < 75 -> HIGH/suspicious (behavioural).
 * Strings are taken from public documentation only (see meta: reference).
 */

rule CERBER_Gen_C2_Poseidon_Go_Agent {
    meta:
        description = "Mythic Poseidon (Golang Apfell) macOS agent binary: Go module paths from the xorrior/MythicAgents repo"
        author = "Cerber (gen)"
        family = "Poseidon"
        severity = "critical"
        score = 88
        date = "2026-10-09"
        reference = "https://pkg.go.dev/github.com/xorrior/poseidon"
        reference2 = "https://docs.specterops.io/mythic-agents/poseidon-docs/home"
    strings:
        $m1 = "github.com/xorrior/poseidon" ascii
        $m2 = "github.com/MythicAgents/poseidon" ascii
        $d1 = "Golang Apfell Agent" ascii
        $c1 = "restfulpatchthrough" ascii
        $c2 = "pkg/commands/triagedirectory" ascii
        $c3 = "pkg/commands/sshauth" ascii
    condition:
        ((uint32(0) == 0xfeedfacf) or (uint32(0) == 0xfeedface) or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and
        filesize < 40MB and 2 of ($m*, $d1, $c*)
}

rule CERBER_Gen_C2_Apfell_JXA_Osascript_Cradle {
    meta:
        description = "Apfell download cradle: curl piped into osascript -l JavaScript (JXA in-memory execution)"
        author = "Cerber (gen)"
        family = "Apfell"
        severity = "critical"
        score = 84
        date = "2026-10-09"
        reference = "https://docs.specterops.io/mythic-agents/apfell-docs/home"
    strings:
        $r1 = /curl\s+[^\n|;]{1,200}\|\s*osascript\s+-l\s+JavaScript/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and $r1
}

rule CERBER_Gen_C2_JXA_NSTask_Base64_Eval_Loader {
    meta:
        description = "JXA script that base64-decodes a blob, runs it through eval and spawns children via NSTask (stager/loader shape)"
        author = "Cerber (gen)"
        family = "JXA_Loader"
        severity = "high"
        score = 72
        date = "2026-10-09"
        reference = "https://docs.specterops.io/mythic-agents/poseidon-docs/commands/jxa"
    strings:
        $o = "ObjC.import(" ascii
        $t = /\$\.NSTask|NSTask\.alloc/ ascii
        $b = "initWithBase64EncodedString" ascii
        $e = /(eval|new Function)\s*\(/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 128KB and
        $o and $t and $b and $e
}

rule CERBER_Gen_C2_Sliver_MachO_Protobuf {
    meta:
        description = "Sliver C2 implant (Mach-O): embedded protobuf package and message names of the implant RPC"
        author = "Cerber (gen)"
        family = "Sliver"
        severity = "critical"
        score = 80
        date = "2026-10-09"
        reference = "https://github.com/BishopFox/sliver"
        reference2 = "https://www.sentinelone.com/blog/from-the-front-lines-new-macos-covid-malware-masquerades-as-apple-wears-face-of-apt/"
    strings:
        $p = "github.com/bishopfox/sliver/protobuf/sliverpbb." ascii
        $s1 = ".PortfwdProtocol" ascii
        $s2 = ".WGTCPForwarder" ascii
        $s3 = ".PivotEntryR" ascii
        $s4 = ".WGSocksServerR" ascii
    condition:
        ((uint32(0) == 0xfeedfacf) or (uint32(0) == 0xfeedface) or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and
        filesize < 60MB and $p and 1 of ($s*)
}

rule CERBER_Gen_C2_Sliver_Covid_Softwareupdated_Persistence {
    meta:
        description = "Sliver implant disguised as Apple softwareupdated under a hidden ~/.androids directory with LaunchAgent persistence"
        author = "Cerber (gen)"
        family = "Sliver_Covid"
        severity = "critical"
        score = 90
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/from-the-front-lines-new-macos-covid-malware-masquerades-as-apple-wears-face-of-apt/"
    strings:
        $a = "/.androids/softwareupdated" ascii
        $b = "LaunchAgents/com.apple.softwareupdate.plist" ascii
        $d = "NSCreateObjectFileImageFromMemory" ascii
    condition:
        (((uint32(0) == 0xfeedfacf) or (uint32(0) == 0xfeedface) or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) or
         (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127))) and
        filesize < 64MB and $a and 1 of ($b, $d)
}

rule CERBER_Gen_C2_GoMachO_InMemory_Module_Loader {
    meta:
        description = "Go Mach-O that loads a second Mach-O bundle from memory via NSCreateObjectFileImageFromMemory and NSLinkModule (covid-style second stage)"
        author = "Cerber (gen)"
        family = "InMemory_Loader"
        severity = "high"
        score = 70
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/from-the-front-lines-new-macos-covid-malware-masquerades-as-apple-wears-face-of-apt/"
    strings:
        $n1 = "NSCreateObjectFileImageFromMemory" ascii
        $n2 = "NSLinkModule" ascii
        $g = "Go build ID" ascii
    condition:
        ((uint32(0) == 0xfeedfacf) or (uint32(0) == 0xfeedface) or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and
        filesize < 40MB and $n1 and $n2 and $g
}

rule CERBER_Gen_C2_Geacon_Pro_MachO {
    meta:
        description = "Geacon / Geacon_Pro (Go Cobalt Strike beacon) Mach-O build: geacon_pro source marker plus firstblood beacon marker"
        author = "Cerber (gen)"
        family = "Geacon"
        severity = "critical"
        score = 76
        date = "2026-10-09"
        reference = "https://hunt.io/blog/geacon-and-geacon-pro-a-constant-menace-to-linux-and-windows-systems"
    strings:
        $a = "geacon_pro" ascii
        $b = "firstblood" ascii
    condition:
        ((uint32(0) == 0xfeedfacf) or (uint32(0) == 0xfeedface) or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and
        filesize < 40MB and $a and $b
}

rule CERBER_Gen_C2_Python_InMemory_Exec_Loader {
    meta:
        description = "Python script that executes a decoded or decompressed blob and fetches or opens a socket to obtain it (in-memory loader)"
        author = "Cerber (gen)"
        family = "Python_Loader"
        severity = "high"
        score = 66
        date = "2026-10-09"
        reference = "https://docs.specterops.io/mythic-agents/poseidon-docs/home"
    strings:
        $e1 = /exec\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads)\(/ ascii
        $n1 = /urllib\.request\.urlopen|requests\.get\(|socket\.socket\(/ ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and $e1 and $n1
}

rule CERBER_Gen_C2_GoMachO_OSAScript_JXA {
    meta:
        description = "Go Mach-O that drives JavaScript for Automation through OSAScript executeAndReturnError (Poseidon jxa command shape)"
        author = "Cerber (gen)"
        family = "Poseidon_JXA"
        severity = "high"
        score = 68
        date = "2026-10-09"
        reference = "https://docs.specterops.io/mythic-agents/poseidon-docs/commands/jxa"
    strings:
        $o = "OSAScript" ascii
        $e = "executeAndReturnError" ascii
        $g = "Go build ID" ascii
    condition:
        ((uint32(0) == 0xfeedfacf) or (uint32(0) == 0xfeedface) or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and
        filesize < 40MB and $o and $e and $g
}

/*
 * Cerber – reguły własne (dprk), napisane 2026-10-09 przez agentów na podstawie publicznych raportów.
 * Warstwa "community": same nie dają werdyktu ZŁOŚLIWY. Zero trafień na ~2800 czystych plikach macOS
 * (programy z /Applications i /System, /usr/bin, LaunchAgents, rozszerzenia VS Code, node_modules).
 */

/*
 * CERBER - North Korean (Lazarus / BlueNoroff / Famous Chollima) macOS rules, staging pack
 *
 * Generated: 2026-10-09 | author: Cerber (gen)
 * Every rule: TYPE GATE (Mach-O magic or text first 8 bytes), explicit SIZE LIMIT,
 * several indicators from published reports. Strings are copied from the references in meta.
 * Score >= 75 = family/IOC-exact, < 75 = behavioural.
 */

// ============================================================================
// FLEXIBLEFERRET - "versus.pkg" / InstallerAlert.app Zoom-themed dropper (Jamf/SentinelOne 2025)
// ============================================================================
rule CERBER_Gen_DPRK_FlexibleFerret_Versus_Installer {
    meta:
        description = "FlexibleFerret Zoom-themed installer: postinstall.sh staging InstallerAlert.app and zoom into /var/tmp, Mac-Installer bundle IDs, versus.pkg name, revoked signing identifiers"
        author = "Cerber (gen)"
        family = "FlexibleFerret"
        severity = "critical"
        score = 90
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/macos-flexibleferret-further-variants-of-dprk-malware-family-unearthed/"
    strings:
        $p1 = "/var/tmp/InstallerAlert.app" ascii
        $p2 = "/var/tmp/zoom" ascii
        $p3 = "postinstall.log" ascii
        $b1 = "Mac-Installer.InstallerAlert" ascii
        $b2 = "Mac-Installer.AlertMsg" ascii
        $n1 = "versus.pkg" ascii
        $n2 = "versus.app" ascii
        $t1 = "58CD8AD5Z4" ascii
        $t2 = "VFYPGAKSLY" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or
         ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 256KB)) and
        (2 of ($p*, $b*, $n*) or ($t1 and 1 of ($p*, $b*, $n*)) or ($t2 and 1 of ($p*, $b*, $n*)))
}

rule CERBER_Gen_DPRK_FlexibleFerret_Zoom_Callservice {
    meta:
        description = "FlexibleFerret fake-Zoom C2 and LaunchAgent: zoom.callservice.us, com.zoom.plist, /var/tmp/zoom payload path"
        author = "Cerber (gen)"
        family = "FlexibleFerret"
        severity = "critical"
        score = 85
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/macos-flexibleferret-further-variants-of-dprk-malware-family-unearthed/"
    strings:
        $z = "zoom.callservice.us" ascii nocase
        $p = "com.zoom.plist" ascii
        $v = "/var/tmp/zoom" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or
         ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 256KB)) and
        2 of ($z, $p, $v)
}

// ============================================================================
// FROSTYFERRET / FRIENDLYFERRET (Ferret family code names, XProtect-named components)
// ============================================================================
rule CERBER_Gen_DPRK_FrostyFerret_VCam_CameraAccess {
    meta:
        description = "FrostyFerret component code names and VCam/CameraAccess payload archive names (fake camera driver lure)"
        author = "Cerber (gen)"
        family = "FrostyFerret"
        severity = "critical"
        score = 90
        date = "2026-10-09"
        reference = "https://www.sentinelone.com/blog/macos-flexibleferret-further-variants-of-dprk-malware-family-unearthed/"
    strings:
        $c1 = "FROSTYFERRET_UI" ascii
        $c2 = "FRIENDLYFERRET_SECD" ascii
        $c3 = "MULTI_FROSTYFERRET_CMDCODES" ascii
        $z1 = "VCam_ARM64.zip" ascii
        $z2 = "VCam_x86_64.zip" ascii
        $z3 = "CameraAccess.zip" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or
         ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 256KB)) and
        (2 of ($c*) or (1 of ($c*) and 1 of ($z*)))
}

// ============================================================================
// MACH-O MAN (Lazarus Chollima Go kit, Bitso Quetzal / ANY.RUN, Apr 2026)
// ============================================================================
rule CERBER_Gen_DPRK_MachOMan_macrasv2 {
    meta:
        description = "Mach-O Man Go stealer (macrasv2): Telegram Bot API exfiltration with the stealer binary name or published C2 IPs"
        author = "Cerber (gen)"
        family = "MachOMan"
        severity = "critical"
        score = 92
        date = "2026-10-09"
        reference = "https://threatcluster.io/article/mach-7ca89085"
    strings:
        $m1 = "macrasv2" ascii
        $t1 = "api.telegram.org/bot" ascii
        $i1 = "172.86.113.102" ascii
        $i2 = "144.172.114.220" ascii
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 32MB and
        (($m1 and ($t1 or 1 of ($i*))) or 2 of ($i*))
}

// ============================================================================
// MAGIC DISK CLEANER trojanised installer (Contagious Interview, Jamf 2025)
// ============================================================================
rule CERBER_Gen_DPRK_MagicDiskCleaner_Trojan {
    meta:
        description = "Trojanised Magic Disk Cleaner / Mac utility installer (Contagious Interview): .macos payload path, /task/tokenlinux poll, tokenlinux.sh, is_vmware_mac check, origToken JWT field"
        author = "Cerber (gen)"
        family = "ContagiousInterview"
        severity = "critical"
        score = 88
        date = "2026-10-09"
        reference = "https://www.jamf.com/blog/contagious-interview-trojanized-macos-installers/"
    strings:
        $a = "Magic Disk Cleaner.app/Contents/MacOS/.macos" ascii
        $b = "/task/tokenlinux" ascii
        $c = "tokenlinux.sh" ascii
        $d = "/task/mac" ascii
        $e = "is_vmware_mac" ascii
        $f = "origToken" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or
         ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 2MB)) and
        ($a or ($b and 1 of ($c, $e, $f)) or ($e and $f and $d))
}

// ============================================================================
// OTTERCANDY / W3PI infrastructure (NTT Security, Jamf 2025)
// ============================================================================
rule CERBER_Gen_DPRK_OtterCandy_W3PI_Infra {
    meta:
        description = "OtterCandy / Contagious Interview C2 infrastructure: w3pi.social, softcus.net, pobelstudio, kikaiverse, lalitae and published 162.0.239.x hosts"
        author = "Cerber (gen)"
        family = "OtterCandy"
        severity = "critical"
        score = 88
        date = "2026-10-09"
        reference = "https://jp.security.ntt/insights_resources/tech_blog/ottercandy_malware_e/"
    strings:
        $d1 = "w3pi.social" ascii nocase
        $d2 = "softcus.net" ascii nocase
        $d3 = "pobelstudio.com" ascii nocase
        $d4 = "pobel.studio" ascii nocase
        $d5 = "kikaiverse.com" ascii nocase
        $d6 = "lalitae.com" ascii nocase
        $i1 = "162.0.239.85" ascii
        $i2 = "162.0.239.89" ascii
    condition:
        (((uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or (uint32be(0) == 0xcafebabe and uint32be(4) < 20)) and filesize < 24MB) or
         ((for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 2MB)) and
        (2 of ($d*, $i*) or ($d1 and 1 of ($i*)))
}

// ============================================================================
// REF9403 - fake coding-interview Next.js repos, SVG steganography (Elastic Security Labs)
// ============================================================================
rule CERBER_Gen_DPRK_REF9403_SVG_Stego_Stealer {
    meta:
        description = "REF9403 Contagious Interview Node.js project: rightwidth.dev C2, /api/service/makelog and /cldbs upload paths, CLDBS directory, GreatStackDev/gocart template"
        author = "Cerber (gen)"
        family = "BeaverTail"
        severity = "critical"
        score = 92
        date = "2026-10-09"
        reference = "https://www.elastic.co/security-labs/threat-command/contagious-interview-malware-svg-steganography"
    strings:
        $c1 = "rightwidth.dev" ascii nocase
        $r = "REF9403" ascii
        $e1 = "/api/service/makelog" ascii
        $e2 = "/api/service/process/" ascii
        $e3 = "/cldbs" ascii
        $f = "CLDBS" ascii
        $g = "GreatStackDev" ascii
        $n = "npm-cache" ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 2MB and
        ((($c1 or $r) and 1 of ($e*, $f, $g)) or 3 of ($e*, $f, $g, $n))
}

// ============================================================================
// Contagious Interview stealer: crypto-wallet extension IDs + keychain path (Elastic REF9403 appendix)
// ============================================================================
rule CERBER_Gen_DPRK_Contagious_Wallet_Keychain_Stealer {
    meta:
        description = "Node.js browser/wallet stealer: multiple crypto-wallet extension IDs plus macOS login keychain and Local Extension Settings paths"
        author = "Cerber (gen)"
        family = "BeaverTail"
        severity = "critical"
        score = 85
        date = "2026-10-09"
        reference = "https://www.elastic.co/security-labs/threat-command/contagious-interview-malware-svg-steganography"
    strings:
        $w1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
        $w2 = "acmacodkjbdgmoleebolmdjonilkdbch" ascii
        $w3 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii
        $w4 = "dmkamcknogkgcdfhhbddcghachkejeap" ascii
        $w5 = "ppbibelpcjmhbdihakflkdcoccbgbkpo" ascii
        $w6 = "egjidjbpglichdcondbcbdnbeeppgdph" ascii
        $w7 = "ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii
        $w8 = "bhhhlbepdkbapadjdnnojkbgioiodbic" ascii
        $w9 = "mcohilncbfahbmgdjkbpemcciiolgcge" ascii
        $w10 = "aholpfdialjgjfhomihkjbmgjidlcdno" ascii
        $kc = "/Library/Keychains/login.keychain-db" ascii
        $les = "Local Extension Settings" ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 2MB and
        (7 of ($w*) or (4 of ($w*) and $kc and $les))
}

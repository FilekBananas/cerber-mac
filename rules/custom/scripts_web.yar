// Cerber - malicious scripts, web and document-macro detection pack
// Author: Cerber | Date: 2026-09-29
// Scope: PowerShell, batch, VBS/JS/HTA/WSF, bash, Python, Node/npm, PHP/ASP/JSP webshells,
//        HTML smuggling, phishing kits, ClickFix, cryptojacking, VBA/XLM macros, .reg droppers.
// Every rule combines several distinctive indicators, a filesize limit and a not-native-executable gate.

rule CERBER_Script_PowerShell_Base64Wide_PayloadStems {
    meta:
        description = "Base64 of UTF-16 PowerShell text containing several download, injection or reflection keywords"
        author = "Cerber"
        family = "PowerShell.EncodedPayload"
        severity = "critical"
        score = 82
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
    strings:
        $a = "Net.WebClient" wide base64
        $b = "DownloadString" wide base64
        $c = "DownloadFile" wide base64
        $d = "Invoke-Expression" wide base64
        $e = "FromBase64String" wide base64
        $f = "Reflection.Assembly" wide base64
        $g = "VirtualAlloc" wide base64
        $h = "Invoke-WebRequest" wide base64
        $i = "IO.Compression.DeflateStream" wide base64
        $j = "Set-MpPreference" wide base64
        $k = "AmsiUtils" wide base64
    condition:
        filesize < 5MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 2 of them
}

rule CERBER_Script_PowerShell_HiddenEncodedLauncher {
    meta:
        description = "powershell.exe started with hidden window, bypass or noprofile flags and a long base64 -EncodedCommand blob"
        author = "Cerber"
        family = "PowerShell.Launcher"
        severity = "high"
        score = 65
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
    strings:
        $ps = /powershell(\.exe)?["']?[ \t]{1,4}[^\r\n]{0,140}[ \t]-e[a-z]{0,15}[ \t]{1,4}["']?[A-Za-z0-9+\/]{80,}/ nocase wide ascii
        $h1 = /[ \t]-w(in|indow|indowstyle)?[ \t]{1,4}(h(idden)?|1)\b/ nocase wide ascii
        $h2 = /[ \t]-(nop|noprofile|noni|noninteractive)\b/ nocase wide ascii
        $h3 = /[ \t]-(ep|exec|executionpolicy)[ \t]{1,4}bypass/ nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $ps and 2 of ($h*)
}

rule CERBER_Script_PowerShell_WebClientCradle_HiddenWindow {
    meta:
        description = "Net.WebClient or Invoke-WebRequest download-and-execute cradle launched with a hidden window"
        author = "Cerber"
        family = "PowerShell.DownloadCradle"
        severity = "high"
        score = 68
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $c1 = /\(\s*New-Object\s+(System\.)?Net\.WebClient\s*\)\s*\.\s*Download(String|File|Data)\s*\(/ nocase wide ascii
        $c2 = /\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\r\n]{0,200}\|\s*(iex|Invoke-Expression)\b/ nocase wide ascii
        $c3 = /(iex|Invoke-Expression)\s*\(?\s*\(?\s*New-Object\s+(System\.)?Net\.WebClient/ nocase wide ascii
        $hw = /[ \t]-w(in|indow|indowstyle)?[ \t]{1,4}(h(idden)?|1)\b/ nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of ($c*) and $hw
}

rule CERBER_Script_PowerShell_WebClientCradle_PasteSiteHost {
    meta:
        description = "PowerShell download-and-execute cradle that pulls from paste sites, chat CDNs, dynamic DNS or tunnelling hosts"
        author = "Cerber"
        family = "PowerShell.DownloadCradle"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $c1 = /\(\s*New-Object\s+(System\.)?Net\.WebClient\s*\)\s*\.\s*Download(String|File|Data)\s*\(/ nocase wide ascii
        $c2 = /\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\r\n]{0,200}\|\s*(iex|Invoke-Expression)\b/ nocase wide ascii
        $c3 = /(iex|Invoke-Expression)\s*\(?\s*\(?\s*New-Object\s+(System\.)?Net\.WebClient/ nocase wide ascii
        $h1 = "pastebin.com/raw" nocase wide ascii
        $h2 = "paste.ee/r/" nocase wide ascii
        $h3 = "hastebin.com/raw" nocase wide ascii
        $h4 = "cdn.discordapp.com/attachments" nocase wide ascii
        $h5 = "transfer.sh/" nocase wide ascii
        $h6 = "anonfiles" nocase wide ascii
        $h7 = "catbox.moe" nocase wide ascii
        $h8 = ".duckdns.org" nocase wide ascii
        $h9 = ".ngrok.io" nocase wide ascii
        $h10 = ".trycloudflare.com" nocase wide ascii
        $h11 = ".hopto.org" nocase wide ascii
        $h12 = ".zapto.org" nocase wide ascii
        $h13 = "ghostbin" nocase wide ascii
        $h14 = "controlc.com" nocase wide ascii
        $h15 = "bit.ly/" nocase wide ascii
        $h16 = "temp.sh/" nocase wide ascii
        $h17 = ".ddns.net" nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of ($c*) and 1 of ($h*)
}

rule CERBER_Script_PowerShell_WebClientCradle_RawIP {
    meta:
        description = "PowerShell download cradle whose URL is a bare IPv4 address"
        author = "Cerber"
        family = "PowerShell.DownloadCradle"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $c1 = /\(\s*New-Object\s+(System\.)?Net\.WebClient\s*\)\s*\.\s*Download(String|File|Data)\s*\(\s*["']https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:\/]/ nocase wide ascii
        $c2 = /\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\r\n]{0,40}["']https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:\/][^\r\n]{0,120}\|\s*(iex|Invoke-Expression)\b/ nocase wide ascii
        $x = /(iex|Invoke-Expression)/ nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($c1 and $x or $c2)
}

rule CERBER_Script_PowerShell_WebClientCradle_SplitStrings {
    meta:
        description = "Net.WebClient or DownloadString names split with string concatenation to dodge signatures"
        author = "Cerber"
        family = "PowerShell.ObfuscatedCradle"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a1 = /['"]Net\.We['"]\s*\+\s*['"]bClient/ nocase wide ascii
        $a2 = /['"]Net\.['"]\s*\+\s*['"]WebClient/ nocase wide ascii
        $a3 = /['"]Net\.WebC['"]\s*\+\s*['"]lient/ nocase wide ascii
        $a4 = /['"]System\.Net\.W['"]\s*\+\s*['"]ebClient/ nocase wide ascii
        $b1 = /['"]Download['"]\s*\+\s*['"]String/ nocase wide ascii
        $b2 = /['"]Downl['"]\s*\+\s*['"]oadString/ nocase wide ascii
        $b3 = /['"]DownloadS['"]\s*\+\s*['"]tring/ nocase wide ascii
        $b4 = /['"]DownloadF['"]\s*\+\s*['"]ile/ nocase wide ascii
        $b5 = /['"]Do['"]\s*\+\s*['"]wnloadString/ nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of ($a*) and 1 of ($b*)
}

rule CERBER_Script_PowerShell_XmlHttpCradle {
    meta:
        description = "PowerShell fetching a script through a COM HTTP object and executing it"
        author = "Cerber"
        family = "PowerShell.DownloadCradle"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $b = /New-Object\s+-ComObject\s+["']?(Msxml2\.(Server)?XMLHTTP|WinHttp\.WinHttpRequest\.5\.1)/ nocase wide ascii
        $c = /\.(responseText|ResponseText)\b/ wide ascii
        $x = /(iex|Invoke-Expression)\s*[\(\$]/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $b and $c and $x
}

rule CERBER_Script_PowerShell_BitsTransfer_DownloadExecute {
    meta:
        description = "Start-BitsTransfer download into a user-writable folder followed by immediate launch"
        author = "Cerber"
        family = "PowerShell.Dropper"
        severity = "medium"
        score = 60
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1197/"
    strings:
        $a = /Start-BitsTransfer\s[^\r\n]{0,120}-Source\s+["']?https?:\/\// nocase wide ascii
        $b = /-Destination\s+["']?\$env:(TEMP|APPDATA|PUBLIC|LOCALAPPDATA)/ nocase wide ascii
        $c = /(Start-Process|Invoke-Item|&)\s*["']?\$env:(TEMP|APPDATA|PUBLIC|LOCALAPPDATA)[^\r\n]{0,60}\.(exe|scr|bat|vbs|js|msi|ps1)/ nocase wide ascii
        $h = /-w(in|indow|indowstyle)?[ \t]{1,4}(h(idden)?|1)\b/ nocase wide ascii
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $h
}

rule CERBER_Script_PowerShell_DownloadFile_TempExec_Hidden {
    meta:
        description = "DownloadFile into TEMP/APPDATA then Start-Process of the same dropped binary with hidden window"
        author = "Cerber"
        family = "PowerShell.Dropper"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = /Download(File|FileAsync)\s*\(\s*["']https?:\/\/[^\r\n"']{4,200}["']\s*,\s*["']?(\$env:(TEMP|APPDATA|PUBLIC|LOCALAPPDATA)|\$\{env:(TEMP|APPDATA)\}|%(TEMP|APPDATA)%)/ nocase wide ascii
        $b = /(Start-Process|Invoke-Item|Invoke-Expression|iex|&)[^\r\n]{0,40}(\$env:(TEMP|APPDATA|PUBLIC|LOCALAPPDATA)|%(TEMP|APPDATA)%)[^\r\n]{0,60}\.(exe|scr|bat|vbs|js|msi|dll)/ nocase wide ascii
        $h = /(-w(in|indow|indowstyle)?[ \t]{1,4}(h(idden)?|1)\b|-WindowStyle\s+Hidden|CreateNoWindow)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $h
}

rule CERBER_Script_PowerShell_AmsiBypass_InitFailed {
    meta:
        description = "Classic AmsiUtils amsiInitFailed reflection bypass"
        author = "Cerber"
        family = "PowerShell.AmsiBypass"
        severity = "critical"
        score = 92
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a = "amsiInitFailed" nocase wide ascii
        $b = "System.Management.Automation.AmsiUtils" nocase wide ascii
        $c = "NonPublic,Static" nocase wide ascii
        $d = "SetValue($null,$true)" nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and 1 of ($b, $c, $d) 
}

rule CERBER_Script_PowerShell_AmsiBypass_StringSplit {
    meta:
        description = "AMSI class or field names split by concatenation or format operators to evade static detection"
        author = "Cerber"
        family = "PowerShell.AmsiBypass"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a1 = /['"]ams['"]\s*\+\s*['"]iInitFailed/ nocase wide ascii
        $a2 = /['"]amsiIn['"]\s*\+\s*['"]itFailed/ nocase wide ascii
        $a3 = /['"]amsiInit['"]\s*\+\s*['"]Failed/ nocase wide ascii
        $a4 = /['"]Am['"]\s*\+\s*['"]siUtils/ nocase wide ascii
        $a5 = /Automation\.A['"]\s*\+\s*['"]msiUtils/ nocase wide ascii
        $a6 = /Automation\.Am['"]\s*\+\s*['"]siUtils/ nocase wide ascii
        $a7 = /['"]amsi['"]\s*\+\s*['"]Context/ nocase wide ascii
        $a8 = /['"]Amsi['"]\s*\+\s*['"]Utils/ nocase wide ascii
        $a9 = /AmsiU['"]\s*\+\s*['"]tils/ nocase wide ascii
        $g = /GetField\s*\(/ nocase wide ascii
        $s = /SetValue\s*\(/ nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of ($a*) and $g and $s
}

rule CERBER_Script_PowerShell_AmsiBypass_MemoryPatch {
    meta:
        description = "Patching AmsiScanBuffer or AmsiOpenSession in memory using the well-known mov eax,0x80070057 ; ret byte sequence"
        author = "Cerber"
        family = "PowerShell.AmsiBypass"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $p1 = /0x[Bb]8\s*,\s*0x57\s*,\s*0x00\s*,\s*0x07\s*,\s*0x80\s*,\s*0x[Cc]3/ wide ascii
        $p2 = /\b184\s*,\s*87\s*,\s*0\s*,\s*7\s*,\s*128\s*,\s*195\b/ wide ascii
        $p3 = /\\xb8\\x57\\x00\\x07\\x80\\xc3/ nocase wide ascii
        $n1 = "AmsiScanBuffer" nocase wide ascii
        $n2 = "AmsiOpenSession" nocase wide ascii
        $n3 = "amsi.dll" nocase wide ascii
        $v = "VirtualProtect" nocase wide ascii
        $m = /Marshal\]?::Copy|WriteProcessMemory|Marshal\.Copy/ nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of ($p*) and 1 of ($n*) and ($v or $m)
}

rule CERBER_Script_PowerShell_AmsiBypass_ContextCorruption {
    meta:
        description = "Reflection based corruption of amsiContext or amsiSession pointer inside System.Management.Automation"
        author = "Cerber"
        family = "PowerShell.AmsiBypass"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a = "amsiContext" nocase wide ascii
        $b = "amsiSession" nocase wide ascii
        $c = /GetField\s*\(\s*["'](amsiContext|amsiSession)["']\s*,\s*["']NonPublic/ nocase wide ascii
        $d = /Marshal\]?::(WriteInt32|WriteInt64|AllocHGlobal)/ nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $c and ($d or $b) and $a
}

rule CERBER_Script_PowerShell_AmsiProviderRemoval {
    meta:
        description = "Deleting the Defender AMSI provider registration so script content is no longer scanned"
        author = "Cerber"
        family = "PowerShell.AmsiBypass"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a = "Microsoft\\AMSI\\Providers" nocase wide ascii
        $b = "{2781761E-28E0-4109-99FE-B9D127C57AFE}" nocase wide ascii
        $c = /(Remove-Item|reg\s+delete|Remove-ItemProperty|Clear-Item)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_PowerShell_EtwPatch_PSEtwLogProvider {
    meta:
        description = "Disabling PowerShell ETW tracing by flipping m_enabled on PSEtwLogProvider"
        author = "Cerber"
        family = "PowerShell.EtwBypass"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/006/"
    strings:
        $a = "PSEtwLogProvider" nocase wide ascii
        $b = "etwProvider" nocase wide ascii
        $c = "m_enabled" nocase wide ascii
        $d = "EventProvider" nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_PowerShell_EtwPatch_EtwEventWrite {
    meta:
        description = "Patching ntdll EtwEventWrite with a return stub from a PowerShell or C# inline loader"
        author = "Cerber"
        family = "PowerShell.EtwBypass"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/006/"
    strings:
        $a = "EtwEventWrite" nocase wide ascii
        $b = "ntdll" nocase wide ascii
        $c = "VirtualProtect" nocase wide ascii
        $d = /0xc3|\\xc3|0xC3/ wide ascii
        $e = "Add-Type" nocase wide ascii
        $f = "GetProcAddress" nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and ($e or $f)
}

rule CERBER_Script_PowerShell_ScriptBlockLoggingBypass {
    meta:
        description = "Overwriting cached group policy settings to switch off ScriptBlock and module logging"
        author = "Cerber"
        family = "PowerShell.LoggingBypass"
        severity = "high"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a = "cachedGroupPolicySettings" nocase wide ascii
        $b = "EnableScriptBlockLogging" nocase wide ascii
        $c = "System.Management.Automation.Utils" nocase wide ascii
        $d = "NonPublic,Static" nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and ($c or $d)
}

rule CERBER_Script_PowerShell_DefenderDisable_SetMpPreference {
    meta:
        description = "Set-MpPreference call switching off several Microsoft Defender protections"
        author = "Cerber"
        family = "PowerShell.DefenderTamper"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $s = "Set-MpPreference" nocase wide ascii
        $f1 = /-DisableRealtimeMonitoring\s+(\$true|1)/ nocase wide ascii
        $f2 = /-DisableIOAVProtection\s+(\$true|1)/ nocase wide ascii
        $f3 = /-DisableBehaviorMonitoring\s+(\$true|1)/ nocase wide ascii
        $f4 = /-DisableScriptScanning\s+(\$true|1)/ nocase wide ascii
        $f5 = /-DisableBlockAtFirstSeen\s+(\$true|1)/ nocase wide ascii
        $f6 = /-DisablePrivacyMode\s+(\$true|1)/ nocase wide ascii
        $f7 = /-MAPSReporting\s+(0|Disabled)/ nocase wide ascii
        $f8 = /-SubmitSamplesConsent\s+(2|NeverSend)/ nocase wide ascii
        $f9 = /-DisableArchiveScanning\s+(\$true|1)/ nocase wide ascii
        $f10 = /-DisableIntrusionPreventionSystem\s+(\$true|1)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $s and 2 of ($f*)
}

rule CERBER_Script_PowerShell_DefenderExclusion_Abuse {
    meta:
        description = "Add-MpPreference exclusion for a whole drive, executable extension, or scripting host"
        author = "Cerber"
        family = "PowerShell.DefenderTamper"
        severity = "high"
        score = 68
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a = /Add-MpPreference\s[^\r\n]{0,60}-Exclusion(Path|Extension|Process)\s+["']?(C:\\["']?(\s|,|;|$)|\.exe|\.dll|\.ps1|powershell(\.exe)?|cmd\.exe|wscript|mshta|rundll32|\$env:(TEMP|PUBLIC))/ nocase wide ascii
        $b = /-Exclusion(Path|Extension|Process)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and #b >= 1
}

rule CERBER_Script_Batch_DefenderService_Stop {
    meta:
        description = "Stopping, deleting or disabling the WinDefend service or Defender drivers from a script"
        author = "Cerber"
        family = "Windows.DefenderTamper"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a1 = /sc(\.exe)?\s+(stop|delete)\s+(WinDefend|WdNisSvc|WdFilter|WdBoot|Sense)\b/ nocase wide ascii
        $a2 = /sc(\.exe)?\s+config\s+(WinDefend|WdNisSvc|WdFilter|WdBoot|Sense)\s+start\s*=\s*(disabled|4)/ nocase wide ascii
        $a3 = /net(\.exe)?\s+stop\s+["']?(WinDefend|Windows Defender Antivirus Service)/ nocase wide ascii
        $a4 = /(Stop-Service|Set-Service)\s+[^\r\n]{0,30}(WinDefend|WdNisSvc)/ nocase wide ascii
        $a5 = /Uninstall-WindowsFeature\s+[^\r\n]{0,20}Windows-Defender/ nocase wide ascii
        $b = /(taskkill|Stop-Process)[^\r\n]{0,40}(MsMpEng|MpCmdRun|NisSrv|SecurityHealthService)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (2 of ($a*) or ($b and 1 of ($a*)))
}

rule CERBER_Script_Reg_DefenderPolicy_Disable {
    meta:
        description = "Registry values that switch off Microsoft Defender anti-spyware and real-time protection"
        author = "Cerber"
        family = "Windows.DefenderTamper"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a = "DisableAntiSpyware" nocase wide ascii
        $b = "DisableRealtimeMonitoring" nocase wide ascii
        $c = "DisableBehaviorMonitoring" nocase wide ascii
        $d = "DisableOnAccessProtection" nocase wide ascii
        $e = "DisableScanOnRealtimeEnable" nocase wide ascii
        $f = /Windows Defender/ nocase wide ascii
        $v = /(dword:00000001|\/d\s+1\b|-Value\s+1\b|0x00000001)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $f and $v and $a and 2 of ($b, $c, $d, $e)
}

rule CERBER_Script_Batch_MpCmdRun_RemoveDefinitions {
    meta:
        description = "MpCmdRun used to wipe every Defender signature definition"
        author = "Cerber"
        family = "Windows.DefenderTamper"
        severity = "high"
        score = 65
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a = /MpCmdRun(\.exe)?["']?\s+-RemoveDefinitions\s+-All/ nocase wide ascii
        $b = /MpCmdRun(\.exe)?["']?\s+-RemoveDefinitions\s+-DynamicSignatures/ nocase wide ascii
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or $b)
}

rule CERBER_Script_Reg_SecurityCenterNotifications_Off {
    meta:
        description = "Registry changes suppressing Windows Security Center antivirus, firewall and update warnings"
        author = "Cerber"
        family = "Windows.SecurityTamper"
        severity = "medium"
        score = 65
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a = "AntiVirusDisableNotify" nocase wide ascii
        $b = "FirewallDisableNotify" nocase wide ascii
        $c = "UpdatesDisableNotify" nocase wide ascii
        $d = "AntiVirusOverride" nocase wide ascii
        $e = "FirewallOverride" nocase wide ascii
        $f = "UpdatesOverride" nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 3 of them
}

rule CERBER_Script_Batch_UacWeakening_Registry {
    meta:
        description = "Commands or registry entries that switch UAC and remote token filtering off"
        author = "Cerber"
        family = "Windows.SecurityTamper"
        severity = "medium"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a = /EnableLUA["']?[ ]+(\/t[ ]+REG_DWORD[ ]+)?\/d[ ]+0\b/ nocase wide ascii
        $b = /ConsentPromptBehaviorAdmin["']?[ ]+(\/t[ ]+REG_DWORD[ ]+)?\/d[ ]+0\b/ nocase wide ascii
        $c = /LocalAccountTokenFilterPolicy["']?[ ]+(\/t[ ]+REG_DWORD[ ]+)?\/d[ ]+1\b/ nocase wide ascii
        $d = /"EnableLUA"=dword:00000000/ nocase wide ascii
        $e = /"ConsentPromptBehaviorAdmin"=dword:00000000/ nocase wide ascii
        $f = /"LocalAccountTokenFilterPolicy"=dword:00000001/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 2 of them
}

rule CERBER_Script_Reg_WDigest_UseLogonCredential {
    meta:
        description = "Enabling WDigest cleartext credential caching in LSASS"
        author = "Cerber"
        family = "Windows.CredentialAccess"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1003/001/"
    strings:
        $a = "UseLogonCredential" nocase wide ascii
        $b = "WDigest" nocase wide ascii
        $v = /(dword:00000001|\/d\s+1\b|-Value\s+1\b|0x00000001|\/d\s+0x1\b)/ nocase wide ascii
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $v
}

rule CERBER_Script_PowerShell_InvokeMimikatz {
    meta:
        description = "Invoke-Mimikatz reflective loader with mimikatz command strings"
        author = "Cerber"
        family = "PowerShell.Mimikatz"
        severity = "critical"
        score = 92
        date = "2026-09-29"
        reference = "https://github.com/PowerShellMafia/PowerSploit"
    strings:
        $a = "Invoke-Mimikatz" nocase wide ascii
        $b = "-DumpCreds" nocase wide ascii
        $c = "sekurlsa::logonpasswords" nocase wide ascii
        $d = "$PEBytes64" nocase wide ascii
        $e = "privilege::debug" nocase wide ascii
        $f = "-DumpCerts" nocase wide ascii
        $g = "lsadump::sam" nocase wide ascii
    condition:
        filesize < 8MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and 1 of ($b, $c, $d, $e, $f, $g) 
}

rule CERBER_Script_PowerShell_ReflectivePEInjection {
    meta:
        description = "PowerSploit Invoke-ReflectivePEInjection helper functions"
        author = "Cerber"
        family = "PowerShell.PowerSploit"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://github.com/PowerShellMafia/PowerSploit"
    strings:
        $a = "Invoke-ReflectivePEInjection" nocase wide ascii
        $b = "Import-DllInRemoteProcess" nocase wide ascii
        $c = "Update-MemoryAddresses" nocase wide ascii
        $d = "Add-SignedIntAsUnsigned" nocase wide ascii
        $e = "Get-ImageNtHeaders" nocase wide ascii
        $f = "Copy-ArrayOfMemAddresses" nocase wide ascii
        $g = "Invoke-MemoryLoadLibrary" nocase wide ascii
        $h = "Get-Win32Constants" nocase wide ascii
    condition:
        filesize < 8MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 3 of them 
}

rule CERBER_Script_PowerShell_InvokeShellcode_PowerSploit {
    meta:
        description = "PowerSploit Invoke-Shellcode injector with meterpreter payload options"
        author = "Cerber"
        family = "PowerShell.PowerSploit"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://github.com/PowerShellMafia/PowerSploit"
    strings:
        $a = "Invoke-Shellcode" nocase wide ascii
        $b = "Get-ProcAddress" nocase wide ascii
        $c = "Get-DelegateType" nocase wide ascii
        $d = "windows/meterpreter/reverse_https" nocase wide ascii
        $e = "windows/meterpreter/reverse_http" nocase wide ascii
        $f = "-Shellcode" nocase wide ascii
        $g = "Local:Get-DelegateType" nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and 2 of ($b, $c, $d, $e, $f, $g) 
}

rule CERBER_Script_PowerShell_PowerView_Recon {
    meta:
        description = "PowerView Active Directory reconnaissance functions used together"
        author = "Cerber"
        family = "PowerShell.PowerView"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://github.com/PowerShellMafia/PowerSploit"
        pua = true
    strings:
        $a1 = "Get-DomainController" nocase wide ascii
        $a2 = "Invoke-UserHunter" nocase wide ascii
        $a3 = "Find-LocalAdminAccess" nocase wide ascii
        $a4 = "Invoke-ShareFinder" nocase wide ascii
        $a5 = "Get-DomainGPOLocalGroup" nocase wide ascii
        $a6 = "Find-DomainUserLocation" nocase wide ascii
        $a7 = "Get-DomainObjectAcl" nocase wide ascii
        $a8 = "Invoke-ACLScanner" nocase wide ascii
        $a9 = "Get-NetDomainTrust" nocase wide ascii
        $a10 = "Get-DomainSID" nocase wide ascii
        $a11 = "Invoke-MapDomainTrust" nocase wide ascii
        $a12 = "Get-NetGPOGroup" nocase wide ascii
        $a13 = "Invoke-FileFinder" nocase wide ascii
        $a14 = "Get-DomainPolicyData" nocase wide ascii
        $a15 = "Find-DomainShare" nocase wide ascii
        $a16 = "Get-NetLoggedon" nocase wide ascii
    condition:
        filesize < 8MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 5 of them 
}

rule CERBER_Script_PowerShell_PowerUp_PrivescChecks {
    meta:
        description = "PowerUp Windows privilege escalation check functions used together"
        author = "Cerber"
        family = "PowerShell.PowerUp"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://github.com/PowerShellMafia/PowerSploit"
        pua = true
    strings:
        $a1 = "Invoke-AllChecks" nocase wide ascii
        $a2 = "Get-UnquotedService" nocase wide ascii
        $a3 = "Get-ModifiableServiceFile" nocase wide ascii
        $a4 = "Write-ServiceBinary" nocase wide ascii
        $a5 = "Find-PathDLLHijack" nocase wide ascii
        $a6 = "Get-RegistryAlwaysInstallElevated" nocase wide ascii
        $a7 = "Get-ModifiableRegistryAutoRun" nocase wide ascii
        $a8 = "Install-ServiceBinary" nocase wide ascii
        $a9 = "Invoke-ServiceAbuse" nocase wide ascii
        $a10 = "Get-ServiceUnquoted" nocase wide ascii
        $a11 = "Write-UserAddMSI" nocase wide ascii
        $a12 = "Get-ModifiableScheduledTaskFile" nocase wide ascii
    condition:
        filesize < 4MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 4 of them 
}

rule CERBER_Script_PowerShell_Kerberoast {
    meta:
        description = "Invoke-Kerberoast style service ticket request and hash export"
        author = "Cerber"
        family = "PowerShell.Kerberoast"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1558/003/"
        pua = true
    strings:
        $a = "Invoke-Kerberoast" nocase wide ascii
        $b = "KerberosRequestorSecurityToken" nocase wide ascii
        $c = "$krb5tgs$" nocase wide ascii
        $e = "Get-DomainSPNTicket" nocase wide ascii
        $f = "servicePrincipalName" nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ((($a or $e) and $b) or ($b and $c and $f))
}

rule CERBER_Script_PowerShell_BloodHound_Collector {
    meta:
        description = "BloodHound and SharpHound collector invocation with collection method options"
        author = "Cerber"
        family = "PowerShell.SharpHound"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://github.com/BloodHoundAD/BloodHound"
        pua = true
    strings:
        $a = "Invoke-BloodHound" nocase wide ascii
        $b = "SharpHound" nocase wide ascii
        $c = "-CollectionMethod" nocase wide ascii
        $d = "-ZipFileName" nocase wide ascii
        $e = "--CollectionMethods" nocase wide ascii
        $f = "LoggedOn" nocase wide ascii
        $g = "-NoSaveCache" nocase wide ascii
    condition:
        filesize < 8MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or $b) and $c and 1 of ($d, $e, $f, $g)
}

rule CERBER_Script_PowerShell_InvokeTheHash_Inveigh {
    meta:
        description = "Invoke-TheHash or Inveigh LLMNR/NBNS poisoning and pass-the-hash tooling"
        author = "Cerber"
        family = "PowerShell.Lateral"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
        pua = true
    strings:
        $a1 = "Invoke-SMBExec" nocase wide ascii
        $a2 = "Invoke-WMIExec" nocase wide ascii
        $a3 = "Invoke-SMBClient" nocase wide ascii
        $a4 = "Invoke-TheHash" nocase wide ascii
        $b1 = "Invoke-Inveigh" nocase wide ascii
        $b2 = "LLMNR" nocase wide ascii
        $b3 = "NBNS" nocase wide ascii
        $b4 = "Inveigh" nocase wide ascii
    condition:
        filesize < 4MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (3 of ($a*) or ($b1 and $b2 and $b3) or (#b4 > 5 and $b2))
}

rule CERBER_Script_PowerShell_GPPPassword_Extraction {
    meta:
        description = "Group Policy Preferences cpassword decryption using the published AES key"
        author = "Cerber"
        family = "PowerShell.CredentialAccess"
        severity = "high"
        score = 75
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1552/006/"
        pua = true
    strings:
        $a = "cpassword" nocase wide ascii
        $b = "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b" nocase wide ascii
        $c = /0x4e\s*,\s*0x99\s*,\s*0x06\s*,\s*0xe8\s*,\s*0xfc\s*,\s*0xb6\s*,\s*0x6c\s*,\s*0xc9/ nocase wide ascii
        $d = "Get-GPPPassword" nocase wide ascii
        $e = "Groups.xml" nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and 1 of ($b, $c, $d) and ($e or $d)
}

rule CERBER_Script_PowerShell_Nishang_Scripts {
    meta:
        description = "Nishang post-exploitation script header or reverse-shell function"
        author = "Cerber"
        family = "PowerShell.Nishang"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://github.com/samratashok/nishang"
        pua = true
    strings:
        $a = "github.com/samratashok/nishang" nocase wide ascii
        $b = "Invoke-PowerShellTcp" nocase wide ascii
        $c = "Invoke-PoshRatHttp" nocase wide ascii
        $d = "Invoke-Encode" nocase wide ascii
        $e = "Do-Exfiltration" nocase wide ascii
        $f = "Invoke-PowerShellUdp" nocase wide ascii
        $g = "Invoke-PsGcatAgent" nocase wide ascii
        $h = "Get-PassHashes" nocase wide ascii
        $i = "Invoke-BruteForce" nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or 2 of ($b, $c, $d, $e, $f, $g, $h, $i))
}

rule CERBER_Script_PowerShell_TcpClientReverseShell_OneLiner {
    meta:
        description = "The widespread TCPClient / GetStream / iex reverse shell loop with PS prompt echo"
        author = "Cerber"
        family = "PowerShell.ReverseShell"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = "System.Net.Sockets.TCPClient" nocase wide ascii
        $b = ".GetStream()" nocase wide ascii
        $c = /0\s*\.\.\s*65535\s*\|\s*%\s*\{\s*0\s*\}/ wide ascii
        $d = /(iex|Invoke-Expression)\s+["']?\$data|\(iex\s+\$data/ nocase wide ascii
        $e = "Out-String" nocase wide ascii
        $f = /\$sendback2?\s*=/ nocase wide ascii
        $g = /"PS "\s*\+\s*\(pwd\)\.Path/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and 2 of ($c, $d, $e, $f, $g)
}

rule CERBER_Script_PowerShell_TcpClientCmdRedirect_ReverseShell {
    meta:
        description = "PowerShell socket client wired to a hidden cmd.exe or powershell.exe process through redirected streams"
        author = "Cerber"
        family = "PowerShell.ReverseShell"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = "System.Net.Sockets.TCPClient" nocase wide ascii
        $b = "RedirectStandardOutput" nocase wide ascii
        $c = "RedirectStandardInput" nocase wide ascii
        $d = /(cmd|powershell)\.exe/ nocase wide ascii
        $e = "GetStream()" nocase wide ascii
        $f = "CreateNoWindow" nocase wide ascii
        $g = "UseShellExecute" nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $e and $b and $c and $d and ($f or $g)
}

rule CERBER_Script_PowerShell_Empire_Stager {
    meta:
        description = "PowerShell Empire launcher with RC4 decrypt loop or header-spoofing WebClient download"
        author = "Cerber"
        family = "PowerShell.Empire"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://github.com/BC-SECURITY/Empire"
    strings:
        $rc4 = /\$S\s*=\s*0\.\.255\s*;\s*0\.\.255\s*\|\s*%\s*\{\s*\$J\s*=\s*\(\s*\$J\s*\+\s*\$S\[\$_\]/ nocase wide ascii
        $rc4b = /\$_\s*-bxor\s*\$S\[\(\$S\[\$I\]\s*\+\s*\$S\[\$H\]\)\s*%\s*256\]/ nocase wide ascii
        $w1 = /\$wc\.Headers\.Add\(\s*["']User-Agent["']/ nocase wide ascii
        $w2 = "DefaultNetworkCredentials" nocase wide ascii
        $w3 = /\$wc\.Proxy\s*=\s*\[System\.Net\.WebRequest\]::DefaultWebProxy/ nocase wide ascii
        $w4 = /\$wc\.DownloadData\(/ nocase wide ascii
        $k = /\$K\s*=\s*\[System\.Text\.Encoding\]::ASCII\.GetBytes\(/ nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($rc4 or $rc4b) or (3 of ($w*) and $k))
}

rule CERBER_Script_PowerShell_Covenant_GruntStager {
    meta:
        description = "Covenant C2 Grunt stager class and message-crafting identifiers"
        author = "Cerber"
        family = "PowerShell.Covenant"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://github.com/cobbr/Covenant"
    strings:
        $a = "GruntStager" nocase wide ascii
        $b = "GruntEncryptedMessage" nocase wide ascii
        $c = "MessageCrafter" nocase wide ascii
        $d = "CookieWebClient" nocase wide ascii
        $e = "CovenantCertHash" nocase wide ascii
        $f = "GruntTaskingMessage" nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 3 of ($a, $b, $c, $d, $e, $f) 
}

rule CERBER_Script_PowerShell_CobaltStrike_PsLoader {
    meta:
        description = "Cobalt Strike PowerShell beacon template with func_get_proc_address and delegate helper"
        author = "Cerber"
        family = "PowerShell.CobaltStrike"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://forensicitguy.github.io/inspecting-powershell-cobalt-strike-beacon/"
    strings:
        $a = "func_get_proc_address" nocase wide ascii
        $b = "func_get_delegate_type" nocase wide ascii
        $c = "$var_code" nocase wide ascii
        $d = "$var_va" nocase wide ascii
        $e = "$var_wpm" nocase wide ascii
        $f = "-bxor 35" nocase wide ascii
        $g = "Set-StrictMode -Version 2" nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and 1 of ($c, $d, $e, $f, $g)
}

rule CERBER_Script_PowerShell_Metasploit_PshTemplate {
    meta:
        description = "msfvenom psh template allocating memory with VirtualAlloc, memset and CreateThread"
        author = "Cerber"
        family = "PowerShell.Metasploit"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1620/"
    strings:
        $a = "msvcrt.dll" nocase wide ascii
        $b = "memset" nocase wide ascii
        $c = "VirtualAlloc" nocase wide ascii
        $d = "CreateThread" nocase wide ascii
        $e = "Add-Type" nocase wide ascii
        $f = "-memberDefinition" nocase wide ascii
        $g = "Win32Functions" nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e and ($f or $g) 
}

rule CERBER_Script_PowerShell_Shellcode_Prologue_Bytes {
    meta:
        description = "Well-known x86 and x64 shellcode prologue bytes written as PowerShell byte array next to Win32 allocation APIs"
        author = "Cerber"
        family = "PowerShell.ShellcodeRunner"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1620/"
    strings:
        $p1 = /0x[fF][cC]\s*,\s*0x48\s*,\s*0x83\s*,\s*0x[eE]4\s*,\s*0x[fF]0\s*,\s*0x[eE]8/ wide ascii
        $p2 = /0x[fF][cC]\s*,\s*0x[eE]8\s*,\s*0x(82|89)\s*,\s*0x00\s*,\s*0x00\s*,\s*0x00/ wide ascii
        $p3 = /0x[fF][cC]\s*,\s*0x[eE]8\s*,\s*0x8[0-9a-f]\s*,\s*0x00\s*,\s*0x00\s*,\s*0x00\s*,\s*0x60\s*,\s*0x89\s*,\s*0x[eE]5/ wide ascii
        $a = "VirtualAlloc" nocase wide ascii
        $b = "CreateThread" nocase wide ascii
        $c = "RtlMoveMemory" nocase wide ascii
        $d = "Marshal]::Copy" nocase wide ascii
        $e = "GetDelegateForFunctionPointer" nocase wide ascii
        $f = "VirtualProtect" nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of ($p*) and $a and 1 of ($b, $c, $d, $e, $f)
}

rule CERBER_Script_PowerShell_AddType_VirtualAlloc_CreateThread {
    meta:
        description = "Add-Type P/Invoke of VirtualAlloc and CreateThread used to run raw shellcode in-process"
        author = "Cerber"
        family = "PowerShell.ShellcodeRunner"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1620/"
    strings:
        $a = /DllImport\(\s*["']kernel32(\.dll)?["'][^\r\n]{0,120}VirtualAlloc/ nocase wide ascii
        $b = /DllImport\(\s*["']kernel32(\.dll)?["'][^\r\n]{0,120}CreateThread/ nocase wide ascii
        $c = "Add-Type" nocase wide ascii
        $d = "WaitForSingleObject" nocase wide ascii
        $e = "RtlMoveMemory" nocase wide ascii
        $f = "Marshal]::Copy" nocase wide ascii
        $g = "[Byte[]]" nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and 1 of ($d, $e, $f) and $g
}

rule CERBER_Script_PowerShell_DelegateShellcodeExec {
    meta:
        description = "Marshal GetDelegateForFunctionPointer used to execute a buffer allocated with VirtualAlloc"
        author = "Cerber"
        family = "PowerShell.ShellcodeRunner"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1620/"
    strings:
        $a = "GetDelegateForFunctionPointer" nocase wide ascii
        $b = "VirtualAlloc" nocase wide ascii
        $c = /Marshal\]?::Copy|Marshal\.Copy/ nocase wide ascii
        $d = "FromBase64String" nocase wide ascii
        $e = "DynamicInvoke" nocase wide ascii
        $f = "Invoke()" nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and ($e or $f)
}

rule CERBER_Script_PowerShell_RemoteProcessInjection {
    meta:
        description = "Add-Type P/Invoke of VirtualAllocEx, WriteProcessMemory and a remote-thread API"
        author = "Cerber"
        family = "PowerShell.Injection"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1055/"
    strings:
        $a = "VirtualAllocEx" nocase wide ascii
        $b = "WriteProcessMemory" nocase wide ascii
        $c = "CreateRemoteThread" nocase wide ascii
        $d = "NtCreateThreadEx" nocase wide ascii
        $e = "QueueUserAPC" nocase wide ascii
        $f = "RtlCreateUserThread" nocase wide ascii
        $g = "Add-Type" nocase wide ascii
        $h = "OpenProcess" nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $g and $a and $b and $h and 1 of ($c, $d, $e, $f)
}

rule CERBER_Script_PowerShell_ReflectiveAssembly_RemoteLoad {
    meta:
        description = "Assembly.Load of a .NET image fetched over HTTP or decoded from base64 and invoked immediately"
        author = "Cerber"
        family = "PowerShell.ReflectiveLoad"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1620/"
    strings:
        $a = /Reflection\.Assembly\]?::Load\s*\(\s*\(?\s*\(?\s*New-Object\s+(System\.)?Net\.WebClient\s*\)?\s*\)?\.DownloadData/ nocase wide ascii
        $b = /\[(System\.)?Reflection\.Assembly\]::Load\(\s*\[(System\.)?Convert\]::FromBase64String\(/ nocase wide ascii
        $c = /(EntryPoint\.Invoke|\.GetMethod\(\s*["'][A-Za-z]{1,30}["']\s*\)\s*\.Invoke)/ nocase wide ascii
        $d = /-w(in|indow|indowstyle)?[ \t]{1,4}(h(idden)?|1)\b/ nocase wide ascii
        $e = /(Invoke-WebRequest|Invoke-RestMethod)[^\r\n]{0,120}\.Content\s*\)/ nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($a and $c) or ($a and $d) or ($b and $c and $d) or ($e and $c and $b))
}

rule CERBER_Script_PowerShell_CompressedBase64_IexStager {
    meta:
        description = "Deflate or Gzip stream over FromBase64String piped into Invoke-Expression"
        author = "Cerber"
        family = "PowerShell.Stager"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /IO\.Compression\.(Deflate|GZip)Stream/ nocase wide ascii
        $b = "FromBase64String" nocase wide ascii
        $c = /(iex|Invoke-Expression)\s*[\(\$]|\|\s*(iex|Invoke-Expression)\b/ nocase wide ascii
        $d = "StreamReader" nocase wide ascii
        $e = "ReadToEnd" nocase wide ascii
        $f = "MemoryStream" nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e and $f
}

rule CERBER_Script_PowerShell_IexNameDerivation {
    meta:
        description = "Invoke-Obfuscation tricks that rebuild the string iex from environment variables or preferences"
        author = "Cerber"
        family = "PowerShell.Obfuscation"
        severity = "high"
        score = 84
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /\$\{?env:comspec\}?\[\s*\d{1,2}\s*,\s*\d{1,2}\s*,\s*\d{1,2}\s*\]/ nocase wide ascii
        $b = /\$pshome\[\s*\d{1,2}\s*\]\s*\+\s*\$pshome\[\s*\d{1,2}\s*\]\s*\+\s*['"]x['"]/ nocase wide ascii
        $c = /\$verbosepreference\.tostring\(\)\[\s*\d{1,2}\s*,\s*\d{1,2}\s*\]/ nocase wide ascii
        $d = /\$shellid\[\s*\d{1,2}\s*\]\s*\+\s*\$shellid\[\s*\d{1,2}\s*\]\s*\+\s*['"]x['"]/ nocase wide ascii
        $e = /\(\s*\$\{?env:public\}?\[\s*\d{1,2}\s*\]\s*\+\s*\$\{?env:public\}?\[\s*\d{1,2}\s*\]/ nocase wide ascii
        $f = /\[\s*string\s*\]\s*\[\s*char\[\]\s*\]\s*\(\s*\d{2,3}\s*,\s*\d{2,3}\s*,\s*\d{2,3}\s*\)\s*-join/ nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_PowerShell_InvokeObfuscation_FormatOperator {
    meta:
        description = "Multiple tiny -f format-operator fragments assembling cmdlet names, typical of Invoke-Obfuscation"
        author = "Cerber"
        family = "PowerShell.Obfuscation"
        severity = "medium"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /["']\{[0-9]\}\{[0-9]\}(\{[0-9]\})?["']\s*-[fF]\s*['"][A-Za-z\-]{1,4}['"]\s*,\s*['"][A-Za-z\-]{1,4}['"]/ wide ascii
        $b = /[&.]\s*\(\s*["']\{[0-9]\}\{[0-9]\}/ wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and #a >= 3 and #b >= 1
}

rule CERBER_Script_PowerShell_CharCodeIex {
    meta:
        description = "The string iex or Invoke-Expression assembled from [char] codes"
        author = "Cerber"
        family = "PowerShell.Obfuscation"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /\[char\]\s*\(?\s*105\s*\)?\s*\+\s*\[char\]\s*\(?\s*101\s*\)?\s*\+\s*\[char\]\s*\(?\s*120/ nocase wide ascii
        $b = /\[char\]\s*\(?\s*73\s*\)?\s*\+\s*\[char\]\s*\(?\s*69\s*\)?\s*\+\s*\[char\]\s*\(?\s*88/ nocase wide ascii
        $c = /\[char\]\s*\(?\s*73\s*\)?\s*\+\s*\[char\]\s*\(?\s*110\s*\)?\s*\+\s*\[char\]\s*\(?\s*118\s*\)?\s*\+\s*\[char\]\s*\(?\s*111/ nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of ($a, $b, $c)
}

rule CERBER_Script_PowerShell_WmiEventSubscription_Persistence {
    meta:
        description = "WMI permanent event subscription binding a filter to a command-line or script consumer"
        author = "Cerber"
        family = "Windows.WmiPersistence"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1546/003/"
    strings:
        $a = "__EventFilter" nocase wide ascii
        $b = "CommandLineEventConsumer" nocase wide ascii
        $c = "ActiveScriptEventConsumer" nocase wide ascii
        $d = "__FilterToConsumerBinding" nocase wide ascii
        $e = "CommandLineTemplate" nocase wide ascii
        $f = "Set-WmiInstance" nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $d and ($b or $c) and ($e or $f or $c)
}

rule CERBER_Script_Batch_ScheduledTask_HiddenPowerShell {
    meta:
        description = "Scheduled task creation that launches a hidden or encoded PowerShell or mshta payload"
        author = "Cerber"
        family = "Windows.Persistence"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1053/005/"
    strings:
        $a = /schtasks(\.exe)?\s+\/create\s/ nocase wide ascii
        $b = /\/tr\s+["']?[^\r\n]{0,80}(powershell|mshta|wscript|cscript|rundll32|regsvr32)[^\r\n]{0,200}(-enc|-e\s+[A-Za-z0-9+\/]{20,}|http:|https:|javascript:|vbscript:|DownloadString|\biex\b)/ nocase wide ascii
        $c = /New-ScheduledTaskAction\s+-Execute\s+["']?(powershell|mshta|wscript|cscript)[^\r\n]{0,60}-Argument[^\r\n]{0,200}(-enc|http:|https:|DownloadString|\biex\b)/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($a and $b) or $c)
}

rule CERBER_Script_Batch_RunKey_ScriptHostPersistence {
    meta:
        description = "Run or RunOnce value that launches mshta, hidden PowerShell, wscript from a user-writable path or a web URL"
        author = "Cerber"
        family = "Windows.Persistence"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1547/001/"
    strings:
        $a = /\\CurrentVersion\\Run(Once)?["']?\s+\/v\s/ nocase wide ascii
        $b = /\\CurrentVersion\\Run(Once)?["']?\s*-Name\s|\\CurrentVersion\\Run(Once)?["']?\s*,\s*["'][A-Za-z0-9_ ]{1,30}["']\s*,/ nocase wide ascii
        $c = /(mshta|powershell|wscript|cscript|rundll32)[^\r\n]{0,80}(-enc|http:|https:|javascript:|vbscript:|DownloadString|\biex\b)/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or $b) and $c
}

rule CERBER_Script_PowerShell_Keylogger_GetAsyncKeyState {
    meta:
        description = "PowerShell keylogger polling GetAsyncKeyState and MapVirtualKey"
        author = "Cerber"
        family = "PowerShell.Keylogger"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1056/001/"
        pua = true
    strings:
        $a = "GetAsyncKeyState" nocase wide ascii
        $b = "MapVirtualKey" nocase wide ascii
        $c = "Add-Type" nocase wide ascii
        $d = "GetForegroundWindow" nocase wide ascii
        $e = "Get-Keystrokes" nocase wide ascii
        $f = /(Out-File|Set-Content|Add-Content|Invoke-WebRequest|Invoke-RestMethod|UploadString)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($a and $b and $c and $f) or ($e and $a) or ($a and $d and $b and $f))
}

rule CERBER_Script_PowerShell_ScreenshotUploader {
    meta:
        description = "System.Drawing screen capture followed by upload of the image"
        author = "Cerber"
        family = "PowerShell.Spyware"
        severity = "medium"
        score = 62
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
    strings:
        $a = "CopyFromScreen" nocase wide ascii
        $b = "System.Drawing" nocase wide ascii
        $c = /(UploadFile|UploadData|Invoke-RestMethod|Invoke-WebRequest)[^\r\n]{0,120}(-Method\s+Post|-InFile|multipart)/ nocase wide ascii
        $d = /api\.telegram\.org\/bot|discord(app)?\.com\/api\/webhooks/ nocase wide ascii
        $e = "Get-TimedScreenshot" nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and ($c or $d or $e)
}

rule CERBER_Script_PowerShell_BrowserCredentialStealer {
    meta:
        description = "PowerShell that reads Chromium Login Data and Local State and unprotects saved secrets"
        author = "Cerber"
        family = "PowerShell.Infostealer"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1555/003/"
    strings:
        $a = "Login Data" nocase wide ascii
        $b = "Local State" nocase wide ascii
        $c = /ProtectedData\]?::Unprotect|CryptUnprotectData/ nocase wide ascii
        $d = "encrypted_key" nocase wide ascii
        $e = "sqlite" nocase wide ascii
        $f = /(Invoke-RestMethod|Invoke-WebRequest|UploadFile|UploadString)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and ($e or $f)
}

rule CERBER_Script_PowerShell_ShadowCopy_WmiDelete {
    meta:
        description = "Deleting all Volume Shadow Copies through Win32_ShadowCopy WMI objects"
        author = "Cerber"
        family = "Windows.RansomwarePrep"
        severity = "medium"
        score = 64
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1490/"
    strings:
        $b = /\.Delete\(\)|Remove-WmiObject|Remove-CimInstance/ nocase wide ascii
        $c = /(Get-WmiObject|Get-CimInstance|gwmi)\s+[^\r\n]{0,20}Win32_ShadowCopy[^\r\n]{0,40}(ForEach|%|Remove-)/ nocase wide ascii
        $d = /(Stop-Service|net\s+stop|sc\s+stop)[^\r\n]{0,30}(vss|sql|veeam|backup)/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $c and $b and $d
}

rule CERBER_Script_Batch_LsassDump_Comsvcs {
    meta:
        description = "rundll32 comsvcs.dll MiniDump aimed at the LSASS process"
        author = "Cerber"
        family = "Windows.CredentialAccess"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1003/001/"
    strings:
        $a = /comsvcs(\.dll)?["']?\s*,\s*(#24|MiniDump)/ nocase wide ascii
        $b = /(lsass|Get-Process\s+lsass)/ nocase wide ascii
        $c = /\bfull\b/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Batch_ProcdumpLsass {
    meta:
        description = "Sysinternals procdump aimed at lsass with silent EULA acceptance"
        author = "Cerber"
        family = "Windows.CredentialAccess"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1003/001/"
        pua = true
    strings:
        $a = /procdump(64)?(\.exe)?["']?\s+[^\r\n]{0,40}-ma\s+(-accepteula\s+)?lsass/ nocase wide ascii
        $b = /procdump(64)?(\.exe)?["']?\s+-accepteula\s+[^\r\n]{0,20}-ma\s+lsass/ nocase wide ascii
        $c = /procdump(64)?(\.exe)?["']?\s+[^\r\n]{0,40}lsass(\.exe)?\s+[^\r\n]{0,80}\.dmp/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Batch_RegSave_SamSystemHives {
    meta:
        description = "reg save of SAM plus SYSTEM or SECURITY hives to disk for offline hash extraction"
        author = "Cerber"
        family = "Windows.CredentialAccess"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1003/002/"
    strings:
        $a = /reg(\.exe)?\s+save\s+["']?hklm\\sam["']?\s/ nocase wide ascii
        $b = /reg(\.exe)?\s+save\s+["']?hklm\\system["']?\s/ nocase wide ascii
        $c = /reg(\.exe)?\s+save\s+["']?hklm\\security["']?\s/ nocase wide ascii
        $d = /ntdsutil[^\r\n]{0,40}(ifm|ac i ntds)/ nocase wide ascii
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($a and ($b or $c)) or ($d and $b))
}

rule CERBER_Script_Batch_EventLog_Clearing {
    meta:
        description = "Bulk clearing of Windows event logs with wevtutil or Clear-EventLog"
        author = "Cerber"
        family = "Windows.DefenseEvasion"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1070/001/"
    strings:
        $a = /wevtutil(\.exe)?\s+cl\s+["']?(Security|System|Application|Microsoft-Windows-[A-Za-z\-\/]{4,60}|Setup)/ nocase wide ascii
        $b = /wevtutil(\.exe)?['"\)]?\s+el\b/ nocase wide ascii
        $c = /wevtutil(\.exe)?\s+(cl|clear-log)\s+["']?(%1|%\w+|\$_|\$log)/ nocase wide ascii
        $d = /Clear-EventLog\s+-LogName\s+["']?(Security|System|Application)/ nocase wide ascii
        $e = /Get-EventLog\s+-List[^\r\n]{0,60}Clear-EventLog/ nocase wide ascii
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (#a >= 2 or ($b and $c) or #d >= 2 or $e)
}

rule CERBER_Script_PowerShell_UacBypass_FodhelperMsSettings {
    meta:
        description = "Hijacking the ms-settings or mscfile shell open command with DelegateExecute for auto-elevation"
        author = "Cerber"
        family = "Windows.UacBypass"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1548/002/"
    strings:
        $a = /Classes\\ms-settings\\(shell\\open\\command|CurVer)/ nocase wide ascii
        $b = /Classes\\mscfile\\shell\\open\\command/ nocase wide ascii
        $c = /DelegateExecute/ nocase wide ascii
        $d = /(fodhelper|computerdefaults|eventvwr|sdclt)(\.exe)?/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or $b) and $c and $d
}

rule CERBER_Script_Batch_CertutilUrlcacheDownload {
    meta:
        description = "certutil -urlcache used to pull a remote file to disk"
        author = "Cerber"
        family = "Batch.Certutil"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = /certutil(\.exe)?["']?\s+(-|\/)(urlcache|ping)\s+(-|\/)split\s+(-|\/)f\s+["']?https?:\/\/[^\s"']{4,200}/ nocase wide ascii
        $b = /certutil(\.exe)?["']?\s+(-|\/)urlcache\s+(-|\/)f\s+["']?https?:\/\/[^\s"']{4,200}/ nocase wide ascii
        $c = /certutil(\.exe)?["']?\s+(-|\/)f\s+(-|\/)urlcache\s+(-|\/)split\s+["']?https?:\/\// nocase wide ascii
        $d = /certutil(\.exe)?["']?\s+(-|\/)verifyctl\s+(-|\/)f\s+(-|\/)split\s+["']?https?:\/\// nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Batch_CertutilDecodeExecutable {
    meta:
        description = "certutil -decode or -decodehex producing an executable or script payload"
        author = "Cerber"
        family = "Batch.Certutil"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = /certutil(\.exe)?["']?\s+(-|\/)decode(hex)?\s+["']?[^\r\n"']{1,100}["']?\s+["']?[^\r\n"']{0,100}\.(exe|dll|scr|ps1|vbs|js|jse|bat|hta|jar|msi|cpl)\b/ nocase wide ascii
        $b = /certutil(\.exe)?["']?\s+(-|\/)encode\s+["']?[^\r\n"']{1,100}["']?\s+["']?[^\r\n"']{0,100}\.(txt|b64|crt|cer)\b/ nocase wide ascii
        $c = /-----BEGIN CERTIFICATE-----/ wide ascii
        $d = /(TVqQAAMAAAAEAAAA|TVpQAAIAAAAEAA8A|TVoAAAAAAAAAAAAA)/ wide ascii
    condition:
        filesize < 8MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($a and $c) or ($a and $d) or ($a and $b))
}

rule CERBER_Script_Batch_BitsadminTransferExecutable {
    meta:
        description = "bitsadmin /transfer downloading an executable or script to disk"
        author = "Cerber"
        family = "Batch.Bitsadmin"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1197/"
    strings:
        $a = /bitsadmin(\.exe)?["']?\s+\/transfer\s+[^\r\n]{0,60}https?:\/\/[^\s"']{4,200}\s+["']?[^\r\n]{0,120}\.(exe|dll|scr|bat|vbs|js|ps1|hta|msi|jar|cmd)/ nocase wide ascii
        $b = /bitsadmin(\.exe)?["']?\s+\/create\s+[^\r\n]{0,40}\r?\n?[^\r\n]{0,10}bitsadmin(\.exe)?["']?\s+\/addfile\s+[^\r\n]{0,40}https?:\/\// nocase wide ascii
        $c = /bitsadmin(\.exe)?["']?\s+\/addfile\s+[^\r\n]{0,40}https?:\/\/[^\s"']{4,200}\s+["']?[^\r\n]{0,100}\.(exe|dll|scr|bat|vbs|js|ps1|hta|msi)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Batch_BitsJob_NotifyCmdPersistence {
    meta:
        description = "BITS job configured with SetNotifyCmdLine so a program launches when the transfer completes"
        author = "Cerber"
        family = "Batch.Bitsadmin"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1197/"
    strings:
        $a = /bitsadmin(\.exe)?["']?\s+\/setnotifycmdline\s+[^\r\n]{0,80}(cmd(\.exe)?|powershell(\.exe)?|regsvr32(\.exe)?|mshta(\.exe)?|rundll32(\.exe)?|wscript(\.exe)?|cscript(\.exe)?)/ nocase wide ascii
        $b = /bitsadmin(\.exe)?["']?\s+\/resume/ nocase wide ascii
        $c = /bitsadmin(\.exe)?["']?\s+\/(create|addfile)/ nocase wide ascii
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and ($b or $c)
}

rule CERBER_Script_Batch_MshtaRemoteOrInline {
    meta:
        description = "mshta launched with a remote URL or inline vbscript/javascript that instantiates COM objects"
        author = "Cerber"
        family = "Batch.Mshta"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1218/005/"
    strings:
        $a = /mshta(\.exe)?["']?\s+["']?https?:\/\/[^\s"']{4,200}/ nocase wide ascii
        $b = /mshta(\.exe)?["']?\s+["']?vbscript:[^\r\n]{0,40}(Execute|CreateObject)/ nocase wide ascii
        $c = /mshta(\.exe)?["']?\s+["']?javascript:[^\r\n]{0,120}(GetObject|ActiveXObject|eval\()/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Batch_Regsvr32_ScrobjSquiblydoo {
    meta:
        description = "regsvr32 loading a remote or local scriptlet through scrobj.dll (Squiblydoo)"
        author = "Cerber"
        family = "Batch.Regsvr32"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1218/010/"
    strings:
        $a = /regsvr32(\.exe)?["']?\s+[^\r\n]{0,30}\/i:["']?(https?:\/\/|\\\\)[^\s"']{4,200}\s+[^\r\n]{0,10}scrobj(\.dll)?/ nocase wide ascii
        $b = /regsvr32(\.exe)?["']?\s+[^\r\n]{0,30}\/u\s+\/n\s+\/s\s+\/i:/ nocase wide ascii
        $c = /regsvr32(\.exe)?["']?\s+[^\r\n]{0,30}\/s\s+\/n\s+\/u\s+\/i:[^\r\n]{0,200}scrobj/ nocase wide ascii
        $d = /regsvr32(\.exe)?["']?\s+[^\r\n]{0,30}\/i:[^\s"']{1,200}\.sct["']?\s+[^\r\n]{0,10}scrobj/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Batch_Rundll32_JavascriptProtocol {
    meta:
        description = "rundll32 executing a javascript: URI through mshtml RunHTMLApplication"
        author = "Cerber"
        family = "Batch.Rundll32"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1218/011/"
    strings:
        $a = /rundll32(\.exe)?["']?\s+javascript:/ nocase wide ascii
        $b = "RunHTMLApplication" nocase wide ascii
        $c = /mshtml[ ]?,[ ]?RunHTMLApplication/ nocase wide ascii
        $d = /(GetObject|ActiveXObject|WScript\.Shell)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or ($c and $d) or ($b and $d))
}

rule CERBER_Script_Batch_Rundll32_ProxyExecutionExports {
    meta:
        description = "rundll32 exports commonly abused to launch programs or scripts without a suspicious parent"
        author = "Cerber"
        family = "Batch.Rundll32"
        severity = "medium"
        score = 68
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1218/011/"
    strings:
        $a = /rundll32(\.exe)?["']?\s+ieadvpack\.dll\s*,\s*(RegisterOCX|LaunchINFSection)\s+[^\r\n]{0,80}(cmd|powershell|\.exe|\.inf)/ nocase wide ascii
        $b = /rundll32(\.exe)?["']?\s+pcwutl\.dll\s*,\s*LaunchApplication/ nocase wide ascii
        $c = /rundll32(\.exe)?["']?\s+zipfldr\.dll\s*,\s*RouteTheCall\s+[^\r\n]{0,80}\.exe/ nocase wide ascii
        $d = /rundll32(\.exe)?["']?\s+(url|ieframe|shdocvw)\.dll\s*,\s*(OpenURL|FileProtocolHandler)[A-Z]?\s+[^\r\n]{0,80}(\.hta|\.exe|\.js|\.vbs|\.scr|\.bat|\.cpl)/ nocase wide ascii
        $e = /rundll32(\.exe)?["']?\s+advpack\.dll\s*,\s*LaunchINFSection\s+[^\r\n]{0,80}\.inf/ nocase wide ascii
        $f = /rundll32(\.exe)?["']?\s+setupapi\.dll\s*,\s*InstallHinfSection\s+[^\r\n]{0,80}\.inf/ nocase wide ascii
        $g = /rundll32(\.exe)?["']?\s+shell32\.dll\s*,\s*ShellExec_RunDLL\s+["']?(cmd|powershell|mshta|wscript|cscript|regsvr32)/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Batch_WmicProcessCreate_Payload {
    meta:
        description = "wmic process call create running a scripting host or LOLBin with hidden, encoded or remote arguments"
        author = "Cerber"
        family = "Batch.Wmic"
        severity = "high"
        score = 68
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1047/"
    strings:
        $a = /wmic(\.exe)?["']?\s+[^\r\n]{0,80}process\s+call\s+create\s+["']?[^\r\n]{0,100}(powershell|mshta|regsvr32|rundll32|cscript|wscript|certutil|bitsadmin)[^\r\n]{0,200}(-enc|-w(in|indow|indowstyle)?\s+(h(idden)?|1)\b|http:|https:|\/i:|javascript:|-urlcache|\/transfer)/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Batch_WmicXslRemoteScript {
    meta:
        description = "wmic /format pointing at a remote or local XSL stylesheet to execute embedded script (Squiblytwo)"
        author = "Cerber"
        family = "Batch.Wmic"
        severity = "critical"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1220/"
    strings:
        $a = /wmic(\.exe)?["']?\s+[^\r\n]{0,80}\/format:["']?(https?:\/\/[^\s"']{4,200}|[^\s"':]{1,80}\.xsl)/ nocase wide ascii
        $b = /wmic(\.exe)?["']?\s+[^\r\n]{0,80}-format:["']?(https?:\/\/[^\s"']{4,200}|[^\s"':]{1,80}\.xsl)/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Batch_MsiexecRemoteQuietInstall {
    meta:
        description = "msiexec quietly installing a package from a bare IP address or from a URL whose extension disguises the installer"
        author = "Cerber"
        family = "Batch.Msiexec"
        severity = "medium"
        score = 60
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/003/"
    strings:
        $a = /msiexec(\.exe)?["']?\s+(\/|-)(q[nb]?|quiet|passive)[^\r\n]{0,30}\s(\/|-)i\s+["']?https?:\/\/[^\s"']{4,200}\.(png|jpg|txt|dat|dll|gif|bmp)/ nocase wide ascii
        $b = /msiexec(\.exe)?["']?\s+(\/|-)i\s+["']?https?:\/\/[^\s"']{4,200}\.(png|jpg|txt|dat|gif|bmp)["']?\s+[^\r\n]{0,20}(\/|-)(q[nb]?|quiet|passive)/ nocase wide ascii
        $c = /msiexec(\.exe)?["']?\s+(\/|-)(q[nb]?|quiet|passive)[^\r\n]{0,30}\s(\/|-)i\s+["']?https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:\/]/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Batch_Cmstp_InfUacBypass {
    meta:
        description = "cmstp silently installing an INF profile from a writable location"
        author = "Cerber"
        family = "Batch.Cmstp"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1548/002/"
    strings:
        $a = /cmstp(\.exe)?["']?\s+(\/|-)(s|au|ns)\s+(\/|-)?(s|au|ns)?\s*["']?[^\r\n]{1,100}\.inf/ nocase wide ascii
        $b = /cmstp(\.exe)?["']?\s+[^\r\n]{0,10}(\/|-)au\s+/ nocase wide ascii
        $c = /(\\Temp\\|%TEMP%|\\AppData\\|%APPDATA%|\\Users\\Public|\$env:TEMP|\$env:APPDATA)/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and ($b or $c)
}

rule CERBER_Script_Batch_InstallUtilLogfileBypass {
    meta:
        description = "InstallUtil invoked with logging disabled and the uninstall switch to run an attacker assembly"
        author = "Cerber"
        family = "Batch.InstallUtil"
        severity = "high"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1218/004/"
    strings:
        $a = /installutil(\.exe)?["']?\s+(\/|-)logfile=\s*(\/|-)logtoconsole=false\s+(\/|-)u\s/ nocase wide ascii
        $b = /installutil(\.exe)?["']?\s+(\/|-)logfile=\s+(\/|-)logtoconsole=false\s/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Batch_Ransomware_BackupDestruction {
    meta:
        description = "Several shadow copy, backup catalog and recovery-disabling commands combined in one script"
        author = "Cerber"
        family = "Batch.RansomwarePrep"
        severity = "critical"
        score = 84
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1490/"
    strings:
        $a = /vssadmin(\.exe)?["']?\s+delete\s+shadows/ nocase wide ascii
        $b = /wmic(\.exe)?["']?\s+shadowcopy\s+delete/ nocase wide ascii
        $c = /bcdedit(\.exe)?["']?\s+(\/set\s+)?\{?default\}?\s*(\/set\s+)?recoveryenabled\s+(no|off)/ nocase wide ascii
        $d = /bcdedit(\.exe)?["']?\s+\/set\s+\{?default\}?\s+bootstatuspolicy\s+ignoreallfailures/ nocase wide ascii
        $e = /wbadmin(\.exe)?["']?\s+delete\s+(catalog|systemstatebackup|backup)/ nocase wide ascii
        $f = /vssadmin(\.exe)?["']?\s+resize\s+shadowstorage\s+[^\r\n]{0,60}\/maxsize=(unbounded|401MB|[0-9]{1,3}MB)/ nocase wide ascii
        $g = /diskshadow(\.exe)?["']?[^\r\n]{0,40}delete\s+shadows\s+all/ nocase wide ascii
        $h = /cipher(\.exe)?["']?\s+\/w:[A-Za-z]:/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 2 of them
}

rule CERBER_Script_Batch_VssadminDeleteShadows {
    meta:
        description = "vssadmin delete shadows /all /quiet as used by ransomware before encryption"
        author = "Cerber"
        family = "Batch.RansomwarePrep"
        severity = "medium"
        score = 60
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1490/"
    strings:
        $a = /vssadmin(\.exe)?["']?\s+delete\s+shadows\s+\/all\s+\/quiet/ nocase wide ascii
        $b = /vssadmin(\.exe)?["']?\s+delete\s+shadows\s+\/for=[A-Za-z]:\s+\/(all|oldest)?\s*\/?quiet/ nocase wide ascii
        $c = /vssadmin(\.exe)?["']?\s+delete\s+shadows\s+\/quiet\s+\/all/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Batch_Ransomware_ServiceKiller {
    meta:
        description = "Mass net stop of backup, database and security services ahead of file encryption"
        author = "Cerber"
        family = "Batch.RansomwarePrep"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1489/"
    strings:
        $a = /net(\.exe)?\s+stop\s+["']?(vss|MSSQL\$?[A-Za-z0-9_]{0,20}|SQLWriter|SQLSERVERAGENT|SQLBrowser|veeam[A-Za-z0-9 ]{0,20}|backup[A-Za-z0-9 ]{0,20}|memtas|mepocs|sophos[A-Za-z0-9 ]{0,20}|acronis[A-Za-z0-9 ]{0,20}|GxVss|GxBlr|GxFWD|GxCVD|GxCIMgr|MSExchange[A-Za-z0-9 ]{0,20}|wrsvc|PDVFSService|ShadowProtectSvc|AcrSch2Svc|BackupExecAgentBrowser|SavRoam|svc\$)/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and #a >= 4
}

rule CERBER_Script_Batch_Ransomware_ProcessKiller {
    meta:
        description = "taskkill sweep over database, mail and office processes that hold files open before encryption"
        author = "Cerber"
        family = "Batch.RansomwarePrep"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1489/"
    strings:
        $a = /taskkill(\.exe)?["']?\s+(\/f\s+\/im|\/im[^\r\n]{0,10}\/f)\s+["']?(sql[A-Za-z0-9]{0,15}|oracle|ocssd|dbsnmp|synctime|agntsvc|isqlplussvc|xfssvccon|mydesktopqos|mydesktopservice|ocautoupds|encsvc|tbirdconfig|mysqld[A-Za-z\-]{0,5}|ocomm|thebat|thunderbird|excel|infopath|msaccess|mspub|onenote|outlook|powerpnt|steam|visio|winword|wordpad|firefoxconfig|zoolz|veeam[A-Za-z0-9]{0,10})(\.exe)?/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and #a >= 4
}

rule CERBER_Script_Batch_AntivirusProcessKiller {
    meta:
        description = "taskkill sweep aimed at antivirus and endpoint security processes"
        author = "Cerber"
        family = "Batch.DefenseEvasion"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a = /taskkill(\.exe)?["']?\s+(\/f\s+\/im|\/im[^\r\n]{0,10}\/f)\s+["']?(avp|MsMpEng|ekrn|egui|avgnt|avguard|avgui|avgsvc|ccsvchst|mbamservice|mbam|mcshield|bdagent|vsserv|360tray|360sd|zhudongfangyu|QQPCTray|SophosUI|ashServ|avastui|AvastSvc|nod32krn|nod32kui|MpCmdRun|NisSrv|SecurityHealthService|rtvscan|savservice|tmbmsrv|tmproxy|PccNTMon|K7TSecurity|FSAV32|fsgk32|fsav|f-secure|WRSA|wrsa|msseces|cavwp|cmdagent|kav|kavtray|avira|savadminservice)(\.exe)?/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and #a >= 3
}

rule CERBER_Script_Batch_CaretSplitLolbinNames {
    meta:
        description = "Command names such as powershell, cmd or mshta spelled with caret escapes to evade string matching"
        author = "Cerber"
        family = "Batch.Obfuscation"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /p\^o\^w\^e\^r\^s\^h\^e\^l\^l/ nocase wide ascii
        $b = /m\^s\^h\^t\^a/ nocase wide ascii
        $c = /c\^e\^r\^t\^u\^t\^i\^l/ nocase wide ascii
        $d = /r\^e\^g\^s\^v\^r\^3\^2/ nocase wide ascii
        $e = /b\^i\^t\^s\^a\^d\^m\^i\^n/ nocase wide ascii
        $f = /w\^s\^c\^r\^i\^p\^t/ nocase wide ascii
        $g = /c\^s\^c\^r\^i\^p\^t/ nocase wide ascii
        $h = /r\^u\^n\^d\^l\^l\^3\^2/ nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Batch_SubstringVariableObfuscation {
    meta:
        description = "Dozens of %var:~n,1% substring expansions rebuilding commands character by character"
        author = "Cerber"
        family = "Batch.Obfuscation"
        severity = "medium"
        score = 62
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /%[A-Za-z0-9_]{1,24}:~-?[0-9]{1,3},[0-9]{1,2}%/ wide ascii
        $b = /set\s+["']?[A-Za-z0-9_]{1,24}=[A-Za-z0-9+\/=\-_]{20,}/ nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and #a >= 40 and $b
}

rule CERBER_Script_Batch_EchoWritesVbsDownloader {
    meta:
        description = "Batch file that echoes an XMLHTTP or ADODB.Stream downloader into a VBS file and runs it"
        author = "Cerber"
        family = "Batch.Dropper"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = /echo[ \t]+(\^?\(?)?(Set|set)[ \t]+\w{1,20}[ \t]*=[ \t]*CreateObject\(\^?["']?(MSXML2\.XMLHTTP|Microsoft\.XMLHTTP|MSXML2\.ServerXMLHTTP[0-9.]{0,4}|ADODB\.Stream|WinHttp\.WinHttpRequest\.5\.1)/ nocase wide ascii
        $b = /(cscript|wscript)(\.exe)?["']?\s+(\/\/[bBnN]+\s+)*["']?[^\r\n]{0,60}\.vbs/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and #a >= 2 and $b
}

rule CERBER_Script_Batch_FtpScriptDownloader {
    meta:
        description = "Batch echoing an FTP command script (open, user, get) and running it silently to fetch a payload"
        author = "Cerber"
        family = "Batch.Dropper"
        severity = "medium"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = /echo[ \t]+open[ \t]+[A-Za-z0-9\.\-]{4,80}[ \t]*>{1,2}[ \t]*[%A-Za-z0-9_\\\.]{1,60}/ nocase wide ascii
        $b = /echo[ \t]+get[ \t]+[^\r\n]{1,60}\.(exe|dll|scr|bat|vbs)/ nocase wide ascii
        $c = /ftp(\.exe)?[ \t]+(-n[ \t]+)?-s:/ nocase wide ascii
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Batch_BackdoorAdminAccount {
    meta:
        description = "Creating a local administrator account and opening Remote Desktop in the same script"
        author = "Cerber"
        family = "Batch.Persistence"
        severity = "low"
        score = 52
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1136/001/"
    strings:
        $a = /net(\.exe)?\s+user\s+[^\r\n\s]{1,30}\s+[^\r\n\s]{1,40}\s+\/add/ nocase wide ascii
        $b = /net(\.exe)?\s+localgroup\s+["']?(administrators|administratorzy)["']?\s+[^\r\n\s]{1,30}\s+\/add/ nocase wide ascii
        $c = "fDenyTSConnections" nocase wide ascii
        $d = /netsh\s+(advfirewall\s+firewall|firewall)\s+(add\s+(rule|portopening)|set\s+service)[^\r\n]{0,80}(3389|remote\s*desktop)/ nocase wide ascii
        $e = /reg(\.exe)?\s+add\s+[^\r\n]{0,80}\\Winlogon\\SpecialAccounts\\UserList/ nocase wide ascii
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and ($c or $d or $e)
}

rule CERBER_Script_Batch_IFEO_StickyKeysBackdoor {
    meta:
        description = "Image File Execution Options Debugger hijack of an accessibility binary to spawn a shell at the logon screen"
        author = "Cerber"
        family = "Batch.Persistence"
        severity = "critical"
        score = 84
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1546/012/"
    strings:
        $a = /Image File Execution Options\\(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe/ nocase wide ascii
        $b = "Debugger" nocase wide ascii
        $c = /(cmd|powershell|wscript|mshta)(\.exe)?/ nocase wide ascii
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Batch_IFEO_SecurityToolBlock {
    meta:
        description = "Image File Execution Options Debugger values set on antivirus or analysis tools so they cannot start"
        author = "Cerber"
        family = "Batch.DefenseEvasion"
        severity = "high"
        score = 82
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $a = /Image File Execution Options\\(MsMpEng|MpCmdRun|NisSrv|SecurityHealthService|avp|ekrn|egui|mbam|MBAMService|avgnt|avguard|bdagent|mcshield|SophosUI|procmon|procmon64|autoruns|processhacker|wireshark)\.exe/ nocase wide ascii
        $b = "Debugger" nocase wide ascii
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_Reg_PolicyLockdown_TaskMgrRegedit {
    meta:
        description = "Registry policy values that remove Task Manager, Regedit, CMD and Run access from the user"
        author = "Cerber"
        family = "Reg.Lockdown"
        severity = "low"
        score = 45
        date = "2026-09-29"
    strings:
        $a = "DisableTaskMgr" nocase wide ascii
        $b = "DisableRegistryTools" nocase wide ascii
        $c = "DisableCMD" nocase wide ascii
        $d = "NoRun" nocase wide ascii
        $e = "NoControlPanel" nocase wide ascii
        $f = "NoFolderOptions" nocase wide ascii
        $g = "NoViewOnDrive" nocase wide ascii
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and 2 of ($c, $d, $e, $f, $g)
}

rule CERBER_Script_Reg_AppInitDlls_Persistence {
    meta:
        description = "AppInit_DLLs enabled with an explicit DLL path in a registry script"
        author = "Cerber"
        family = "Reg.Persistence"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1546/010/"
    strings:
        $a = "AppInit_DLLs" nocase wide ascii
        $b = "LoadAppInit_DLLs" nocase wide ascii
        $c = /(dword:00000001|\/d\s+1\b|-Value\s+1\b)/ nocase wide ascii
        $d = /\.dll/ nocase wide ascii
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Reg_WinlogonUserinitShell_Hijack {
    meta:
        description = "Winlogon Userinit or Shell value appended with an extra program"
        author = "Cerber"
        family = "Reg.Persistence"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1547/004/"
    strings:
        $a = /"Userinit"\s*=\s*"[^"\r\n]{0,60}userinit\.exe,\s*[^"\r\n]{3,120}"/ nocase wide ascii
        $b = /"Shell"\s*=\s*"explorer\.exe,\s*[^"\r\n]{3,120}"/ nocase wide ascii
        $c = /reg(\.exe)?\s+add\s+[^\r\n]{0,80}Winlogon[^\r\n]{0,20}\/v\s+(Userinit|Shell)\s+[^\r\n]{0,40}\/d\s+["'][^\r\n"']{0,60}(userinit\.exe|explorer\.exe),[^\r\n"']{3,120}/ nocase wide ascii
        $d = /Winlogon/ nocase wide ascii
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $d and 1 of ($a, $b, $c)
}

rule CERBER_Script_Reg_RunKey_ScriptHostDropper {
    meta:
        description = ".reg file adding a Run or RunOnce value that launches hidden PowerShell, mshta, wscript or a remote script"
        author = "Cerber"
        family = "Reg.Persistence"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1547/001/"
    strings:
        $a = /\\CurrentVersion\\Run(Once)?\]\s{0,4}[^\[]{0,300}=\s*"[^"\r\n]{0,200}(powershell|mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?[^"\r\n]{0,200}(-enc|http:|https:|javascript:|vbscript:|DownloadString|iex)/ nocase wide ascii
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Reg_IFEO_DebuggerHijack {
    meta:
        description = ".reg file setting an Image File Execution Options Debugger for an accessibility tool or security product"
        author = "Cerber"
        family = "Reg.Persistence"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1546/012/"
    strings:
        $a = /Image File Execution Options\\(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker|MsMpEng|MpCmdRun|SecurityHealthService|avp|ekrn)\.exe\]/ nocase wide ascii
        $b = /"Debugger"\s*=\s*"[^"\r\n]{1,120}"/ nocase wide ascii
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_Autorun_UsbWorm_Inf {
    meta:
        description = "autorun.inf pointing at an executable hidden in a recycler-style folder or launching a script"
        author = "Cerber"
        family = "Autorun.Worm"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1091/"
    strings:
        $a = /\[autorun\]/ nocase wide ascii
        $b = /open\s*=\s*[^\r\n]{0,40}(RECYCLER|RECYCLED|\$RECYCLE\.BIN|System Volume Information|\.\\)[^\r\n]{0,60}\.(exe|scr|vbs|bat|cmd|pif|com)/ nocase wide ascii
        $c = /(shellexecute|shell\\open\\command|shell\\explore\\command)\s*=/ nocase wide ascii
        $d = /open\s*=\s*[^\r\n]{0,40}\.(scr|pif|vbs|cmd)\b/ nocase wide ascii
        $e = "USEAUTOPLAY" nocase wide ascii
    condition:
        filesize < 8KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and (($b) or ($c and $d and $e))
}

rule CERBER_Script_Xml_SettingContentMs_CommandExec {
    meta:
        description = ".SettingContent-ms file whose DeepLink runs a command interpreter"
        author = "Cerber"
        family = "SettingContent.Abuse"
        severity = "high"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    strings:
        $a = "<PCSettings>" nocase wide ascii
        $b = "<DeepLink>" nocase wide ascii
        $c = /<DeepLink>\s*[^<]{0,40}(powershell|cmd(\.exe)?|mshta|wscript|cscript|rundll32|regsvr32)/ nocase wide ascii
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Scf_UncIconNtlmLeak {
    meta:
        description = "Explorer command (.scf) or internet shortcut whose icon path points at a remote SMB share to leak NTLM hashes"
        author = "Cerber"
        family = "Scf.NtlmLeak"
        severity = "medium"
        score = 68
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1187/"
    strings:
        $a = /\[Shell\]/ nocase wide ascii
        $b = /Command\s*=\s*2/ nocase wide ascii
        $c = /IconFile\s*=\s*\\\\[A-Za-z0-9\.\-_]{1,80}\\/ nocase wide ascii
        $d = /\[InternetShortcut\]/ nocase wide ascii
    condition:
        filesize < 4KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $c and (($a and $b) or $d)
}

rule CERBER_Script_Scriptlet_Sct_ShellExec {
    meta:
        description = "Windows Script Component (.sct) that runs shell commands from embedded JScript or VBScript"
        author = "Cerber"
        family = "Scriptlet.Sct"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1218/010/"
    strings:
        $a = /<scriptlet>/ nocase wide ascii
        $b = /<registration[^>]{0,200}(progid|classid)=/ nocase wide ascii
        $c = /<script\s+language\s*=\s*["']?(JScript|VBScript)/ nocase wide ascii
        $d = /(WScript\.Shell|ActiveXObject|Shell\.Application|GetObject\(["']winmgmts)/ nocase wide ascii
        $e = /\.(Run|Exec|ShellExecute)\s*\(/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Xsl_MsXslScript_Exec {
    meta:
        description = "XSLT stylesheet with a Microsoft script block that instantiates COM objects to run commands"
        author = "Cerber"
        family = "Xsl.ScriptExec"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1220/"
    strings:
        $a = /<xsl:stylesheet|<stylesheet/ nocase wide ascii
        $b = /urn:schemas-microsoft-com:(xslt|xsl-script)/ nocase wide ascii
        $c = /<(ms|msxsl):script[^>]{0,80}language\s*=\s*["']?(JScript|VBScript)/ nocase wide ascii
        $d = /(WScript\.Shell|ActiveXObject|Shell\.Application)/ nocase wide ascii
        $e = /\.(Run|Exec|ShellExecute)\s*\(/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Inf_CmstpScrobjInstall {
    meta:
        description = "Connection Manager INF that registers a remote scriptlet through scrobj.dll for UAC bypass"
        author = "Cerber"
        family = "Inf.Cmstp"
        severity = "critical"
        score = 84
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1548/002/"
    strings:
        $a = /\[DefaultInstall(_SingleUser)?\]/ nocase wide ascii
        $b = "UnRegisterOCXs" nocase wide ascii
        $c = /%11%\\scrobj\.dll,NI,/ nocase wide ascii
        $d = /RunPreSetupCommands/ nocase wide ascii
        $e = /\[version\]/ nocase wide ascii
        $f = /Signature\s*=\s*["']?\$chicago\$/ nocase wide ascii
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $e and $f and (($b and $c) or $d)
}

rule CERBER_Script_Xml_MsBuildInlineTask_Shellcode {
    meta:
        description = "MSBuild project with an inline C# task that allocates executable memory or runs a process"
        author = "Cerber"
        family = "MSBuild.InlineTask"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1127/001/"
    strings:
        $a = /<UsingTask/ nocase wide ascii
        $b = /TaskFactory\s*=\s*["']CodeTaskFactory["']/ nocase wide ascii
        $c = "Microsoft.Build.Framework" nocase wide ascii
        $d = "VirtualAlloc" nocase wide ascii
        $e = "WriteProcessMemory" nocase wide ascii
        $f = "CreateThread" nocase wide ascii
        $g = /Marshal\.Copy|GetDelegateForFunctionPointer/ nocase wide ascii
        $h = "FromBase64String" nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and ($f or $e or $g) and $h
}

rule CERBER_Script_Text_RansomNote_Instructions {
    meta:
        description = "Ransom note text: encrypted files, payment in cryptocurrency and Tor contact instructions"
        author = "Cerber"
        family = "Ransom.Note"
        severity = "high"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1486/"
    strings:
        $a = /your (files|data|documents|network) (have been|has been|are|were) (encrypted|locked)/ nocase wide ascii
        $b = /(bitcoin|BTC wallet|monero|XMR)/ nocase wide ascii
        $c = /(\.onion|tor browser|torproject)/ nocase wide ascii
        $d = /(decrypt(ion)? (key|tool|software)|private key)/ nocase wide ascii
        $e = /(within|in) (24|48|72|96) hours/ nocase wide ascii
        $f = /(do not|don't) (try to |attempt to )?(rename|modify|delete|use third[- ]party|contact (the )?(police|fbi))/ nocase wide ascii
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and 1 of ($e, $f)
}

rule CERBER_Script_Lnk_PowerShellHiddenCommand {
    meta:
        description = "Windows shortcut whose target arguments start hidden PowerShell with encoded or download commands"
        author = "Cerber"
        family = "Lnk.PowerShell"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    strings:
        $a = "powershell" nocase wide ascii
        $b = /-w(in|indow|indowstyle)?[ ](h(idden)?|1)/ nocase wide ascii
        $c = "-enc" nocase wide ascii
        $d = "downloadstring" nocase wide ascii
        $f = "-nop" nocase wide ascii
        $g = "http" nocase wide ascii
        $h = "-ep bypass" nocase wide ascii
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and filesize < 2MB and $a and $b and ((2 of ($c, $d, $f, $h) and $g) or ($c and $f))
}

rule CERBER_Script_Lnk_ScriptHostRemote {
    meta:
        description = "Windows shortcut that launches mshta, wscript, regsvr32 or rundll32 against a remote or javascript target"
        author = "Cerber"
        family = "Lnk.ScriptHost"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    strings:
        $a = /(mshta|regsvr32|wscript|cscript|rundll32)(\.exe)?/ nocase wide ascii
        $b = "http" nocase wide ascii
        $c = "javascript:" nocase wide ascii
        $d = "vbscript:" nocase wide ascii
        $e = "scrobj" nocase wide ascii
        $f = "/i:http" nocase wide ascii
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and filesize < 1MB and $a and (($b and ($c or $d)) or ($e and $f and $b))
}

rule CERBER_Script_Lnk_CmdCurlCertutilDropper {
    meta:
        description = "Windows shortcut invoking cmd.exe /c with a downloader utility or script host"
        author = "Cerber"
        family = "Lnk.CmdDropper"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = "cmd.exe" nocase wide ascii
        $c = "curl" nocase wide ascii
        $d = "certutil" nocase wide ascii
        $e = "bitsadmin" nocase wide ascii
        $f = "http" nocase wide ascii
        $g = "start /min" nocase wide ascii
        $h = ".vbs" nocase wide ascii
        $j = "wscript" nocase wide ascii
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and filesize < 1MB and $a and $f and (1 of ($c, $d, $e)) and 1 of ($g, $h, $j)
}

rule CERBER_Script_VBScript_HttpDownloadAdodbExecute {
    meta:
        description = "VBScript that downloads with an HTTP COM object, saves through ADODB.Stream and launches the file"
        author = "Cerber"
        family = "VBScript.Dropper"
        severity = "high"
        score = 62
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $h = /CreateObject\(\s*["'](MSXML2\.(Server)?XMLHTTP[0-9.]{0,4}|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest\.5\.1)["']\s*\)/ nocase wide ascii
        $s = /CreateObject\(\s*["']ADODB\.Stream["']\s*\)/ nocase wide ascii
        $w = /\.SaveToFile/ nocase wide ascii
        $u = /\.Open[ \t(]+["']GET["'][ \t]*,[ \t]*["']https?:\/\/[^"'\r\n]{4,200}["']/ nocase wide ascii
        $r = /\.(Run|Exec)[ \t]*[\( ]|\.ShellExecute\b/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $h and $s and $w and $r and $u
}

rule CERBER_Script_VBScript_WshRunPowerShellHidden {
    meta:
        description = "WScript.Shell Run or Exec starting PowerShell with hidden, encoded or bypass switches"
        author = "Cerber"
        family = "VBScript.Launcher"
        severity = "high"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $a = /\.(Run|Exec)[ \t]*\(?[ \t]*["'][^\r\n]{0,80}powershell(\.exe)?[^\r\n]{0,160}(-w(in|indow|indowstyle)?[ \t]+(h(idden)?|1)|-enc|-nop|-ep[ \t]+bypass|-executionpolicy[ \t]+bypass)/ nocase wide ascii
        $b = /CreateObject\(\s*["']WScript\.Shell["']\s*\)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_VBScript_RunLolbinWithRemoteUrl {
    meta:
        description = "WScript.Shell Run of cmd, curl, certutil, mshta or regsvr32 pointed at an http URL"
        author = "Cerber"
        family = "VBScript.Launcher"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $a = /\.(Run|Exec)[ \t]*\(?[ \t]*["'][^\r\n]{0,40}(cmd(\.exe)?[ \t]+\/c[ \t]+)?[^\r\n]{0,80}(curl|certutil|bitsadmin|mshta|regsvr32)[^\r\n]{0,120}https?:\/\/[^\r\n]{4,200}/ nocase wide ascii
        $b = /CreateObject\(\s*["']WScript\.Shell["']\s*\)/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_VBScript_ChrArithmeticObfuscation {
    meta:
        description = "Payload assembled from dozens of Chr() calls and executed with Execute or Eval"
        author = "Cerber"
        family = "VBScript.Obfuscation"
        severity = "medium"
        score = 62
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /Chr[BW]?\(\s*[0-9]{2,3}\s*\)\s*&/ nocase wide ascii
        $e = /\b(Execute|ExecuteGlobal|Eval)\b/ nocase wide ascii
        $c = /CreateObject\(/ nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and #a >= 40 and $e and $c
}

rule CERBER_Script_VBScript_StrReverseExecute {
    meta:
        description = "Execute, Eval or CreateObject fed by StrReverse output to hide the payload text"
        author = "Cerber"
        family = "VBScript.Obfuscation"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /(Execute|ExecuteGlobal|Eval)[ \t]*\(?[ \t]*StrReverse[ \t]*\(/ nocase wide ascii
        $b = /CreateObject[ \t]*\([ \t]*StrReverse[ \t]*\([ \t]*["']/ nocase wide ascii
        $c = /StrReverse[ \t]*\([ \t]*["'][^"'\r\n]{4,60}["'][ \t]*\)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($b or ($a and #c >= 1))
}

rule CERBER_Script_VBScript_WmiWin32ProcessCreateHidden {
    meta:
        description = "winmgmts Win32_Process.Create with a Win32_ProcessStartup that hides the window, starting a shell or script host"
        author = "Cerber"
        family = "VBScript.Wmi"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $a = /GetObject\(\s*["']winmgmts:/ nocase wide ascii
        $b = "Win32_ProcessStartup" nocase wide ascii
        $c = /ShowWindow\s*=\s*0/ nocase wide ascii
        $d = "Win32_Process" nocase wide ascii
        $e = /\.Create[ \t]*[\( ]/ nocase wide ascii
        $f = /(powershell|cmd(\.exe)?\s+\/c|wscript|mshta|cscript)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e and $f
}

rule CERBER_Script_VBScript_UsbWorm_SelfCopy {
    meta:
        description = "Script copies itself onto removable drives and writes autorun.inf"
        author = "Cerber"
        family = "VBScript.Worm"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $a = "WScript.ScriptFullName" nocase wide ascii
        $b = "autorun.inf" nocase wide ascii
        $c = /\.Drives\b/ nocase wide ascii
        $d = /DriveType\s*=\s*1\b/ nocase wide ascii
        $e = /\.(CopyFile|Copy)\b/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_VBScript_RunKeySelfCopyPersistence {
    meta:
        description = "Script copies itself and registers the copy under the Run key"
        author = "Cerber"
        family = "VBScript.Persistence"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1547/001/"
    strings:
        $a = "WScript.ScriptFullName" nocase wide ascii
        $b = /RegWrite[ \t]+["']HK(CU|LM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\/ nocase wide ascii
        $c = /\.(CopyFile|Copy)\b/ nocase wide ascii
        $d = /(GetSpecialFolder|Environ|ExpandEnvironmentStrings)/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_VBScript_DisableSecurityFeaturesRegWrite {
    meta:
        description = "RegWrite calls that remove Task Manager, Regedit, CMD and Defender protections"
        author = "Cerber"
        family = "VBScript.Tamper"
        severity = "medium"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
    strings:
        $w = /RegWrite/ nocase wide ascii
        $a = "DisableTaskMgr" nocase wide ascii
        $b = "DisableRegistryTools" nocase wide ascii
        $c = "DisableCMD" nocase wide ascii
        $d = "DisableAntiSpyware" nocase wide ascii
        $e = "DisableRealtimeMonitoring" nocase wide ascii
        $f = "EnableLUA" nocase wide ascii
        $g = "NoControlPanel" nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $w and 3 of ($a, $b, $c, $d, $e, $f, $g)
}

rule CERBER_Script_VBScript_OutlookMassMailerWorm {
    meta:
        description = "Outlook automation that walks address lists and mails an attachment, in the style of the Love Letter worm"
        author = "Cerber"
        family = "VBScript.Worm"
        severity = "high"
        score = 82
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $a = /CreateObject\(\s*["']Outlook\.Application["']\s*\)/ nocase wide ascii
        $b = /GetNameSpace\(\s*["']MAPI["']\s*\)/ nocase wide ascii
        $c = /AddressLists/ nocase wide ascii
        $d = /Attachments\.Add/ nocase wide ascii
        $e = /\.Send\b/ nocase wide ascii
        $f = "LOVE-LETTER-FOR-YOU" nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($a and $b and $c and $d and $e) or $f)
}

rule CERBER_Script_VBScript_AvEnumerationDownloader {
    meta:
        description = "Script that queries the installed antivirus product and then talks to a remote server"
        author = "Cerber"
        family = "VBScript.Recon"
        severity = "medium"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $a = /root\\SecurityCenter2?/ nocase wide ascii
        $b = "AntiVirusProduct" nocase wide ascii
        $c = /(XMLHTTP|ADODB\.Stream|WinHttp\.WinHttpRequest)/ nocase wide ascii
        $d = /(Win32_ComputerSystem|Win32_OperatingSystem)/ nocase wide ascii
        $e = /\.(Run|Exec)[ \t]*[\( ]/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_VBScript_Base64DomDecodeDrop {
    meta:
        description = "MSXML DOM bin.base64 decode followed by a binary write to disk"
        author = "Cerber"
        family = "VBScript.Dropper"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $a = "bin.base64" nocase wide ascii
        $b = "nodeTypedValue" nocase wide ascii
        $c = /(Microsoft\.XMLDOM|MSXML2\.DOMDocument[0-9.]{0,4})/ nocase wide ascii
        $d = /(ADODB\.Stream|SaveToFile|Scripting\.FileSystemObject)/ nocase wide ascii
        $e = /\.(Run|Exec)[ \t]*[\( ]|ShellExecute/ nocase wide ascii
    condition:
        filesize < 8MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_VBScript_ScriptMonikerGetObject {
    meta:
        description = "GetObject with a script: moniker that loads and runs a remote scriptlet"
        author = "Cerber"
        family = "VBScript.ScriptMoniker"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1218/010/"
    strings:
        $a = /GetObject\(\s*["']script:https?:\/\/[^\s"']{4,200}/ nocase wide ascii
        $b = /GetObject\(\s*["']script:\\\\[^\s"']{4,200}/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_JScript_WshRunPowerShellHidden {
    meta:
        description = "ActiveXObject WScript.Shell launching PowerShell with hidden, encoded or bypass switches"
        author = "Cerber"
        family = "JScript.Launcher"
        severity = "high"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/007/"
    strings:
        $a = /\.(Run|Exec)[ \t]*\([ \t]*["'][^\r\n]{0,80}powershell(\.exe)?[^\r\n]{0,160}(-w(in|indow|indowstyle)?[ \t]+(h(idden)?|1)|-enc|-nop|-ep[ \t]+bypass|-executionpolicy[ \t]+bypass)/ nocase wide ascii
        $b = /ActiveXObject\(\s*["']WScript\.Shell["']\s*\)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_JScript_XmlHttpAdodbStreamDropper {
    meta:
        description = "JScript downloader using an XMLHTTP COM object, ADODB.Stream SaveToFile and a launch call"
        author = "Cerber"
        family = "JScript.Dropper"
        severity = "high"
        score = 64
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $h = /ActiveXObject\(\s*["'](MSXML2\.(Server)?XMLHTTP[0-9.]{0,4}|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest\.5\.1)["']\s*\)/ nocase wide ascii
        $s = /ActiveXObject\(\s*["']ADODB\.Stream["']\s*\)/ nocase wide ascii
        $w = /\.SaveToFile\(/ nocase wide ascii
        $u = /\.open[ \t(]+["']GET["'][ \t]*,[ \t]*["']https?:\/\/[^"'\r\n]{4,200}["']/ nocase wide ascii
        $r = /\.(Run|Exec)[ \t]*\(|\.ShellExecute\(/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $h and $s and $w and $r and $u
}

rule CERBER_Script_JScript_DeanEdwardsEvalWithWshObjects {
    meta:
        description = "Dean Edwards packer output wrapped around WScript.Shell or ADODB.Stream automation"
        author = "Cerber"
        family = "JScript.Obfuscated"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /eval\(function\(p,a,c,k,e,(d|r)\)/ wide ascii
        $b = /ActiveXObject/ nocase wide ascii
        $c = /(WScript\.Shell|ADODB\.Stream|Scripting\.FileSystemObject|Shell\.Application)/ nocase wide ascii
        $d = "WScript." nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_JScript_FromCharCodeBlobsEval {
    meta:
        description = "Several long String.fromCharCode number lists decoded and evaluated next to ActiveXObject usage"
        author = "Cerber"
        family = "JScript.Obfuscated"
        severity = "medium"
        score = 64
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /String\.fromCharCode\(\s*[0-9]{2,3}\s*(,\s*[0-9]{2,3}\s*){7,}\)/ wide ascii
        $b = /eval\(/ wide ascii
        $c = /ActiveXObject/ nocase wide ascii
        $d = "WScript" nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and #a >= 3 and $b and $c and $d
}

rule CERBER_Script_JScript_WmiWin32ProcessCreate {
    meta:
        description = "JScript using winmgmts Win32_Process Create with a hidden startup object"
        author = "Cerber"
        family = "JScript.Wmi"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/007/"
    strings:
        $a = /GetObject\(\s*["']winmgmts:/ nocase wide ascii
        $b = "Win32_ProcessStartup" nocase wide ascii
        $c = /ShowWindow\s*=\s*0/ nocase wide ascii
        $d = "Win32_Process" nocase wide ascii
        $e = /\.Create\s*\(/ nocase wide ascii
        $f = /ActiveXObject|WScript/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e and $f
}

rule CERBER_Script_JScript_EncodedScriptHeader {
    meta:
        description = "Microsoft Script Encoder output (#@~^ header and ^#~@ trailer) as used to hide VBS and JS droppers"
        author = "Cerber"
        family = "Script.Encoded"
        severity = "medium"
        score = 58
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $s = "#@~^"
        $e = "^#~@"
    condition:
        uint32be(0) == 0x23407E5E and filesize < 2MB and $s and $e
}

rule CERBER_Script_Html_ScriptEncodeLanguageAttribute {
    meta:
        description = "Script block declared as VBScript.Encode or JScript.Encode holding encoder output"
        author = "Cerber"
        family = "Script.Encoded"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /language\s*=\s*["']?(VBScript|JScript)\.Encode/ nocase wide ascii
        $b = "#@~^" wide ascii
        $c = "^#~@" wide ascii
    condition:
        filesize < 4MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Wsf_JobShellDropper {
    meta:
        description = "Windows Script File job that runs shell commands and fetches content over HTTP"
        author = "Cerber"
        family = "Wsf.Dropper"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/007/"
    strings:
        $a = /<job[ >]/ nocase wide ascii
        $b = /<script\s+language\s*=\s*["'](VBScript|JScript)["']/ nocase wide ascii
        $c = /(WScript\.Shell|Shell\.Application)/ nocase wide ascii
        $d = /\.(Run|Exec|ShellExecute)[ \t]*[\( ]/ nocase wide ascii
        $e = /(XMLHTTP|ADODB\.Stream|powershell|certutil)/ nocase wide ascii
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Hta_HiddenShellRun {
    meta:
        description = "HTA application with hidden window attributes that runs commands through WScript.Shell"
        author = "Cerber"
        family = "Hta.Dropper"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1218/005/"
    strings:
        $a = /<hta:application/ nocase wide ascii
        $b = /(showintaskbar\s*=\s*["']?no|windowstate\s*=\s*["']?minimize|window\.resizeTo\(\s*0|window\.moveTo\(\s*-[0-9]{3,5})/ nocase wide ascii
        $c = /(WScript\.Shell|Shell\.Application)/ nocase wide ascii
        $d = /\.(Run|Exec|ShellExecute)[ \t]*[\( ]/ nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Hta_PowerShellLauncher {
    meta:
        description = "HTA whose script starts PowerShell with hidden, encoded or download-cradle arguments"
        author = "Cerber"
        family = "Hta.Launcher"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1218/005/"
    strings:
        $a = /<hta:application/ nocase wide ascii
        $b = /powershell(\.exe)?[^\r\n]{0,200}(-w(in|indow|indowstyle)?[ \t]+(h(idden)?|1)|-enc|-nop|-ep[ \t]+bypass|DownloadString|IEX)/ nocase wide ascii
        $c = /(WScript\.Shell|Shell\.Application)/ nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Hta_XmlHttpDropper {
    meta:
        description = "HTA that downloads through XMLHTTP, writes with ADODB.Stream and starts the file"
        author = "Cerber"
        family = "Hta.Dropper"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1218/005/"
    strings:
        $a = /<hta:application/ nocase wide ascii
        $b = /(MSXML2\.(Server)?XMLHTTP|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest)/ nocase wide ascii
        $c = /(ADODB\.Stream|SaveToFile)/ nocase wide ascii
        $d = /\.(Run|Exec|ShellExecute)[ \t]*[\( ]/ nocase wide ascii
        $u = /\.Open[ \t(]+["']GET["'][ \t]*,[ \t]*["']https?:\/\/[^"'\r\n]{4,200}["']/ nocase wide ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $u
}

rule CERBER_Script_Vba_AutoExec_ShellPowerShell {
    meta:
        description = "VBA auto-run procedure that shells out to hidden or encoded PowerShell"
        author = "Cerber"
        family = "Vba.Dropper"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $auto = /(Sub|Function)[ \t]+(AutoOpen|Auto_Open|AutoExec|Document_Open|Document_New|Workbook_Open|Workbook_Activate)[ \t]*\(/ nocase wide ascii
        $ps = /powershell(\.exe)?[ \t]+[^\r\n]{0,100}(-w(in|indow|indowstyle)?[ \t]+(h(idden)?|1)|-enc|-nop|-ep[ \t]+bypass|-executionpolicy[ \t]+bypass|-noni)/ nocase wide ascii
        $sh = /(\bShell[ \t]*\(|[\r\n:][ \t]*(Call[ \t]+)?Shell[ \t]+[A-Za-z_"(]|\.Run[ \t]*[\( ][ \t]*[A-Za-z_"']|\.Exec[ \t]*[\( ])/ nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $auto and $ps and $sh
}

rule CERBER_Script_Vba_UrlDownloadToFile_AutoExecShell {
    meta:
        description = "VBA that declares URLDownloadToFile from urlmon and launches the downloaded file from an auto-run macro"
        author = "Cerber"
        family = "Vba.Dropper"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $auto = /(Sub|Function)[ \t]+(AutoOpen|Auto_Open|AutoExec|Document_Open|Workbook_Open|Document_New)[ \t]*\(/ nocase wide ascii
        $decl = /Declare[ \t]+(PtrSafe[ \t]+)?Function[ \t]+URLDownloadToFile[AW]?[ \t]+Lib[ \t]+["']urlmon["']/ nocase wide ascii
        $run = /(\bShell[ \t]*\(|[\r\n:][ \t]*(Call[ \t]+)?Shell[ \t]+[A-Za-z_"(]|ShellExecute[AW]?[ \t]*[\( ][ \t]*[A-Za-z_"0]|\.Run[ \t]*[\( ][ \t]*[A-Za-z_"'])/ nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $auto and $decl and $run
}

rule CERBER_Script_Vba_HttpAdodbSave_AutoExecRun {
    meta:
        description = "VBA auto-run macro using XMLHTTP and ADODB.Stream to write a file and then run it"
        author = "Cerber"
        family = "Vba.Dropper"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $auto = /(Sub|Function)[ \t]+(AutoOpen|Auto_Open|AutoExec|Document_Open|Workbook_Open|Document_New)[ \t]*\(/ nocase wide ascii
        $h = /CreateObject\(\s*"(MSXML2\.(Server)?XMLHTTP[0-9.]{0,4}|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest\.5\.1)"\s*\)/ nocase wide ascii
        $s = /CreateObject\(\s*"ADODB\.Stream"\s*\)/ nocase wide ascii
        $w = /\.SaveToFile/ nocase wide ascii
        $r = /(\bShell[ \t]*\(|[\r\n:][ \t]*(Call[ \t]+)?Shell[ \t]+[A-Za-z_"(]|ShellExecute[AW]?[ \t]*[\( ][ \t]*[A-Za-z_"0]|\.Run[ \t]*[\( ][ \t]*[A-Za-z_"'])/ nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $auto and $h and $s and $w and $r
}

rule CERBER_Script_Vba_WscriptShellCmdRun_AutoExec {
    meta:
        description = "VBA auto-run macro invoking cmd.exe through WScript.Shell with a hidden window and a download or LOLBin"
        author = "Cerber"
        family = "Vba.Launcher"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $auto = /(Sub|Function)[ \t]+(AutoOpen|Auto_Open|AutoExec|Document_Open|Workbook_Open|Document_New)[ \t]*\(/ nocase wide ascii
        $a = /CreateObject\(\s*"WScript\.Shell"\s*\)/ nocase wide ascii
        $b = /\.Run[ \t]*\(?[ \t]*[^\r\n]{0,60}cmd(\.exe)?[ \t]+\/c[^\r\n]{0,200}(http|powershell|mshta|certutil|bitsadmin|regsvr32|curl)/ nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $auto and $a and $b
}

rule CERBER_Script_Vba_WmiProcessCreate_AutoExec {
    meta:
        description = "VBA auto-run macro that starts a process through winmgmts Win32_Process with a hidden Win32_ProcessStartup"
        author = "Cerber"
        family = "Vba.Wmi"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $auto = /(Sub|Function)[ \t]+(AutoOpen|Auto_Open|AutoExec|Document_Open|Workbook_Open|Document_New)[ \t]*\(/ nocase wide ascii
        $a = /GetObject\(\s*"winmgmts:/ nocase wide ascii
        $b = "Win32_ProcessStartup" nocase wide ascii
        $c = /ShowWindow\s*=\s*0/ nocase wide ascii
        $d = /Win32_Process/ nocase wide ascii
        $e = /\.Create[ \t]*[\( ]/ nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $auto and $a and $b and $c and $d and $e
}

rule CERBER_Script_Vba_ShellcodeRunnerDeclares {
    meta:
        description = "VBA declarations of VirtualAlloc, RtlMoveMemory and CreateThread used to run shellcode in Office"
        author = "Cerber"
        family = "Vba.Shellcode"
        severity = "critical"
        score = 86
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $a = /Declare[ \t]+(PtrSafe[ \t]+)?Function[ \t]+(VirtualAlloc|ZwAllocateVirtualMemory)[ \t]+Lib[ \t]+"(kernel32|ntdll)"/ nocase wide ascii
        $b = /Declare[ \t]+(PtrSafe[ \t]+)?(Function|Sub)[ \t]+(RtlMoveMemory|CopyMemory|MoveMemory)[ \t]+Lib[ \t]+"(kernel32|ntdll)"/ nocase wide ascii
        $c = /Declare[ \t]+(PtrSafe[ \t]+)?Function[ \t]+(CreateThread|EnumSystemCodePages[AW]?|CreateTimerQueueTimer|EnumWindows)[ \t]+Lib[ \t]+"(kernel32|user32)"/ nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Vba_MacScriptDoShellScript {
    meta:
        description = "VBA on macOS using MacScript or AppleScriptTask to run a shell command that downloads or executes code"
        author = "Cerber"
        family = "Vba.MacOS"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $a = /MacScript[ \t]*\([ \t]*"do shell script[^\r\n]{0,200}(curl|python|bash|sh[ \t]+-c|osascript|nohup)/ nocase wide ascii
        $b = /#If[ \t]+Mac(Win32)?[ \t]+Then/ nocase wide ascii
        $c = /(Sub|Function)[ \t]+(AutoOpen|Auto_Open|Document_Open|Workbook_Open)[ \t]*\(/ nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and ($b or $c)
}

rule CERBER_Script_Vba_BinaryPayloadDropToTemp {
    meta:
        description = "VBA writing a binary blob to a TEMP or APPDATA path and running it from an auto-run macro"
        author = "Cerber"
        family = "Vba.Dropper"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $auto = /(Sub|Function)[ \t]+(AutoOpen|Auto_Open|AutoExec|Document_Open|Workbook_Open|Document_New)[ \t]*\(/ nocase wide ascii
        $env = /Environ\$?\(\s*"(TEMP|TMP|APPDATA|USERPROFILE|PUBLIC|LOCALAPPDATA)"\s*\)/ nocase wide ascii
        $open = /Open[ \t]+[^\r\n]{0,60}For[ \t]+Binary/ nocase wide ascii
        $put = /\bPut[ \t]+#/ nocase wide ascii
        $run = /(\bShell[ \t]*\(|[\r\n:][ \t]*(Call[ \t]+)?Shell[ \t]+[A-Za-z_"(]|ShellExecute[AW]?[ \t]*[\( ][ \t]*[A-Za-z_"0]|\.Run[ \t]*[\( ][ \t]*[A-Za-z_"'])/ nocase wide ascii
    condition:
        filesize < 5MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $auto and $env and $open and $put and $run
}

rule CERBER_Script_Vba_ShellApplicationObfuscated {
    meta:
        description = "Auto-run macro reaching Shell.Application ShellExecute with strings rebuilt by Chr, Replace or StrReverse"
        author = "Cerber"
        family = "Vba.Launcher"
        severity = "medium"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $auto = /(Sub|Function)[ \t]+(AutoOpen|Auto_Open|AutoExec|Document_Open|Workbook_Open|Document_New)[ \t]*\(/ nocase wide ascii
        $a = /CreateObject\(\s*"Shell\.Application"\s*\)/ nocase wide ascii
        $b = /\.ShellExecute[ \t]/ nocase wide ascii
        $c = /(Chr[$W]?\(\s*[0-9]{2,3}\s*\)\s*&|StrReverse\(|Replace\([^\r\n]{0,80},[^\r\n]{0,40},)/ nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $auto and $a and $b and #c >= 6
}

rule CERBER_Script_Vba_ExecuteExcel4MacroDropper {
    meta:
        description = "VBA that hands a payload to Excel 4.0 macro engine through ExecuteExcel4Macro"
        author = "Cerber"
        family = "Vba.Xlm"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $auto = /(Sub|Function)[ \t]+(AutoOpen|Auto_Open|AutoExec|Document_Open|Workbook_Open)[ \t]*\(/ nocase wide ascii
        $a = /ExecuteExcel4Macro[ \t]*\(?[ \t]*"?/ nocase wide ascii
        $b = /(EXEC|CALL|REGISTER|URLDownloadToFile|RUN)\(/ wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $auto and $a and $b
}

rule CERBER_Script_Vba_CallByNameShellObfuscation {
    meta:
        description = "Auto-run macro invoking Run or Exec through CallByName on a WScript.Shell object built from strings"
        author = "Cerber"
        family = "Vba.Obfuscation"
        severity = "medium"
        score = 68
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
    strings:
        $auto = /(Sub|Function)[ \t]+(AutoOpen|Auto_Open|AutoExec|Document_Open|Workbook_Open|Document_New)[ \t]*\(/ nocase wide ascii
        $a = /CallByName[ \t]*\(?[ \t]*[A-Za-z_]{1,20}[ \t]*,[ \t]*"?(Run|Exec)"?[ \t]*,[ \t]*VbMethod/ nocase wide ascii
        $b = /CreateObject[ \t]*\(/ nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $auto and $a and $b
}

rule CERBER_Script_Xlm_Sylk_MacroExec {
    meta:
        description = "SYLK spreadsheet carrying Excel 4.0 macro formulas that execute commands or call Win32 APIs"
        author = "Cerber"
        family = "Xlm.Sylk"
        severity = "high"
        score = 84
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    strings:
        $a = /;E=?(EXEC|CALL|REGISTER|RUN)\(/ nocase
        $b = /;E=?(HALT|FORMULA|GOTO|ALERT|WAIT)\(/ nocase
        $c = "URLDownloadToFile" nocase
        $d = /C;X[0-9]{1,3};Y[0-9]{1,5};/
    condition:
        uint32be(0) == 0x49443B50 and filesize < 2MB and $d and $a and ($b or $c)
}

rule CERBER_Script_Xlm_Biff_UrlDownloadRegister {
    meta:
        description = "Excel binary workbook whose 4.0 macro cells register URLDownloadToFile from urlmon"
        author = "Cerber"
        family = "Xlm.Biff"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    strings:
        $a = "URLDownloadToFileA"
        $b = /URLMon/ nocase
        $c = "JJCCJJ"
        $d = "URLDownloadToFileW"
    condition:
        uint32be(0) == 0xD0CF11E0 and filesize < 8MB and $b and ($a or $d) and $c
}

rule CERBER_Script_Xlm_Biff_Kernel32ShellcodeRegister {
    meta:
        description = "Excel binary workbook with macro cells registering VirtualAlloc, WriteProcessMemory and CreateThread"
        author = "Cerber"
        family = "Xlm.Biff"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    strings:
        $a = /Kernel32/ nocase
        $b = "VirtualAlloc"
        $c = "WriteProcessMemory"
        $d = "CreateThread"
        $e = "JJJJJ"
    condition:
        uint32be(0) == 0xD0CF11E0 and filesize < 8MB and $a and $b and $c and $d and $e
}

rule CERBER_Script_Xlm_MacrosheetXml_Exec {
    meta:
        description = "Excel macrosheet XML with formulas that call EXEC, REGISTER or CALL for command execution"
        author = "Cerber"
        family = "Xlm.Xml"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    strings:
        $a = /<(x:|xm:)?(macrosheet|ExcelWorkbook|Worksheet)[ >]/ nocase
        $b = /<f>[^<]{0,20}(EXEC|CALL|REGISTER|RUN)\([^<]{0,200}<\/f>/
        $c = /(URLDownloadToFile|cmd\.exe|powershell|regsvr32|rundll32|mshta|VirtualAlloc)/ nocase
        $d = /macrosheet|xmlns:xm=|xmlns:x="urn:schemas-microsoft-com:office:excel"/ nocase
    condition:
        filesize < 4MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $d and $b and $c
}

rule CERBER_Script_Xlm_WorkbookXml_HiddenAutoOpen {
    meta:
        description = "Workbook part defining Auto_Open together with a very hidden macro sheet"
        author = "Cerber"
        family = "Xlm.Xml"
        severity = "high"
        score = 68
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    strings:
        $a = /<definedName[^>]{0,40}name="_xlnm\.Auto_Open"/ nocase
        $b = /<sheet[^>]{0,80}state="veryHidden"/ nocase
        $c = /<workbook[ >]/ nocase
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Office_RemoteTemplateInjection {
    meta:
        description = "Office relationship that loads an attached template or OLE object from an http URL"
        author = "Cerber"
        family = "Office.TemplateInjection"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1221/"
    strings:
        $a = /relationships\/attachedTemplate"[^>]{0,120}Target="https?:\/\/[^"]{4,200}"/ nocase
        $b = /relationships\/oleObject"[^>]{0,120}Target="https?:\/\/[^"]{4,200}"[^>]{0,60}TargetMode="External"/ nocase
        $c = /relationships\/frame"[^>]{0,120}Target="https?:\/\/[^"]{4,200}"[^>]{0,60}TargetMode="External"/ nocase
        $d = /TargetMode="External"/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $d and 1 of ($a, $b, $c)
}

rule CERBER_Script_Office_RtfOle2LinkUrlMoniker {
    meta:
        description = "RTF carrying an OLE2Link object with a URL moniker to fetch remote content"
        author = "Cerber"
        family = "Rtf.Ole2Link"
        severity = "critical"
        score = 86
        date = "2026-09-29"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-0199"
    strings:
        $rtf = "{\\rtf"
        $a = "4f4c45324c696e6b" nocase
        $b = "e0c9ea79f9bace118c8200aa004ba90b" nocase
        $c = "\\objdata" nocase
        $d = "\\objupdate" nocase
        $e = "\\objautlink" nocase
    condition:
        filesize < 8MB and $rtf at 0 and $c and $a and $b and ($d or $e)
}

rule CERBER_Script_Office_RtfEquationEditorObject {
    meta:
        description = "RTF embedding an Equation Editor object, the delivery pattern of CVE-2017-11882 style exploits"
        author = "Cerber"
        family = "Rtf.EquationEditor"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2017-11882"
    strings:
        $rtf = "{\\rtf"
        $a = "4571756174696f6e2e33" nocase
        $b = "0002ce02" nocase
        $c = "\\objdata" nocase
        $d = "\\objemb" nocase
        $e = "d0cf11e0a1b11ae1" nocase
    condition:
        filesize < 8MB and $rtf at 0 and $c and $d and $e and ($a or $b)
}

rule CERBER_Script_Office_DdeFieldCommandExec {
    meta:
        description = "Word DDE or DDEAUTO field whose instruction launches cmd, PowerShell or mshta"
        author = "Cerber"
        family = "Office.Dde"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1559/002/"
    strings:
        $a = /(<w:instrText[^>]{0,40}>|\\fldinst[ \t]*\{?[ \t]*|w:instr=")[ \t]*DDE(AUTO)?[ \t]+["']?[^\r\n]{0,120}(cmd(\.exe)?|powershell(\.exe)?|mshta|regsvr32|certutil|wscript|cscript)/ nocase wide ascii
    condition:
        filesize < 8MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Bash_ReverseShell_DevTcp {
    meta:
        description = "Interactive bash whose stdio is redirected to /dev/tcp for a reverse connection"
        author = "Cerber"
        family = "Bash.ReverseShell"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = /(ba)?sh[ \t]+-i[ \t]*>&[ \t]*\/dev\/(tcp|udp)\/[A-Za-z0-9.\-_${}]{1,60}\/[0-9${}A-Za-z_]{1,8}[ \t]+0>&1/
        $b = /exec[ \t]+[0-9]<>[ \t]*\/dev\/tcp\/[A-Za-z0-9.\-_${}]{1,60}\/[0-9${}A-Za-z_]{1,8}[ \t]*;[ \t]*(cat[ \t]+<&[0-9][ \t]*\|[ \t]*)?while[ \t]+read[ \t]+[A-Za-z]{1,10}/
        $c = /0<&[0-9]{1,3}[ \t]*;[ \t]*exec[ \t]+[0-9]{1,3}<>[ \t]*\/dev\/tcp\/[A-Za-z0-9.\-_${}]{1,60}\/[0-9${}A-Za-z_]{1,8}[ \t]*;[ \t]*(ba)?sh[ \t]+<&[0-9]{1,3}[ \t]+>&[0-9]{1,3}/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Bash_ReverseShell_MkfifoNetcat {
    meta:
        description = "Named pipe relaying an interactive shell to netcat"
        author = "Cerber"
        family = "Bash.ReverseShell"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = /mkfifo[ \t]+\/tmp\/[A-Za-z0-9_.]{1,12}/
        $b = /\/bin\/(ba)?sh[ \t]+-i[ \t]+2>&1/
        $c = /\|[ \t]*(nc|ncat|netcat)[ \t]+[0-9A-Za-z.\-]{3,60}[ \t]+[0-9]{2,5}[ \t]*>/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Bash_ReverseShell_NetcatExec {
    meta:
        description = "nc or ncat started with -e or -c to execute a shell after connecting"
        author = "Cerber"
        family = "Bash.ReverseShell"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = /(nc|ncat|netcat)[ \t]+(-[a-z]+[ \t]+)*-e[ \t]+\/bin\/(ba)?sh[ \t]+[0-9A-Za-z.\-]{3,60}[ \t]+[0-9]{2,5}/
        $b = /(nc|ncat|netcat)[ \t]+[0-9A-Za-z.\-]{3,60}[ \t]+[0-9]{2,5}[ \t]+(-[a-z]+[ \t]+)*-e[ \t]+\/bin\/(ba)?sh/
        $c = /(nc|ncat|netcat)[ \t]+(-[a-z]+[ \t]+)*-c[ \t]+["']?(ba)?sh[ \t]+[0-9A-Za-z.\-]{3,60}[ \t]+[0-9]{2,5}/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Bash_ReverseShell_PythonPerlRubyPhp_OneLiners {
    meta:
        description = "Interpreter one-liners that open a socket and duplicate it over the standard streams"
        author = "Cerber"
        family = "Bash.ReverseShell"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $py = /python[0-9.]*[ \t]+-c[ \t]+["']import[ \t]+socket[,;]?[ \t]*(subprocess|os)[^\r\n]{0,200}dup2\(/
        $pl = /perl[ \t]+-e[ \t]+["']use[ \t]+Socket;[^\r\n]{0,240}(sockaddr_in|inet_aton)[^\r\n]{0,240}(exec|system)\(["']?\/bin\/(ba)?sh/
        $rb = /ruby[ \t]+-rsocket[ \t]+-e[ \t]*["'][^\r\n]{0,80}TCPSocket\.(new|open)\(/
        $ph = /php[ \t]+-r[ \t]+["']\$sock=fsockopen\([^\r\n]{0,80}\);[^\r\n]{0,40}(exec|shell_exec|system|passthru|popen|proc_open)\(["']?\/bin\/(ba)?sh/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Bash_ReverseShell_SocatExecPty {
    meta:
        description = "socat connecting out with an EXEC bash pty address"
        author = "Cerber"
        family = "Bash.ReverseShell"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = /socat[ \t]+[^\r\n]{0,10}(tcp|TCP)(4|6)?:[0-9A-Za-z.\-]{3,60}:[0-9]{2,5}[ \t]+EXEC:['"]?(ba)?sh[ \t]+-li['"]?,pty/ nocase
        $b = /socat[ \t]+(exec|EXEC):['"]?(ba)?sh[ \t]+-li['"]?,pty,stderr,setsid,sigint,sane[ \t]+(tcp|TCP)(4|6)?:/ nocase
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Bash_ReverseShell_AwkOpensslTelnetZsh {
    meta:
        description = "Less common reverse shell primitives: awk /inet/tcp, openssl s_client fifo, telnet pipe and zsh ztcp"
        author = "Cerber"
        family = "Bash.ReverseShell"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = /\/inet\/tcp\/0\/[0-9A-Za-z.\-]{3,60}\/[0-9]{2,5}/
        $a2 = /\|&[ \t]*s[ \t]*;/
        $b = /openssl[ \t]+s_client[ \t]+-quiet[ \t]+-connect[ \t]+[0-9A-Za-z.\-]{3,60}:[0-9]{2,5}/
        $b2 = /mkfifo[ \t]+\/tmp\/[A-Za-z0-9_.]{1,12}/
        $c = /telnet[ \t]+[0-9A-Za-z.\-]{3,60}[ \t]+[0-9]{2,5}[ \t]*\|[ \t]*\/bin\/(ba)?sh[ \t]*\|[ \t]*telnet/
        $d = /zmodload[ \t]+zsh\/net\/tcp[ \t]*&&[ \t]*ztcp[ \t]/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($a and $a2) or ($b and $b2) or $c or $d)
}

rule CERBER_Script_Bash_CurlPipeShell_RawIpv4 {
    meta:
        description = "curl or wget streaming a script from a bare public IPv4 address straight into a shell"
        author = "Cerber"
        family = "Bash.Dropper"
        severity = "high"
        score = 68
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = /(curl|wget)[ \t]+[^\r\n|]{0,60}https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:\/][^\r\n|]{0,100}\|[ \t]*(sudo[ \t]+)?(ba|z|da)?sh\b/
        $lo = /https?:\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0|10\.[0-9]{1,3}\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and not $lo
}

rule CERBER_Script_Bash_CurlPipeShell_PasteOrTunnelHost {
    meta:
        description = "Script piped into a shell from paste sites, anonymous file hosts, chat CDNs or dynamic DNS domains"
        author = "Cerber"
        family = "Bash.Dropper"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = /(curl|wget)[ \t]+[^\r\n|]{0,60}(pastebin\.com\/raw|paste\.ee\/r|hastebin\.com\/raw|transfer\.sh|termbin\.com|0x0\.st|ix\.io|sprunge\.us|cdn\.discordapp\.com\/attachments|[a-z0-9\-]{3,30}\.(duckdns\.org|ngrok\.io|ngrok-free\.app|hopto\.org|ddns\.net|zapto\.org|trycloudflare\.com))[^\r\n|]{0,100}\|[ \t]*(sudo[ \t]+)?(ba|z|da)?sh\b/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Bash_Base64DecodePipeShell {
    meta:
        description = "A long base64 literal decoded and piped or evaluated by a shell"
        author = "Cerber"
        family = "Bash.Obfuscation"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = /echo[ \t]+["']?[A-Za-z0-9+\/=]{60,}["']?[ \t]*\|[ \t]*base64[ \t]+(-d|--decode|-D)[ \t]*\|[ \t]*(sudo[ \t]+)?(ba|z|da)?sh\b/
        $b = /(ba|z|da)?sh[ \t]+-c[ \t]+["']\$\(echo[ \t]+[A-Za-z0-9+\/=]{60,}[ \t]*\|[ \t]*base64[ \t]+(-d|--decode|-D)\)["']/
        $c = /eval[ \t]+["']?\$\(echo[ \t]+["']?[A-Za-z0-9+\/=]{60,}["']?[ \t]*\|[ \t]*base64[ \t]+(-d|--decode|-D)\)/
        $d = /base64[ \t]+(-d|--decode|-D)[ \t]*<<<[ \t]*["'][A-Za-z0-9+\/=]{60,}["'][ \t]*\|[ \t]*(ba|z|da)?sh\b/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Bash_DownloadChmodExecTmp_Nohup {
    meta:
        description = "Download into a world-writable directory, chmod and background execution in one command chain"
        author = "Cerber"
        family = "Bash.Dropper"
        severity = "medium"
        score = 55
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = /(wget|curl)[ \t]+[^\r\n;&|]{0,120}(\/tmp|\/var\/tmp|\/dev\/shm)\/[A-Za-z0-9_.\-]{1,30}[ \t]*(;|&&)[ \t]*chmod[ \t]+(\+x|7[0-7][0-7])[ \t]+(\/tmp|\/var\/tmp|\/dev\/shm)\/[A-Za-z0-9_.\-]{1,30}[ \t]*(;|&&)[ \t]*(nohup[ \t]+)?(\.\/|\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)[A-Za-z0-9_.\-]{0,30}[^\r\n]{0,40}(&[ \t]*$|&[ \t]*[;\r\n]|>[ \t]*\/dev\/null)/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Bash_MiraiStyle_BinsLoader {
    meta:
        description = "Multi-directory cd chain followed by wget/tftp download and chmod 777 typical of IoT botnet loaders"
        author = "Cerber"
        family = "Bash.Botnet"
        severity = "high"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = /cd[ \t]+\/tmp[ \t]*\|\|[ \t]*cd[ \t]+\/var\/(run|tmp)[ \t]*\|\|[ \t]*cd[ \t]+\/(mnt|dev\/shm)/
        $b = /chmod[ \t]+(777|\+x)[ \t]/
        $c = /(wget|curl|tftp|ftpget|busybox[ \t]+wget)[ \t]/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Bash_BusyboxBotTelnetProbe {
    meta:
        description = "Busybox applet probing strings used by Mirai-family telnet brute-force loaders"
        author = "Cerber"
        family = "Bash.Botnet"
        severity = "high"
        score = 82
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = "/bin/busybox MIRAI"
        $b = "/bin/busybox ECCHI"
        $c = "/bin/busybox KAMI"
        $d = "/bin/busybox hello"
        $e = /cat[ \t]+\/proc\/mounts;[ \t]*\/bin\/busybox/
        $f = /echo[ \t]+-e[ \t]+["']\\x6b\\x61\\x6d\\x69["'][ \t]*>/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Bash_Kinsing_Kdevtmpfsi {
    meta:
        description = "Kinsing cryptominer installer names its fake kernel worker kdevtmpfsi"
        author = "Cerber"
        family = "Bash.Kinsing"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/software/S0599/"
    strings:
        $a = "kdevtmpfsi"
        $b = "kinsing"
        $c = "kthreaddi"
        $d = /(pkill|killall|kill)[ \t]+(-9[ \t]+)?(-f[ \t]+)?kdevtmpfsi/
        $e = /\/(tmp|var\/tmp|dev\/shm)\/(kdevtmpfsi|kinsing)/
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and 1 of ($b, $c, $d, $e)
}

rule CERBER_Script_Bash_TeamTNT_Scripts {
    meta:
        description = "Shell script tied to TeamTNT tooling: process hider preload, masscan sweeps and cloud credential harvesting"
        author = "Cerber"
        family = "Bash.TeamTNT"
        severity = "high"
        score = 86
        date = "2026-09-29"
        reference = "https://attack.mitre.org/groups/G0139/"
    strings:
        $a = "TeamTNT" nocase
        $b = "libprocesshider"
        $c = "chimaera" nocase
        $d = "ld.so.preload"
        $e = /\.aws\/credentials/
        $f = "xmrig" nocase
        $g = "masscan"
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and 2 of ($b, $c, $d, $e, $f, $g)
}

rule CERBER_Script_Bash_CloudCredentialSweeper_Exfil {
    meta:
        description = "Script that gathers several cloud and developer credential files and uploads them"
        author = "Cerber"
        family = "Bash.CredentialTheft"
        severity = "high"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1552/001/"
    strings:
        $a = ".aws/credentials"
        $b = ".docker/config.json"
        $c = ".kube/config"
        $d = ".ssh/id_rsa"
        $e = ".npmrc"
        $f = ".git-credentials"
        $g = ".s3cfg"
        $h = /gcloud\/(credentials\.db|legacy_credentials)/
        $x = /(curl[ \t]+[^\r\n]{0,80}(-F|--data-binary|-T|--upload-file)|wget[ \t]+[^\r\n]{0,40}--post-file|nc[ \t]+[0-9A-Za-z.\-]{3,60}[ \t]+[0-9]{2,5}[ \t]*<)/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 4 of ($a, $b, $c, $d, $e, $f, $g, $h) and $x
}

rule CERBER_Script_Bash_XmrigMinerInstaller {
    meta:
        description = "Installer script that fetches xmrig, configures stratum pools and starts it in the background"
        author = "Cerber"
        family = "Bash.Cryptominer"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1496/"
        pua = true
    strings:
        $a = "xmrig" nocase
        $b = "--donate-level"
        $c = /stratum\+(tcp|ssl):\/\//
        $d = /(nohup|crontab|systemctl[ \t]+enable|chmod[ \t]+\+x)/
        $e = /(wget|curl)[ \t]/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $e and $d and ($b or $c)
}

rule CERBER_Script_Miner_XmrigConfigJson {
    meta:
        description = "XMRig style JSON configuration with pool credentials and donate level"
        author = "Cerber"
        family = "Miner.XmrigConfig"
        severity = "medium"
        score = 60
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1496/"
        pua = true
    strings:
        $a = "\"donate-level\""
        $b = "\"pools\""
        $c = "\"algo\""
        $d = "\"user\""
        $e = "\"pass\""
        $f = /"(rig-id|coin|randomx|cpu|huge-pages)"/
    condition:
        filesize < 64KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e and $f
}

rule CERBER_Script_Miner_StratumPoolCommandLine {
    meta:
        description = "Miner command line pointing at a well-known Monero pool over stratum with a wallet argument"
        author = "Cerber"
        family = "Miner.CommandLine"
        severity = "medium"
        score = 58
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1496/"
        pua = true
    strings:
        $a = /stratum\+(tcp|ssl):\/\/[A-Za-z0-9.\-]{0,40}(minexmr\.com|supportxmr\.com|nanopool\.org|moneroocean\.stream|2miners\.com|hashvault\.pro|c3pool\.com|herominers\.com|minergate\.com|f2pool\.com|nicehash\.com|unmineable\.com|xmrpool\.eu|monerohash\.com)/ nocase
        $b = /(-u|--user)[ \t]+["']?[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}/
        $c = /(-o|--url)[ \t]+stratum/
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and ($b or $c)
}

rule CERBER_Script_Bash_MinerCompetitorKiller {
    meta:
        description = "Script that terminates rival cryptominers and known miner process names"
        author = "Cerber"
        family = "Bash.Cryptominer"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1496/"
    strings:
        $a = /(pkill|killall)[ \t]+(-9[ \t]+)?(-f[ \t]+)?["']?(xmrig|minerd|kdevtmpfsi|kinsing|cpuminer|cryptonight|ddgs|sysupdate|networkservice|watchdogs|kworkerds|dbused|bioset|sustes|ksoftirqds|kthreaddk)/
        $b = /grep[ \t]+-E[ \t]+["'][^"'\r\n]{0,80}(xmrig|minerd|cryptonight)[^"'\r\n]{0,80}["'][^\r\n]{0,40}xargs[ \t]+kill[ \t]+-9/
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (#a >= 3 or $b)
}

rule CERBER_Script_Bash_CrontabDownloadPersistence {
    meta:
        description = "crontab or cron.d entry that re-downloads and pipes a script every few minutes"
        author = "Cerber"
        family = "Bash.Persistence"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1053/003/"
    strings:
        $a = /crontab[ \t]+-l[ \t]*(2>\/dev\/null|2>&1)?[ \t]*;[ \t]*echo[ \t]+["'][^\r\n"']{0,30}\*[^\r\n"']{0,60}(curl|wget)[^\r\n"']{0,160}(\|[ \t]*(ba)?sh|-O|-o)/
        $b = /echo[ \t]+["']?[^\r\n"']{0,20}\*[^\r\n"']{0,40}(root)?[^\r\n"']{0,10}(curl|wget)[^\r\n"']{0,160}\|[ \t]*(ba)?sh[^\r\n]{0,20}>{1,2}[ \t]*\/(etc\/cron\.(d|hourly|daily)|var\/spool\/cron)/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Bash_SystemdUnitFromTmpDropper {
    meta:
        description = "Script writing a systemd service that executes a binary from a temporary directory and restarts forever"
        author = "Cerber"
        family = "Bash.Persistence"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1543/002/"
    strings:
        $a = /(cat|echo|tee|printf)[^\r\n]{0,60}\/etc\/systemd\/system\/[A-Za-z0-9_.\-]{1,40}\.service/
        $b = /ExecStart=[ \t]*(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|\/var\/run\/|\/usr\/bin\/\.[A-Za-z0-9])[^\r\n]{0,80}/
        $c = "Restart=always"
        $d = /systemctl[ \t]+(enable|daemon-reload)/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Bash_SshAuthorizedKeysImplant_Immutable {
    meta:
        description = "Attacker public key appended to authorized_keys and protected with chattr +i or a sshd relaxation"
        author = "Cerber"
        family = "Bash.Persistence"
        severity = "high"
        score = 82
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1098/004/"
    strings:
        $a = /(echo|printf)[ \t]+["'](ssh-(rsa|ed25519)|ecdsa-sha2-nistp256)[ \t]+AAAA[A-Za-z0-9+\/=]{40,}[^\r\n"']{0,60}["'][ \t]*>{1,2}[ \t]*[~$A-Za-z\/.]{0,30}\.ssh\/authorized_keys/
        $b = /chattr[ \t]+\+[a-z]*i[a-z]*[ \t]+[^\r\n]{0,40}authorized_keys/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_Bash_LogWiping_AntiForensics {
    meta:
        description = "Several distinct log truncation and shell-history erasure commands combined in one script"
        author = "Cerber"
        family = "Bash.AntiForensics"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1070/002/"
    strings:
        $a = /rm[ \t]+-rf?[ \t]+\/var\/log\/\*/
        $b = /(cat[ \t]+\/dev\/null|echo[ \t]+-n|:)[ \t]*>[ \t]*\/var\/log\/(wtmp|btmp|lastlog|auth\.log|secure|messages|syslog)/
        $c = /unset[ \t]+HISTFILE|export[ \t]+HISTFILESIZE=0|export[ \t]+HISTSIZE=0|HISTFILE=\/dev\/null/
        $d = /ln[ \t]+-sf?[ \t]+\/dev\/null[ \t]+[~$A-Za-z\/.]{0,20}\.bash_history/
        $e = /shred[ \t]+(-[a-z]+[ \t]+)*\/var\/log\//
        $f = /sed[ \t]+-i[ \t]+["']\/[^\r\n"']{3,40}\/d["'][ \t]+\/var\/log\/(auth\.log|secure|syslog|messages|wtmp)/
        $g = /history[ \t]+-c/
        $h = />[ \t]*[~$A-Za-z\/.]{0,20}\.bash_history/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 3 of them
}

rule CERBER_Script_Bash_LdSoPreloadRootkitInstall {
    meta:
        description = "Shared object appended to /etc/ld.so.preload, optionally locked with chattr"
        author = "Cerber"
        family = "Bash.Rootkit"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1574/006/"
    strings:
        $a = /(echo|printf)[ \t]+["']?\/[A-Za-z0-9_\/.\-]{1,60}\.so["']?[ \t]*>{1,2}[ \t]*\/etc\/ld\.so\.preload/
        $b = /chattr[ \t]+(\+|-)[a-z]*i[a-z]*[ \t]+\/etc\/ld\.so\.preload/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_Bash_CloudMonitorRemoval_MinerPrep {
    meta:
        description = "Removal of Alibaba, Tencent and Huawei cloud security agents alongside a download or persistence step"
        author = "Cerber"
        family = "Bash.CryptominerPrep"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1496/"
    strings:
        $a = "/usr/local/aegis"
        $b = "quartz_uninstall.sh"
        $c = "aliyun-service"
        $d = "/usr/local/qcloud/stargate"
        $e = "/usr/local/qcloud/YunJing"
        $f = "hostguard"
        $g = "/usr/local/cloudmonitor"
        $h = /(curl|wget|crontab|xmrig|chattr)/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 3 of ($a, $b, $c, $d, $e, $f, $g) and $h
}

rule CERBER_Script_Bash_RedisCronOrSshKeyWrite {
    meta:
        description = "redis-cli commands that repoint the RDB dump directory at cron or .ssh to write a payload file"
        author = "Cerber"
        family = "Bash.RedisAbuse"
        severity = "high"
        score = 84
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1053/003/"
    strings:
        $a = /config[ \t]+set[ \t]+dir[ \t]+["']?(\/var\/spool\/cron(\/crontabs)?|\/etc\/cron\.d|\/root\/\.ssh|\/home\/[a-z]{1,20}\/\.ssh)/ nocase
        $b = /config[ \t]+set[ \t]+dbfilename[ \t]+["']?(root|authorized_keys|[a-z0-9]{1,12})/ nocase
        $c = /[\r\n; \t]save[\r\n; \t]/ nocase
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Bash_DockerPrivilegedChrootPipeShell {
    meta:
        description = "docker run with host filesystem mount and chroot that pipes a downloaded script into a shell"
        author = "Cerber"
        family = "Bash.ContainerEscape"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1611/"
    strings:
        $a = /docker[ \t]+(-H[ \t]+[^\r\n]{0,40}[ \t]+)?run[ \t]+[^\r\n]{0,120}(--privileged|-v[ \t]+\/:\/[a-z]{1,8})[^\r\n]{0,200}chroot[ \t]+\/[a-z]{1,8}[ \t]+[^\r\n]{0,200}(curl|wget)[^\r\n]{0,100}\|[ \t]*(ba)?sh/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Bash_SetuidBashBackdoor {
    meta:
        description = "Setting the setuid bit on a shell binary or its copy"
        author = "Cerber"
        family = "Bash.Backdoor"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = /chmod[ \t]+(u\+s|\+s|4[0-7]{3})[ \t]+\/(bin|usr\/bin)\/(ba|da|z)?sh\b/
        $b = /cp[ \t]+\/bin\/(ba)?sh[ \t]+[^\r\n;&]{1,60}[;&]+[ \t]*chmod[ \t]+(u\+s|\+s|4[0-7]{3})/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Bash_EtcPasswdRootAliasAppend {
    meta:
        description = "Second uid 0 account appended to /etc/passwd or created with useradd -o -u 0"
        author = "Cerber"
        family = "Bash.Backdoor"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1136/001/"
    strings:
        $a = /(echo|printf)[ \t]+["']?[A-Za-z0-9_.\-]{1,20}:[A-Za-z0-9.\/$]{1,120}:0:0:[^\r\n"']{0,30}:\/[a-z\/]{1,20}:\/bin\/(ba)?sh["']?[ \t]*>>[ \t]*\/etc\/passwd/
        $b = /useradd[ \t]+([^\r\n]{0,40}[ \t])?-o[ \t]+-u[ \t]*0[ \t]/
        $c = /useradd[ \t]+([^\r\n]{0,40}[ \t])?-u[ \t]*0[ \t]+-o[ \t]/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Bash_MinerHostTuning_SecurityStackOff {
    meta:
        description = "Miner host preparation: NMI watchdog off, hugepages tuning and SELinux, firewall and AppArmor disabled"
        author = "Cerber"
        family = "Bash.CryptominerPrep"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1496/"
    strings:
        $a = /nmi_watchdog/
        $c = /setenforce[ \t]+0/
        $d = /SELINUX=disabled/
        $e = /(service[ \t]+iptables[ \t]+stop|systemctl[ \t]+stop[ \t]+firewalld|ufw[ \t]+disable|iptables[ \t]+-F)/
        $f = /(service[ \t]+apparmor[ \t]+stop|systemctl[ \t]+(stop|disable)[ \t]+apparmor)/
        $g = /wrmsr[ \t]+-a[ \t]+0x1a4/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or $g) and 2 of ($c, $d, $e, $f)
}

rule CERBER_Script_Bash_ProcMountBindHide {
    meta:
        description = "Bind-mounting an empty directory over /proc/PID to hide a process from ps"
        author = "Cerber"
        family = "Bash.Rootkit"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1574/006/"
    strings:
        $a = /mount[ \t]+-o[ \t]+bind[ \t]+[^\r\n]{1,40}[ \t]+\/proc\/[0-9$\{\}A-Za-z_]{1,20}/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Bash_EsxiRansomwareVmKill {
    meta:
        description = "ESXi script that force-kills virtual machines and touches datastore disk images"
        author = "Cerber"
        family = "Bash.Ransomware"
        severity = "high"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1486/"
    strings:
        $a = /esxcli[ \t]+vm[ \t]+process[ \t]+kill[ \t]+(--type|-t)=?[ \t]*(force|hard|soft)/
        $b = "/vmfs/volumes"
        $c = /\.(vmdk|vmx|vmsn|vswp|nvram)/
        $d = /vim-cmd[ \t]+vmsvc\/(getallvms|power\.off)/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and ($c or $d)
}

rule CERBER_Script_Bash_LinuxRansomEncryptLoop {
    meta:
        description = "find plus openssl enc loop that encrypts many files in place and then deletes originals"
        author = "Cerber"
        family = "Bash.Ransomware"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1486/"
    strings:
        $a = /find[ \t]+\/[^\r\n]{0,200}-name[ \t]+["']?\*\.[a-z0-9]{2,5}["']?[^\r\n]{0,200}-exec/
        $b = /openssl[ \t]+enc[ \t]+-aes-256-cbc[^\r\n]{0,120}(-in|-pass)/
        $c = /(rm[ \t]+-f|shred)[ \t]/
        $d = /(ransom|bitcoin|BTC|your files|decrypt)/ nocase
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Bash_MacOS_HiddenPasswordPromptAuthonly {
    meta:
        description = "osascript hidden-answer password dialog validated with dscl authonly, as used by macOS stealers"
        author = "Cerber"
        family = "Bash.MacOSStealer"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1056/002/"
    strings:
        $a = "with hidden answer" nocase
        $b = /dscl[ \t]+(\.|\/Local\/Default)[ \t]+-?authonly/ nocase
        $c = "display dialog" nocase
        $d = /(curl|ditto|zip)[ \t]/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Bash_MacOS_ChromeSafeStorageKeychainDump {
    meta:
        description = "security find-generic-password reading Chrome Safe Storage combined with archiving or upload"
        author = "Cerber"
        family = "Bash.MacOSStealer"
        severity = "medium"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1555/001/"
    strings:
        $a = /security[ \t]+find-generic-password[ \t]+[^\r\n]{0,40}Chrome/ nocase
        $b = "Chrome Safe Storage"
        $c = "Login Data"
        $d = /(curl|ditto|zip)[ \t]/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Python_ExecZlibBase64Blob {
    meta:
        description = "exec of a decompressed base64 literal chain typical of packed stealers and droppers"
        author = "Cerber"
        family = "Python.Obfuscated"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /exec\([ \t]*(zlib|bz2|lzma|gzip)\.decompress\([ \t]*base64\.b64decode\([ \t]*(b)?["'][A-Za-z0-9+\/=]{80,}["']/
        $b = /exec\([ \t]*(zlib|bz2|lzma|gzip)\.decompress\([ \t]*base64\.b(64|85)decode\([ \t]*\(?[ \t]*(b)?["'][A-Za-z0-9+\/=]{80,}["'][ \t]*\)?[ \t]*\[[ \t]*::[ \t]*-1[ \t]*\]/
        $c = /exec\([ \t]*base64\.b64decode\([ \t]*(b)?["'][A-Za-z0-9+\/=]{120,}["'][ \t]*\)[ \t]*\)/
    condition:
        filesize < 5MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Python_ImportDunderZlibExec {
    meta:
        description = "exec chains built from __import__ calls or reversed lambdas to hide zlib and base64 decoding"
        author = "Cerber"
        family = "Python.Obfuscated"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /exec\([ \t]*__import__\([ \t]*["']zlib["'][ \t]*\)\.decompress\([ \t]*__import__\([ \t]*["']base64["'][ \t]*\)\.b64decode\(/
        $b = /lambda[ \t]+__?[ \t]*:[ \t]*__import__\([ \t]*["']zlib["'][ \t]*\)\.decompress\([ \t]*__import__\([ \t]*["']base64["'][ \t]*\)\.b64decode\([ \t]*__?[ \t]*\[[ \t]*::[ \t]*-1[ \t]*\]/
        $c = /exec\([ \t]*\([ \t]*_[ \t]*\)\([ \t]*b?["'][A-Za-z0-9+\/=]{40,}["']/
        $d = /__import__\([ \t]*["']marshal["'][ \t]*\)\.loads\([ \t]*__import__\([ \t]*["']zlib["'][ \t]*\)\.decompress\(/
    condition:
        filesize < 5MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Python_MarshalCompileExecDecoded {
    meta:
        description = "exec or eval of compile() or marshal.loads() fed by base64 or zlib decoded data"
        author = "Cerber"
        family = "Python.Obfuscated"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /exec\([ \t]*marshal\.loads\([ \t]*(zlib\.decompress\([ \t]*)?base64\.b64decode\([ \t]*(b)?["'][A-Za-z0-9+\/=]{60,}["']/
        $b = /(exec|eval)\([ \t]*compile\([ \t]*(zlib\.decompress\([ \t]*)?base64\.b64decode\([ \t]*(b)?["'][A-Za-z0-9+\/=]{60,}["'][^\r\n]{0,60}["']exec["']/
        $c = /exec\([ \t]*marshal\.loads\([ \t]*b?["']\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/
    condition:
        filesize < 5MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Python_ReverseShell_Dup2Pty {
    meta:
        description = "Python socket reverse shell that duplicates the socket over stdio and spawns a shell"
        author = "Cerber"
        family = "Python.ReverseShell"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = /socket\.socket\(/
        $b = /\.connect\(\([ \t]*[^\r\n\)]{2,70}\)\)/
        $c = /os\.dup2\([ \t]*\w{1,10}\.fileno\(\)[ \t]*,[ \t]*[012][ \t]*\)/
        $d = /(subprocess\.(call|Popen)\([ \t]*\[[ \t]*["'](\/bin\/)?(ba)?sh["']|pty\.spawn\([ \t]*["'](\/bin\/)?(ba)?sh["']|os\.system\([ \t]*["'](\/bin\/)?(ba)?sh)/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and ((#c >= 3 and $d) or (#c >= 3 and #b >= 1 and $d))
}

rule CERBER_Script_Python_ReverseShell_CdRecvLoop {
    meta:
        description = "Tutorial-style Python reverse shell handling cd and command output in a recv loop"
        author = "Cerber"
        family = "Python.ReverseShell"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = /\[:2\]\.decode\([ \t]*["']utf-8["'][ \t]*\)[ \t]*==[ \t]*["']cd["']/
        $b = /os\.chdir\(/
        $c = /subprocess\.Popen\(/
        $d = /\.recv\([ \t]*[0-9]{3,5}[ \t]*\)/
        $e = /shell[ \t]*=[ \t]*True/
        $f = /\.connect\(/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e and $f
}

rule CERBER_Script_Python_DiscordWebhookInfostealer {
    meta:
        description = "Python script posting stolen browser or Discord data to a Discord webhook"
        author = "Cerber"
        family = "Python.Infostealer"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/006/"
    strings:
        $w = /discord(app)?\.com\/api\/webhooks\/[0-9]{15,20}\/[A-Za-z0-9_\-]{20,80}/
        $a = "Login Data"
        $b = /Local Storage[\\\/]+leveldb/
        $c = "os_crypt"
        $d = "CryptUnprotectData"
        $e = "Cookies"
        $f = "wallet" nocase
        $g = /requests\.(post|get)\(|urllib\.request/
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $w and $g and 2 of ($a, $b, $c, $d, $e, $f)
}

rule CERBER_Script_Python_DiscordTokenGrabberRegex {
    meta:
        description = "Discord token regex fragments together with Local Storage leveldb scanning"
        author = "Cerber"
        family = "Python.DiscordGrabber"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/006/"
    strings:
        $a = /mfa\\\.\[[^\]]{2,20}\]\{84\}/
        $b = /\[[\\wA-Za-z0-9_\-]{2,20}\]\{24\}\\\.\[[\\wA-Za-z0-9_\-]{2,20}\]\{6\}\\\.\[[\\wA-Za-z0-9_\-]{2,20}\]\{2[5-8]\}/
        $c = "leveldb" nocase
        $d = "Local Storage" nocase
        $e = ".ldb"
        $f = "dQw4w9WgXcQ:"
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or $b) and ($c or $d or $e or $f)
}

rule CERBER_Script_Python_TelegramBotExfilStealer {
    meta:
        description = "Stealer that sends collected browser, cookie or wallet files through the Telegram Bot API"
        author = "Cerber"
        family = "Python.Infostealer"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/006/"
    strings:
        $a = /api\.telegram\.org\/bot[0-9A-Za-z:_\-{}%]{0,60}\/send(Document|Message|Photo)/
        $b = "Login Data"
        $c = "Cookies"
        $d = "wallet.dat" nocase
        $e = "os_crypt"
        $f = "CryptUnprotectData"
        $g = /Local State/
        $h = /zipfile|shutil\.make_archive/
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $h and 2 of ($b, $c, $d, $e, $f, $g)
}

rule CERBER_Script_Python_ChromiumDecryptWithExfil {
    meta:
        description = "Chromium Login Data plus os_crypt encrypted_key decryption combined with a network or mail exfil channel"
        author = "Cerber"
        family = "Python.Infostealer"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/006/"
    strings:
        $a = "Login Data"
        $b = "Local State"
        $c = "os_crypt"
        $d = "encrypted_key"
        $e = "CryptUnprotectData"
        $f = /(requests\.post|smtplib\.SMTP|ftplib\.FTP|api\.telegram\.org|discord(app)?\.com\/api\/webhooks|pastebin\.com\/api)/
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e and $f
}

rule CERBER_Script_Stealer_WalletExtensionIdList {
    meta:
        description = "Several crypto wallet browser extension IDs listed together, the target list of wallet stealers"
        author = "Cerber"
        family = "Infostealer.Wallets"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1555/003/"
    strings:
        $a1 = "nkbihfbeogaeaoehlefnkodbefgpgknn"
        $a2 = "ejbalbakoplchlghecdalmeeeajnimhm"
        $a3 = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
        $a4 = "fhbohimaelbohpjbbldcngcnapndodjp"
        $a5 = "hnfanknocfeofbddgcijnmhnfnkdnaad"
        $a6 = "aeachknmefphepccionboohckonoeemg"
        $a7 = "egjidjbpglichdcondbcbdnbeeppgdph"
        $a8 = "ibnejdfjmmkpcnlpebklmnkoeoihofec"
        $a9 = "fnjhmkhhmkbjkkabndcnnogagogbneec"
        $a10 = "dmkamcknogkgcdfhhbddcghachkejeap"
        $a11 = "amkmjjmmflddogmhpjloimipbofnfjih"
        $a12 = "mcohilncbfahbmgdjkbpemcciiolgcge"
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 4 of them 
}

rule CERBER_Script_Stealer_WalletPathSweep {
    meta:
        description = "Script enumerating several desktop wallet data folders and sending them out"
        author = "Cerber"
        family = "Infostealer.Wallets"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1555/003/"
    strings:
        $a = /exodus(\.wallet)?/ nocase
        $b = /Electrum[\\\/]+wallets/ nocase
        $c = "wallet.dat"
        $d = /Atomic[\\\/]+Local Storage/ nocase
        $e = "Coinomi" nocase
        $f = "Guarda" nocase
        $g = /Ethereum[\\\/]+keystore/ nocase
        $h = /Bitcoin[\\\/]+wallets/ nocase
        $i = "Jaxx" nocase
        $x = /(requests\.post|webhook|api\.telegram\.org|smtplib|ftplib|https?\.request|UploadFile|Invoke-RestMethod)/ nocase
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 5 of ($a, $b, $c, $d, $e, $f, $g, $h, $i) and $x
}

rule CERBER_Script_Python_CryptoClipboardHijacker {
    meta:
        description = "Clipboard monitor that swaps copied Bitcoin and Ethereum addresses"
        author = "Cerber"
        family = "Python.Clipper"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/006/"
    strings:
        $a = /pyperclip\.paste\(\)|GetClipboardData\(/
        $b = /pyperclip\.copy\(|SetClipboardData\(/
        $c = /\[13\]\[a-km-zA-HJ-NP-Z1-9\]\{25,3[0-9]\}/
        $d = /0x\[a-fA-F0-9\]\{40\}/
        $e = /bc1\[[a-z0-9]{2,10}\]\{/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and ($d or $e)
}

rule CERBER_Script_Python_RansomwareFernetWalk {
    meta:
        description = "Python file encryptor walking the disk with Fernet, deleting originals and dropping a ransom note"
        author = "Cerber"
        family = "Python.Ransomware"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/006/"
    strings:
        $a = "cryptography.fernet"
        $b = "os.walk("
        $c = ".encrypt("
        $d = "os.remove("
        $e = /\.(docx|xlsx|pdf|jpg|png|txt|sql)/
        $f = /(ransom|bitcoin|BTC|your files (have been|are) (encrypted|locked)|README_TO_DECRYPT)/ nocase
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e and $f
}

rule CERBER_Script_Python_SetupPyInstallHookBeacon {
    meta:
        description = "setup.py with a custom install command that beacons hostname and user to a remote host"
        author = "Cerber"
        family = "Python.SupplyChain"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/006/"
    strings:
        $a = /cmdclass[ \t]*=[ \t]*\{/
        $b = /class[ \t]+\w{1,30}\((install|develop|egg_info)\)/
        $c = /socket\.gethostname\(\)/
        $d = /getpass\.getuser\(\)/
        $e = /(requests\.(get|post)\(|urllib\.request\.urlopen\(|urlopen\(|socket\.gethostbyname\()/
        $f = /(oastify\.com|burpcollaborator\.net|interact\.sh|pipedream\.net|webhook\.site|dnslog\.cn|ceye\.io|requestbin|ngrok\.io)/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e and $f
}

rule CERBER_Script_Python_CtypesWindowsShellcodeRunner {
    meta:
        description = "ctypes based VirtualAlloc, RtlMoveMemory and CreateThread shellcode loader"
        author = "Cerber"
        family = "Python.ShellcodeRunner"
        severity = "critical"
        score = 84
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1620/"
    strings:
        $a = /ctypes\.windll\.kernel32\.VirtualAlloc/
        $b = /ctypes\.windll\.kernel32\.RtlMoveMemory|ctypes\.memmove\(/
        $c = /ctypes\.windll\.kernel32\.CreateThread/
        $d = /WaitForSingleObject/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Python_ExecRemoteFetchedCode {
    meta:
        description = "exec or eval of code fetched directly from a hard-coded URL"
        author = "Cerber"
        family = "Python.Loader"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = /exec\([ \t]*(requests\.get|urllib\.request\.urlopen|urlopen|urllib2\.urlopen)\([ \t]*["']https?:\/\/[^"'\r\n]{4,150}["'][ \t]*(,[^)]{0,40})?\)[ \t]*\.(text|read\(\)|content)/
        $b = /eval\([ \t]*(requests\.get|urllib\.request\.urlopen|urlopen)\([ \t]*["']https?:\/\/[^"'\r\n]{4,150}["'][ \t]*(,[^)]{0,40})?\)[ \t]*\.(text|read\(\))/
        $c = /exec\([ \t]*compile\([ \t]*(requests\.get|urllib\.request\.urlopen)\([ \t]*["']https?:\/\/[^"'\r\n]{4,150}["']/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Python_KeyloggerWithRemoteExfil {
    meta:
        description = "pynput keyboard listener logging keystrokes together with mail, webhook, FTP or Telegram delivery"
        author = "Cerber"
        family = "Python.Keylogger"
        severity = "medium"
        score = 62
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1056/001/"
        pua = true
    strings:
        $a = "pynput.keyboard"
        $b = "Listener("
        $c = "on_press"
        $d = /(smtplib\.SMTP|discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|ftplib\.FTP)/
        $e = /(keylog|keystrokes|log_keys|key_log)/ nocase
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Python_AntiVmBlacklistStealer {
    meta:
        description = "Stealer anti-analysis process blacklist paired with webhook or Telegram exfiltration"
        author = "Cerber"
        family = "Python.Infostealer"
        severity = "medium"
        score = 62
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/006/"
    strings:
        $a1 = "vboxservice.exe" nocase
        $a2 = "vboxtray.exe" nocase
        $a3 = "vmtoolsd.exe" nocase
        $a4 = "vmwaretray.exe" nocase
        $a5 = "vmwareuser.exe" nocase
        $a6 = "wireshark.exe" nocase
        $a7 = "x64dbg.exe" nocase
        $a8 = "ollydbg.exe" nocase
        $a9 = "processhacker.exe" nocase
        $a10 = "fiddler.exe" nocase
        $a11 = "httpdebuggerui.exe" nocase
        $a12 = "pestudio.exe" nocase
        $w = /(discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot)/
        $h = /(HWID|getpass\.getuser|os\.getlogin|Login Data)/
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 7 of ($a*) and $w and $h
}

rule CERBER_Script_Python_RobloxCookieLogger {
    meta:
        description = "Roblox security cookie theft posted to a webhook"
        author = "Cerber"
        family = "Python.Infostealer"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/006/"
    strings:
        $a = ".ROBLOSECURITY"
        $b = /discord(app)?\.com\/api\/webhooks\//
        $c = /requests\.(post|get)\(/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Python_TelegramTdataStealer {
    meta:
        description = "Telegram Desktop tdata session theft keyed on the map file prefix"
        author = "Cerber"
        family = "Python.Infostealer"
        severity = "high"
        score = 82
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/006/"
    strings:
        $a = "D877F783D5D3EF8C"
        $b = "tdata" nocase
        $c = /(shutil\.(copy|copytree)|zipfile|requests\.post|make_archive)/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Python_GrabberOutputFileNames {
    meta:
        description = "Stealer that writes Passwords, Cookies, Autofills, Cards and Wallet dumps and ships an archive"
        author = "Cerber"
        family = "Python.Infostealer"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/006/"
    strings:
        $a = /["']Passwords?\.txt["']/ nocase
        $b = /["']Cookies?\.txt["']/ nocase
        $c = /["']Autofills?\.txt["']/ nocase
        $d = /["'](Credit ?Cards?|Cards?)\.txt["']/ nocase
        $e = /["']Wallets?["']/ nocase
        $f = /["'](Discord ?)?Tokens?\.txt["']/ nocase
        $g = /["']History\.txt["']/ nocase
        $h = /(zipfile|make_archive)/
        $i = /(requests\.post|webhook|api\.telegram\.org)/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 5 of ($a, $b, $c, $d, $e, $f, $g) and $h and $i
}

rule CERBER_Script_Python_LaZagneCredentialDumper {
    meta:
        description = "LaZagne credential recovery tool modules and banner"
        author = "Cerber"
        family = "Python.LaZagne"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://github.com/AlessandroZ/LaZagne"
        pua = true
    strings:
        $a = "LaZagne" nocase
        $b = "lazagne.config"
        $c = /softwares[\\\/.]+browsers/
        $d = "Alessandro ZANNI"
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and 1 of ($b, $c, $d)
}

rule CERBER_Script_Node_PackageJson_InstallHookDownloadExec {
    meta:
        description = "package.json lifecycle script that downloads with curl or wget and pipes to a shell or runs from tmp"
        author = "Cerber"
        family = "Node.SupplyChain"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1195/002/"
    strings:
        $a = /"(preinstall|install|postinstall|prepare)"[ \t]*:[ \t]*"[^"\r\n]{0,200}(curl|wget)[ \t][^"\r\n]{0,150}(\|[ \t]*(ba)?sh|-o[ \t]+\/tmp|>[ \t]*\/tmp|\|[ \t]*node)[^"\r\n]{0,80}"/
        $b = /"(preinstall|install|postinstall|prepare)"[ \t]*:[ \t]*"[^"\r\n]{0,120}(powershell|certutil|bitsadmin|mshta|nc[ \t]+-e|\/dev\/tcp\/|base64[ \t]+-d)[^"\r\n]{0,160}"/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Node_PackageJson_InstallHookEnvBeacon {
    meta:
        description = "package.json install hook that beacons whoami or hostname to an out-of-band collaborator domain"
        author = "Cerber"
        family = "Node.SupplyChain"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1195/002/"
    strings:
        $a = /"(preinstall|install|postinstall)"[ \t]*:[ \t]*"[^"\r\n]{0,120}(\$\(whoami\)|`whoami`|\$\(hostname\)|%USERNAME%|\$USER)[^"\r\n]{0,120}(oastify|burpcollaborator|interact\.sh|pipedream|requestbin|webhook\.site|dnslog|ceye\.io|canarytokens|ngrok|oast\.)/
        $b = /"(preinstall|install|postinstall)"[ \t]*:[ \t]*"[^"\r\n]{0,120}(oastify|burpcollaborator|interact\.sh|pipedream|requestbin|webhook\.site|dnslog|ceye\.io|canarytokens|ngrok|oast\.)[^"\r\n]{0,120}(\$\(whoami\)|`whoami`|\$\(hostname\)|%USERNAME%|\$USER)/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or $b)
}

rule CERBER_Script_Node_JS_EnvDumpExfilCollector {
    meta:
        description = "Node code that serialises process.env and posts it to a request-catcher or messaging webhook"
        author = "Cerber"
        family = "Node.SupplyChain"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1195/002/"
    strings:
        $a = /JSON\.stringify\(process\.env\)|Object\.(entries|keys)\(process\.env\)/
        $b = /(https?\.(request|get)\(|fetch\(|axios\.(post|get)\(|dns\.(resolve|lookup)[A-Za-z0-9]{0,5}\()/
        $c = /(webhook\.site|oastify\.com|burpcollaborator\.net|interact\.sh|pipedream\.net|requestbin|ngrok(-free)?\.(io|app)|discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|dnslog\.cn|ceye\.io|canarytokens)/
        $d = /os\.(hostname|userInfo)\(\)/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $d and
        // the env dump, the request and the collector host must be part of the same code, not
        // strings scattered across a multi-megabyte bundle
        for any i in (1..#a) : (
            for any j in (1..#c) : ( @c[j] > @a[i] - 3000 and @c[j] < @a[i] + 3000 ) and
            for any k in (1..#b) : ( @b[k] > @a[i] - 3000 and @b[k] < @a[i] + 3000 )
        )
}

rule CERBER_Script_Node_ShaiHuludWorm {
    meta:
        description = "Shai-Hulud npm worm indicators: exfil webhook GUID, repository names, bun bootstrap and TruffleHog use"
        author = "Cerber"
        family = "Node.ShaiHulud"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://securelist.com/shai-hulud-2-0/118214/"
    strings:
        $a = "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7"
        $b = /shai-hulud/ nocase
        $c = "Sha1-Hulud: The Second Coming"
        $d = "setup_bun.js"
        $e = "bun_environment.js"
        $f = "trufflehog" nocase
        $g = /npm[ \t]+publish/
        $h = "shai-hulud-workflow.yml"
        $i = "NPM_TOKEN"
    condition:
        filesize < 12MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or $c or ($d and $e) or $h or ($b and 1 of ($f, $g, $i)))
}

rule CERBER_Script_Node_S1ngularityAiCliRecon {
    meta:
        description = "Nx s1ngularity style payload that drives local AI CLIs in unsafe modes to hunt for secrets and wallets"
        author = "Cerber"
        family = "Node.S1ngularity"
        severity = "high"
        score = 82
        date = "2026-09-29"
        reference = "https://www.okta.com/blog/threat-intelligence/the-s1ngularity-attack--when-attackers-prompt-your-ai-agents-to/"
    strings:
        $a = "--dangerously-skip-permissions"
        $b = "--yolo"
        $c = "--trust-all-tools"
        $d = /s1ngularity/ nocase
        $e = "/tmp/inventory.txt"
        $f = /wallet|keystore|id_rsa/ nocase
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 2 of ($a, $b, $c) and 2 of ($d, $e, $f)
}

rule CERBER_Script_Node_ChalkNpmWalletHijack {
    meta:
        description = "Malicious payload from the September 2025 chalk and debug npm compromise that rewrites crypto addresses in fetch and XHR traffic"
        author = "Cerber"
        family = "Node.WalletHijack"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised"
    strings:
        $a = "checkethereumw"
        $b = "stealthProxyControl"
        $c = "runmask"
        $d = /newdloca[a-z]{0,4}/
        $e = "0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976"
        $f = "bc1qms4f8ys8c4z47h0q29nnmyekc9r74u5ypqw6wm"
        $g = "window.ethereum"
        $h = "XMLHttpRequest.prototype.send"
    condition:
        filesize < 8MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (2 of ($a, $b, $c, $d) or $e or $f or (1 of ($a, $b, $c) and $g and $h))
}

rule CERBER_Script_Node_ReverseShell_NetSpawnPipe {
    meta:
        description = "Node.js reverse shell spawning a shell and piping it to a net.Socket client"
        author = "Cerber"
        family = "Node.ReverseShell"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = /spawn\([ \t]*["'](\/bin\/(ba)?sh|cmd\.exe|powershell(\.exe)?)["']/
        $b = /net\.Socket\(\)/
        $c = /\.pipe\([ \t]*\w{1,10}\.stdin[ \t]*\)/
        $d = /\w{1,10}\.stdout\.pipe\([ \t]*\w{1,10}[ \t]*\)/
        $e = /\w{1,10}\.stderr\.pipe\([ \t]*\w{1,10}[ \t]*\)/
        $f = /\.connect\([ \t]*[0-9]{2,5}[ \t]*,/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e and $f
}

rule CERBER_Script_Node_ExecCurlPipeFromRawHost {
    meta:
        description = "child_process command string that pipes a script from a raw IP, paste site or dynamic DNS host into a shell"
        author = "Cerber"
        family = "Node.Dropper"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = /(exec|execSync|spawn|spawnSync)\([ \t]*[`"'][^`"'\r\n]{0,60}(curl|wget)[ \t]+[^`"'\r\n|]{0,60}https?:\/\/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|pastebin\.com\/raw|transfer\.sh|[a-z0-9\-]{3,30}\.(duckdns\.org|ngrok\.io|ngrok-free\.app|hopto\.org|ddns\.net|trycloudflare\.com))[^`"'\r\n|]{0,100}\|[ \t]*(ba)?sh/
        $lo = /https?:\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0|10\.[0-9]{1,3}\.|192\.168\.)/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and not $lo
}

rule CERBER_Script_Node_DiscordDesktopCoreInjection {
    meta:
        description = "Discord client injection patching discord_desktop_core to run JavaScript and ship harvested data to a webhook URL"
        author = "Cerber"
        family = "Node.DiscordInjection"
        severity = "high"
        score = 84
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1555/003/"
    strings:
        $a = "discord_desktop_core"
        $b = "executeJavaScript"
        $c = /discord(app)?\.com\/api\/webhooks\/[0-9]{15,20}\/[A-Za-z0-9_\-]{20,80}/
        $d = "BrowserWindow"
        $e = /(getToken|localStorage|token)/
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Node_DiscordTokenGrabberLeveldb {
    meta:
        description = "Node script walking leveldb folders of Discord, Chrome and Brave for tokens and posting them to a webhook"
        author = "Cerber"
        family = "Node.DiscordGrabber"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1555/003/"
    strings:
        $a = "Local Storage"
        $b = "leveldb"
        $c = ".ldb"
        $d = /(readdirSync|readFileSync)/
        $e = /discord(app)?\.com\/api\/webhooks\//
        $f = /mfa\\\.\[[^\]]{2,20}\]\{84\}|[\w\-]{24}\\\.[\w\-]{6}\\\.[\w\-]{27}/
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and ($e or $f)
}

rule CERBER_Script_Node_CredentialFileSweepExfil {
    meta:
        description = "Node code reading several credential stores (AWS, SSH, npm, kube, docker, git) and sending them over the network"
        author = "Cerber"
        family = "Node.CredentialTheft"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1195/002/"
    strings:
        $a = ".aws/credentials"
        $b = ".ssh/id_rsa"
        $c = ".npmrc"
        $d = ".kube/config"
        $e = ".docker/config.json"
        $f = ".git-credentials"
        $g = /os\.homedir\(\)/
        $h = /(https?\.request\(|fetch\(|axios\.(post|get)\(|dns\.resolve)/
        $x = /(webhook\.site|oastify\.com|burpcollaborator\.net|interact\.sh|pipedream\.net|discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|ngrok)/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 4 of ($a, $b, $c, $d, $e, $f) and $g and $h and $x
}

rule CERBER_Script_Js_MagecartCheckoutSkimmer {
    meta:
        description = "Payment skimmer that only activates on checkout URLs, reads card fields and ships them via image beacons or XHR"
        author = "Cerber"
        family = "Js.Skimmer"
        severity = "high"
        score = 72
        date = "2026-09-29"
    strings:
        $a = /(location|document\.URL|window\.location\.href)[^\r\n]{0,30}(indexOf|includes|match)\([ \t]*["'](checkout|onepage|payment|billing)["']/
        $b = /(cardnumber|cc-number|cc_number|card_number)/
        $c = /(cvv|cvc|cvv2|securitycode)/
        $d = "btoa("
        $e = /(new[ \t]+Image\(\)|sendBeacon\(|XMLHttpRequest)/
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Js_WalletDrainerTelegramNotify {
    meta:
        description = "Web3 drainer front end requesting approvals and notifying an operator through the Telegram Bot API"
        author = "Cerber"
        family = "Js.WalletDrainer"
        severity = "high"
        score = 72
        date = "2026-09-29"
    strings:
        $a = "setApprovalForAll"
        $b = "eth_requestAccounts"
        $c = /api\.telegram\.org\/bot[0-9A-Za-z:_\-]{0,60}\/sendMessage/
        $d = /(eth_sendTransaction|permit\(|increaseAllowance)/
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Php_ChinaChopper_EvalRequestVar {
    meta:
        description = "One-line PHP backdoor evaluating a request parameter (China Chopper, AntSword and clones)"
        author = "Cerber"
        family = "Php.ChinaChopper"
        severity = "critical"
        score = 92
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /@?(eval|assert)[ \t]*\([ \t]*@?\$_(POST|REQUEST|GET|COOKIE)[ \t]*\[[ \t]*\$?['"]?[A-Za-z0-9_]{1,20}['"]?[ \t]*\][ \t]*\)/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Php_EvalDecodedRequestVar {
    meta:
        description = "eval over a decoder chain whose input is a request variable"
        author = "Cerber"
        family = "Php.Webshell"
        severity = "critical"
        score = 92
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /eval[ \t]*\([ \t]*(@[ \t]*)?(gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode|convert_uudecode|rawurldecode|urldecode)[ \t]*\([ \t]*(@[ \t]*)?(base64_decode[ \t]*\([ \t]*)?(str_rot13[ \t]*\([ \t]*)?@?\$_(POST|REQUEST|GET|COOKIE)/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Php_ExecFunctionRequestParam {
    meta:
        description = "system, passthru, shell_exec, exec or popen called directly on a request variable"
        author = "Cerber"
        family = "Php.Webshell"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /\b(system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)[ \t]*\([ \t]*(stripslashes[ \t]*\([ \t]*)?@?\$_(GET|POST|REQUEST|COOKIE)[ \t]*\[/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Php_CmdVariableFromRequestExecuted {
    meta:
        description = "Command variable assigned from a request parameter and passed to a process execution function"
        author = "Cerber"
        family = "Php.Webshell"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /\$(cmd|c|command|exec|shell)[ \t]*=[ \t]*\(?[ \t]*@?\$_(GET|POST|REQUEST)\[[ \t]*['"](cmd|c|command|exec|shell|x)['"][ \t]*\][ \t]*\)?[ \t]*;/
        $b = /\b(system|passthru|shell_exec|exec|popen)[ \t]*\([ \t]*\$(cmd|c|command|exec|shell)\b/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_Php_VariableFunctionFromRequest {
    meta:
        description = "Request parameter used as the function name with another request parameter as its argument"
        author = "Cerber"
        family = "Php.Webshell"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /\$_(GET|POST|REQUEST|COOKIE)[ \t]*\[[ \t]*['"]?[A-Za-z0-9_]{1,20}['"]?[ \t]*\][ \t]*\([ \t]*\$_(GET|POST|REQUEST|COOKIE)[ \t]*\[/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Php_CallbackAssertOrCreateFunctionRequest {
    meta:
        description = "assert, create_function or preg_replace /e driven by request data"
        author = "Cerber"
        family = "Php.Webshell"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /create_function[ \t]*\([ \t]*['"]{2}[ \t]*,[ \t]*@?\$_(POST|REQUEST|GET)/
        $b = /preg_replace[ \t]*\([ \t]*['"]\/\.\*\/e['"][ \t]*,[ \t]*@?\$_(POST|REQUEST|GET)/
        $c = /array_map[ \t]*\([ \t]*['"]assert['"][ \t]*,[ \t]*@?\$_(POST|REQUEST|GET)/
        $d = /call_user_func[ \t]*\([ \t]*['"]assert['"][ \t]*,[ \t]*@?\$_(POST|REQUEST|GET)/
        $e = /(usort|uasort|uksort|array_filter|array_walk)[ \t]*\([^\r\n]{0,60}['"]assert['"][^\r\n]{0,60}\$_(POST|REQUEST|GET)/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Php_HexEscapedFunctionNames {
    meta:
        description = "PHP using hex-escaped eval, base64_decode, assert or system names alongside request variables"
        author = "Cerber"
        family = "Php.Obfuscated"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $php = "<?php"
        $a = /\\x65\\x76\\x61\\x6c/ nocase
        $b = /\\x62\\x61\\x73\\x65\\x36\\x34\\x5f\\x64\\x65\\x63\\x6f\\x64\\x65/ nocase
        $c = /\\x61\\x73\\x73\\x65\\x72\\x74/ nocase
        $d = /\\x73\\x79\\x73\\x74\\x65\\x6d/ nocase
        $e = /\\x67\\x7a\\x69\\x6e\\x66\\x6c\\x61\\x74\\x65/ nocase
        $f = /\\x73\\x68\\x65\\x6c\\x6c\\x5f\\x65\\x78\\x65\\x63/ nocase
        $g = /\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53/ nocase
        $r = /\$_(POST|REQUEST|GET|COOKIE)/
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $php and $r and 1 of ($a, $b, $c, $d, $e, $f, $g)
}

rule CERBER_Script_Php_GzinflateBase64EvalBlob {
    meta:
        description = "eval of a long gzinflate/gzuncompress plus base64 or rot13 blob hiding the real code"
        author = "Cerber"
        family = "Php.Obfuscated"
        severity = "high"
        score = 68
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $php = "<?php"
        $a = /eval[ \t]*\([ \t]*(gzinflate|gzuncompress)[ \t]*\([ \t]*base64_decode[ \t]*\([ \t]*['"][A-Za-z0-9+\/=]{200,}['"]/
        $b = /eval[ \t]*\([ \t]*str_rot13[ \t]*\([ \t]*gzinflate[ \t]*\([ \t]*str_rot13[ \t]*\([ \t]*base64_decode[ \t]*\([ \t]*['"][A-Za-z0-9+\/=]{100,}['"]/
        $c = /eval[ \t]*\([ \t]*gzinflate[ \t]*\([ \t]*str_rot13[ \t]*\([ \t]*base64_decode[ \t]*\([ \t]*['"][A-Za-z0-9+\/=]{100,}['"]/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $php and 1 of ($a, $b, $c)
}

rule CERBER_Script_Php_WsoShell_FilesMan {
    meta:
        description = "WSO web shell (FilesMan default action and login helpers)"
        author = "Cerber"
        family = "Php.WSO"
        severity = "critical"
        score = 92
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = "FilesMan"
        $b = "wsoLogin"
        $c = "WSOsetcookie"
        $d = "$default_action"
        $e = "wso_version"
        $f = "$auth_pass"
        $g = "wsoSecParam"
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and 2 of ($b, $c, $d, $e, $f, $g)
}

rule CERBER_Script_Php_C99Shell {
    meta:
        description = "c99shell family markers and helper function names"
        author = "Cerber"
        family = "Php.C99"
        severity = "critical"
        score = 92
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = "c99shell" nocase
        $b = "c99madshell" nocase
        $c = "c99_buff_prepare"
        $d = "c99getsource"
        $e = "c99sh_surl"
        $f = "c99_sess_put"
        $g = "c99fsearch"
        $h = "c99ftpbrutecheck"
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 2 of them
}

rule CERBER_Script_Php_R57Shell {
    meta:
        description = "r57shell family markers"
        author = "Cerber"
        family = "Php.R57"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = "r57shell" nocase
        $b = "r57 shell" nocase
        $c = "rst.void.ru"
        $d = "c99madshell" nocase
        $e = /r57(shell)?\.(php|txt)/ nocase
        $f = "@ini_restore(\"disable_functions\")"
        $g = "$downloaders = array('wget'"
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 2 of them
}

rule CERBER_Script_Php_B374kShell {
    meta:
        description = "b374k web shell banner and configuration variables"
        author = "Cerber"
        family = "Php.B374k"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = "b374k" nocase
        $b = "$s_pass"
        $c = "$s_ver"
        $d = "b374k-shell" nocase
        $e = "b374k/b374k" nocase
        $f = "$GLOBALS['module']"
        $g = "$s_auth"
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and 1 of ($b, $c, $d, $e, $f, $g)
}

rule CERBER_Script_Php_Weevely_Backdoor {
    meta:
        description = "Weevely3 stego agent with kh/kf key halves and referer plus Accept-Language transport"
        author = "Cerber"
        family = "Php.Weevely"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://github.com/epinna/weevely3"
    strings:
        $kh = /\$kh[ \t]*=[ \t]*["'][0-9a-f]{4}["']/
        $kf = /\$kf[ \t]*=[ \t]*["'][0-9a-f]{4}["']/
        $a = "HTTP_ACCEPT_LANGUAGE"
        $b = "HTTP_REFERER"
        $c = "parse_str("
        $d = "gzuncompress"
        $e = /preg_match_all\([ \t]*["']\/\(\[\\w\]\)\[\\w-\]\+\(\?:;q=0\.\(\[\\d\]\)\)\?,\?\/["']/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($kh and $kf and ($a or $b)) or ($a and $b and $c and $d) or $e)
}

rule CERBER_Script_Php_Godzilla_XorSessionPayload {
    meta:
        description = "Godzilla PHP shell with XOR-encoded session payload, getBasicsInfo handshake and md5 response framing"
        author = "Cerber"
        family = "Php.Godzilla"
        severity = "critical"
        score = 92
        date = "2026-09-29"
        reference = "https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/"
    strings:
        $a = "$payloadName"
        $b = "getBasicsInfo"
        $c = "3c6e0b8a9c15224a"
        $d = /\$[A-Za-z_]{1,10}\[\$i\+1&15\]/
        $e = /substr\(md5\(\$[A-Za-z_]{1,12}\.\$[A-Za-z_]{1,12}\),[ ]?0,[ ]?16\)/
        $f = /\$_SESSION\[\$[A-Za-z_]{1,12}\]/
        $g = /substr\(md5\(\$[A-Za-z_]{1,12}\.\$[A-Za-z_]{1,12}\),[ ]?16\)/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($b and ($a or $c or $f)) or ($e and $g) or ($e and $d) or ($a and $c))
}

rule CERBER_Script_Php_Behinder_AesPhpInput {
    meta:
        description = "Behinder PHP shell: default e45e329feb5d925b key, or session key k with the i+1&15 XOR loop, decoding php://input"
        author = "Cerber"
        family = "Php.Behinder"
        severity = "critical"
        score = 92
        date = "2026-09-29"
        reference = "https://github.com/rebeyond/Behinder"
    strings:
        $a = "e45e329feb5d925b"
        $b = "openssl_decrypt"
        $c = "php://input"
        $d = /(eval|assert)[ \t]*\(/
        $e = "$_SESSION['k']"
        $x = /\$[A-Za-z_]{1,10}\[\$i\+1&15\]/
        $b64a = "cGhwOi8vaW5wdXQ="
        $b64b = "b3BlbnNzbA=="
        $sk = /\$_SESSION\[[ ]?['"]k['"][ ]?\][ ]?=[ ]?\$[A-Za-z_]{1,10}/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($a and ($b or $c or $e) and $d) or ($x and $sk) or ($b64a and $b64b))
}

rule CERBER_Script_Php_AntSwordDefaultPassword {
    meta:
        description = "AntSword default connector password ant passed to eval, assert or a variable function"
        author = "Cerber"
        family = "Php.AntSword"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://github.com/AntSwordProject/antSword"
    strings:
        $a = /(eval|assert)[ \t]*\([ \t]*@?\$_(POST|GET|REQUEST)[ \t]*\[[ \t]*['"]ant['"][ \t]*\]/
        $e = /\$[A-Za-z_]\w{0,10}[ \t]*\([ \t]*@?\$_(POST|GET|REQUEST)[ \t]*\[[ \t]*['"]ant['"][ \t]*\]/
        $b = /@ini_set\([ \t]*["']display_errors["'][ \t]*,[ \t]*["']0["'][ \t]*\)[ \t]*;[ \t]*@set_time_limit\([ \t]*0[ \t]*\)/
        $c = /\$_(POST|GET|REQUEST)/
        $d = /(eval|assert)[ \t]*\(/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or $e or ($b and $c and $d))
}

rule CERBER_Script_Php_PentestmonkeyReverseShell {
    meta:
        description = "pentestmonkey php-reverse-shell layout with fsockopen and proc_open"
        author = "Cerber"
        family = "Php.ReverseShell"
        severity = "high"
        score = 90
        date = "2026-09-29"
        reference = "https://github.com/pentestmonkey/php-reverse-shell"
        pua = true
    strings:
        $a = "php-reverse-shell" nocase
        $b = "pentestmonkey" nocase
        $c = "fsockopen("
        $d = "proc_open("
        $e = "$shell = 'uname -a; w; id; /bin/sh -i';"
        $f = "Successfully opened reverse shell to"
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $c and $d and ($a or $b or $e or $f)
}

rule CERBER_Script_Php_UploaderWithPhpUname {
    meta:
        description = "Minimal upload shell that prints php_uname and writes uploaded files into the current directory"
        author = "Cerber"
        family = "Php.Uploader"
        severity = "medium"
        score = 58
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = "php_uname()"
        $b = "move_uploaded_file("
        $c = "getcwd()"
        $d = /enctype[ \t]*=[ \t]*["']multipart\/form-data["']/
        $e = /\$_FILES\[[ \t]*['"][A-Za-z0-9_]{1,20}['"][ \t]*\]\[[ \t]*['"]name['"][ \t]*\]/
        $f = /<input[^>]{0,40}type=["']submit["'][^>]{0,40}(upload|Upload)/
    condition:
        filesize < 20KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e and $f
}

rule CERBER_Script_Php_FilePutContentsRequestPayload {
    meta:
        description = "Writing request-supplied or base64-decoded request data to a file and including it"
        author = "Cerber"
        family = "Php.Dropper"
        severity = "high"
        score = 60
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /file_put_contents[ \t]*\([ \t]*[^,\r\n]{1,60},[ \t]*(base64_decode[ \t]*\([ \t]*)?@?\$_(POST|REQUEST|GET)[ \t]*\[/
        $b = /(include|require)(_once)?[ \t]*\(?[ \t]*['"]?\$?[A-Za-z_]{1,20}['"]?[ \t]*\)?[ \t]*;/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_Php_WordPressRogueAdminCreation {
    meta:
        description = "WordPress code creating an administrator from request input and logging the visitor in without authentication"
        author = "Cerber"
        family = "Php.WordPressBackdoor"
        severity = "high"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /wp_(create|insert)_user[ \t]*\(/
        $b = /['"]role['"][ \t]*=>[ \t]*['"]administrator['"]/
        $c = "wp_set_auth_cookie("
        $d = /\$_(GET|REQUEST|POST)\[/
        $e = /wp_signon|wp_set_current_user/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Php_HtaccessRunPhpInImages {
    meta:
        description = ".htaccess mapping image or text extensions to the PHP handler so uploaded files execute"
        author = "Cerber"
        family = "Php.Htaccess"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /(AddType|AddHandler)[ \t]+(application\/x-httpd-php[0-9]*|x-httpd-php[0-9]*|application\/x-httpd-php-source|php[0-9]?-script)[ \t]+[^\r\n]{0,40}\.(jpg|jpeg|png|gif|txt|ico|pdf|zip|css|js|bmp|webp)\b/ nocase
        $b = /SetHandler[ \t]+application\/x-httpd-php/ nocase
        $c = /<FilesMatch[ \t]+["'][^\r\n"']{0,60}\.(jpg|jpeg|png|gif|ico|txt)/ nocase
    condition:
        filesize < 8KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or ($b and $c))
}

rule CERBER_Script_Php_HtaccessSearchEngineRedirect {
    meta:
        description = ".htaccess SEO-spam redirect that only fires for visitors arriving from search engines"
        author = "Cerber"
        family = "Php.Htaccess"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /RewriteCond[ \t]+%\{HTTP_REFERER\}[ \t]+[^\r\n]{0,80}(google|yahoo|bing|msn|aol|ask)[^\r\n]{0,60}(google|yahoo|bing|msn|aol|ask)/ nocase
        $b = /RewriteRule[ \t]+[^\r\n]{1,30}[ \t]+https?:\/\/[^\r\n\[]{4,120}\[[^\]\r\n]{0,20}R=30[0-9][^\]\r\n]{0,20}\]/ nocase
    condition:
        filesize < 16KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_Asp_ChinaChopper_EvalRequest {
    meta:
        description = "Classic ASP one-liner executing request input with eval or execute"
        author = "Cerber"
        family = "Asp.ChinaChopper"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /<%[^%]{0,200}(eval|execute)[ \t(]+(Request|request)(\.(Form|QueryString|Item))?[ \t]*[\(\[][ \t]*["'][A-Za-z0-9_]{1,20}["'][ \t]*[\)\]]/ nocase
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Aspx_ChinaChopper_JscriptUnsafeEval {
    meta:
        description = "ASPX one-liner using JScript.NET eval with the unsafe security mode on a request item"
        author = "Cerber"
        family = "Aspx.ChinaChopper"
        severity = "critical"
        score = 95
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /eval[ \t]*\([ \t]*Request\.(Item|Form)[ \t]*\[[ \t]*["'][A-Za-z0-9_]{1,20}["'][ \t]*\][ \t]*,[ \t]*["']unsafe["'][ \t]*\)/ nocase
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Aspx_AssemblyLoadRequestPayload {
    meta:
        description = "ASPX that loads a .NET assembly directly from the request body or a base64 request field"
        author = "Cerber"
        family = "Aspx.Webshell"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /Assembly\.Load[ \t]*\([ \t]*Request\.BinaryRead\(/ nocase
        $b = /Assembly\.Load[ \t]*\([ \t]*(System\.)?Convert\.FromBase64String[ \t]*\([ \t]*(Request|HttpContext\.Current\.Request)(\.Form)?[ \t]*\[/ nocase
        $c = /Assembly\.Load[ \t]*\([ \t]*[A-Za-z_]{1,20}[ \t]*\)[^\r\n]{0,80}CreateInstance/ nocase
        $d = /Request\.(BinaryRead|Form|Item)/ nocase
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or $b or ($c and $d))
}

rule CERBER_Script_Aspx_ProcessStartCmdFromRequest {
    meta:
        description = "ASPX page starting cmd.exe with a command taken from the request and returning its output"
        author = "Cerber"
        family = "Aspx.Webshell"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /System\.Diagnostics\.Process/ nocase
        $b = /Request(\.Form|\.QueryString)?[ \t]*\[[ \t]*["'](cmd|c|command|exec)["'][ \t]*\]/ nocase
        $c = "cmd.exe" nocase
        $d = "RedirectStandardOutput" nocase
        $e = /<%@[ \t]*Page/ nocase
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $e and $a and $b and $c and $d
}

rule CERBER_Script_Aspx_AesAssemblyLoad_SessionKey {
    meta:
        description = "Behinder or Godzilla ASPX shell decrypting the request with AES and loading the assembly it carries (direct call or reflection)"
        author = "Cerber"
        family = "Aspx.Behinder"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /(Assembly\.Load\(|GetMethod\([ ]?["']Load["'])/ nocase
        $b = /(RijndaelManaged|AesManaged|AesCryptoServiceProvider)/ nocase
        $c = /CreateDecryptor\(/ nocase
        $d = /Session\[[ \t]*["'](k|payload)["'][ \t]*\]/ nocase
        $f = "e45e329feb5d925b"
        $g = "3c6e0b8a9c15224a"
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and ($f or $g or $d)
}

rule CERBER_Script_Aspx_AspxSpyFileManager {
    meta:
        description = "ASPXSpy style ASP.NET file manager and remote administration shell"
        author = "Cerber"
        family = "Aspx.AspxSpy"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = "ASPXSpy" nocase
        $b = /(ProcessStartInfo|Process\.Start\(|new[ ]+Process\()/
        $c = /(Registry|Microsoft\.Win32)/
        $d = /(SqlConnection|SqlExec)/
        $e = "Bin_Ver" nocase
        $f = /(FileStream|Directory\.GetFiles)/
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and 2 of ($c, $d, $e, $f)
}

rule CERBER_Script_Asp_ClassicCmdShell_FsoWscript {
    meta:
        description = "Classic ASP command shell using WScript.Shell exec on a form field and FileSystemObject helpers"
        author = "Cerber"
        family = "Asp.Webshell"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = "WScript.Shell" nocase
        $b = "Scripting.FileSystemObject" nocase
        $c = /Request\.(Form|QueryString)[ \t]*\([ \t]*["'][A-Za-z0-9_]{1,20}["'][ \t]*\)/ nocase
        $d = /\.(Exec|Run)[ \t]*\([ \t]*["']?[^\r\n]{0,40}cmd(\.exe)?[ \t]+\/c/ nocase
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Web_ReGeorgTunnel {
    meta:
        description = "reGeorg and Neo-reGeorg HTTP tunnel endpoint with its fixed banner and header names"
        author = "Cerber"
        family = "Web.ReGeorg"
        severity = "critical"
        score = 88
        date = "2026-09-29"
        reference = "https://github.com/sensepost/reGeorg"
        pua = true
    strings:
        $a = "Georg says, 'All seems fine'"
        $b = "X-CMD"
        $c = "X-STATUS"
        $d = "X-TARGET"
        $e = "X-ERROR"
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and 1 of ($b, $c, $d, $e)
}

rule CERBER_Script_Jsp_RuntimeExecRequestParameter {
    meta:
        description = "Runtime.exec or ProcessBuilder fed directly by request.getParameter"
        author = "Cerber"
        family = "Jsp.Webshell"
        severity = "critical"
        score = 92
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /Runtime\.getRuntime\(\)\.exec[ \t]*\([ \t]*(new[ \t]+String[ \t]*\[\][ \t]*\{[^}]{0,80}\}[ \t]*,[ \t]*)?request\.getParameter[ \t]*\(/
        $b = /new[ \t]+ProcessBuilder[ \t]*\([^;\r\n]{0,80}request\.getParameter[ \t]*\(/
        $c = /Runtime\.getRuntime\(\)\.exec[ \t]*\([ \t]*(new[ \t]+String[ \t]*\[\][ \t]*\{[^}]{0,80})?["']?(cmd(\.exe)?|\/bin\/(ba)?sh)["']?[ \t]*,[ \t]*["'](\/c|-c)["'][ \t]*,[ \t]*request\.getParameter/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Jsp_Behinder_ClassLoaderAes {
    meta:
        description = "Behinder JSP shell: ClassLoader subclass exposing defineClass and AES decryption of the request body"
        author = "Cerber"
        family = "Jsp.Behinder"
        severity = "critical"
        score = 92
        date = "2026-09-29"
        reference = "https://github.com/rebeyond/Behinder"
    strings:
        $a = /class[ \t]+[A-Za-z]{1,3}[ \t]+extends[ \t]+ClassLoader/
        $b = /defineClass[ \t]*\([ \t]*[A-Za-z]{1,4}[ \t]*,[ \t]*0[ \t]*,[ \t]*[A-Za-z]{1,4}\.length/
        $c = /Cipher\.getInstance\([ \t]*["']AES/
        $d = "e45e329feb5d925b"
        $e = /session\.putValue\([ \t]*["']u["']/
        $f = /request\.get(Reader|InputStream)\(\)/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($a and $b and $c and ($e or $f)) or ($d and $a))
}

rule CERBER_Script_Jsp_Godzilla_ClassLoaderMd5 {
    meta:
        description = "Godzilla JSP shell: ClassLoader subclass, AES, session payload attribute and md5 response framing (default or custom key)"
        author = "Cerber"
        family = "Jsp.Godzilla"
        severity = "critical"
        score = 92
        date = "2026-09-29"
        reference = "https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/"
    strings:
        $a = "3c6e0b8a9c15224a"
        $b = "extends ClassLoader"
        $c = "defineClass"
        $d = /(getSession\(\)|session)\.(set|get)Attribute\([ \t]*["']payload["']/
        $e = "MessageDigest"
        $f = /md5\.substring\([ ]?0[ ]?,[ ]?16[ ]?\)/
        $g = "Cipher"
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $b and $c and (($a) or ($d and ($e or $g)) or ($f and $g))
}

rule CERBER_Script_Jsp_TomcatMemoryShell_FilterInject {
    meta:
        description = "JSP that registers a filter into Tomcat StandardContext at runtime to hold a command backdoor in memory"
        author = "Cerber"
        family = "Jsp.MemShell"
        severity = "critical"
        score = 82
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = "org.apache.catalina.core.StandardContext"
        $b = "FilterDef"
        $c = /(addFilterMap|FilterMap|ApplicationFilterConfig|addFilterMapBefore)/
        $d = /(Runtime\.getRuntime\(\)\.exec|defineClass|ProcessBuilder)/
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Jsp_SpringControllerMemoryShell {
    meta:
        description = "Runtime registration of a Spring request mapping that executes commands, used as a memory web shell"
        author = "Cerber"
        family = "Jsp.MemShell"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = "RequestMappingHandlerMapping"
        $b = "registerMapping"
        $c = "RequestMappingInfo"
        $d = /Runtime\.getRuntime\(\)\.exec|ProcessBuilder/
        $e = /(request|req)\.getParameter\(/
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Jsp_ClassLoaderDefineClassFromRequest {
    meta:
        description = "JSP that turns request bytes into a class through a ClassLoader subclass and instantiates it"
        author = "Cerber"
        family = "Jsp.Webshell"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /extends[ \t]+ClassLoader/
        $b = /defineClass[ \t]*\(/
        $c = /(request\.getInputStream\(\)|request\.getParameter\([ \t]*["'][A-Za-z0-9_]{1,10}["'][ \t]*\))/
        $d = /\.newInstance\(\)/
        $e = /(Base64|decodeBuffer|BASE64Decoder)/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Jsp_JspSpyFileManager {
    meta:
        description = "JspSpy style Java file manager with upload action and command execution"
        author = "Cerber"
        family = "Jsp.JspSpy"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = "SHELL_NAME"
        $b = /\?o=upload/
        $c = "Runtime.getRuntime()"
        $d = /(JspSpy|jspspy)/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($a and $b and $c) or ($d and $b))
}

rule CERBER_Script_Jsp_ReverseShellSocketExec {
    meta:
        description = "JSP that opens a java.net.Socket and pipes a spawned shell to it"
        author = "Cerber"
        family = "Jsp.ReverseShell"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $a = "java.net.Socket"
        $b = /\/bin\/(ba)?sh|cmd\.exe/
        $c = /Runtime\.getRuntime\(\)\.exec/
        $d = "getInputStream()"
        $e = "getOutputStream()"
        $f = /new[ \t]+Socket[ \t]*\(/
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $f and $b and $c and $d and $e
}

rule CERBER_Script_Web_Log4ShellObfuscatedLookup {
    meta:
        description = "Log4Shell JNDI lookup hidden behind nested lower, upper or default-value lookups"
        author = "Cerber"
        family = "Web.Log4Shell"
        severity = "medium"
        score = 60
        date = "2026-09-29"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    strings:
        $a = /\$\{\$\{(::-j|lower:j|upper:j|env:[A-Za-z_]{1,10}:-j|[a-z]{1,8}:[a-z]{1,8}:-j)\}[^\r\n]{0,60}\}/ nocase
        $b = /\$\{[a-z:\-]{0,8}j\}\$\{[a-z:\-]{0,8}n\}\$\{[a-z:\-]{0,8}d\}\$\{[a-z:\-]{0,8}i\}/ nocase
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of ($a, $b)
}

rule CERBER_Script_Html_FollinaMsdtProtocolHandler {
    meta:
        description = "ms-msdt protocol URI abusing PCWDiagnostic with an injected PowerShell expression (Follina)"
        author = "Cerber"
        family = "Html.Follina"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-30190"
    strings:
        $a = "ms-msdt:" nocase
        $b = "PCWDiagnostic" nocase
        $c = "IT_RebrowseForFile" nocase
        $d = "IT_BrowseForFile" nocase
        $e = /Invoke-Expression|\$\(IEX|FromBase64String/ nocase
    condition:
        filesize < 8MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and ($c or $d) and $e
}

rule CERBER_Script_Html_SearchMsWebDavLure {
    meta:
        description = "search-ms URI whose crumb location points at a remote WebDAV or SMB host to present attacker files"
        author = "Cerber"
        family = "Html.SearchMs"
        severity = "high"
        score = 60
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    strings:
        $a = /search-ms:[^\r\n"']{0,160}crumb=location:\\\\[A-Za-z0-9.\-]{3,80}(@|\\)/ nocase
        $b = /search-ms:[^\r\n"']{0,160}crumb=location:%5C%5C[A-Za-z0-9.\-]{3,80}/ nocase
        $c = /search-ms:[^\r\n"']{0,160}crumb=location:https?:\/\//i
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Html_Smuggling_ExecutableBlobDownload {
    meta:
        description = "HTML that decodes a base64 payload into a Blob and forces the download of an executable, ISO or script"
        author = "Cerber"
        family = "Html.Smuggling"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/006/"
    strings:
        $a = "atob("
        $b = "new Blob("
        $c = /(msSaveOrOpenBlob|msSaveBlob|createObjectURL)/
        $d = /\.download[ \t]*=[ \t]*["'][^"'\r\n]{1,40}\.(iso|img|exe|scr|hta|vbs|lnk|msi|dll|wsf|cpl|docm|xlsm|xll)["']/ nocase
        $d2 = /(fileName|filename|file_name|fname)[ \t]*=[ \t]*["'][^"'\r\n]{1,40}\.(iso|img|exe|scr|hta|vbs|lnk|msi|dll|wsf|cpl|docm|xlsm|xll)["']/ nocase
        $e = /\.click\(\)/
    condition:
        filesize < 20MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and ($d or $d2) and $e
}

rule CERBER_Script_Html_Smuggling_ZipWithPasswordLure {
    meta:
        description = "Blob based ZIP or archive drop paired with a password lure shown to the victim"
        author = "Cerber"
        family = "Html.Smuggling"
        severity = "medium"
        score = 62
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/006/"
    strings:
        $a = "atob("
        $b = "new Blob("
        $c = /\.download[ \t]*=[ \t]*["'][^"'\r\n]{1,40}\.(zip|rar|7z)["']/ nocase
        $d = /(password|pass|passcode)[ \t]*(is|:)[ \t]*["']?[A-Za-z0-9]{3,20}/ nocase
        $e = /(msSaveOrOpenBlob|createObjectURL)/
        $f = /(Uint8Array|charCodeAt)/
    condition:
        filesize < 20MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e and $f
}

rule CERBER_Script_Html_Smuggling_DataUriAutoDownload {
    meta:
        description = "Anchor with a base64 data URI of an executable-like MIME type that is clicked automatically with an executable file name"
        author = "Cerber"
        family = "Html.Smuggling"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/006/"
    strings:
        $a = /href[ \t]*=[ \t]*["']data:application\/(octet-stream|x-msdownload|x-msdos-program|x-dosexec|vnd\.microsoft\.portable-executable)[^"']{0,20};base64,/ nocase
        $b = /download[ \t]*=[ \t]*["'][^"'\r\n]{1,40}\.(exe|scr|hta|vbs|js|lnk|msi|dll|iso|img|wsf|jar)["']/ nocase
        $c = /\.click\(\)/
    condition:
        filesize < 20MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_Html_ClickFix_ClipboardCommandWinR {
    meta:
        description = "Fake verification page that writes a shell command to the clipboard and tells the user to paste it into Win+R"
        author = "Cerber"
        family = "Html.ClickFix"
        severity = "critical"
        score = 92
        date = "2026-09-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/"
    strings:
        $w = /(writeText|copyToClipboard|clipboardData\.setData|execCommand\([ \t]*["']copy["'])/
        $c = /(writeText|setData)[ \t]*\([ \t]*[^\r\n]{0,80}(powershell|mshta|cmd(\.exe)?[ \t]+\/c|msiexec|curl|conhost|certutil|wscript|cscript|bitsadmin)/ nocase
        $win = /(Win(dows)?[ ]?(key|button|logo[ ]key|logo)?[ ]?\+[ ]?R\b|Windows[ ]?(key|button)[^<\r\n]{0,20}\bR\b|Press[ ]Win\b)/ nocase
        $ctrl = /Ctrl[ ]?\+[ ]?V/ nocase
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $w and $c and $win and $ctrl
}

rule CERBER_Script_Html_ClickFix_MshtaUrlClipboard {
    meta:
        description = "Clipboard payload that launches mshta against a remote URL after a fake CAPTCHA step"
        author = "Cerber"
        family = "Html.ClickFix"
        severity = "critical"
        score = 86
        date = "2026-09-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/"
    strings:
        $a = /(writeText|setData)[ \t]*\([ \t]*[^\r\n]{0,40}mshta(\.exe)?[ ]+["']?https?:\/\/[^\s"']{4,200}/ nocase
        $b = /(captcha|robot|verify|verification|human)/ nocase
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_Html_ClickFix_DecodedClipboardWrite {
    meta:
        description = "Clipboard write whose command is decoded at runtime with atob, unescape or fromCharCode next to Win+R instructions"
        author = "Cerber"
        family = "Html.ClickFix"
        severity = "high"
        score = 84
        date = "2026-09-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/"
    strings:
        $a = /writeText[ \t]*\([ \t]*(atob|decodeURIComponent|unescape|String\.fromCharCode|window\.atob)[ \t]*\(/
        $win = /(Win(dows)?[ ]?(key|button|logo[ ]key|logo)?[ ]?\+[ ]?R\b|Windows[ ]?(key|button)[^<\r\n]{0,20}\bR\b|Press[ ]Win\b)/ nocase
        $ctrl = /Ctrl[ ]?\+[ ]?V/ nocase
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $win and $ctrl
}

rule CERBER_Script_Html_ClickFix_MacOSTerminalPaste {
    meta:
        description = "ClickFix variant for macOS that copies a curl or base64 shell pipeline and asks the user to paste it into Terminal"
        author = "Cerber"
        family = "Html.ClickFix"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/"
    strings:
        $w = /(writeText|setData|execCommand\([ \t]*["']copy["'])/
        $c = /(writeText|setData)[ \t]*\([ \t]*[^\r\n]{0,120}(curl[ \t]+-[a-zA-Z]{1,6}[^\r\n]{0,140}\|[ \t]*(ba|z)?sh|base64[ \t]+-(D|d)[^\r\n]{0,40}\|[ \t]*(ba|z)?sh|osascript[ \t]+-e)/
        $t = /(Terminal|Cmd[ ]?\+[ ]?V|\xe2\x8c\x98[ ]?\+?[ ]?V)/
        $v = /(captcha|robot|verify|verification|human|fix)/ nocase
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $w and $c and $t and $v
}

rule CERBER_Script_Html_ClickFix_ErrorFixLure {
    meta:
        description = "Fake browser or DNS error page instructing the user to run a pasted command through the Run dialog"
        author = "Cerber"
        family = "Html.ClickFix"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/"
    strings:
        $lure1 = /(DNS_PROBE_FINISHED|ERR_NAME_NOT_RESOLVED|ERR_CONNECTION_(RESET|REFUSED|TIMED_OUT)|Browser (Update|Extension)|Update (Chrome|Edge|Firefox)|font (is )?(not found|missing|update))/ nocase
        $w = /(writeText|setData|copyToClipboard|execCommand\([ \t]*["']copy["'])/
        $c = /(powershell|mshta|cmd(\.exe)?[ \t]+\/c|msiexec|curl|conhost)[^\r\n]{0,200}/ nocase
        $win = /(Win(dows)?[ ]?(key|button|logo[ ]key|logo)?[ ]?\+[ ]?R\b|Windows[ ]?(key|button)[^<\r\n]{0,20}\bR\b|Press[ ]Win\b)/ nocase
        $ctrl = /Ctrl[ ]?\+[ ]?V/ nocase
        $fix = /(How to fix|Fix it|Quick fix|Fix the (problem|issue|error))/ nocase
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $lure1 and $w and $c and $win and $ctrl and $fix
}

rule CERBER_Script_Phishing_PhpKitTelegramBotCredentials {
    meta:
        description = "PHP phishing handler that forwards submitted credentials to a Telegram bot"
        author = "Cerber"
        family = "Phishing.Kit"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1566/"
    strings:
        $a = /api\.telegram\.org\/bot[^\r\n"']{0,80}(sendMessage|sendDocument)/
        $b = /\$_POST\[[ \t]*['"](password|pass|passwd|pwd|email|login|username|user)['"][ \t]*\]/ nocase
        $c = "chat_id"
        $d = /(REMOTE_ADDR|HTTP_X_FORWARDED_FOR|HTTP_CLIENT_IP)/
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and #b >= 2 and $c and $d
}

rule CERBER_Script_Phishing_JsKitTelegramFetch {
    meta:
        description = "Credential form page whose script posts the entered password to a Telegram bot from the browser"
        author = "Cerber"
        family = "Phishing.Kit"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1566/"
    strings:
        $a = /api\.telegram\.org\/bot[^\r\n"'`]{0,80}\/sendMessage/
        $b = /type[ \t]*=[ \t]*["']password["']/ nocase
        $c = /(fetch|XMLHttpRequest|axios|\$\.ajax|\$\.post)/
        $d = /(password|passwd|pass)["']?\)?\.value|\.val\(\)/ nocase
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Phishing_PhpKitMailerGeoplugin {
    meta:
        description = "PHP credential harvester that mails submitted passwords together with victim IP and geolocation lookups"
        author = "Cerber"
        family = "Phishing.Kit"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1566/"
    strings:
        $a = /mail[ \t]*\([ \t]*\$[A-Za-z_]{1,20}[ \t]*,/
        $b = /\$_POST\[[ \t]*['"](password|pass|passwd|pwd)['"][ \t]*\]/ nocase
        $c = /(geoplugin\.net\/json\.gp\?ip=|ip-api\.com\/(json|php)|ipinfo\.io\/[^\r\n"']{0,30}json)/ nocase
        $d = /(getenv\([ \t]*["']REMOTE_ADDR["']|\$_SERVER\[[ \t]*['"]REMOTE_ADDR['"])/
        $e = /(Password|PASS|Passwd)[ \t]*:/
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and #b >= 1 and $c and $d and $e
}

rule CERBER_Script_Phishing_UrlHashPrefilledEmailAtob {
    meta:
        description = "Login page that decodes the victim address from the URL fragment with atob and pre-fills the form"
        author = "Cerber"
        family = "Phishing.Kit"
        severity = "medium"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1566/"
    strings:
        $a = /location\.(hash|search)/
        $b = "atob("
        $c = /type[ \t]*=[ \t]*["']password["']/ nocase
        $d = /<form[^>]{0,120}action[ \t]*=[ \t]*["'][^"']{0,100}\.php["']/ nocase
        $e = /\.value[ \t]*=/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Phishing_InspectionBlockingLoginPage {
    meta:
        description = "Password form combined with F12, Ctrl+U and context menu blocking to hinder inspection of the kit"
        author = "Cerber"
        family = "Phishing.Kit"
        severity = "medium"
        score = 60
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1566/"
    strings:
        $a = /keyCode[ ]*==[ ]*123/
        $b = /contextmenu/
        $c = /ctrlKey[ ]*&&[ ]*[^\r\n]{0,30}keyCode[ ]*==[ ]*85/
        $d = /type[ \t]*=[ \t]*["']password["']/ nocase
        $e = /<form[^>]{0,120}action[ \t]*=/ nocase
        $f = /ctrlKey[ ]*&&[ ]*shiftKey[ ]*&&[ ]*[^\r\n]{0,30}keyCode[ ]*==[ ]*73/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and ($c or $f) and $d and $e
}

rule CERBER_Script_Phishing_MicrosoftLureFormToPhp {
    meta:
        description = "Microsoft sign-in lookalike whose password form posts to a local PHP script"
        author = "Cerber"
        family = "Phishing.Kit"
        severity = "medium"
        score = 55
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1566/"
    strings:
        $a = /(Sign in to your account|Sign in to Outlook|Office 365|Microsoft 365)/ nocase
        $b = /type[ \t]*=[ \t]*["']password["']/ nocase
        $c = /<form[^>]{0,120}action[ \t]*=[ \t]*["'][^"'\/:]{1,60}\.php["']/ nocase
        $d = /(Microsoft|Outlook)/
        $e = /(Stay signed in|Can.t access your account|Sign-in options)/ nocase
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Phishing_EvilginxPhishletYaml {
    meta:
        description = "Evilginx phishlet definition with proxy hosts, sub filters and captured auth tokens"
        author = "Cerber"
        family = "Phishing.Evilginx"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://github.com/kgretzky/evilginx2"
        pua = true
    strings:
        $a = "proxy_hosts:"
        $b = "sub_filters:"
        $c = "auth_tokens:"
        $d = "min_ver:"
        $e = "credentials:"
        $f = "login:"
    condition:
        filesize < 64KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and ($e or $f)
}

rule CERBER_Script_Svg_ScriptDecodeRedirectOrBlob {
    meta:
        description = "SVG image carrying a script that decodes base64 and redirects, writes HTML or builds a download Blob"
        author = "Cerber"
        family = "Svg.Smuggling"
        severity = "medium"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/006/"
    strings:
        $svg = "<svg"
        $script = /<script[^>]{0,60}>/ nocase
        $a = "atob("
        $b = /(window\.)?location(\.href|\.replace|\.assign)?[ ]*(=|\()/
        $c = /(document\.write\(|new Blob\()/
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $svg in (0..1024) and $script and $a and ($b or $c)
}

rule CERBER_Script_Html_DataUriRedirectPhishing {
    meta:
        description = "Page that redirects the browser to a base64 data:text/html URL, a common phishing landing trick"
        author = "Cerber"
        family = "Html.Phishing"
        severity = "medium"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1566/"
    strings:
        $a = /<meta[ \t]+http-equiv[ \t]*=[ \t]*["']refresh["'][ \t]+content[ \t]*=[ \t]*["'][0-9]{1,3};[ ]?url=data:text\/html[;,]/ nocase
        $b = /(location(\.href)?|window\.open)[ ]*(=|\()[ ]*["']data:text\/html;base64,[A-Za-z0-9+\/=]{40,}/ nocase
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Html_TechSupportScamLockPage {
    meta:
        description = "Fake malware alert page that blocks navigation, goes fullscreen and pushes a support phone number"
        author = "Cerber"
        family = "Html.TechScam"
        severity = "medium"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1566/"
    strings:
        $a = /(Your computer (has been|is) (infected|blocked)|Windows (Defender )?Security Alert|Virus (Alert|Detected))/ nocase
        $b = /(toll[- ]free|Call (Microsoft|Windows|Apple)( Support)?|Technical Support)/ nocase
        $c = "onbeforeunload"
        $d = /(requestFullscreen|history\.pushState)/
        $e = /toll[- ]?free[^\r\n]{0,40}[0-9]{3}[-. ][0-9]{3}[-. ][0-9]{4}/ nocase
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Js_CoinHiveMinerApi {
    meta:
        description = "CoinHive browser miner initialised through its Anonymous or User API"
        author = "Cerber"
        family = "Js.Cryptojacker"
        severity = "high"
        score = 84
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1496/"
    strings:
        $a = /new[ ]+CoinHive\.(Anonymous|User|Token|Anonymous)[ ]*\(/
        $b = /CoinHive\.CONFIG\.(REQUIRES_AUTH|LIB_URL|WEBSOCKET_SHARDS)/
        $c = /\.(start|stop)\([ ]*(CoinHive\.(FORCE_MULTI_TAB|IF_EXCLUSIVE_TAB|FORCE_EXCLUSIVE_TAB))?[ ]*\)/
        $d = /coinhive\.com\/lib\/(coinhive|coinhive\.min)\.js|authedmine\.com\/lib/ nocase
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or $b) and ($c or $d)
}

rule CERBER_Script_Js_WebMinerVariants_Scripts {
    meta:
        description = "Browser miners derived from the CoinHive API: CryptoLoot, Minero, WebMinePool, CoinImp, JSECoin"
        author = "Cerber"
        family = "Js.Cryptojacker"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1496/"
    strings:
        $a = /new[ ]+(CRLT|Client|WMP|CoinImp|JSEMiner|deepMiner|WebMinerPool)\.(Anonymous|User|Miner)[ ]*\(/
        $b = /(crypto-loot\.com|webminepool\.com|minero\.cc|coinimp\.com|jsecoin\.com|papoto\.com|coin-have\.com|monerominer\.rocks)\/[A-Za-z0-9_\/\-\.]{1,60}\.js/ nocase
        $c = /\.(start|stop)\(\)/
        $d = /(throttleMiner|setThrottle|getHashesPerSecond|getTotalHashes|getAcceptedHashes)/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($a and $c) or ($b and $d))
}

rule CERBER_Script_Js_WebMinerApiSurface_Wasm {
    meta:
        description = "JavaScript exposing the miner control API (hash rate, throttle, threads) around a cryptonight WebAssembly core"
        author = "Cerber"
        family = "Js.Cryptojacker"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1496/"
    strings:
        $a = "getHashesPerSecond"
        $b = "getTotalHashes"
        $c = "getAcceptedHashes"
        $d = "setNumThreads"
        $e = "getThrottle"
        $f = "hasWASMSupport"
        $g = /cryptonight|cryptonight-wasm|CryptonightWASMWrapper/i
        $h = /(WebAssembly\.(instantiate|compile)|wasm)/
    condition:
        filesize < 12MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 4 of ($a, $b, $c, $d, $e, $f) and $g and $h
}

rule CERBER_Script_Html_CryptojackerScriptInclude {
    meta:
        description = "HTML script tag loading a known browser miner library"
        author = "Cerber"
        family = "Html.Cryptojacker"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1496/"
    strings:
        $a = /<script[^>]{0,120}src[ \t]*=[ \t]*["'](https?:)?\/\/(www\.)?(coinhive\.com|coin-hive\.com|authedmine\.com|crypto-loot\.com|webminepool\.com|minero\.cc|coinimp\.com|jsecoin\.com|papoto\.com|browsermine\.com)[^"']{0,80}\.js/ nocase
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_PowerShell_PowerSploit_ModuleFunctions {
    meta:
        description = "Several PowerSploit post-exploitation function names in one script"
        author = "Cerber"
        family = "PowerShell.PowerSploit"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://github.com/PowerShellMafia/PowerSploit"
        pua = true
    strings:
        $a1 = "Invoke-DllInjection" nocase wide ascii
        $a2 = "Invoke-TokenManipulation" nocase wide ascii
        $a3 = "Invoke-NinjaCopy" nocase wide ascii
        $a4 = "Invoke-CredentialInjection" nocase wide ascii
        $a5 = "Out-Minidump" nocase wide ascii
        $a6 = "Get-VaultCredential" nocase wide ascii
        $a7 = "Get-Keystrokes" nocase wide ascii
        $a8 = "Get-TimedScreenshot" nocase wide ascii
        $a9 = "Install-SSP" nocase wide ascii
        $a10 = "Add-Persistence" nocase wide ascii
        $a11 = "Find-AVSignature" nocase wide ascii
        $a12 = "Invoke-WmiCommand" nocase wide ascii
        $a13 = "Get-MicrophoneAudio" nocase wide ascii
        $a14 = "Set-MasterBootRecord" nocase wide ascii
        $a15 = "Invoke-Portscan" nocase wide ascii
    condition:
        filesize < 8MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 4 of them
}

rule CERBER_Script_PowerShell_SharpToolLoaders_InvokeAssembly {
    meta:
        description = "PowerShell wrappers that reflectively run offensive .NET tools such as Rubeus, SafetyKatz or Seatbelt"
        author = "Cerber"
        family = "PowerShell.Loader"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        pua = true
    strings:
        $a1 = "Invoke-Rubeus" nocase wide ascii
        $a2 = "Invoke-SharpLoader" nocase wide ascii
        $a3 = "Invoke-SafetyKatz" nocase wide ascii
        $a4 = "Invoke-Seatbelt" nocase wide ascii
        $a5 = "Invoke-Certify" nocase wide ascii
        $a6 = "Invoke-SharpView" nocase wide ascii
        $a7 = "Invoke-Assembly" nocase wide ascii
        $a8 = "Invoke-DomainPasswordSpray" nocase wide ascii
        $a9 = "Invoke-SharpChromium" nocase wide ascii
        $a10 = "Invoke-SharpDump" nocase wide ascii
        $a11 = "Invoke-SharpWMI" nocase wide ascii
        $b = /FromBase64String|Assembly\]?::Load|EntryPoint/ nocase wide ascii
    condition:
        filesize < 8MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 2 of ($a*) and $b
}

rule CERBER_Script_PowerShell_Base64Utf8StringIex {
    meta:
        description = "Base64 text decoded to a string and passed straight to Invoke-Expression"
        author = "Cerber"
        family = "PowerShell.Obfuscation"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /(iex|Invoke-Expression)[ \t]*\(?[ \t]*\[(System\.)?(Text\.)?Encoding\]::(UTF8|Unicode|ASCII)\.GetString\([ \t]*\[(System\.)?Convert\]::FromBase64String\(/ nocase wide ascii
        $b = /\[(System\.)?Convert\]::FromBase64String\([ \t]*["'][A-Za-z0-9+\/=]{60,}["']/ nocase wide ascii
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_PowerShell_XorDecodeLoopIex {
    meta:
        description = "Base64 payload decoded byte by byte with -bxor and executed with Invoke-Expression"
        author = "Cerber"
        family = "PowerShell.Obfuscation"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1027/"
    strings:
        $a = /-bxor[ \t]*(0x[0-9a-fA-F]{1,2}|[0-9]{1,3}|\$[A-Za-z_]{1,10})/ nocase wide ascii
        $b = "FromBase64String" nocase wide ascii
        $c = /(iex|Invoke-Expression)[ \t]*\(?[ \t]*(\[(System\.)?Text\.Encoding\]|-join|\$\(|\()/ nocase wide ascii
        $e = /(GetString|-join)/ nocase wide ascii
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $e
}

rule CERBER_Script_PowerShell_DnsTxtRecordStager {
    meta:
        description = "Payload retrieved from a DNS TXT record and executed with Invoke-Expression"
        author = "Cerber"
        family = "PowerShell.Stager"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1071/004/"
    strings:
        $a = /(Resolve-DnsName|nslookup)[^\r\n]{0,100}(-Type[ \t]+TXT|-q=txt|-type=txt)[^\r\n]{0,140}(iex|Invoke-Expression)/ nocase wide ascii
        $b = /(iex|Invoke-Expression)[^\r\n]{0,140}(Resolve-DnsName|nslookup)[^\r\n]{0,100}(-Type[ \t]+TXT|-q=txt|-type=txt)/ nocase wide ascii
    condition:
        filesize < 300KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Batch_SafeModeRansomwareBoot {
    meta:
        description = "bcdedit forcing safe mode boot followed by a restart so encryption runs without security tooling"
        author = "Cerber"
        family = "Batch.RansomwarePrep"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1490/"
    strings:
        $a = /bcdedit(\.exe)?["']?[ \t]+\/set[ \t]+(\{default\}|\{current\})?[ \t]*safeboot[ \t]+(minimal|network)/ nocase wide ascii
        $b = /shutdown(\.exe)?[ \t]+(\/r|-r)[ \t]+(\/t|-t)[ \t]+[0-9]{1,3}/ nocase wide ascii
        $c = /reg(\.exe)?[ \t]+add[ \t]+[^\r\n]{0,80}\\SafeBoot\\(Minimal|Network)\\/ nocase wide ascii
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and (($a and $b) or ($c and $a))
}

rule CERBER_Script_Batch_ServiceCreate_ScriptBinPath {
    meta:
        description = "sc create registering a service whose binPath runs a scripting host with hidden or remote arguments"
        author = "Cerber"
        family = "Batch.Persistence"
        severity = "medium"
        score = 68
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1543/003/"
    strings:
        $a = /sc(\.exe)?[ \t]+(\\\\[A-Za-z0-9.\-]{1,40}[ \t]+)?create[ \t]+[A-Za-z0-9_\-]{1,40}[ \t]+[^\r\n]{0,40}binpath=[ \t]*["'][^\r\n]{0,60}(cmd(\.exe)?[ \t]+\/c|powershell(\.exe)?|mshta|rundll32|regsvr32)[^\r\n]{0,200}(-w(in|indow|indowstyle)?[ \t]+(h(idden)?|1)|-enc|-nop|http:|https:|\/i:|javascript:)/ nocase wide ascii
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Xml_ScheduledTaskHiddenPowerShell {
    meta:
        description = "Task Scheduler XML exporting a hidden task that starts PowerShell or mshta with encoded or remote arguments"
        author = "Cerber"
        family = "Xml.ScheduledTask"
        severity = "high"
        score = 70
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1053/005/"
    strings:
        $a = /<Task[ >]/ wide ascii
        $b = /<Hidden>true<\/Hidden>/ wide ascii
        $c = /<Command>[^<]{0,60}(powershell|mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?<\/Command>/ nocase wide ascii
        $d = /<Arguments>[^<]{0,200}(-w(in|indow|indowstyle)?[ \t]+(h(idden)?|1)|-enc|-nop|http:|https:|javascript:)/ nocase wide ascii
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Msc_GrimResourceApdsXss {
    meta:
        description = "Management console file that abuses the apds.dll redirect page to run JavaScript through a StringTable resource"
        author = "Cerber"
        family = "Msc.GrimResource"
        severity = "critical"
        score = 90
        date = "2026-09-29"
        reference = "https://www.elastic.co/security-labs/grimresource"
    strings:
        $a = "<ConsoleFile"
        $b = /res:\/\/apds\.dll\/redirect\.html/ nocase
        $c = /javascript:/ nocase
        $d = /(ActiveXObject|DotNetToJScript|eval\()/ nocase
    condition:
        filesize < 8MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Xml_LibraryMsRemoteLocation {
    meta:
        description = "Windows library or search connector file pointing its location at a remote WebDAV or SMB URL"
        author = "Cerber"
        family = "Xml.LibraryMs"
        severity = "medium"
        score = 60
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1187/"
    strings:
        $a = /<libraryDescription[ >]/ nocase wide ascii
        $b = /<searchConnectorDescription[ >]/ nocase wide ascii
        $c = /<simpleLocation>[ \t\r\n]*<url>[ \t]*(https?:\/\/|\\\\\\\\)[^<]{4,200}<\/url>/ nocase wide ascii
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or $b) and $c
}

rule CERBER_Script_Onenote_HtaWsfLauncher {
    meta:
        description = "OneNote notebook embedding an HTA, WSF, VBS or PowerShell launcher behind a fake button"
        author = "Cerber"
        family = "Onenote.Dropper"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    strings:
        $hta = "<HTA:APPLICATION" nocase wide ascii
        $job = "<job id" nocase wide ascii
        $wsh = "WScript.Shell" nocase wide ascii
        $run = ".Run" nocase wide ascii
        $ps1 = "powershell" nocase wide ascii
        $ps2 = /-w(indowstyle)?[ ](h(idden)?|1)/ nocase wide ascii
        $ps3 = "-enc" nocase wide ascii
        $mshta = "mshta" nocase wide ascii
    condition:
        uint32(0) == 0x7B5C52E4 and uint32(4) == 0x4DA7D88C and filesize < 30MB and ($hta or ($job and $wsh) or ($wsh and $run) or ($ps1 and $ps2 and $ps3) or ($mshta and $ps1))
}

rule CERBER_Script_Pdf_LaunchActionCommandInterpreter {
    meta:
        description = "PDF Launch action that starts cmd.exe, PowerShell or a shell with arguments"
        author = "Cerber"
        family = "Pdf.Launch"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    strings:
        $hdr = "%PDF-"
        $a = "/Launch"
        $b = /\/F[ ]?\((cmd|cmd\.exe|powershell|powershell\.exe|\/bin\/sh|\/bin\/bash)\)/ nocase
        $c = /\/P[ ]?\([^\)]{0,120}(\/c|-c|-enc|http)/ nocase
    condition:
        filesize < 20MB and $hdr in (0..1024) and $a and $b and $c
}

rule CERBER_Script_Bash_CurlWgetFallbackPipeShell {
    meta:
        description = "Parenthesised curl or wget fallback chain piped into a shell, the loader idiom of miner and botnet installers"
        author = "Cerber"
        family = "Bash.Dropper"
        severity = "high"
        score = 66
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = /\([ \t]*(curl|wget)[ \t]+[^\r\n)|]{1,120}\|\|[ \t]*(curl|wget)[ \t]+[^\r\n)|]{1,120}\)[ \t]*\|[ \t]*(sudo[ \t]+)?(ba|z|da)?sh\b/
        $lo = /https?:\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0)/
        $h = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|\.(duckdns\.org|ngrok\.io|ngrok-free\.app|hopto\.org|ddns\.net|zapto\.org|trycloudflare\.com|top|xyz|ru|cn|su|pw|tk)\//
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $h and not $lo
}

rule CERBER_Script_Bash_SshpassWormScanner {
    meta:
        description = "Brute-force and spread script combining a scanner, sshpass password guessing and payload download"
        author = "Cerber"
        family = "Bash.Worm"
        severity = "high"
        score = 68
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1110/"
    strings:
        $a = /sshpass[ \t]+-p[ \t]*["']?[^\r\n]{1,40}[ \t]+ssh[ \t]/
        $b = /(masscan|zmap|pnscan|nmap[ \t]+-p)/
        $c = /(while[ \t]+read|for[ \t]+[A-Za-z]{1,10}[ \t]+in[ \t]+\$\()/
        $d = /(wget|curl)[ \t]+[^\r\n]{0,80}https?:\/\//
        $e = /(pass(word)?s?\.txt|users?\.txt|combo\.txt)/ nocase
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Perl_IrcBotFloodCommands {
    meta:
        description = "IRC controlled bot exposing UDP, TCP and HTTP flood or scan commands"
        author = "Cerber"
        family = "Perl.IrcBot"
        severity = "high"
        score = 78
        date = "2026-09-29"
    strings:
        $a = "PRIVMSG"
        $b = "IO::Socket"
        $c = /(udpflood|tcpflood|synflood|httpflood|!udp|!tcp|!http|!portscan|!scan)/ nocase
        $d = /(system\(|exec\(|`\$)/
        $e = /(JOIN|NICK)[ ]/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and #c >= 2 and $d and $e
}

rule CERBER_Script_Perl_CgiShellParamSystem {
    meta:
        description = "Perl CGI script that runs a command taken from a query parameter and prints the output"
        author = "Cerber"
        family = "Perl.Webshell"
        severity = "medium"
        score = 62
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /\#!\/usr\/bin\/perl/
        $b = /(param\(["']cmd["']\)|\$in\{["']cmd["']\}|\$FORM\{["']cmd["']\}|\$ENV\{["']QUERY_STRING["']\})/
        $c = /(system\(|`\$[a-z]{1,10}`|open\([A-Z]{1,6},[ ]*["']?\$[a-z]{1,10}[ ]*\|)/
        $d = /Content-type:[ ]*text\/(html|plain)/ nocase
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Python_WebBackdoorRequestCmdExec {
    meta:
        description = "Flask, Django or CGI handler that executes a command taken from a request parameter"
        author = "Cerber"
        family = "Python.Webshell"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /(os\.popen|os\.system|subprocess\.(check_output|Popen|run|call|getoutput))\([ \t]*request\.(args|form|values|GET|POST|params)(\.get\(|\[)[ \t]*['"](cmd|c|command|exec|shell)['"]/
        $b = /(cmd|command)[ \t]*=[ \t]*request\.(args|form|values|GET|POST)(\.get\(|\[)[ \t]*['"](cmd|c|command|exec)['"]/
        $c = /(os\.popen|os\.system|subprocess\.(check_output|Popen|run|call|getoutput))\([ \t]*(cmd|command)\b/
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and ($a or ($b and $c))
}

rule CERBER_Script_Node_ExpressBackdoorReqCmdExec {
    meta:
        description = "Express route handing a request field straight to child_process exec or spawn"
        author = "Cerber"
        family = "Node.Webshell"
        severity = "high"
        score = 68
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /(exec|execSync|spawn|spawnSync)\([ \t]*(req|request)\.(query|body|params)\.(cmd|command|exec|c)\b/
        $b = /(exec|execSync)\([ \t]*(req|request)\.(query|body|params)\[[ \t]*['"](cmd|command|exec|c)['"]/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Node_GlassWormInvisibleUnicodeDecoder {
    meta:
        description = "Decoder for payloads hidden in Unicode variation selectors that evals the decoded bytes, as used by GlassWorm"
        author = "Cerber"
        family = "Node.GlassWorm"
        severity = "critical"
        score = 90
        date = "2026-09-29"
    strings:
        $a = "0xFE00"
        $b = "0xE0100"
        $c = "codePointAt"
        $d = /eval[ ]*\([ ]*(Buffer\.from|atob|new[ ]+TextDecoder)/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Yaml_GithubWorkflowSecretsExfil {
    meta:
        description = "GitHub Actions workflow that serialises all secrets and posts them to an external endpoint"
        author = "Cerber"
        family = "Yaml.SupplyChain"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1195/002/"
    strings:
        $a = "toJSON(secrets)"
        $b = /(curl|wget|Invoke-WebRequest|Invoke-RestMethod)[ \t]+[^\r\n]{0,120}https?:\/\/[^\r\n]{4,120}/
        $c = /(webhook\.site|oastify\.com|pipedream\.net|requestbin|burpcollaborator|interact\.sh|ngrok)/
        $d = /(runs-on:|on:[ \t\r\n]+(push|pull_request|workflow_dispatch))/
    condition:
        filesize < 64KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Cfm_CfexecuteFormCommand {
    meta:
        description = "ColdFusion page running a command taken from a form or URL variable through cfexecute"
        author = "Cerber"
        family = "Cfm.Webshell"
        severity = "high"
        score = 72
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /<cfexecute[^>]{0,120}name[ ]*=[ ]*["'][^"']{0,60}(cmd\.exe|\/bin\/(ba)?sh|powershell)/ nocase
        $b = /#(form|url)\.[A-Za-z0-9_]{1,15}#/ nocase
        $c = /arguments[ ]*=[ ]*["'][^"']{0,40}#(form|url)\./ nocase
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c
}

rule CERBER_Script_AutoIt_ShellcodeLoaderDllCall {
    meta:
        description = "AutoIt script that allocates executable memory through DllCall and jumps into it"
        author = "Cerber"
        family = "AutoIt.Loader"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1620/"
    strings:
        $a = /DllCall\([ ]*["']kernel32\.dll["'][ ]*,[ ]*["']ptr["'][ ]*,[ ]*["']VirtualAlloc["']/ nocase
        $b = /(DllCall\([ ]*["']kernel32\.dll["'][ ]*,[^\r\n]{0,60}["']RtlMoveMemory["']|DllStructSetData)/ nocase
        $c = /(CallWindowProc|DllCallAddress|EnumWindows|NtUnmapViewOfSection|WriteProcessMemory)/ nocase
        $d = "#NoTrayIcon" nocase
        $e = /(BinaryToString|Binary\()/ nocase
    condition:
        filesize < 8MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d and $e
}

rule CERBER_Script_Html_ClickFix_InstructionsLure {
    meta:
        description = "Fake human-verification page instructing Win+R, Ctrl+V and Enter, even when the clipboard write happens in external script"
        author = "Cerber"
        family = "Html.ClickFix"
        severity = "medium"
        score = 62
        date = "2026-09-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/"
    strings:
        $win = /(Win(dows)?[ ]?(key|button|logo[ ]key|logo)?[ ]?\+[ ]?R\b|Windows[ ]?(key|button)[^<\r\n]{0,20}\bR\b|Press[ ]Win\b)/ nocase
        $ctrl = /Ctrl[ ]?\+[ ]?V/ nocase
        $enter = /(press|hit|then)[ ]+(the[ ]+)?Enter/ nocase
        $lure = /(I.m not a robot|I am not a robot|Verify you are human|Verify you are not a robot|Checking (if|that) you are human|Cloudflare|Ray ID)/ nocase
        $btn = /(<button|onclick=)/ nocase
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $win and $ctrl and $enter and $lure and $btn
}

rule CERBER_Script_Js_ClipboardWriteHiddenPowerShellOrMshta {
    meta:
        description = "Script writing hidden-window PowerShell or an mshta URL into the clipboard, the payload half of a ClickFix lure"
        author = "Cerber"
        family = "Js.ClickFix"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/"
    strings:
        $a = /(writeText|setData)[ ]*\([ ]*[^\r\n]{0,60}powershell(\.exe)?[^\r\n]{0,80}-w(in|indow|indowstyle)?[ ]+(h(idden)?|1)/ nocase
        $b = /(writeText|setData)[ ]*\([ ]*[^\r\n]{0,40}mshta(\.exe)?[ ]+["']?https?:\/\//i
    condition:
        filesize < 4MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of them
}

rule CERBER_Script_Php_BacktickExecRequestVar {
    meta:
        description = "Shell-execution backticks wrapped around a request variable"
        author = "Cerber"
        family = "Php.Webshell"
        severity = "critical"
        score = 86
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /(<\?=|echo|print|=|\(|shell_exec)[ \t]*`[ \t]*\$_(GET|POST|REQUEST|COOKIE)[ \t]*\[[^\]\r\n]{1,20}\][ \t]*`/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a
}

rule CERBER_Script_Php_Base64EncodedFunctionNameDispatch {
    meta:
        description = "assert, eval or system name hidden as a base64 literal and dispatched with request input"
        author = "Cerber"
        family = "Php.Webshell"
        severity = "critical"
        score = 84
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /base64_decode[ \t]*\([ \t]*["'](YXNzZXJ0|ZXZhbA==?|c3lzdGVt|c2hlbGxfZXhlYw==|cGFzc3RocnU=|cG9wZW4=|cHJvY19vcGVu)["'][ \t]*\)/
        $b = /\$_(POST|GET|REQUEST|COOKIE)[ \t]*\[/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_Php_ChrBuiltFunctionNames {
    meta:
        description = "eval, assert or base64_decode assembled from chr() calls next to request or session variables"
        author = "Cerber"
        family = "Php.Webshell"
        severity = "high"
        score = 78
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /chr[ ]?\(98\)[ ]?\.[ ]?chr[ ]?\(97\)[ ]?\.[ ]?chr[ ]?\(115\)[ ]?\.[ ]?chr[ ]?\(101\)[ ]?\.[ ]?chr[ ]?\(54\)[ ]?\.[ ]?chr[ ]?\(52\)/ nocase
        $b = /chr[ ]?\(101\)[ ]?\.[ ]?chr[ ]?\(118\)[ ]?\.[ ]?chr[ ]?\(97\)[ ]?\.[ ]?chr[ ]?\(108\)/ nocase
        $c = /chr[ ]?\(97\)[ ]?\.[ ]?chr[ ]?\(115\)[ ]?\.[ ]?chr[ ]?\(115\)[ ]?\.[ ]?chr[ ]?\(101\)[ ]?\.[ ]?chr[ ]?\(114\)[ ]?\.[ ]?chr[ ]?\(116\)/ nocase
        $r = /\$_(POST|GET|REQUEST|COOKIE|SESSION)[ \t]*\[|session_start[ ]?\(/
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of ($a, $b, $c) and $r
}

rule CERBER_Script_Php_SingleCharConcatFunctionName {
    meta:
        description = "Function name built from single-character string concatenation and then called with a request variable"
        author = "Cerber"
        family = "Php.Webshell"
        severity = "high"
        score = 76
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /(['"][a-z_]['"][ ]*\.[ ]*){4,10}['"][a-z_]['"]/
        $b = /\$[A-Za-z_]\w{0,10}[ ]*\([ ]*@?\$_(POST|GET|REQUEST|COOKIE)[ ]*\[/
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

rule CERBER_Script_Aspx_JscriptEvalTwoArgRequest {
    meta:
        description = "JScript.NET page evaluating a request value with a second security argument, including hex-escaped or split unsafe"
        author = "Cerber"
        family = "Aspx.ChinaChopper"
        severity = "critical"
        score = 84
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $lang = /language[ ]*=[ ]*["']?JScript/ nocase
        $req = /Request(\.Item|\.Form|\.QueryString)?[ ]*\[/
        $ev = /eval[ ]*\([ ]*[A-Za-z_][A-Za-z0-9_]{0,15}[ ]*,[ ]*["'][^"'\r\n]{1,60}["']([ ]*\+[ ]*["'][^"'\r\n]{1,60}["'])?[ ]*\)/ nocase
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $lang and $req and $ev
}

rule CERBER_Script_Aspx_CmdRunCmdProcessTextbox {
    meta:
        description = "Classic cmd.aspx style page whose RunCmd handler starts a process from textbox values and prints the output"
        author = "Cerber"
        family = "Aspx.Webshell"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
    strings:
        $a = /Sub[ \t]+RunCmd[ \t]*\([ \t]*Src[ \t]+As[ \t]+Object/ nocase
        $b = "ProcessStartInfo" nocase
        $c = "RedirectStandardOutput" nocase
        $d = /\.(text|Text)/
    condition:
        filesize < 100KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b and $c and $d
}

rule CERBER_Script_Node_EvalDecodedBase64Blob {
    meta:
        description = "eval or new Function over a long base64, hex or zlib-compressed literal, the payload wrapper seen in malicious npm packages"
        author = "Cerber"
        family = "Node.Obfuscated"
        severity = "high"
        score = 74
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1195/002/"
    strings:
        $a = /(eval|new[ ]+Function)[ ]*\([ ]*(Buffer\.from|atob)[ ]*\([ ]*["'][A-Za-z0-9+\/=]{120,}["'][ ]*,[ ]*["'](base64|hex)["']/
        $b = /(eval|new[ ]+Function)[ ]*\([ ]*(require\([ ]*["']zlib["'][ ]*\)|zlib)\.(inflate|gunzip|unzip)Sync[ ]*\([ ]*Buffer\.from[ ]*\([ ]*["'][A-Za-z0-9+\/=]{120,}["']/
        $c = /(eval|new[ ]+Function)[ ]*\([ ]*atob[ ]*\([ ]*["'][A-Za-z0-9+\/=]{200,}["']/
        $d = /require[ ]*\([ ]*["'](child_process|https?|net|fs)["'][ ]*\)/
    condition:
        filesize < 3MB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and 1 of ($a, $b, $c) and $d
}

rule CERBER_Script_Bash_IfsObfuscatedDownloadPipe {
    meta:
        description = "curl or wget written with ${IFS} separators and piped straight into a shell, as in exploit-delivered botnet loaders"
        author = "Cerber"
        family = "Bash.Dropper"
        severity = "high"
        score = 80
        date = "2026-09-29"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $a = /(curl|wget)\$\{IFS\}[^\r\n|]{3,120}\|[ ]*(\$\{IFS\})?(sudo\$\{IFS\})?(ba|z|da)?sh\b/
        $b = /(curl|wget)\$\{IFS\}(-[A-Za-z\-]{1,6}\$\{IFS\})*https?:\/\/[^\s|]{4,120}/
    condition:
        filesize < 200KB and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32be(0) != 0xcafebabe and uint32(0) != 0xfeedfacf and uint32(0) != 0xfeedface and $a and $b
}

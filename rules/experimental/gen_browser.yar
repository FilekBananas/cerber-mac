/*
 * Cerber – reguły własne (browser), napisane 2026-10-09 przez agentów na podstawie publicznych raportów.
 * Warstwa "community": same nie dają werdyktu ZŁOŚLIWY. Zero trafień na ~2800 czystych plikach macOS
 * (programy z /Applications i /System, /usr/bin, LaunchAgents, rozszerzenia VS Code, node_modules).
 */

/*
 * CERBER staging - browser hijacking and malicious browser extensions (macOS)
 * Author: Cerber (gen) | Date: 2026-10-09
 *
 * Same policy as rules/custom/macos.yar: TYPE GATE, SIZE LIMIT, SEVERAL INDICATORS,
 * score >= 75 CERTAIN, < 75 HIGH/behavioural. Legitimate extensions and enterprise
 * profiles use many of these keys; each rule needs the complete malicious combination.
 *
 * References:
 *   MITRE ATT&CK T1176.001 https://attack.mitre.org/techniques/T1176/001/
 *   ExtensionInstallForcelist abuse on macOS https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac
 *   Fake Perplexity search-hijack extension (2026) https://securityarsenal.com/blog/malicious-perplexity-chrome-extension-hunting-search-interception-malware
 *   Odyssey / cookie and wallet stealers on macOS https://moonlock.com/fake-bluewallet-app-steals-crypto
 *   Mac malware stealing exchange cookies https://unit42.paloaltonetworks.com/mac-malware-steals-cryptocurrency-exchanges-cookies/
 */

rule CERBER_Gen_Browser_Manifest_SearchHijack_WebRequest {
    meta:
        description = "Chromium extension manifest that overrides the default search provider and also has all-URL webRequest access (search interception pattern)"
        author = "Cerber (gen)"
        family = "BrowserHijack"
        severity = "high"
        score = 62
        date = "2026-10-09"
        reference = "https://securityarsenal.com/blog/malicious-perplexity-chrome-extension-hunting-search-interception-malware"
    strings:
        $mv = "\"manifest_version\"" ascii
        $so = "\"chrome_settings_overrides\"" ascii
        $sp = "\"search_provider\"" ascii
        $all = "\"<all_urls>\"" ascii
        $wr = "\"webRequest\"" ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and
        $mv and $so and $sp and $all and $wr
}

rule CERBER_Gen_Browser_Manifest_Debugger_Cookies_AllUrls {
    meta:
        description = "Chromium extension manifest combining debugger, cookies, webRequestBlocking and <all_urls> (full traffic and session-cookie control)"
        author = "Cerber (gen)"
        family = "BrowserSpy"
        severity = "high"
        score = 60
        date = "2026-10-09"
        reference = "https://attack.mitre.org/techniques/T1176/001/"
    strings:
        $mv = "\"manifest_version\"" ascii
        $dbg = "\"debugger\"" ascii
        $ck = "\"cookies\"" ascii
        $wrb = "\"webRequestBlocking\"" ascii
        $all = "\"<all_urls>\"" ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and
        $mv and $dbg and $ck and $wrb and $all
}

rule CERBER_Gen_Browser_ChromePolicy_ForceExtension_Proxy_Plist {
    meta:
        description = "Chrome managed-policy plist that force-installs an extension and also pushes a PAC proxy (traffic interception via browser policy)"
        author = "Cerber (gen)"
        family = "BrowserHijack"
        severity = "high"
        score = 68
        date = "2026-10-09"
        reference = "https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac"
    strings:
        $x = "<?xml" ascii
        $f = "ExtensionInstallForcelist" ascii
        $p1 = "ProxyAutoConfigURLString" ascii
        $p2 = "ProxyMode" ascii
        $p3 = "ProxyServerMode" ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 128KB and
        $x and $f and $p1 and ($p2 or $p3)
}

rule CERBER_Gen_Browser_MobileConfig_ForcedExtension_HomepageSearch {
    meta:
        description = "Configuration profile that force-installs a browser extension and also pins homepage or default search for Chrome, Edge or Brave"
        author = "Cerber (gen)"
        family = "BrowserHijack"
        severity = "critical"
        score = 74
        date = "2026-10-09"
        reference = "https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac"
    strings:
        $x = "<?xml" ascii
        $pt = "com.apple.ManagedClient.preferences" ascii
        $d1 = "com.google.Chrome" ascii
        $d2 = "com.microsoft.Edge" ascii
        $d3 = "com.brave.Browser" ascii
        $f = "ExtensionInstallForcelist" ascii
        $h1 = "HomepageLocation" ascii
        $h2 = "DefaultSearchProviderSearchURL" ascii
        $h3 = "RestoreOnStartupURLs" ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 64KB and
        $x and $pt and (1 of ($d*)) and $f and 1 of ($h*)
}

rule CERBER_Gen_Browser_MobileConfig_PAC_Proxy_Hijack {
    meta:
        description = "Configuration profile that sets a PAC proxy URL with auto-discovery or proxy type auto (silent traffic redirection)"
        author = "Cerber (gen)"
        family = "ProxyHijack"
        severity = "high"
        score = 58
        date = "2026-10-09"
        reference = "https://attack.mitre.org/techniques/T1176/001/"
    strings:
        $pt = "com.apple.ManagedClient.preferences" ascii
        $pac = /<key>ProxyAutoConfigURLString<\/key>\s*<string>https?:\/\/[^<]{4,200}<\/string>/ ascii
        $auto1 = "ProxyAutoDiscoveryEnable" ascii
        $auto2 = /<key>ProxyType<\/key>\s*<string>auto<\/string>/ ascii
    condition:
        uint32be(0) == 0x3c3f786d and filesize < 64KB and
        $pt and $pac and (1 of ($auto*))
}

rule CERBER_Gen_Browser_FirefoxPolicies_ForcedAddon_Search {
    meta:
        description = "Firefox policies.json that force-installs an add-on from a URL and also sets a homepage or search engine"
        author = "Cerber (gen)"
        family = "BrowserHijack"
        severity = "high"
        score = 66
        date = "2026-10-09"
        reference = "https://attack.mitre.org/techniques/T1176/001/"
    strings:
        $p = "\"policies\"" ascii
        $es = "\"ExtensionSettings\"" ascii
        $inst = "\"install_url\"" ascii
        $h1 = "\"Homepage\"" ascii
        $h2 = "\"SearchEngines\"" ascii
        $h3 = "\"Default\"" ascii
    condition:
        (for all i in (0..7) : (uint8(i) >= 9 and uint8(i) < 127)) and filesize < 64KB and
        $p and $es and $inst and (1 of ($h*))
}

rule CERBER_Gen_Browser_Extension_RemoteCode_Eval {
    meta:
        description = "Browser extension script that fetches remote text, reads it and evaluates it (remote code loading inside an extension context)"
        author = "Cerber (gen)"
        family = "BrowserExtensionLoader"
        severity = "critical"
        score = 72
        date = "2026-10-09"
        reference = "https://attack.mitre.org/techniques/T1176/001/"
    strings:
        $f = /\bfetch\([^;]{1,300}\.text\(\)[\s\S]{0,400}\b(eval|new Function)\s*\(/ ascii
        $c1 = "chrome.runtime" ascii
        $c2 = "chrome.tabs" ascii
        $c3 = "chrome.cookies" ascii
        $c4 = "browser.runtime" ascii
    condition:
        filesize < 256KB and $f and ($c3 or ($c1 and $c2) or $c4)
}

rule CERBER_Gen_Browser_Extension_WalletTarget_Exfil {
    meta:
        description = "Extension script that references a crypto-wallet extension ID, reads cookies or storage and POSTs data out"
        author = "Cerber (gen)"
        family = "BrowserWalletStealer"
        severity = "high"
        score = 68
        date = "2026-10-09"
        reference = "https://moonlock.com/fake-bluewallet-app-steals-crypto"
    strings:
        $w1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii nocase
        $w2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii nocase
        $ck = "chrome.cookies.getAll" ascii
        $st = "chrome.storage.local.get" ascii
        $post = /method\s*:\s*['"]POST['"]/ ascii
    condition:
        filesize < 256KB and 1 of ($w*) and ($ck or $st) and $post
}

rule CERBER_Gen_Browser_Extension_AllCookies_Exfil {
    meta:
        description = "Extension script that dumps every cookie with an empty filter, serialises it to JSON and POSTs it (session-cookie theft)"
        author = "Cerber (gen)"
        family = "BrowserCookieStealer"
        severity = "high"
        score = 65
        date = "2026-10-09"
        reference = "https://unit42.paloaltonetworks.com/mac-malware-steals-cryptocurrency-exchanges-cookies/"
    strings:
        $all = /chrome\.cookies\.getAll\(\s*\{\s*\}\s*[,)]/ ascii
        $ser = /JSON\.stringify\(\s*\w+\s*\)/ ascii
        $post = /method\s*:\s*['"]POST['"]/ ascii
    condition:
        filesize < 256KB and $all and $ser and $post
}

"""Malware families the AI classifier chooses between.

The static engines name what they matched (ClamAV "Osx.Trojan.Amos-…", YARA "MacOS_Infostealer_Atomic…",
hash labels "MalwareBazaar.AMOS", IOC "ThreatFox.amos", heuristics "Heur:SHELL.KeychainExfil"). `candidates()`
turns those names into a short list of families the file may belong to – plus "another family" and "legitimate
software" – and the local model only has to pick one (cerber/engines/ai.py). A multiple-choice question is
something a small model answers far more reliably than "is this malware?".

`KB` describes behaviour, not signatures: it lets the model compare what the evidence shows with what each
family is known to do. Families the KB does not know still become candidates, described by the detections
that named them.
"""
from __future__ import annotations

import re

# id, display name, category, aliases (lower-case words or phrases found in detection names), behaviour
KB: list[tuple[str, str, str, tuple[str, ...], str]] = [
    # ---- macOS info-stealers
    ("amos", "Atomic macOS Stealer (AMOS)", "stealer", ("amos", "atomic", "atomicstealer", "atomic stealer", "shamos",
     "odyssey"), "Stealer sold as a service (also rebranded as Odyssey, SHAMOS). AppleScript/osascript fake password "
     "dialog checked with dscl, dumps Keychain, browser passwords/cookies, crypto wallets, Notes and documents, zips "
     "them (ditto) and POSTs them to a C2. Spread as fake app .dmg files and ClickFix 'paste in Terminal' pages."),
    ("banshee", "Banshee Stealer", "stealer", ("banshee",), "Stealer-as-a-service: osascript password prompt, browser "
     "and crypto-wallet theft, Keychain, anti-VM checks, skips Russian-language systems; later builds encrypt strings "
     "with Apple's XProtect algorithm."),
    ("poseidon_stealer", "Poseidon Stealer", "stealer", ("poseidon stealer", "poseidonstealer", "poseidon"),
     "AppleScript-based stealer from a former AMOS developer: fake password prompt, browser data, crypto wallets, "
     "VPN configurations (OpenVPN/FortiVPN), Telegram; distributed via malicious Google ads for fake apps."),
    ("cuckoo", "Cuckoo Stealer", "stealer", ("cuckoo",), "Stealer + spyware Mach-O hidden in fake music/utility apps; "
     "osascript password prompt, LaunchAgent persistence, collects Keychain, browser data, Notes, Telegram, screenshots."),
    ("cthulhu", "Cthulhu Stealer", "stealer", ("cthulhu",), "Go-based stealer in fake apps (CleanMyMac, Adobe); "
     "osascript password prompt, Keychain and crypto-wallet theft, sends to C2."),
    ("metastealer", "MetaStealer (macOS)", "stealer", ("metastealer",), "Go-based stealer disguised as business "
     "documents in .dmg files; steals Keychain, passwords and files."),
    ("realst", "Realst Stealer", "stealer", ("realst", "realstealer"), "Rust stealer distributed via fake blockchain "
     "games; steals browser data, crypto wallets and Keychain."),
    ("macstealer", "MacStealer", "stealer", ("macstealer",), "Python-built stealer (weed.dmg) that collects Keychain, "
     "browser passwords and documents and sends them via Telegram."),
    ("xloader", "XLoader / Formbook (macOS)", "stealer", ("xloader", "formbook"), "Stealer/keylogger; macOS builds "
     "disguised as OfficeNote and similar apps, steal clipboard, browser credentials, keystrokes."),
    ("macsync", "MacSync / Mac.c Stealer", "stealer", ("macsync", "mac.c"), "Newer stealer family (2025+), "
     "code-signed Swift droppers, AMOS-like theft of passwords, wallets and files."),
    # ---- adware / browser hijackers (mostly PUA)
    ("adload", "Adload", "adware", ("adload",), "Adware/proxyware Mach-O (often Go) with LaunchAgents, search "
     "hijacking and turning the Mac into a residential proxy."),
    ("shlayer", "Shlayer / Bundlore", "adware", ("shlayer", "bundlore", "zshlayer"), "Adware dropper from fake Flash "
     "/ video-player installers: bash script that openssl-decrypts and runs an embedded payload, removes quarantine."),
    ("pirrit", "Pirrit", "adware", ("pirrit",), "Adware that injects ads into Safari/Chrome via proxies and extensions."),
    ("genieo", "Genieo", "adware", ("genieo",), "Browser hijacker/adware changing search and homepage."),
    ("maxofferdeal", "MaxOfferDeal / Safari adware", "adware", ("maxofferdeal", "searchmine", "searchbaron"),
     "Browser hijackers redirecting searches through ad domains, installed with LaunchAgents and configuration "
     "profiles."),
    ("silversparrow", "Silver Sparrow", "downloader", ("silversparrow", "silver sparrow"), "Downloader in .pkg "
     "installers using JavaScript in Distribution XML, LaunchAgent polling a C2 for payloads."),
    # ---- spyware / backdoors / APT
    ("xcsset", "XCSSET", "backdoor", ("xcsset",), "Infects Xcode projects; run-only AppleScript modules steal browser "
     "data, notes, Telegram, inject into Safari, persist via LaunchAgents and dock shortcuts."),
    ("cloudmensis", "CloudMensis", "backdoor", ("cloudmensis", "badrat"), "Spyware using pCloud/Yandex/Dropbox as C2; "
     "exfiltrates documents, keystrokes, screenshots."),
    ("jokerspy", "JokerSpy", "backdoor", ("jokerspy", "swiftbelt"), "Python backdoor with SwiftBelt recon tool, "
     "targets crypto exchanges."),
    ("windtail", "WindTail", "backdoor", ("windtail",), "APT backdoor that exfiltrates documents, persists as login item."),
    ("oceanlotus", "OceanLotus (APT32)", "backdoor", ("oceanlotus", "apt32"), "Vietnamese APT backdoor delivered in "
     "fake documents/apps; encrypted Mach-O with C2 commands."),
    # ---- North Korea (Lazarus / BlueNoroff / Famous Chollima)
    ("rustbucket", "RustBucket", "backdoor", ("rustbucket",), "BlueNoroff: fake PDF viewer app, second-stage "
     "downloaded only when the right PDF is opened, Rust/Swift backdoor, LaunchAgent persistence."),
    ("kandykorn", "KandyKorn", "backdoor", ("kandykorn", "sugarloader", "hloader"), "Lazarus: Python loader from a "
     "fake crypto-bot project, reflective loading of SUGARLOADER/KandyKorn RAT, Discord-borne lures."),
    ("objcshellz", "ObjCShellz", "backdoor", ("objcshellz",), "BlueNoroff simple Objective-C remote shell that runs C2 "
     "commands."),
    ("poolrat", "POOLRAT / SIMPLESEA", "backdoor", ("poolrat", "simplesea"), "Lazarus backdoor (3CX supply-chain)."),
    ("hiddenrisk", "Hidden Risk (BlueNoroff)", "backdoor", ("hidden risk", "hiddenrisk"), "Fake crypto-news PDF lure "
     "app, downloads backdoor, persists by appending to ~/.zshenv."),
    ("beavertail", "BeaverTail / InvisibleFerret", "stealer", ("beavertail", "invisibleferret", "ottercookie",
     "contagious interview"), "North Korean 'fake job interview' campaign: obfuscated JavaScript in a coding test "
     "project or npm package steals browser wallets and downloads the Python backdoor InvisibleFerret (keylogger, "
     "remote access)."),
    ("ferret", "FlexibleFerret / FrostyFerret", "stealer", ("flexibleferret", "frostyferret", "ferret",
     "chromeupdate"), "North Korean fake camera/driver/Chrome update apps that show a fake password dialog and send "
     "the password to Dropbox; persistence via LaunchAgent."),
    ("nimdoor", "NimDoor", "backdoor", ("nimdoor",), "North Korean Nim backdoor for Web3/crypto staff via fake Zoom "
     "update script on Telegram; AppleScript, zsh stealer of Keychain and browser data."),
    ("spectralblur", "SpectralBlur", "backdoor", ("spectralblur",), "North Korean backdoor with file transfer, shell "
     "and sleep commands."),
    # ---- ransomware / miners
    ("evilquest", "EvilQuest / ThiefQuest", "ransomware", ("evilquest", "thiefquest"), "Ransomware + data theft + "
     "virus spreading through pirated apps; encrypts files, keylogger, reverse shell."),
    ("keranger", "KeRanger", "ransomware", ("keranger",), "Ransomware shipped in a trojanized Transmission installer."),
    ("lockbit_mac", "LockBit (macOS build)", "ransomware", ("lockbit",), "Test macOS/Apple Silicon build of the "
     "LockBit encryptor."),
    ("turtle", "Turtle ransomware", "ransomware", ("turtle",), "Go-based cross-platform ransomware with a macOS build."),
    ("xmrig", "XMRig coinminer", "miner", ("xmrig", "coinminer", "cryptominer", "miner"), "Monero miner; malicious "
     "when hidden in cracked apps or started by LaunchAgents without the user's knowledge (stratum pools)."),
    # ---- offensive tools / C2 implants
    ("mythic", "Mythic agent (Poseidon/Apfell)", "hacktool", ("mythic", "apfell", "poseidon agent"), "Open-source C2 "
     "framework agents for macOS: Go (Poseidon) or JavaScript-for-Automation (Apfell) implants."),
    ("sliver", "Sliver implant", "hacktool", ("sliver",), "Open-source Go C2 implant (BishopFox) used by red teams "
     "and attackers."),
    ("geacon", "Geacon (Cobalt Strike in Go)", "hacktool", ("geacon", "cobaltstrike", "cobalt strike", "crossc2"),
     "Go reimplementation of the Cobalt Strike beacon for macOS/Linux."),
    ("empire", "Empire / EmPyre", "hacktool", ("empire", "empyre"), "Python post-exploitation framework launchers."),
    # ---- delivery techniques
    ("clickfix", "ClickFix / fake CAPTCHA lure", "downloader", ("clickfix", "fakecaptcha", "fake captcha"), "Web page "
     "or message telling the user to paste a command into Terminal; the copied command downloads and runs a "
     "stealer (often AMOS)."),
]

KB_BY_ID = {k[0]: k for k in KB}

CATEGORY_PL = {"stealer": "kradzież danych", "adware": "adware", "downloader": "pobieranie i uruchamianie",
               "backdoor": "tylne drzwi", "ransomware": "ransomware", "miner": "koparka kryptowalut",
               "hacktool": "narzędzie hakerskie", "phishing": "wyłudzanie", "persistence": "autostart"}

# heuristic / behaviour names → the category they point at
_HINTS = [
    (re.compile(r"keychain|credential|password|wallet|cookie|browser|stealer|exfil|logindata", re.I), "stealer"),
    (re.compile(r"downloadexec|pipetoshell|fetchremote|dropper|downloader|curlpipe|stager|loader", re.I), "downloader"),
    (re.compile(r"reverseshell|backdoor|\bc2\b|_c2_|rat\b|remoteaccess|implant", re.I), "backdoor"),
    (re.compile(r"ransom|encrypt", re.I), "ransomware"),
    (re.compile(r"miner|stratum|xmrig", re.I), "miner"),
    (re.compile(r"adware|hijack|searchhijack", re.I), "adware"),
    (re.compile(r"hacktool|mythic|sliver|cobalt", re.I), "hacktool"),
]
# ClamAV / vendor names: Platform.Category.Family-123 – these family slots say nothing
_GENERIC = {"agent", "generic", "malware", "trojan", "downloader", "dropper", "heuristic", "heuristics", "exploit",
            "packed", "suspicious", "unknown", "script", "macro", "doc", "pdf", "html", "js", "osx", "macos", "win",
            "unix", "multios", "andr", "phishing", "coinminer", "adware", "pua", "tool", "backdoor", "keylogger",
            "spyware", "ransomware", "worm", "virus", "test", "eicar", "infostealer", "stealer", "loader", "rat",
            "shell", "cerber", "gen", "community", "core", "custom", "xprotect", "yara", "heur", "behav", "stage",
            "malwarebazaar", "threatfox", "urlhaus", "clamav", "sigbase", "hash", "ioc"}
_WORD = re.compile(r"[a-z][a-z0-9]{2,}")

MAX_OPTIONS = 9
SIGNATURE_ENGINES = {"clamav", "hash", "fuzzy", "ioc"}     # their names carry a family; heuristics name behaviours


def _haystack(det: dict) -> str:
    return f"{det.get('name', '')} {det.get('description', '')}".lower().replace("_", " ").replace("-", " ")


def _known_hits(text: str) -> list[str]:
    words = set(_WORD.findall(text))
    hits = []
    for fid, _name, _cat, aliases, _desc in KB:
        for a in aliases:
            if (" " in a or "." in a) and a in text or a in words:
                hits.append(fid)
                break
    return hits


def _signature_family(name: str) -> str | None:
    """'ClamAV:Osx.Trojan.Amos-9958390-0' → 'amos'; 'MalwareBazaar.AtomicStealer' → 'atomicstealer'."""
    base = name.split(":", 1)[-1]
    parts = re.split(r"[.\-/]", base)
    for p in parts[2:3] + parts[1:2]:                  # Platform.Category.Family-NNN, then Source.Family
        p = p.lower()
        if p and p.isalpha() and len(p) >= 4 and p not in _GENERIC:
            return p
    return None


def candidates(detections: list[dict]) -> list[dict]:
    """Options for the classifier: families the static engines point at (most-cited first), category look-alikes
    when no family was named, and always 'other' and 'benign'. Each option: id, name, category, description,
    cited (how many detections named it)."""
    cited: dict[str, int] = {}
    unknown: dict[str, list[str]] = {}
    cats: dict[str, int] = {}
    for d in detections:
        if d.get("engine") == "ai":
            continue
        text = _haystack(d)
        hits = _known_hits(text)
        for fid in hits:
            cited[fid] = cited.get(fid, 0) + 1
        if not hits and d.get("engine") in SIGNATURE_ENGINES and (fam := _signature_family(d.get("name") or "")):
            unknown.setdefault(fam, []).append((d.get("description") or d.get("name") or "")[:160])
        for rx, cat in _HINTS:
            if rx.search(d.get("name") or ""):
                cats[cat] = cats.get(cat, 0) + 1
    opts: list[dict] = []
    for fid, n in sorted(cited.items(), key=lambda kv: -kv[1]):
        _id, name, cat, _al, desc = KB_BY_ID[fid]
        opts.append({"id": fid, "name": name, "category": cat, "description": desc, "cited": n})
    for fam, descs in list(unknown.items())[:4]:
        opts.append({"id": "sig_" + fam, "name": fam.capitalize(), "category": "other", "cited": len(descs),
                     "description": "Family named by a signature; the signature says: " + "; ".join(descs[:2])})
    if not opts and cats:                              # nothing named a family: offer the look-alikes
        for cat, _n in sorted(cats.items(), key=lambda kv: -kv[1])[:2]:
            for fid, name, c, _al, desc in KB:
                if c == cat and len(opts) < MAX_OPTIONS - 2:
                    opts.append({"id": fid, "name": name, "category": c, "description": desc, "cited": 0})
    opts = opts[:MAX_OPTIONS - 2]
    top_cat = max(cats, key=cats.get) if cats else (opts[0]["category"] if opts else "other")
    opts.append({"id": "other", "name": "Inna szkodliwa rodzina", "category": top_cat, "cited": 0,
                 "description": "Clearly harmful behaviour, but none of the families above matches it."})
    opts.append({"id": "benign", "name": "Legalne oprogramowanie", "category": "none", "cited": 0,
                 "description": "Legitimate software (installer, updater, admin/developer tool, browser, game, "
                                "SDK…) – the engine findings are explained by normal behaviour."})
    return opts

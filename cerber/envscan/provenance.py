"""Where a program came from and how far to trust it (provenance), plus suspicious names.

Nothing here decides alone. `origin()` describes an executable (signature, notarisation hints, how it got onto
this Mac – App Store, Homebrew, a download by which app from which address and when –, how old it is, where it
lives) and sums it up as a trust tier; `name_signals()` flags names that malware likes (keyloggers, stealers,
RATs, fake updates, double extensions, look-alike characters, random names …). Both feed the process / network
judgement and cerber.correlate, which only raises an alarm when several independent things point the same way.

Trust tiers (best first):
    apple        system volume / Apple signature
    appstore     Mac App Store signature or receipt
    devid        valid Developer ID signature (hardened runtime: probably notarised)
    pkgmgr       Homebrew / MacPorts / nix / language toolchains (ad-hoc signed by design)
    local_build  linker-signed code built on this Mac (cargo/go/clang/Xcode output in a project folder)
    unknown      ad-hoc / unsigned, nothing else known
    untrusted    broken signature, revoked, deleted while running, or unsigned + downloaded / odd location
Read-only: file metadata, xattrs and the LaunchServices quarantine database; no network.
"""
from __future__ import annotations

import os
import re
import sqlite3
import time
import unicodedata

from ..core import Confidence
from .model import Signal
from .patterns import analyze_command, classify_path, is_apple_path, looks_random

TRUSTED = ("apple", "appstore", "devid")
TIERS = ("apple", "appstore", "devid", "pkgmgr", "local_build", "unknown", "untrusted")
TRUST_PL = {"apple": "system Apple", "appstore": "Mac App Store", "devid": "zaufany twórca (Developer ID)",
            "pkgmgr": "menedżer pakietów (np. Homebrew)", "local_build": "zbudowany na tym Macu",
            "unknown": "nieznane pochodzenie", "untrusted": "niezaufany"}
QUARANTINE_DB = "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
CORE_DATA_EPOCH = 978307200
BROWSERS = re.compile(r"(?i)chrome|safari|firefox|brave|edge|opera|arc|vivaldi|orion|chromium|tor browser")
MESSENGERS = re.compile(r"(?i)telegram|discord|whatsapp|messages|signal|slack|skype|mail|outlook|spark|airmail|"
                        r"thunderbird|wechat|line|viber|teams")
DEV_DIRS = re.compile(r"/(?:DerivedData|target/(?:debug|release)|\.build|build|dist|out|bin|node_modules|"
                      r"\.venv|venv|cmake-build-[^/]+|Build/Products|zig-out)/")
_qdb_cache: dict[str, dict] = {}


# --------------------------------------------------------------------------- xattrs

def _getxattr(path: str, name: str) -> bytes | None:
    try:
        from ..analyzers.exe_macos_trust import getxattr
        return getxattr(path, name)
    except Exception:  # noqa: BLE001
        return None


def parse_quarantine(raw: bytes | str | None) -> dict | None:
    """com.apple.quarantine = "flags;hex-time;agent;uuid" → {flags, time, agent, uuid, approved}."""
    if not raw:
        return None
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    parts = text.strip("\x00").split(";")
    if len(parts) < 3:
        return None
    try:
        flags = int(parts[0], 16)
    except ValueError:
        flags = 0
    try:
        ts = int(parts[1], 16)
    except ValueError:
        ts = None
    return {"flags": flags, "time": ts, "agent": parts[2] or None, "uuid": parts[3] if len(parts) > 3 else None,
            "approved": bool(flags & 0x40)}


def quarantine_events(home: str) -> dict:
    """LaunchServices download history: uuid → {url, origin, agent, time}. Cached per home."""
    if home in _qdb_cache:
        return _qdb_cache[home]
    out: dict = {}
    db = os.path.join(home, QUARANTINE_DB)
    if os.path.exists(db):
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
            try:
                rows = con.execute("SELECT LSQuarantineEventIdentifier, LSQuarantineDataURLString, "
                                   "LSQuarantineOriginURLString, LSQuarantineAgentName, LSQuarantineTimeStamp "
                                   "FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 20000").fetchall()
            finally:
                con.close()
            for uid, url, origin, agent, ts in rows:
                out[str(uid).upper()] = {"url": url, "origin": origin, "agent": agent,
                                         "time": (ts + CORE_DATA_EPOCH) if isinstance(ts, (int, float)) else None}
        except sqlite3.Error:
            pass
    _qdb_cache[home] = out
    return out


# --------------------------------------------------------------------------- helpers

def bundle_of(path: str) -> str | None:
    """Outermost .app bundle that contains `path` (the unit the user installed)."""
    m = re.match(r"^(.*?\.app)(?:/|$)", path)
    return m.group(1) if m else None


def _birth(path: str) -> float | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return getattr(st, "st_birthtime", None) or st.st_mtime


def _days(ts: float | None, now: float) -> float | None:
    return None if ts is None else max(0.0, (now - ts) / 86400)


def _cask_apps() -> set[str]:
    apps: set[str] = set()
    for root in ("/opt/homebrew/Caskroom", "/usr/local/Caskroom"):
        try:
            for token in os.listdir(root):
                tdir = os.path.join(root, token)
                for ver in os.listdir(tdir):
                    vdir = os.path.join(tdir, ver)
                    if os.path.isdir(vdir):
                        apps.update(n for n in os.listdir(vdir) if n.endswith(".app"))
        except OSError:
            continue
    return apps


_CASKS: set[str] | None = None


def install_source(path: str, bundle: str | None) -> str | None:
    global _CASKS
    if bundle and os.path.exists(os.path.join(bundle, "Contents/_MASReceipt/receipt")):
        return "App Store"
    pi = classify_path(path)
    if pi.has("pkgmgr"):
        return "Homebrew" if "/homebrew/" in path.lower() or "/Cellar/" in path else "menedżer pakietów"
    if bundle:
        if _CASKS is None:
            _CASKS = _cask_apps()
        if os.path.basename(bundle) in _CASKS:
            return "Homebrew (cask)"
    return None


def is_local_build(path: str, sign_flags: str = "", status: str = "", home: str | None = None) -> bool:
    """Code built on this Mac: linker-signed ad-hoc in a project/build folder (not a download, not hidden)."""
    if status not in ("adhoc", "unsigned"):
        return False
    pi = classify_path(path, home)
    if pi.has("tmp", "shared", "trash", "volume", "hidden", "random_appsupport", "random_library", "apple"):
        return False
    if _getxattr(path, "com.apple.quarantine"):
        return False
    linker = "linker-signed" in (sign_flags or "")
    in_dev = bool(DEV_DIRS.search(path)) or "/Developer/" in path or "/Projects/" in path or "/projekty" in path
    return linker and (in_dev or not path.startswith(("/Applications/", "/Library/")))


def script_of(cmdline: list | None) -> str | None:
    """The script file an interpreter runs (`python3 /x/y.py`, `node /x/cli.js`, `bash x.sh`)."""
    if not cmdline:
        return None
    try:
        ci = analyze_command([str(a) for a in cmdline])
    except Exception:  # noqa: BLE001
        return None
    return ci.script if ci.interpreter and ci.script and ci.script.startswith("/") else None


def dev_context(exe: str | None, cmdline: list | None = None, sign=None, home: str | None = None) -> bool:
    """Developer / package-manager code: Homebrew tools, local builds, and interpreters running a script from a
    project or a package folder (node_modules, site-packages, .venv, a git checkout under ~). Connections and
    open ports of such code are everyday development, not an incident – unless something else says otherwise."""
    home = home or os.path.expanduser("~")
    if exe:
        pi = classify_path(exe, home)
        if pi.has("pkgmgr"):
            return True
        if sign is not None and is_local_build(exe, getattr(sign, "flags", ""), getattr(sign, "status", ""), home):
            return True
    sp = script_of(cmdline)
    if not sp:
        return False
    pi = classify_path(sp, home)
    if pi.has("tmp", "shared", "trash", "volume", "hidden", "random_appsupport", "random_library", "varfolders"):
        return False
    if pi.has("pkgmgr") or DEV_DIRS.search(sp) or "/site-packages/" in sp or "/node_modules/" in sp:
        return True
    if re.match(rf"^{re.escape(home)}/(?:Downloads|Desktop)/[^/]+$", sp):
        return False                                     # a loose script straight from Downloads / Desktop
    return sp.startswith(home + "/") and "/Library/" not in sp[len(home):]


# --------------------------------------------------------------------------- origin

def origin(path: str, sign=None, home: str | None = None, now: float | None = None,
           qevents: dict | None = None) -> dict:
    """Everything known about where `path` came from. `sign`: an envscan.util.SignInfo (or None = unknown)."""
    now = now or time.time()
    home = home or os.path.expanduser("~")
    pi = classify_path(path, home)
    exists = os.path.exists(path)
    bundle = bundle_of(path)
    o: dict = {"path": path, "exists": exists, "bundle": bundle, "location": sorted(pi.tags)}
    if sign is not None:
        o.update(sign_status=getattr(sign, "status", None), signer=getattr(sign, "signer", None),
                 team_id=getattr(sign, "team_id", None) or None, hardened=bool(getattr(sign, "runtime", False)),
                 verified=getattr(sign, "verified", None))
    status = getattr(sign, "status", "") if sign is not None else ""
    q = None
    for p in (path, bundle):
        if p and exists:
            q = parse_quarantine(_getxattr(p, "com.apple.quarantine"))
            if q:
                break
    if q:
        ev = (qevents if qevents is not None else quarantine_events(home)).get(str(q.get("uuid") or "").upper())
        if ev:
            q.update(url=ev.get("url"), origin_url=ev.get("origin"), agent=q.get("agent") or ev.get("agent"),
                     time=q.get("time") or ev.get("time"))
        q["days"] = _days(q.get("time"), now)
        o["download"] = q
    o["installed_by"] = install_source(path, bundle) if exists else None
    born = _birth(bundle or path) if exists else None
    o["age_days"] = _days(born, now)
    # trust tier
    if pi.has("apple") or status == "apple" or is_apple_path(path):
        tier = "apple"
    elif status == "appstore" or o["installed_by"] == "App Store":
        tier = "appstore"
    elif not exists:
        tier = "untrusted"
    elif sign is not None and getattr(sign, "verified", None) is False and status in ("devid", "appstore", "development", "other"):
        tier = "untrusted"                            # signature broken: modified after signing
    elif status == "devid":
        tier = "devid"
    elif pi.has("pkgmgr") or (o["installed_by"] or "").startswith(("Homebrew", "menedżer")):
        tier = "pkgmgr"
    elif is_local_build(path, getattr(sign, "flags", ""), status, home):
        tier = "local_build"
    elif status in ("adhoc", "unsigned", "development", "other", "") and (
            q or pi.has("tmp", "shared", "trash", "volume", "hidden", "random_appsupport", "random_library")):
        tier = "untrusted"
    else:
        tier = "unknown"
    o["trust"] = tier
    o["label"] = origin_label(o)
    return o


def origin_label(o: dict) -> str:
    """One Polish sentence: "Developer ID: Valve · pobrany przez Chrome 3 dni temu z steampowered.com · 2 lata"."""
    parts = [o.get("signer") or TRUST_PL.get(o.get("trust", ""), "")]
    if o.get("installed_by"):
        parts.append(f"zainstalowany przez {o['installed_by']}")
    d = o.get("download")
    if d:
        src = d.get("origin_url") or d.get("url") or ""
        host = re.sub(r"^[a-z]+://([^/]+).*$", r"\1", src) if src else ""
        when = d.get("days")
        parts.append("pobrany" + (f" przez {d['agent']}" if d.get("agent") else "")
                     + (f" z {host}" if host else "") + (f" {_ago(when)}" if when is not None else ""))
    if o.get("trust") == "local_build":
        parts.append("zbudowany lokalnie")
    if o.get("age_days") is not None and not d:
        parts.append(f"na dysku od {_ago(o['age_days'], suffix=False)}")
    return " · ".join(p for p in parts if p)


def _ago(days: float, suffix: bool = True) -> str:
    if days < 1 / 24:
        s = "kilku minut"
        return "przed chwilą" if suffix else s
    if days < 1:
        h = int(days * 24)
        return f"{h} h temu" if suffix else f"{h} h"
    if days < 60:
        return f"{int(days)} dni temu" if suffix else f"{int(days)} dni"
    if days < 730:
        return f"{int(days / 30)} mies. temu" if suffix else f"{int(days / 30)} mies."
    return f"{int(days / 365)} lat temu" if suffix else f"{int(days / 365)} lat"


def origin_signals(o: dict, prefix: str, what: str = "program") -> list[Signal]:
    """Indicators that come from the origin alone. Small on purpose – correlation adds them up."""
    trust = o.get("trust")
    if trust in TRUSTED or trust in ("pkgmgr", "local_build"):
        return []
    out: list[Signal] = []
    path = o.get("path", "")
    d = o.get("download")
    if d and trust == "untrusted":
        via = d.get("agent") or "?"
        recent = d.get("days") is not None and d["days"] < 14
        out.append(Signal(f"{prefix}.DownloadedUnsigned", 25 if recent else 15, Confidence.MEDIUM,
                          f"{what} bez zaufanego podpisu pobrany z Internetu (przez {via}"
                          + (f", {_ago(d['days'])}" if d.get("days") is not None else "") + ")",
                          [path, d.get("origin_url") or d.get("url") or ""]))
        if MESSENGERS.search(via):
            out.append(Signal(f"{prefix}.FromMessenger", 15, Confidence.LOW,
                              f"przysłany komunikatorem lub pocztą ({via}) – częsty sposób rozsyłania złośliwych "
                              "programów", [path]))
    if o.get("exists") is False:
        out.append(Signal(f"{prefix}.DeletedWhileRunning", 20, Confidence.MEDIUM,
                          f"{what} działa, ale jego pliku już nie ma na dysku", [path]))
    elif o.get("verified") is False and o.get("sign_status") in ("devid", "appstore", "other", "development"):
        out.append(Signal(f"{prefix}.BrokenSignature", 35, Confidence.MEDIUM,
                          f"{what} zmieniony po podpisaniu (podpis nieważny)", [path]))
    age = o.get("age_days")
    if trust == "untrusted" and age is not None and age < 2:
        out.append(Signal(f"{prefix}.Fresh", 10, Confidence.LOW, f"{what} pojawił się na dysku {_ago(age)}", [path]))
    return out


# --------------------------------------------------------------------------- names

# word families (matched on tokens of the name, so "Steal" in "StealthBrowser" or "rat" in "Pirate" do not count)
_FAMILIES: list[tuple[str, int, str]] = [
    (r"key ?log+(?:ger|er)?|keystroke|keyspy|keycapt", 40, "rejestrator klawiszy (keylogger)"),
    (r"steal(?:er)?|stealr|grabber|grab(?:ber)?|cookie ?(?:stealer|grab)|password ?(?:stealer|grab|dump)|"
     r"pass ?dump|cred(?:ential)?s? ?(?:dump|steal|harvest)|wallet ?(?:drain|steal)|drainer|clipper", 40,
     "kradzież haseł / portfeli (stealer)"),
    (r"rat|remote ?access ?trojan|backdoor|back ?door|revshell|reverse ?shell|bind ?shell|webshell", 35,
     "zdalne sterowanie komputerem (RAT / backdoor)"),
    (r"trojan|virus|wirus|malware|worm|rootkit|bootkit|ransom(?:ware)?|crypt[o0]?locker|locker|wiper|botnet|"
     r"zombie|spyware|stalkerware|spy ?(?:agent|ware|app)|keylog", 35, "nazwa szkodliwego oprogramowania"),
    (r"payload|dropper|stager|shellcode|inject(?:or)?|hollow|loader ?(?:x|rat)|implant|beacon|c ?2|cnc", 25,
     "element ataku (payload / dropper / implant)"),
    (r"meterpreter|metasploit|msfvenom|cobalt ?strike|sliver|mythic|poseidon|apfell|havoc|empire|empyre|"
     r"mimikatz|lazagne|pupy|quasar|njrat|darkcomet|nanocore|remcos|asyncrat|xworm|atomic ?stealer|amos|"
     r"banshee|cthulhu|poseidon ?stealer|realst|metastealer|macstealer|xcsset|silver ?sparrow|shlayer|bundlore|"
     r"adload|pirrit|genieo|mackeeper", 45, "nazwa znanego narzędzia ataku lub rodziny złośliwego oprogramowania"),
    (r"xmrig|xmr ?stak|cpuminer|minerd|ccminer|nbminer|lolminer|nanominer|srbminer|cryptonight|miner", 30,
     "koparka kryptowalut"),
    (r"flash ?player|adobe ?flash|flash ?update", 30, "fałszywa aktualizacja Flash Playera (Flash nie istnieje od 2020)"),
    (r"crack(?:ed)?|keygen|patch(?:er)?|activator|kms ?pico|loader ?crack|serial ?gen|warez|nulled|unlocker", 20,
     "„crack” / keygen – częsty nośnik złośliwego oprogramowania"),
    (r"hack(?:tool|er)?|exploit|privesc|priv ?esc|bypass|disable ?(?:xprotect|gatekeeper|sip|av)|kill ?av|"
     r"av ?killer|uac", 20, "narzędzie hakerskie / obejście zabezpieczeń"),
]
_FAMILY_RX = [(re.compile(rf"(?:^|\s)(?:{rx})(?:$|\s)", re.I), score, why) for rx, score, why in _FAMILIES]
_LURES = re.compile(r"(?i)(?:^|\s)(?:flash ?player|adobe ?flash|update|updater|installer|install|setup|"
                    r"codec|player|free|premium|invoice|faktura|payment|platnosc|płatność|receipt|order|zamowienie|"
                    r"zamówienie|resume|cv|document|dokument|scan|skan|photo|zdjecie|zdjęcie|video|wideo|"
                    r"tradingview|metamask|ledger ?live|trezor|exodus|electrum|wallet)(?:$|\s)")
_DOC_EXT = r"pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|heic|mp4|mov|mp3|zip|csv|odt|pages|numbers|key"
_EXEC_EXT = r"app|command|tool|sh|bash|zsh|scpt|applescript|terminal|pkg|mpkg|dmg|jar|py|pl|rb|js|exe|scr|bat|" \
            r"cmd|vbs|ps1|workflow|action|webloc|inetloc|url"
_DOUBLE_EXT = re.compile(rf"(?i)\.(?:{_DOC_EXT})\s*\.(?:{_EXEC_EXT})$")
_SPACE_EXT = re.compile(rf"(?i)\s{{2,}}\.(?:{_EXEC_EXT})$|\.(?:{_DOC_EXT})\s+$")
_BIDI = re.compile("[‪-‮⁦-⁩​-‏⁠﻿]")
_APPLE_LIKE = re.compile(r"(?i)^(?:com\.apple\.|apple ?(?:update|security|helper|service|daemon|agent|sync)|"
                         r"mac ?os ?(?:update|helper|service|agent)|macos ?(?:update|helper)|system ?(?:update|helper|"
                         r"service)|software ?update|icloud ?(?:helper|sync|agent)|safari ?(?:update|helper)|"
                         r"finder ?(?:helper|agent)|xprotect|launchd|kernel_?task|mdworker|syspolicyd|trustd|"
                         r"securityd|softwareupdated|cfprefsd|loginwindow|windowserver)")


def name_tokens(name: str) -> str:
    """'KeyLogger_v2.app' → 'key logger v2 app' (camelCase, digits and separators split, lower-case)."""
    base = unicodedata.normalize("NFKC", name)
    base = re.sub(r"([a-ząćęłńóśźż])([A-ZĄĆĘŁŃÓŚŹŻ])", r"\1 \2", base)
    base = re.sub(r"([A-Za-z])(\d)|(\d)([A-Za-z])", lambda m: " ".join(x for x in m.groups() if x), base)
    return " ".join(re.split(r"[^0-9A-Za-ząćęłńóśźżĄĆĘŁŃÓŚŹŻ]+", base)).lower().strip()


def _mixed_script(name: str) -> bool:
    """Latin mixed with look-alike Cyrillic/Greek letters (homoglyph spoofing: 'Gооgle Chrome')."""
    scripts = set()
    for ch in name:
        if ch.isalpha():
            n = unicodedata.name(ch, "")
            scripts.add("LATIN" if n.startswith("LATIN") else "CYRILLIC" if n.startswith("CYRILLIC")
                        else "GREEK" if n.startswith("GREEK") else "OTHER")
    return "LATIN" in scripts and bool(scripts & {"CYRILLIC", "GREEK"})


def name_signals(name: str, prefix: str, what: str = "plik", trusted: bool = False,
                 untrusted: bool = False) -> list[Signal]:
    """Indicators in a file/process/label name. `trusted` (Apple / App Store / Developer ID) silences the word
    families – a signed "Keyboard Maestro" or "Little Snitch" must not look like malware; tricks that only make
    sense for deceit (double extension, invisible/look-alike characters) always count."""
    if not name:
        return []
    out: list[Signal] = []
    base = os.path.basename(name.rstrip("/"))
    if _BIDI.search(base):
        out.append(Signal(f"{prefix}.Name.InvisibleChars", 45, Confidence.HIGH,
                          f"{what}: nazwa zawiera niewidoczne znaki sterujące (np. odwracanie kierunku tekstu) – "
                          "ukrywa prawdziwe rozszerzenie", [repr(base)[:120]]))
    if _DOUBLE_EXT.search(base) or _SPACE_EXT.search(base):
        out.append(Signal(f"{prefix}.Name.DoubleExtension", 30, Confidence.MEDIUM,
                          f"{what}: podwójne rozszerzenie – udaje dokument, a jest programem/skryptem", [base]))
    if _mixed_script(base):
        out.append(Signal(f"{prefix}.Name.Homoglyph", 25, Confidence.MEDIUM,
                          f"{what}: nazwa miesza litery łacińskie z podobnymi cyrylicą/greką (podszywanie się)",
                          [base]))
    if trusted:
        return out
    tokens = name_tokens(re.sub(r"\.(?:app|command|sh|py|pkg|dmg|plist|tool|exe|bin|dylib|scpt)$", "", base,
                                flags=re.I))
    best = None
    for rx, score, why in _FAMILY_RX:
        if rx.search(tokens) and (best is None or score > best[0]):
            best = (score, why)
    if best:
        # a name never decides on its own ("wirus.txt" may be a prank or a biology note): at most 20 points, LOW
        score = max(5, round(min(best[0], 40) / 2)) if untrusted else max(3, round(min(best[0], 40) / 5))
        out.append(Signal(f"{prefix}.Name.Malicious", score, Confidence.LOW,
                          f"{what}: nazwa może wskazywać na {best[1]} (sama nazwa niczego nie przesądza)", [base]))
    if _APPLE_LIKE.search(base) and untrusted:
        out.append(Signal(f"{prefix}.Name.AppleLike", 20, Confidence.LOW,
                          f"{what}: nazwa podszywa się pod element systemu Apple, a program nie jest od Apple", [base]))
    if untrusted and _LURES.search(tokens):
        out.append(Signal(f"{prefix}.Name.Lure", 10, Confidence.LOW,
                          f"{what}: nazwa jak przynęta (aktualizacja, instalator, faktura, portfel…)", [base]))
    stem = re.sub(r"\.[A-Za-z0-9]{1,10}$", "", base).lstrip(".")
    if untrusted and len(stem) >= 6 and (looks_random(stem) or re.fullmatch(r"[0-9a-f]{12,}|[A-Za-z0-9]{24,}", stem)):
        out.append(Signal(f"{prefix}.Name.Random", 15, Confidence.LOW,
                          f"{what}: losowo wyglądająca nazwa (typowe dla złośliwych programów)", [base]))
    if untrusted and base.startswith(".") and not base.startswith(("._", ".DS_Store")):
        out.append(Signal(f"{prefix}.Name.Hidden", 15, Confidence.LOW, f"{what}: ukryta nazwa (zaczyna się od kropki)",
                          [base]))
    return out

"""Live attack evidence: what a running program is doing right now, not what it is.

Cheap, read-only, user-level checks (no root, no extra processes, nothing left running) used by the environment
scan (collector "live") and by the live watch (netwatch: Mega scan and background protection), which re-checks
only what is due (cache by pid + start time, a time budget per poll):

    remote shell   a shell or interpreter whose standard input and output are a TCP connection
                   (reverse shell, bind shell, `nc -e`, `bash -i >& /dev/tcp/…`, dup2'ed sockets)
    secret access  a program that does not own them holding browser passwords / cookies, the login keychain
                   file, crypto-wallet data or a messenger session open – or copies of them in a temp folder
    (staging)      copies of such data collected in /tmp, /Users/Shared or $TMPDIR: files.stealer_artifacts()

Apple / App Store / Developer ID programs are never looked at (their owners, Spotlight, backup, sync and security
tools live there). Interpreters (python, node, osascript, shells …) always are – the script is the suspect, not the
Apple-signed interpreter – and Apple's file tools (cp, ditto, zip, sqlite3 …) only count when osascript or a
program of unknown origin started them; the event then names that program (the one to stop).

Every hit carries `confidence` for the active defense (`event_meta`): "high" only for evidence legitimate software
does not produce (score >= 80 with HIGH confidence, i.e. severity "malicious"), "medium" for "suspicious",
"low" for the rest – plus `attack` (remote_shell, credential_theft, c2, masquerade …) and short `evidence`.
"""
from __future__ import annotations

import os
import re
import sys
import time
from typing import Callable

from ..core import Confidence
from .model import LOW_SCORE, Signal, combine, severity_of
from .patterns import SHELLS, analyze_command, classify_path, interpreter_of, is_apple_path, redact

LV = "Heur:Env.Live"
TRUSTED_TIERS = ("apple", "appstore", "devid")

# Apple's own file tools: harmless alone, a stealer's hands when osascript / an unknown program drives them
APPLE_TOOLS = frozenset({"cp", "ditto", "zip", "tar", "sqlite3", "cat", "rsync", "scp", "curl", "mv", "dd", "gzip",
                         "bzip2", "xz", "base64", "openssl", "strings", "head", "tail", "plutil", "sftp", "nc"})
# backup / sync tools read every file of the home folder (keychain and browser stores included)
BACKUP_TOOLS = re.compile(r"(?i)^(?:restic|borg|borgmatic|rsync|rclone|kopia|duplicacy|duplicity|duplicati|arq\w*|"
                          r"bztransmit|bzfilelist|bzbmenu|crashplan\w*|code42\w*|syncthing|unison|carbon copy cloner|"
                          r"ccc\w*|superduper\w*|chronosync\w*|goodsync\w*|mackup|timemachine\w*)$")
BROWSER_BUNDLE = re.compile(r"(?i)/(?:Google Chrome[^/]*|Chromium[^/]*|Brave Browser[^/]*|Microsoft Edge[^/]*|"
                            r"Vivaldi[^/]*|Opera[^/]*|Arc|Thorium[^/]*|Yandex[^/]*|Firefox[^/]*|LibreWolf|"
                            r"Waterfox[^/]*|Zen[^/]*|Floorp|Mullvad Browser|Tor Browser|Safari[^/]*|Orion[^/]*)\.app/")

# ---------------------------------------------------------------------------------------------- secret stores

# Chromium family: Application Support folder → (name, owner regex on exe / bundle / script path)
CHROMIUM = [
    (r"Google/Chrome(?: Beta| Canary| Dev| for Testing)?", "Chrome", r"google chrome|chrome for testing"),
    (r"Chromium", "Chromium", r"chromium"),
    (r"BraveSoftware/Brave-Browser(?:-Beta|-Nightly)?", "Brave", r"brave browser"),
    (r"Microsoft Edge(?: Beta| Dev| Canary)?", "Edge", r"microsoft edge"),
    (r"Vivaldi", "Vivaldi", r"vivaldi"),
    (r"com\.operasoftware\.Opera(?:GX|Neon)?", "Opera", r"/opera"),
    (r"Arc/User Data", "Arc", r"/arc\.app/"),
    (r"Yandex/YandexBrowser", "Yandex", r"yandex"),
    (r"Thorium", "Thorium", r"thorium"),
]
# browser-extension wallets (Chrome Web Store ids) – the most stolen thing on macOS after passwords
WALLET_EXTENSIONS = {
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask", "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
    "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet", "ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
    "fhbohimaelbohpjbbldcngcnapndodjp": "Binance Wallet", "fnjhmkhhmkbjkkabndcnnogagogbneec": "Ronin",
    "egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet", "aholpfdialjgjfhomihkjbmgjidlcdno": "Exodus Web3",
    "dmkamcknogkgcdfhhbddcghachkejeap": "Keplr", "mcohilncbfahbmgdjkbpemcciiolgcge": "OKX Wallet",
    "acmacodkjbdgmoleebolmdjonilkdbch": "Rabby", "bhhhlbepdkbapadjdnnojkbgioiodbic": "Solflare",
    "efbglgofoippbgcjepnhiblaibcnclgk": "Martian", "ejjladinnckdgjemekebdpeokbikhfci": "Petra",
    "opcgpfmipidbgpenhmajoajpbobppdil": "Sui Wallet", "jnlgamecbpmbajjfhmmmlhejkemejdma": "Braavos",
    "dlcobpjiigpikoobohmabehhmhfoodbb": "Argent X", "afbcbjpbpfadlkmhmclhkeeodmamcflc": "Math Wallet",
    "aeachknmefphepccionboohckonoeemg": "Coin98", "hmeobnfnfcmdkdcmlblgagmfpfboieaf": "XDEFI",
    "ffnbelfdoeiohenkjibnmadjiehjhajb": "Yoroi", "lpfcbjknijpeeillifnkikgncikgfhdo": "Nami",
    "kmhcihpebfmpgmihbkipmjlmmioameka": "Eternl", "hpglfhgfnhbgpjdenjgmdgoeiappafln": "Guarda",
    "jiidiaalihmmhddjgbnbgdfflelocpak": "Bitget Wallet", "fcfcfllfndlomdhbehjjcoimbgofdncg": "Leap",
    "fijngjgcjhjmmpcmkeiomlglpeiijkld": "Talisman", "kkpllkodjeloidieedojogacfhpaihoh": "Enkrypt",
    "ppbibelpcjmhbdihakflkdcoccbgbkpo": "UniSat", "idnnbdplmphpflfnlkomgpfbpcgelopg": "Xverse",
}
# paths relative to the home folder: (regex, category, Polish label, owner regex or None = only Apple)
HOME_STORES: list[tuple[str, str, str, str | None]] = [
    (r"Library/Keychains/login\.keychain(?:-db)?$", "keychain", "plik pęku kluczy (login.keychain-db)", None),
    (r"Library/Keychains/[0-9A-F-]{36}/keychain-2\.db", "keychain", "lokalny pęk kluczy (keychain-2.db)", None),
    (r"Library/Cookies/Cookies\.binarycookies$", "cookies", "ciasteczka Safari (zalogowane sesje)", None),
    (r"Library/Containers/com\.apple\.Safari/Data/Library/Cookies/Cookies\.binarycookies$", "cookies",
     "ciasteczka Safari (zalogowane sesje)", None),
    (r"Library/Application Support/(?:Firefox|LibreWolf|Waterfox|zen|Floorp|Mullvad Browser)/Profiles/[^/]+/"
     r"(?:logins\.json|key4\.db|signons\.sqlite)$", "passwords", "hasła zapisane w przeglądarce Firefox",
     r"firefox|librewolf|waterfox|/zen|floorp|mullvad"),
    (r"Library/Application Support/(?:Firefox|LibreWolf|Waterfox|zen|Floorp|Mullvad Browser)/Profiles/[^/]+/"
     r"cookies\.sqlite(?:-wal|-shm)?$", "cookies", "ciasteczka przeglądarki Firefox (zalogowane sesje)",
     r"firefox|librewolf|waterfox|/zen|floorp|mullvad"),
    (r"Library/Application Support/Telegram Desktop/tdata/", "session", "sesję Telegrama (tdata)", r"telegram"),
    (r"Library/Group Containers/6N38VWS5BX\.ru\.keepcoder\.Telegram/", "session", "dane i sesję Telegrama",
     r"telegram"),
    (r"Library/Application Support/(?:discord|discordcanary|discordptb)/Local Storage/leveldb/", "session",
     "token logowania Discorda", r"discord"),
    (r"Library/Application Support/Exodus/exodus\.wallet/", "wallet", "portfel Exodus", r"exodus"),
    (r"\.electrum/wallets/", "wallet", "portfel Electrum", r"electrum"),
    (r"\.electron-cash/wallets/", "wallet", "portfel Electron Cash", r"electron.?cash"),
    (r"Library/Application Support/atomic/Local Storage/", "wallet", "portfel Atomic Wallet", r"atomic"),
    (r"Library/Application Support/Ledger Live/", "wallet", "dane Ledger Live", r"ledger"),
    (r"Library/Application Support/Coinomi/wallets/", "wallet", "portfel Coinomi", r"coinomi"),
    (r"Library/Application Support/Guarda/", "wallet", "portfel Guarda", r"guarda"),
    (r"Library/Application Support/WalletWasabi/Client/Wallets/", "wallet", "portfel Wasabi", r"wasabi"),
    (r"Library/Application Support/(?:Bitcoin|Litecoin|DashCore|Dogecoin)/(?:wallets/|wallet\.dat)", "wallet",
     "portfel kryptowalut (Core)", r"bitcoin|litecoin|dash|dogecoin"),
    (r"Monero/wallets/", "wallet", "portfel Monero", r"monero"),
    (r"Library/Application Support/Binance/", "wallet", "dane aplikacji Binance", r"binance"),
    (r"Library/Application Support/@trezor/suite-desktop/", "wallet", "dane Trezor Suite", r"trezor"),
    (r"Library/Application Support/Daedalus[^/]*/wallets/", "wallet", "portfel Daedalus", r"daedalus"),
    (r"\.sparrow/wallets/", "wallet", "portfel Sparrow", r"sparrow"),
]
# names of copied stores (a stealer works on copies in a temp folder)
COPY_NAMES = {"login data": ("passwords", "kopię haseł przeglądarki (Login Data)"),
              "login data for account": ("passwords", "kopię haseł przeglądarki (Login Data)"),
              "key4.db": ("passwords", "kopię kluczy haseł Firefoksa (key4.db)"),
              "login.keychain-db": ("keychain", "kopię pęku kluczy (login.keychain-db)"),
              "login.keychain": ("keychain", "kopię pęku kluczy (login.keychain)"),
              "cookies.binarycookies": ("cookies", "kopię ciasteczek Safari"),
              "wallet.dat": ("wallet", "kopię portfela (wallet.dat)")}
CATEGORY_SCORE = {"keychain": 90, "passwords": 80, "wallet": 80, "session": 70, "cookies": 55}
CATEGORY_PL = {"keychain": "pęk kluczy", "passwords": "hasła", "wallet": "portfel kryptowalut",
               "session": "sesja komunikatora", "cookies": "ciasteczka"}

_HOME_RX = [(re.compile(rx), cat, label, re.compile(owner, re.I) if owner else None)
            for rx, cat, label, owner in HOME_STORES]
_CHROMIUM_RX = [(re.compile(rf"^Library/Application Support/{root}/(.+)$"), name, re.compile(owner, re.I))
                for root, name, owner in CHROMIUM]
_CR_PASSWORDS = re.compile(r"(?:^|/)(?:Login Data(?: For Account)?|Web Data)(?:-journal|-wal|-shm)?$")
_CR_COOKIES = re.compile(r"(?:^|/)Cookies(?:-journal|-wal|-shm)?$")
_CR_EXTENSION = re.compile(r"(?:Local Extension Settings|Sync Extension Settings|IndexedDB)/(?:chrome-extension_)?"
                           r"([a-p]{32})")


def secret_store(path: str, home: str) -> dict | None:
    """{category, label, owner (compiled regex or None), copy} when `path` is a credential / session store."""
    if not path or not path.startswith("/"):
        return None
    if path.startswith(home + "/"):
        rel = path[len(home) + 1:]
        for rx, name, owner in _CHROMIUM_RX:
            m = rx.match(rel)
            if not m:
                continue
            rest = m.group(1)
            if _CR_PASSWORDS.search(rest):
                return {"category": "passwords", "label": f"hasła zapisane w przeglądarce {name}", "owner": owner,
                        "copy": False}
            if _CR_COOKIES.search(rest):
                return {"category": "cookies", "label": f"ciasteczka przeglądarki {name} (zalogowane sesje)",
                        "owner": owner, "copy": False}
            e = _CR_EXTENSION.search(rest)
            if e and e.group(1) in WALLET_EXTENSIONS:
                return {"category": "wallet", "label": f"portfel {WALLET_EXTENSIONS[e.group(1)]} (rozszerzenie {name})",
                        "owner": owner, "copy": False}
            return None
        for rx, cat, label, owner in _HOME_RX:
            if rx.match(rel):
                return {"category": cat, "label": label, "owner": owner, "copy": False}
    hit = COPY_NAMES.get(os.path.basename(path).lower())
    if hit:
        pi = classify_path(path, home)
        if pi.has("tmp", "shared", "trash") or (pi.has("varfolders") and not pi.has("translocated")):
            owner = BROWSER_BUNDLE if hit[0] in ("passwords", "cookies") else \
                re.compile(r"bitcoin|litecoin|exodus|electrum", re.I) if hit[0] == "wallet" else None
            return {"category": hit[0], "label": hit[1] + " w folderze tymczasowym", "owner": owner, "copy": True}
    return None


def owns(store: dict, *paths: str | None) -> bool:
    owner = store.get("owner")
    if owner is None:
        return False
    return any(p and owner.search(p) for p in paths)


# ---------------------------------------------------------------------------------------------- processes

def _base(name: str | None) -> str:
    return re.sub(r"(?:[\d.]+)$", "", os.path.basename(name or ""))


def is_interpreter(info: dict) -> str | None:
    return interpreter_of(info.get("exe") or "") or interpreter_of(info.get("name") or "")


def ancestry(pid: int, procs: dict[int, dict], depth: int = 6) -> list[dict]:
    out, cur, seen = [], (procs.get(pid) or {}).get("ppid"), {pid}
    while cur and cur > 1 and cur not in seen and len(out) < depth:
        seen.add(cur)
        info = procs.get(cur)
        if not info:
            break
        out.append(info)
        cur = info.get("ppid")
    return out


def _odd(path: str, home: str) -> bool:
    """A place where scripts / programs of an attack sit (temp, shared, hidden, random folder, loose download)."""
    pi = classify_path(path, home)
    if pi.has("tmp", "shared", "trash", "volume", "random_appsupport", "random_library") or \
            (pi.has("varfolders") and not pi.has("translocated")):
        return True
    if pi.has("hidden") and not pi.has("pkgmgr"):
        return True
    return bool(re.match(rf"^{re.escape(home)}/(?:Downloads|Desktop)/[^/]+$", path))


def _dev(path: str, home: str) -> bool:
    from .provenance import DEV_DIRS
    pi = classify_path(path, home)
    return pi.has("pkgmgr") or bool(DEV_DIRS.search(path)) or (path.startswith(home + "/") and
                                                               "/Library/" not in path[len(home):])


# subject → (score factor, confidence, may several categories add up)
SUBJECTS = {
    "untrusted": (1.0, Confidence.HIGH, True), "odd_script": (1.0, Confidence.HIGH, True),
    "via_tool": (1.0, Confidence.HIGH, True), "inline": (0.9, Confidence.HIGH, True),
    "unknown": (0.85, Confidence.HIGH, True),
    "script": (0.75, Confidence.MEDIUM, False), "dev_script": (0.7, Confidence.MEDIUM, False),
    "pkgmgr": (0.6, Confidence.MEDIUM, False), "local_build": (0.6, Confidence.MEDIUM, False),
}


def subject_of(info: dict, trust: str | None, home: str) -> tuple[str | None, str, str | None]:
    """(subject kind, Polish description, culprit file) of a candidate process; kind None = not a candidate."""
    exe = info.get("exe") or ""
    interp = is_interpreter(info)
    if interp:
        ci = analyze_command([str(a) for a in info.get("cmdline") or []])
        if ci.inline_code is not None:
            return "inline", f"polecenie {interp} podane wprost w wierszu poleceń", None
        sp = ci.script
        if sp and sp.startswith("/"):
            if _odd(sp, home):
                return "odd_script", f"skrypt {interp} z nietypowego miejsca ({sp})", sp
            if _dev(sp, home):
                return "dev_script", f"skrypt {interp} z projektu lub pakietu ({sp})", sp
            return "script", f"skrypt {interp} ({sp})", sp
        if sp:
            return "dev_script", f"skrypt {interp} ({sp})", None
        if interp in ("osascript",) or not info.get("cmdline") or len(info.get("cmdline") or []) <= 1:
            return "inline", f"{interp} czytający polecenia ze standardowego wejścia", None
        return "dev_script", f"{interp} ({' '.join(str(a) for a in (info.get('cmdline') or [])[1:3])[:120]})", None
    if not exe:
        return None, "", None
    if is_apple_path(exe) or trust == "apple":
        return ("tool", "", None) if _base(exe) in APPLE_TOOLS else (None, "", None)
    if BACKUP_TOOLS.match(_base(exe)) or BACKUP_TOOLS.match(info.get("name") or ""):
        return None, "", None
    if trust in TRUSTED_TIERS:
        return None, "", None
    desc = {"untrusted": "program niezaufanego pochodzenia", "unknown": "program bez zaufanego podpisu",
            "pkgmgr": "program z menedżera pakietów", "local_build": "program zbudowany na tym Macu"}
    kind = trust if trust in desc else "unknown"
    return kind, desc[kind], exe


def culprit_ancestor(chain: list[dict], origin_of: Callable[[str], dict], home: str) -> tuple[dict, str] | None:
    """The program that drives an Apple tool: osascript, a program of unknown origin, a script from an odd place."""
    for a in chain:
        exe = a.get("exe") or ""
        name = _base(a.get("name") or exe)
        if name == "osascript" or _base(exe) == "osascript":
            return a, "osascript"
        interp = is_interpreter(a)
        if interp:
            ci = analyze_command([str(x) for x in a.get("cmdline") or []])
            if ci.script and ci.script.startswith("/") and _odd(ci.script, home):
                return a, f"skrypt {ci.script}"
            continue
        if exe and not is_apple_path(exe):
            try:
                trust = (origin_of(exe) or {}).get("trust")
            except Exception:  # noqa: BLE001
                trust = None
            if trust in ("untrusted", "unknown"):
                return a, f"program {os.path.basename(exe)} ({'niezaufany' if trust == 'untrusted' else 'bez podpisu'})"
    return None


def _addr(a) -> tuple[str, int] | None:
    if not a:
        return None
    if isinstance(a, (tuple, list)) and len(a) >= 2:
        return str(a[0]), int(a[1] or 0)
    ip, port = getattr(a, "ip", None), getattr(a, "port", None)
    return (str(ip), int(port or 0)) if ip else None


def stdio_sockets(conns: list) -> dict[int, dict]:
    """fd 0/1/2 that are connected inet sockets: {fd: {"peer": (ip, port), "status": …}}."""
    out: dict[int, dict] = {}
    for c in conns or []:
        fd = c.get("fd") if isinstance(c, dict) else getattr(c, "fd", None)
        if fd not in (0, 1, 2):
            continue
        raddr = _addr(c.get("raddr") if isinstance(c, dict) else getattr(c, "raddr", None))
        if not raddr or not raddr[0] or raddr[0] in ("*", "0.0.0.0", "::"):
            continue
        status = c.get("status") if isinstance(c, dict) else getattr(c, "status", None)
        out[fd] = {"peer": raddr, "status": str(status or "")}
    return out


def _loopback(ip: str) -> bool:
    from .netaudit import is_loopback
    return is_loopback(ip)


def remote_shell_signals(info: dict, conns: list, prefix: str = LV) -> list[Signal]:
    """stdin AND stdout/stderr of the process are one established TCP connection to another computer."""
    s = stdio_sockets(conns)
    if 0 not in s or not (1 in s or 2 in s):
        return []
    if s[0]["status"] and s[0]["status"].upper() not in ("ESTABLISHED", "CLOSE_WAIT"):
        return []
    ip, port = s[0]["peer"]
    peer = f"{ip}:{port}"
    name = info.get("name") or os.path.basename(info.get("exe") or "?")
    interp = is_interpreter(info)
    local = _loopback(ip)
    if interp:
        if local:
            return [Signal(f"{prefix}.RemoteShell", 45, Confidence.MEDIUM,
                           f"{name}: wejście i wyjście to połączenie TCP z tym samym Makiem ({peer}) – powłoka "
                           "sterowana przez gniazdo (np. przez tunel)", [peer, info.get("exe") or name])]
        return [Signal(f"{prefix}.RemoteShell", 90, Confidence.HIGH,
                       f"{name}: wejście i wyjście powłoki to połączenie z {peer} – ktoś z zewnątrz może wydawać "
                       "polecenia na tym Macu (odwrotna lub nasłuchująca powłoka)", [peer, info.get("exe") or name])]
    if local or is_apple_path(info.get("exe") or "/"):
        return []                       # e.g. `cat < /dev/tcp/…` port checks with Apple's tools
    return [Signal(f"{prefix}.SocketStdio", 45, Confidence.MEDIUM,
                   f"{name}: program bez zaufanego podpisu z połączeniem sieciowym ({peer}) jako wejściem i wyjściem",
                   [peer, info.get("exe") or name])]


def secret_signals(info: dict, files: list[str], subject: str, subject_pl: str, home: str,
                   prefix: str = LV) -> tuple[list[Signal], list[dict]]:
    """Credential / session stores held open by a candidate that does not own them."""
    if subject not in SUBJECTS:
        return [], []
    factor, conf, additive = SUBJECTS[subject]
    exe = info.get("exe") or ""
    cmd = " ".join(str(a) for a in (info.get("cmdline") or [])[:6])
    seen: dict[str, dict] = {}
    for path in files or []:
        st = secret_store(path, home)
        if st is None or owns(st, exe, cmd):
            continue
        key = st["label"]
        if key not in seen:
            seen[key] = {**st, "path": path}
    if not seen:
        return [], []
    sigs = []
    for st in seen.values():
        cat = st["category"]
        score = int(round(CATEGORY_SCORE[cat] * factor))
        c = conf if cat != "cookies" or subject in ("untrusted", "via_tool") else Confidence(max(conf - 1, 1))
        name = f"{prefix}.SecretAccess.{cat.capitalize()}" if additive else f"{prefix}.SecretAccess"
        short = redact(st["path"].replace(home, "~", 1), 200)
        sigs.append(Signal(name, score, c, f"{subject_pl} trzyma otwarte: {st['label']} – a nie jest programem, "
                                           "do którego te dane należą", [short, exe or "?"]))
    return sigs, list(seen.values())


# ---------------------------------------------------------------------------------------------- script rules

# script-analyzer rules already covered by patterns.CMD_RULES on the same command line (no double counting)
_SAME_AS_CMD = {"PipeToShell": "DownloadExec", "DownloadExecute": "DownloadExec", "DecodePipe": "EncodedExec",
                "DecodeExec": "EncodedExec", "ReverseShellDevTcp": "ReverseShell", "NamedPipeShell": "ReverseShell",
                "ReverseShell": "ReverseShell", "RemoveQuarantine": "QuarantineStrip",
                "DisableGatekeeper": "GatekeeperDisable", "PasswordPrompt": "PasswordPrompt",
                "FakePasswordPrompt": "PasswordPrompt", "DsclAuth": "CredentialCheck"}
_INLINE_COMBO_MIN = 40          # inline shell/python/node code: only whole theft chains (credentials + upload)
_rules_cache: dict[str, tuple] = {}


def _rules(lang: str) -> tuple[list, list]:
    """(rules, combos) of cerber.analyzers' script analyzers for `lang` – imported lazily, empty on any error
    (the static analyzers are maintained separately; a refactor there must not break the live checks)."""
    if lang in _rules_cache:
        return _rules_cache[lang]
    rules: list = []
    combos: list = []
    try:
        from ..analyzers.scripts_common import COMBOS
        from ..analyzers.scripts_shell import RULES as SH, STEALER_COMBOS
        if lang == "osascript":
            from ..analyzers.scripts_macos import APPLE_RULES, OSA_COMBOS
            rules, combos = list(APPLE_RULES) + list(SH), list(STEALER_COMBOS) + list(COMBOS) + list(OSA_COMBOS)
        elif lang == "shell":
            rules, combos = list(SH), list(STEALER_COMBOS) + list(COMBOS)
        elif lang == "python":
            from ..analyzers.scripts_python import RULES as PY
            rules, combos = list(PY) + list(SH), list(STEALER_COMBOS) + list(COMBOS)
        elif lang == "node":
            from ..analyzers.scripts_web import JS_COMBOS, JS_RULES
            rules, combos = list(JS_RULES) + list(SH), list(STEALER_COMBOS) + list(COMBOS) + list(JS_COMBOS)
    except Exception:  # noqa: BLE001
        rules, combos = [], []
    _rules_cache[lang] = (rules, combos)
    return rules, combos


def _combo_hit(hits, combo) -> bool:
    try:
        from ..analyzers.scripts_common import _near
    except Exception:  # noqa: BLE001
        _near = None
    caps = set(hits.caps)
    if not set(combo.all_of) <= caps or (combo.any_of and not set(combo.any_of) & caps):
        return False
    if _near is None:
        return True
    if not _near(hits, tuple(combo.all_of), combo.window):
        return False
    return not combo.any_of or any(_near(hits, tuple(combo.all_of) + (a,), combo.window) for a in combo.any_of)


def script_signals(cmdline: list, prefix: str, home: str, have: set[str] | None = None) -> list[Signal]:
    """The static script heuristics applied to what a running interpreter executes: AppleScript given with -e
    (macOS stealers run their whole script that way), any script file from an odd place (temp, hidden, shared,
    a loose download), and – for inline shell / python / node code – only complete theft chains."""
    ci = analyze_command([str(a) for a in cmdline or []])
    interp = ci.interpreter
    lang = {"osascript": "osascript", "python": "python", "node": "node", "bun": "node", "deno": "node"}.get(
        interp or "", "shell" if interp in ("sh", "bash", "zsh", "dash", "ksh") else None)
    if lang is None:
        return []
    code, where, full = None, "", False
    if ci.inline_code:
        code, where, full = ci.inline_code, "polecenie w wierszu poleceń", lang == "osascript"
    elif ci.script and ci.script.startswith("/") and _odd(ci.script, home):
        try:
            if os.path.getsize(ci.script) <= (256 << 10):
                with open(ci.script, "rb") as fh:
                    raw = fh.read(256 << 10)
                if b"\0" not in raw[:4096] and not raw.startswith((b"Fasd", b"JsOsa")):
                    code, where, full = raw.decode("utf-8", "replace"), f"skrypt {ci.script}", True
        except OSError:
            code = None
    if not code:
        return []
    rules, combos = _rules(lang)
    if not rules:
        return []
    try:
        from ..analyzers.scripts_common import scan_text
        hits = scan_text(code[:400_000], rules)
    except Exception:  # noqa: BLE001
        return []
    have = have or set()
    out: list[Signal] = []
    if full:
        for rule, ev in hits.dets:
            if _SAME_AS_CMD.get(rule.name) in have or rule.score <= 0:
                continue
            conf = Confidence.HIGH if rule.score >= 30 else Confidence.MEDIUM if rule.score >= 15 else Confidence.LOW
            out.append(Signal(f"{prefix}.Script.{rule.name}", int(rule.score), conf, f"{where}: {rule.desc}",
                              [redact(str(ev), 160)]))
    for cb in combos:
        if (not full and cb.score < _INLINE_COMBO_MIN) or _SAME_AS_CMD.get(cb.name) in have:
            continue
        if _combo_hit(hits, cb):
            out.append(Signal(f"{prefix}.Script.{cb.name}", int(cb.score),
                              Confidence.HIGH if cb.score >= 30 else Confidence.MEDIUM, f"{where}: {cb.desc}",
                              [",".join(sorted(hits.caps))]))
    return out


# ---------------------------------------------------------------------------------------------- probing

def probe(pid: int, create_time: float | None = None, files: bool = True) -> tuple[list[str], list[dict]] | str:
    """(open regular files, inet sockets) of a process, or "gone" / "denied"."""
    try:
        import psutil
    except ImportError:
        return "denied"
    try:
        p = psutil.Process(pid)
        if create_time and abs(p.create_time() - float(create_time)) > 1.0:
            return "gone"
        conns = [{"fd": c.fd, "raddr": tuple(c.raddr) if c.raddr else None, "laddr": tuple(c.laddr) if c.laddr else None,
                  "status": c.status, "type": int(c.type)} for c in p.net_connections(kind="inet")]
        paths = [f.path for f in p.open_files()] if files else []
        return paths, conns
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return "gone"
    except psutil.AccessDenied:
        return "denied"
    except Exception:  # noqa: BLE001 - a process vanishing mid-call, odd fd types
        return "gone"


_CERBER_MODULE = re.compile(r"^cerber(?:\.|$)")
_OURS: set[str] | None = None


def _our_pythons() -> set[str]:
    """Executables of Cerber's interpreter (the venv link, its target and the framework launcher psutil reports)."""
    global _OURS
    if _OURS is None:
        from .. import config
        ours = {os.path.realpath(sys.executable), os.path.realpath(os.path.join(config.ROOT, ".venv", "bin", "python"))}
        try:
            import psutil
            ours.add(os.path.realpath(psutil.Process().exe()))
        except Exception:  # noqa: BLE001
            pass
        _OURS = {p for p in ours if p}
    return _OURS


def is_cerber_process(pid: int, procs: dict[int, dict], cache: dict[int, bool] | None = None) -> bool:
    """Cerber's own processes in any lineage (app, background protection, a scan's sandboxes, the CLI): the
    scanner reads every file, browser stores and keychains included."""
    cache = cache if cache is not None else {}
    if pid in cache:
        return cache[pid]
    ours = _our_pythons()
    chain, cur, res = [], pid, False
    for _ in range(14):
        if cur in cache:
            res = cache[cur]
            break
        info = procs.get(cur)
        if not info:
            break
        chain.append(cur)
        exe = info.get("exe") or ""
        if exe.endswith("/Contents/MacOS/Cerber"):
            from .processes import _is_cerber_app
            if _is_cerber_app(exe):
                res = True
                break
        cmd = [str(a) for a in info.get("cmdline") or []]
        if "-m" in cmd and cmd.index("-m") + 1 < len(cmd) and _CERBER_MODULE.match(cmd[cmd.index("-m") + 1]) and \
                exe and os.path.realpath(exe) in ours:
            res = True
            break
        ppid = info.get("ppid")
        if not ppid or ppid <= 1 or ppid == cur:
            break
        cur = ppid
    for c in chain:
        cache[c] = res
    return res


class LiveSweep:
    """Re-checks the candidate processes that are due; every attack is reported once per process instance.

    origin_of(exe) -> provenance dict with "trust" (may run codesign); trust_hint(exe) -> the tier when already
    known, else None; is_ours(pid) -> skip (Cerber itself). A program whose tier is not known yet is probed anyway
    (a probe is far cheaper than codesign) and its provenance is resolved only when the probe shows something, or
    a few per sweep in the background (trusted programs then drop out). New processes are probed on their first
    three sweeps (a reverse shell dup2()s its socket right after start), then every `recheck_s`. A sweep stops
    after `budget_s` seconds of wall time or `max_probes` probes; the rest waits for the next sweep (oldest first)."""

    def __init__(self, home: str, origin_of: Callable[[str], dict], is_ours: Callable[[int], bool] | None = None,
                 recheck_s: float = 60.0, budget_s: float = 0.25, max_probes: int = 80, prefix: str = LV,
                 probe_fn: Callable = probe, trust_hint: Callable[[str], str | None] | None = None,
                 max_resolve: int = 4):
        self.home = home
        self.origin_of = origin_of
        self.trust_hint = trust_hint
        self.max_resolve = max_resolve
        self.is_ours = is_ours or (lambda pid: False)
        self.recheck_s = recheck_s
        self.budget_s = budget_s
        self.max_probes = max_probes
        self.prefix = prefix
        self.probe = probe_fn
        self.state: dict[tuple, dict] = {}       # (pid, create_time) -> {"n", "next", "pending"} or {"skip"}
        self.reported: dict[tuple, int] = {}     # (subject pid, create_time, attack) -> best score reported
        self.stats = {"probed": 0, "denied": 0, "candidates": 0, "hits": 0}

    def _candidate(self, info: dict, resolve: bool = True) -> tuple[str | None, str, str | None]:
        """subject_of() with the trust tier; kind "pending" = a program whose tier is not known yet."""
        exe = info.get("exe") or ""
        trust = None
        if exe and not is_apple_path(exe) and not is_interpreter(info):
            if BACKUP_TOOLS.match(_base(exe)) or BACKUP_TOOLS.match(info.get("name") or ""):
                return None, "", None
            trust = self.trust_hint(exe) if self.trust_hint else None
            if trust is None:
                if not resolve:
                    return "pending", "", exe
                try:
                    trust = (self.origin_of(exe) or {}).get("trust")
                except Exception:  # noqa: BLE001
                    trust = None
        return subject_of(info, trust, self.home)

    def run(self, procs: dict[int, dict], now: float | None = None) -> list[dict]:
        now = now if now is not None else time.time()
        alive = {(pid, (i or {}).get("create_time")) for pid, i in procs.items()}
        for k in [k for k in self.state if k not in alive]:
            del self.state[k]
        for k in [k for k in self.reported if k[:2] not in alive]:
            del self.reported[k]
        due: list[tuple[float, int, tuple]] = []
        n_cand = resolved = 0
        for pid, info in procs.items():
            if not info or pid <= 1:
                continue
            key = (pid, info.get("create_time"))
            st = self.state.get(key)
            if st is None:
                kind, _desc, _f = self._candidate(info, resolve=False)
                if kind is None or self.is_ours(pid):
                    self.state[key] = {"skip": True}
                    continue
                st = self.state[key] = {"n": 0, "next": 0.0, "pending": kind == "pending", "born": now,
                                        "slow": kind == "pending" or interpreter_of(info.get("exe") or "") in SHELLS}
            if st.get("skip"):
                continue
            if st.get("pending"):
                exe = info.get("exe") or ""
                known = self.trust_hint is not None and self.trust_hint(exe) is not None
                if known or resolved < self.max_resolve:
                    resolved += 0 if known else 1       # codesign a few unknown programs per sweep
                    st["pending"] = st["slow"] = False
                    if self._candidate(info)[0] is None:
                        st["skip"] = True
                        continue
            n_cand += 1
            if st["next"] <= now:
                due.append((st["next"], -st["born"], pid, key))
        self.stats["candidates"] = n_cand
        due.sort()                                      # never / quickly re-probed first, newest processes first
        hits: list[dict] = []
        t0 = time.monotonic()
        for i, (_nxt, _born, pid, key) in enumerate(due):
            if i >= self.max_probes or time.monotonic() - t0 > self.budget_s:
                break
            st = self.state[key]
            info = procs[pid]
            st["n"] += 1
            # long-running shells rarely turn into something else, unclassified programs are mostly signed apps
            st["next"] = 0.0 if st["n"] < 3 else now + self.recheck_s * (4 if st["slow"] else 1)
            res = self.probe(pid, info.get("create_time"))
            self.stats["probed"] += 1
            if res == "denied":
                self.stats["denied"] += 1
                st["next"] = now + 10 * self.recheck_s
                continue
            if res == "gone":
                st["skip"] = True
                continue
            files, conns = res
            for hit in self.judge(pid, info, files, conns, procs):
                rk = (hit["pid"], (procs.get(hit["pid"]) or {}).get("create_time"), hit["attack"])
                if hit["score"] < self.reported.get(rk, 0) + 10:
                    continue                            # once per program instance (unless it gets worse)
                self.reported[rk] = hit["score"]
                hits.append(hit)
        self.stats["hits"] += len(hits)
        if len(self.state) > 20000:
            self.state.clear()
        return hits

    def judge(self, pid: int, info: dict, files: list[str], conns: list, procs: dict[int, dict]) -> list[dict]:
        """Live signals of one probed process → hit dicts {pid, exe, name, attack, signals, title, detail, …}."""
        out = []
        name = info.get("name") or os.path.basename(info.get("exe") or "?")
        chain = ancestry(pid, procs)
        parents = " > ".join(_base(c.get("name") or c.get("exe")) for c in reversed(chain[:4]))
        rs = remote_shell_signals(info, conns, self.prefix)
        if rs and not is_interpreter(info) and self._candidate(info)[0] is None:
            rs = []                                     # a trusted program (its tier was not known yet)
        if rs:
            peer = rs[0].evidence[0]
            out.append(self._hit(pid, info, "remote_shell", rs,
                                 f"Zdalna powłoka: {name} (pid {pid}) sterowana przez połączenie z {peer}",
                                 rs[0].description + (f"; uruchomiona przez: {parents}" if parents else ""),
                                 target=None, extra={"peer": peer, "parents": parents}))
        exe, cmd = info.get("exe") or "", " ".join(str(a) for a in (info.get("cmdline") or [])[:6])
        if not any(st is not None and not owns(st, exe, cmd) for st in (secret_store(f, self.home) for f in files)):
            return out                                  # cheap gate before provenance / ancestry lookups
        kind, desc, target = self._candidate(info)
        subject_info, subject_pid = info, pid
        if kind == "tool":
            cul = culprit_ancestor(chain, self.origin_of, self.home)
            if cul is None:
                return out
            subject_info, why = cul
            subject_pid = subject_info.get("pid") or pid
            kind, desc = "via_tool", f"{_base(info.get('exe') or name)} (pid {pid}) uruchomiony przez {why}"
            target = subject_info.get("exe") if not is_interpreter(subject_info) else None
            if is_interpreter(subject_info):
                ci = analyze_command([str(a) for a in subject_info.get("cmdline") or []])
                target = ci.script if ci.script and ci.script.startswith("/") else None
        elif kind in ("inline", "dev_script", "script") and culprit_ancestor(chain, self.origin_of, self.home):
            kind = "via_tool"
        if kind is None:
            return out
        sigs, stores = secret_signals(info, files, kind, desc, self.home, self.prefix)
        if sigs:
            labels = ", ".join(s["label"] for s in stores[:3])
            sname = subject_info.get("name") or os.path.basename(subject_info.get("exe") or "?")
            out.append(self._hit(subject_pid, subject_info, "credential_theft", sigs,
                                 f"Dostęp do haseł lub danych logowania: {sname} – {labels}",
                                 f"{desc}; otwarte: {labels}" + (f"; łańcuch: {parents} > {name}" if parents else ""),
                                 target=target, extra={"stores": [s["category"] for s in stores],
                                                       "parents": parents, "via_pid": pid if subject_pid != pid else None}))
        return out

    @staticmethod
    def _hit(pid: int, info: dict, attack: str, sigs: list[Signal], title: str, detail: str,
             target: str | None, extra: dict) -> dict:
        det = combine(sigs)
        return {"pid": pid, "exe": info.get("exe"), "name": info.get("name"), "cmdline": info.get("cmdline"),
                "attack": attack, "signals": sigs, "score": det.score if det else 0, "title": title,
                "detail": detail, "target": target, **extra}


# ---------------------------------------------------------------------------------------------- event metadata

ATTACK_TAGS: list[tuple[str, re.Pattern]] = [
    ("remote_shell", re.compile(r"\.(?:RemoteShell|SocketStdio|ReverseShell|ReverseShellDevTcp|NamedPipeShell|"
                                r"NetcatListen)$")),
    ("credential_theft", re.compile(r"\.(?:SecretAccess(?:\.\w+)?|Staging|Archive|StealerStaging|StealerArchive|"
                                    r"KeychainDump|CredentialCheck|PasswordPrompt|FakePasswordPrompt|MacStealer|"
                                    r"KeychainExfil|BrowserExfil|CredentialExfil|KeychainAccess|SafeStorageKey)$")),
    ("c2", re.compile(r"\.(?:IocConnection|Beaconing)$")),
    ("download_exec", re.compile(r"\.(?:DownloadExec|EncodedExec|PipeToShell|DecodePipe)$")),
    ("injection", re.compile(r"\.DyldInsert$")),
    ("masquerade", re.compile(r"\.(?:AppleMasquerade|Name\.AppleLike|Name\.Homoglyph)$")),
    ("suspicious_chain", re.compile(r"\.(?:OsascriptChild|DocumentAppSpawn|BrowserSpawn)$")),
    ("deleted_exe", re.compile(r"\.(?:DeletedExec|DeletedWhileRunning)$")),
    ("miner", re.compile(r"\.(?:Miner|MinerBinary)$")),
]
_EV_NAME = re.compile(r"^(\S+) \[\+(-?\d+)\]")


def attack_of(names: list[tuple[str, int]]) -> str | None:
    """Machine-readable kind of attack from (signal name, score) pairs; weak signals (< 10) do not count."""
    strong = [n for n, sc in names if sc >= LOW_SCORE]
    for tag, rx in ATTACK_TAGS:
        if any(rx.search(n) for n in strong):
            return tag
    return None


def names_from_evidence(evidence: list[str]) -> list[tuple[str, int]]:
    """(signal name, score) pairs from a combined Detection's evidence lines "name [+n]: …"."""
    out = []
    for line in evidence or []:
        m = _EV_NAME.match(str(line))
        if m:
            out.append((m.group(1), int(m.group(2))))
    return out


def confidence_of(det) -> str:
    """For the active defense: "high" = malicious (>= 80 with HIGH confidence) – act; "medium" = suspicious
    (>= 35, MEDIUM or better) – warn; "low" = anything else."""
    if det is None or det.score <= 0:
        return "low"
    if severity_of(det) == "malicious":            # not "pua": a miner is unwanted, not an attack to stop
        return "high"
    if det.score >= 35 and det.confidence >= Confidence.MEDIUM:
        return "medium"
    return "low"


def event_meta(signals: list[Signal] | None, names: list[tuple[str, int]] | None = None) -> dict:
    """{"confidence", "attack", "evidence", "signals"} for a netwatch item / env finding (additive fields)."""
    det = combine(signals) if signals else None
    pairs = names if names is not None else [(s.name, s.score) for s in signals or []]
    ev: list[str] = []
    for s in sorted(signals or [], key=lambda s: -s.score):
        line = s.description + (f" [{s.evidence[0]}]" if s.evidence and s.evidence[0] else "")
        ev.append(redact(line, 240))
        if len(ev) >= 5:
            break
    return {"confidence": confidence_of(det), "attack": attack_of(pairs), "evidence": ev,
            "signals": [n for n, _ in sorted(pairs, key=lambda p: -p[1])][:8]}


# ---------------------------------------------------------------------------------------------- env collector

def user_temp_dir() -> str | None:
    """The user's real $TMPDIR (/var/folders/…/T) – Cerber's sandboxes override the variable."""
    try:
        d = os.confstr(65537)                      # _CS_DARWIN_USER_TEMP_DIR
    except (ValueError, OSError, AttributeError):
        d = None
    d = (d or "").rstrip("/")
    return os.path.realpath(d) if d and os.path.isdir(d) else None


def collect_live(ctx) -> None:
    """Environment scan: remote shells and secret stores held open by programs that do not own them."""
    from .processes import _own_lineage, snapshot
    from .provenance import origin, quarantine_events
    ctx.progress("aktywne ataki (zdalne powłoki, dostęp do haseł)")
    procs = snapshot(ctx)
    if not procs:
        return
    home = ctx.homes[0].home if ctx.homes else os.path.expanduser("~")
    known = {e.get("exe"): e.get("origin") for e in ctx.inventory.get("processes") or [] if e.get("origin")}
    qev: dict | None = None

    def origin_of(exe: str) -> dict:
        nonlocal qev
        o = known.get(exe)
        if o is None:
            if qev is None:
                qev = quarantine_events(home)
            o = known[exe] = origin(exe, ctx.sign(exe) if os.path.exists(exe) else None, home, qevents=qev)
        return o

    skip = _own_lineage()
    cache: dict[int, bool] = {}
    sweep = LiveSweep(home, origin_of, lambda pid: pid in skip or is_cerber_process(pid, procs, cache),
                      recheck_s=1e9, budget_s=float(ctx.options.get("live_budget", 20)), max_probes=5000,
                      trust_hint=lambda exe: (known.get(exe) or {}).get("trust"), max_resolve=0)
    t0 = time.monotonic()
    hits = sweep.run(procs)
    for h in hits:
        meta = event_meta(h["signals"])
        exe = h.get("exe")
        details = {"pid": h["pid"], "exe": exe, "attack": h["attack"], "confidence": meta["confidence"],
                   "evidence": meta["evidence"], "target": h.get("target"), "parents": h.get("parents"),
                   "cmdline": redact(" ".join(str(a) for a in h.get("cmdline") or []), 300)}
        for k in ("peer", "stores", "via_pid"):
            if h.get(k) is not None:
                details[k] = h[k]
        ctx.add_finding("process", h["title"], f"pid {h['pid']}", h["signals"], details)
        if h.get("target") and os.path.exists(h["target"]):
            ctx.add_target(h["target"], f"program/skrypt aktywnego ataku (pid {h['pid']})", 2)
    ctx.inventory["live_checks"] = {**sweep.stats, "hits": len(hits), "seconds": round(time.monotonic() - t0, 2)}

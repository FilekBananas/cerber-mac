"""Known-malware artefacts of the most dangerous macOS families (2021-2026).

Exact file/folder paths, launchd labels and plist names, bundle identifiers and process names that
primary technical write-ups (SentinelOne, Jamf, Elastic, Microsoft, Huntress, Moonlock, Kandji/Iru,
Unit 42, ESET, ThreatFabric, Objective-See, Securelist, Darktrace, Bitdefender, eSentire) tie to one
family: infostealers (AMOS and its backdoor, Banshee, Poseidon/Odyssey, Cuckoo, Cthulhu, MacSync),
DPRK/APT backdoors (KandyKorn, RustBucket, Hidden Risk, NimDoor, BeaverTail/InvisibleFerret,
FlexibleFerret, SpectralBlur, CloudMensis, LightSpy, JokerSpy, ZuRu, ChillyHell, PasivRobber, 3CX
SmoothOperator, XCSSET), ransomware (Turtle, LockBit) and adware (Adload, Activator).

Runs at the "Dokładny" and "Mega" levels (envscan.COLLECTORS entry "artifacts"). Read-only and fast:
lstat() of fixed paths, listdir() of a few small folders (never recursive), 4-byte magic reads to tell
a Mach-O from an unrelated file of the same name, launchd plist / Info.plist parsing of top-level items.

Scoring
    strong   an artefact only that family creates (e.g. /Library/Caches/com.apple.safari.ck,
             ~/Library/CoreKit/CoreKitAgent): HIGH, score 80-95 -> "złośliwy" on its own
    medium   unusual but not unique (a hidden Mach-O ~/.helper): 30-70, needs a second artefact
    weak     generic names (~/.pass, /tmp/out.zip, ~/.zshrc_aliases): counted only together with a
             non-weak artefact of the same family, or when 3+ weak artefacts of one family coexist;
             always handed to the file scanner so the content decides
All artefacts of one family (per home folder / system) are merged into one finding.

Test hooks: options["artifacts_root"] is prepended to every absolute system path, home folders come
from options["homes_override"]; ctx._procs (the processes.snapshot cache) may be pre-filled.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass

from ..core import Confidence
from .model import Signal
from .util import MACHO_MAGICS, EnvContext, load_plist, read_bytes, safe_listdir

P = "Heur:Env.Artifact"

# family key -> (display name used in Polish titles, pua)
FAMILIES: dict[str, tuple[str, bool]] = {
    "AMOS": ("Atomic Stealer (AMOS)", False),
    "Banshee": ("Banshee Stealer", False),
    "PoseidonOdyssey": ("Poseidon/Odyssey Stealer", False),
    "Cthulhu": ("Cthulhu Stealer", False),
    "Cuckoo": ("Cuckoo Stealer", False),
    "MacSync": ("MacSync (Mac.c) Stealer", False),
    "ClickFixLoader": ("backdoor z kampanii ClickFix", False),
    "KandyKorn": ("KandyKorn / SUGARLOADER (Lazarus)", False),
    "RustBucket": ("RustBucket (BlueNoroff)", False),
    "HiddenRisk": ("Hidden Risk (BlueNoroff)", False),
    "TodoSwift": ("TodoSwift (BlueNoroff)", False),
    "NimDoor": ("NimDoor / RootTroy (BlueNoroff)", False),
    "FlexibleFerret": ("FlexibleFerret (Contagious Interview)", False),
    "BeaverTail": ("BeaverTail / InvisibleFerret (Contagious Interview)", False),
    "ChillyHell": ("ChillyHell (backdoor)", False),
    "PasivRobber": ("PasivRobber (spyware)", False),
    "ZuRu": ("ZuRu (trojanizowany Termius/iTerm2)", False),
    "CloudMensis": ("CloudMensis / BadRAT (spyware)", False),
    "SmoothOperator": ("SmoothOperator (trojanizowany 3CX)", False),
    "JokerSpy": ("JokerSpy (backdoor)", False),
    "XCSSET": ("XCSSET", False),
    "LightSpy": ("LightSpy (spyware)", False),
    "SpectralBlur": ("SpectralBlur (backdoor)", False),
    "EvilQuest": ("EvilQuest / ThiefQuest", False),
    "DazzleSpy": ("DazzleSpy (spyware)", False),
    "Turtle": ("ransomware Turtle", False),
    "LockBit": ("ransomware LockBit", False),
    "Activator": ("Activator (backdoor w crackowanych aplikacjach)", False),
    "Adload": ("Adload (adware)", True),
}


@dataclass(frozen=True)
class Art:
    family: str
    path: str               # absolute system path, or "~/..." = inside every scanned home folder
    score: int
    what: str               # Polish: what this artefact is
    kind: str = "any"       # any | file | dir | macho
    weak: bool = False


@dataclass(frozen=True)
class DirPat:
    family: str
    directory: str          # absolute or "~/..."; listed once, never recursively
    regex: str
    score: int
    what: str
    kind: str = "any"
    child: str | None = None    # a file inside the matched folder that confirms the hit
    child_score: int = 0
    weak: bool = False


SHARED = "/Users/Shared"
LA, LD = "Library/LaunchAgents", "/Library/LaunchDaemons"
UUID_RX = r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"

ARTIFACTS: tuple[Art, ...] = (
    # --- Atomic Stealer / AMOS (+ SHAMOS) backdoor; Moonlock, Huntress, Iru, Unit 42
    Art("AMOS", f"{LD}/com.finder.helper.plist", 85, "LaunchDaemon backdoora AMOS (com.finder.helper uruchamia ~/.agent)", "file"),
    Art("AMOS", "~/.helper", 50, "ukryty program backdoora AMOS (~/.helper)", "macho"),
    Art("AMOS", "~/.agent", 30, "skrypt-strażnik backdoora AMOS (~/.agent uruchamia ~/.helper)", "file"),
    Art("AMOS", "~/.mainhelper", 60, "wariant backdoora AMOS (~/.mainhelper)", "file"),
    Art("AMOS", "~/Library/Application Support/.com.apple.accountsd", 85,
        "ukryty folder AMOS podszywający się pod usługę Apple (AccountsHelper)", "dir"),
    Art("AMOS", "~/Library/Application Support/.com.apple.metadata.mds", 85,
        "ukryty folder AMOS podszywający się pod Spotlight (mdworker_shared)", "dir"),
    Art("AMOS", "~/.pass", 15, "plik z przechwyconym hasłem (AMOS)", "file", weak=True),
    Art("AMOS", "~/.username", 15, "znacznik ofiary AMOS (~/.username)", "file", weak=True),
    Art("AMOS", "~/.id", 10, "identyfikator ofiary AMOS (~/.id)", "file", weak=True),
    Art("AMOS", "~/.logged", 10, "znacznik kampanii AMOS (~/.logged)", "file", weak=True),
    Art("AMOS", "/tmp/out.zip", 15, "archiwum łupu stealera (/tmp/out.zip)", "file", weak=True),
    Art("AMOS", "/tmp/starter", 20, "program startowy AMOS w /tmp", "macho", weak=True),
    Art("AMOS", "/tmp/helper", 20, "instalator AMOS w /tmp", "macho", weak=True),
    # --- Banshee (Elastic)
    Art("Banshee", "~/password-entered", 70, "plik z hasłem wyłudzonym przez Banshee Stealer", "file"),
    Art("Banshee", "/tmp/tempAppleScript", 50, "tymczasowy AppleScript Banshee Stealer", "file"),
    # --- Poseidon / Odyssey (CYFIRMA)
    Art("PoseidonOdyssey", "/tmp/lovemrtrump", 85, "folder przygotowawczy Poseidon/Odyssey Stealer (/tmp/lovemrtrump)"),
    # --- Cthulhu (Darktrace, Cado)
    Art("Cthulhu", f"{SHARED}/NW/Userinfo.txt", 85, "dane ofiary zebrane przez Cthulhu Stealer", "file"),
    Art("Cthulhu", f"{SHARED}/NW/Keychain.txt", 85, "zrzut pęku kluczy zebrany przez Cthulhu Stealer", "file"),
    Art("Cthulhu", f"{SHARED}/NW", 20, "folder roboczy Cthulhu Stealer (/Users/Shared/NW)", "dir", weak=True),
    # --- MacSync / Mac.c (Securelist, Huntress)
    Art("MacSync", "~/Library/Logs/.sysnotif-agent.log", 85, "ukryty dziennik backdoora MacSync", "file"),
    Art("MacSync", f"~/{LA}/com.apple.finder.agent.plist", 80, "LaunchAgent MacSync podszywający się pod Findera", "file"),
    Art("MacSync", "/tmp/osalogging.zip", 85, "archiwum łupu MacSync (/tmp/osalogging.zip)", "file"),
    Art("MacSync", "/tmp/.kgrab.sh", 85, "skrypt kradzieży pęku kluczy MacSync", "file"),
    Art("MacSync", "/tmp/.kpwd", 80, "przechwycone hasło (MacSync)", "file"),
    Art("MacSync", "~/.local/.mpwd", 85, "przechwycone hasło (MacSync)", "file"),
    # --- ClickFix backdoor loader (Microsoft, Huntress)
    Art("ClickFixLoader", "~/Library/Application Support/Google/GoogleUpdate.app", 60,
        "fałszywa aplikacja GoogleUpdate.app (backdoor z kampanii ClickFix)", "dir"),
    # --- KandyKorn / SUGARLOADER / HLOADER (Elastic)
    Art("KandyKorn", "/Library/Caches/com.apple.safari.ck", 90, "plik konfiguracyjny SUGARLOADER/KandyKorn", "file"),
    Art("KandyKorn", f"{SHARED}/.sld", 85, "SUGARLOADER (/Users/Shared/.sld)"),
    Art("KandyKorn", f"{SHARED}/.log", 70, "kopia SUGARLOADER ukryta jako /Users/Shared/.log", "macho"),
    Art("KandyKorn", f"{SHARED}/FinderTools", 70, "dropper FinderTools (KandyKorn, etap Python)"),
    Art("KandyKorn", "/Applications/Discord.app/Contents/MacOS/.lock", 90,
        "HLOADER: prawdziwy plik Discorda przemianowany na .lock, a w jego miejscu loader", "file"),
    Art("KandyKorn", "/Applications/Discord.app/Contents/MacOS/MacOS.tmp", 70, "tymczasowa kopia HLOADER w Discord.app", "file"),
    # --- RustBucket (Elastic, Jamf)
    Art("RustBucket", "~/Library/Metadata/System Update", 90, "RustBucket: kopia implantu „System Update”"),
    Art("RustBucket", f"~/{LA}/com.apple.systemupdate.plist", 85, "LaunchAgent RustBucket podszywający się pod Apple", "file"),
    Art("RustBucket", f"{SHARED}/.pd", 70, "etap 2 RustBucket (/Users/Shared/.pd)", "macho"),
    # --- Hidden Risk (SentinelOne)
    Art("HiddenRisk", "/tmp/.zsh_init_success", 85, "znacznik persystencji Hidden Risk przez ~/.zshenv", "file"),
    Art("HiddenRisk", "/tmp/growth", 60, "backdoor Hidden Risk (/tmp/growth)", "macho"),
    # --- TodoSwift (Kandji/Iru)
    Art("TodoSwift", "/tmp/NetMsgStatus", 85, "etap 2 TodoSwift (/tmp/NetMsgStatus)", "file"),
    Art("TodoSwift", "/tmp/GoogleMsgStatus.pdf", 40, "wabik PDF TodoSwift", "file", weak=True),
    # --- NimDoor + BlueNoroff 2025 toolkit (SentinelOne, Huntress)
    Art("NimDoor", "~/Library/Application Support/Google LLC/GoogIe LLC", 95, "loader NimDoor „GoogIe LLC” (duże i zamiast l)"),
    Art("NimDoor", "~/Library/CoreKit/CoreKitAgent", 90, "trojan NimDoor CoreKitAgent"),
    Art("NimDoor", "~/Library/DnsService", 70, "folder NimDoor ze skryptami kradzieży (DnsService)", "dir"),
    Art("NimDoor", f"~/{LA}/com.google.update.plist", 40, "LaunchAgent NimDoor podszywający się pod Google", "file"),
    Art("NimDoor", "~/.ses", 20, "beacon AppleScript NimDoor (~/.ses)", "file", weak=True),
    Art("NimDoor", "/private/tmp/.config", 10, "plik konfiguracyjny NimDoor w /tmp", "file", weak=True),
    Art("NimDoor", "/private/tmp/cfg", 10, "plik konfiguracyjny NimDoor w /tmp", "file", weak=True),
    Art("NimDoor", f"{LD}/com.telegram2.update.agent.plist", 90, "LaunchDaemon BlueNoroff „Telegram 2”", "file"),
    Art("NimDoor", "/Library/Application Support/Frameworks/Telegram 2", 90, "implant BlueNoroff „Telegram 2”"),
    Art("NimDoor", "/Library/WebServer/bin/remoted", 90, "backdoor RootTroy (BlueNoroff) podszywający się pod remoted"),
    Art("NimDoor", "/private/tmp/google_cache.db", 60, "zrzuty ekranu XScreen (BlueNoroff)", "file"),
    Art("NimDoor", "/Library/AirPlay/.cache", 80, "artefakt CryptoBot (BlueNoroff) w /Library/AirPlay"),
    Art("NimDoor", "/Library/AirPlay/.pid", 80, "artefakt CryptoBot (BlueNoroff) w /Library/AirPlay"),
    Art("NimDoor", "/Library/Google/Cache", 20, "konfiguracja RootTroy (/Library/Google/Cache)", "dir", weak=True),
    # --- FlexibleFerret (Jamf)
    Art("FlexibleFerret", f"~/{LA}/com.driver9990as7tpatch.plist", 95, "LaunchAgent FlexibleFerret", "file"),
    Art("FlexibleFerret", "/var/tmp/macpatch.sh", 85, "loader FlexibleFerret (/var/tmp/macpatch.sh)", "file"),
    Art("FlexibleFerret", "/var/tmp/CDrivers", 85, "backdoor FlexibleFerret w Go (/var/tmp/CDrivers)"),
    Art("FlexibleFerret", "/var/tmp/CDrivers.zip", 85, "archiwum backdoora FlexibleFerret", "file"),
    Art("FlexibleFerret", "/var/tmp/drivfixer.sh", 85, "skrypt FlexibleFerret (drivfixer.sh)", "file"),
    # --- BeaverTail / InvisibleFerret (Unit 42, eSentire)
    Art("BeaverTail", "~/.n2", 60, "folder ładunków InvisibleFerret (~/.n2)", "dir"),
    Art("BeaverTail", "~/.n2/pay", 85, "moduł backdoora InvisibleFerret (~/.n2/pay)", "file"),
    Art("BeaverTail", "~/.n2/bow", 85, "moduł kradzieży z przeglądarek InvisibleFerret (~/.n2/bow)", "file"),
    Art("BeaverTail", "~/.n2/mlip", 80, "moduł schowka InvisibleFerret (~/.n2/mlip)", "file"),
    Art("BeaverTail", "~/.npl", 75, "loader InvisibleFerret w Pythonie (~/.npl)", "file"),
    Art("BeaverTail", "~/.sysinfo", 20, "loader InvisibleFerret (~/.sysinfo)", "file", weak=True),
    Art("BeaverTail", "~/.pyp", 40, "przenośny Python pobrany przez BeaverTail (~/.pyp)", "dir"),
    Art("BeaverTail", "~/p.zi", 60, "archiwum Pythona pobrane przez BeaverTail (~/p.zi)", "file"),
    # --- ChillyHell (Jamf)
    Art("ChillyHell", "~/Library/com.apple.qtop/qtop", 95, "backdoor ChillyHell (qtop)"),
    Art("ChillyHell", f"~/{LA}/com.apple.qtop.plist", 95, "LaunchAgent ChillyHell", "file"),
    Art("ChillyHell", f"{LD}/com.apple.qtop.plist", 95, "LaunchDaemon ChillyHell", "file"),
    Art("ChillyHell", "/usr/local/bin/qtop", 50, "kopia ChillyHell w /usr/local/bin", "macho"),
    Art("ChillyHell", "/tmp/kworker", 50, "ładunek ChillyHell (/tmp/kworker)", "macho"),
    # --- PasivRobber (Kandji/Iru)
    Art("PasivRobber", "/Library/protect/wsus", 95, "instalacja spyware PasivRobber (/Library/protect/wsus)", "dir"),
    Art("PasivRobber", f"{LD}/com.apple.goed.plist", 95, "LaunchDaemon PasivRobber (com.apple.goed)", "file"),
    Art("PasivRobber", "/Library/Caches/com.apple.goed", 85, "pamięć podręczna PasivRobber", "dir"),
    # --- ZuRu (SentinelOne 2025, Objective-See 2021)
    Art("ZuRu", "/tmp/.fseventsd", 85, "backdoor ZuRu (Khepri) ukryty jako /tmp/.fseventsd"),
    Art("ZuRu", f"{LD}/com.apple.xssooxxagent.plist", 95, "LaunchDaemon ZuRu", "file"),
    Art("ZuRu", f"{SHARED}/com.apple.xssooxxagent", 95, "backdoor ZuRu w /Users/Shared"),
    Art("ZuRu", "/tmp/apple-local-ipc.sock.lock", 40, "plik blokady backdoora ZuRu", "file"),
    Art("ZuRu", "/private/tmp/Termius", 20, "kopia trojanizowanego Termius w /tmp", weak=True),
    Art("ZuRu", "/tmp/GoogleUpdate", 60, "beacon ZuRu 2021 (/tmp/GoogleUpdate)", "macho"),
    Art("ZuRu", "/Applications/Termius.app/Contents/MacOS/.localized", 90, "loader ZuRu dopisany do Termius.app", "file"),
    Art("ZuRu", "/Applications/Termius.app/Contents/Frameworks/Termius Helper.app/Contents/MacOS/.Termius Helper1", 95,
        "oryginalny helper Termius przemianowany przez ZuRu", "file"),
    Art("ZuRu", "/Applications/iTerm.app/Contents/Frameworks/libcrypto.2.dylib", 80,
        "złośliwa biblioteka ZuRu wstrzyknięta do iTerm.app", "file"),
    # --- CloudMensis / BadRAT (ESET)
    Art("CloudMensis", "/Library/WebServer/share/httpd/manual/WindowServer", 95, "downloader CloudMensis udający WindowServer"),
    Art("CloudMensis", f"{LD}/.com.apple.WindowServer.plist", 95, "ukryty LaunchDaemon CloudMensis", "file"),
    Art("CloudMensis", "~/Library/Containers/com.apple.FaceTime/Data/Library/windowserver", 95, "agent szpiegujący CloudMensis"),
    Art("CloudMensis", "~/Library/Containers/com.apple.Notes/Data/Library/.CFUserTextDecoding", 90, "plik CloudMensis w kontenerze Notatek"),
    Art("CloudMensis", "~/Library/Containers/com.apple.languageassetd/loginwindow", 90, "plik CloudMensis udający loginwindow"),
    Art("CloudMensis", "~/Library/Application Support/com.apple.spotlight/Resources_V3/.CrashRep", 90, "plik CloudMensis w folderze Spotlight"),
    Art("CloudMensis", "~/Library/Preferences/com.apple.iTunesInfo29.plist", 80, "konfiguracja CloudMensis udająca iTunes", "file"),
    Art("CloudMensis", "~/Library/Preferences/com.apple.iTunesInfo28.plist", 80, "konfiguracja CloudMensis udająca iTunes", "file"),
    Art("CloudMensis", "~/Library/Preferences/com.apple.iTunesInfo.plist", 30, "konfiguracja CloudMensis udająca iTunes", "file", weak=True),
    # --- 3CX SmoothOperator (SentinelOne, Objective-See)
    Art("SmoothOperator", "~/Library/Application Support/3CX Desktop App/UpdateAgent", 90, "UpdateAgent – ładunek SmoothOperator (3CX)"),
    Art("SmoothOperator", "~/Library/Application Support/3CX Desktop App/.main_storage", 85, "konfiguracja SmoothOperator (3CX)", "file"),
    Art("SmoothOperator", "~/Library/Application Support/3CX Desktop App/.session-lock", 20, "plik blokady SmoothOperator", "file", weak=True),
    # --- JokerSpy (Elastic, SentinelOne)
    Art("JokerSpy", f"{SHARED}/xcc", 85, "narzędzie JokerSpy xcc (sprawdza uprawnienia TCC)", "file"),
    Art("JokerSpy", f"{SHARED}/sh.py", 70, "backdoor JokerSpy w Pythonie (/Users/Shared/sh.py)", "file"),
    Art("JokerSpy", "~/Public/Safari/sar.dat", 90, "konfiguracja backdoora JokerSpy", "file"),
    Art("JokerSpy", f"{SHARED}/keybag", 40, "biblioteki kryptograficzne JokerSpy", "dir"),
    Art("JokerSpy", f"{SHARED}/tcc.db", 50, "kopia bazy uprawnień TCC zrobiona przez JokerSpy", "file"),
    Art("JokerSpy", f"{SHARED}/sb", 20, "wynik SwiftBelt (JokerSpy)", "file", weak=True),
    Art("JokerSpy", f"{SHARED}/sb.log", 20, "wynik SwiftBelt (JokerSpy)", "file", weak=True),
    # --- XCSSET (Microsoft 2025)
    Art("XCSSET", "/Applications/Reminders.app", 50, "fałszywa aplikacja Przypomnienia (XCSSET; prawdziwa jest w /System/Applications)", "dir"),
    Art("XCSSET", "~/.zshrc_aliases", 15, "plik persystencji XCSSET dołączany do ~/.zshrc", "file", weak=True),
    Art("XCSSET", "/tmp/.n", 10, "ładunek JavaScript XCSSET", "file", weak=True),
    Art("XCSSET", "/tmp/.f", 10, "moduł XCSSET", "file", weak=True),
    Art("XCSSET", "/tmp/.i", 10, "skrypt uruchamiający XCSSET", "file", weak=True),
    Art("XCSSET", "/tmp/.e", 10, "plik błędów XCSSET", "file", weak=True),
    # --- LightSpy (ThreatFabric)
    Art("LightSpy", f"{SHARED}/update.app", 80, "dropper LightSpy (/Users/Shared/update.app)", "dir"),
    Art("LightSpy", f"{SHARED}/irc.pid", 30, "plik PID LightSpy", "file", weak=True),
    # --- SpectralBlur (Objective-See)
    Art("SpectralBlur", f"{SHARED}/.macshare", 85, "backdoor SpectralBlur (/Users/Shared/.macshare)"),
    Art("SpectralBlur", f"{SHARED}/mac.jpg", 85, "backdoor SpectralBlur udający obrazek mac.jpg", "macho"),
    # --- EvilQuest, DazzleSpy (Objective-See, ESET)
    Art("EvilQuest", "~/Library/AppQuest/com.apple.questd", 90, "EvilQuest/ThiefQuest (questd)"),
    Art("EvilQuest", "/Library/AppQuest/com.apple.questd", 90, "EvilQuest/ThiefQuest (questd)"),
    Art("DazzleSpy", "~/.local/softwareupdate", 80, "DazzleSpy udający aktualizację systemu", "macho"),
    # --- LockBit for macOS (Objective-See)
    Art("LockBit", "/tmp/locker.log", 20, "dziennik szyfrowania LockBit dla macOS", "file", weak=True),
)

DIR_PATTERNS: tuple[DirPat, ...] = (
    DirPat("Cuckoo", "~", rf"^\.local-{UUID_RX}$", 70, "ukryty folder Cuckoo Stealer (~/.local-<UUID>)", "dir",
           child="pw.dat", child_score=25),
    DirPat("MacSync", "/tmp", r"^\.sys-\d{16}$", 80, "dropper MacSync (/tmp/.sys-<16 cyfr>)"),
    DirPat("XCSSET", "~/Library/Caches/com.apple.finder", r"\.app$", 85,
           "fałszywa aplikacja (np. Launchpad) ukryta przez XCSSET w pamięci podręcznej Findera", "dir"),
    DirPat("Activator", "/Library/LaunchAgents", rf"^launched\.{UUID_RX}\.plist$", 80,
           "LaunchAgent backdoora Activator (launched.<UUID>.plist)", "file"),
    DirPat("Activator", f"~/{LA}", rf"^launched\.{UUID_RX}\.plist$", 80,
           "LaunchAgent backdoora Activator (launched.<UUID>.plist)", "file"),
    DirPat("Adload", "~/Library/Application Support", rf"^\.{UUID_RX}$", 50,
           "ukryty folder o nazwie UUID w Application Support (wzorzec Adload)", "dir"),
    DirPat("Adload", "/Library/Application Support", rf"^\.{UUID_RX}$", 50,
           "ukryty folder o nazwie UUID w Application Support (wzorzec Adload)", "dir"),
    DirPat("Turtle", "~/Desktop", r"\.TURTLERANSv0$", 90, "plik zaszyfrowany przez ransomware Turtle", "file"),
    DirPat("Turtle", "~/Documents", r"\.TURTLERANSv0$", 90, "plik zaszyfrowany przez ransomware Turtle", "file"),
    DirPat("LockBit", "~/Desktop", r"^!!!-Restore-My-Files-!!!", 90, "notatka okupu LockBit", "file"),
    DirPat("LockBit", "~/Documents", r"^!!!-Restore-My-Files-!!!", 90, "notatka okupu LockBit", "file"),
    DirPat("LockBit", "~", r"^!!!-Restore-My-Files-!!!", 90, "notatka okupu LockBit", "file"),
)

# launchd Label -> (family, score, weak). Label names alone, because plist file names get changed.
LABELS: dict[str, tuple[str, int, bool]] = {
    "com.finder.helper": ("AMOS", 85, False),
    "com.user.loginscript": ("Cuckoo", 20, True),     # also a common tutorial label -> weak
    "com.apple.finder.agent": ("MacSync", 80, False),
    "com.apple.systemupdate": ("RustBucket", 80, False),
    "com.google.update": ("NimDoor", 30, False),
    "com.telegram2.update.agent": ("NimDoor", 90, False),
    "com.driver9990as7tpatch": ("FlexibleFerret", 95, False),
    "com.apple.qtop": ("ChillyHell", 95, False),
    "com.apple.goed": ("PasivRobber", 95, False),
    "com.apple.xssooxxagent": ("ZuRu", 95, False),
}
LAUNCHD_DIRS = ("~/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons")

# CFBundleIdentifier of a top-level app -> (family, score)
BUNDLE_IDS: dict[str, tuple[str, int]] = {
    "upd.upd": ("Cuckoo", 75),
    "Education.LessonOne": ("HiddenRisk", 85),
    "MasaMatsu.TodoTasks": ("TodoSwift", 85),
}
APP_DIRS = ("/Applications", "~/Applications", SHARED, "~/Downloads")

# running process name -> (family, score)
PROCESS_NAMES: dict[str, tuple[str, int]] = {
    "GoogIe LLC": ("NimDoor", 95),
    "CoreKitAgent": ("NimDoor", 85),
    "trojan1_arm64": ("NimDoor", 95),
    "InjectWithDyldArm64": ("NimDoor", 90),
    "com.apple.xssooxxagent": ("ZuRu", 95),
    ".fseventsd": ("ZuRu", 80),
}


def _conf(score: int) -> Confidence:
    return Confidence.HIGH if score >= 60 else Confidence.MEDIUM if score >= 30 else Confidence.LOW


def _tag(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "", os.path.basename(path.rstrip("/")))[:28] or "item"


def _plural(n: int) -> str:
    if n == 1:
        return "znany artefakt"
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return "znane artefakty"
    return "znanych artefaktów"


class _Resolver:
    def __init__(self, ctx: EnvContext):
        self.root = str(ctx.options.get("artifacts_root") or "").rstrip("/")
        self.homes = list(ctx.homes)

    def expand(self, path: str) -> list[tuple[str, str]]:
        """[(scope, real path)]: scope is the home folder for "~/" paths, "system" otherwise."""
        if path == "~" or path.startswith("~/"):
            rest = path[2:]
            return [(h.home, os.path.join(h.home, rest) if rest else h.home) for h in self.homes]
        return [("system", self.root + path)]

    def display(self, real: str) -> str:
        return real[len(self.root):] if self.root and real.startswith(self.root + "/") else real


def _matches_kind(path: str, kind: str) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if kind == "any":
        return True
    if kind == "dir":
        return stat.S_ISDIR(st.st_mode)
    if kind == "file":
        return stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)
    if kind == "macho":
        if not stat.S_ISREG(st.st_mode):
            return False
        head = read_bytes(path, 4) or b""
        return head[:4] in MACHO_MAGICS
    return False


class _Hits:
    """family -> scope -> list of (Signal, weak, path)."""

    def __init__(self) -> None:
        self.data: dict[tuple[str, str], list[tuple[Signal, bool, str]]] = {}

    def add(self, family: str, scope: str, path: str, score: int, what: str, evidence: list[str],
            weak: bool = False, suffix: str = "") -> None:
        pua = FAMILIES.get(family, ("", False))[1]
        sig = Signal(f"{P}.{family}.{_tag(path)}{suffix}", score, _conf(score), what, evidence, pua=pua)
        self.data.setdefault((family, scope), []).append((sig, weak, path))


def _check_paths(ctx: EnvContext, rv: _Resolver, hits: _Hits, known: dict[str, tuple[str, str]]) -> None:
    for a in ARTIFACTS:
        for scope, real in rv.expand(a.path):
            known[os.path.normpath(real)] = (a.family, scope)
            if _matches_kind(real, a.kind):
                hits.add(a.family, scope, real, a.score, a.what, [rv.display(real)], a.weak)


def _check_dir_patterns(ctx: EnvContext, rv: _Resolver, hits: _Hits) -> None:
    for dp in DIR_PATTERNS:
        rx = re.compile(dp.regex, 0 if dp.family == "Turtle" else re.I)
        for scope, real_dir in rv.expand(dp.directory):
            names, _err = safe_listdir(real_dir)
            for n in names[:5000]:
                if not rx.search(n):
                    continue
                p = os.path.join(real_dir, n)
                if not _matches_kind(p, dp.kind):
                    continue
                hits.add(dp.family, scope, p, dp.score, dp.what, [rv.display(p)], dp.weak)
                if dp.child and os.path.lexists(os.path.join(p, dp.child)):
                    hits.add(dp.family, scope, os.path.join(p, dp.child), dp.child_score,
                             f"{dp.what}: zawiera {dp.child}", [rv.display(os.path.join(p, dp.child))], dp.weak,
                             suffix=".child")


def _program_paths(d: dict) -> list[str]:
    out = []
    if isinstance(d.get("Program"), str):
        out.append(d["Program"])
    pa = d.get("ProgramArguments")
    if isinstance(pa, list):
        out += [a for a in pa if isinstance(a, str)]
    return out


def _check_launchd(ctx: EnvContext, rv: _Resolver, hits: _Hits, known: dict[str, tuple[str, str]]) -> None:
    for d in LAUNCHD_DIRS:
        for scope, real_dir in rv.expand(d):
            names, _err = safe_listdir(real_dir)
            for n in names[:2000]:
                if not n.endswith(".plist"):
                    continue
                p = os.path.join(real_dir, n)
                data, err = load_plist(p, 1 << 20)
                if err or not isinstance(data, dict):
                    continue
                label = data.get("Label")
                if isinstance(label, str) and label in LABELS:
                    fam, score, weak = LABELS[label]
                    hits.add(fam, scope, p, score,
                             f"zadanie launchd z etykietą znanej persystencji ({label})", [rv.display(p), f"Label={label}"],
                             weak, suffix=".label")
                for prog in _program_paths(data):
                    if prog.startswith("~/"):
                        cands = [os.path.join(h.home, prog[2:]) for h in rv.homes]
                    elif prog.startswith("/"):
                        cands = [rv.root + prog]
                    else:
                        continue
                    for real_prog in cands:
                        hit = known.get(os.path.normpath(real_prog))
                        if hit:
                            fam, art_scope = hit
                            hits.add(fam, art_scope, p, 40, "zadanie launchd uruchamia znany artefakt",
                                     [rv.display(p), f"program={prog}"], suffix=".launchd")


def _check_bundles(ctx: EnvContext, rv: _Resolver, hits: _Hits) -> None:
    for d in APP_DIRS:
        for scope, real_dir in rv.expand(d):
            names, _err = safe_listdir(real_dir)
            for n in names[:3000]:
                if not n.endswith(".app"):
                    continue
                app = os.path.join(real_dir, n)
                data, err = load_plist(os.path.join(app, "Contents", "Info.plist"), 1 << 20)
                if err or not isinstance(data, dict):
                    continue
                bid = data.get("CFBundleIdentifier")
                if isinstance(bid, str) and bid in BUNDLE_IDS:
                    fam, score = BUNDLE_IDS[bid]
                    hits.add(fam, scope, app, score, f"aplikacja o identyfikatorze znanego malware ({bid})",
                             [rv.display(app), f"CFBundleIdentifier={bid}"], suffix=".bundle")


def _check_processes(ctx: EnvContext, rv: _Resolver, hits: _Hits, known: dict[str, tuple[str, str]]) -> None:
    procs = getattr(ctx, "_procs", None)
    if procs is None:
        from .processes import snapshot
        procs = snapshot(ctx)
    for pid, info in procs.items():
        name = info.get("name") or ""
        exe = info.get("exe") or ""
        if name in PROCESS_NAMES:
            fam, score = PROCESS_NAMES[name]
            hits.add(fam, "system", exe or name, score, f"uruchomiony proces o nazwie znanego malware ({name})",
                     [f"pid={pid}", exe or name], suffix=".proc")
        if exe:
            real = rv.root + exe if rv.root and exe.startswith("/") else exe
            hit = known.get(os.path.normpath(real))
            if hit:
                fam, scope = hit
                hits.add(fam, scope, real, 30, "znany artefakt jest właśnie uruchomiony", [f"pid={pid}", exe],
                         suffix=".running")


def collect_artifacts(ctx: EnvContext) -> None:
    ctx.progress("znane artefakty złośliwego oprogramowania (AMOS, Banshee, KandyKorn, NimDoor …)")
    rv = _Resolver(ctx)
    hits = _Hits()
    known: dict[str, tuple[str, str]] = {}
    _check_paths(ctx, rv, hits, known)
    _check_dir_patterns(ctx, rv, hits)
    _check_launchd(ctx, rv, hits, known)
    _check_bundles(ctx, rv, hits)
    if not ctx.options.get("artifacts_skip_processes"):
        _check_processes(ctx, rv, hits, known)
    inv = ctx.inv("known_artifacts")
    for (family, scope), items in sorted(hits.data.items()):
        strong = [x for x in items if not x[1]]
        weak = [x for x in items if x[1]]
        for _sig, _w, path in items:
            if path.startswith("/"):
                ctx.add_target(path, f"known {family} artefact", 2 if strong else 1)
        if not strong and len({p for _s, _w, p in weak}) < 3:
            inv.append({"family": family, "scope": scope, "weak_only": [rv.display(p) for _s, _w, p in weak]})
            continue
        sigs = [s for s, _w, _p in items]
        display, _pua = FAMILIES.get(family, (family, False))
        paths = sorted({rv.display(p) for _s, _w, p in items})
        best = max(items, key=lambda x: (not x[1], x[0].score))
        location = rv.display(best[2])
        n = len(paths)
        title = f"{display}: {n} {_plural(n)}" if n > 1 else f"{display}: {_plural(1)} {location}"
        details = {"family": family, "artifacts": paths}
        if scope != "system":
            details["home"] = scope
        inv.append({"family": family, "scope": scope, "artifacts": paths})
        ctx.add_finding("artifacts", title, location, sigs, details)

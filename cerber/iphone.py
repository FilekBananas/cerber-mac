"""iPhone check over the cable: device info, installed apps, crash logs and an MVT-style analysis of a local
backup against public iOS spyware/stalkerware indicators (cerber/feeds_ios.py) plus generic heuristics.

An iPhone's file system cannot be read without a jailbreak, so – like Amnesty's Mobile Verification Toolkit – the
analysis works on a local backup (Finder/AppleMobileBackup or `idevicebackup2`) plus what the device reports itself.

    parent (unsandboxed)  talks to the device with fixed argv, never a shell: libimobiledevice when installed
                          (/opt/homebrew/bin), Xcode's devicectl when present, Apple's AppleMobileBackup and
                          system_profiler. Nothing on the phone is changed (crash reports are copied with --keep).
    inner (sandbox)       parses everything that came from the phone or the backup (plists, SQLite, crash logs)
                          under the read-only `scan` profile: no network, no writes outside the workspace; SQLite
                          files are opened read-only + immutable, so the backup is never modified either.

Nothing is sent anywhere. A backup is only created when the user explicitly asks for it (button in the app).

    python -m cerber.iphone devices | scan [UDID] [--make-backup] | backup PATH     (JSON lines, like gui_backend)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import html
import json
import os
import plistlib
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from typing import Callable

from . import config
from .core import Confidence
from .envscan.model import SEVERITY_ORDER, Signal, combine, severity_of

Emit = Callable[[dict], None]

MOBILESYNC = os.path.expanduser("~/Library/Application Support/MobileSync/Backup")
BACKUP_DIR = os.path.join(config.HOME, "iphone_backups")          # backups made by Cerber (idevicebackup2)
TOOL_DIRS = ["/opt/homebrew/bin", "/usr/local/bin"]
LIBIMD = ["idevice_id", "ideviceinfo", "idevicepair", "idevicebackup2", "ideviceinstaller", "idevicecrashreport",
          "ideviceprovision"]
APPLE_BACKUP = ("/System/Library/PrivateFrameworks/MobileDevice.framework/Versions/A/AppleMobileDeviceHelper.app"
                "/Contents/Resources/AppleMobileBackup")
DEVICECTL = ["/Applications/Xcode.app/Contents/Developer/usr/bin/devicectl",
             "/Applications/Xcode-beta.app/Contents/Developer/usr/bin/devicectl"]
COCOA_EPOCH = 978307200
MAX_PLIST = 64 << 20
MAX_CRASH_FILES = 3000
ENV_TO_VERDICT = {"malicious": "MALICIOUS", "pua": "PUA", "suspicious": "SUSPICIOUS", "low": "INFO", "info": "CLEAN"}
INDEX = "gui-index.jsonl"
STATE_RANK = {"usb": 3, "wifi": 2, "offline": 1}

PRODUCT_NAMES = {
    "iPhone10,3": "iPhone X", "iPhone10,6": "iPhone X", "iPhone11,2": "iPhone XS", "iPhone11,4": "iPhone XS Max",
    "iPhone11,6": "iPhone XS Max", "iPhone11,8": "iPhone XR", "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max", "iPhone12,8": "iPhone SE (2. gen.)", "iPhone13,1": "iPhone 12 mini",
    "iPhone13,2": "iPhone 12", "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13", "iPhone14,2": "iPhone 13 Pro",
    "iPhone14,3": "iPhone 13 Pro Max", "iPhone14,6": "iPhone SE (3. gen.)", "iPhone14,7": "iPhone 14",
    "iPhone14,8": "iPhone 14 Plus", "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max",
    "iPhone15,4": "iPhone 15", "iPhone15,5": "iPhone 15 Plus", "iPhone16,1": "iPhone 15 Pro",
    "iPhone16,2": "iPhone 15 Pro Max", "iPhone17,1": "iPhone 16 Pro", "iPhone17,2": "iPhone 16 Pro Max",
    "iPhone17,3": "iPhone 16", "iPhone17,4": "iPhone 16 Plus", "iPhone17,5": "iPhone 16e",
}

# jailbreak / sideloading tools (bundle id → name); keywords catch renamed builds
JAILBREAK_APPS = {
    "com.saurik.cydia": "Cydia", "org.coolstar.sileostore": "Sileo", "org.coolstar.sileo": "Sileo",
    "xyz.willy.zebra": "Zebra", "me.apptapp.installer": "Installer", "science.xnu.undecimus": "unc0ver",
    "com.opa334.trollstore": "TrollStore", "com.opa334.trollstorepersistencehelper": "TrollStore Helper",
    "com.opa334.dopamine": "Dopamine", "com.electrateam.chimera": "Chimera", "org.coolstar.electra1131": "Electra",
    "org.coolstar.electra1141": "Electra", "org.coolstar.odyssey": "Odyssey", "org.coolstar.taurine": "Taurine",
    "kjc.loader": "checkra1n", "com.tigisoftware.filza": "Filza", "com.serena.santanderfm": "Santander",
    "com.samiiau.loader": "palera1n", "com.roothide.bootstrap": "RootHide Bootstrap",
}
JAILBREAK_WORDS = re.compile(r"cydia|sileo|unc0ver|checkra1n|palera1n|dopamine|trollstore|electra|chimera|"
                             r"odyssey|taurine|substrate|substitute|ellekit|roothide|filza", re.I)
JAILBREAK_PATHS = re.compile(r"(?:^|/)(?:Library/Cydia|Library/Sileo|\.installed_(?:unc0ver|dopamine|odyssey|taurine)"
                             r"|com\.saurik\.Cydia|org\.coolstar\.|jailbreakd|/var/jb/)", re.I)
SIDELOAD_APPS = {"com.rileytestut.altstore": "AltStore", "com.sidestore.sidestore": "SideStore",
                 "com.sidestore": "SideStore", "com.lightsoftware.esign": "ESign", "com.scarlet.app": "Scarlet"}
SPY_WORDS = re.compile(r"spy|stalk|keylog|snoop|stealth|hidden ?app|phone ?track|track(er)? ?(phone|kid|partner)|"
                       r"monitor(ing)? ?(app|phone)|parental ?monitor", re.I)
SENSITIVE_TCC = {"kTCCServiceMicrophone": "mikrofon", "kTCCServiceCamera": "aparat", "kTCCServicePhotos": "zdjęcia",
                 "kTCCServiceAddressBook": "kontakty", "kTCCServiceCalendar": "kalendarz",
                 "kTCCServiceMediaLibrary": "biblioteka multimediów", "kTCCServiceReminders": "przypomnienia",
                 "kTCCServiceBluetoothAlways": "Bluetooth", "kTCCServiceUserTracking": "śledzenie między aplikacjami"}
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'\\\x00-\x1f\x7f]{2,2048}")
HOSTISH_RE = re.compile(r"^(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}$")
# published indicators that are also names of real iOS daemons/files: a hit alone is only "suspicious"
GENERIC_PROCS = {"backupagent", "diagnosticd", "gatekeeperd", "payload", "com.apple.avcapture"}

ADVICE = {
    "spyware": [
        "Nie resetuj od razu telefonu – najpierw zachowaj kopię zapasową i ten raport (to dowód dla specjalistów).",
        "Skontaktuj się ze specjalistami: Access Now Digital Security Helpline (help@accessnow.org, bezpłatnie) "
        "albo Amnesty International Security Lab.",
        "Zaktualizuj iOS do najnowszej wersji (Ustawienia → Ogólne → Uaktualnienia).",
        "Włącz Tryb blokady (Ustawienia → Prywatność i ochrona → Tryb blokady).",
        "Uruchamiaj telefon ponownie codziennie – część narzędzi szpiegujących nie przetrwa restartu.",
        "Po konsultacji przywróć iPhone'a do ustawień fabrycznych i skonfiguruj go jako nowy (bez przywracania kopii).",
    ],
    "stalkerware": [
        "Ktoś mógł zainstalować aplikację lub profil śledzący. Zanim cokolwiek usuniesz, pomyśl o swoim bezpieczeństwie"
        " – osoba, która to zrobiła, może zauważyć usunięcie.",
        "Jeśli doświadczasz przemocy lub kontroli: Niebieska Linia 800 120 002 (bezpłatnie), w nagłej sytuacji 112.",
        "Usuń nieznaną aplikację (przytrzymaj ikonę → Usuń aplikację) i nieznane profile "
        "(Ustawienia → Ogólne → VPN i urządzenia zarządzane).",
        "Zmień kod blokady telefonu i hasło Apple ID, włącz uwierzytelnianie dwupoziomowe.",
        "Sprawdź „Kontrolę bezpieczeństwa” (Ustawienia → Prywatność i ochrona → Kontrola bezpieczeństwa) – pokaże, "
        "komu udostępniasz lokalizację i dane.",
    ],
    "profile": [
        "Jeśli to nie jest telefon służbowy albo nie rozpoznajesz profilu: Ustawienia → Ogólne → VPN i urządzenia "
        "zarządzane → wybierz profil → Usuń profil.",
        "Po usunięciu zmień hasło Apple ID i kod blokady.",
    ],
    "rootca": [
        "Ustawienia → Ogólne → To urządzenie → Ustawienia zaufania certyfikatów – wyłącz pełne zaufanie dla "
        "nieznanego certyfikatu.",
        "Usuń profil, który go zainstalował (Ustawienia → Ogólne → VPN i urządzenia zarządzane).",
    ],
    "jailbreak": [
        "Jeśli to nie Ty zrobiłeś jailbreak – ktoś miał fizyczny dostęp do telefonu i mógł zainstalować cokolwiek.",
        "Zrób kopię danych, a potem przywróć iPhone'a przez Finder („Przywróć iPhone'a…”) – to usuwa jailbreak; "
        "zaktualizuj iOS.",
        "Zmień kod blokady i hasło Apple ID.",
    ],
    "sideload": [
        "Sprawdź, czy rozpoznajesz te aplikacje (aplikacje firmowe/testowe są normalne na telefonie służbowym).",
        "Nieznane usuń, a w Ustawienia → Ogólne → VPN i urządzenia zarządzane sprawdź, czy nie ma nieznanego "
        "profilu firmy/dewelopera.",
    ],
    "phishing": [
        "Nie otwieraj tych linków.",
        "Jeśli otworzyłeś link i podałeś dane – zmień hasła do tych usług i włącz uwierzytelnianie dwupoziomowe.",
    ],
    "update": ["Zaktualizuj iOS (Ustawienia → Ogólne → Uaktualnienia) i włącz automatyczne uaktualnienia."],
    "passcode": ["Ustaw kod blokady (Ustawienia → Face ID i kod) – najlepiej 6 cyfr lub dłuższy kod alfanumeryczny."],
}


# ================================================================== helpers (both sides)

def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _fmt_dt(v) -> str | None:
    if isinstance(v, _dt.datetime):
        if v.tzinfo is not None:
            v = v.astimezone().replace(tzinfo=None)
        return v.strftime("%Y-%m-%d %H:%M")
    if isinstance(v, str) and v:
        return v[:16].replace("T", " ")
    return None


def _cocoa(ts) -> str | None:
    """Apple timestamps: seconds (or nanoseconds since iOS 11 in sms.db) since 2001-01-01."""
    try:
        t = float(ts)
    except (TypeError, ValueError):
        return None
    if t <= 0:
        return None
    if t > 1e12:
        t /= 1e9
    try:
        return _dt.datetime.fromtimestamp(t + COCOA_EPOCH).strftime("%Y-%m-%d %H:%M")
    except (OverflowError, OSError, ValueError):
        return None


def _days_ago(stamp: str | None) -> float | None:
    if not stamp:
        return None
    try:
        d = _dt.datetime.strptime(stamp[:16], "%Y-%m-%d %H:%M")
    except ValueError:
        return None
    return (_dt.datetime.now() - d).total_seconds() / 86400


def _plist_file(path: str, cap: int = MAX_PLIST):
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > cap:
            return None
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except Exception:  # noqa: BLE001 - malformed input is expected
        return None


def _plist_bytes(data) -> object | None:
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_PLIST:
        return None
    try:
        return plistlib.loads(bytes(data))
    except Exception:  # noqa: BLE001
        return None


def _sqlite(path: str) -> sqlite3.Connection | None:
    """Read-only + immutable: no journal/WAL files are created, the file is never modified."""
    try:
        con = sqlite3.connect(f"file:{urllib.parse.quote(path)}?mode=ro&immutable=1", uri=True, timeout=5)
        con.execute("PRAGMA trusted_schema=OFF")
        con.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return con
    except sqlite3.Error:
        return None


def _rows(con: sqlite3.Connection, sql: str, args=()) -> list:
    try:
        return con.execute(sql, args).fetchall()
    except sqlite3.Error:
        return []


def _host(url: str) -> str | None:
    u = url if "://" in url else "http://" + url
    try:
        h = urllib.parse.urlsplit(u).hostname
    except ValueError:
        return None
    return h.lower().rstrip(".") if h else None


def extract_urls(text: str) -> list[str]:
    out = []
    for m in URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;:!?)]}>'\"")
        if len(u) > 8:
            out.append(u)
    return out


def _norm_udid(u: str) -> str:
    return (u or "").replace("-", "").upper()


def valid_udid(u: str | None) -> bool:
    return bool(u) and bool(re.fullmatch(r"[0-9A-Fa-f][0-9A-Fa-f-]{19,44}", u))


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "", s.split("(")[0])[:40] or "IOC"


def _pl_count(n: int, one: str, few: str, many: str) -> str:
    if n == 1:
        return f"{n} {one}"
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return f"{n} {few}"
    return f"{n} {many}"


# ================================================================== indicators

class Matcher:
    """Lookups in the iOS indicator DB (feeds_ios) and Cerber's general URL/domain/IP list (URLhaus/ThreatFox)."""

    def __init__(self, ios_path: str | None = None, mac_path: str | None = None):
        self.ind = None
        self.bulk: dict[str, dict[str, list[dict]]] = {"process": {}, "file_name": {}, "file_path": {}}
        self.names: dict[str, str] = {}
        self._cache: dict[tuple, list] = {}
        try:
            from .feeds_ios import IOS_IOCDB, IOSIndicators
            ios_path = ios_path or IOS_IOCDB
            ind = IOSIndicators(ios_path)
            self.ind = ind if ind.available else None
        except Exception:  # noqa: BLE001 - DB missing or module not built yet
            self.ind = None
        if self.ind:
            con = _sqlite(ios_path)
            if con:
                for kind, value, threat, source, role in _rows(
                        con, "SELECT kind, value, threat, source, role FROM ioc WHERE kind IN "
                             "('process','file_name','file_path')"):
                    self.bulk[kind].setdefault(value, []).append(
                        {"kind": kind, "value": value, "threat": threat, "source": source, "role": role})
                for (threat,) in _rows(con, "SELECT DISTINCT threat FROM ioc WHERE role IN ('app','c2','website')"):
                    name = threat.split(":", 1)[-1].strip()
                    key = re.sub(r"[^a-z0-9]", "", name.lower())
                    if len(key) >= 4:
                        self.names[key] = threat
                con.close()
        if mac_path is None:
            mac_path = config.IOCDB
        self.mac = _sqlite(mac_path) if mac_path and os.path.isfile(mac_path) else None

    @property
    def available(self) -> bool:
        return self.ind is not None

    def close(self) -> None:
        for c in (self.ind, self.mac):
            try:
                if c is not None:
                    c.close()
            except Exception:  # noqa: BLE001
                pass

    def stats(self) -> dict:
        try:
            return self.ind.stats() if self.ind else {"total": 0}
        except Exception:  # noqa: BLE001
            return {"total": 0}

    def _mac(self, kind: str, value: str) -> list[dict]:
        if not self.mac or not value:
            return []
        return [{"kind": kind, "value": value, "threat": t, "source": "URLhaus/ThreatFox", "role": "mac_ioc"}
                for (t,) in _rows(self.mac, "SELECT threat FROM ioc WHERE kind=? AND value=?", (kind, value))]

    def _cached(self, key: tuple, fn) -> list[dict]:
        if key not in self._cache:
            if len(self._cache) > 200_000:
                self._cache.clear()
            try:
                self._cache[key] = fn()
            except Exception:  # noqa: BLE001
                self._cache[key] = []
        return self._cache[key]

    def domain(self, host: str | None) -> list[dict]:
        if not host:
            return []
        host = host.lower().strip(".")

        def run() -> list[dict]:
            hits = list(self.ind.match_domain(host)) if self.ind else []
            parts = host.split(".")
            if re.fullmatch(r"[\d.]+", host):
                hits += self._mac("ip", host)
                if self.ind:
                    hits += self.ind.lookup("ip", host)
            else:
                for i in range(len(parts) - 1):
                    hits += self._mac("domain", ".".join(parts[i:]))
            return hits
        return self._cached(("d", host), run)

    def url(self, url: str) -> list[dict]:
        u = url.strip()
        if not u:
            return []

        def run() -> list[dict]:
            hits = list(self.ind.match_url(u)) if self.ind else []
            low = u.lower()
            hits += self._mac("url", low) or self._mac("url", low.rstrip("/"))
            host = _host(u)
            known = {(h["threat"], h["source"]) for h in hits}
            hits += [h for h in self.domain(host) if (h["threat"], h["source"]) not in known]
            return hits
        return self._cached(("u", u), run)

    def lookup(self, kind: str, value: str | None) -> list[dict]:
        if not self.ind or not value:
            return []
        return self._cached((kind, value.lower()), lambda: list(self.ind.lookup(kind, value.lower())))

    def process(self, name: str | None) -> list[dict]:
        if not name or not self.ind:
            return []
        n = os.path.basename(name.strip()).lower()
        if not n:
            return []
        hits = list(self.bulk["process"].get(n, []))
        if not hits and len(n) == 15:                   # names are truncated to 15 chars in some logs (MVT)
            for k, v in self.bulk["process"].items():
                if k.startswith(n):
                    hits += v
        return [{**h, "weak": True} if h["value"] in GENERIC_PROCS else h for h in hits]

    def path(self, rel: str) -> list[dict]:
        """A backup-relative path (or device path) against file_path / file_name indicators."""
        if not self.ind or not rel:
            return []
        low = rel.lower().lstrip("/")
        hits = []
        for ioc, items in self.bulk["file_path"].items():
            core = re.sub(r"^/?(?:private/)?var/(?:mobile/|root/)?", "", ioc.lstrip("/"))
            if low == core or low.endswith("/" + core) or ("/" in core and len(core) > 12 and core in low):
                hits += items
        base = os.path.basename(low)
        if len(base) >= 6:
            weak = base.lstrip(".").startswith("com.apple.")
            hits += [{**h, "weak": True} if weak else h for h in self.bulk["file_name"].get(base, [])]
        return hits

    def stalkerware_name(self, app_name: str | None) -> str | None:
        key = re.sub(r"[^a-z0-9]", "", (app_name or "").lower())
        return self.names.get(key) if len(key) >= 4 else None


# ================================================================== findings

WHERE_PL = {
    "sms": "w wiadomościach SMS/iMessage", "safari": "w historii Safari", "safari_tabs": "w kartach Safari",
    "webkit": "w danych stron WWW (WebKit)", "chrome": "w historii Chrome", "firefox": "w historii Firefoksa",
    "whatsapp": "w wiadomościach WhatsApp", "datausage": "w statystykach transferu danych (DataUsage)",
    "osanalytics": "w dziennych statystykach sieci (OSAnalytics)", "idstatus": "w kontach iMessage/FaceTime",
    "interaction": "w historii interakcji (kontakty)", "tcc": "w uprawnieniach prywatności (TCC)",
    "locationd": "w usługach lokalizacji", "crash": "w raportach awarii z telefonu", "files": "w plikach kopii",
    "apps": "w zainstalowanych aplikacjach", "profiles": "w profilach konfiguracyjnych", "shortcuts": "w skrótach",
}
ROLE_SCORE = {"infra": (90, Confidence.HIGH), "weak": (40, Confidence.MEDIUM), "app": (85, Confidence.HIGH), "c2": (60, Confidence.HIGH),
              "website": (35, Confidence.MEDIUM), "mac_ioc": (45, Confidence.MEDIUM)}


class Ctx:
    """Collects findings, checks and inventory of one analysis; emits findings as they are made."""

    def __init__(self, matcher: Matcher, emit: Emit | None = None):
        self.m = matcher
        self.emit = emit or (lambda ev: None)
        self.findings: list[dict] = []
        self.checks: list[dict] = []
        self.limitations: list[str] = []
        self.posture: dict = {}
        self.device: dict = {}
        self.backup: dict = {}
        self.apps: dict[str, dict] = {}
        self.tcc: dict[str, set] = {}
        self.locations: set[str] = set()
        self.profiles: list[dict] = []
        self.stats: dict = {}
        self._groups: dict[tuple, dict] = {}
        self._step = 0
        self.steps_total = 1

    # -- progress / bookkeeping
    def step(self, title: str) -> None:
        self._step += 1
        self.emit({"ev": "progress", "stage": "analyze", "done": min(self._step, self.steps_total),
                   "total": self.steps_total, "current": title})

    def check(self, cid: str, title: str, status: str, detail: str = "") -> None:
        """status: ok | found | missing | skipped | error"""
        self.checks.append({"id": cid, "title": title, "status": status, "detail": detail})

    def finding(self, category: str, title: str, location: str, signals: list[Signal],
                advice: list[str] | None = None, threat: str | None = None, details: dict | None = None) -> dict | None:
        det = combine(signals, engine="iphone")
        if det is None:
            return None
        evidence: list[str] = []
        for s in signals:
            for e in s.evidence:
                if e not in evidence:
                    evidence.append(e)
        f = {"id": f"f{len(self.findings) + 1}", "category": category, "title": title, "location": location,
             "severity": severity_of(det), "score": det.score, "confidence": det.confidence.name,
             "description": det.description, "evidence": evidence[:40], "evidence_total": len(evidence),
             "signals": det.evidence[:10], "advice": list(advice or []), "threat": threat,
             "details": details or {}}
        self.findings.append(f)
        self.emit({"ev": "iphone_finding", "item": f})
        return f

    # -- indicator hits, grouped per (threat, role, where) and turned into findings by flush()
    def hit(self, hits: list[dict], where: str, evidence: str, location: str) -> None:
        for h in hits:
            role = h.get("role") or "infra"
            if h.get("weak") and role == "infra":
                role = "weak"
            key = (h.get("threat") or "?", role, where)
            g = self._groups.setdefault(key, {"evidence": [], "values": set(), "sources": set(), "location": location,
                                              "kinds": set()})
            g["values"].add(h.get("value"))
            g["sources"].add(h.get("source") or "?")
            g["kinds"].add(h.get("kind"))
            line = f"{h.get('value')} ← {evidence}" if h.get("value") and h.get("value") not in evidence else evidence
            if line not in g["evidence"] and len(g["evidence"]) < 60:
                g["evidence"].append(line[:400])

    def flush(self) -> None:
        for (threat, role, where), g in sorted(self._groups.items(), key=lambda kv: -ROLE_SCORE.get(kv[0][1], (0,))[0]):
            score, conf = ROLE_SCORE.get(role, (60, Confidence.MEDIUM))
            wpl = WHERE_PL.get(where, where)
            srcs = ", ".join(sorted(g["sources"]))
            n = len(g["values"])
            what = _pl_count(n, "wskaźnik", "wskaźniki", "wskaźników")
            if role == "infra":
                title = f"Ślad oprogramowania szpiegującego {threat} {wpl}"
                desc = (f"Znaleziono {what} znanych z ataków {threat} ({wpl}). Wskaźniki pochodzą z publicznych "
                        f"śledztw ({srcs}). To bardzo poważny sygnał infekcji albo próby ataku (np. link wysłany "
                        f"w wiadomości), choć nie jest jeszcze ostatecznym dowodem – potwierdzić go mogą specjaliści.")
                advice, cat = ADVICE["spyware"], "spyware"
            elif role == "weak":
                title = f"Możliwy ślad {threat} {wpl}"
                desc = (f"Nazwa procesu lub pliku pasuje do wskaźnika {threat} ({srcs}), ale taka sama nazwa występuje "
                        f"też w zwykłym iOS – samo to trafienie nie przesądza o infekcji. Ważne, jeśli są inne ślady.")
                advice, cat = ADVICE["spyware"][2:5], "spyware"
            elif role == "app":
                title = f"Aplikacja śledząca (stalkerware): {threat.split(':', 1)[-1].strip()}"
                desc = (f"Na telefonie jest aplikacja z listy oprogramowania śledzącego ({srcs}). Taka aplikacja może "
                        f"przekazywać komuś Twoje wiadomości, lokalizację i zdjęcia.")
                advice, cat = ADVICE["stalkerware"], "stalkerware"
            elif role == "c2":
                title = f"Kontakt z serwerem oprogramowania śledzącego ({threat}) {wpl}"
                desc = (f"Znaleziono {what} serwerów, z którymi łączy się oprogramowanie śledzące {threat} ({srcs}). "
                        f"Może to oznaczać, że na telefonie działa (lub działało) takie oprogramowanie.")
                advice, cat = ADVICE["stalkerware"], "stalkerware"
            elif role == "website":
                title = f"Strona producenta oprogramowania śledzącego ({threat}) {wpl}"
                desc = (f"Ktoś odwiedzał stronę producenta oprogramowania śledzącego ({threat}). Jeśli to nie Ty – ktoś "
                        f"mógł przygotowywać instalację programu do śledzenia tego telefonu.")
                advice, cat = ADVICE["stalkerware"], "stalkerware"
            else:
                title = f"Złośliwe adresy z list zagrożeń {wpl}"
                desc = (f"Znaleziono {what} z publicznych list złośliwych adresów ({srcs}: {threat}) – zwykle phishing "
                        f"lub strony z malware, często przysyłane w SMS-ach.")
                advice, cat = ADVICE["phishing"], "phishing"
            sig = Signal(f"IOC.iOS.{_slug(threat)}", score, conf, desc, g["evidence"])
            self.finding(cat, title, g["location"], [sig], advice, threat=threat,
                         details={"source": srcs, "role": role, "where": where, "indicators": sorted(
                             v for v in g["values"] if v)[:50]})
        self._groups.clear()

    def result(self) -> dict:
        self.flush()
        self.findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0), -f["score"]))
        apps = sorted(self.apps.values(), key=lambda a: (a.get("source") == "appstore", a.get("bundle_id") or ""))
        return {"findings": self.findings, "checks": self.checks, "limitations": self.limitations,
                "posture": self.posture, "device": self.device, "backup": self.backup,
                "apps": [{k: v for k, v in a.items() if k != "seen"} | {"seen": sorted(a.get("seen") or [])}
                         for a in apps][:800],
                "apps_total": len(self.apps), "profiles": self.profiles, "stats": self.stats,
                "indicators": self.m.stats()}


# ================================================================== backup access

class Backup:
    """A local iOS backup (Finder / iTunes / idevicebackup2 layout: Manifest.db + <xx>/<sha1> files)."""

    def __init__(self, root: str):
        self.root = os.path.realpath(root)
        self.info = _plist_file(os.path.join(self.root, "Info.plist")) or {}
        self.manifest = _plist_file(os.path.join(self.root, "Manifest.plist")) or {}
        self.status = _plist_file(os.path.join(self.root, "Status.plist")) or {}
        self.encrypted = bool(self.manifest.get("IsEncrypted"))
        self.db = None
        mdb = os.path.join(self.root, "Manifest.db")
        if os.path.isfile(mdb) and not self.encrypted:
            con = _sqlite(mdb)
            if con is not None and _rows(con, "SELECT 1 FROM Files LIMIT 1") is not None:
                self.db = con
            elif os.path.getsize(mdb) > 0:
                self.encrypted = True               # unreadable Manifest.db = encrypted (or damaged)

    @property
    def valid(self) -> bool:
        return bool(self.info or self.manifest or self.db)

    def meta(self) -> dict:
        lock = self.manifest.get("Lockdown") or {}
        udid = self.info.get("Target Identifier") or self.info.get("Unique Identifier") or lock.get("UniqueDeviceID")
        date = self.info.get("Last Backup Date") or self.status.get("Date") or self.manifest.get("Date")
        pt = self.info.get("Product Type") or lock.get("ProductType")
        return {"path": self.root, "udid": udid or os.path.basename(self.root),
                "device_name": self.info.get("Device Name") or self.info.get("Display Name") or lock.get("DeviceName"),
                "model": self.info.get("Product Name") or PRODUCT_NAMES.get(pt or "", pt),
                "product_type": pt, "ios": self.info.get("Product Version") or lock.get("ProductVersion"),
                "date": _fmt_dt(date), "encrypted": self.encrypted,
                "passcode_set": self.manifest.get("WasPasscodeSet"),
                "complete": (self.status.get("SnapshotState") in (None, "finished")),
                "full": self.status.get("IsFullBackup")}

    @staticmethod
    def file_id(domain: str, rel: str) -> str:
        return hashlib.sha1(f"{domain}-{rel}".encode()).hexdigest()

    def path_of(self, file_id: str) -> str | None:
        for cand in (os.path.join(self.root, file_id[:2], file_id), os.path.join(self.root, file_id)):
            if os.path.isfile(cand):
                return cand
        return None

    def get(self, domain: str, rel: str) -> str | None:
        return self.path_of(self.file_id(domain, rel))

    def by_rel(self, rel: str) -> list[tuple[str, str, str]]:
        """(domain, relativePath, file path) of every backed-up file with this exact relative path."""
        if self.db is None:
            return []
        out = []
        for fid, dom, r in _rows(self.db, "SELECT fileID, domain, relativePath FROM Files WHERE relativePath=? "
                                          "AND flags=1", (rel,)):
            p = self.path_of(fid)
            if p:
                out.append((dom, r, p))
        return out

    def like(self, rel_like: str, domain_like: str = "%") -> list[tuple[str, str, str]]:
        if self.db is None:
            return []
        out = []
        for fid, dom, r in _rows(self.db, "SELECT fileID, domain, relativePath FROM Files WHERE relativePath LIKE ? "
                                          "AND domain LIKE ? AND flags=1 LIMIT 5000", (rel_like, domain_like)):
            p = self.path_of(fid)
            if p:
                out.append((dom, r, p))
        return out

    def first(self, *rels: str) -> tuple[str, str, str] | None:
        for rel in rels:
            hits = self.by_rel(rel)
            if hits:
                return hits[0]
        return None


def backup_meta(path: str, source: str = "finder") -> dict:
    b = Backup(path)
    m = b.meta() if b.valid else {"path": os.path.realpath(path), "udid": os.path.basename(path.rstrip("/")),
                                  "invalid": True}
    m["source"] = source
    return m


# ================================================================== analysis modules (run INSIDE the sandbox)

def _check_urls(ctx: Ctx, rows, where: str, location: str) -> int:
    """rows: iterable of (url, context text). Returns the number of URLs checked."""
    n = 0
    for url, ctxt in rows:
        if not url:
            continue
        n += 1
        hits = ctx.m.url(url)
        if hits:
            ctx.hit(hits, where, f"{url[:300]}" + (f" ({ctxt})" if ctxt else ""), location)
    return n


def mod_sms(ctx: Ctx, b: Backup) -> None:
    title = "Wiadomości SMS/iMessage"
    f = b.first("Library/SMS/sms.db")
    con = _sqlite(f[2]) if f else None
    if not con:
        ctx.check("sms", title, "missing", "brak bazy wiadomości w kopii")
        return
    urls = []
    msgs = 0
    rows = _rows(con, "SELECT m.text, m.attributedBody, m.date, h.id, m.is_from_me FROM message m "
                      "LEFT JOIN handle h ON m.handle_id = h.ROWID") or \
        _rows(con, "SELECT m.text, NULL, m.date, h.id, m.is_from_me FROM message m "
                   "LEFT JOIN handle h ON m.handle_id = h.ROWID")
    emails = set()
    for text, body, date, handle, from_me in rows:
        msgs += 1
        txt = text or ""
        if not txt and isinstance(body, (bytes, bytearray)):
            txt = bytes(body[:65536]).decode("utf-8", "ignore")
        who = ("wysłana" if from_me else f"od {str(handle)[:60]}") if handle or from_me else ""
        when = _cocoa(date) or ""
        for u in extract_urls(txt):
            urls.append((u, ", ".join(x for x in (f"SMS {who}".strip(), when) if x)))
        if handle and "@" in str(handle) and not from_me:
            emails.add(str(handle).lower())
    n = _check_urls(ctx, urls, "sms", "Library/SMS/sms.db")
    for e in emails:
        ctx.hit(ctx.m.lookup("email", e), "sms", f"nadawca {e}", "Library/SMS/sms.db")
    # FORCEDENTRY: ".gif" attachments that are really PDF / PSD files (Citizen Lab, 2021)
    fe = []
    for fname, mime, uti, tname in _rows(con, "SELECT filename, mime_type, uti, transfer_name FROM attachment"):
        name = (tname or fname or "").lower()
        if not name.endswith(".gif"):
            continue
        fake = (uti or "") in ("com.adobe.pdf", "com.adobe.photoshop-image") or \
            (mime or "") in ("application/pdf", "image/vnd.adobe.photoshop")
        if not fake and fname:
            rel = str(fname).replace("~/", "", 1).lstrip("/")
            p = b.get("MediaDomain", rel)
            if p:
                try:
                    with open(p, "rb") as fh:
                        head = fh.read(8)
                    fake = head.startswith((b"%PDF", b"8BPS"))
                except OSError:
                    pass
        if fake:
            fe.append(f"{tname or fname} (typ: {mime or uti or 'PDF/PSD wg zawartości'})")
    if fe:
        ctx.finding("spyware", "Załączniki iMessage w stylu exploita FORCEDENTRY (Pegasus)", "Library/SMS/Attachments",
                    [Signal("Heur:iOS.ForcedEntry.FakeGif", 60, Confidence.HIGH,
                            "Pliki wysłane jako obrazki .gif są w rzeczywistości dokumentami PDF/PSD – tak wyglądał "
                            "exploit FORCEDENTRY używany przez Pegasusa (NSO) w 2021 r. Możliwe też rzadkie, "
                            "niewinne przypadki.", fe[:20])], ADVICE["spyware"], threat="Pegasus (NSO Group)")
    con.close()
    ctx.stats["sms_messages"] = msgs
    ctx.stats["sms_urls"] = n
    ctx.check("sms", title, "ok", f"{msgs} wiadomości, {n} linków sprawdzonych")


def mod_safari(ctx: Ctx, b: Backup) -> None:
    title = "Historia i karty Safari"
    found = False
    total = 0
    for dom, rel, p in b.by_rel("Library/Safari/History.db"):
        con = _sqlite(p)
        if not con:
            continue
        found = True
        rows = _rows(con, "SELECT i.url, MAX(v.visit_time) FROM history_items i LEFT JOIN history_visits v "
                          "ON v.history_item = i.id GROUP BY i.id")
        total += _check_urls(ctx, ((u, f"Safari, {_cocoa(t) or ''}".rstrip(", ")) for u, t in rows), "safari",
                             "Library/Safari/History.db")
        con.close()
    for dom, rel, p in b.by_rel("Library/Safari/BrowserState.db"):
        con = _sqlite(p)
        if not con:
            continue
        found = True
        rows = _rows(con, "SELECT url, last_viewed_time FROM tabs")
        total += _check_urls(ctx, ((u, f"karta Safari, {_cocoa(t) or ''}".rstrip(", ")) for u, t in rows),
                             "safari_tabs", "Library/Safari/BrowserState.db")
        con.close()
    ctx.stats["safari_urls"] = total
    ctx.check("safari", title, "ok" if found else "missing",
              f"{total} adresów sprawdzonych" if found else "brak historii Safari w kopii (np. wyłączona w iCloud)")


def mod_browsers(ctx: Ctx, b: Backup) -> None:
    title = "Inne przeglądarki (Chrome, Firefox)"
    total = 0
    found = []
    for dom, rel, p in b.like("%Chrome/Default/History", "%chrome%"):
        con = _sqlite(p)
        if con:
            found.append("Chrome")
            total += _check_urls(ctx, ((u, "Chrome") for (u,) in _rows(con, "SELECT url FROM urls")), "chrome", rel)
            con.close()
    for dom, rel, p in b.like("%browser.db", "%mozilla%"):
        con = _sqlite(p)
        if con:
            found.append("Firefox")
            total += _check_urls(ctx, ((u, "Firefox") for (u,) in _rows(con, "SELECT url FROM history")), "firefox",
                                 rel)
            con.close()
    ctx.check("browsers", title, "ok" if found else "missing",
              f"{', '.join(sorted(set(found)))}: {total} adresów" if found else "nie znaleziono")


def mod_whatsapp(ctx: Ctx, b: Backup) -> None:
    title = "Wiadomości WhatsApp (linki)"
    hits = b.like("ChatStorage.sqlite", "%whatsapp%")
    if not hits:
        ctx.check("whatsapp", title, "missing", "WhatsApp nie występuje w kopii")
        return
    total = 0
    for dom, rel, p in hits:
        con = _sqlite(p)
        if not con:
            continue
        rows = _rows(con, "SELECT ZTEXT, ZMESSAGEDATE FROM ZWAMESSAGE WHERE ZTEXT LIKE '%http%' OR ZTEXT LIKE '%www.%'")
        urls = [(u, f"WhatsApp, {_cocoa(d) or ''}".rstrip(", ")) for t, d in rows for u in extract_urls(t or "")]
        total += _check_urls(ctx, urls, "whatsapp", rel)
        con.close()
    ctx.check("whatsapp", title, "ok", f"{total} linków sprawdzonych")


WEBKIT_ORIGIN = re.compile(r"(?:^|/)(?:https?|wss?)_([a-z0-9.-]+\.[a-z]{2,24})_\d+(?:/|\.|$)", re.I)


def mod_webkit(ctx: Ctx, b: Backup) -> None:
    title = "Dane stron WWW (WebKit: statystyki, pamięć stron)"
    n = 0
    found = False
    for dom, rel, p in b.like("%ResourceLoadStatistics/observations.db"):
        con = _sqlite(p)
        if not con:
            continue
        found = True
        for d, seen in _rows(con, "SELECT registrableDomain, lastSeen FROM ObservedDomains"):
            n += 1
            hits = ctx.m.domain(d)
            if hits:
                ctx.hit(hits, "webkit", f"{d} (WebKit {dom.split('-', 1)[-1]}, {_unix(seen) or ''})".replace(", )", ")"),
                        rel)
        con.close()
    for dom, rel, p in b.like("%full_browsing_session_resourceLog.plist"):
        data = _plist_file(p)
        if data is None:
            continue
        found = True
        for s in _strings(data):
            h = s.lower().strip(".")
            if HOSTISH_RE.match(h):
                n += 1
                hits = ctx.m.domain(h)
                if hits:
                    ctx.hit(hits, "webkit", f"{h} (dziennik sesji WebKit)", rel)
    ctx.stats["webkit_domains"] = n
    ctx.check("webkit", title, "ok" if found else "missing", f"{n} domen sprawdzonych" if found else "brak danych")


def _unix(ts) -> str | None:
    try:
        return _dt.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M") if ts else None
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _strings(obj, depth: int = 0):
    if depth > 12:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield k
            yield from _strings(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v, depth + 1)


def mod_manifest(ctx: Ctx, b: Backup) -> None:
    """One pass over every backed-up file: app containers, website data origins, file indicators, jailbreak traces."""
    title = "Lista plików kopii (Manifest.db)"
    if b.db is None:
        ctx.check("manifest", title, "skipped" if b.encrypted else "missing",
                  "kopia zaszyfrowana" if b.encrypted else "brak Manifest.db")
        return
    n = 0
    jb: list[str] = []
    origins: dict[str, str] = {}
    try:
        cur = b.db.execute("SELECT domain, relativePath FROM Files")
        for dom, rel in cur:
            n += 1
            dom = dom or ""
            rel = rel or ""
            if dom.startswith(("AppDomain-", "AppDomainGroup-", "AppDomainPlugin-")):
                bid = dom.split("-", 1)[1]
                if dom.startswith("AppDomain-"):
                    a = ctx.apps.setdefault(bid, {"bundle_id": bid})
                    a.setdefault("seen", set()).add("dane w kopii")
            if not rel:
                continue
            hits = ctx.m.path(rel)
            if hits:
                ctx.hit(hits, "files", f"{dom}: {rel}", "Manifest.db")
            if JAILBREAK_PATHS.search(rel) and len(jb) < 30:
                jb.append(f"{dom}: {rel}")
            if "WebsiteData" in rel or "/Caches/" in rel or "WebKit" in rel:
                m = WEBKIT_ORIGIN.search(rel)
                if m:
                    origins.setdefault(m.group(1).lower(), f"{dom}: {rel[:160]}")
    except sqlite3.Error as exc:
        ctx.limitations.append(f"Manifest.db przeczytany częściowo ({exc})")
    for host, where in origins.items():
        hits = ctx.m.domain(host)
        if hits:
            ctx.hit(hits, "webkit", f"{host} ({where})", "Manifest.db")
    if jb:
        ctx.finding("jailbreak", "Ślady jailbreaka w plikach kopii", "Manifest.db",
                    [Signal("Heur:iOS.Jailbreak.Files", 45, Confidence.MEDIUM,
                            "W kopii są pliki narzędzi do jailbreaka (Cydia/Sileo/unc0ver/Dopamine…). Jailbreak "
                            "wyłącza zabezpieczenia iOS – jeśli to nie Ty go zrobiłeś, ktoś miał dostęp do telefonu.",
                            jb)], ADVICE["jailbreak"])
    ctx.stats["backup_files"] = n
    ctx.stats["website_origins"] = len(origins)
    ctx.check("manifest", title, "ok", f"{n} plików, {len(origins)} stron z zapisanymi danymi")


def mod_datausage(ctx: Ctx, b: Backup) -> None:
    title = "Procesy używające sieci (DataUsage)"
    f = b.first("Library/Databases/DataUsage.sqlite")
    con = _sqlite(f[2]) if f else None
    if not con:
        ctx.check("datausage", title, "missing", "brak DataUsage.sqlite w kopii")
        return
    traffic = {pk: (tot or 0) for pk, tot in _rows(
        con, "SELECT ZHASPROCESS, SUM(COALESCE(ZWIFIIN,0)+COALESCE(ZWIFIOUT,0)+COALESCE(ZWWANIN,0)+COALESCE(ZWWANOUT,0)) "
             "FROM ZLIVEUSAGE GROUP BY ZHASPROCESS")}
    rows = _rows(con, "SELECT Z_PK, ZPROCNAME, ZBUNDLENAME, ZFIRSTTIMESTAMP, ZTIMESTAMP FROM ZPROCESS")
    triang = []
    pks = []
    for pk, proc, bundle, first, last in rows:
        pks.append(pk or 0)
        when = f"{_cocoa(first) or '?'} – {_cocoa(last) or '?'}"
        for part in {p for p in str(proc or "").split("/") if p}:
            hits = ctx.m.process(part)
            if hits:
                ctx.hit(hits, "datausage", f"proces {part} ({when})", "DataUsage.sqlite")
            if part == "BackupAgent" and traffic.get(pk, 0) > 0:
                triang.append(f"BackupAgent: {traffic.get(pk)} B przesłanych ({when})")
        if bundle:
            ctx.hit(ctx.m.lookup("bundle_id", str(bundle)), "datausage", f"aplikacja {bundle} ({when})",
                    "DataUsage.sqlite")
    if triang:
        ctx.finding("spyware", "Możliwy ślad Operation Triangulation (BackupAgent w sieci)", "DataUsage.sqlite",
                    [Signal("Heur:iOS.Triangulation.BackupAgent", 70, Confidence.HIGH,
                            "Przestarzały proces systemowy BackupAgent przesyłał dane przez sieć. Według Kaspersky to "
                            "najbardziej niezawodny wskaźnik infekcji Operation Triangulation (exploit iMessage, "
                            "2019–2023).", triang)], ADVICE["spyware"], threat="Operation Triangulation")
    gaps = 0
    if pks:
        s = sorted(pks)
        gaps = sum(max(0, b2 - a2 - 1) for a2, b2 in zip(s, s[1:]))
    con.close()
    ctx.stats["datausage_processes"] = len(rows)
    ctx.check("datausage", title, "ok", f"{len(rows)} procesów" + (f"; {gaps} usuniętych wpisów (zwykle normalne "
                                                                     f"czyszczenie iOS)" if gaps else ""))


def mod_osanalytics(ctx: Ctx, b: Backup) -> None:
    title = "Dzienne statystyki sieci (OSAnalytics)"
    f = b.first("Library/Preferences/com.apple.osanalytics.addaily.plist")
    data = _plist_file(f[2]) if f else None
    if not isinstance(data, dict):
        ctx.check("osanalytics", title, "missing", "brak pliku w kopii")
        return
    base = data.get("netUsageBaseline") or {}
    for proc, vals in base.items() if isinstance(base, dict) else []:
        hits = ctx.m.process(str(proc))
        if hits:
            ts = vals[0] if isinstance(vals, list) and vals else None
            ctx.hit(hits, "osanalytics", f"proces {proc}" + (f" ({_fmt_dt(ts)})" if _fmt_dt(ts) else ""),
                    "com.apple.osanalytics.addaily.plist")
    ctx.check("osanalytics", title, "ok", f"{len(base) if isinstance(base, dict) else 0} procesów")


def mod_identities(ctx: Ctx, b: Backup) -> None:
    """IDStatusCache (iMessage/FaceTime lookups – Pegasus attack accounts) and interactionC (contacts)."""
    title = "Konta iMessage/FaceTime i interakcje (IDStatusCache, interactionC)"
    found = False
    n = 0
    for rel in ("Library/Preferences/com.apple.identityservices.idstatuscache.plist",
                "Library/IdentityServices/idstatuscache.plist"):
        for dom, r, p in b.by_rel(rel):
            data = _plist_file(p)
            if not isinstance(data, dict):
                continue
            found = True
            for service, entries in data.items():
                if not isinstance(entries, dict):
                    continue
                for ident, val in entries.items():
                    s = str(ident)
                    if s.startswith("mailto:"):
                        n += 1
                        e = s[7:].lower()
                        when = _cocoa((val or {}).get("LookupDate")) if isinstance(val, dict) else None
                        ctx.hit(ctx.m.lookup("email", e), "idstatus",
                                f"{e} ({service}{', ' + when if when else ''})", r)
    f = b.first("Library/CoreDuet/People/interactionC.db")
    con = _sqlite(f[2]) if f else None
    if con:
        found = True
        for ident, name in _rows(con, "SELECT ZIDENTIFIER, ZDISPLAYNAME FROM ZCONTACTS"):
            s = str(ident or "").lower()
            if "@" in s:
                n += 1
                ctx.hit(ctx.m.lookup("email", s.replace("mailto:", "")), "interaction", f"kontakt {s}",
                        "interactionC.db")
        for (bid,) in _rows(con, "SELECT DISTINCT ZBUNDLEID FROM ZINTERACTIONS"):
            if bid:
                ctx.hit(ctx.m.lookup("bundle_id", str(bid)), "interaction", f"aplikacja {bid}", "interactionC.db")
        con.close()
    ctx.check("identities", title, "ok" if found else "missing",
              f"{n} adresów e-mail sprawdzonych" if found else "brak danych w kopii")


def mod_tcc(ctx: Ctx, b: Backup) -> None:
    title = "Uprawnienia prywatności aplikacji (TCC)"
    f = b.first("Library/TCC/TCC.db")
    con = _sqlite(f[2]) if f else None
    if not con:
        ctx.check("tcc", title, "missing", "brak TCC.db w kopii")
        return
    rows = _rows(con, "SELECT service, client, auth_value FROM access") or \
        [(s, c, 2 if a else 0) for s, c, a in _rows(con, "SELECT service, client, allowed FROM access")]
    for service, client, auth in rows:
        if not client:
            continue
        cl = str(client)
        hits = ctx.m.lookup("bundle_id", cl) + ctx.m.process(cl)
        if hits:
            ctx.hit(hits, "tcc", f"{cl}: {service}", "TCC.db")
        if auth in (2, 3) and service in SENSITIVE_TCC:
            ctx.tcc.setdefault(cl.lower(), set()).add(SENSITIVE_TCC[service])
    con.close()
    ctx.check("tcc", title, "ok", f"{len(rows)} wpisów")


def mod_locationd(ctx: Ctx, b: Backup) -> None:
    title = "Aplikacje z dostępem do lokalizacji"
    f = b.first("Library/Caches/locationd/clients.plist")
    data = _plist_file(f[2]) if f else None
    if not isinstance(data, dict):
        ctx.check("locationd", title, "missing", "brak pliku w kopii")
        return
    for key, val in data.items():
        k = str(key)
        ident = k.split(":", 1)[-1]
        if ident.startswith("/") or "/" in ident:
            hits = ctx.m.process(os.path.basename(ident.rstrip("/"))) + ctx.m.path(ident)
        else:
            hits = ctx.m.lookup("bundle_id", ident)
            if isinstance(val, dict) and val.get("Authorization") in (2, 3, 4):
                ctx.locations.add(ident.lower())
        if hits:
            ctx.hit(hits, "locationd", k, "locationd/clients.plist")
    ctx.check("locationd", title, "ok", f"{len(data)} klientów usług lokalizacji")


def mod_shortcuts(ctx: Ctx, b: Backup) -> None:
    title = "Skróty (Shortcuts)"
    f = b.first("Library/Shortcuts/Shortcuts.sqlite")
    con = _sqlite(f[2]) if f else None
    if not con:
        ctx.check("shortcuts", title, "missing", "brak bazy skrótów w kopii")
        return
    urls = []
    for name, data in _rows(con, "SELECT s.ZNAME, a.ZDATA FROM ZSHORTCUT s JOIN ZSHORTCUTACTIONS a "
                                 "ON a.ZSHORTCUT = s.Z_PK"):
        if isinstance(data, (bytes, bytearray)):
            txt = bytes(data[:1 << 20]).decode("utf-8", "ignore")
            urls += [(u, f"skrót „{name}”") for u in extract_urls(txt)]
    n = _check_urls(ctx, urls, "shortcuts", "Shortcuts.sqlite")
    con.close()
    ctx.check("shortcuts", title, "ok", f"{n} adresów w skrótach")


PROFILE_DOMAIN = "SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles"
PAYLOAD_PL = {"com.apple.mdm": "zarządzanie urządzeniem (MDM)", "com.apple.security.root": "certyfikat główny (CA)",
              "com.apple.security.pem": "certyfikat", "com.apple.security.pkcs1": "certyfikat",
              "com.apple.security.pkcs12": "tożsamość (certyfikat + klucz)", "com.apple.vpn.managed": "VPN",
              "com.apple.proxy.http.global": "globalne proxy HTTP", "com.apple.dnsSettings.managed": "ustawienia DNS",
              "com.apple.webcontent-filter": "filtr treści WWW", "com.apple.wifi.managed": "sieć Wi‑Fi",
              "com.apple.app.lock": "blokada jednej aplikacji", "com.apple.applicationaccess": "ograniczenia",
              "com.apple.eas.account": "konto Exchange", "com.apple.mail.managed": "konto poczty"}


def mod_profiles(ctx: Ctx, b: Backup) -> None:
    title = "Profile konfiguracyjne, MDM i certyfikaty"
    files = b.like("%", PROFILE_DOMAIN) + [x for x in b.like("Library/ConfigurationProfiles/%")
                                           if x[0] != PROFILE_DOMAIN]
    if not files:
        ctx.check("profiles", title, "missing" if b.db is not None else "skipped",
                  "brak profili w kopii" if b.db is not None else "kopia zaszyfrowana")
        return
    count = 0
    for dom, rel, p in files:
        name = os.path.basename(rel)
        if name == "CloudConfigurationDetails.plist":
            d = _plist_file(p) or {}
            if isinstance(d, dict):
                ctx.posture["supervised"] = bool(d.get("IsSupervised"))
                if d.get("OrganizationName"):
                    ctx.posture["organization"] = str(d.get("OrganizationName"))[:120]
            continue
        if not (name.endswith(".stub") or name.startswith("profile-")):
            continue
        d = _plist_file(p)
        if not isinstance(d, dict):
            continue
        count += 1
        payloads = [x for x in (d.get("PayloadContent") or []) if isinstance(x, dict)]
        types = [str(x.get("PayloadType") or "") for x in payloads]
        prof = {"name": str(d.get("PayloadDisplayName") or name)[:160], "identifier": str(d.get("PayloadIdentifier") or ""),
                "uuid": str(d.get("PayloadUUID") or ""), "organization": str(d.get("PayloadOrganization") or "")[:160],
                "installed": _fmt_dt(d.get("InstallDate")), "types": types,
                "removal_disallowed": bool(d.get("PayloadRemovalDisallowed")), "file": rel}
        ctx.profiles.append(prof)
        ev = [f"{prof['name']} ({prof['identifier'] or prof['uuid']})" + (f", {prof['organization']}" if
                                                                           prof['organization'] else ""),
              "zawartość: " + (", ".join(PAYLOAD_PL.get(t, t) for t in types) or "—")
              + (f"; zainstalowany {prof['installed']}" if prof["installed"] else "")]
        for key in (prof["uuid"], prof["identifier"]):
            if key:
                ctx.hit(ctx.m.lookup("profile_id", key), "profiles", ev[0], rel)
        if prof["identifier"].startswith("com.apple."):
            continue                                         # Apple's own (e.g. beta software profile)
        sigs = []
        if "com.apple.mdm" in types:
            sigs.append(Signal("Heur:iOS.Profile.MDM", 25, Confidence.MEDIUM,
                               "Telefon jest zarządzany zdalnie (MDM): administrator może instalować aplikacje, profile "
                               "i certyfikaty oraz widzieć listę aplikacji. Normalne na telefonie służbowym – na "
                               "prywatnym to poważny sygnał.", ev))
        if "com.apple.security.root" in types:
            sigs.append(Signal("Heur:iOS.Profile.RootCA", 35, Confidence.MEDIUM,
                               "Profil instaluje własny certyfikat główny (CA). Po włączeniu zaufania pozwala odczytywać "
                               "szyfrowany ruch HTTPS (podsłuch).", ev))
        if any(t in types for t in ("com.apple.proxy.http.global", "com.apple.vpn.managed",
                                    "com.apple.dnsSettings.managed", "com.apple.webcontent-filter")):
            sigs.append(Signal("Heur:iOS.Profile.TrafficRedirect", 20, Confidence.MEDIUM,
                               "Profil kieruje ruch sieciowy przez VPN/proxy/DNS/filtr ustawiony przez kogoś innego.",
                               ev))
        if prof["removal_disallowed"] and sigs:
            sigs.append(Signal("Heur:iOS.Profile.NoRemoval", 10, Confidence.LOW,
                               "Profilu nie można usunąć zwykłym sposobem.", ev))
        if sigs:
            if ctx.posture.get("supervised") and "com.apple.mdm" in types:
                sigs = [s.scaled(0.6, "telefon nadzorowany przez organizację – zwykle służbowy") for s in sigs]
            root = any(s.name.endswith("RootCA") for s in sigs)
            ctx.finding("profile", f"Profil konfiguracyjny: {prof['name']}", rel, sigs,
                        ADVICE["profile"] + (ADVICE["rootca"] if root else []),
                        details={"profile": prof})
    ctx.posture["profiles"] = count
    ctx.posture["mdm"] = any("com.apple.mdm" in p["types"] for p in ctx.profiles)
    ctx.check("profiles", title, "ok", f"{count} profili")


def mod_prefs(ctx: Ctx, b: Backup) -> None:
    title = "Ustawienia bezpieczeństwa (Tryb blokady, kod)"
    f = b.first("Library/Preferences/.GlobalPreferences.plist")
    d = _plist_file(f[2]) if f else None
    if isinstance(d, dict):
        ctx.posture["lockdown_mode"] = bool(d.get("LDMGlobalEnabled"))
    pc = b.manifest.get("WasPasscodeSet")
    if pc is not None:
        ctx.posture["passcode_set"] = bool(pc)
        if not pc:
            ctx.finding("posture", "Telefon nie ma kodu blokady", "Manifest.plist",
                        [Signal("Posture:iOS.NoPasscode", 20, Confidence.MEDIUM,
                                "Bez kodu blokady każdy, kto weźmie telefon do ręki, może zainstalować aplikację "
                                "śledzącą albo profil.", ["WasPasscodeSet = false"])], ADVICE["passcode"])
    ctx.check("prefs", title, "ok" if isinstance(d, dict) or pc is not None else "missing",
              ("Tryb blokady: " + ("włączony" if ctx.posture.get("lockdown_mode") else "wyłączony"))
              if "lockdown_mode" in ctx.posture else "brak danych")


def _app_from_meta(ctx: Ctx, bid: str, meta) -> None:
    a = ctx.apps.setdefault(bid, {"bundle_id": bid})
    a.setdefault("seen", set()).add("Info.plist")
    md = _plist_bytes(meta.get("iTunesMetadata")) if isinstance(meta, dict) else None
    if isinstance(md, dict):
        a["name"] = a.get("name") or str(md.get("itemName") or md.get("bundleDisplayName") or "")[:120] or None
        a["vendor"] = str(md.get("artistName") or "")[:120] or None
        a["version"] = a.get("version") or md.get("bundleShortVersionString")
        src = str(md.get("sourceApp") or "com.apple.AppStore")
        a["store"] = src
        a["source"] = ("appstore" if src == "com.apple.AppStore" else "testflight" if "testflight" in src.lower()
                       else "other_store")
        dl = md.get("com.apple.iTunesStore.downloadInfo") or {}
        pd = (dl.get("purchaseDate") if isinstance(dl, dict) else None) or md.get("purchaseDate")
        a["installed"] = _fmt_dt(pd)


def mod_apps(ctx: Ctx, b: Backup | None) -> None:
    """Installed apps from the backup (Info.plist, Manifest.plist) and the device lists – indicators + heuristics."""
    title = "Zainstalowane aplikacje"
    if b is not None:
        for bid in b.info.get("Installed Applications") or []:
            a = ctx.apps.setdefault(str(bid), {"bundle_id": str(bid)})
            a.setdefault("seen", set()).add("Info.plist")
        for bid, meta in (b.info.get("Applications") or {}).items():
            _app_from_meta(ctx, str(bid), meta)
        for bid, meta in (b.manifest.get("Applications") or {}).items():
            a = ctx.apps.setdefault(str(bid), {"bundle_id": str(bid)})
            a.setdefault("seen", set()).add("Manifest.plist")
            if isinstance(meta, dict) and meta.get("CFBundleVersion"):
                a.setdefault("version", meta.get("CFBundleVersion"))
    if not ctx.apps:
        ctx.check("apps", title, "missing", "brak listy aplikacji")
        return
    backup_date = ctx.backup.get("date")
    plain: list[str] = []
    jb: list[str] = []
    for bid, a in sorted(ctx.apps.items()):
        low = bid.lower()
        if low.startswith("com.apple."):
            a.setdefault("source", "apple")
            continue
        name = a.get("name") or bid
        label = f"{name} ({bid})" if name != bid else bid
        hits = ctx.m.lookup("bundle_id", bid)
        if hits:
            ctx.hit(hits, "apps", label + (f", zainstalowana {a['installed']}" if a.get("installed") else ""),
                    "lista aplikacji")
            continue                                     # already a finding of its own (indicator)
        if low in JAILBREAK_APPS or JAILBREAK_WORDS.search(low):
            jb.append(f"{JAILBREAK_APPS.get(low, name)} ({bid})")
            continue
        src = a.get("source")
        if src == "appstore":
            continue
        sigs: list[Signal] = []
        if low in SIDELOAD_APPS:
            sigs.append(Signal("Heur:iOS.App.SideloadTool", 25, Confidence.MEDIUM,
                               f"{SIDELOAD_APPS[low]} – narzędzie do instalowania aplikacji spoza App Store.", [label]))
        elif src == "testflight":
            continue                                     # beta from TestFlight: reviewed by Apple, user-invited
        elif src == "other_store":
            sigs.append(Signal("Heur:iOS.App.AltMarketplace", 10, Confidence.LOW,
                               f"Aplikacja z alternatywnego sklepu ({a.get('store')}).", [label]))
        else:
            sigs.append(Signal("Heur:iOS.App.NotAppStore", 15, Confidence.LOW,
                               "Aplikacja nie pochodzi z App Store (firmowa, deweloperska lub zainstalowana obejściem).",
                               [label]))
        signer = a.get("signer") or ""
        if re.search(r"iPhone Distribution|Enterprise", signer, re.I):
            sigs.append(Signal("Heur:iOS.App.EnterpriseSigned", 20, Confidence.MEDIUM,
                               f"Podpisana certyfikatem firmowym ({signer[:80]}) – tak bywa rozpowszechniane "
                               f"oprogramowanie szpiegujące (np. Hermit) i stalkerware.", [label]))
        elif a.get("developer") or re.search(r"iPhone Developer|Apple Development", signer, re.I):
            sigs.append(Signal("Heur:iOS.App.DevSigned", 10, Confidence.LOW,
                               "Zainstalowana jako aplikacja deweloperska (Xcode/AltStore).", [label]))
        stalk = ctx.m.stalkerware_name(a.get("name"))
        if stalk or SPY_WORDS.search(f"{name} {bid}"):
            sigs.append(Signal("Heur:iOS.App.SpyName", 30, Confidence.MEDIUM,
                               f"Nazwa jak aplikacja śledząca{' (' + stalk + ')' if stalk else ''}.", [label]))
        perms = sorted(ctx.tcc.get(low, set()) | ({"lokalizacja"} if low in ctx.locations else set()))
        if perms:
            sigs.append(Signal("Heur:iOS.App.SensitivePerms", 15, Confidence.MEDIUM,
                               "Ma dostęp do: " + ", ".join(perms) + ".", [label]))
        age = _days_between(a.get("installed"), backup_date)
        if age is not None and age <= 30 and len(sigs) > 1:
            sigs.append(Signal("Heur:iOS.App.Recent", 10, Confidence.LOW,
                               f"Zainstalowana niedawno ({a.get('installed')}).", [label]))
        total = sum(s.score for s in sigs)
        if total >= 35:
            ctx.finding("app", f"Podejrzana aplikacja spoza App Store: {name}", bid, sigs,
                        ADVICE["stalkerware"] if any(s.name.endswith("SpyName") for s in sigs) else ADVICE["sideload"],
                        details={"app": {k: v for k, v in a.items() if k != "seen"}})
        else:
            plain.append(label + (f" – {', '.join(perms)}" if perms else ""))
    if jb:
        ctx.finding("jailbreak", "Narzędzia do jailbreaka na telefonie", "lista aplikacji",
                    [Signal("Heur:iOS.Jailbreak.Apps", 50, Confidence.MEDIUM,
                            "Zainstalowane są narzędzia do jailbreaka. Jailbreak wyłącza zabezpieczenia iOS i pozwala "
                            "ukryć oprogramowanie szpiegujące – jeśli to nie Ty, ktoś miał dostęp do telefonu.", jb)],
                    ADVICE["jailbreak"])
    if plain:
        ctx.finding("app", f"Aplikacje spoza App Store: {len(plain)}", "lista aplikacji",
                    [Signal("Heur:iOS.App.NotAppStore", 15, Confidence.LOW,
                            "Te aplikacje nie pochodzą z App Store (firmowe, testowe, deweloperskie). Na telefonie "
                            "służbowym to normalne – na prywatnym sprawdź, czy je rozpoznajesz.", plain)],
                    ADVICE["sideload"])
    store = sum(1 for a in ctx.apps.values() if a.get("source") == "appstore")
    ctx.posture["apps_total"] = len(ctx.apps)
    ctx.posture["apps_not_appstore"] = len(plain) + sum(1 for f in ctx.findings if f["category"] == "app"
                                                          and f["title"].startswith("Podejrzana"))
    ctx.check("apps", title, "ok", f"{len(ctx.apps)} aplikacji ({store} z App Store)")


def _days_between(a: str | None, b: str | None) -> float | None:
    try:
        da = _dt.datetime.strptime(a[:16], "%Y-%m-%d %H:%M")
        db = _dt.datetime.strptime(b[:16], "%Y-%m-%d %H:%M") if b else _dt.datetime.now()
    except (TypeError, ValueError):
        return None
    return abs((db - da).total_seconds()) / 86400


# ------------------------------------------------------------------ data read from the device (parent wrote it)

def mod_device(ctx: Ctx, d: str) -> None:
    """Files collected from the phone by the parent: info, app lists, provisioning profiles, crash reports."""
    info = _plist_file(os.path.join(d, "info.plist"))
    if isinstance(info, dict):
        pt = info.get("ProductType")
        ctx.device.update({k: v for k, v in {
            "name": info.get("DeviceName"), "product_type": pt, "model": PRODUCT_NAMES.get(pt or "", pt),
            "ios": info.get("ProductVersion"), "build": info.get("BuildVersion"),
            "udid": info.get("UniqueDeviceID")}.items() if v})
    try:
        with open(os.path.join(d, "devicectl_details.json"), encoding="utf-8") as fh:
            dd = (json.load(fh).get("result") or {})
        dp, hw = dd.get("deviceProperties") or {}, dd.get("hardwareProperties") or {}
        for k, v in (("name", dp.get("name")), ("ios", dp.get("osVersionNumber")), ("build", dp.get("osBuildUpdate")),
                     ("model", hw.get("marketingName")), ("product_type", hw.get("productType")),
                     ("udid", hw.get("udid"))):
            if v and not ctx.device.get(k):
                ctx.device[k] = v
        if dp.get("developerModeStatus"):
            ctx.posture["developer_mode"] = dp.get("developerModeStatus") == "enabled"
    except (OSError, ValueError, AttributeError):
        pass
    du = _plist_file(os.path.join(d, "disk_usage.plist"))
    if isinstance(du, dict) and du.get("TotalDataCapacity"):
        ctx.device["storage_total"] = du.get("TotalDataCapacity")
        ctx.device["storage_used"] = max(0, int(du.get("TotalDataCapacity") or 0) - int(du.get("TotalDataAvailable") or 0))
    # apps: ideviceinstaller (plist array, has SignerIdentity) and devicectl (JSON, builtByDeveloper)
    n_apps = 0
    raw = _plist_file(os.path.join(d, "apps_ideviceinstaller.plist"))
    for it in raw if isinstance(raw, list) else []:
        if not isinstance(it, dict) or not it.get("CFBundleIdentifier"):
            continue
        if str(it.get("ApplicationType") or "User") not in ("User", "Any"):
            continue
        bid = str(it["CFBundleIdentifier"])
        a = ctx.apps.setdefault(bid, {"bundle_id": bid})
        a.setdefault("seen", set()).add("telefon")
        a["name"] = a.get("name") or str(it.get("CFBundleDisplayName") or it.get("CFBundleName") or "")[:120] or None
        a["version"] = a.get("version") or it.get("CFBundleShortVersionString")
        signer = str(it.get("SignerIdentity") or "")
        a["signer"] = signer or None
        if signer and "source" not in a:
            a["source"] = "appstore" if signer == "Apple iPhone OS Application Signing" else "unknown"
        n_apps += 1
    try:
        with open(os.path.join(d, "apps_devicectl.json"), encoding="utf-8") as fh:
            apps = (json.load(fh).get("result") or {}).get("apps") or []
    except (OSError, ValueError, AttributeError):
        apps = []
    for it in apps:
        if not isinstance(it, dict) or not it.get("bundleIdentifier") or it.get("defaultApp") or it.get("internalApp"):
            continue
        bid = str(it["bundleIdentifier"])
        a = ctx.apps.setdefault(bid, {"bundle_id": bid})
        a.setdefault("seen", set()).add("telefon")
        a["name"] = a.get("name") or str(it.get("name") or "")[:120] or None
        a["version"] = a.get("version") or it.get("version")
        if it.get("builtByDeveloper"):
            a["developer"] = True
        n_apps += 1
    # provisioning profiles (enterprise / developer certificates trusted on the phone)
    try:
        with open(os.path.join(d, "provisioning.txt"), encoding="utf-8", errors="replace") as fh:
            prov = fh.read(200_000)
    except OSError:
        prov = ""
    ents = [ln.strip() for ln in prov.splitlines() if ln.strip() and not ln.lower().startswith(("device has", "error"))]
    if ents:
        ctx.posture["provisioning_profiles"] = len(ents)
        ctx.finding("app", f"Profile aprowizacji na telefonie: {len(ents)}", "ideviceprovision",
                    [Signal("Heur:iOS.ProvisioningProfiles", 12, Confidence.LOW,
                            "Na telefonie są profile pozwalające uruchamiać aplikacje spoza App Store (firmowe lub "
                            "deweloperskie). Sprawdź, czy rozpoznajesz wystawców.", ents[:30])], ADVICE["sideload"])
    crash_dir = os.path.join(d, "crashes")
    if os.path.isdir(crash_dir):
        mod_crashlogs(ctx, crash_dir)
    if n_apps:
        ctx.check("device_apps", "Aplikacje odczytane z telefonu", "ok", f"{n_apps} aplikacji")


IPS_PROC = re.compile(r'"(?:procName|app_name|name|procPath|bundleID|coalitionName)"\s*:\s*"([^"]{1,300})"')
OLD_PROC = re.compile(r"^(?:Process|Path|Identifier|Responsible Process):\s+(\S[^\[\n]{0,250})", re.M)


def mod_crashlogs(ctx: Ctx, crash_dir: str) -> None:
    title = "Raporty awarii z telefonu"
    n = 0
    names: set[str] = set()
    for root, _dirs, files in os.walk(crash_dir):
        for fn in files:
            if n >= MAX_CRASH_FILES:
                break
            p = os.path.join(root, fn)
            if os.path.islink(p):
                continue
            n += 1
            try:
                with open(p, "rb") as fh:
                    head = fh.read(256 << 10).decode("utf-8", "replace")
            except OSError:
                continue
            vals = set(IPS_PROC.findall(head)) | {v.strip() for v in OLD_PROC.findall(head)}
            base = fn.split("-")[0].split(".")[0]
            if base:
                vals.add(base)
            for v in vals:
                rel = os.path.relpath(p, crash_dir)
                hits = []
                if "/" in v:
                    hits += ctx.m.path(v) + ctx.m.process(os.path.basename(v))
                elif re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+){2,}", v):
                    hits += ctx.m.lookup("bundle_id", v) + ctx.m.process(v)
                else:
                    hits += ctx.m.process(v)
                if hits:
                    ctx.hit(hits, "crash", f"{v} (raport {rel})", "raporty awarii")
                names.add(v)
    ctx.stats["crash_reports"] = n
    ctx.check("crash", title, "ok" if n else "missing", f"{n} raportów, {len(names)} nazw procesów"
              if n else "brak raportów")


# ------------------------------------------------------------------ whole analysis

def analyze(backup_path: str | None, device_dir: str | None, matcher: Matcher | None = None,
            emit: Emit | None = None, device: dict | None = None) -> dict:
    """Analyse a backup and/or data collected from the device. Pure function of its inputs (tests call it directly)."""
    m = matcher or Matcher()
    try:
        return _analyze(m, backup_path, device_dir, emit, device)
    finally:
        if matcher is None:
            m.close()


def _analyze(m: Matcher, backup_path: str | None, device_dir: str | None, emit: Emit | None,
             device: dict | None) -> dict:
    ctx = Ctx(m, emit)
    ctx.device.update({k: v for k, v in (device or {}).items() if v})
    if not m.available:
        ctx.limitations.append("Brak bazy wskaźników iOS (db/compiled/ios_ioc.sqlite) – sprawdzono tylko heurystyki. "
                               "Zbuduj ją poleceniem: ./cerber.sh update --only-ios")
    b = Backup(backup_path) if backup_path else None
    steps = [("Dane z telefonu", lambda: mod_device(ctx, device_dir))] if device_dir and os.path.isdir(device_dir) else []
    if b is not None:
        if not b.valid:
            ctx.limitations.append(f"To nie wygląda na kopię zapasową iPhone'a (brak Info.plist/Manifest): {backup_path}")
            b = None
    if b is not None:
        meta = b.meta()
        ctx.backup = meta
        for k in ("name", "model", "ios", "udid", "product_type"):
            src = {"name": "device_name"}.get(k, k)
            if meta.get(src) and not ctx.device.get(k):
                ctx.device[k] = meta[src]
        age = _days_ago(meta.get("date"))
        if age is not None and age > 14:
            ctx.limitations.append(f"Kopia zapasowa ma {int(age)} dni – nowsze zdarzenia nie są w niej widoczne. "
                                   "Zrób świeżą kopię, aby sprawdzić bieżący stan.")
        if b.encrypted:
            ctx.limitations.append(
                "Kopia jest zaszyfrowana hasłem – Cerber jej nie odszyfrowuje (wymagałoby to hasła i dodatkowej "
                "biblioteki). Sprawdzono tylko listę aplikacji i dane urządzenia. Aby sprawdzić wiadomości, historię "
                "Safari, profile i statystyki sieci: zrób kopię bez szyfrowania (Finder → iPhone → odznacz „Szyfruj "
                "lokalną kopię zapasową”, potrzebne jest jej obecne hasło) albo odszyfruj ją narzędziem MVT "
                "(mvt-ios decrypt-backup) i wskaż Cerberowi odszyfrowany folder.")
        if meta.get("complete") is False:
            ctx.limitations.append("Kopia nie została dokończona (przerwana) – część plików może być niedostępna.")
        steps += [("Lista plików kopii", lambda: mod_manifest(ctx, b)),
                  ("Uprawnienia i lokalizacja", lambda: (mod_tcc(ctx, b), mod_locationd(ctx, b))),
                  ("Wiadomości SMS/iMessage", lambda: mod_sms(ctx, b)),
                  ("Historia Safari", lambda: mod_safari(ctx, b)),
                  ("Inne przeglądarki", lambda: mod_browsers(ctx, b)),
                  ("Dane stron WWW", lambda: mod_webkit(ctx, b)),
                  ("WhatsApp", lambda: mod_whatsapp(ctx, b)),
                  ("Procesy w sieci (DataUsage)", lambda: mod_datausage(ctx, b)),
                  ("Statystyki OSAnalytics", lambda: mod_osanalytics(ctx, b)),
                  ("Konta iMessage i interakcje", lambda: mod_identities(ctx, b)),
                  ("Skróty", lambda: mod_shortcuts(ctx, b)),
                  ("Profile i MDM", lambda: mod_profiles(ctx, b)),
                  ("Ustawienia bezpieczeństwa", lambda: mod_prefs(ctx, b))]
    steps.append(("Aplikacje", lambda: mod_apps(ctx, b)))
    ctx.steps_total = len(steps)
    for title, fn in steps:
        ctx.step(title)
        try:
            fn()
        except KeyboardInterrupt:
            raise
        except Exception as exc:  # noqa: BLE001 - one broken artefact must not stop the rest
            ctx.check(title.lower().replace(" ", "_"), title, "error", f"{type(exc).__name__}: {exc}"[:200])
        ctx.flush()
    ios = str(ctx.device.get("ios") or "")
    ctx.posture["ios"] = ios or None
    major = int(ios.split(".")[0]) if ios.split(".")[0].isdigit() else None
    if major is not None and major < 18:
        ctx.finding("posture", f"Stara wersja iOS ({ios})", "iOS",
                    [Signal("Posture:iOS.Outdated", 15, Confidence.MEDIUM,
                            "Ta wersja iOS nie dostaje już wszystkich poprawek bezpieczeństwa – znane luki (także "
                            "używane przez oprogramowanie szpiegujące) mogą być niezałatane.", [f"iOS {ios}"])],
                    ADVICE["update"])
    if b is not None:
        ctx.posture["backup_encrypted"] = b.encrypted
        if b.db is not None:
            b.db.close()
    if m.mac is None:
        ctx.limitations.append("Brak ogólnej listy złośliwych adresów (ioc.sqlite) – linki sprawdzono tylko "
                               "wskaźnikami iOS.")
    return ctx.result()


def advice_for(findings: list[dict], posture: dict) -> list[str]:
    """Overall 'what to do next' – most serious first, deduplicated."""
    out: list[str] = []
    cats = {f["category"] for f in findings if SEVERITY_ORDER.get(f["severity"], 0) >= 2}
    for f in sorted(findings, key=lambda f: -SEVERITY_ORDER.get(f["severity"], 0)):
        if SEVERITY_ORDER.get(f["severity"], 0) >= 1:
            for a in f.get("advice") or []:
                if a not in out:
                    out.append(a)
    if "spyware" not in cats:
        out += [a for a in ADVICE["update"] if a not in out]
        if posture.get("lockdown_mode") is False:
            out.append("Jeśli obawiasz się ataku (dziennikarz, aktywista, polityk, prawnik): włącz Tryb blokady "
                       "(Ustawienia → Prywatność i ochrona → Tryb blokady).")
    return out[:14]


# ================================================================== inner (sandbox) entry point

def inner_iphone(a) -> int:
    """`python -m cerber.sandbox inner-iphone --work W --job J` – runs under the read-only `scan` profile."""
    from .sandbox import _Emitter, harden
    emit = _Emitter()
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    verified = harden("scan", a.work, emit)
    with open(a.job) as fh:
        job = json.load(fh)
    try:
        if job.get("mode") == "list":
            data = {"backups": [backup_meta(p, src) for p, src in job.get("backups") or []]}
        else:
            data = analyze(job.get("backup"), job.get("device_dir"), emit=emit, device=job.get("device"))
    except KeyboardInterrupt:
        data = {"cancelled": True, "findings": [], "checks": [], "limitations": ["przerwano"]}
    data["verified"] = verified
    with open(os.path.join(a.work, "out", "iphone.json"), "w") as fh:
        json.dump(data, fh, ensure_ascii=False, default=str)
    emit({"ev": "inner_done"})
    sys.stdout.flush()
    os._exit(0)


# ================================================================== parent side: device access (fixed argv)

def _child_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "CERBER_"))}
    env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    env["LANG"] = "en_US.UTF-8"
    return env


def _run(argv: list[str], timeout: float = 60) -> tuple[int, bytes, str]:
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, env=_child_env())
        return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -2, b"", "przekroczono limit czasu"
    except OSError as exc:
        return -1, b"", str(exc)


def find_tools() -> dict:
    found: dict[str, str] = {}
    for name in LIBIMD:
        for d in TOOL_DIRS:
            p = os.path.join(d, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                found[name] = p
                break
    cands = []
    rc, out, _ = _run(["/usr/bin/xcode-select", "-p"], timeout=5)
    if rc == 0 and out.strip():
        cands.append(os.path.join(out.decode("utf-8", "replace").strip(), "usr/bin/devicectl"))
    for c in cands + DEVICECTL:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            found["devicectl"] = c
            break
    if os.access(APPLE_BACKUP, os.X_OK):
        found["apple_backup"] = APPLE_BACKUP
    return found


def _devicectl_json(tool: str, args: list[str], timeout: float = 60) -> dict | None:
    fd, path = tempfile.mkstemp(prefix="cerber-devicectl-", suffix=".json")
    os.close(fd)
    try:
        _run([tool] + args + ["-q", "-t", str(int(timeout)), "-j", path], timeout=timeout + 15)
        if os.path.getsize(path) == 0 or os.path.getsize(path) > (32 << 20):
            return None
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _plist_out(out: bytes) -> dict | None:
    if not out or len(out) > (4 << 20):
        return None
    try:
        d = plistlib.loads(out)
        return d if isinstance(d, dict) else None
    except Exception:  # noqa: BLE001
        return None


def _usb_iphones() -> list[tuple[str | None, str]]:
    """(udid or None, name) of iPhones/iPads on USB according to system_profiler (no extra tools needed)."""
    found = []

    def walk(o) -> None:
        if isinstance(o, dict):
            name = str(o.get("_name") or o.get("USBDeviceKeyProductName") or "")
            if re.search(r"\biP(hone|ad)\b", name):
                serial = next((str(v) for k, v in o.items() if "serial" in k.lower() and isinstance(v, str)), "")
                s = serial.replace("-", "").strip()
                udid = (s[:8] + "-" + s[8:]) if re.fullmatch(r"[0-9A-Fa-f]{24}", s) else s if \
                    re.fullmatch(r"[0-9A-Fa-f]{40}", s) else None
                found.append((udid, name))
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    for dtype in ("SPUSBHostDataType", "SPUSBDataType"):
        rc, out, _ = _run(["/usr/sbin/system_profiler", "-json", dtype], timeout=40)
        if rc == 0 and out:
            try:
                walk(json.loads(out))
            except ValueError:
                pass
    return found


def list_devices(tools: dict) -> tuple[list[dict], list[str]]:
    devs: dict[str, dict] = {}
    notes: list[str] = []

    def put(udid: str, **kw) -> dict:
        d = devs.setdefault(_norm_udid(udid), {"udid": udid, "name": None, "model": None, "product_type": None,
                                               "ios": None, "state": "offline", "trusted": None, "sources": []})
        for k, v in kw.items():
            if k == "source":
                if v not in d["sources"]:
                    d["sources"].append(v)
            elif k == "state":
                if STATE_RANK.get(v, 0) > STATE_RANK.get(d["state"], 0):
                    d["state"] = v
            elif v is not None and d.get(k) in (None, ""):
                d[k] = v
        return d

    if "idevice_id" in tools:
        for flag, state in (("-l", "usb"), ("-n", "wifi")):
            rc, out, _ = _run([tools["idevice_id"], flag], timeout=15)
            for line in out.decode("utf-8", "replace").splitlines():
                u = line.split()[0] if line.split() else ""
                if valid_udid(u):
                    put(u, state=state, source="libimobiledevice")
        for d in list(devs.values()):
            if "ideviceinfo" not in tools:
                break
            rc, out, err = _run([tools["ideviceinfo"], "-u", d["udid"], "-x"], timeout=20)
            info = _plist_out(out) if rc == 0 else None
            if info:
                pt = info.get("ProductType")
                put(d["udid"], name=info.get("DeviceName"), product_type=pt, model=PRODUCT_NAMES.get(pt or "", pt),
                    ios=info.get("ProductVersion"), trusted=True)
            else:
                d["trusted"] = False
                d["error"] = (err.strip().splitlines() or [""])[-1][:200]
    if "devicectl" in tools:
        data = _devicectl_json(tools["devicectl"], ["list", "devices"], timeout=40) or {}
        for dv in (data.get("result") or {}).get("devices") or []:
            hw, dp, cp = (dv.get("hardwareProperties") or {}, dv.get("deviceProperties") or {},
                          dv.get("connectionProperties") or {})
            if hw.get("deviceType") not in ("iPhone", "iPad") and str(hw.get("platform") or "").lower() != "ios":
                continue
            udid = hw.get("udid") or dv.get("identifier")
            if not valid_udid(udid):
                continue
            state = "usb" if cp.get("transportType") == "wired" else \
                "wifi" if cp.get("tunnelState") == "connected" else "offline"
            put(udid, name=dp.get("name"), model=hw.get("marketingName"), product_type=hw.get("productType"),
                ios=dp.get("osVersionNumber"), state=state, source="devicectl",
                paired=cp.get("pairingState") == "paired", last_seen=_fmt_dt(cp.get("lastConnectionDate")),
                coredevice_id=dv.get("identifier"))
    for udid, name in _usb_iphones():
        if udid:
            put(udid, name=None, model=name, state="usb", source="usb")
        elif not any(d["state"] == "usb" for d in devs.values()):
            put("usb-" + re.sub(r"\W", "", name).lower(), model=name, state="usb", source="usb")
    for d in devs.values():
        if d["state"] == "usb" and d["sources"] == ["usb"]:
            d["trusted"] = None
    out = sorted(devs.values(), key=lambda d: (-STATE_RANK.get(d["state"], 0), d.get("name") or ""))
    if any(d["state"] == "usb" and d.get("trusted") is False for d in out):
        notes.append("Odblokuj iPhone'a i stuknij „Zaufaj” (lub „Ufaj”), a potem odśwież listę – bez tego telefon nie "
                     "udostępnia żadnych danych.")
    return out, notes


def mobilesync_access() -> str:
    """ok | denied (no Full Disk Access) | missing (no Finder backups on this Mac)."""
    if not os.path.isdir(MOBILESYNC):
        return "missing" if os.path.isdir(os.path.dirname(MOBILESYNC)) or not os.path.exists(
            os.path.dirname(os.path.dirname(MOBILESYNC))) else "denied"
    try:
        os.listdir(MOBILESYNC)
        return "ok"
    except PermissionError:
        return "denied"
    except OSError:
        return "missing"


def backup_candidates(access: str) -> list[tuple[str, str]]:
    out = []
    roots = [(BACKUP_DIR, "cerber")] + ([(MOBILESYNC, "finder")] if access == "ok" else [])
    for root, src in roots:
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for n in names:
            p = os.path.join(root, n)
            if os.path.isdir(p) and not os.path.islink(p) and any(
                    os.path.exists(os.path.join(p, f)) for f in ("Manifest.plist", "Manifest.db", "Info.plist")):
                out.append((p, src))
    return out


def tool_notes(tools: dict, access: str, has_backups: bool) -> list[str]:
    notes = []
    if not any(t in tools for t in ("idevice_id", "devicectl")):
        notes.append("Brak narzędzi do odczytu iPhone'a przez kabel (libimobiledevice ani Xcode). Cerber widzi "
                     "podłączony telefon, ale nie odczyta z niego listy aplikacji ani raportów awarii. Możesz je "
                     "zainstalować samodzielnie: brew install libimobiledevice ideviceinstaller (Cerber niczego nie "
                     "instaluje). Kopie zapasowe z Findera i tak zostaną przeanalizowane.")
    elif "idevice_id" not in tools:
        notes.append("Używam narzędzi Apple z Xcode (devicectl) do odczytu aplikacji i raportów awarii. Dokładniejszy "
                     "odczyt (podpisy aplikacji, profile aprowizacji) daje libimobiledevice: brew install "
                     "libimobiledevice ideviceinstaller.")
    if access == "denied":
        notes.append("Cerber nie ma dostępu do kopii zapasowych z Findera (~/Library/Application Support/MobileSync/"
                     "Backup). Nadaj mu „Pełny dostęp do dysku”: Ustawienia systemowe → Prywatność i ochrona → Pełny "
                     "dostęp do dysku → włącz Cerber (albo Terminal, jeśli uruchamiasz Cerbera z terminala), potem "
                     "uruchom Cerbera ponownie.")
    if not has_backups and access != "denied":
        notes.append("Nie znaleziono kopii zapasowej iPhone'a. Zrób ją w Finderze: podłącz iPhone'a kablem → Finder → "
                     "iPhone → „Utwórz kopię zapasową teraz”, najlepiej BEZ szyfrowania (zaszyfrowanej kopii Cerber "
                     "nie przeanalizuje w całości). Możesz też wskazać folder z kopią przyciskiem „Wybierz kopię…”.")
    return notes


def backup_tool(tools: dict) -> str | None:
    return "idevicebackup2" if "idevicebackup2" in tools else "apple" if "apple_backup" in tools else None


def collect_device(udid: str, tools: dict, dest: str, emit: Emit, cancel: threading.Event) -> dict:
    """Read what the phone reports (read-only operations only) into `dest`; returns a short status."""
    os.makedirs(dest, mode=0o700, exist_ok=True)
    got: dict = {"udid": udid, "collected": [], "missing": []}
    steps = []
    if "ideviceinfo" in tools:
        steps.append(("informacje o urządzeniu", [tools["ideviceinfo"], "-u", udid, "-x"], "info.plist", 30))
        steps.append(("zajętość pamięci", [tools["ideviceinfo"], "-u", udid, "-q", "com.apple.disk_usage", "-x"],
                      "disk_usage.plist", 30))
    if "ideviceinstaller" in tools:
        steps.append(("lista aplikacji", [tools["ideviceinstaller"], "-u", udid, "-l", "-o", "xml", "-o", "list_user"],
                      "apps_ideviceinstaller.plist", 120))
    if "ideviceprovision" in tools:
        steps.append(("profile aprowizacji", [tools["ideviceprovision"], "-u", udid, "list"], "provisioning.txt", 60))
    total = len(steps) + 1 + (2 if "devicectl" in tools else 0)
    done = 0

    def prog(cur: str) -> None:
        emit({"ev": "progress", "stage": "device", "done": done, "total": total, "current": cur})
    for label, argv, fname, tmo in steps:
        if cancel.is_set():
            return got
        prog(label)
        rc, out, err = _run(argv, timeout=tmo)
        if fname == "apps_ideviceinstaller.plist" and (rc != 0 or not out.lstrip().startswith(b"<")):
            rc, out, err = _run([tools["ideviceinstaller"], "-u", udid, "list", "--user", "--xml"], timeout=tmo)
        if rc == 0 and out and len(out) < (64 << 20):
            with open(os.path.join(dest, fname), "wb") as fh:
                fh.write(out)
            got["collected"].append(label)
        else:
            got["missing"].append(f"{label}: {(err.strip().splitlines() or ['błąd'])[-1][:160]}")
        done += 1
    dc_ok = "devicectl" in tools
    if dc_ok and not cancel.is_set():
        for label, args, fname in (("szczegóły urządzenia (Xcode)", ["device", "info", "details", "--device", udid],
                                    "devicectl_details.json"),
                                   ("lista aplikacji (Xcode)", ["device", "info", "apps", "--device", udid,
                                                                "--include-all-apps"], "apps_devicectl.json")):
            prog(label)
            data = _devicectl_json(tools["devicectl"], args, timeout=45) if dc_ok else None
            if data and (data.get("info") or {}).get("outcome") == "success":
                with open(os.path.join(dest, fname), "w", encoding="utf-8") as fh:
                    json.dump(data, fh)
                got["collected"].append(label)
            else:
                if dc_ok:
                    got["missing"].append(f"{label}: telefon niedostępny dla Xcode (podłącz go, odblokuj i zaufaj "
                                          f"temu Macowi)")
                dc_ok = False               # an unreachable device makes every devicectl call wait for its timeout
            done += 1
    # crash reports: copied, never deleted from the phone (--keep)
    prog("raporty awarii")
    crash = os.path.join(dest, "crashes")
    os.makedirs(crash, mode=0o700, exist_ok=True)
    ok = False
    if "idevicecrashreport" in tools and not cancel.is_set():
        rc, _out, err = _run([tools["idevicecrashreport"], "-u", udid, "-k", "-e", crash], timeout=900)
        ok = rc == 0
    if not ok and dc_ok and not cancel.is_set():
        rc, _out, err = _run([tools["devicectl"], "device", "copy", "from", "--device", udid, "--domain-type",
                              "systemCrashLogs", "--source", "/", "--destination", crash, "-q", "-t", "600"],
                             timeout=630)
        ok = rc == 0
    n = sum(len(f) for _r, _d, f in os.walk(crash))
    if ok or n:
        got["collected"].append(f"raporty awarii ({n})")
    else:
        got["missing"].append("raporty awarii: brak narzędzia lub telefon niedostępny")
    done += 1
    prog("gotowe")
    return got


def _dir_size(path: str, cap_files: int = 400_000) -> int:
    total = n = 0
    for root, _d, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
            n += 1
            if n > cap_files:
                return total
    return total


def create_backup(udid: str, tools: dict, emit: Emit, cancel: threading.Event,
                  storage_used: int | None = None) -> tuple[str | None, str | None]:
    """Make a fresh backup (explicit user action only). Returns (backup dir, error)."""
    if not valid_udid(udid):
        return None, "Nieprawidłowy identyfikator urządzenia."
    if "idevicebackup2" in tools:
        dest = BACKUP_DIR
        os.makedirs(dest, mode=0o700, exist_ok=True)
        argv = [tools["idevicebackup2"], "-u", udid, "backup", "--full", dest]
    elif "apple_backup" in tools:
        dest = MOBILESYNC
        argv = [tools["apple_backup"], "-b", "-t", udid]
    else:
        return None, ("Brak narzędzia do tworzenia kopii. Zrób kopię w Finderze (iPhone → „Utwórz kopię zapasową "
                      "teraz”) i wybierz ją w Cerberze, albo zainstaluj libimobiledevice (brew install libimobiledevice).")
    probe = dest if os.path.isdir(dest) else os.path.expanduser("~")
    free = shutil.disk_usage(probe).free
    if storage_used and free < storage_used + (2 << 30):
        return None, (f"Za mało wolnego miejsca: kopia może zająć do {storage_used / 1e9:.0f} GB, a na dysku jest "
                      f"{free / 1e9:.0f} GB wolnego.")
    if free < (3 << 30):
        return None, f"Za mało wolnego miejsca na dysku ({free / 1e9:.1f} GB)."
    emit({"ev": "log", "msg": f"Tworzenie kopii zapasowej do {dest} – na telefonie może pojawić się prośba o kod "
                              f"blokady; nie odłączaj kabla."})
    target = os.path.join(dest, udid)
    before = _dir_size(target) if os.path.isdir(target) else 0
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env=_child_env(), start_new_session=True)
    state = {"pct": 0.0, "last": "", "t": 0.0, "lines": 0}

    def reader() -> None:
        buf = b""
        while True:
            ch = proc.stdout.read(512)
            if not ch:
                break
            buf += ch
            parts = re.split(rb"[\r\n]", buf)
            buf = parts.pop()
            for raw in parts:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                m = re.findall(r"(\d{1,3}(?:\.\d+)?)\s?%", line)
                if m:
                    state["pct"] = max(state["pct"], min(100.0, float(m[-1])))
                else:
                    state["last"] = line[:200]
                    if state["lines"] < 200:
                        state["lines"] += 1
                        emit({"ev": "log", "msg": f"kopia: {line[:300]}"})
    t = threading.Thread(target=reader, daemon=True)
    t.start()
    t0 = time.time()
    while proc.poll() is None:
        if cancel.is_set():
            try:
                os.killpg(proc.pid, signal.SIGINT)
                proc.wait(timeout=20)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
            return None, "przerwano"
        if time.time() - state["t"] > 2:
            state["t"] = time.time()
            size = _dir_size(target, 200_000) if os.path.isdir(target) else 0
            emit({"ev": "progress", "stage": "backup", "done": int(state["pct"]), "total": 100,
                  "bytes": max(0, size - before) if size else 0, "elapsed_s": int(time.time() - t0),
                  "current": state["last"] or None})
        time.sleep(0.5)
    t.join(timeout=5)
    if proc.returncode != 0:
        return None, f"Tworzenie kopii nie powiodło się (kod {proc.returncode}): {state['last'] or 'brak szczegółów'}"
    emit({"ev": "progress", "stage": "backup", "done": 100, "total": 100})
    for cand in (target, os.path.join(dest, udid.replace("-", ""))):
        if os.path.isdir(cand):
            return cand, None
    if dest == MOBILESYNC and mobilesync_access() == "denied":
        return None, ("Kopia została utworzona w Finderze, ale Cerber nie ma do niej dostępu – nadaj mu „Pełny dostęp "
                      "do dysku” (Ustawienia systemowe → Prywatność i ochrona) i uruchom skan ponownie.")
    return None, "Kopia zakończona, ale nie znaleziono jej folderu."


# ================================================================== sandbox orchestration + app protocol

def _sandbox_off() -> bool:
    return os.environ.get("CERBER_NO_SANDBOX") == "1"


def _in_sandbox(job: dict, emit: Emit, cancel: threading.Event, light: bool) -> dict | None:
    """Run the analysis (or backup listing) in the sandbox. light=True: plain private dir instead of a noexec volume
    (the volume takes ~20 s to set up – too slow for refreshing a device list; Seatbelt still applies)."""
    if _sandbox_off():
        if job.get("mode") == "list":
            return {"backups": [backup_meta(p, s) for p, s in job.get("backups") or []], "verified": []}
        return analyze(job.get("backup"), job.get("device_dir"), emit=emit, device=job.get("device"))
    from .sandbox import new_workspace, remove_workspace, run_inner
    work = job.pop("_work", None)
    own = work is None
    if own:
        old = os.environ.get("CERBER_NO_NOEXEC")
        if light:
            os.environ["CERBER_NO_NOEXEC"] = "1"
        try:
            work = new_workspace()
        finally:
            if light:
                if old is None:
                    os.environ.pop("CERBER_NO_NOEXEC", None)
                else:
                    os.environ["CERBER_NO_NOEXEC"] = old
    try:
        jp = os.path.join(work, "in", "job.json")
        with open(jp, "w") as fh:
            json.dump(job, fh)

        def relay(ev: dict) -> None:
            if ev.get("ev") in ("inner_done",):
                return
            if light and ev.get("ev") == "log":
                return
            emit(ev)
        return run_inner(work, "scan", ["inner-iphone", "--work", work, "--job", jp], relay, cancel,
                         out_name="iphone.json", wall=6 * 3600)
    finally:
        if own:
            remove_workspace(work)


def devices_event(emit: Emit, cancel: threading.Event | None = None) -> dict:
    tools = find_tools()
    devices, notes = list_devices(tools)
    access = mobilesync_access()
    cands = backup_candidates(access)
    backups: list[dict] = []
    if cands:
        data = _in_sandbox({"mode": "list", "backups": cands}, emit, cancel or threading.Event(), light=True)
        backups = sorted((data or {}).get("backups") or [], key=lambda b: b.get("date") or "", reverse=True)
    for d in devices:
        mine = [b for b in backups if _norm_udid(b.get("udid") or "") == _norm_udid(d["udid"])]
        d["backup"] = mine[0] if mine else None
    tool = backup_tool(tools)
    target = BACKUP_DIR if tool == "idevicebackup2" else MOBILESYNC
    probe = target if os.path.isdir(target) else os.path.expanduser("~")
    try:
        free = shutil.disk_usage(probe).free
    except OSError:
        free = None
    mt = Matcher(mac_path="")
    stats = mt.stats()
    mt.close()
    ev = {"ev": "iphone_devices", "devices": devices, "backups": backups,
          "tools": {"libimobiledevice": "idevice_id" in tools, "devicectl": "devicectl" in tools,
                    "apple_backup": "apple_backup" in tools, "paths": tools},
          "access": {"mobilesync": access, "mobilesync_path": MOBILESYNC, "backup_dir": BACKUP_DIR},
          "can_backup": tool, "backup_target": {"dir": target, "free_bytes": free},
          "indicators": {"total": stats.get("total", 0), "built": stats.get("built"),
                         "sources": [{"name": s.get("name"), "license": s.get("license"), "url": s.get("url")}
                                     for s in stats.get("sources") or []]},
          "notes": notes + tool_notes(tools, access, bool(backups))}
    emit(ev)
    return ev


def _write_report(summary: dict, base: str) -> tuple[str | None, str | None]:
    os.makedirs(os.path.dirname(base), exist_ok=True)
    jp = base + ".json"
    with open(jp, "w") as fh:
        json.dump(summary, fh, indent=1, ensure_ascii=False, default=str)
    hp = write_html(summary, base + ".html")
    return hp, jp


def scan(emit: Emit, udid: str | None = None, backup: str | None = None, make_backup: bool = False,
         cancel: threading.Event | None = None) -> int:
    cancel = cancel or threading.Event()
    t0, started = time.time(), _now()
    tools = find_tools()
    if udid and not valid_udid(udid):
        emit({"ev": "error", "fatal": True, "msg": f"Nieprawidłowy identyfikator urządzenia: {udid[:60]}"})
        return 1
    if backup:
        backup = os.path.realpath(os.path.expanduser(backup))
        if not os.path.isdir(backup):
            emit({"ev": "error", "fatal": True, "msg": f"To nie jest folder kopii zapasowej: {backup}"})
            return 1
        if not any(os.path.exists(os.path.join(backup, f)) for f in ("Manifest.plist", "Manifest.db", "Info.plist")):
            subs = [os.path.join(backup, n) for n in sorted(os.listdir(backup))
                    if os.path.isfile(os.path.join(backup, n, "Manifest.plist"))]
            if len(subs) == 1:
                backup = subs[0]                      # the user picked the folder above <UDID>
            else:
                emit({"ev": "error", "fatal": True, "msg": "W tym folderze nie ma kopii zapasowej iPhone'a "
                                                           "(brak Manifest.plist / Info.plist)."})
                return 1
    from .sandbox import cleanup_stale, new_workspace, remove_workspace
    if not _sandbox_off():
        cleanup_stale()
    work = new_workspace() if not _sandbox_off() else tempfile.mkdtemp(prefix="cerber-iphone-")
    notes: list[str] = []
    device_status = None
    try:
        dev_dir = None
        if udid:
            emit({"ev": "stage", "id": "device", "title": "Odczyt informacji z iPhone'a…"})
            dev_dir = os.path.join(work, "in", "device")
            device_status = collect_device(udid, tools, dev_dir, emit, cancel)
            notes += [f"Nie odczytano: {m}" for m in device_status["missing"]]
        if make_backup and udid and not cancel.is_set():
            emit({"ev": "stage", "id": "backup", "title": "Tworzenie kopii zapasowej iPhone'a…"})
            used = None
            du = _plist_file(os.path.join(dev_dir or "", "disk_usage.plist")) if dev_dir else None
            if isinstance(du, dict) and du.get("TotalDataCapacity"):
                used = int(du["TotalDataCapacity"]) - int(du.get("TotalDataAvailable") or 0)
            path, err = create_backup(udid, tools, emit, cancel, used)
            if err and not cancel.is_set():
                emit({"ev": "error", "fatal": False, "msg": err})
                notes.append(err)
            backup = path or backup
        if not backup and udid:
            access = mobilesync_access()
            mine = [p for p, _s in backup_candidates(access) if _norm_udid(os.path.basename(p)) == _norm_udid(udid)]
            mine.sort(key=lambda p: max((os.path.getmtime(os.path.join(p, f)) for f in ("Manifest.db", "Status.plist",
                                                                                         "Info.plist")
                                         if os.path.exists(os.path.join(p, f))), default=0), reverse=True)
            if mine:
                backup = mine[0]
            else:
                notes.append("Nie znaleziono kopii zapasowej tego iPhone'a – sprawdzono tylko dane odczytane z "
                             "telefonu (wiadomości, Safari, profile i statystyki sieci są tylko w kopii).")
                if access == "denied":
                    notes.append(tool_notes(tools, access, True)[-1])
        if not backup and not dev_dir:
            emit({"ev": "error", "fatal": True, "msg": "Nie ma czego sprawdzić: nie podłączono iPhone'a i nie wskazano "
                                                       "kopii zapasowej."})
            return 1
        if cancel.is_set():
            data = None
        else:
            emit({"ev": "stage", "id": "sandbox", "title": "Uruchamianie izolowanego sandboksa…"})
            emit({"ev": "stage", "id": "analyze", "title": "Analiza kopii zapasowej i danych z telefonu…"})
            job = {"mode": "analyze", "backup": backup, "device_dir": dev_dir,
                   "device": {"udid": udid} if udid else {}, "_work": work}
            data = _in_sandbox(job, emit, cancel, light=False)
        cancelled = cancel.is_set()
        if data is None and not cancelled:
            return 1
        data = data or {"findings": [], "checks": [], "limitations": []}
        emit({"ev": "stage", "id": "report", "title": "Zapisywanie raportu…"})
        findings = data.get("findings") or []
        worst = max((SEVERITY_ORDER.get(f["severity"], 0) for f in findings), default=0)
        sev = next((k for k, v in SEVERITY_ORDER.items() if v == worst), "info")
        verdict = ENV_TO_VERDICT.get(sev, "CLEAN") if findings else "CLEAN"
        dev = data.get("device") or {}
        title = dev.get("name") or dev.get("model") or (os.path.basename(backup) if backup else "iPhone")
        from .sandbox import ISOLATION
        bk = data.get("backup") or {}
        coverage = ("full" if bk and not bk.get("encrypted") else
                    "partial" if bk or data.get("apps_total") else "none")
        summary = {
            "mode": "iphone", "title": title, "started": started, "finished": _now(),
            "seconds": round(time.time() - t0, 1), "cancelled": cancelled, "verdict": verdict,
            "counts": {k: sum(1 for f in findings if f["severity"] == k) for k in SEVERITY_ORDER},
            "device": dev, "backup": data.get("backup") or ({"path": backup} if backup else None),
            "device_read": device_status, "coverage": coverage, "findings": findings, "checks": data.get("checks") or [],
            "posture": data.get("posture") or {}, "apps": data.get("apps") or [],
            "apps_total": data.get("apps_total", 0), "profiles": data.get("profiles") or [],
            "stats": data.get("stats") or {}, "indicators": data.get("indicators") or {},
            "limitations": notes + list(data.get("limitations") or []),
            "advice": advice_for(findings, data.get("posture") or {}),
            "sandbox": {"mode": "readonly", "isolation": ISOLATION["scan"], "verified": data.get("verified") or []},
            "report_html": None, "report_json": None,
        }
        stamp = time.strftime("%Y%m%d-%H%M%S")
        base = os.path.join(config.REPORTS, f"gui-{stamp}-iphone")
        try:
            hp, jp = _write_report(summary, base)
            summary["report_html"], summary["report_json"] = hp, jp
            with open(jp, "w") as fh:
                json.dump(summary, fh, indent=1, ensure_ascii=False, default=str)
            with open(os.path.join(config.REPORTS, INDEX), "a") as fh:
                fh.write(json.dumps({"id": f"gui-{stamp}-iphone", "mode": "iphone", "title": f"iPhone: {title}",
                                     "verdict": verdict, "started": started,
                                     "files": (data.get("stats") or {}).get("backup_files", 0),
                                     "report_html": hp, "report_json": jp}, ensure_ascii=False) + "\n")
        except OSError as exc:
            emit({"ev": "error", "fatal": False, "msg": f"Nie udało się zapisać raportu: {exc}"})
        emit({"ev": "iphone_done", "summary": summary})
        return 130 if cancelled else 0
    finally:
        if _sandbox_off():
            shutil.rmtree(work, ignore_errors=True)
        else:
            remove_workspace(work)


def gui_command(a, emit: Emit) -> int:
    """`gui_backend iphone devices | scan [UDID] [--make-backup] | backup PATH`."""
    cancel = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: cancel.set())
    signal.signal(signal.SIGTERM, lambda *_: cancel.set())
    args = list(a.args or [])
    sub = args[0] if args else "devices"
    if sub == "devices":
        devices_event(emit, cancel)
        return 0
    if sub == "scan":
        return scan(emit, udid=args[1] if len(args) > 1 else None, make_backup=bool(getattr(a, "make_backup", False)),
                    cancel=cancel)
    if sub == "backup":
        if len(args) < 2:
            emit({"ev": "error", "fatal": True, "msg": "Brak ścieżki do kopii zapasowej"})
            return 1
        return scan(emit, backup=args[1], cancel=cancel)
    emit({"ev": "error", "fatal": True, "msg": f"Nieznane polecenie iphone: {sub}"})
    return 1


# ================================================================== HTML report

SEV_PL = {"malicious": "groźne", "pua": "niechciane", "suspicious": "podejrzane", "low": "niskie", "info": "info"}
STATUS_PL = {"ok": "sprawdzono", "found": "znaleziono", "missing": "brak danych", "skipped": "pominięto",
             "error": "błąd"}
VERDICT_TEXT = {"MALICIOUS": "Znaleziono ślady groźnego oprogramowania", "SUSPICIOUS": "Są podejrzane elementy",
                "PUA": "Są niechciane elementy", "INFO": "Drobne uwagi", "CLEAN": "Nie znaleziono śladów zagrożeń"}


def write_html(s: dict, path: str) -> str:
    from .report import CSS, VERDICT_PL
    e = html.escape
    dev = s.get("device") or {}
    bk = s.get("backup") or {}
    post = s.get("posture") or {}
    v = s.get("verdict", "CLEAN")
    rows = []
    for f in s.get("findings") or []:
        ev = "".join(f"<li><code>{e(str(x))}</code></li>" for x in (f.get("evidence") or [])[:40])
        more = f.get("evidence_total", 0) - min(40, len(f.get("evidence") or []))
        adv = "".join(f"<li>{e(a)}</li>" for a in f.get("advice") or [])
        rows.append(f'<div class="card"><span class="sev sev-{e(f["severity"])}">{e(SEV_PL.get(f["severity"], ""))}'
                    f'</span> <b>{e(f["title"])}</b> <span class="muted">· {f.get("score", 0)} pkt · '
                    f'{e(str(f.get("location") or ""))}</span><p>{e(f.get("description") or "")}</p>'
                    + (f"<details open><summary>Dowody</summary><ul>{ev}</ul>"
                       + (f"<p class='muted'>… i {more} więcej</p>" if more > 0 else "") + "</details>" if ev else "")
                    + (f"<details><summary>Co zrobić</summary><ul>{adv}</ul></details>" if adv else "") + "</div>")
    checks = "".join(f"<tr><td>{e(c['title'])}</td><td>{e(STATUS_PL.get(c['status'], c['status']))}</td>"
                     f"<td>{e(c.get('detail') or '')}</td></tr>" for c in s.get("checks") or [])
    apps = "".join(f"<tr><td>{e(str(a.get('name') or ''))}</td><td><code>{e(a['bundle_id'])}</code></td>"
                   f"<td>{e(str(a.get('source') or '—'))}</td><td>{e(str(a.get('installed') or ''))}</td></tr>"
                   for a in (s.get("apps") or []) if a.get("source") != "apple")
    profs = "".join(f"<tr><td>{e(p['name'])}</td><td>{e(p.get('organization') or '')}</td>"
                    f"<td>{e(', '.join(p.get('types') or []))}</td><td>{e(str(p.get('installed') or ''))}</td></tr>"
                    for p in s.get("profiles") or [])
    lim = "".join(f"<li>{e(x)}</li>" for x in s.get("limitations") or [])
    adv = "".join(f"<li>{e(x)}</li>" for x in s.get("advice") or [])
    ind = s.get("indicators") or {}
    srcs = "".join(f"<tr><td>{e(str(x.get('name')))}</td><td>{e(str(x.get('license') or ''))}</td>"
                   f"<td><code>{e(str(x.get('url') or ''))}</code></td></tr>" for x in ind.get("sources") or [])
    pt = [("Urządzenie", f"{dev.get('name') or '—'} ({dev.get('model') or dev.get('product_type') or '?'})"),
          ("iOS", dev.get("ios") or "—"),
          ("Kopia zapasowa", f"{bk.get('date') or '—'}" + (" · zaszyfrowana" if bk.get("encrypted") else "")
           + (f" · {bk.get('path')}" if bk.get("path") else "")),
          ("Tryb blokady", {True: "włączony", False: "wyłączony"}.get(post.get("lockdown_mode"), "nie wiadomo")),
          ("Kod blokady", {True: "ustawiony", False: "BRAK"}.get(post.get("passcode_set"), "nie wiadomo")),
          ("Zarządzanie (MDM)", {True: "tak", False: "nie"}.get(post.get("mdm"), "nie wiadomo")),
          ("Aplikacje", str(s.get("apps_total") or post.get("apps_total") or 0))]
    tiles = "".join(f'<div class="tile"><span class="muted">{e(k)}</span><b style="font-size:15px">{e(str(val))}</b>'
                    f'</div>' for k, val in pt)
    cov = {"none": "<p><b>Za mało danych do oceny</b> – nie było kopii zapasowej, a telefon nie udostępnił listy "
                   "aplikacji. Zrób kopię zapasową (bez szyfrowania) i sprawdź ponownie.</p>",
           "partial": "<p class='muted'>Sprawdzenie niepełne – zobacz „Ograniczenia”.</p>"}.get(s.get("coverage"), "")
    doc = f"""<!doctype html><html lang="pl"><head><meta charset="utf-8"><title>Cerber – iPhone: {e(s.get('title', ''))}</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><style>{CSS}</style></head><body><main>
<h1>Cerber – sprawdzenie iPhone'a</h1>
<p class="muted">{e(s.get('started', ''))} → {e(s.get('finished', ''))} ({s.get('seconds', 0)} s) · analiza lokalna, nic nie
zostało wysłane do sieci · kopia i telefon nie zostały zmienione</p>
<div class="card"><span class="v {e(v)}">{e(VERDICT_PL.get(v, v))}</span> <b>{e(VERDICT_TEXT.get(v, ''))}</b>{cov}</div>
<div class="grid">{tiles}</div>
{'<h2>Co zrobić</h2><div class="card"><ol>' + adv + '</ol></div>' if adv else ''}
<h2>Znaleziska ({len(s.get('findings') or [])})</h2>
{''.join(rows) or '<div class="card">Brak znalezisk.</div>'}
<h2>Co sprawdzono</h2><div class="card"><table><tr><th>obszar</th><th>stan</th><th>szczegóły</th></tr>{checks}</table></div>
{'<h2>Ograniczenia</h2><div class="card"><ul>' + lim + '</ul></div>' if lim else ''}
{'<h2>Profile konfiguracyjne</h2><div class="card"><table><tr><th>nazwa</th><th>organizacja</th><th>zawartość</th><th>instalacja</th></tr>' + profs + '</table></div>' if profs else ''}
{'<h2>Aplikacje</h2><div class="card"><table><tr><th>nazwa</th><th>identyfikator</th><th>źródło</th><th>instalacja</th></tr>' + apps + '</table></div>' if apps else ''}
<h2>Wskaźniki iOS</h2><div class="card"><p>{ind.get('total', 0):,} wskaźników (baza z {e(str(ind.get('built') or '—'))}).
Trafienie we wskaźnik to poważny sygnał, ale nie ostateczny dowód – w razie wątpliwości skonsultuj wynik ze
specjalistami (np. Access Now Helpline).</p><table><tr><th>źródło</th><th>licencja</th><th>adres</th></tr>{srcs}</table></div>
</main></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


# ================================================================== CLI

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m cerber.iphone")
    ap.add_argument("args", nargs="*", help="devices | scan [UDID] | backup PATH")
    ap.add_argument("--make-backup", action="store_true", help="najpierw utwórz nową kopię zapasową (scan UDID)")
    a = ap.parse_args(argv)
    lock = threading.Lock()

    def emit(ev: dict) -> None:
        with lock:
            print(json.dumps(ev, ensure_ascii=False, default=str), flush=True)
    config.ensure_dirs()
    return gui_command(a, emit)


if __name__ == "__main__":
    raise SystemExit(main())

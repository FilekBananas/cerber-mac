"""Importers of macOS-only malware file hashes (exact-match) into the Cerber hash DB.

    ThreatFox     full export, only fk_malware "osx.*" hash IOCs with confidence >= 50 (abuse.ch, CC0)
    ESET          eset/malware-ioc (BSD-2): only table rows whose detection name is OSX/* or MacOS/*
    CIRCL OSINT   MISP OSINT feed (CC-BY / TLP:WHITE): events clearly about macOS, hashes of non-Windows files
    OTX           AlienVault pulses about macOS (needs CERBER_OTX_KEY, skipped otherwise)
    Bazaar API    newest Mach-O / DMG / PKG samples (needs CERBER_ABUSECH_KEY, skipped otherwise)

Every source downloads and parses at update time; nothing is embedded here.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import time
import urllib.parse
import urllib.request
import zipfile
from typing import Callable

from . import config
from .engines.hashdb import SRC_MACOS, HashDB

Log = Callable[[str], None]

THREATFOX = "https://threatfox.abuse.ch/export/csv/full/"
ESET_ZIP = "https://github.com/eset/malware-ioc/archive/refs/heads/master.zip"
CIRCL_BASE = "https://www.circl.lu/doc/misp/feed-osint/"
OTX_SEARCH = "https://otx.alienvault.com/api/v1/search/pulses"
BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"

HEX = re.compile(r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")
ESET_MAC = re.compile(r"\b((?:OSX|MacOS|macOS)/[A-Za-z0-9._]+)")
MAC_EVENT = re.compile(r"mac ?os|\bosx\b|os x\b|mach-?o|\.dmg\b|macransom|applejeus|xcsset|shlayer|"
                       r"atomic stealer|\bamos\b|kandykorn|rustbucket|dazzlespy|keydnap|flashback|"
                       r"macos_x|fruitfly|bundlore|pirrit", re.I)
WIN_FILE = re.compile(r"\.(exe|dll|msi|scr|bat|cmd|ps1|vbs|js|jar|apk|doc[xm]?|xls[xm]?|ppt[xm]?|lnk|elf|so)$"
                      r"|\.sys$|win(32|64|dows)|linux|android", re.I)
MAC_PULSE = re.compile(r"mac ?os|\bosx\b|os x\b|mach-?o|\.dmg\b|applejeus|xcsset|shlayer|atomic stealer|"
                       r"\bamos\b|kandykorn|rustbucket|dazzlespy|banshee|poseidon stealer|macsync", re.I)


def _digest(h: str) -> bytes | None:
    h = h.strip().lower()
    if len(h) in (32, 40, 64):
        try:
            return bytes.fromhex(h)
        except ValueError:
            return None
    return None


MAX_DOWNLOAD = 1 << 30


def _get(url: str, headers: dict | None = None, data: bytes | None = None, timeout: int = 120) -> bytes:
    if not url.lower().startswith("https://"):           # urlopen would also accept file:// or ftp://
        raise ValueError(f"odrzucono adres spoza https: {url[:120]}")
    h = {"User-Agent": config.USER_AGENT, **(headers or {})}
    with urllib.request.urlopen(urllib.request.Request(url, headers=h, data=data), timeout=timeout) as r:
        body = r.read(MAX_DOWNLOAD + 1)
    if len(body) > MAX_DOWNLOAD:
        raise ValueError(f"plik większy niż {MAX_DOWNLOAD >> 20} MB: {url[:120]}")
    return body


def _cached(url: str, name: str, max_age_h: float, log: Log) -> str:
    dest = os.path.join(config.FEEDS, name)
    if not os.path.exists(dest) or time.time() - os.path.getmtime(dest) > max_age_h * 3600:
        os.makedirs(config.FEEDS, exist_ok=True)
        log(f"    pobieranie {name} …")
        data = _get(url, timeout=600)
        with open(dest + ".part", "wb") as fh:
            fh.write(data)
        os.replace(dest + ".part", dest)
    return dest


def _add(db: HashDB, rows: list) -> int:
    """Insert rows, return how many were actually new (existing digests are ignored)."""
    if not rows:
        return 0
    return max(db.add_file_hashes(rows), 0)


# ------------------------------------------------------------------ ThreatFox (osx.* families)

def parse_threatfox(text: str, min_conf: int = 50) -> list[tuple[bytes, str]]:
    out = []
    lines = (ln for ln in text.splitlines() if ln and not ln.startswith("#"))
    for row in csv.reader(lines, skipinitialspace=True):
        if len(row) < 10 or not row[5].startswith("osx."):
            continue
        if row[3] not in ("sha256_hash", "md5_hash", "sha1_hash"):
            continue
        try:
            if int(row[9]) < min_conf:
                continue
        except ValueError:
            continue
        d = _digest(row[2])
        if d:
            out.append((d, f"ThreatFox.{row[7].strip() or row[5]}"))
    return out


def import_threatfox(db: HashDB, log: Log) -> int:
    from .updater import abusech_urls, fetch_feed
    path = fetch_feed(abusech_urls("threatfox", ["full.csv.zip", "full.zip"]),
                      os.path.join(config.FEEDS, "threatfox_full.zip"), log, "ThreatFox (macOS)")
    with zipfile.ZipFile(path) as z:
        name = next(n for n in z.namelist() if n.endswith(".csv"))
        text = z.read(name).decode("utf-8", "replace")
    return _add(db, [(d, None, lb, SRC_MACOS, 0) for d, lb in parse_threatfox(text)])


# ------------------------------------------------------------------ ESET malware-ioc

def parse_eset_text(text: str) -> list[tuple[bytes, str]]:
    out = []
    for line in text.splitlines():
        m = ESET_MAC.search(line)
        if not m or "|" not in line:
            continue
        for h in HEX.findall(line):
            d = _digest(h)
            if d:
                out.append((d, f"ESET.{m.group(1)}"))
    return out


def import_eset(db: HashDB, log: Log) -> int:
    path = _cached(ESET_ZIP, "eset-malware-ioc.zip", 24, log)
    rows = []
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.endswith((".adoc", ".md", ".txt")):
                for d, lb in parse_eset_text(z.read(n).decode("utf-8", "replace")):
                    rows.append((d, None, lb, SRC_MACOS, 0))
    return _add(db, rows)


# ------------------------------------------------------------------ CIRCL OSINT (MISP feed)

_HASH_TYPES = {"md5", "sha1", "sha256"}


def event_is_mac(info: str, tags: list[str]) -> bool:
    return bool(MAC_EVENT.search(info) or any(MAC_EVENT.search(t) for t in tags))


MAC_HINT = re.compile(r"osx|mac ?os|\bmac\b|mach-?o|\.(dmg|pkg|app)\b|darwin", re.I)


def parse_misp_event(ev: dict) -> list[tuple[bytes, str]]:
    """Hashes of an event about macOS; mixed events keep only attributes with a macOS hint
    (comment/filename mentions OSX/Mac/.dmg/.app, an extension-less Unix filename, or an event-level
    macOS platform tag). Anything that looks like a Windows/Linux/Android file is dropped."""
    ev = ev.get("Event", ev)
    label = "CIRCL." + re.sub(r"^OSINT\s*-?\s*", "", ev.get("info", "")).strip()[:40]
    platform_tag = any("macos" in t.get("name", "").lower() for t in ev.get("Tag", []))
    out = []

    def take(attrs: list) -> None:
        fns = [a.get("value", "") for a in attrs if a.get("type") == "filename"]
        text = " ".join(fns + [a.get("comment", "") for a in attrs])
        if any(WIN_FILE.search(f) for f in fns) or WIN_FILE.search(text):
            return
        bare = any(f and "." not in os.path.basename(f) for f in fns)
        for a in attrs:
            t, v = a.get("type", ""), a.get("value", "")
            hint = platform_tag or bare or MAC_HINT.search(text + " " + a.get("comment", ""))
            if "|" in t:                      # filename|sha256
                f, _, v = v.partition("|")
                t = t.split("|")[1]
                if WIN_FILE.search(f):
                    continue
                hint = hint or MAC_HINT.search(f) or "." not in os.path.basename(f)
            if t in _HASH_TYPES and a.get("to_ids", True) and hint:
                d = _digest(v)
                if d:
                    out.append((d, label))

    for a in ev.get("Attribute", []):
        take([a])
    for o in ev.get("Object", []):
        take(o.get("Attribute", []))
    return out


def import_circl(db: HashDB, log: Log) -> int:
    manifest = json.loads(_get(CIRCL_BASE + "manifest.json", timeout=120))
    rows = []
    for uuid, m in manifest.items():
        tags = [t.get("name", "") for t in m.get("Tag", [])]
        if not event_is_mac(m.get("info", ""), tags):
            continue
        try:
            rows += [(d, None, lb, SRC_MACOS, 0) for d, lb in parse_misp_event(json.loads(_get(f"{CIRCL_BASE}{uuid}.json")))]
        except Exception as exc:  # noqa: BLE001
            log(f"    CIRCL {uuid}: {exc!r}")
    return _add(db, rows)


# ------------------------------------------------------------------ AlienVault OTX (key)

def parse_otx_pulse(p: dict) -> list[tuple[bytes, str]]:
    if not MAC_PULSE.search(p.get("name", "") + " " + " ".join(p.get("tags", []))):
        return []
    label = "OTX." + p.get("name", "").strip()[:40]
    return [(d, label) for i in p.get("indicators", [])
            if i.get("type") in ("FileHash-SHA256", "FileHash-SHA1", "FileHash-MD5")
            for d in [_digest(i.get("indicator", ""))] if d]


def import_otx(db: HashDB, log: Log) -> int:
    key = os.environ.get("CERBER_OTX_KEY")
    if not key:
        log("    OTX: pominięto (brak CERBER_OTX_KEY)")
        return 0
    rows = []
    for q in ("macos", "osx malware", "mach-o", "atomic stealer"):
        for page in range(1, 6):
            url = f"{OTX_SEARCH}?{urllib.parse.urlencode({'q': q, 'limit': 50, 'page': page})}"
            data = json.loads(_get(url, {"X-OTX-API-KEY": key}))
            for p in data.get("results", []):
                rows += [(d, None, lb, SRC_MACOS, 0) for d, lb in parse_otx_pulse(p)]
            if not data.get("next"):
                break
    return _add(db, rows)


# ------------------------------------------------------------------ MalwareBazaar API (key)

def parse_bazaar_api(resp: dict) -> list[tuple[bytes, str]]:
    out = []
    if resp.get("query_status") != "ok":
        return out
    for s in resp.get("data", []):
        label = f"MalwareBazaar.{s.get('signature') or 'Generic.' + str(s.get('file_type'))}"
        for k in ("sha256_hash", "md5_hash", "sha1_hash"):
            d = _digest(s.get(k) or "")
            if d:
                out.append((d, label))
    return out


def import_bazaar_api(db: HashDB, log: Log) -> int:
    key = config.abusech_key()
    if not key:
        log("    MalwareBazaar API: pominięto (brak klucza abuse.ch)")
        return 0
    rows = []
    for post in ({"query": "get_file_type", "file_type": "macho", "limit": "1000"},
                 {"query": "get_file_type", "file_type": "dmg", "limit": "1000"},
                 {"query": "get_file_type", "file_type": "pkg", "limit": "1000"},
                 {"query": "get_taginfo", "tag": "macos", "limit": "1000"}):
        data = json.loads(_get(BAZAAR_API, {"Auth-Key": key}, urllib.parse.urlencode(post).encode()))
        rows += [(d, None, lb, SRC_MACOS, 0) for d, lb in parse_bazaar_api(data)]
    return _add(db, rows)


# ------------------------------------------------------------------ driver

SOURCES = [("threatfox", import_threatfox), ("eset", import_eset), ("circl", import_circl),
           ("otx", import_otx), ("bazaar_api", import_bazaar_api)]


def import_macos_hashes(db: HashDB, log: Log) -> dict:
    """Run every source; a failing source is logged and skipped. Returns net-new hashes per source."""
    res: dict = {}
    for name, fn in SOURCES:
        try:
            res[name] = fn(db, log)
            log(f"  Mac hashe {name}: +{res[name]:,} nowych")
        except Exception as exc:  # noqa: BLE001
            log(f"  BŁĄD Mac hashe {name}: {exc!r}")
            res[name] = 0
    return res


def mac_total(db: HashDB) -> int:
    return db._con().execute("SELECT COUNT(*) FROM file WHERE src=?", (SRC_MACOS,)).fetchone()[0]


def refresh_only(log: Log) -> dict:
    """Add the Mac hashes to a copy of the existing hashes.sqlite and swap it in atomically."""
    import shutil
    if not os.path.exists(config.HASHDB):
        raise RuntimeError("brak db/compiled/hashes.sqlite - najpierw pełna aktualizacja (cerber update)")
    tmp = config.HASHDB + ".new"
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(tmp + ext):
            os.remove(tmp + ext)
    src = HashDB(config.HASHDB, readonly=False)
    src._con().execute("PRAGMA wal_checkpoint(TRUNCATE)")
    src._con().close()
    shutil.copyfile(config.HASHDB, tmp)
    db = HashDB(tmp, readonly=False)
    db.delete_source(SRC_MACOS)          # authoritative rebuild of this source
    res = import_macos_hashes(db, log)
    total = mac_total(db)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    db.set_source("macos_feeds", now, total, now)
    db._con().commit()
    db._con().close()
    os.replace(tmp, config.HASHDB)
    res["total"] = total
    return res

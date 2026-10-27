"""Download and build every signature database Cerber uses.

    ClamAV          freshclam (official client) -> compiled body sigs + hash sigs
    MalwareBazaar   full SHA256/MD5/SHA1 dump + TLSH (abuse.ch, no key needed for the dump)
    signature-base  hash IOCs (Florian Roth)
    YARA-Forge      core + full rule packages (aggregates signature-base, Elastic, ReversingLabs, …)
    XProtect        Apple's own YARA rules from this Mac
    Elastic         protections-artifacts macOS YARA rules (Elastic License 2.0, community tier)
    URLhaus/ThreatFox  malicious URL / domain / IP IOCs
    calibration     rules/signatures that fire on clean Apple system files get disabled
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
import urllib.request
import zipfile
from typing import Callable

from . import config
from .engines import clamav_db
from .engines.hashdb import SRC_BAZAAR, SRC_CLAMAV, SRC_SIGBASE, HashDB
from .engines.ioc_fuzzy import is_shared_domain
from .engines.yara_engine import build_rules, split_rules

Log = Callable[[str], None]

YARAFORGE = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-{tier}.zip"
BAZAAR_FULL = "https://bazaar.abuse.ch/export/csv/full/"
SIGBASE_ZIP = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
URLHAUS = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX = "https://threatfox.abuse.ch/export/csv/full/"
# Elastic Security "protections-artifacts": only the macOS YARA files (MacOS_*.yar, ~85 rules, ~70 KB).
# Elastic License 2.0 (local use and redistribution allowed; the licence text is stored next to the rules).
# They go to the community tier: hints only (never a verdict on their own) and subject to the
# fp_disabled.json calibration like every other community rule.
ELASTIC_TREE = "https://api.github.com/repos/elastic/protections-artifacts/git/trees/main?recursive=1"
ELASTIC_RAW = "https://raw.githubusercontent.com/elastic/protections-artifacts/main/{path}"
ELASTIC_PREFIX = "yara/rules/MacOS_"
XPROTECT_DIRS = ["/var/protected/xprotect/XProtect.bundle/Contents/Resources",
                 "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources"]


def _download(url: str, dest: str, log: Log, timeout: int = 600) -> str:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": config.USER_AGENT})
    tmp = dest + ".part"
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r, open(tmp, "wb") as fh:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        last = 0.0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            fh.write(chunk)
            done += len(chunk)
            if time.time() - last > 2:
                pct = f" {done * 100 // total}%" if total else ""
                log(f"    … {done >> 20} MB{pct}")
                last = time.time()
    os.replace(tmp, dest)
    log(f"    pobrano {os.path.basename(dest)}: {done >> 20} MB w {time.time() - t0:.0f}s")
    return dest


# ------------------------------------------------------------------ ClamAV

def update_clamav(log: Log) -> dict:
    tools = config.tools()
    fc = tools.get("freshclam")
    conf = os.path.join(config.CLAMAV_RAW, "freshclam.conf")
    if fc:
        if not os.path.exists(conf):
            with open(conf, "w") as fh:
                fh.write(f"DatabaseDirectory {config.CLAMAV_RAW}\nDatabaseMirror database.clamav.net\n"
                         "DNSDatabaseInfo current.cvd.clamav.net\nForeground yes\n")
        log("  freshclam: pobieranie/aktualizacja baz ClamAV …")
        p = subprocess.run([fc, f"--config-file={conf}"], capture_output=True, text=True, timeout=1800)
        tail = (p.stdout + p.stderr).strip().splitlines()[-3:]
        for line in tail:
            log(f"    {line}")
    else:
        log("  UWAGA: brak freshclam (brew install clamav) – używam istniejących plików .cvd")
    if not any(f.endswith((".cvd", ".cld")) for f in os.listdir(config.CLAMAV_RAW)):
        raise RuntimeError("brak baz ClamAV w " + config.CLAMAV_RAW)
    log("  kompilacja sygnatur bajtowych/logicznych ClamAV …")
    meta = clamav_db.compile_clamav(config.CLAMAV_RAW, config.CLAMAV_COMPILED + ".new", log=lambda m: log("  " + m))
    if os.path.isdir(config.CLAMAV_COMPILED):
        shutil.rmtree(config.CLAMAV_COMPILED)
    os.replace(config.CLAMAV_COMPILED + ".new", config.CLAMAV_COMPILED)
    return meta


def import_clamav_hashes(db: HashDB, log: Log) -> dict:
    counts = {"file": 0, "section": 0, "fp": 0}
    fbuf, sbuf, pbuf = [], [], []

    def flush():
        if fbuf:
            counts["file"] += db.add_file_hashes(fbuf)
            fbuf.clear()
        if sbuf:
            counts["section"] += db.add_section_hashes(sbuf)
            sbuf.clear()
        if pbuf:
            counts["fp"] += db.add_fp(pbuf)
            pbuf.clear()

    for table, digest, size, name, pua in clamav_db.iter_hash_sigs(clamav_db.iter_db_files(config.CLAMAV_RAW)):
        if table == "file":
            fbuf.append((digest, size, name, SRC_CLAMAV, int(pua)))
        elif table == "section":
            sbuf.append((digest, size or 0, name, int(pua)))
        else:
            pbuf.append((digest, size, name))
        if len(fbuf) + len(sbuf) + len(pbuf) >= 200_000:
            flush()
    flush()
    log(f"  ClamAV hashe: {counts['file']:,} plików, {counts['section']:,} sekcji PE, {counts['fp']:,} białej listy")
    return counts


# ------------------------------------------------------------------ MalwareBazaar

def tlsh_lval(t: str) -> int | None:
    t = t.strip()
    if t.startswith("T1"):
        t = t[2:]
    if len(t) < 6:
        return None
    try:
        return int(t[2:4][::-1], 16)
    except ValueError:
        return None


def update_bazaar(db: HashDB, log: Log) -> int:
    dest = os.path.join(config.FEEDS, "bazaar_full.zip")
    if not os.path.exists(dest) or time.time() - os.path.getmtime(dest) > 12 * 3600:
        log("  MalwareBazaar: pobieranie pełnego zrzutu (~220 MB) …")
        _download(BAZAAR_FULL, dest, log)
    rows, tl = [], []
    n = 0
    with zipfile.ZipFile(dest) as z:
        name = next(i for i in z.namelist() if i.endswith(".csv"))
        with z.open(name) as fh:
            text = io.TextIOWrapper(fh, encoding="utf-8", errors="replace", newline="")
            reader = csv.reader((line for line in text if not line.startswith("#")), skipinitialspace=True)
            for row in reader:
                if len(row) < 9:
                    continue
                sha256, md5, sha1 = row[1].strip(), row[2].strip(), row[3].strip()
                ftype = row[6].strip() or "unknown"
                sig = row[8].strip()
                label = sig if sig and sig.lower() not in ("n/a", "null", "none") else f"Generic.{ftype}"
                for h in (sha256, md5, sha1):
                    try:
                        rows.append((bytes.fromhex(h), None, label, SRC_BAZAAR, 0))
                    except ValueError:
                        pass
                if len(row) >= 14:
                    t = row[13].strip()
                    lv = tlsh_lval(t) if t and t.lower() != "n/a" else None
                    if lv is not None:
                        tl.append((t, lv, label))
                n += 1
                if len(rows) >= 300_000:
                    db.add_file_hashes(rows)
                    rows.clear()
                if len(tl) >= 300_000:
                    db.add_tlsh(tl)
                    tl.clear()
    db.add_file_hashes(rows)
    db.add_tlsh(tl)
    log(f"  MalwareBazaar: {n:,} próbek (SHA256+MD5+SHA1, TLSH)")
    return n


# ------------------------------------------------------------------ signature-base (hash IOCs only)

def update_sigbase(db: HashDB, log: Log) -> int:
    dest = os.path.join(config.FEEDS, "signature-base.zip")
    log("  signature-base: pobieranie …")
    _download(SIGBASE_ZIP, dest, log)
    n = 0
    rows = []
    with zipfile.ZipFile(dest) as z:
        for member in z.namelist():
            if member.endswith(("iocs/hash-iocs.txt", "iocs/otx-hash-iocs.txt")):
                for line in z.read(member).decode("utf-8", "replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or ";" not in line:
                        continue
                    h, desc = line.split(";", 1)
                    try:
                        d = bytes.fromhex(h.strip())
                    except ValueError:
                        continue
                    if len(d) in (16, 20, 32):
                        rows.append((d, None, re.sub(r"\s+", "_", desc.strip())[:80] or "IOC", SRC_SIGBASE, 0))
                        n += 1
    db.add_file_hashes(rows)
    log(f"  signature-base: {n:,} hashy IOC")
    return n


# ------------------------------------------------------------------ YARA

def update_elastic_macos(log: Log, offline: bool = False) -> str | None:
    """Fetch Elastic's macOS YARA rules into db/yara/elastic (keeps the previous copy on any error)."""
    d = os.path.join(config.YARA_SOURCES, "elastic")
    if offline:
        return d if os.path.isdir(d) else None
    try:
        log("  Elastic protections-artifacts (macOS): pobieranie …")
        req = urllib.request.Request(ELASTIC_TREE, headers={"User-Agent": config.USER_AGENT,
                                                            "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            tree = json.load(r)
        paths = sorted(t["path"] for t in tree.get("tree", [])
                       if t.get("type") == "blob" and t.get("path", "").startswith(ELASTIC_PREFIX)
                       and t["path"].endswith(".yar"))
        if not paths:
            raise RuntimeError("brak plików MacOS_*.yar w repozytorium")
        tmp = d + ".new"
        if os.path.isdir(tmp):
            shutil.rmtree(tmp)
        os.makedirs(tmp)
        for path in paths + ["LICENSE.txt"]:
            name = os.path.basename(path)
            if name == "LICENSE.txt":
                name = "ELASTIC_LICENSE_2.0.txt"
            req = urllib.request.Request(ELASTIC_RAW.format(path=path), headers={"User-Agent": config.USER_AGENT})
            with urllib.request.urlopen(req, timeout=60) as r, open(os.path.join(tmp, name), "wb") as fh:
                fh.write(r.read())
        if os.path.isdir(d):
            shutil.rmtree(d)
        os.replace(tmp, d)
        log(f"    Elastic: {len(paths)} plików reguł macOS")
    except Exception as exc:  # noqa: BLE001
        log(f"    Elastic niedostępny ({exc}); używam poprzedniej wersji jeśli jest")
    return d if os.path.isdir(d) else None


def update_yara(log: Log, offline: bool = False) -> dict:
    """Download (unless offline) and compile every YARA source. offline=True only recompiles what is
    already on disk (cached YARA-Forge zips, db/yara/elastic, XProtect from this Mac, rules/)."""
    root = config.YARA_SOURCES
    os.makedirs(root, exist_ok=True)
    # YARA-Forge core + full (full minus core = community tier)
    core_rules: dict[str, str] = {}
    for tier in ("core", "full"):
        dest = os.path.join(config.FEEDS, f"yara-forge-{tier}.zip")
        if offline:
            if not os.path.exists(dest):
                log(f"  YARA-Forge {tier}: brak pliku {dest} (tryb offline)")
                continue
        else:
            try:
                log(f"  YARA-Forge {tier}: pobieranie …")
                _download(YARAFORGE.format(tier=tier), dest, log)
            except Exception as exc:  # noqa: BLE001
                log(f"    błąd pobierania ({exc}); używam poprzedniej wersji jeśli jest")
                if not os.path.exists(dest):
                    continue
        with zipfile.ZipFile(dest) as z:
            for member in z.namelist():
                if member.endswith(".yar"):
                    core_rules[tier] = z.read(member).decode("utf-8", "replace")
    tiers_dirs = []
    if "core" in core_rules:
        d = os.path.join(root, "core")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "yara-forge-core.yar"), "w") as fh:
            fh.write(core_rules["core"])
        tiers_dirs.append(("core", d))
    if "full" in core_rules:
        full = core_rules["full"]
        core_names = {r[0] for r in split_rules(core_rules.get("core", ""))}
        pieces, last = [], 0
        header_end = split_rules(full)[0][1] if split_rules(full) else 0
        header = full[:header_end]
        body = []
        for name, s, e in split_rules(full):
            if name not in core_names:
                body.append(full[s:e])
        d = os.path.join(root, "community")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "yara-forge-community.yar"), "w") as fh:
            fh.write(header + "\n\n".join(body))
        tiers_dirs.append(("community", d))
    # XProtect
    xd = os.path.join(root, "xprotect")
    os.makedirs(xd, exist_ok=True)
    for src in XPROTECT_DIRS:
        if os.path.exists(os.path.join(src, "XProtect.yara")):
            for fn in ("XProtect.yara", "XPScripts.yr"):
                if os.path.exists(os.path.join(src, fn)):
                    shutil.copyfile(os.path.join(src, fn), os.path.join(xd, fn))
            log(f"  XProtect: reguły Apple z {src}")
            break
    tiers_dirs.append(("xprotect", xd))
    ed = update_elastic_macos(log, offline)
    if ed:
        tiers_dirs.append(("community", ed))
    from .feeds_macos_yara import update_macos_yara
    md = update_macos_yara(log, offline)
    if md:
        tiers_dirs.append(("community", md))
    tiers_dirs.append(("custom", config.CUSTOM_RULES))
    tiers_dirs.append(("community", config.EXPERIMENTAL_RULES))
    log("  kompilacja reguł YARA (wadliwe reguły są wycinane pojedynczo) …")
    meta = build_rules(tiers_dirs, config.YARA_BIN + ".new", config.YARA_META + ".new", log=lambda m: log("  " + m))
    if md:
        try:
            with open(os.path.join(md, "SOURCES.json"), encoding="utf-8") as fh:
                srcs = json.load(fh)
            meta["macfeeds"] = {"sources": len(srcs), "rules": sum(v["kept"] for v in srcs.values() if isinstance(v.get("kept"), int)),
                                "per_source": {k: v.get("kept") for k, v in srcs.items()}}
            with open(config.YARA_META + ".new", "w") as fh:
                json.dump(meta, fh, indent=1)
        except (OSError, ValueError):
            pass
    os.replace(config.YARA_BIN + ".new", config.YARA_BIN)
    os.replace(config.YARA_META + ".new", config.YARA_META)
    log(f"  YARA: {meta['rules']:,} reguł ({', '.join(f'{k}={v}' for k, v in meta['stats'].items() if k.endswith(':rules'))})")
    return meta


# ------------------------------------------------------------------ IOC feeds

def update_ioc(log: Log) -> int:
    path = config.IOCDB + ".new"
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE ioc(kind TEXT, value TEXT, threat TEXT, PRIMARY KEY(kind, value)) WITHOUT ROWID")
    n = 0
    try:
        dest = os.path.join(config.FEEDS, "urlhaus_recent.csv")
        log("  URLhaus: pobieranie …")
        _download(URLHAUS, dest, log)
        rows = []
        with open(dest, encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(line for line in fh if not line.startswith("#")):
                if len(row) < 7:
                    continue
                url, threat, tags = row[2].strip(), row[5].strip() or "malware_download", row[6].strip()
                label = f"URLhaus.{threat}" + (f".{tags.split(',')[0]}" if tags and tags != "None" else "")
                rows.append(("url", url.lower(), label))
                host = re.sub(r"^[a-z]+://", "", url.lower()).split("/", 1)[0].split(":", 1)[0]
                # only raw-IP hosts become host-level IOCs; a domain that once served a malicious
                # file (often shared hosting/CDN) is not malicious as a whole
                if host and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                    rows.append(("ip", host, label))
        con.executemany("INSERT OR IGNORE INTO ioc VALUES (?,?,?)", rows)
        n += len(rows)
    except Exception as exc:  # noqa: BLE001
        log(f"    URLhaus niedostępny: {exc}")
    try:
        dest = os.path.join(config.FEEDS, "threatfox_full.zip")
        log("  ThreatFox: pobieranie …")
        _download(THREATFOX, dest, log)
        rows = []
        with zipfile.ZipFile(dest) as z:
            name = next(i for i in z.namelist() if i.endswith(".csv"))
            text = io.TextIOWrapper(z.open(name), encoding="utf-8", errors="replace", newline="")
            for row in csv.reader((line for line in text if not line.startswith("#")), skipinitialspace=True):
                if len(row) < 6:
                    continue
                value, itype, family = row[2].strip().lower(), row[3].strip(), row[5].strip()
                label = f"ThreatFox.{family or 'malware'}"
                if itype == "url":
                    rows.append(("url", value, label))
                elif itype == "domain" and not is_shared_domain(value):
                    rows.append(("domain", value, label))
                elif itype == "ip:port":
                    rows.append(("ip", value.split(":", 1)[0], label))
                elif itype in ("sha256_hash", "md5_hash", "sha1_hash"):
                    rows.append(("hash", value, label))
        con.executemany("INSERT OR IGNORE INTO ioc VALUES (?,?,?)", rows)
        n += len(rows)
    except Exception as exc:  # noqa: BLE001
        log(f"    ThreatFox niedostępny (może wymagać klucza abuse.ch): {exc}")
    con.commit()
    con.close()
    os.replace(path, config.IOCDB)
    log(f"  IOC: {n:,} wskaźników (URL/domeny/IP)")
    return n


# ------------------------------------------------------------------ calibration

CLEAN_CORPUS = ["/usr/bin", "/usr/sbin", "/usr/libexec", "/bin", "/sbin", "/System/Library/CoreServices",
                "/System/Applications", "/System/Library/PrivateFrameworks/SkyLight.framework",
                "/System/Library/Frameworks/Security.framework"]


def calibrate(log: Log, max_files: int = 25000) -> dict:
    """Scan clean Apple system files (sealed system volume) and disable every
    YARA rule / ClamAV signature that fires there."""
    from .engines.clamav import ClamAVEngine
    from .engines.yara_engine import YaraEngine
    from .pipeline import Pipeline

    from .engines.hashdb import HashDB, HashEngine

    yara_eng = YaraEngine(config.YARA_BIN, config.YARA_META)
    engines = [yara_eng]
    if os.path.exists(config.HASHDB):
        engines.insert(0, HashEngine(HashDB(config.HASHDB)))
    if os.path.isdir(config.CLAMAV_COMPILED):
        engines.append(ClamAVEngine(config.CLAMAV_COMPILED))
    pipe = Pipeline(engines=engines, analyzers=[])
    disabled: dict[str, list[str]] = {}
    fp_sha256: dict[str, str] = {}
    n = 0
    t0 = time.time()
    for root in CLEAN_CORPUS:
        for dp, _dn, fns in os.walk(root):
            for fn in fns:
                p = os.path.join(dp, fn)
                try:
                    if os.path.islink(p) or not os.path.isfile(p) or os.path.getsize(p) > (64 << 20):
                        continue
                    res = pipe.scan_file(p)
                except (OSError, MemoryError):
                    continue
                n += 1
                for o in res.iter_tree():
                    for d in o.detections:
                        if d.engine == "hash":
                            fp_sha256[o.sha256] = f"{d.name} @ {p}"   # whitelist this exact file
                            continue
                        rule = d.name.split(":", 1)[1] if ":" in d.name else d.name
                        disabled.setdefault(rule, []).append(p)
                if n % 2000 == 0:
                    log(f"    kalibracja: {n} plików, {len(disabled)} reguł do wyłączenia")
                if n >= max_files:
                    break
            if n >= max_files:
                break
    # pass 2: third-party apps that Gatekeeper accepts as notarized – only community-tier
    # ("YARA-ext") rules may be disabled here, never ClamAV/XProtect/core/custom signatures
    n2 = 0
    apps = sorted(os.path.join("/Applications", a) for a in os.listdir("/Applications") if a.endswith(".app"))
    for app in apps:
        try:
            p = subprocess.run(["spctl", "--assess", "--type", "execute", "-vv", app], capture_output=True,
                               text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            continue
        out_txt = p.stdout + p.stderr
        if p.returncode != 0 or not re.search(r"source=(Notarized Developer ID|Apple System|Mac App Store)", out_txt):
            continue
        per_app = 0
        for dp, _dn, fns in os.walk(app):
            for fn in fns:
                fp = os.path.join(dp, fn)
                try:
                    if os.path.islink(fp) or not os.path.isfile(fp) or os.path.getsize(fp) > (64 << 20):
                        continue
                    res = pipe.scan_file(fp)
                except (OSError, MemoryError):
                    continue
                n2 += 1
                per_app += 1
                for o in res.iter_tree():
                    for d in o.detections:
                        if d.name.startswith("YARA-ext:"):
                            disabled.setdefault(d.name.split(":", 1)[1], []).append(fp)
                if per_app >= 4000:
                    break
            if per_app >= 4000:
                break
    log(f"  kalibracja: {n2} plików z notaryzowanych aplikacji firm trzecich")
    out = {"built": time.strftime("%Y-%m-%d %H:%M:%S"), "files": n + n2, "disabled": sorted(disabled),
           "examples": {k: v[:3] for k, v in disabled.items()}, "fp_sha256": sorted(fp_sha256),
           "fp_sha256_examples": dict(list(fp_sha256.items())[:50])}
    with open(config.FP_CALIBRATION, "w") as fh:
        json.dump(out, fh, indent=1)
    log(f"  kalibracja: {n} czystych plików systemowych w {time.time() - t0:.0f}s, "
        f"wyłączono {len(disabled)} reguł/sygnatur dających fałszywe alarmy")
    return out


def update_all(log: Log = print, clamav=True, bazaar=True, sigbase=True, yara_rules=True, ioc=True,
               calib=True, offline: bool = False, machashes: bool = True, ios: bool = True) -> dict:
    config.ensure_dirs()
    summary: dict = {}
    t0 = time.time()
    steps = []
    if clamav:
        steps.append(("ClamAV", lambda: update_clamav(log)))
    if yara_rules:
        steps.append(("YARA", lambda: update_yara(log, offline=offline)))
    if ioc:
        steps.append(("IOC", lambda: update_ioc(log)))
    if ios:     # iPhone spyware/stalkerware indicators -> ios_ioc.sqlite (manual update only)
        from .feeds_ios import update_ios_indicators
        steps.append(("iOS", lambda: update_ios_indicators(log, offline=offline)))
    for name, fn in steps:
        log(f"[{name}]")
        try:
            summary[name] = fn()
        except Exception as exc:  # noqa: BLE001
            log(f"  BŁĄD {name}: {exc!r}")
            summary[name] = {"error": repr(exc)}
    if clamav or bazaar or sigbase:
        log("[Baza hashy]")
        tmp = config.HASHDB + ".new"
        if os.path.exists(tmp):
            os.remove(tmp)
        db = HashDB(tmp, readonly=False)
        try:
            summary["clamav_hashes"] = import_clamav_hashes(db, log)
            if bazaar:
                summary["bazaar"] = update_bazaar(db, log)
            if sigbase:
                summary["sigbase"] = update_sigbase(db, log)
            if machashes:
                from .feeds_macos import import_macos_hashes
                summary["macos_feeds"] = import_macos_hashes(db, log)
        except Exception as exc:  # noqa: BLE001
            log(f"  BŁĄD bazy hashy: {exc!r}")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        for k in ("clamav_hashes", "bazaar", "sigbase", "macos_feeds"):
            if k in summary:
                v = summary[k]
                db.set_source(k, now, v if isinstance(v, int) else sum(v.values()), now)
        db._con().execute("ANALYZE")
        db._con().commit()
        db._con().close()
        os.replace(tmp, config.HASHDB)
    if calib and os.path.exists(config.YARA_BIN):
        log("[Kalibracja fałszywych alarmów]")
        try:
            summary["calibration"] = len(calibrate(log)["disabled"])
        except Exception as exc:  # noqa: BLE001
            log(f"  BŁĄD kalibracji: {exc!r}")
    log(f"Gotowe w {time.time() - t0:.0f}s")
    return summary


def main(argv=None) -> int:
    """python -m cerber.updater yara [--offline]   rebuild only the YARA set (no ClamAV/Bazaar/IOC download)."""
    import argparse
    ap = argparse.ArgumentParser(prog="python -m cerber.updater")
    ap.add_argument("what", choices=["yara"], help="which database to rebuild")
    ap.add_argument("--offline", action="store_true",
                    help="no network: recompile from cached YARA-Forge zips, db/yara/elastic, XProtect and rules/")
    a = ap.parse_args(argv)
    config.ensure_dirs()
    meta = update_yara(print, offline=a.offline)
    return 0 if meta.get("rules") else 1


if __name__ == "__main__":
    raise SystemExit(main())

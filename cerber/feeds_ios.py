"""iOS / mobile spyware indicators (iPhone scanning) -> db/compiled/ios_ioc.sqlite.

    MVT           mvt-project/mvt-indicators (MIT): indicators.yaml index + the STIX2 bundles it lists
                  (Predator, Triangulation, KingSpawn/QuaDream, RCS Lab, Candiru, DarkSword, Coruna, …);
                  bundles hosted in AmnestyTech / AssoEchap repos come from those sources instead
    Amnesty Tech  AmnestyTech/investigations (CC-BY): every *.stix2 / *.stix bundle (Pegasus, Cytrox,
                  NoviSpy, Helios, …) + plain NSO/Pegasus domain lists of folders without a bundle
    Echap         AssoEchap/stalkerware-indicators (CC-BY 4.0): ioc.yaml (app ids, signing certs,
                  vendor websites, C2 domains/IPs); watchware.yaml (parental control) is ignored
    Citizen Lab   citizenlab/malware-indicators (CC BY-NC-SA 4.0): 2016 NSO "Million Dollar Dissident"
                  (Trident/Pegasus iPhone chain) csv

Every source is downloaded and parsed at update time; no indicator is embedded here. Parse functions
are pure (text/bytes in -> rows out) so they can be tested offline.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import sqlite3
import time
import urllib.parse
import urllib.request
import zipfile
from typing import Callable

from . import config
from .engines.ioc_fuzzy import is_shared_domain

Log = Callable[[str], None]

IOS_IOCDB = os.path.join(config.COMPILED, "ios_ioc.sqlite")
DB_VERSION = "1"

MVT_ZIP = "https://github.com/mvt-project/mvt-indicators/archive/refs/heads/main.zip"
AMNESTY_ZIP = "https://github.com/AmnestyTech/investigations/archive/refs/heads/master.zip"
ECHAP_ZIP = "https://github.com/AssoEchap/stalkerware-indicators/archive/refs/heads/master.zip"
CITIZENLAB_NSO = "https://raw.githubusercontent.com/citizenlab/malware-indicators/master/201608_NSO_Group/iocs.csv"
RAW = "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"

# name -> (url, license as stated in the repo)
SOURCE_META = {
    "MVT": ("https://github.com/mvt-project/mvt-indicators", "MIT (LICENSE)"),
    "Amnesty Tech": ("https://github.com/AmnestyTech/investigations", "CC-BY 2.0 (README: \"shared under the license CC-BY\")"),
    "Echap": ("https://github.com/AssoEchap/stalkerware-indicators", "CC-BY 4.0 (README)"),
    "Citizen Lab": ("https://github.com/citizenlab/malware-indicators", "CC BY-NC-SA 4.0 (README)"),
}
# repos parsed by their own step -> MVT index entries pointing there are skipped
OWN_STEP_OWNERS = {"amnestytech": "Amnesty Tech", "assoechap": "Echap"}

KINDS = ("domain", "url", "ip", "email", "process", "file_name", "file_path", "bundle_id",
         "sha256", "sha1", "md5", "profile_id", "cert")
ROLES = ("infra", "c2", "website", "app")
_ROLE_RANK = {"c2": 4, "app": 3, "infra": 2, "website": 1}

# Readable labels for STIX malware names (labels only, never indicators). Unknown names pass through.
THREAT_LABELS = {
    "pegasus": "Pegasus (NSO Group)",
    "predator": "Predator (Intellexa/Cytrox)",
    "operationtriangulation": "Operation Triangulation",
    "kingspawn": "KingSpawn/Reign (QuaDream)",
    "rcslab": "Hermit (RCS Lab)",
    "wyrmspy_dragonegg": "WyrmSpy/DragonEgg (APT41)",
    "candiru": "DevilsTongue (Candiru)",
    "novispy": "NoviSpy (Serbia)",
    "wintego helios": "Helios (Wintego)",
    "mercenaryspywarecampaign": "Mercenary spyware campaign (Amnesty 2023)",
    "eaglemsgspy": "EagleMsgSpy",
    "residentbat": "ResidentBat",
    "cellebrite": "Cellebrite (forensic extraction)",
    "darksword": "DarkSword (iOS exploit kit)",
    "coruna": "Coruna (iOS exploit kit)",
    "morpheus": "Morpheus (IPS)",
    "btmob": "BTMOB RAT",
    "spyrtacus": "Spyrtacus (SIO)",
}

# Big legit platforms on top of ioc_fuzzy.SHARED_DOMAINS: the domain and all its subdomains are never
# stored (a hit on a phone would be a false alarm), whatever a feed says.
LEGIT_DOMAINS = {
    "apple.com", "icloud.com", "icloud-content.com", "me.com", "mac.com", "mzstatic.com", "cdn-apple.com",
    "apple-dns.net", "aaplimg.com", "apple.news", "itunes.com", "apple-cloudkit.com", "push.apple.com",
    "google.com", "google.co.uk", "googlevideo.com", "googlesyndication.com", "doubleclick.net",
    "googletagmanager.com", "google-analytics.com", "android.com", "gmail.com", "goo.gl", "g.co", "youtu.be",
    "amazon.com", "amazon.co.uk", "akamai.net", "akamaihd.net", "akamaiedge.net", "akamaized.net",
    "edgekey.net", "edgesuite.net", "fastly.net", "fastly.com", "cloudflare.net", "azure.com",
    "office.com", "office365.com", "outlook.com", "hotmail.com", "msn.com", "bing.com", "skype.com",
    "whatsapp.com", "whatsapp.net", "facebook.net", "fbcdn.net", "fb.com", "instagram.com", "messenger.com",
    "telegram.me", "signal.org", "t.co", "twimg.com", "bit.ly", "tinyurl.com", "ow.ly", "is.gd",
    "yahoo.com", "wikipedia.org", "tiktok.com", "snapchat.com", "spotify.com", "netflix.com",
    "yandex.net", "yandex.com", "mail.ru", "vk.com", "wechat.com", "weixin.qq.com", "alibaba.com",
    "aliyuncs.com", "paypal.com", "zoom.us", "slack.com", "adobe.com", "digicert.com", "letsencrypt.org",
    "sectigo.com", "godaddy.com", "verisign.com", "example.com", "example.org", "example.net", "localhost",
}
# hosting platforms whose *bare* name must never be an IOC (specific subdomains are fine)
PLATFORM_DOMAINS = {"firebaseio.com", "firebasedatabase.app", "herokuapp.com", "000webhostapp.com",
                    "glitch.me", "repl.co", "ngrok.app", "onrender.com", "fly.dev", "s3.amazonaws.com"}

_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$")
_BUNDLE = re.compile(r"^[a-z0-9_][a-z0-9_-]*(?:\.[a-z0-9_-]+)+$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,63}$")
_HEX = {"md5": 32, "sha1": 40, "sha256": 64}
_COMPARE = re.compile(r"([a-z0-9-]+:[A-Za-z0-9_.'\"-]+)\s*(=|!=|LIKE|MATCHES|IN)\s*'((?:[^'\\]|\\.)*)'")


# ------------------------------------------------------------------ normalisation

def defang(v: str) -> str:
    v = v.strip().strip("\"'").strip()
    v = re.sub(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*\.\s*\}", ".", v, flags=re.I)
    v = re.sub(r"\[\s*:\s*\]", ":", v)
    v = re.sub(r"\[\s*@\s*\]|\[at\]", "@", v, flags=re.I)
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    v = re.sub(r"^(https?)\[?:\]?//", r"\1://", v, flags=re.I)
    return v


def domain_is_legit(d: str) -> bool:
    """Shared hosting / CDN / big legit platform: never stored as a domain IOC."""
    if is_shared_domain(d) or d in PLATFORM_DOMAINS:
        return True
    parts = d.split(".")
    return any(".".join(parts[i:]) in LEGIT_DOMAINS for i in range(len(parts) - 1))


def _ip(v: str) -> str | None:
    v = v.strip("[]")
    if v.endswith(("/32", "/128")):
        v = v.rsplit("/", 1)[0]
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return None
    return str(ip) if ip.is_global and not ip.is_multicast else None


def normalize(kind: str, value: str) -> str | None:
    """Lowercased, defanged, validated value or None (garbage / shared / legit)."""
    if not isinstance(value, str):
        return None
    v = defang(value).lower()
    if not v or len(v) > 2048:
        return None
    if kind == "domain":
        v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v).split("/", 1)[0].split("?", 1)[0]
        v = v.rsplit("@", 1)[-1]
        if v.count(":") == 1:
            v = v.split(":", 1)[0]
        v = v.strip(".")
        while v.startswith("*."):
            v = v[2:]
        if _ip(v):
            return None      # IPs go to the ip kind
        return v if _DOMAIN.match(v) and not domain_is_legit(v) else None
    if kind == "url":
        if "://" not in v and "/" not in v:
            return None      # bare host is not a URL
        host = urllib.parse.urlsplit(v if "://" in v else "http://" + v).hostname or ""
        if not host or (not _ip(host) and not _DOMAIN.match(host)):
            return None
        return v
    if kind == "ip":
        return _ip(v)
    if kind == "email":
        return v if _EMAIL.match(v) else None
    if kind in _HEX:
        v = v.replace(":", "").replace(" ", "")
        return v if len(v) == _HEX[kind] and re.fullmatch(r"[0-9a-f]+", v) else None
    if kind == "cert":
        v = v.replace(":", "").replace(" ", "")
        return v if len(v) in (32, 40, 64) and re.fullmatch(r"[0-9a-f]+", v) else None
    if kind == "bundle_id":
        return v if _BUNDLE.match(v) else None
    if kind in ("process", "file_name", "file_path", "profile_id"):
        return v if len(v) >= 2 and "\n" not in v else None
    return None


def threat_label(name: str | None) -> str:
    n = (name or "").strip()
    return THREAT_LABELS.get(n.lower(), n.replace("_", "/")) if n else ""


# ------------------------------------------------------------------ STIX2

def _stix_kind(path: str) -> str | None:
    obj, _, prop = path.partition(":")
    prop = prop.replace("'", "").replace('"', "").lower()
    if obj == "domain-name" and prop == "value":
        return "domain"
    if obj == "url" and prop == "value":
        return "url"
    if obj in ("ipv4-addr", "ipv6-addr") and prop == "value":
        return "ip"
    if obj == "email-addr" and prop == "value":
        return "email"
    if obj == "process" and prop == "name":
        return "process"
    if obj == "file" and prop == "name":
        return "file_name"
    if obj == "file" and prop == "path":
        return "file_path"
    if obj == "app" and prop == "id":
        return "bundle_id"
    if obj == "configuration-profile" and prop == "id":
        return "profile_id"
    if obj in ("app", "x509-certificate") and (prop.startswith("cert.") or prop.startswith("hashes.")):
        return "cert"
    if obj in ("file", "artifact") and prop.startswith("hashes."):
        algo = prop.split(".", 1)[1].replace("-", "")
        return algo if algo in _HEX else None
    return None                  # android-property, windows-registry-key, …


def parse_stix_pattern(pattern: str) -> list[tuple[str, str]]:
    """Every equality comparison of a STIX pattern (OR/AND combined too) -> [(kind, normalised value)]."""
    out = []
    for path, op, val in _COMPARE.findall(pattern or ""):
        if op != "=":
            continue             # LIKE/MATCHES/!= are not exact indicators
        kind = _stix_kind(path)
        if not kind:
            continue
        val = val.replace("\\'", "'").replace("\\\\", "\\")
        if kind == "domain" and _ip(defang(val).lower()):
            kind = "ip"          # some bundles list IPs as domain-name
        v = normalize(kind, val)
        if v:
            out.append((kind, v))
    return out


def parse_stix2(data: bytes | str | dict, default_threat: str = "") -> list[tuple[str, str, str]]:
    """STIX2 bundle -> [(kind, value, threat)]. Threat via 'indicates' relationship -> malware/tool name;
    a bundle with one malware object uses it for unlinked indicators; else default_threat."""
    doc = data if isinstance(data, dict) else json.loads(data)
    objs = doc.get("objects", []) if isinstance(doc, dict) else []
    names = {o["id"]: o.get("name", "") for o in objs if isinstance(o, dict) and "id" in o
             and o.get("type") in ("malware", "tool", "threat-actor", "intrusion-set", "campaign")}
    rel: dict[str, str] = {}
    for o in objs:
        if isinstance(o, dict) and o.get("type") == "relationship" and o.get("target_ref") in names:
            rel.setdefault(o.get("source_ref", ""), names[o["target_ref"]])
    only = next(iter(names.values())) if len(names) == 1 else ""
    out = []
    for o in objs:
        if not isinstance(o, dict) or o.get("type") != "indicator":
            continue
        if o.get("pattern_type", "stix") != "stix" or o.get("revoked"):
            continue
        name = rel.get(o.get("id", "")) or only
        threat = threat_label(name) or default_threat or threat_label(o.get("name"))
        if not threat:
            continue
        for kind, v in parse_stix_pattern(o.get("pattern", "")):
            out.append((kind, v, threat))
    return out


# ------------------------------------------------------------------ MVT index (indicators.yaml)

def parse_mvt_index(text: str) -> list[dict]:
    """Minimal reader of mvt-indicators' indicators.yaml (no PyYAML): one dict per '-' entry with
    name/type/owner/repo/branch/path/download_url."""
    entries: list[dict] = []
    cur: dict | None = None
    for line in text.splitlines():
        s = line.split(" #", 1)[0].rstrip()
        if not s.strip() or s.lstrip().startswith("#"):
            continue
        if re.match(r"^\s{0,4}-\s*$", s) or re.match(r"^\s{0,2}-\s+\w+\s*:", s):
            cur = {}
            entries.append(cur)
            s = s.replace("-", " ", 1)
        m = re.match(r"^\s*(name|type|owner|repo|branch|path|download_url|url)\s*:\s*(.+)$", s)
        if m and cur is not None:
            cur.setdefault(m.group(1), m.group(2).strip().strip("\"'"))
    return [e for e in entries if e.get("path") or e.get("download_url") or e.get("url")]


def _index_threat(name: str) -> str:
    return re.sub(r"\s*indicators of compromise\s*$", "", name or "", flags=re.I).strip()


# ------------------------------------------------------------------ Echap stalkerware-indicators

def parse_echap_yaml(text: str) -> list[dict]:
    """ioc.yaml -> [{name, type, packages, certificates, websites, distribution, c2_domains, c2_ips}]."""
    apps: list[dict] = []
    cur: dict | None = None
    key = sub = None
    for raw in text.splitlines():
        line = re.sub(r"\s+#.*$", "", raw).rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^-\s+name\s*:\s*(.+)$", line)
        if m:
            cur = {"name": m.group(1).strip().strip("\"'")}
            apps.append(cur)
            key = sub = None
            continue
        if cur is None:
            continue
        m = re.match(r"^ {2}([A-Za-z0-9_]+)\s*:\s*(.*)$", line)
        if m:
            key, sub = m.group(1), None
            if m.group(2):
                cur[key] = m.group(2).strip().strip("\"'")
            continue
        m = re.match(r"^ {4,}([A-Za-z0-9_]+)\s*:\s*$", line)
        if m:
            sub = m.group(1)
            continue
        m = re.match(r"^\s*-\s+(.+)$", line)
        if m and key:
            name = f"{key}_{sub}" if sub else key
            v = cur.setdefault(name, [])
            if isinstance(v, list):
                v.append(m.group(1).strip().strip("\"'"))
    for a in apps:
        a["c2_ips"] = a.pop("c2_ips", []) + a.pop("c2_ip", [])
    return apps


def echap_rows(apps: list[dict]) -> list[tuple[str, str, str, str]]:
    """Parsed ioc.yaml -> [(kind, value, threat, role)]; only type 'stalkerware'."""
    out = []
    for a in apps:
        if a.get("type", "stalkerware") != "stalkerware" or not a.get("name"):
            continue
        threat = f"Stalkerware: {a['name']}"
        for kind, field, role in (("bundle_id", "packages", "app"), ("cert", "certificates", "app"),
                                  ("domain", "websites", "website"), ("domain", "distribution", "website"),
                                  ("domain", "c2_domains", "c2"), ("ip", "c2_ips", "c2")):
            for v in a.get(field) or []:
                if kind == "domain" and _ip(defang(v).lower()):
                    k = "ip"
                else:
                    k = kind
                n = normalize(k, v)
                if n:
                    out.append((k, n, threat, role))
    return out


def parse_echap(text: str) -> list[tuple[str, str, str, str]]:
    return echap_rows(parse_echap_yaml(text))


# ------------------------------------------------------------------ plain lists / csv

def parse_plain_list(text: str, kind: str, threat: str) -> list[tuple[str, str, str]]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        v = normalize(kind, line) if line else None
        if v:
            out.append((kind, v, threat))
    return out


def parse_amnesty_csv(text: str, threat: str) -> list[tuple[str, str, str]]:
    """Amnesty 'domain_name,ip_address' csv: domains only (the VPS IPs are years old, re-assigned)."""
    out = []
    for row in csv.DictReader(io.StringIO(text)):
        v = normalize("domain", row.get("domain_name") or row.get("domain") or "")
        if v:
            out.append(("domain", v, threat))
    return out


def parse_misp_csv(text: str, threat: str) -> list[tuple[str, str, str]]:
    """Citizen Lab MISP-style csv (category,type,value,…): domains, URLs, emails, hashes.
    ip-dst rows are skipped: 2016 cloud IPs have long been re-assigned (false positives)."""
    types = {"domain": "domain", "hostname": "domain", "url": "url", "email-src": "email", "email-dst": "email",
             "sha256": "sha256", "sha1": "sha1", "md5": "md5"}
    out = []
    for row in csv.DictReader(io.StringIO(text)):
        kind = types.get((row.get("type") or "").strip())
        if not kind or str(row.get("to_ids", "1")).strip() == "0":
            continue
        v = normalize(kind, row.get("value") or "")
        if v:
            out.append((kind, v, threat))
    return out


# ------------------------------------------------------------------ download / cache

def _get(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": config.USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _cached(url: str, name: str, max_age_h: float, log: Log, offline: bool = False) -> str:
    dest = os.path.join(config.FEEDS, name)
    if offline:
        if not os.path.exists(dest):
            raise RuntimeError(f"brak {name} w pamięci podręcznej (tryb offline)")
        return dest
    if not os.path.exists(dest) or time.time() - os.path.getmtime(dest) > max_age_h * 3600:
        os.makedirs(config.FEEDS, exist_ok=True)
        log(f"    pobieranie {name} …")
        data = _get(url, timeout=300)
        with open(dest + ".part", "wb") as fh:
            fh.write(data)
        os.replace(dest + ".part", dest)
    return dest


def _fetched(path: str) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(path)))


def _zip_root(z: zipfile.ZipFile) -> str:
    first = z.namelist()[0]
    return first.split("/", 1)[0] + "/"


Rows = list  # [(kind, value, threat, role)]


def import_mvt(log: Log, offline: bool) -> tuple[Rows, str]:
    path = _cached(MVT_ZIP, "ios_mvt-indicators.zip", 12, log, offline)
    rows: Rows = []
    with zipfile.ZipFile(path) as z:
        root = _zip_root(z)
        entries = parse_mvt_index(z.read(root + "indicators.yaml").decode("utf-8", "replace"))
        for e in entries:
            owner = e.get("owner", "").lower()
            if owner in OWN_STEP_OWNERS:
                continue                                 # parsed by the Amnesty / Echap step
            default = _index_threat(e.get("name", ""))
            try:
                if owner == "mvt-project" and e.get("repo") == "mvt-indicators":
                    data = z.read(root + e["path"])
                else:                                    # bundle hosted elsewhere: fetch it raw
                    url = e.get("download_url") or e.get("url") or RAW.format(
                        owner=e.get("owner"), repo=e.get("repo"), branch=e.get("branch", "main"), path=e["path"])
                    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", url.split("://", 1)[-1])[-120:]
                    with open(_cached(url, "ios_ext_" + safe, 12, log, offline), "rb") as fh:
                        data = fh.read()
                got = parse_stix2(data, default)
                rows += [(k, v, t, "infra") for k, v, t in got]
            except Exception as exc:  # noqa: BLE001
                log(f"    MVT {e.get('path') or e.get('download_url')}: pominięto ({exc!r})")
    return rows, _fetched(path)


def import_amnesty(log: Log, offline: bool) -> tuple[Rows, str]:
    path = _cached(AMNESTY_ZIP, "ios_amnesty-investigations.zip", 12, log, offline)
    rows: Rows = []
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        bundle_dirs = {os.path.dirname(n) for n in names if n.endswith((".stix2", ".stix"))}
        for n in names:
            try:
                if n.endswith((".stix2", ".stix")):
                    rows += [(k, v, t, "infra") for k, v, t in parse_stix2(z.read(n))]
                elif os.path.dirname(n) not in bundle_dirs and re.search(r"_nso[_/]", n):
                    # older NSO/Pegasus investigations published only as plain lists
                    text = z.read(n).decode("utf-8", "replace")
                    if n.endswith("/domains.txt"):
                        rows += [(k, v, t, "infra") for k, v, t in parse_plain_list(text, "domain", THREAT_LABELS["pegasus"])]
                    elif n.endswith("/indicators.csv"):
                        rows += [(k, v, t, "infra") for k, v, t in parse_amnesty_csv(text, THREAT_LABELS["pegasus"])]
            except Exception as exc:  # noqa: BLE001
                log(f"    Amnesty {n}: pominięto ({exc!r})")
    return rows, _fetched(path)


def import_echap(log: Log, offline: bool) -> tuple[Rows, str]:
    path = _cached(ECHAP_ZIP, "ios_echap-stalkerware.zip", 12, log, offline)
    with zipfile.ZipFile(path) as z:
        text = z.read(_zip_root(z) + "ioc.yaml").decode("utf-8", "replace")
    return parse_echap(text), _fetched(path)


def import_citizenlab(log: Log, offline: bool) -> tuple[Rows, str]:
    path = _cached(CITIZENLAB_NSO, "ios_citizenlab-nso-2016.csv", 24 * 7, log, offline)
    with open(path, encoding="utf-8", errors="replace") as fh:
        got = parse_misp_csv(fh.read(), THREAT_LABELS["pegasus"])
    return [(k, v, t, "infra") for k, v, t in got], _fetched(path)


SOURCES = [("MVT", import_mvt), ("Amnesty Tech", import_amnesty), ("Echap", import_echap),
           ("Citizen Lab", import_citizenlab)]


# ------------------------------------------------------------------ DB build

SCHEMA = """
CREATE TABLE ioc(kind TEXT NOT NULL, value TEXT NOT NULL, threat TEXT NOT NULL, source TEXT NOT NULL,
                 role TEXT NOT NULL DEFAULT 'infra', PRIMARY KEY(kind, value, threat, source)) WITHOUT ROWID;
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE sources(name TEXT PRIMARY KEY, url TEXT, license TEXT, fetched TEXT, counts TEXT, note TEXT);
"""


def build_db(path: str, rows_by_source: dict, source_info: dict | None = None) -> dict:
    """Write rows {source: [(kind, value, threat, role)]} into a fresh sqlite at path+'.new', swap it in.
    Duplicates of one (kind, value, threat, source) keep the strongest role."""
    tmp = path + ".new"
    for ext in ("", "-journal", "-wal", "-shm"):
        if os.path.exists(tmp + ext):
            os.remove(tmp + ext)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    con = sqlite3.connect(tmp)
    con.executescript(SCHEMA)
    source_info = source_info or {}
    for src, rows in rows_by_source.items():
        best: dict = {}
        for kind, value, threat, role in rows:
            if kind not in KINDS or role not in ROLES or not value or not threat:
                continue
            k = (kind, value, threat)
            if k not in best or _ROLE_RANK[role] > _ROLE_RANK[best[k]]:
                best[k] = role
        con.executemany("INSERT INTO ioc VALUES (?,?,?,?,?)",
                        [(k, v, t, src, r) for (k, v, t), r in best.items()])
        counts: dict = {}
        for (k, _v, _t) in best:
            counts[k] = counts.get(k, 0) + 1
        url, lic = SOURCE_META.get(src, ("", ""))
        info = source_info.get(src, {})
        con.execute("INSERT INTO sources VALUES (?,?,?,?,?,?)",
                    (src, info.get("url", url), info.get("license", lic), info.get("fetched", ""),
                     json.dumps(dict(sorted(counts.items()))), info.get("note", "")))
    con.executemany("INSERT INTO meta VALUES (?,?)", [("built", time.strftime("%Y-%m-%d %H:%M:%S")),
                                                      ("version", DB_VERSION)])
    con.commit()
    con.close()
    os.replace(tmp, path)
    return IOSIndicators(path).stats()


def _old_rows(path: str, source: str) -> tuple[Rows, str]:
    """Rows of one source from the current DB (kept when that source fails to update)."""
    if not os.path.exists(path):
        return [], ""
    try:
        con = sqlite3.connect(f"file:{urllib.parse.quote(path)}?mode=ro", uri=True)
        rows = con.execute("SELECT kind, value, threat, role FROM ioc WHERE source=?", (source,)).fetchall()
        f = con.execute("SELECT fetched FROM sources WHERE name=?", (source,)).fetchone()
        con.close()
        return [tuple(r) for r in rows], (f[0] if f else "")
    except sqlite3.Error:
        return [], ""


def update_ios_indicators(log: Log = print, offline: bool = False, path: str | None = None) -> dict:
    """Download (or, offline, reuse cached downloads), parse every source and rebuild ios_ioc.sqlite.
    A failing source keeps its rows from the previous DB; nothing is replaced if every source is empty."""
    path = path or IOS_IOCDB
    rows_by_source: dict = {}
    info: dict = {}
    errors: dict = {}
    for name, fn in SOURCES:
        try:
            rows, fetched = fn(log, offline)
            rows_by_source[name] = rows
            info[name] = {"fetched": fetched}
            log(f"  iOS {name}: {len(rows):,} wskaźników")
        except Exception as exc:  # noqa: BLE001
            errors[name] = repr(exc)
            old, fetched = _old_rows(path, name)
            log(f"  BŁĄD iOS {name}: {exc!r}" + (f" – zachowano {len(old):,} wskaźników z poprzedniej bazy" if old else ""))
            if old:
                rows_by_source[name] = old
                info[name] = {"fetched": fetched, "note": f"z poprzedniej bazy (błąd aktualizacji: {exc!r})"[:300]}
    if not any(rows_by_source.values()):
        log("  BŁĄD iOS: żadne źródło nie dało wskaźników – baza nie została zmieniona")
        res = IOSIndicators(path).stats()
        res["errors"] = errors
        return res
    res = build_db(path, rows_by_source, info)
    res["errors"] = errors
    log(f"  iOS: {res['total']:,} wskaźników w {os.path.basename(path)} "
        f"({', '.join(f'{k}={v}' for k, v in res['kinds'].items())})")
    return res


# ------------------------------------------------------------------ read-only lookup API

class IOSIndicators:
    """Read-only access to ios_ioc.sqlite. Safe when the DB is missing (available=False, empty results)."""

    def __init__(self, path: str | None = None):
        self.path = path or IOS_IOCDB
        self.available = False
        self._con = None
        if os.path.exists(self.path):
            try:
                self._con = sqlite3.connect(f"file:{urllib.parse.quote(self.path)}?mode=ro", uri=True,
                                            check_same_thread=False)
                self._con.execute("SELECT 1 FROM ioc LIMIT 1").fetchall()
                self.available = True
            except sqlite3.Error:
                self._con = None

    def close(self) -> None:
        if self._con is not None:
            self._con.close()
            self._con = None
            self.available = False

    def _query(self, kind: str, values: list[str]) -> list[dict]:
        if not self.available or not values:
            return []
        vals = list(dict.fromkeys(values))
        q = f"SELECT kind, value, threat, source, role FROM ioc WHERE kind=? AND value IN ({','.join('?' * len(vals))})"
        try:
            rows = self._con.execute(q, (kind, *vals)).fetchall()
        except sqlite3.Error:
            return []
        return [dict(zip(("kind", "value", "threat", "source", "role"), r)) for r in rows]

    def lookup(self, kind: str, value: str) -> list[dict]:
        v = (value or "").strip().lower()
        if kind == "domain":
            v = v.rstrip(".")
        return self._query(kind, [v]) if v else []

    def match_domain(self, host: str) -> list[dict]:
        h = (host or "").strip().lower().rstrip(".")
        if h.startswith("[") and "]" in h:
            h = h[1:h.index("]")]
        elif h.count(":") == 1:
            h = h.split(":", 1)[0]
        if not h:
            return []
        ip = _ip(h)
        if ip or re.fullmatch(r"[0-9a-f:.]+", h) and (":" in h or h.count(".") == 3):
            return self._query("ip", [ip or h])
        parts = h.split(".")
        return self._query("domain", [".".join(parts[i:]) for i in range(max(1, len(parts) - 1))])

    def match_url(self, url: str) -> list[dict]:
        u = (url or "").strip().lower()
        if not u:
            return []
        u = u.split("#", 1)[0]
        bare = re.sub(r"^[a-z][a-z0-9+.-]*://", "", u)
        cands = []
        for b in (bare, bare.rstrip("/"), bare.rstrip("/") + "/"):
            cands += [b, "http://" + b, "https://" + b]
        if "?" in bare:
            base = bare.split("?", 1)[0].rstrip("/")
            cands += [base, base + "/", "http://" + base, "https://" + base, "http://" + base + "/",
                      "https://" + base + "/"]
        out = self._query("url", [u] + cands)
        try:
            host = urllib.parse.urlsplit("http://" + bare).hostname or ""
        except ValueError:
            host = ""
        seen = {(r["kind"], r["value"], r["threat"], r["source"]) for r in out}
        for r in self.match_domain(host):
            if (r["kind"], r["value"], r["threat"], r["source"]) not in seen:
                out.append(r)
        return out

    def stats(self) -> dict:
        res: dict = {"total": 0, "built": "", "kinds": {}, "sources": []}
        if not self.available:
            return res
        try:
            con = self._con
            res["kinds"] = dict(con.execute("SELECT kind, COUNT(*) FROM ioc GROUP BY kind ORDER BY kind").fetchall())
            res["total"] = sum(res["kinds"].values())
            row = con.execute("SELECT value FROM meta WHERE key='built'").fetchone()
            res["built"] = row[0] if row else ""
            for name, url, lic, fetched, counts, note in con.execute(
                    "SELECT name, url, license, fetched, counts, note FROM sources ORDER BY name"):
                try:
                    c = json.loads(counts or "{}")
                except ValueError:
                    c = {}
                res["sources"].append({"name": name, "url": url, "license": lic, "fetched": fetched,
                                       "counts": c, "note": note or ""})
        except sqlite3.Error:
            pass
        return res


# ------------------------------------------------------------------ CLI

def format_table(st: dict) -> str:
    kinds = [k for k in KINDS if any(s["counts"].get(k) for s in st.get("sources", []))]
    head = ["źródło"] + kinds + ["razem"]
    lines = [head]
    for s in st.get("sources", []):
        lines.append([s["name"]] + [str(s["counts"].get(k, 0)) for k in kinds] + [str(sum(s["counts"].values()))])
    lines.append(["razem"] + [str(st["kinds"].get(k, 0)) for k in kinds] + [str(st.get("total", 0))])
    w = [max(len(r[i]) for r in lines) for i in range(len(head))]
    out = ["  ".join(c.ljust(w[i]) if i == 0 else c.rjust(w[i]) for i, c in enumerate(r)) for r in lines]
    out.insert(1, "-" * len(out[0]))
    out.insert(len(out) - 1, "-" * len(out[0]))
    for s in st.get("sources", []):
        out.append(f"{s['name']}: {s['url']} | licencja: {s['license']} | pobrano: {s['fetched']}"
                   + (f" | {s['note']}" if s.get("note") else ""))
    return "\n".join(out)


def main(argv=None) -> int:
    """python -m cerber.feeds_ios [--offline]   rebuild only the iOS indicator DB."""
    import argparse
    ap = argparse.ArgumentParser(prog="python -m cerber.feeds_ios",
                                 description="pobierz i zbuduj bazę wskaźników szpiegostwa iOS (ios_ioc.sqlite)")
    ap.add_argument("--offline", action="store_true", help="bez sieci: przebuduj z pobranych wcześniej plików")
    a = ap.parse_args(argv)
    config.ensure_dirs()
    print("[iOS]")
    st = update_ios_indicators(print, offline=a.offline)
    if st.get("total"):
        print(format_table(st))
    return 0 if st.get("total") else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""IOC lookup service (URLhaus/ThreatFox) and TLSH similarity engine (MalwareBazaar)."""
from __future__ import annotations

import os
import re
import sqlite3
import threading

from ..core import Confidence, Detection, ScanContext, ScanObject
from ..pipeline import Engine
from .hashdb import HashDB

try:
    import tlsh
except ImportError:  # pragma: no cover
    tlsh = None


# Shared hosting / CDN / platform domains: a malicious URL hosted there says nothing about the
# domain as a whole, so domain-level IOC hits on them are ignored (exact URL hits still count).
SHARED_DOMAINS = {
    "github.com", "githubusercontent.com", "github.io", "gitlab.com", "gitlab.io", "bitbucket.org",
    "sourceforge.net", "codeberg.org", "gitee.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "cloudflare.com", "cloudflare-ipfs.com", "workers.dev", "pages.dev", "r2.dev", "trycloudflare.com",
    "amazonaws.com", "cloudfront.net", "azureedge.net", "azurewebsites.net", "windows.net", "blob.core.windows.net",
    "googleapis.com", "googleusercontent.com", "google.com", "gstatic.com", "appspot.com", "firebaseapp.com",
    "firebasestorage.app", "web.app", "discord.com", "discordapp.com", "discordapp.net", "dropbox.com",
    "dropboxusercontent.com", "1drv.ms", "onedrive.live.com", "live.com", "microsoft.com", "sharepoint.com",
    "apple.com", "icloud.com", "mozilla.org", "npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org",
    "cloudinary.com", "imgur.com", "archive.org", "mediafire.com", "mega.nz", "wetransfer.com", "box.com",
    "pastebin.com", "paste.ee", "telegram.org", "t.me", "vercel.app", "netlify.app", "herokuapp.com",
    "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "000webhostapp.com", "ngrok.io",
    "ngrok-free.app", "duckdns.org", "no-ip.com", "ddns.net", "hopto.org", "zapto.org", "youtube.com",
    "facebook.com", "twitter.com", "x.com", "linkedin.com", "yandex.ru", "baidu.com", "qq.com",
}


def is_shared_domain(d: str) -> bool:
    d = d.lower().rstrip(".")
    parts = d.split(".")
    return any(".".join(parts[i:]) in SHARED_DOMAINS for i in range(len(parts) - 1))


class IocService:
    """services.ioc.lookup(kind, value) -> threat label or None. kind: url | domain | ip | hash."""

    def __init__(self, path: str):
        self.path = path
        self._local = threading.local()

    def _con(self):
        con = getattr(self._local, "con", None)
        if con is None or getattr(self._local, "pid", None) != os.getpid():
            con = sqlite3.connect(f"file:{self.path}?mode=ro&immutable=1", uri=True, check_same_thread=False)
            self._local.con, self._local.pid = con, os.getpid()
        return con

    def lookup(self, kind: str, value: str) -> str | None:
        v = value.strip().lower()
        if not v:
            return None
        if kind == "domain" and is_shared_domain(v):
            return None
        con = self._con()
        row = con.execute("SELECT threat FROM ioc WHERE kind=? AND value=?", (kind, v)).fetchone()
        if row:
            return row[0]
        if kind == "url":
            # try without trailing slash / query
            base = re.sub(r"[?#].*$", "", v).rstrip("/")
            if base != v:
                row = con.execute("SELECT threat FROM ioc WHERE kind='url' AND value IN (?,?)",
                                  (base, base + "/")).fetchone()
                if row:
                    return row[0]
        if kind == "domain":
            if is_shared_domain(v):
                return None
            parts = v.split(".")
            for i in range(1, max(1, len(parts) - 1)):  # parent domains (not bare TLD)
                row = con.execute("SELECT threat FROM ioc WHERE kind='domain' AND value=?",
                                  (".".join(parts[i:]),)).fetchone()
                if row:
                    return row[0]
        return None

    def count(self) -> int:
        try:
            return self._con().execute("SELECT COUNT(*) FROM ioc").fetchone()[0]
        except sqlite3.Error:
            return 0


def tlsh_lval(t: str) -> int | None:
    t = t.strip()
    if t.startswith("T1"):
        t = t[2:]
    try:
        return int(t[2:4][::-1], 16)
    except ValueError:
        return None


# Executables only: MalwareBazaar contains many trojanized copies of legitimate scripts/packages
# (pip, npm modules…) that are near-identical to the clean originals, so TLSH on text causes FPs.
FUZZY_TYPES = {"pe", "elf", "macho", "dex", "java_class"}


class FuzzyEngine(Engine):
    """TLSH nearest-neighbour search against MalwareBazaar samples (deep mode only).

    Distance <= 30: near-identical variant; <= 50: same family likely. Only
    raises suspicion (HIGH/MEDIUM), never a final verdict on its own."""
    name = "fuzzy"

    def __init__(self, db: HashDB, strong: int = 30, weak: int = 50, max_candidates: int = 400_000):
        self.db = db
        self.strong = strong
        self.weak = weak
        self.max_candidates = max_candidates

    def scan(self, obj: ScanObject, ctx: ScanContext) -> None:
        if tlsh is None or not ctx.deep or obj.ftype not in FUZZY_TYPES or obj.size < 512:
            return
        if any(d.confidence == Confidence.CERTAIN for d in obj.detections):
            return
        h = tlsh.hash(obj.data)
        if not h or h == "TNULL":
            return
        obj.meta["tlsh"] = h
        lv = tlsh_lval(h)
        if lv is None:
            return
        best = (10**9, None, None)
        n = 0
        for cand, name in self.db.tlsh_candidates(lv, 1):
            d = tlsh.diff(h, cand)
            if d < best[0]:
                best = (d, name, cand)
                if d == 0:
                    break
            n += 1
            if n >= self.max_candidates:
                break
        dist, name, cand = best
        if name is None or dist > self.weak:
            return
        generic = name.lower().startswith(("generic.", "unknown")) or name in ("n/a", "")
        # TLSH neighbours are ambiguous: file infectors and trojanized installers are near-identical
        # to the clean originals, and static Go/Rust/musl binaries share most of their bytes with any
        # other program built the same way. Similarity is therefore only a supporting hint that can
        # never produce a verdict on its own (max 20 < SUSPICIOUS threshold).
        if generic:
            if dist <= 15:
                ctx.detect(obj, Detection(f"Fuzzy:TLSH.{name}", "fuzzy", Confidence.LOW, 5,
                                          f"Near-identical (TLSH {dist}) to an unclassified MalwareBazaar sample",
                                          [f"nearest={cand}"]))
            return
        conf, score = (Confidence.MEDIUM, 20) if dist <= 20 else (Confidence.LOW, 8)
        ctx.detect(obj, Detection(f"Fuzzy:TLSH.{name}", "fuzzy", conf, score,
                                  f"Similar (TLSH distance {dist}) to a MalwareBazaar {name} sample "
                                  f"(supporting evidence only)", [f"nearest={cand}"]))

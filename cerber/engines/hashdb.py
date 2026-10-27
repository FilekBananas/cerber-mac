"""Hash signature database (SQLite): whole-file hashes, PE-section hashes, whitelist.

Tables (WITHOUT ROWID, digest stored as raw bytes – length tells the algorithm):
    file(digest, size, name, src, pua)      MD5 / SHA1 / SHA256 of whole files
    section(digest, size, name, pua)        ClamAV .mdb/.msb: hash of one PE section
    fp(digest, size, name)                  known-good / false-positive whitelist
    tlsh(tlsh, lval, name)                  fuzzy hashes of known malware (deep mode)
    source(name, version, count, updated)   provenance
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from typing import Iterable

from ..core import Confidence, Detection, ScanContext, ScanObject
from ..pipeline import Engine

SRC_CLAMAV, SRC_BAZAAR, SRC_SIGBASE, SRC_CUSTOM, SRC_OTHER = 1, 2, 3, 4, 5
SRC_MACOS = 6
SRC_NAMES = {SRC_CLAMAV: "ClamAV", SRC_BAZAAR: "MalwareBazaar", SRC_SIGBASE: "signature-base",
             SRC_CUSTOM: "Custom", SRC_OTHER: "Feed", SRC_MACOS: "macOS-feeds"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS file(digest BLOB PRIMARY KEY, size INTEGER, name TEXT, src INTEGER, pua INTEGER) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS section(digest BLOB, size INTEGER, name TEXT, pua INTEGER, PRIMARY KEY(digest, size)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS fp(digest BLOB PRIMARY KEY, size INTEGER, name TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS tlsh(tlsh TEXT PRIMARY KEY, lval INTEGER, name TEXT) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS tlsh_lval ON tlsh(lval);
CREATE TABLE IF NOT EXISTS source(name TEXT PRIMARY KEY, version TEXT, count INTEGER, updated TEXT);
"""


class HashDB:
    def __init__(self, path: str, readonly: bool = True):
        self.path = path
        self.readonly = readonly
        self._local = threading.local()
        if not readonly:
            con = self._con()
            con.executescript(SCHEMA)
            con.commit()

    def _con(self) -> sqlite3.Connection:
        con = getattr(self._local, "con", None)
        pid = os.getpid()
        if con is None or getattr(self._local, "pid", None) != pid:  # never share across fork
            if self.readonly:
                con = sqlite3.connect(f"file:{self.path}?mode=ro&immutable=1", uri=True, check_same_thread=False)
            else:
                con = sqlite3.connect(self.path, check_same_thread=False)
                con.execute("PRAGMA journal_mode=OFF")
                con.execute("PRAGMA synchronous=OFF")
            con.execute("PRAGMA cache_size=-65536")
            self._local.con, self._local.pid = con, pid
        return con

    # --------------------------------------------------------------- writing
    def add_file_hashes(self, rows: Iterable[tuple[bytes, int | None, str, int, int]], replace=False) -> int:
        verb = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
        con = self._con()
        cur = con.executemany(f"{verb} INTO file VALUES (?,?,?,?,?)", rows)
        con.commit()
        return cur.rowcount

    def add_section_hashes(self, rows: Iterable[tuple[bytes, int, str, int]]) -> int:
        con = self._con()
        cur = con.executemany("INSERT OR IGNORE INTO section VALUES (?,?,?,?)", rows)
        con.commit()
        return cur.rowcount

    def add_fp(self, rows: Iterable[tuple[bytes, int | None, str]]) -> int:
        con = self._con()
        cur = con.executemany("INSERT OR IGNORE INTO fp VALUES (?,?,?)", rows)
        con.commit()
        return cur.rowcount

    def add_tlsh(self, rows: Iterable[tuple[str, int, str]]) -> int:
        con = self._con()
        cur = con.executemany("INSERT OR IGNORE INTO tlsh VALUES (?,?,?)", rows)
        con.commit()
        return cur.rowcount

    def delete_source(self, src: int) -> None:
        con = self._con()
        con.execute("DELETE FROM file WHERE src=?", (src,))
        con.commit()

    def set_source(self, name: str, version: str, count: int, updated: str) -> None:
        con = self._con()
        con.execute("INSERT OR REPLACE INTO source VALUES (?,?,?,?)", (name, version, count, updated))
        con.commit()

    # --------------------------------------------------------------- reading
    def lookup_file(self, digests: list[bytes], size: int) -> list[tuple[str, int, int]]:
        q = f"SELECT name, src, pua, size FROM file WHERE digest IN ({','.join('?' * len(digests))})"
        out = []
        for name, src, pua, sz in self._con().execute(q, digests):
            if sz is None or sz == size:
                out.append((name, src, pua))
        return out

    def is_fp(self, digests: list[bytes], size: int) -> str | None:
        q = f"SELECT name, size FROM fp WHERE digest IN ({','.join('?' * len(digests))})"
        for name, sz in self._con().execute(q, digests):
            if sz is None or sz == size:
                return name
        return None

    def lookup_sections(self, pairs: list[tuple[bytes, int]]) -> list[tuple[str, int]]:
        out = []
        con = self._con()
        for digest, size in pairs:
            for name, pua in con.execute("SELECT name, pua FROM section WHERE digest=? AND size=?", (digest, size)):
                out.append((name, pua))
        return out

    def tlsh_candidates(self, lval: int, spread: int = 2):
        return self._con().execute("SELECT tlsh, name FROM tlsh WHERE lval BETWEEN ? AND ?",
                                   (lval - spread, lval + spread))

    def counts(self) -> dict[str, int]:
        con = self._con()
        out = {}
        for t in ("file", "section", "fp", "tlsh"):
            try:
                out[t] = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            except sqlite3.Error:
                out[t] = 0
        return out

    def sources(self) -> list[tuple]:
        try:
            return list(self._con().execute("SELECT name, version, count, updated FROM source ORDER BY name"))
        except sqlite3.Error:
            return []


class HashEngine(Engine):
    name = "hash"

    def __init__(self, db: HashDB, fp_sha256: set[str] | None = None):
        self.db = db
        self.fp_sha256 = fp_sha256 or set()

    def scan(self, obj: ScanObject, ctx: ScanContext) -> None:
        if obj.sha256 in self.fp_sha256:
            obj.meta["clamav_fp"] = "calibration"
            if obj.parent is None:
                obj.meta["whitelisted"] = "calibration (clean Apple system file)"
            return
        md5 = bytes.fromhex(obj.md5)
        sha1 = bytes.fromhex(obj.sha1)
        sha256 = bytes.fromhex(obj.sha256)
        digests = [md5, sha1, sha256]
        fp = self.db.is_fp(digests, obj.size)
        if fp:
            obj.meta["clamav_fp"] = fp
            if obj.parent is None:
                obj.meta["whitelisted"] = fp
            return
        for name, src, pua in self.db.lookup_file(digests, obj.size):
            label = SRC_NAMES.get(src, "Hash")
            ctx.detect(obj, Detection(f"{label}:{name}", "hash", Confidence.CERTAIN, 100,
                                      f"Exact hash match in the {label} database", pua=bool(pua)))
        if obj.ftype == "pe":
            from .clamav import get_exe
            exe = get_exe(obj)
            if exe is not None and exe.sections:
                pairs = []
                for s in exe.sections[:64]:
                    if s.raw_size and s.raw_off + s.raw_size <= obj.size:
                        chunk = obj.data[s.raw_off:s.raw_off + s.raw_size]
                        pairs.append((hashlib.md5(chunk).digest(), s.raw_size))
                        pairs.append((hashlib.sha256(chunk).digest(), s.raw_size))
                        pairs.append((hashlib.sha1(chunk).digest(), s.raw_size))
                for name, pua in self.db.lookup_sections(pairs):
                    ctx.detect(obj, Detection(f"ClamAV:{name}", "hash", Confidence.CERTAIN, 100,
                                              "PE section hash match (ClamAV .mdb)", pua=bool(pua)))

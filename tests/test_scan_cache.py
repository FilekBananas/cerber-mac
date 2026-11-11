"""Scan memory ("already scanned and clean" cache, cerber/scancache.py) – offline.

* a hit only while the file is provably unchanged: content, touch (even back to the same mtime), chmod and rename
  all invalidate the row (ctime / path);
* a different context fingerprint (databases, calibration, code, level, size limit) invalidates everything;
* rows with a bad HMAC, from another key or with a forged identity are ignored; rows expire after 30 days;
* infection hotspots, Mach-O programs and scripts outside /Applications and /System are never cached;
* only complete CLEAN results are recorded; the parent's merge re-checks every row against the disk.

    .venv/bin/python -m unittest tests.test_scan_cache -v
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerber import config, scancache, scanner  # noqa: E402
from cerber.scanner import ScanOptions  # noqa: E402

FP = bytes(range(16))
FP2 = bytes(range(1, 17))
DAY = 86400
REG = stat.S_IFREG


class CacheTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cerber-scancache-test-")
        self.cache_dir = os.path.join(self.tmp, "scancache")
        p = mock.patch.object(config, "SCAN_CACHE_DIR", self.cache_dir)
        p.start()
        self.addCleanup(p.stop)
        # the scanned files must live outside the infection hotspots (tempfile's /var/folders is one of them)
        self.data = tempfile.mkdtemp(prefix=".scancache-data-", dir=os.path.join(config.ROOT, "tests"))
        self.addCleanup(shutil.rmtree, self.data, True)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        if scancache.in_hotspot(os.path.join(self.data, "x")):
            self.skipTest("the project lies in an infection hotspot")

    def write(self, name: str, data: bytes = b"plain document text\n") -> str:
        p = os.path.join(self.data, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
        return p

    def side(self, paths, idents=None) -> str:
        side = os.path.join(self.tmp, f"side-{time.monotonic_ns()}.jsonl")
        rec = scancache.Recorder(side)
        for i, p in enumerate(paths):
            rec.add(p, idents[i] if idents else scancache.identity(os.lstat(p)))
        rec.close()
        return side

    def remember(self, paths, fp: bytes = FP, now: float | None = None, roots=None) -> int:
        return scancache.merge(self.side(paths), fp, roots if roots is not None else [self.data], now=now)

    def hit(self, path: str, fp: bytes = FP, now: float | None = None) -> bool:
        return scancache.Lookup(fp, now=now).hit(path, os.lstat(path))

    def rows_file(self) -> str:
        return os.path.join(self.cache_dir, scancache.ROWS_NAME)


# ------------------------------------------------------------------ the rules

class EligibilityRulesTest(unittest.TestCase):
    DATA = REG | 0o644
    EXE = REG | 0o755
    MACHO = b"\xcf\xfa\xed\xfe\x07\x00\x00\x01"

    def test_infection_hotspots_never_cached(self):
        for p in ("/Users/alice/Downloads/report.pdf", "/Users/alice/Desktop/notes.txt",
                  "/users/alice/DOWNLOADS/case.txt", "/tmp/x.bin", "/private/tmp/x.bin", "/var/tmp/x",
                  "/private/var/tmp/x", "/private/var/folders/ab/cd/T/x.bin", "/var/folders/ab/x",
                  "/Users/Shared/x.dat", "/Users/alice/Library/LaunchAgents/com.evil.plist",
                  "/Library/LaunchDaemons/com.evil.plist", "/Library/PrivilegedHelperTools/helper.dat",
                  "/Library/StartupItems/Foo/data", "/Volumes/USB/document.txt",
                  "/System/Volumes/Data/Users/alice/Downloads/x.txt",
                  "/Users/alice/Library/Mobile Documents/com~apple~CloudDocs/Desktop/a.txt",
                  "/Users/alice/Library/Containers/com.apple.mail/Data/Library/Mail Downloads/inv.pdf",
                  "/Applications/Foo.app/Contents/Library/LaunchAgents/x.plist"):
            with self.subTest(p=p):
                self.assertTrue(scancache.in_hotspot(p))
                self.assertFalse(scancache.cache_eligible(p, self.DATA, b"%PDF-1.7"))
                self.assertFalse(scancache.cache_eligible(p, self.DATA))

    def test_programs_and_scripts_only_in_program_homes(self):
        sup = "/Users/alice/Library/Application Support/Foo"
        self.assertFalse(scancache.cache_eligible(f"{sup}/agent", self.DATA, self.MACHO))         # Mach-O by magic
        self.assertFalse(scancache.cache_eligible(f"{sup}/fat", self.DATA, b"\xca\xfe\xba\xbe\0\0\0\2"))
        self.assertFalse(scancache.cache_eligible(f"{sup}/run", self.DATA, b"#!/bin/sh\n"))      # shebang
        self.assertFalse(scancache.cache_eligible(f"{sup}/tool.dat", self.EXE, b"data"))         # executable bit
        for ext in ("sh", "py", "command", "js", "scpt", "applescript", "rb", "pl", "zsh", "jar"):
            self.assertFalse(scancache.cache_eligible(f"{sup}/x.{ext}", self.DATA, b"data"), ext)
        self.assertTrue(scancache.cache_eligible(f"{sup}/settings.json", self.DATA, b'{"a": 1}'))
        self.assertTrue(scancache.cache_eligible("/Users/alice/Documents/thesis.docx", self.DATA, b"PK\x03\x04"))
        # inside the program homes everything that is not in a hotspot may be cached
        self.assertTrue(scancache.cache_eligible("/Applications/Foo.app/Contents/MacOS/Foo", self.EXE, self.MACHO))
        self.assertTrue(scancache.cache_eligible("/System/Library/Frameworks/X.framework/X", self.EXE, self.MACHO))
        self.assertTrue(scancache.cache_eligible("/Applications/Foo.app/Contents/Resources/run.sh", self.EXE))
        self.assertTrue(scancache.program_home("/applications/Foo.app/x"))
        self.assertFalse(scancache.program_home("/Users/alice/Applications/Foo.app/x"))
        self.assertFalse(scancache.program_home("/System/Volumes/Preboot/x"))

    def test_lookup_side_without_content(self):
        # on lookup the content is not read: the stored row was checked and ctime proves it is unchanged
        self.assertTrue(scancache.cache_eligible("/Users/alice/Documents/a.txt", self.DATA))
        self.assertFalse(scancache.cache_eligible("/Users/alice/Documents/a.sh", self.DATA))
        self.assertFalse(scancache.cache_eligible("/Users/alice/Documents/a.bin", self.EXE))

    def test_only_complete_clean_results(self):
        ok = {"verdict": "CLEAN", "detections": [], "errors": []}
        self.assertTrue(scancache.result_cacheable(ok))
        for v in ("INFO", "SUSPICIOUS", "PUA", "MALICIOUS"):
            self.assertFalse(scancache.result_cacheable({**ok, "verdict": v}), v)
        self.assertFalse(scancache.result_cacheable({**ok, "errors": ["file larger than …, only the head"]}))
        self.assertFalse(scancache.result_cacheable({**ok, "timeout": True}))
        self.assertFalse(scancache.result_cacheable({**ok, "unreadable": True}))
        self.assertFalse(scancache.result_cacheable({**ok, "detections": [{"name": "Heur:X", "score": 5}]}))

    def test_levels(self):
        self.assertEqual([lv for lv in scanner.LEVELS if scancache.enabled_for(lv)], ["quick", "patterns"])


# ------------------------------------------------------------------ identity

class IdentityTest(CacheTestBase):
    def test_hit_and_miss_without_row(self):
        a, b = self.write("a.txt"), self.write("b.txt")
        self.assertEqual(self.remember([a]), 1)
        self.assertTrue(self.hit(a))
        self.assertFalse(self.hit(b))

    def test_content_change_same_size_and_mtime(self):
        a = self.write("a.txt", b"AAAA plain text\n")
        st0 = os.lstat(a)
        self.remember([a])
        time.sleep(0.01)
        with open(a, "r+b") as fh:
            fh.write(b"BBBB")
        os.utime(a, ns=(st0.st_atime_ns, st0.st_mtime_ns))           # size and mtime restored, ctime is not
        st1 = os.lstat(a)
        self.assertEqual((st1.st_size, st1.st_mtime_ns), (st0.st_size, st0.st_mtime_ns))
        self.assertFalse(self.hit(a))

    def test_touch(self):
        a = self.write("a.txt")
        self.remember([a])
        time.sleep(0.01)
        os.utime(a)
        self.assertFalse(self.hit(a))

    def test_touch_back_to_same_times(self):
        a = self.write("a.txt")
        st0 = os.lstat(a)
        self.remember([a])
        time.sleep(0.01)
        os.utime(a, ns=(st0.st_atime_ns, st0.st_mtime_ns))
        self.assertFalse(self.hit(a))

    def test_chmod(self):
        a = self.write("a.txt")
        self.remember([a])
        time.sleep(0.01)
        os.chmod(a, 0o600)
        self.assertFalse(self.hit(a))

    def test_rename(self):
        a = self.write("a.txt")
        self.remember([a])
        b = os.path.join(self.data, "b.txt")
        os.rename(a, b)
        self.assertFalse(self.hit(b))                 # same inode, other path
        os.rename(b, a)
        self.assertFalse(self.hit(a))                 # back in place, but the renames bumped ctime


# ------------------------------------------------------------------ context fingerprint

class FingerprintTest(CacheTestBase):
    def setUp(self):
        super().setUp()
        self.compiled = os.path.join(self.tmp, "compiled")
        os.makedirs(os.path.join(self.compiled, "clamav"))
        for rel in ("yara.bin", "hashes.sqlite", "clamav/meta.json"):
            Path(self.compiled, rel).write_bytes(b"db v1")
        self.calib = os.path.join(self.compiled, "fp_disabled.json")
        Path(self.calib).write_text('{"disabled": []}')
        for name, val in (("COMPILED", self.compiled), ("FP_CALIBRATION", self.calib)):
            p = mock.patch.object(config, name, val)
            p.start()
            self.addCleanup(p.stop)

    def bump(self, path: str, data: bytes) -> None:
        time.sleep(0.01)
        Path(path).write_bytes(data)

    def test_other_fingerprint_misses(self):
        a = self.write("a.txt")
        self.remember([a], fp=FP)
        self.assertTrue(self.hit(a, fp=FP))
        self.assertFalse(self.hit(a, fp=FP2))

    def test_what_changes_the_fingerprint(self):
        opts = ScanOptions(level="patterns")
        fp = scancache.context_fingerprint(opts)
        self.assertEqual(len(fp), 16)
        self.assertEqual(fp, scancache.context_fingerprint(ScanOptions(level="patterns")))       # deterministic
        self.bump(os.path.join(self.compiled, "clamav", "meta.json"), b"db v2")
        fp_db = scancache.context_fingerprint(opts)
        self.assertNotEqual(fp_db[:12], fp[:12])
        self.bump(self.calib, b'{"disabled": ["Some.Rule"]}')
        fp_cal = scancache.context_fingerprint(opts)
        self.assertNotEqual(fp_cal[:12], fp_db[:12])
        quick = scancache.context_fingerprint(ScanOptions(level="quick"))
        self.assertEqual(quick[:12], fp_cal[:12])
        self.assertNotEqual(quick[12:], fp_cal[12:])                           # level → options part
        small = scancache.context_fingerprint(ScanOptions(level="patterns", max_file_size=1 << 20))
        self.assertNotEqual(small[12:], fp_cal[12:])

    def test_code_hash(self):
        pkg = os.path.join(self.tmp, "pkg")
        os.makedirs(os.path.join(pkg, "sub", "__pycache__"))
        Path(pkg, "a.py").write_text("X = 1\n")
        Path(pkg, "sub", "b.py").write_text("Y = 2\n")
        h1 = scancache.code_hash(pkg)
        Path(pkg, "sub", "__pycache__", "b.cpython-314.pyc").write_bytes(b"ignored")
        scancache._CODE.pop(pkg, None)
        self.assertEqual(scancache.code_hash(pkg), h1)
        Path(pkg, "sub", "b.py").write_text("Y = 3\n")
        scancache._CODE.pop(pkg, None)
        self.assertNotEqual(scancache.code_hash(pkg), h1)
        self.assertEqual(len(scancache.code_hash()), 32)

    def test_database_changed_during_scan_nothing_stored(self):
        a = self.write("a.txt")
        session = scancache.ParentSession(ScanOptions(level="patterns"), [self.data])
        side = self.side([a])
        self.bump(os.path.join(self.compiled, "yara.bin"), b"db v2")
        logged = []
        self.assertEqual(session.merge(side, logged.append), 0)
        self.assertIn("zmieniły się", logged[0])
        self.assertFalse(self.hit(a, fp=session.fp))

    def test_new_database_generation_compacts_old_rows_away(self):
        a = self.write("a.txt")
        self.remember([a], fp=FP)
        b = self.write("b.txt")
        self.remember([b], fp=FP2)                      # other base part → compaction drops the FP rows
        info = scancache.info()
        self.assertEqual(info["rows"], 1)
        self.assertFalse(self.hit(a, fp=FP))
        self.assertTrue(self.hit(b, fp=FP2))


# ------------------------------------------------------------------ tampering and expiry

class TamperTest(CacheTestBase):
    def record_offsets(self) -> list[int]:
        size = os.path.getsize(self.rows_file())
        return list(range(scancache.HEADER.size, size, scancache.REC.size))

    def patch_file(self, off: int, data: bytes) -> None:
        with open(self.rows_file(), "r+b") as fh:
            fh.seek(off)
            fh.write(data)

    def test_bad_hmac_ignored(self):
        a = self.write("a.txt")
        self.remember([a])
        off = self.record_offsets()[0]
        with open(self.rows_file(), "rb") as fh:
            fh.seek(off + 100)
            last = fh.read(1)
        self.patch_file(off + 100, bytes([last[0] ^ 1]))
        lk = scancache.Lookup(FP)
        self.assertFalse(lk.hit(a, os.lstat(a)))
        self.assertEqual(lk.bad, 1)

    def test_forged_identity_after_change(self):
        """An attacker without the key changes the file and rewrites the row's identity to match: HMAC fails."""
        a = self.write("a.txt")
        self.remember([a])
        time.sleep(0.01)
        Path(a).write_bytes(b"EVIL payload text \n")
        st = os.lstat(a)
        self.patch_file(self.record_offsets()[0] + 8,
                        struct.pack("<qQqqq", st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns))
        lk = scancache.Lookup(FP)
        self.assertFalse(lk.hit(a, st))
        self.assertEqual(lk.bad, 1)

    def test_rows_under_another_key_ignored(self):
        a = self.write("a.txt")
        self.remember([a])
        key = os.path.join(self.cache_dir, scancache.KEY_NAME)
        os.chmod(key, 0o600)
        Path(key).write_bytes(os.urandom(32))
        self.assertFalse(self.hit(a))

    def test_key_with_loose_permissions_not_trusted(self):
        a = self.write("a.txt")
        self.remember([a])
        os.chmod(os.path.join(self.cache_dir, scancache.KEY_NAME), 0o644)
        self.assertFalse(self.hit(a))

    def test_truncated_record_ignored(self):
        a, b = self.write("a.txt"), self.write("b.txt")
        self.remember([a, b])
        with open(self.rows_file(), "r+b") as fh:
            fh.truncate(os.path.getsize(self.rows_file()) - 10)
        lk = scancache.Lookup(FP)
        self.assertEqual(len(lk), 1)
        self.assertEqual(lk.hit(a, os.lstat(a)) + lk.hit(b, os.lstat(b)), 1)
        c = self.write("c.txt")
        self.assertEqual(self.remember([c]), 1)            # a misaligned file is compacted, not appended to
        self.assertTrue(self.hit(c))

    def test_symlinked_rows_file_ignored(self):
        a = self.write("a.txt")
        self.remember([a])
        real = self.rows_file() + ".real"
        os.rename(self.rows_file(), real)
        os.symlink(real, self.rows_file())
        self.assertFalse(self.hit(a))


class ExpiryTest(CacheTestBase):
    def test_rows_expire_after_30_days(self):
        a = self.write("a.txt")
        then = time.time() - 31 * DAY
        self.remember([a], now=then)
        self.assertTrue(self.hit(a, now=then + 60))
        self.assertFalse(self.hit(a))

    def test_rows_from_the_future_ignored(self):
        a = self.write("a.txt")
        self.remember([a], now=time.time() + 3 * DAY)
        self.assertFalse(self.hit(a))

    def test_compaction_drops_expired_rows(self):
        a, b = self.write("a.txt"), self.write("b.txt")
        self.remember([a], now=time.time() - 31 * DAY)
        self.remember([b])
        info = scancache.info()
        self.assertEqual((info["rows"], info["live"]), (1, 1))
        self.assertTrue(self.hit(b))

    def test_append_then_same_file_again(self):
        a, b = self.write("a.txt"), self.write("b.txt")
        self.remember([a])
        self.remember([b])
        self.remember([a])
        self.assertEqual(scancache.info()["rows"], 3)     # appended; the newest row per file wins on load
        lk = scancache.Lookup(FP)
        self.assertEqual(len(lk), 2)
        self.assertTrue(lk.hit(a, os.lstat(a)) and lk.hit(b, os.lstat(b)))


# ------------------------------------------------------------------ the parent's merge

class ParentMergeTest(CacheTestBase):
    def test_identity_changed_between_scan_and_merge(self):
        a = self.write("a.txt")
        side = self.side([a])                         # what the child saw right before scanning
        time.sleep(0.01)
        with open(a, "ab") as fh:
            fh.write(b"appended after the scan\n")
        self.assertEqual(scancache.merge(side, FP, [self.data]), 0)
        self.assertFalse(self.hit(a))

    def test_rows_outside_the_scanned_roots_rejected(self):
        a = self.write("a.txt")
        self.assertEqual(self.remember([a], roots=[os.path.join(self.data, "elsewhere")]), 0)
        self.assertEqual(self.remember([a], roots=[self.data + "/"]), 1)

    def test_path_through_symlink_rejected(self):
        a = self.write("sub/a.txt")
        link = os.path.join(self.data, "link")
        os.symlink(os.path.join(self.data, "sub"), link)
        via = os.path.join(link, "a.txt")
        self.assertEqual(scancache.merge(self.side([via], [scancache.identity(os.lstat(a))]), FP, [self.data]), 0)
        os.symlink(a, os.path.join(self.data, "file-link"))
        p = os.path.join(self.data, "file-link")
        self.assertEqual(scancache.merge(self.side([p], [scancache.identity(os.lstat(a))]), FP, [self.data]), 0)

    def test_parent_reads_content_itself(self):
        """The child cannot get a program or script remembered by calling it a plain file."""
        macho = self.write("agent", b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\0" * 64)
        script = self.write("run", b"#!/bin/sh\necho hi\n")
        sh = self.write("x.sh", b"echo hi\n")
        exe = self.write("tool.dat", b"plain bytes\n")
        os.chmod(exe, 0o755)
        plain = self.write("notes.txt")
        self.assertEqual(self.remember([macho, script, sh, exe, plain]), 1)
        self.assertTrue(self.hit(plain))
        self.assertFalse(any(self.hit(p) for p in (macho, script, sh, exe)))

    def test_hotspot_rows_never_reach_the_side_file(self):
        side = os.path.join(self.tmp, "side.jsonl")
        rec = scancache.Recorder(side)
        rec.add("/Users/alice/Downloads/a.txt", [1, 2, 3, 4, 5])
        rec.add("/private/tmp/b.txt", [1, 2, 3, 4, 5])
        rec.close()
        self.assertEqual(os.path.getsize(side), 0)

    def test_malformed_side_rows(self):
        a = self.write("a.txt")
        st = os.lstat(a)
        good = json.dumps([a, *scancache.identity(st)])
        side = os.path.join(self.tmp, "side.jsonl")
        with open(side, "w") as fh:
            fh.write("not json\n")
            fh.write(json.dumps([a, 1, 2]) + "\n")
            fh.write(json.dumps([a, True, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]) + "\n")
            fh.write(json.dumps([123, 1, 2, 3, 4, 5]) + "\n")
            fh.write(json.dumps(["relative/path", 1, 2, 3, 4, 5]) + "\n")
            fh.write(json.dumps(["/a\udcff\u0000b", 1, 2, 3, 4, 5]) + "\n")
            fh.write(json.dumps(["\ud800", 1, 2, 3, 4, 5]) + "\n")
            fh.write("[" * 100000 + "\n")
            fh.write("x" * 20000 + "\n")
            fh.write(good + "\n")
            fh.write(good[:-3])                      # torn last line
        self.assertEqual(scancache.merge(side, FP, [self.data]), 1)
        self.assertTrue(self.hit(a))

    def test_side_file_fifo_or_link_does_not_hang(self):
        fifo = os.path.join(self.tmp, "fifo.jsonl")
        os.mkfifo(fifo)
        self.assertEqual(scancache.merge(fifo, FP, [self.data]), 0)
        link = os.path.join(self.tmp, "link.jsonl")
        os.symlink("/etc/passwd", link)
        self.assertEqual(scancache.merge(link, FP, [self.data]), 0)

    def test_cache_dir_and_key_are_private(self):
        a = self.write("a.txt")
        self.remember([a])
        self.assertEqual(stat.S_IMODE(os.lstat(self.cache_dir).st_mode), 0o700)
        for name in (scancache.KEY_NAME, scancache.ROWS_NAME):
            self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(self.cache_dir, name)).st_mode), 0o600, name)
        self.assertEqual(os.path.getsize(os.path.join(self.cache_dir, scancache.KEY_NAME)), 32)
        self.assertIn("SCAN_CACHE_DIR", config.PRIVATE_DIRS)
        self.assertFalse(config.SCAN_CACHE_DIR.startswith(config.COMPILED))

    def test_info_and_clear(self):
        a, b = self.write("a.txt"), self.write("b.txt")
        self.remember([a, b])
        info = scancache.info()
        self.assertEqual(info["rows"], 2)
        self.assertTrue(info["key"] and info["oldest"] and info["bytes"] > 0)
        self.assertGreater(scancache.clear(), 0)
        self.assertEqual(os.listdir(self.cache_dir), [])
        self.assertFalse(self.hit(a))


# ------------------------------------------------------------------ through scan_paths

class ScanPathsTest(CacheTestBase):
    """The real walker + pipeline (no signature databases loaded): what the scanner skips and records."""

    def bundle(self):
        return [], type("Services", (), {"ioc": None})(), {"missing": []}

    def opts(self, side: str = "", cache: bool = True, level: str = "patterns") -> ScanOptions:
        return ScanOptions(level=level, workers=1, cache=cache, cache_fp=FP.hex(), cache_record=side)

    def scan(self, opts: ScanOptions) -> dict:
        return scanner.scan_paths([self.data], opts, log=lambda m: None, engines_bundle=self.bundle(),
                                  progress=False)

    def test_second_scan_skips_unchanged_files(self):
        files = [self.write(f"f{i}.txt", f"plain text number {i}\n".encode()) for i in range(3)]
        side = os.path.join(self.tmp, "side.jsonl")
        r1 = self.scan(self.opts(side))
        self.assertEqual((r1["files"], r1["cache_hits"]), (3, 0))
        self.assertFalse(os.path.exists(self.rows_file()))            # the scanner itself never writes the cache
        self.assertEqual(scancache.merge(side, FP, [self.data]), 3)
        st_rows = os.stat(self.rows_file())

        r2 = self.scan(self.opts(os.path.join(self.tmp, "side2.jsonl")))
        self.assertEqual((r2["files"], r2["cache_hits"], r2["bytes"], r2["counts"]["CLEAN"]), (3, 3, 0, 3))
        self.assertEqual(scancache.identity(os.stat(self.rows_file())), scancache.identity(st_rows))

        time.sleep(0.01)
        Path(files[1]).write_bytes(b"changed content\n")
        r3 = self.scan(self.opts(os.path.join(self.tmp, "side3.jsonl")))
        self.assertEqual((r3["files"], r3["cache_hits"], r3["bytes"]), (3, 2, len(b"changed content\n")))

        self.assertEqual(self.scan(self.opts(cache=False))["cache_hits"], 0)                 # --no-cache
        self.assertEqual(self.scan(self.opts(level="deep"))["cache_hits"], 0)                # never for deep

    def test_flagged_or_incomplete_results_never_recorded(self):
        names = ["clean", "info", "suspicious", "pua", "malicious", "errors", "timeout", "detection"]
        paths = {n: self.write(f"{n}.txt") for n in names}
        by_path = {p: n for n, p in paths.items()}

        def fake_scan_one(args):
            path, _timeout = args
            n = by_path[path]
            st = os.lstat(path)
            r = {"path": path, "verdict": n.upper() if n in ("info", "suspicious", "pua", "malicious") else "CLEAN",
                 "score": 0, "size": st.st_size, "objects": 1, "detections": [], "errors": [], "ai_context": None,
                 "_id": list(scancache.identity(st))}
            if n == "errors":
                r["errors"] = ["file larger than 1024 bytes, only the head was scanned"]
            if n == "timeout":
                r["timeout"] = True
            if n == "detection":
                r["detections"] = [{"name": "Heur:Weak", "score": 5}]
            return r

        side = os.path.join(self.tmp, "side.jsonl")
        with mock.patch.object(scanner, "_scan_one", fake_scan_one):
            rep = self.scan(self.opts(side))
        self.assertEqual(rep["files"], len(names))
        recorded = [row[0] for row in scancache.read_side(side)]
        self.assertEqual(recorded, [paths["clean"]])
        self.assertTrue(all("_id" not in r for r in rep["results"]))


if __name__ == "__main__":
    unittest.main()

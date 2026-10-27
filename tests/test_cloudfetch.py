"""Mega: risky cloud-only files are remembered by the walk, downloaded within budget, scanned and given back."""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from cerber import cloudfetch, config, gui_backend, scanner
from cerber.dataless import cloud_rank
from cerber.scanner import ScanOptions, iter_files


class RankTest(unittest.TestCase):
    def test_rank(self):
        self.assertEqual(cloud_rank("/c/Foo.app/Contents/MacOS/Foo", 0o644), 0)
        self.assertEqual(cloud_rank("/c/install.SH", 0o644), 0)
        self.assertEqual(cloud_rank("/c/helper", 0o755), 0)
        self.assertEqual(cloud_rank("/c/Setup.dmg", 0o644), 1)
        self.assertEqual(cloud_rank("/c/faktura.pdf", 0o644), 2)
        self.assertIsNone(cloud_rank("/c/IMG_0001.HEIC", 0o644))
        self.assertIsNone(cloud_rank("/c/IMG_0001.JPG", 0o755))        # FAT copy: every file executable
        self.assertIsNone(cloud_rank("/c/notes", 0o644))


class WalkCollectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        os.makedirs(os.path.join(t, "cloudfolder"))
        for rel in ("plain.txt", "run.sh", "photo.jpg", "cloudfolder/x.sh"):
            with open(os.path.join(t, rel), "w") as fh:
                fh.write("#!/bin/sh\n")
        self.t = t
        self.placeholders = {os.stat(os.path.join(t, n)).st_ino for n in ("run.sh", "photo.jpg", "cloudfolder")}

    def tearDown(self):
        self.tmp.cleanup()

    def walk(self, collect: bool) -> tuple[list[str], dict]:
        opts = ScanOptions(collect_cloud=collect)
        stats: dict = {}
        with mock.patch.object(scanner, "is_dataless", lambda st: st.st_ino in self.placeholders):
            files = list(iter_files([self.t], opts, [], stats))
        return files, stats

    def test_collects_only_risky_files_and_unlisted_folders(self):
        files, stats = self.walk(True)
        self.assertEqual([os.path.basename(f) for f in files], ["plain.txt"])
        self.assertEqual(stats["cloud_only"], 3)
        self.assertEqual([(os.path.basename(p), r) for p, _size, r in stats["cloud_files"]], [("run.sh", 0)])
        self.assertEqual([os.path.basename(d) for d in stats["cloud_dirs"]], ["cloudfolder"])

    def test_nothing_collected_outside_mega(self):
        _files, stats = self.walk(False)
        self.assertEqual(stats["cloud_only"], 3)
        self.assertEqual(stats["cloud_files"], [])
        self.assertEqual(stats["cloud_dirs"], [])


class FakeHelper:
    """Stands in for the helper process: `answers` maps (op, path) → reply (None = timed out)."""

    def __init__(self, answers: dict):
        self.answers = answers
        self.calls: list[tuple[str, str]] = []

    def __call__(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def call(self, op, path, timeout):
        self.calls.append((op, path))
        return self.answers.get((op, path), {"ok": True})


class FetchTest(unittest.TestCase):
    def run_fetch(self, files, dirs=(), answers=None, **limits):
        helper = FakeHelper(answers or {})
        with mock.patch.object(cloudfetch, "Helper", helper), \
                mock.patch.multiple(cloudfetch, **limits) if limits else contextlib.nullcontext():
            got = cloudfetch.fetch(list(files), list(dirs), threading.Event(), lambda *a: None, lambda m: None,
                                   max_file=1000)
        return got, helper

    def test_order_limits_and_kinds(self):
        files = [["/c/big.zip", 5000, 1], ["/c/b.pdf", 10, 2], ["/c/a.sh", 50, 0], ["/c/z.dmg", 20, 1],
                 ["/c/a.sh", 50, 0]]
        got, helper = self.run_fetch(files, FETCH_MAX_FILES=2)
        self.assertEqual([p for op, p in helper.calls], ["/c/a.sh", "/c/z.dmg"])       # code first, then smallest
        st = got["stats"]
        self.assertEqual((st["candidates"], st["fetched"], st["too_big"], st["over_limit"]), (4, 2, 1, 1))
        self.assertEqual(st["bytes"], 70)
        self.assertEqual(st["kinds"], {"programy i skrypty": 1, "instalatory i archiwa": 1})

    def test_stalled_cloud_stops(self):
        files = [[f"/c/{i}.sh", 1, 0] for i in range(6)]
        got, helper = self.run_fetch(files, answers={("open", f"/c/{i}.sh"): None for i in range(6)})
        self.assertEqual(len(helper.calls), cloudfetch.STALL_LIMIT)
        self.assertTrue(got["stats"]["stalled"])
        self.assertEqual(got["fetched"], [])

    def test_unlisted_folders_are_listed(self):
        answers = {("list", "/c/dir"): {"ok": True, "entries": [
            ["tool.command", "f", True, 30, 0o644], ["IMG.HEIC", "f", True, 99, 0o644],
            ["here.txt", "f", False, 5, 0o644], ["sub", "d", True, 0, 0o755], ["../x", "f", True, 1, 0o755]]},
            ("list", "/c/dir/sub"): {"ok": False, "err": "x"}}
        got, helper = self.run_fetch([], ["/c/dir"], answers)
        self.assertEqual(got["fetched"], ["/c/dir/tool.command"])
        self.assertEqual(got["local"], ["/c/dir/here.txt"])
        self.assertEqual((got["stats"]["dirs_listed"], got["stats"]["dirs_failed"]), (1, 1))


class HelperProcessTest(unittest.TestCase):
    def test_real_helper(self):
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            with open(os.path.join(d, "f.sh"), "w") as fh:
                fh.write("echo\n")
            reqs = [{"op": "open", "path": d + "/f.sh"}, {"op": "list", "path": d},
                    {"op": "evict", "path": d + "/f.sh"}, {"op": "open", "path": "relative"}]
            out = subprocess.run([sys.executable, "-m", "cerber.cloudfetch", "serve"], cwd=config.ROOT,
                                 input="".join(json.dumps(r) + "\n" for r in reqs), capture_output=True, text=True,
                                 timeout=60).stdout.splitlines()
            got = [json.loads(x) for x in out]
            self.assertEqual(len(got), 4)
            self.assertTrue(got[0]["ok"])
            self.assertEqual(got[1]["entries"][0][:3], ["f.sh", "f", False])
            self.assertFalse(got[2]["ok"])                     # not an iCloud file: a clean refusal, no crash
            self.assertTrue(got[2]["err"])
            self.assertFalse(got[3]["ok"])
            self.assertTrue(os.path.exists(d + "/f.sh"))       # eviction never deletes anything


class StepTest(unittest.TestCase):
    def test_cloud_step_scans_and_gives_back(self):
        report = {"files": 10, "results": [], "counts": {}, "cloud_only": 7,
                  "cloud_candidates": [["/c/a.sh", 5, 0]], "cloud_dirs": []}
        got = {"fetched": ["/c/a.sh", "/c/b.sh"], "local": [],
               "stats": {"fetched": 2, "candidates": 2, "bytes": 10, "kinds": {}}}
        sub = {"files": 2, "results": [{"path": "/c/b.sh", "verdict": "MALICIOUS", "score": 99}], "counts": {}}
        cancel = mock.Mock(set=False, event=threading.Event())
        evicted = []
        with mock.patch.object(cloudfetch, "fetch", return_value=got), \
                mock.patch.object(gui_backend, "run_file_scan", return_value=sub) as rfs, \
                mock.patch.object(cloudfetch, "evict", side_effect=lambda ps, log: evicted.extend(ps) or len(ps)), \
                mock.patch.object(gui_backend, "emit", create=True):
            fetched = gui_backend.run_cloud_step(report, ScanOptions(collect_cloud=True), cancel)
            gui_backend.cloud_give_back(report, fetched)
        self.assertEqual(rfs.call_args[0][0], ["/c/a.sh", "/c/b.sh"])
        self.assertEqual(report["files"], 12)
        self.assertEqual(report["cloud_only"], 5)
        self.assertNotIn("cloud_candidates", report)
        self.assertEqual(evicted, ["/c/a.sh"])                 # the flagged one stays on disk
        self.assertEqual((report["cloud_fetch"]["evicted"], report["cloud_fetch"]["kept"]), (1, 1))

    def test_nothing_to_do(self):
        report = {"files": 1, "results": [], "cloud_only": 3, "cloud_candidates": [], "cloud_dirs": []}
        with mock.patch.object(cloudfetch, "fetch") as f:
            self.assertEqual(gui_backend.run_cloud_step(report, ScanOptions(), mock.Mock(set=False)), [])
        f.assert_not_called()
        self.assertNotIn("cloud_fetch", report)


if __name__ == "__main__":
    unittest.main()

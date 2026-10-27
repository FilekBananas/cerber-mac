"""File walker: iCloud/File Provider placeholders ("dataless") are counted, never listed or opened."""
from __future__ import annotations

import errno
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from cerber import dataless, scanner
from cerber.scanner import ScanOptions, iter_files


class WalkTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        os.makedirs(os.path.join(t, "cloud", "deep"))
        os.makedirs(os.path.join(t, "local"))
        for rel in ("a.txt", "local/b.txt", "cloud/c.txt", "cloud/deep/d.txt", "evicted.bin"):
            with open(os.path.join(t, rel), "w") as fh:
                fh.write("x")
        self.cloud = os.path.join(t, "cloud")
        self.evicted = os.path.join(t, "evicted.bin")
        self.placeholders = {os.stat(self.cloud).st_ino, os.stat(self.evicted).st_ino}

    def tearDown(self):
        self.tmp.cleanup()

    def fake_dataless(self, st) -> bool:
        return st.st_ino in self.placeholders

    def test_placeholders_skipped_and_never_listed(self):
        listed = []
        real_scandir = os.scandir

        def spy(d):
            listed.append(d)
            return real_scandir(d)

        stats, dirs = {}, []
        with mock.patch.object(scanner, "is_dataless", self.fake_dataless), mock.patch.object(os, "scandir", spy):
            files = sorted(os.path.relpath(f, self.tmp.name)
                           for f in iter_files([self.tmp.name], ScanOptions(), [], stats, dirs.append))
        self.assertEqual(files, ["a.txt", "local/b.txt"])
        self.assertEqual(stats["cloud_only"], 2)
        self.assertNotIn(self.cloud, listed)                 # listing it would make macOS download it
        self.assertEqual(sorted(dirs), sorted(listed))

    def test_placeholder_as_top_path(self):
        stats = {}
        with mock.patch.object(scanner, "is_dataless", self.fake_dataless):
            self.assertEqual(list(iter_files([self.cloud], ScanOptions(), [], stats)), [])
        self.assertEqual(stats["cloud_only"], 1)

    def test_not_materialized_error_counts_as_cloud(self):
        real_scandir = os.scandir

        def deadlk(d):
            if d == self.cloud:
                raise OSError(errno.EDEADLK, os.strerror(errno.EDEADLK), d)
            return real_scandir(d)

        stats, skipped = {}, []
        with mock.patch.object(os, "scandir", deadlk):
            files = list(iter_files([self.tmp.name], ScanOptions(), skipped, stats))
        self.assertEqual(stats["cloud_only"], 1)
        self.assertEqual(skipped, [])
        self.assertFalse(any("/cloud/" in f for f in files))

    @unittest.skipUnless(sys.platform == "darwin", "macOS iopolicy")
    def test_materialization_off_inherited(self):
        code = ("from cerber import dataless as d; d.never_materialize(); import subprocess, sys; "
                "print(d.materialization_off(), subprocess.run([sys.executable, '-c', "
                "'from cerber import dataless as d; print(d.materialization_off())'], "
                "capture_output=True, text=True).stdout.strip())")
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                             cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))).stdout.split()
        self.assertEqual(out, ["True", "True"])

    def test_flag_value(self):
        self.assertTrue(dataless.is_dataless(mock.Mock(st_flags=0x40000060)))
        self.assertFalse(dataless.is_dataless(mock.Mock(st_flags=0x20)))


if __name__ == "__main__":
    unittest.main()

"""Container coverage found missing by the safe benchmark (tests/benchmark/safe_bench.py) stays fixed.

* Unix compress (.Z, LZW) is unpacked (pure Python, works in the strictest sandbox);
* a file that is one base64 text is decoded and what it decodes to is scanned (no score of its own);
* encrypted archives: lure passwords (years, short digit runs) and a password printed in the file name are tried.

    .venv/bin/python -m unittest tests.test_container_coverage -v
"""
from __future__ import annotations

import base64
import os
import random
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerber.analyzers.embedded_blobs import _whole_file_base64  # noqa: E402
from cerber.core import ScanObject  # noqa: E402
from cerber.filetype import identify_bytes  # noqa: E402
from cerber.formats.arc_common import EXTRA_PASSWORDS, candidate_passwords  # noqa: E402
from cerber.formats.arc_stream import LzwAdapter, make_adapter  # noqa: E402

TEXT = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARX-ANTIVIRUS-TEST-FILE!$H+H*"   # near-miss, harmless
# `printf '<TEXT>' | compress -c` (16-bit codes), so the test also runs where `compress` is missing
TEXT_Z = bytes.fromhex(
    "1f9d90586a3c0901a504902050b6d0e002454b401a28a078497163c8108a7d48"
    "1449322488941653a8047142c423961623a924b192444a95292da81409d9c248"
    "122645429040b202890a")


def _decode(data: bytes) -> tuple[bytes, str | None]:
    a = LzwAdapter(data)
    out = bytearray()
    while (c := a.step()) is not None:
        out += c
    return bytes(out), a.error


class LzwTest(unittest.TestCase):
    def test_known_vector(self):
        self.assertEqual(identify_bytes(TEXT_Z)[0], "compress")
        got, err = _decode(TEXT_Z)
        self.assertIsNone(err)
        self.assertEqual(got, TEXT)
        self.assertIsInstance(make_adapter("compress", TEXT_Z), LzwAdapter)

    @unittest.skipUnless(shutil.which("compress"), "no compress(1)")
    def test_round_trip_against_system_compress(self):
        rnd = random.Random(7)
        cases = [TEXT, b"a", b"ab" * 4000, bytes(rnd.getrandbits(8) for _ in range(120_000)),
                 b"the quick brown fox " * 9000, bytes(rnd.choice(b"ab") for _ in range(150_000))]
        for c in cases:
            for bits in (10, 12, 16):
                z = subprocess.run(["compress", "-c", "-b", str(bits)], input=c, capture_output=True).stdout
                got, err = _decode(z)
                self.assertIsNone(err, (len(c), bits))
                self.assertEqual(got, c, (len(c), bits))

    def test_garbage_is_an_error_not_a_crash(self):
        _, err = _decode(b"\x1f\x9d\x90" + bytes(range(256)) * 4)
        self.assertIsNotNone(err)
        _, err = _decode(b"\x1f\x9d\x7f")
        self.assertIsNotNone(err)


class WholeBase64Test(unittest.TestCase):
    def _obj(self, data: bytes) -> ScanObject:
        return ScanObject(data=data, display_path="x.txt")

    def test_whole_file(self):
        enc = base64.encodebytes(TEXT * 3)
        self.assertEqual(_whole_file_base64(self._obj(enc)), TEXT * 3)

    def test_not_whole_file(self):
        self.assertIsNone(_whole_file_base64(self._obj(b"hello " + base64.b64encode(TEXT * 2))))
        self.assertIsNone(_whole_file_base64(self._obj(b"e038b5168d9209267058112d845341cae83d92b1d1af0a10b66830acb7529494")))
        self.assertIsNone(_whole_file_base64(self._obj(b"QUJD")))           # too short to matter


class PasswordTest(unittest.TestCase):
    def test_lure_passwords(self):
        for p in ("2024", "2025", "2026", "1111", "0000"):
            self.assertIn(p, EXTRA_PASSWORDS)

    def test_password_from_file_name(self):
        for name, pw in (("Setup (password 7788).zip", "7788"), ("Installer_pass_x9k2.rar", "x9k2"),
                         ("program-haslo=qwe123.7z", "qwe123")):
            obj = ScanObject(data=b"PK\x03\x04", display_path=os.path.join("/Users/x/Downloads", name))
            self.assertEqual(candidate_passwords(obj)[0], pw, name)
        obj = ScanObject(data=b"PK\x03\x04", display_path="/Users/x/compass_report.zip")
        self.assertEqual(candidate_passwords(obj)[0], "infected")


if __name__ == "__main__":
    unittest.main()

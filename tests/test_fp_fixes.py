"""False positives seen on a real Mac (quick laptop scan, 2026-11-10) must stay fixed.

* a PDF font subset ("12456789:ABCDEFGHIJ…") is not a Telegram bot token; a random-looking one still is;
* a raw disk image (GPT / Apple partition map) gets no Windows-script YARA rules;
* a DMG bigger than the scan limit (head only, "koly" trailer cut off) is still identified as a DMG;
* build-tool identification (PyInstaller) and `chcp 65001` are hints at most, never SUSPICIOUS.

    .venv/bin/python -m unittest tests.test_fp_fixes -v
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerber.analyzers import ioc  # noqa: E402
from cerber.core import Confidence, ScanObject  # noqa: E402
from cerber.engines import yara_engine as ye  # noqa: E402
from cerber.filetype import identify  # noqa: E402
from cerber.verdict import SUSPICIOUS_SCORE  # noqa: E402


class FpFixesTest(unittest.TestCase):
    def test_telegram_token_lookalikes(self):
        font = "12456789:ABCDEFGHIJQUVWXYZbcdefghijrstuvwxyz 13456789:ABCDEFGHIJUVWXYZabdefghijqrstuvwxyz"
        self.assertNotIn("telegram_token", ioc.extract_iocs(font))
        real = 'bot = "1102015437:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ"'
        self.assertEqual(ioc.extract_iocs(real).get("telegram_token"), ["1102015437:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ"])

    def test_raw_disk_images(self):
        gpt = bytearray(64 * 1024)
        gpt[510:512] = b"\x55\xaa"
        gpt[512:520] = b"EFI PART"
        self.assertTrue(ye._is_fs_image(bytes(gpt)))
        apm = bytearray(8192)
        apm[0:2], apm[512:514] = b"ER", b"PM"
        self.assertTrue(ye._is_fs_image(bytes(apm)))
        self.assertFalse(ye._is_fs_image(b"powershell -c iex(downloadFile('x')) $env:temp rundll32.exe" * 50))

    def test_head_only_dmg_is_still_a_dmg(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "big.dmg")
        with open(p, "wb") as fh:
            fh.write(b"BZh91AY&SY" + os.urandom(20000))
            fh.write(b"koly" + b"\0" * 508)
        head = open(p, "rb").read(4096)
        obj = ScanObject(data=head, display_path=p, real_path=p)
        identify(obj)
        self.assertEqual(obj.ftype, "dmg")

    def test_noise_rules_are_not_suspicious(self):
        self.assertIn("TELEKOM_SECURITY_Cn_Utf8_Windows_Terminal", ye.NOISY_RULES)
        conf, score, _ = ye.classify("MF_yr_MachO_File_pyinstaller", "community:x", {"score": 60}, "community")
        self.assertLess(score, SUSPICIOUS_SCORE)
        self.assertEqual(conf, Confidence.MEDIUM)


if __name__ == "__main__":
    unittest.main()

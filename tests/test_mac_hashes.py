"""Offline tests of the macOS hash importers (synthetic feed data, no network)."""
import os
import tempfile
import unittest
from unittest import mock

from cerber import feeds_macos as fm
from cerber.engines.hashdb import SRC_MACOS, HashDB

A = "a" * 64
B = "b" * 40
C = "c" * 32
D = "d" * 64
E = "e" * 64


class ParseTests(unittest.TestCase):
    def test_threatfox(self):
        hdr = "# comment\n"
        row = lambda v, t, m, conf: f'"2026-01-01 00:00:00", "1", "{v}", "{t}", "payload", "{m}", "None", "Pretty", "", "{conf}", "False", "None", "t", "0", "x"\n'
        txt = hdr + row(A, "sha256_hash", "osx.amos", 100) + row(B, "sha1_hash", "osx.amos", 50) \
            + row(C, "md5_hash", "osx.amos", 20) + row(D, "sha256_hash", "win.lumma", 100) \
            + row("evil.com", "domain", "osx.amos", 100)
        got = fm.parse_threatfox(txt)
        self.assertEqual([d.hex() for d, _ in got], [A, B])
        self.assertEqual(got[0][1], "ThreatFox.Pretty")

    def test_eset(self):
        txt = (f"| `{A.upper()}` | `x` | OSX/Agent.DJ | desc\n"
               f"| `{B.upper()}` | `x.exe` | Win32/Foo | desc\n"
               f"| `{C}` | JS/Exploit | note about macOS in text\n")
        got = fm.parse_eset_text(txt)
        self.assertEqual([(d.hex(), lb) for d, lb in got], [(A, "ESET.OSX/Agent.DJ")])

    def test_misp(self):
        ev = {"Event": {"info": "OSINT - Mac Malware of 2017", "Attribute": [
            {"type": "sha256", "value": A, "to_ids": True, "comment": "OSX/FruitFly"},
            {"type": "sha256", "value": D, "to_ids": False},
            {"type": "filename|md5", "value": "setup.exe|" + C, "to_ids": True}],
            "Object": [{"Attribute": [{"type": "filename", "value": "macsvc"}, {"type": "sha256", "value": E}]},
                       {"Attribute": [{"type": "filename", "value": "Updater.exe"}, {"type": "sha256", "value": B}]}]}}
        got = {d.hex() for d, _ in fm.parse_misp_event(ev)}
        self.assertEqual(got, {A, E})
        self.assertTrue(fm.event_is_mac("OSINT - OSX Malware", []))
        self.assertFalse(fm.event_is_mac("Emotet campaign", ["tlp:white"]))

    def test_otx(self):
        p = {"name": "Atomic Stealer macOS", "tags": [], "indicators": [
            {"type": "FileHash-SHA256", "indicator": A}, {"type": "domain", "indicator": "x.com"}]}
        self.assertEqual(len(fm.parse_otx_pulse(p)), 1)
        self.assertEqual(fm.parse_otx_pulse({"name": "Emotet", "indicators": p["indicators"]}), [])

    def test_bazaar_api(self):
        r = {"query_status": "ok", "data": [{"sha256_hash": A, "md5_hash": C, "sha1_hash": B, "signature": "AMOS"}]}
        self.assertEqual(len(fm.parse_bazaar_api(r)), 3)
        self.assertEqual(fm.parse_bazaar_api({"query_status": "no_results"}), [])


class DriverTests(unittest.TestCase):
    def test_dedupe_failure_and_keys(self):
        with tempfile.TemporaryDirectory() as td:
            db = HashDB(os.path.join(td, "h.sqlite"), readonly=False)
            db.add_file_hashes([(bytes.fromhex(A), None, "Existing", 2, 0)])
            rows = [(bytes.fromhex(A), "x"), (bytes.fromhex(D), "y")]

            def ok(db_, log):
                return fm._add(db_, [(d, None, lb, SRC_MACOS, 0) for d, lb in rows])

            def boom(db_, log):
                raise OSError("network down")
            with mock.patch.object(fm, "SOURCES", [("ok", ok), ("boom", boom)]):
                res = fm.import_macos_hashes(db, lambda m: None)
            self.assertEqual(res, {"ok": 1, "boom": 0})       # existing digest not duplicated
            self.assertEqual(fm.mac_total(db), 1)
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("CERBER_OTX_KEY", None)
                os.environ.pop("CERBER_ABUSECH_KEY", None)
                self.assertEqual(fm.import_otx(db, lambda m: None), 0)
                self.assertEqual(fm.import_bazaar_api(db, lambda m: None), 0)


if __name__ == "__main__":
    unittest.main()

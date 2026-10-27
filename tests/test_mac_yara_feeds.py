"""Offline tests of the macOS YARA feed filter/dedupe/rename logic (no network)."""
import os
import tempfile
import unittest
from unittest import mock

import yara

from cerber import config, feeds_macos_yara as f

SAMPLE = '''import "pe"
// komentarz
private rule helper_mac { strings: $a = "osascript" condition: $a }
rule Win_Only { strings: $a = "MZ-only-thing" condition: $a }
rule Mac_Stealer_Test {
    meta: description = "test condition: here"
    strings: $a = "LaunchAgents" $b = "security find-generic-password"
    condition: helper_mac and any of them
}
rule Generic_Thing { strings: $s = "~/Library/Keychains" condition: $s }
rule Uses_Console { strings: $s = "osascript -e" condition: $s and console.log("x") }
rule HUNT_Thing_osx { strings: $s = "hunt osx marker" condition: $s }
'''


class MacYaraFeeds(unittest.TestCase):
    def test_is_macos_rule(self):
        self.assertTrue(f.is_macos_rule("MALW_OSX_Leverage", "x"))
        self.assertTrue(f.is_macos_rule("Foo", 'strings: $a = "LaunchDaemons"'))
        self.assertFalse(f.is_macos_rule("Machine_Thing", '$a = "machine learning"'))
        self.assertFalse(f.is_macos_rule("Win_Only", '$a = "MZ"'))

    def test_normalize_ignores_name_comments_spaces(self):
        a = 'rule A { // c\n strings: $a = "x"\n condition: $a }'
        b = 'rule Bee{strings:$a="x" condition:$a /* z */}'
        self.assertEqual(f.body_hash(a), f.body_hash(b))
        self.assertNotEqual(f.body_hash(a), f.body_hash(a.replace('"x"', '"y"')))

    def test_select_filters_renames_and_compiles(self):
        text, st = f.select_rules([("a.yar", SAMPLE)], "t", set(), deny_re=r"^HUNT_")
        self.assertEqual(st["total"], 6)
        self.assertIn("MF_t_Mac_Stealer_Test", text)
        self.assertIn("MF_t_helper_mac", text)             # zależność prywatna dołączona i przemianowana
        self.assertNotIn("Win_Only", text)
        self.assertNotIn("Uses_Console", text)             # console.* odrzucone
        self.assertNotIn("HUNT_Thing_osx", text)           # deny_re
        rules = yara.compile(source=text)
        hit = {m.rule for m in rules.match(data=b"osascript LaunchAgents ~/Library/Keychains")}
        self.assertEqual(hit, {"MF_t_Generic_Thing", "MF_t_Mac_Stealer_Test"})

    def test_dedupe_against_seen(self):
        seen = {f.body_hash('rule X { strings: $s = "~/Library/Keychains" condition: $s }')}
        text, st = f.select_rules([("a.yar", SAMPLE)], "t", seen)
        self.assertEqual(st["dup"], 1)
        self.assertNotIn("Generic_Thing", text)

    def test_duplicate_names_get_unique(self):
        r1 = 'rule Same_osx { strings: $a = "one" condition: $a }'
        r2 = 'rule Same_osx { strings: $a = "two" condition: $a }'
        text, _ = f.select_rules([("a", r1), ("b", r2)], "t", set())
        self.assertEqual(len(list(yara.compile(source=text))), 2)

    def test_update_survives_network_failure_and_offline(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(config, "YARA_SOURCES", td):
            self.assertIsNone(f.update_macos_yara(lambda m: None, offline=True))
            logs = []
            with mock.patch.object(f, "fetch_files", side_effect=OSError("brak sieci")):
                d = f.update_macos_yara(logs.append, sources=[{"tag": "z", "repo": "x/y", "branch": "m", "license": "MIT"}])
            self.assertTrue(os.path.isdir(d))
            self.assertTrue(any("niedostępne" in m for m in logs))
            with mock.patch.object(f, "fetch_files", return_value=[("a.yar", SAMPLE)]):
                f.update_macos_yara(logs.append, sources=[{"tag": "z", "repo": "x/y", "branch": "m", "license": "MIT"}])
            self.assertTrue(os.path.exists(os.path.join(d, "z.yar")))
            self.assertTrue(os.path.exists(os.path.join(d, "SOURCES.json")))

    def test_skip_env(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(config, "YARA_SOURCES", td), \
                mock.patch.dict(os.environ, {"CERBER_MACYARA_SKIP": "z"}), \
                mock.patch.object(f, "fetch_files", side_effect=AssertionError("nie powinno pobierać")):
            f.update_macos_yara(lambda m: None, sources=[{"tag": "z", "repo": "x/y", "branch": "m", "license": "MIT"}])


if __name__ == "__main__":
    unittest.main()

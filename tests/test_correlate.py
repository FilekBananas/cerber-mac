"""Provenance, suspicious names and correlation (process + network + autostart + files judged together)."""
from __future__ import annotations

import os
import tempfile
import time
import unittest

from cerber.correlate import correlate, escalate_results
from cerber.envscan import provenance as pv

HOME = "/Users/tester"
EVIL = f"{HOME}/Library/Application Support/.syncd/updater"
STEAM = f"{HOME}/Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/MacOS/steam_osx"
NODE = f"{HOME}/projekty/app/node_modules/.bin/vite"


def proc(exe, name, trust, **o):
    origin = {"path": exe, "exists": True, "trust": trust, "label": trust, **o}
    return {"exe": exe, "name": name, "pids": [100 + len(exe) % 50], "origin": origin}


def env(processes, launchd=(), findings=()):
    return {"inventory": {"processes": list(processes), "launchd": list(launchd)}, "findings": list(findings)}


def finding(cat, exe, score, title="t", sig="Heur:Env.Process.HiddenPath"):
    return {"category": cat, "title": title, "location": exe, "severity": "suspicious",
            "detection": {"score": score, "evidence": [f"{sig} [+{score}]: x"]}, "details": {"exe": exe}}


class NamesTest(unittest.TestCase):
    def test_name_alone_never_decides(self):
        for n in ("wirus.txt", "virus_bakteria.pdf", "KeyLogger.app", "mac_stealer", "RAT-client"):
            sigs = pv.name_signals(n, "T", untrusted=True)
            self.assertTrue(sigs, n)
            self.assertTrue(all(s.score <= 20 and s.confidence.name == "LOW" for s in sigs), (n, sigs))

    def test_deceit_tricks_count_more(self):
        self.assertGreaterEqual(max(s.score for s in pv.name_signals("faktura.pdf.app", "T")), 30)
        self.assertGreaterEqual(max(s.score for s in pv.name_signals("photo‮gnp.app", "T")), 45)
        self.assertTrue(pv.name_signals("Gооgle Chrome.app", "T", trusted=True))      # Cyrillic о

    def test_clean_names(self):
        for n in ("Steam.app", "Keyboard Maestro.app", "StealthBrowser", "Pirate notes.txt", "Separate.app", "node",
                  "Ratatouille.mp4", "Update Manager.app"):
            self.assertEqual(pv.name_signals(n, "T"), [], n)
        self.assertEqual(pv.name_signals("KeyLogger Pro.app", "T", trusted=True), [])   # signed: words silenced

    def test_tokens(self):
        self.assertEqual(pv.name_tokens("KeyLogger_v2.app"), "key logger v 2 app")


class ProvenanceTest(unittest.TestCase):
    def test_parse_quarantine(self):
        q = pv.parse_quarantine(b"0083;65f1a2b3;Telegram;ABCD-1")
        self.assertEqual((q["agent"], q["uuid"], q["approved"]), ("Telegram", "ABCD-1", False))
        self.assertTrue(pv.parse_quarantine("00c3;65f1a2b3;Safari;X")["approved"])
        self.assertIsNone(pv.parse_quarantine(""))

    def test_tiers(self):
        class S:
            def __init__(self, status, flags=""):
                self.status, self.flags, self.team_id, self.runtime, self.verified = status, flags, "", False, True
                self.signer = status

        with tempfile.TemporaryDirectory() as d:
            exe = os.path.join(d, "projekty", "x", "target", "release", "tool")
            os.makedirs(os.path.dirname(exe))
            open(exe, "w").close()
            home = d
            self.assertEqual(pv.origin(exe, S("adhoc", "adhoc,linker-signed"), home)["trust"], "local_build")
            self.assertEqual(pv.origin(exe, S("devid"), home)["trust"], "devid")
            hidden = os.path.join(d, "Library", "Application Support", ".x", "agent")
            os.makedirs(os.path.dirname(hidden))
            open(hidden, "w").close()
            self.assertEqual(pv.origin(hidden, S("unsigned"), home)["trust"], "untrusted")
            self.assertEqual(pv.origin("/nonexistent/x", S("unsigned"), home)["trust"], "untrusted")
            self.assertEqual(pv.origin("/usr/bin/curl", None, home)["trust"], "apple")

    def test_origin_signals_small_and_trust_aware(self):
        o = {"path": "/x", "trust": "untrusted", "exists": True, "age_days": 0.5,
             "download": {"agent": "Telegram", "days": 1}}
        sigs = pv.origin_signals(o, "T")
        self.assertTrue(any("Downloaded" in s.name for s in sigs))
        self.assertLess(sum(s.score for s in sigs), 60)
        self.assertEqual(pv.origin_signals({**o, "trust": "devid"}, "T"), [])


class CorrelateTest(unittest.TestCase):
    def test_backdoor_from_weak_signals(self):
        """Hidden folder + downloaded via Telegram + LaunchAgent + port 4444: no single strong signature."""
        e = env([proc(EVIL, "updater", "untrusted", download={"agent": "Telegram", "days": 1}, age_days=1)],
                launchd=[{"plist": f"{HOME}/Library/LaunchAgents/com.sync.updater.plist", "program": EVIL,
                          "run_at_load": True}],
                findings=[finding("process", EVIL, 30)])
        net = {"connections": [{"exe": EVIL, "remote": "45.9.1.2", "port": 4444, "public": True}]}
        cor = correlate(e, net, [], home=HOME)
        self.assertEqual(len(cor["cases"]), 1)
        c = cor["cases"][0]
        self.assertEqual(c["severity"], "malicious", c)
        self.assertGreaterEqual(len([d for d, v in c["dims"].items() if v >= 15]), 3)
        self.assertEqual(cor["findings"][0]["category"], "correlation")
        self.assertEqual(cor["escalate"], [])                     # the file does not exist in this test

    def test_one_weak_signal_is_not_a_case(self):
        e = env([proc(EVIL, "updater", "untrusted")])
        self.assertEqual(correlate(e, {}, [], home=HOME)["cases"], [])
        net = {"connections": [{"exe": EVIL, "remote": "45.9.1.2", "port": 8443, "public": True}]}
        self.assertEqual(correlate(env([proc(EVIL, "updater", "unknown")]), net, [], home=HOME)["cases"], [])

    def test_trusted_programs_stay_quiet(self):
        e = env([proc(STEAM, "steam_osx", "devid"), proc(NODE, "node", "local_build")],
                launchd=[{"plist": "/Library/LaunchAgents/com.valvesoftware.steam.plist", "program": STEAM,
                          "run_at_load": True}])
        net = {"listening": [{"exe": STEAM, "port": 27036, "exposure": "all"},
                             {"exe": NODE, "port": 9009, "exposure": "all"}],
               "connections": [{"exe": STEAM, "remote": "155.133.230.69", "port": 27017, "public": True},
                               {"exe": NODE, "remote": "1.2.3.4", "port": 8080, "public": True}]}
        self.assertEqual(correlate(e, net, [], home=HOME)["cases"], [])

    def test_ioc_counts_even_for_signed(self):
        e = env([proc(STEAM, "steam_osx", "devid")])
        net = {"connections": [{"exe": STEAM, "remote": "203.0.113.66", "port": 443, "public": True,
                                "ioc": "ThreatFox"}]}
        e["findings"] = [finding("process", STEAM, 10)]
        cor = correlate(e, net, [], home=HOME)
        self.assertTrue(cor["cases"])

    def test_package_of_weak_files(self):
        app = "/Applications/Free Converter.app"
        res = [{"path": f"{app}/Contents/MacOS/conv", "verdict": "SUSPICIOUS", "score": 40, "primary": "A"},
               {"path": f"{app}/Contents/Resources/install.sh", "verdict": "SUSPICIOUS", "score": 38, "primary": "B"},
               {"path": f"{app}/Contents/Resources/com.x.plist", "verdict": "INFO", "score": 12, "primary": "C"}]
        cor = correlate(env([]), {}, res, home=HOME)
        self.assertEqual(len(cor["cases"]), 1)
        self.assertIn(cor["cases"][0]["severity"], ("suspicious", "malicious"))
        self.assertGreater(cor["cases"][0]["dims"]["file"], 40)          # more than the strongest file alone

    def test_escalate_results(self):
        with tempfile.NamedTemporaryFile() as f:
            res = []
            n = escalate_results(res, [{"path": f.name, "score": 70, "verdict": "SUSPICIOUS", "why": "w",
                                        "reasons": ["r"]}])
            self.assertEqual((n, res[0]["verdict"], res[0]["detections"][0]["engine"]), (1, "SUSPICIOUS", "correlation"))
            self.assertEqual(escalate_results(res, [{"path": f.name, "score": 70, "verdict": "SUSPICIOUS",
                                                     "why": "w", "reasons": []}]), 0)   # once


if __name__ == "__main__":
    unittest.main()

"""Quarantine is the user's decision: a button for high-risk finds, never automatic unless switched on."""
from __future__ import annotations

import argparse
import os
import tempfile
import unittest

from cerber import gui_backend as g
from cerber.watch import auto_quarantine


class OfferTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.f = os.path.join(self.tmp.name, "x.sh")
        with open(self.f, "w") as fh:
            fh.write("echo\n")
        self.roots = list(g.SCAN_ROOTS)
        g.SCAN_ROOTS[:] = [self.tmp.name]

    def tearDown(self):
        g.SCAN_ROOTS[:] = self.roots
        self.tmp.cleanup()

    def pub(self, verdict: str, score: int, **kw) -> dict:
        return g.public_result({"path": self.f, "verdict": verdict, "score": score, "detections": [], **kw},
                               **({"sandboxed": True, "base": self.tmp.name} if kw.pop("sandboxed", False) else {}))

    def test_button_for_high_risk_only(self):
        self.assertTrue(self.pub("MALICIOUS", 90)["can_quarantine"])
        self.assertTrue(self.pub("SUSPICIOUS", g.QUARANTINE_SCORE)["can_quarantine"])
        self.assertTrue(self.pub("PUA", 70)["can_quarantine"])
        low = self.pub("SUSPICIOUS", g.QUARANTINE_SCORE - 1)
        self.assertFalse(low["can_quarantine"])
        self.assertIn("Niskie ryzyko", low["quarantine_note"])
        self.assertFalse(self.pub("INFO", 20)["can_quarantine"])

    def test_notes(self):
        self.assertIsNone(self.pub("MALICIOUS", 90)["quarantine_note"])
        self.assertIn("sandboksu", g.public_result({"path": self.f, "verdict": "MALICIOUS", "score": 90},
                                                   base=self.tmp.name, sandboxed=True)["quarantine_note"])
        g.SCAN_ROOTS[:] = ["/somewhere/else"]
        self.assertIn("spoza", self.pub("MALICIOUS", 90)["quarantine_note"])
        os.remove(self.f)
        self.assertIn("nie ma", self.pub("MALICIOUS", 90)["quarantine_note"])

    def test_already_quarantined(self):
        p = self.pub("MALICIOUS", 90, quarantined="abc")
        self.assertFalse(p["can_quarantine"])
        self.assertIsNone(p["quarantine_note"])


class WatchDefaultTest(unittest.TestCase):
    def test_auto_quarantine_is_opt_in(self):
        ns = argparse.Namespace
        self.assertFalse(auto_quarantine(ns(quarantine=False, no_quarantine=False)))
        self.assertTrue(auto_quarantine(ns(quarantine=True, no_quarantine=False)))
        self.assertFalse(auto_quarantine(ns(quarantine=True, no_quarantine=True)))
        self.assertFalse(auto_quarantine(ns()))


if __name__ == "__main__":
    unittest.main()

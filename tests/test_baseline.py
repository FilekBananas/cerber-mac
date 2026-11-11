"""The "normal behaviour" autoencoder of this Mac (cerber/envscan/baseline.py).

* features: fixed length, names only as hash buckets (no path or name text in the vector);
* loader: plain JSON only, refuses wrong format / dimensions / oversized layers;
* the hint: LOW confidence, at most 15 points, no "confidence": "high" (active defense never acts on it);
* no model → the collector does nothing; a model that reconstructs badly flags, a good one does not.

    .venv/bin/python -m unittest tests.test_baseline -v
"""
from __future__ import annotations

import json
import os
import random
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerber.core import Confidence  # noqa: E402
from cerber.envscan import baseline as bl  # noqa: E402


def _spec(dims=(bl.DIM, 8, bl.DIM), zero=True, threshold=0.5):
    rnd = random.Random(1)
    layers = []
    for i, o in zip(dims[:-1], dims[1:]):
        layers.append({"W": [[0.0 if zero else rnd.uniform(-.1, .1) for _ in range(i)] for _ in range(o)],
                       "b": [0.0] * o})
    return {"format": bl.MODEL_FORMAT, "dim": bl.DIM, "mean": [0.0] * bl.DIM, "std": [1.0] * bl.DIM,
            "layers": layers, "threshold": threshold, "scale": threshold * 3, "meta": {"test": True}}


class BaselineTest(unittest.TestCase):
    def _info(self, **kw):
        now = time.time()
        return {"pid": 4242, "ppid": 1, "name": "updater", "exe": "/Users/x/Library/Application Support/.k2/updater",
                "cmdline": ["updater", "--id", "abc"], "uid": os.getuid(), "create_time": now - 10, **kw}

    def test_feature_vector(self):
        x = bl.features(self._info(), [{"raddr": ("45.33.12.7", 4444), "status": "ESTABLISHED", "type": 1}],
                        "unsigned", {"exe": "/sbin/launchd", "name": "launchd"}, "/Users/x", os.getuid())
        self.assertEqual(len(x), bl.DIM)
        self.assertTrue(all(isinstance(v, float) for v in x))
        self.assertEqual(len(bl.features({"pid": 5}, None, None, None, "/Users/x", 501)), bl.DIM)

    def test_loader_refuses_bad_models(self):
        bl.Model(_spec())
        for bad in ({**_spec(), "format": "pickle"}, {**_spec(), "dim": 5}, {**_spec(), "mean": [0.0]},
                    _spec(dims=(bl.DIM, 8, 7)), _spec(dims=(bl.DIM, bl.MAX_LAYER + 1, bl.DIM)), [], "x"):
            with self.assertRaises((ValueError, KeyError, TypeError)):
                bl.Model(bad)
        d = tempfile.mkdtemp()
        p = os.path.join(d, "m.json")
        with open(p, "wb") as fh:
            fh.write(b"\x80\x04cos\nsystem\n")                    # a pickle is not JSON
        self.assertIsNone(bl.Model.load(p))
        with open(p, "w") as fh:
            json.dump(_spec(), fh)
        self.assertIsNotNone(bl.Model.load(p))

    def _run(self, spec):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "m.json")
        with open(p, "w") as fh:
            json.dump(spec, fh)
        added = []
        ctx = SimpleNamespace(homes=[SimpleNamespace(home="/Users/x")], inventory={}, progress=lambda m: None,
                              sign=lambda exe: SimpleNamespace(status="unsigned"),
                              add_finding=lambda *a: added.append(a))
        procs = {4242: self._info(), 1: {"pid": 1, "exe": "/sbin/launchd", "name": "launchd"}}
        with mock.patch.object(bl, "model_path", lambda: p), \
                mock.patch("cerber.envscan.processes.snapshot", lambda ctx: procs), \
                mock.patch("cerber.envscan.processes._own_lineage", lambda: set()), \
                mock.patch("cerber.envscan.live.is_cerber_process", lambda *a: False), \
                mock.patch("cerber.envscan.live.probe", lambda *a, **k: ([], [])):
            bl.collect_baseline(ctx)
        return added, ctx.inventory

    def test_hint_is_bounded_and_never_high(self):
        added, inv = self._run(_spec(threshold=0.01))           # a zero network reconstructs nothing → anomaly
        self.assertEqual(len(added), 1)
        _cat, _title, _loc, sigs, details = added[0]
        self.assertTrue(all(s.score <= bl.BASELINE_CAP and s.confidence == Confidence.LOW for s in sigs))
        self.assertNotEqual(details.get("confidence"), "high")
        self.assertEqual(inv["baseline"]["anomalies"], 1)

    def test_good_reconstruction_no_hint(self):
        added, _ = self._run(_spec(threshold=1e9))
        self.assertEqual(added, [])

    def test_no_model_no_findings(self):
        with mock.patch.object(bl, "model_path", lambda: "/nonexistent/m.json"):
            ctx = SimpleNamespace(inventory={})
            bl.collect_baseline(ctx)
        self.assertEqual(ctx.inventory["baseline"], {"model": None})


if __name__ == "__main__":
    unittest.main()

"""ML TLSH hint (cerber/analyzers/ml_tlsh.py): JSON-only loader, <= 15 points, never MALICIOUS on its own, and the
active defense never acts on a verdict that only the ML points made MALICIOUS."""
from __future__ import annotations

import json
import os
import pickle
import random
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cerber import verdict as V  # noqa: E402
from cerber.analyzers import ml_tlsh as M  # noqa: E402
from cerber.core import Confidence, Detection, Verdict  # noqa: E402
from cerber.pipeline import Pipeline  # noqa: E402


def const_model(logit: float, t_medium: float = 0.9, t_low: float = 0.5) -> dict:
    """A valid model whose output is a constant (all weights zero, bias = logit)."""
    return {"format": M.MODEL_FORMAT, "version": 1, "kind": "mlp",
            "layers": [{"W": [[0.0]] * M.MLP_DIM, "b": [logit]}],
            "thresholds": {"medium": t_medium, "low": t_low}}


def fake_macho(n: int = 16384, seed: int = 1) -> bytes:
    rng = random.Random(seed)
    words = [b"_objc_msgSend", b"/usr/lib/libSystem.B.dylib", b"__TEXT", b"__DATA", b"NSString", b"main"]
    body = bytearray()
    while len(body) < n:
        body += rng.choice(words) if rng.random() < 0.3 else bytes([rng.randrange(256)])
    return b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01" + bytes(body[:n])


def scan(model: M.Model, data: bytes):
    pipe = Pipeline(analyzers=[M.MLTlshAnalyzer(model)], options={"deep": True, "macos": False})
    return pipe.scan_bytes(data, "/tmp/x")


class LoaderTest(unittest.TestCase):
    def test_refuses_pickle(self):
        for proto in range(0, pickle.HIGHEST_PROTOCOL + 1):
            with self.assertRaises(M.ModelError):
                M.load_model_bytes(pickle.dumps(const_model(0.0), protocol=proto))

    def test_refuses_npz_zip_and_non_objects(self):
        for blob in (b"PK\x03\x04" + b"\x00" * 40, b"\x93NUMPY\x01\x00", b"[1, 2, 3]", b"", b"\xff\xfe{"):
            with self.assertRaises(M.ModelError):
                M.load_model_bytes(blob)

    def test_refuses_bad_shapes_and_numbers(self):
        bad = []
        m = const_model(0.0)
        m["format"] = "other"
        bad.append(m)
        m = const_model(0.0)
        m["layers"][0]["W"] = m["layers"][0]["W"][:-1]           # wrong input width
        bad.append(m)
        m = const_model(0.0)
        m["layers"][0]["b"] = [0.0, 0.0]                          # two outputs, rows of width 1
        bad.append(m)
        m = const_model(0.0)
        m["thresholds"] = {"medium": 1.5}
        bad.append(m)
        m = const_model(0.0)
        m["kind"] = "pickle"
        bad.append(m)
        m = {"format": M.MODEL_FORMAT, "version": 1, "kind": "gbdt", "base": 0.0,
             "trees": [[[999, 0.5, 1, 2], [-1, 1.0], [-1, 2.0]]], "thresholds": {"medium": 0.9}}
        bad.append(m)                                             # feature index out of range
        for spec in bad:
            with self.assertRaises(M.ModelError, msg=str(spec)[:80]):
                M.load_model_bytes(json.dumps(spec).encode())
        with self.assertRaises(M.ModelError):
            M.load_model_bytes(json.dumps(const_model(0.0)).replace("0.0]", "NaN]", 1).encode())

    def test_refuses_symlinked_model(self):
        d = tempfile.mkdtemp()
        try:
            real = os.path.join(d, "real.json")
            Path(real).write_text(json.dumps(const_model(0.0)))
            self.assertIsInstance(M.load_model(real), M.Model)
            os.symlink(real, os.path.join(d, "link.json"))
            with self.assertRaises(OSError):
                M.load_model(os.path.join(d, "link.json"))
        finally:
            shutil.rmtree(d)

    def test_gbdt_and_tlsh_decoding(self):
        spec = {"format": M.MODEL_FORMAT, "version": 1, "kind": "gbdt", "base": -1.0,
                "trees": [[[0, 100.5, 1, 2], [-1, -3.0], [-1, 5.0]]], "thresholds": {"medium": 0.9, "low": 0.5}}
        model = M.load_model_bytes(json.dumps(spec).encode())
        raw = M.tlsh_raw("T12BF34E23532C287AC449607F458747227881FEAA53B593AA0B94C11DBBD7FAD1B3BF41")
        self.assertEqual(len(raw), M.RAW_DIM)
        self.assertEqual(raw[:3], [0x3F, 4, 14])                 # header "F3" -> Lvalue 0x3F, Q byte "4E"
        self.assertAlmostEqual(model.logit(raw), -4.0)          # lval 63 <= 100.5 -> left leaf
        self.assertIsNone(M.tlsh_raw("TNULL"))
        self.assertIsNone(M.tlsh_raw("T1zz"))
        self.assertEqual(len(M.mlp_dense(raw)), M.MLP_DIM)

    def test_shipped_model_if_present_is_json_and_valid(self):
        path = M.default_model_path()
        if not os.path.exists(path):
            self.skipTest("brak db/compiled/ml_tlsh.json")
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(1), b"{")
        model = M.load_model(path)
        self.assertLess(model.t_low, 1.0)
        self.assertLessEqual(model.t_low, model.t_medium)


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.always = M.load_model_bytes(json.dumps(const_model(50.0)).encode())   # p ~= 1 for everything

    def test_score_capped_and_confidence_bounded(self):
        root = scan(self.always, fake_macho())
        dets = [d for o in root.iter_tree() for d in o.detections if d.engine == M.ML_ENGINE]
        self.assertEqual(len(dets), 1)
        self.assertEqual(dets[0].name, M.DET_NAME)
        self.assertLessEqual(dets[0].score, 15)
        self.assertLessEqual(dets[0].confidence, Confidence.MEDIUM)
        res = M.score_digest(self.always, "T12BF34E23532C287AC449607F458747227881FEAA53B593AA0B94C11DBBD7FAD1B3BF41")
        self.assertEqual(res[2], M.ML_CAP)
        self.assertEqual(M.ML_CAP, 15)

    def test_never_malicious_alone(self):
        root = scan(self.always, fake_macho())
        self.assertLessEqual(root.meta["verdict"], Verdict.INFO)
        # many Mach-O members in one container: still one name per unit, no MALICIOUS
        self.assertNotEqual(root.meta["verdict"], Verdict.MALICIOUS)

    def test_quiet_model_and_shallow_scan(self):
        never = M.load_model_bytes(json.dumps(const_model(-50.0)).encode())
        self.assertFalse([d for o in scan(never, fake_macho()).iter_tree() for d in o.detections])
        pipe = Pipeline(analyzers=[M.MLTlshAnalyzer(self.always)], options={"deep": False, "macos": False})
        self.assertFalse([d for o in pipe.scan_bytes(fake_macho(), "/tmp/x").iter_tree() for d in o.detections])
        # not a Mach-O -> not applied
        self.assertFalse([d for o in scan(self.always, b"#!/bin/sh\n" + b"echo hi\n" * 400).iter_tree()
                          for d in o.detections])

    def test_pushes_but_does_not_decide(self):
        """65 points of real (HIGH) evidence + 15 ML = 80 -> MALICIOUS by score, but ml_decisive() says so."""
        root = scan(self.always, fake_macho())
        root.detections.append(Detection("Heur:MachO.Test", "heuristic", Confidence.HIGH, 65))
        V.compute_verdict(root)
        self.assertEqual(root.meta["verdict"], Verdict.MALICIOUS)
        from cerber.scanner import result_dict
        r = result_dict(root, False)
        self.assertTrue(V.ml_decisive(r))
        root.detections[-1].score = 80                        # enough without the model
        V.compute_verdict(root)
        self.assertFalse(V.ml_decisive(result_dict(root, False)))


def res(score: int, *dets: dict, verdict: str = "MALICIOUS", path: str = "/x") -> dict:
    return {"path": path, "verdict": verdict, "score": score, "detections": list(dets)}


ML_DET = {"name": M.DET_NAME, "engine": "ml", "confidence": "MEDIUM", "score": 15}
HEUR = {"name": "Heur:X", "engine": "heuristic", "confidence": "HIGH", "score": 70}
SIG = {"name": "ClamAV:Osx.Trojan.Amos", "engine": "clamav", "confidence": "CERTAIN", "score": 100}


class DefenseGuardTest(unittest.TestCase):
    def test_ml_decisive_rules(self):
        self.assertTrue(V.ml_decisive(res(85, HEUR, ML_DET)))           # 85 - 15 = 70 < 80
        self.assertFalse(V.ml_decisive(res(95, HEUR | {"score": 80}, ML_DET)))
        self.assertFalse(V.ml_decisive(res(85, HEUR, ML_DET, SIG)))      # a signature decided
        self.assertFalse(V.ml_decisive(res(85, HEUR)))                   # no ML involved
        self.assertFalse(V.ml_decisive(res(85, HEUR, ML_DET, verdict="SUSPICIOUS")))
        self.assertFalse(V.ml_decisive(None))

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.file = os.path.join(self.tmp, "a.bin")
        Path(self.file).write_bytes(b"x")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_gui_backend_skips_ml_decided(self):
        from cerber import gui_backend as gb
        calls = []
        fake = SimpleNamespace(on_malicious_file=lambda p, r: calls.append(p) or {"quarantined": "q"})
        with mock.patch.object(gb, "DEFENDER", fake), mock.patch.object(gb, "DEFENDED", {}), \
                mock.patch.object(gb, "SCAN_ROOTS", [self.tmp]):
            r1 = res(85, HEUR, ML_DET, path=self.file)
            gb.defend_result(r1)
            self.assertEqual(calls, [])
            self.assertNotIn("quarantined", r1)
            gb.defend_result(res(95, HEUR | {"score": 80}, ML_DET, path=self.file))
            self.assertEqual(calls, [self.file])

    def test_watch_persist_skips_ml_decided(self):
        from cerber import config, watch
        calls = []
        fake = SimpleNamespace(enabled=True, on_malicious_file=lambda p, r: calls.append(p) or {"quarantined": "q"})
        me = SimpleNamespace(defender=fake)
        job = SimpleNamespace(paths=[self.tmp], id="t", name="t")
        reports = os.path.join(self.tmp, "reports")
        with mock.patch.object(config, "REPORTS", reports), mock.patch("cerber.report.write_html", lambda *a: None):
            r = {"report_data": {"results": [res(85, HEUR, ML_DET, path=self.file)]}, "flagged": []}
            watch.Watcher._persist(me, job, r)
            self.assertEqual(calls, [])
            r = {"report_data": {"results": [res(95, HEUR | {"score": 80}, ML_DET, path=self.file)]}, "flagged": []}
            watch.Watcher._persist(me, job, r)
            self.assertEqual(calls, [self.file])

    def test_ai_ignores_ml_hint(self):
        from cerber.engines import ai
        accs, facts = ai.accusations(res(30, HEUR | {"score": 30}, ML_DET))
        self.assertEqual([a["name"] for a in accs], ["Heur:X"])
        self.assertEqual(facts, [])


if __name__ == "__main__":
    unittest.main()

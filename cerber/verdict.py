"""Turn the detections of an object tree into one verdict for the top-level file.

Heuristic evidence is aggregated per *unit*: a real file/member/stream together
with its decoded layers and its architecture slices. A unit's score also
includes the detections of the containers above it (e.g. an archive flagged
for an RTLO member name), but never those of unrelated siblings – otherwise
weak, unrelated signals from thousands of files in a big bundle (app.asar,
node_modules, installers) would add up to a false "malicious" verdict.
Exact signature matches (Confidence.CERTAIN) anywhere in the tree decide on
their own.
"""
from __future__ import annotations

from .core import Confidence, ScanObject, Verdict

MALICIOUS_SCORE = 80
SUSPICIOUS_SCORE = 35
INFO_SCORE = 10

SAME_UNIT_KINDS = {"decoded", "slice", "normalized", "unpacked"}
TRUST_ENGINES = {"macos"}


def _unit_of(o: ScanObject) -> ScanObject:
    while o.parent is not None and o.kind in SAME_UNIT_KINDS:
        o = o.parent
    return o


def _mostly_pua(names: dict[str, int], pua_names: set[str]) -> bool:
    """Heuristic score dominated by adware/hacktool/grayware findings."""
    if not pua_names:
        return False
    pua_score = sum(v for k, v in names.items() if k in pua_names)
    return pua_score * 2 >= sum(names.values())


def compute_verdict(root: ScanObject) -> None:
    dets = [d for o in root.iter_tree() for d in o.detections]
    certain = [d for d in dets if d.confidence == Confidence.CERTAIN]
    certain_mal = [d for d in certain if not d.pua]
    whitelisted = root.meta.get("whitelisted")
    # validly signed by Apple / a notarized Developer ID: weak heuristics count half
    # (strong heuristics and signatures are never dampened – signed malware exists)
    trusted = bool(root.meta.get("trusted_signer"))

    # own heuristic evidence per unit: name -> (max score, is HIGH>=30, is pua)
    own: dict[int, dict[str, tuple[int, bool, bool]]] = {}
    units: dict[int, ScanObject] = {}
    for o in root.iter_tree():
        u = _unit_of(o)
        units[id(u)] = u
        rec = own.setdefault(id(u), {})
        for d in o.detections:
            if d.confidence >= Confidence.CERTAIN:
                continue
            sc = d.score // 2 if trusted and d.confidence <= Confidence.MEDIUM else d.score
            prev = rec.get(d.name)
            # signature/trust problems ("macos" engine) are serious but say nothing about what the
            # code does: they can make a file SUSPICIOUS, never MALICIOUS without content evidence
            high = d.confidence == Confidence.HIGH and d.score >= 30 and d.engine not in TRUST_ENGINES
            if prev is None or sc > prev[0]:
                rec[d.name] = (sc, high or (prev[1] if prev else False), d.pua)

    best_score, best_high, best_names, best_pua, best_unit = 0, 0, {}, set(), root
    for uid, u in units.items():
        merged: dict[str, tuple[int, bool, bool]] = dict(own.get(uid, {}))
        a = u.parent
        seen = {uid}
        while a is not None:  # containers above this unit
            au = _unit_of(a)
            if id(au) not in seen:
                seen.add(id(au))
                for name, val in own.get(id(au), {}).items():
                    if name not in merged or val[0] > merged[name][0]:
                        merged[name] = val
            a = au.parent
        score = sum(v[0] for v in merged.values())
        if score > best_score:
            best_score = score
            best_high = sum(1 for v in merged.values() if v[1])
            best_names = {k: v[0] for k, v in merged.items()}
            best_pua = {k for k, v in merged.items() if v[2]}
            best_unit = u

    score = best_score
    if certain_mal and not whitelisted:
        verdict = Verdict.MALICIOUS
    elif certain and not whitelisted:
        verdict = Verdict.PUA
    elif whitelisted:
        verdict = Verdict.CLEAN
    elif score >= MALICIOUS_SCORE and best_high >= 1 and not _mostly_pua(best_names, best_pua):
        verdict = Verdict.MALICIOUS
    elif score >= SUSPICIOUS_SCORE and _mostly_pua(best_names, best_pua):
        verdict = Verdict.PUA
    elif score >= SUSPICIOUS_SCORE:
        verdict = Verdict.SUSPICIOUS
    elif score >= INFO_SCORE:
        verdict = Verdict.INFO
    else:
        verdict = Verdict.CLEAN

    root.meta["verdict"] = verdict
    root.meta["score"] = score
    if best_score and best_unit is not root:
        root.meta["worst_object"] = best_unit.display_path
    if dets:
        best = max(dets, key=lambda d: (d.confidence, not d.pua, d.score))
        root.meta["primary"] = best.name
    else:
        root.meta["primary"] = None

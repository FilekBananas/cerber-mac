"""Data model of the live-environment scan (EnvFinding / EnvReport / Signal).

Kept free of heavy imports so that cerber.analyzers.plist_persistence can
import the shared launchd rules without pulling psutil & co.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any

from ..core import Confidence, Detection

# Same thresholds as cerber.verdict, so a finding "reads" like a file verdict.
MALICIOUS_SCORE = 80
SUSPICIOUS_SCORE = 35
LOW_SCORE = 10


@dataclass
class Signal:
    """One indicator. Several signals about the same item are merged into one Detection."""
    name: str                       # "Heur:Launchd.TempPath"
    score: int
    confidence: Confidence
    description: str
    evidence: list[str] = field(default_factory=list)
    pua: bool = False

    def scaled(self, factor: float, note: str = "") -> "Signal":
        conf = self.confidence
        if factor < 1 and conf > Confidence.LOW:
            conf = Confidence(conf - 1)
        desc = self.description + (f" ({note})" if note else "")
        return Signal(self.name, int(round(self.score * factor)), conf, desc, list(self.evidence), self.pua)


def combine(signals: list[Signal], engine: str = "env") -> Detection | None:
    """Merge the signals of one item into a single Detection.

    Score = sum of the per-name maxima (capped at 100); confidence = strongest
    signal, promoted to HIGH when two independent MEDIUM+ indicators agree and
    the total is already in "suspicious" territory.
    """
    if not signals:
        return None
    best: dict[str, Signal] = {}
    for s in signals:
        cur = best.get(s.name)
        if cur is None or (s.score, s.confidence) > (cur.score, cur.confidence):
            best[s.name] = s
    sigs = sorted(best.values(), key=lambda s: (s.confidence, s.score), reverse=True)
    total = min(100, sum(max(0, s.score) for s in sigs))
    conf = max(s.confidence for s in sigs)
    strong = [s for s in sigs if s.confidence >= Confidence.MEDIUM and s.score >= 15]
    if conf == Confidence.MEDIUM and len(strong) >= 2 and total >= 60:
        conf = Confidence.HIGH
    top = sigs[0]
    desc = top.description
    if len(sigs) > 1:
        _n = len(sigs) - 1
        _w = "inny wskaźnik" if _n == 1 else ("inne wskaźniki" if _n % 10 in (2, 3, 4) and _n % 100 not in (12, 13, 14) else "innych wskaźników")
        desc += f" (+{_n} {_w})"
    evidence: list[str] = []
    for s in sigs:
        line = f"{s.name} [+{s.score}]: {s.description}"
        if s.evidence:
            line += " :: " + " | ".join(e[:300] for e in s.evidence[:3])
        evidence.append(line)
    scoring = [s for s in sigs if s.score >= LOW_SCORE]
    pua = bool(scoring) and all(s.pua for s in scoring)
    return Detection(name=top.name, engine=engine, confidence=conf, score=total,
                     description=desc, evidence=evidence, pua=pua)


def severity_of(det: Detection) -> str:
    if det.confidence == Confidence.CERTAIN:
        return "pua" if det.pua else "malicious"
    if det.score >= MALICIOUS_SCORE and det.confidence >= Confidence.HIGH:
        return "pua" if det.pua else "malicious"
    if det.score >= SUSPICIOUS_SCORE:
        return "pua" if det.pua else "suspicious"
    if det.score >= LOW_SCORE:
        return "low"
    return "info"


SEVERITY_ORDER = {"malicious": 4, "pua": 3, "suspicious": 2, "low": 1, "info": 0}


@dataclass
class EnvFinding:
    category: str            # persistence | process | network | posture | browser | shell | ssh | profile | kext | hosts | dns | tcc | ...
    title: str               # human readable, English
    location: str            # path / pid / setting name
    detection: Detection     # engine="env", calibrated confidence/score
    details: dict            # raw data for the report (JSON-serialisable, privacy-filtered)

    @property
    def severity(self) -> str:
        return severity_of(self.detection)

    @property
    def score(self) -> int:
        return self.detection.score

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "location": self.location,
            "severity": self.severity,
            "detection": self.detection.to_dict(),
            "details": jsonable(self.details),
        }


@dataclass
class EnvReport:
    findings: list[EnvFinding]
    targets: list[str]       # existing files/dirs the file scanner must deep-scan afterwards
    inventory: dict          # everything enumerated, incl. "counts" per category
    posture: dict            # SIP, Gatekeeper, FileVault, firewall, XProtect, updates ...
    limitations: list[str]   # what could not be checked and why

    def by_severity(self, minimum: str = "info") -> list[EnvFinding]:
        floor = SEVERITY_ORDER[minimum]
        return [f for f in self.findings if SEVERITY_ORDER[f.severity] >= floor]

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "targets": list(self.targets),
            "inventory": jsonable(self.inventory),
            "posture": jsonable(self.posture),
            "limitations": list(self.limitations),
        }


def jsonable(obj: Any, _depth: int = 0) -> Any:
    """Convert plist/psutil data into something json.dumps accepts."""
    if _depth > 12:
        return repr(obj)[:200]
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, (bytes, bytearray)):
        return f"<{len(obj)} bytes>"
    if isinstance(obj, (_dt.datetime, _dt.date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {str(k): jsonable(v, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [jsonable(v, _depth + 1) for v in obj]
    if isinstance(obj, Detection):
        return obj.to_dict()
    if hasattr(obj, "to_dict"):
        try:
            return jsonable(obj.to_dict(), _depth + 1)
        except Exception:  # noqa: BLE001
            pass
    return str(obj)

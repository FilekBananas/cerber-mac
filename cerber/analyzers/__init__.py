"""Analyzer plugins.

Every module in this package is imported automatically; any class decorated
with @register becomes part of the scan pipeline. Analyzers must never raise:
the pipeline catches exceptions, but an analyzer should record problems in
obj.errors and carry on.

Scoring guide for Detection.score (summed over the whole object tree):
     5  weak indicator (common in clean software too)
    15  notable (unusual for clean files)
    30  strong (rare outside malware)
    50  very strong (malware technique with little legitimate use)
    80+ practically certain malicious
Use Confidence.CERTAIN only for exact family/signature matches.
Detection names: "Heur:<Area>.<What>", e.g. "Heur:VBA.AutoExec.Shell",
"Heur:PS1.EncodedCommand", "Heur:MachO.AdhocSigned".
"""
from __future__ import annotations

import importlib
import pkgutil

from ..core import Analyzer

REGISTRY: list[type[Analyzer]] = []


def register(cls: type[Analyzer]) -> type[Analyzer]:
    REGISTRY.append(cls)
    return cls


_loaded = False


def load_all() -> list[Analyzer]:
    global _loaded
    if not _loaded:
        for mod in pkgutil.iter_modules(__path__):
            if not mod.name.startswith("_"):
                importlib.import_module(f"{__name__}.{mod.name}")
        _loaded = True
    return sorted((cls() for cls in REGISTRY), key=lambda a: (a.order, a.name))

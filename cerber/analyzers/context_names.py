"""Name + location + origin of top-level files (analyzer "context_names", order 25, after exe_macos_trust).

Weak, context-only hints for programs, scripts and installers – they never decide alone (at most LOW/MEDIUM
points), but add up with what the content engines and the correlation step find:
    Heur:Context.Name.*            names malware likes (keylogger, stealer, RAT, crack …: ≤ 20, LOW), double
                                   extensions / invisible or look-alike characters (25–45: deceit by design)
    Heur:Context.DownloadedUnsigned  executable downloaded from the Internet without a trusted signature
    Heur:Context.Location          program/script in /tmp, /Users/Shared, a hidden or random-named folder
A valid Apple / Developer ID / App Store signature (meta "trusted_signer") silences the name words and location.
Shared logic: cerber.envscan.provenance.
"""
from __future__ import annotations

import os
import re
import time

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from ..envscan.patterns import classify_path
from ..envscan.provenance import name_signals
from ..filetype import EXECUTABLE_TYPES, SCRIPT_TYPES
from . import register

_EXTENSION_DIR = re.compile(r"/(?:Extensions/[a-p]{32}/|extensions/[^/]+\.xpi/|Extensions/[^/]+@[^/]+/|"
                            r"Safari/Extensions/)")
RUNNABLE_EXT = (".app", ".command", ".tool", ".pkg", ".mpkg", ".dmg", ".terminal", ".scpt", ".applescript",
                ".workflow", ".jar", ".sh", ".py", ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1")


@register
class ContextNamesAnalyzer(Analyzer):
    name = "context_names"
    order = 25

    def applies(self, obj: ScanObject) -> bool:
        return obj.parent is None and bool(obj.real_path)

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        path = obj.real_path or ""
        base = os.path.basename(path.rstrip("/"))
        runnable = obj.ftype in EXECUTABLE_TYPES or (obj.ftype in SCRIPT_TYPES - {"text", "html"}) \
            or base.lower().endswith(RUNNABLE_EXT) \
            or ".app/Contents/MacOS/" in path
        trusted = bool(obj.meta.get("trusted_signer"))
        q = (obj.meta.get("macos") or {}).get("quarantine")
        pi = classify_path(path)
        if pi.has("apple", "pkgmgr"):
            return
        # inside an app bundle the app as a whole is judged (its main executable); in project folders hidden
        # dirs (.webpack, .venv, .git, .env files) are ordinary – only odd *system* places count there
        in_bundle = pi.has("app_bundle")
        home = os.path.expanduser("~")
        in_project = path.startswith(home + "/") and not path.startswith(home + "/Library/") and not pi.has("tmp")
        odd = [t for t in ("tmp", "shared", "trash", "random_appsupport", "random_library") if pi.has(t)]
        if pi.has("hidden") and not (in_bundle or in_project):
            odd.append("hidden")
        main_exe = in_bundle and "/Contents/MacOS/" in path and path.count(".app/") == 1
        # browser extension files run inside the browser's sandbox, not as programs; the browser-extension
        # analysis (permissions, origin) judges them. Bundlers name their chunks "elm-Ch65hlGH.js": not random
        # malware names, and "downloaded, unsigned" is meaningless for every .js there
        in_extension = bool(_EXTENSION_DIR.search(path))
        untrusted = runnable and not trusted and bool(q or odd) and (not in_bundle or main_exe) and not in_extension
        sigs = name_signals(base, "Heur:Context", "nazwa pliku",
                            trusted=trusted or not runnable or in_bundle or in_extension, untrusted=untrusted)
        if not runnable:          # documents: only the deceit tricks (double extension, invisible chars) count
            sigs = [s for s in sigs if s.name.endswith(("DoubleExtension", "InvisibleChars", "Homoglyph"))]
        if runnable and not trusted and q and (not in_bundle or main_exe) and not in_extension:
            agent = q.get("agent") if isinstance(q, dict) else None
            ts = q.get("time") if isinstance(q, dict) else None
            days = (time.time() - ts) / 86400 if isinstance(ts, (int, float)) else None
            sigs.append(_sig("Heur:Context.DownloadedUnsigned", 10 if days is None or days > 14 else 15,
                             "program lub skrypt pobrany z Internetu bez zaufanego podpisu"
                             + (f" (przez {agent})" if agent else ""), [path]))
        if runnable and not trusted and odd:
            sigs.append(_sig("Heur:Context.Location", 15, "program lub skrypt w nietypowym miejscu ("
                             + ", ".join(odd) + ")", [path]))
        # context alone (name + place + download) stays below "podejrzany": at most 30 points; only deceit tricks
        # (double extension, invisible / look-alike characters) may go higher – content engines decide the rest
        deceit = [s for s in sigs if s.name.endswith(("DoubleExtension", "InvisibleChars", "Homoglyph"))]
        budget = 30
        kept = list(deceit)
        for s in sorted((s for s in sigs if s not in deceit), key=lambda s: -s.score):
            if budget <= 0:
                break
            if s.score > budget:
                s = type(s)(s.name, budget, s.confidence, s.description, s.evidence)
            budget -= s.score
            kept.append(s)
        for s in kept:
            if s.score > 0:
                ctx.detect(obj, Detection(s.name, "heuristic", s.confidence, s.score, s.description,
                                          [str(e)[:200] for e in s.evidence if e]))


def _sig(name: str, score: int, desc: str, ev: list[str]):
    from ..envscan.model import Signal
    return Signal(name, score, Confidence.LOW, desc, ev)

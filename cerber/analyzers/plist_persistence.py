"""File-level persistence-plist heuristics (LaunchAgent/LaunchDaemon, Info.plist LSEnvironment,
loginwindow hooks, emond rules).

Runs on any property list: XML (`plist`, or `xml` with a <plist> root) and binary
(`bplist`), so a LaunchAgent inside a pkg/dmg/zip is judged the same way the live
scanner judges the one in ~/Library/LaunchAgents. The rules themselves live in
cerber.envscan.launchd_rules (shared with the live environment scan).
"""
from __future__ import annotations

import plistlib
import re

from ..core import Analyzer, Detection, ScanContext, ScanObject
from ..envscan.launchd_rules import analyze_plist, scope_for_path
from . import register

MAX_PLIST = 8 << 20


def _logical_path(obj: ScanObject) -> str:
    """Best guess of where the plist would be installed: the innermost path that looks absolute,
    else the member path inside the container (pkg payloads use ./Library/LaunchAgents/...)."""
    tail = obj.display_path.rsplit(">>", 1)[-1]
    if tail.startswith("./"):
        tail = tail[1:]
    if obj.parent is None and obj.real_path:
        return obj.real_path
    m = re.search(r"(/(?:Users/[^/]+/)?Library/Launch(?:Agents|Daemons)/[^/>]+)$", tail)
    if m:
        return m.group(1)
    return tail if tail.startswith("/") else "/" + tail.lstrip("/")


@register
class PlistPersistenceAnalyzer(Analyzer):
    name = "plist_persistence"
    order = 45

    def applies(self, obj: ScanObject) -> bool:
        if obj.size > MAX_PLIST or obj.size < 20:
            return False
        if obj.ftype in ("plist", "bplist"):
            return True
        if obj.ftype == "xml":
            head = obj.data[:4096]
            return b"<plist" in head or b"<!DOCTYPE plist" in head
        return False

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        try:
            data = plistlib.loads(obj.data)
        except Exception as exc:  # noqa: BLE001 - malformed plists are common in archives
            if obj.ftype != "xml":
                obj.errors.append(f"plist_persistence: parse error {type(exc).__name__}")
            return
        path = _logical_path(obj)
        # a plist that really lives on the sealed system volume is Apple's own
        scope = scope_for_path(path)
        if obj.real_path and obj.real_path.startswith("/System/") and obj.parent is None:
            scope = "system"
        # a plist inside a container (dmg / pkg / archive) is not a job installed on this Mac: it may belong to
        # an Apple device image (Xcode DeveloperDiskImage.dmg: com.apple.* daemons in /Developer/usr/...)
        embedded = obj.parent is not None
        pa = analyze_plist(data, path, scope=scope, embedded=embedded)
        if pa.kind == "none" and not pa.signals:
            return
        obj.meta["persistence_plist"] = {"kind": pa.kind, "scope": scope, **pa.meta}
        for s in pa.signals:
            if s.score <= 0:
                continue
            ctx.detect(obj, Detection(name=s.name, engine="heuristic", confidence=s.confidence, score=s.score,
                                      description=s.description, evidence=list(s.evidence), pua=s.pua))
        # hand inline scripts (bash -c / osascript -e / python -c payloads) to the other analyzers
        for i, code in enumerate(pa.inline_codes[:4]):
            ctx.add_child(obj, code.encode("utf-8", "replace"), f"launchd-inline-{i}.sh", kind="decoded")

"""Electron ASAR archives (app.asar, node_modules.asar).

Layout: uint32 4 | uint32 header_size | uint32 header_obj_size | uint32 json_len | JSON index |
file data at 8 + header_size. Index nodes are {"files": {...}} for directories and
{"size": n, "offset": "k", "unpacked": bool} for files; unpacked files live next to the archive
in <name>.asar.unpacked/ and are scanned from disk separately.

Without splitting, a multi-file bundle is one big blob and signatures could match strings that
come from unrelated files; every member becomes its own scan object here.
"""
from __future__ import annotations

import json
import struct

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from . import register

MAX_INDEX = 64 << 20


def is_asar(data: bytes) -> bool:
    return len(data) > 24 and data[:4] == b"\x04\x00\x00\x00" and data[16:25] == b'{"files":'


@register
class AsarAnalyzer(Analyzer):
    name = "asar"
    order = 10

    def applies(self, obj: ScanObject) -> bool:
        return is_asar(obj.data)

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        d = obj.data
        try:
            header_size = struct.unpack_from("<I", d, 4)[0]
            json_len = struct.unpack_from("<I", d, 12)[0]
            if json_len > MAX_INDEX or 16 + json_len > len(d):
                obj.errors.append("asar: index larger than file")
                return
            index = json.loads(d[16:16 + json_len].decode("utf-8", "replace"))
        except (struct.error, ValueError) as exc:
            obj.errors.append(f"asar: bad header ({exc})")
            return
        base = 8 + header_size
        members = unpacked = skipped = 0
        stack = [("", index)]
        while stack:
            prefix, node = stack.pop()
            files = node.get("files") if isinstance(node, dict) else None
            if not isinstance(files, dict):
                continue
            for name, entry in files.items():
                if not isinstance(entry, dict):
                    continue
                path = f"{prefix}{name}"
                if "files" in entry:
                    stack.append((path + "/", entry))
                    continue
                if entry.get("unpacked"):
                    unpacked += 1
                    continue
                if "link" in entry:
                    continue
                try:
                    size = int(entry.get("size", 0))
                    off = base + int(entry.get("offset", 0))
                except (TypeError, ValueError):
                    skipped += 1
                    continue
                if size <= 0:
                    continue
                if off < base or off + size > len(d):
                    skipped += 1
                    continue
                if name in ("..", ".") or "/../" in f"/{path}/":
                    ctx.detect(obj, Detection("Heur:Archive.PathTraversal", "heuristic", Confidence.MEDIUM, 30,
                                              "ASAR entry name escapes the archive", [path]))
                child = ctx.add_child(obj, d[off:off + size], path, kind="member")
                if child is not None:
                    members += 1
                elif ctx.child_count >= ctx.limits.max_children:
                    break
        obj.meta["archive"] = {"format": "asar", "members": members, "unpacked": unpacked, "skipped": skipped}

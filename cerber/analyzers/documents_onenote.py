"""OneNote (.one) analyzer: extracts embedded files (FileDataStoreObject blobs) and flags
scripts/executables hidden in notebooks (the 2023 OneNote malspam technique)."""
from __future__ import annotations

import re
import struct

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from ..filetype import identify_bytes
from ..formats.doc_common import EXEC_EXTENSIONS, classify_payload, short
from . import register

ONE_MAGIC = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")          # {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
ONETOC2_MAGIC = bytes.fromhex("a1 2f ff 43 d9 ef 76 4c 9e e2 10 ea 57 22 76 5f".replace(" ", ""))
FDSO_HEADER = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")        # {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
FDSO_FOOTER = bytes.fromhex("22a7fb71790f0b4abb13899256426b24")        # {71FBA722-0F79-4A0B-BB13-899256426B24}
MAX_BLOBS = 500
_U16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,260}")
_FNAME_RE = re.compile(r"([^\\/:*?\"<>|]{1,200}\.([A-Za-z0-9]{2,5}))$")
_EXT_HINT = {"pe": "exe", "dos": "exe", "elf": "elf", "macho": "macho", "zip": "zip", "ooxml": "docx", "pdf": "pdf",
             "ole2": "ole", "png": "png", "jpeg": "jpg", "gif": "gif", "bmp": "bmp", "lnk": "lnk", "hta": "hta",
             "html": "html", "vbs": "vbs", "javascript": "js", "batch": "bat", "powershell": "ps1", "rtf": "rtf"}


def _det(ctx, obj, name, conf, score, desc, ev=None):
    ctx.detect(obj, Detection(name, "heuristic", conf, score, desc, [short(e, 300) for e in (ev or [])][:20]))


def iter_blobs(data: bytes):
    start = 0
    n = 0
    while n < MAX_BLOBS:
        i = data.find(FDSO_HEADER, start)
        if i < 0 or i + 36 > len(data):
            return
        size = struct.unpack_from("<Q", data, i + 16)[0]
        begin = i + 36
        end = begin + size
        if size == 0 or end > len(data):
            start = i + 16
            continue
        yield i, data[begin:end]
        n += 1
        start = end


@register
class OneNoteAnalyzer(Analyzer):
    name = "onenote"
    order = 40

    def applies(self, obj: ScanObject) -> bool:
        return obj.data[:16] in (ONE_MAGIC, ONETOC2_MAGIC)

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        data = obj.data
        meta: dict = {"format": "onenote" if data[:16] == ONE_MAGIC else "onenote_toc", "embedded": []}
        obj.meta["onenote"] = meta
        if obj.ftype in ("binary", "unknown"):
            obj.fdesc = "OneNote section" if meta["format"] == "onenote" else "OneNote table of contents"
        risky = []
        for idx, (off, blob) in enumerate(iter_blobs(data)):
            ftype, _ = identify_bytes(blob[:1 << 16])
            ext = _EXT_HINT.get(ftype, "bin")
            meta["embedded"].append({"offset": off, "size": len(blob), "type": ftype})
            ctx.add_child(obj, blob, f"onenote/embedded_{idx}.{ext}", kind="member")
            _, reason = classify_payload(blob)
            if reason:
                risky.append(f"blob at {off:#x}: {reason} ({len(blob)} bytes)")
        # embedded file names (UTF-16 property values)
        names = []
        for m in _U16_RE.finditer(data[:64 << 20]):
            fm = _FNAME_RE.search(m.group().decode("utf-16-le", "replace"))
            if fm and fm.group(2).lower() in EXEC_EXTENSIONS and fm.group(2).lower() != "url":
                names.append(fm.group(1).strip())
                if len(names) > 50:
                    break
        names = sorted(set(names))
        if names:
            meta["dangerous_names"] = names
        if meta["embedded"]:
            _det(ctx, obj, "Heur:OneNote.Attachments", Confidence.INFO, 3, "OneNote notebook embeds files",
                 [f"{e['type']} ({e['size']} B)" for e in meta["embedded"][:10]])
        if risky:
            _det(ctx, obj, "Heur:OneNote.EmbeddedExecutable", Confidence.HIGH, 60,
                 "OneNote notebook embeds an executable or script", risky[:10])
        if names:
            _det(ctx, obj, "Heur:OneNote.DangerousAttachmentName", Confidence.MEDIUM, 40,
                 "OneNote notebook references attachments with executable/script extensions", names[:10])

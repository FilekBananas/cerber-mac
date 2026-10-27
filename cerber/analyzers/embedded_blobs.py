"""Long base64 / hex blobs inside any object: decode (bounded) and hand known file types back
as children so every engine rescans them. Flags Heur:Embedded.<Enc>.<Type>.

Every decoded blob of a known type is rescanned as a child, but only blobs that are unusual
for their container are *scored*: web bundles (webpack chunks, Electron app.asar, VS Code
extension.js, ...) routinely inline base64 HTML/JS (data: URIs, workers, srcdoc iframes),
WebAssembly, and zipped/Office templates. An executable hidden in text is always reported.
"""
from __future__ import annotations

import re

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from ..filetype import ARCHIVE_TYPES, DOCUMENT_TYPES, EXECUTABLE_TYPES, SCRIPT_TYPES, identify_bytes
from ..deobf.primitives import b64decode_loose, hexdecode
from . import register

MAX_SCAN = 8 << 20
MAX_BLOBS = 24
MAX_BLOB = 16 << 20
_B64 = re.compile(rb"[A-Za-z0-9+/]{256,}={0,2}")
_HEX = re.compile(rb"[0-9a-fA-F]{512,}")   # flat class (fast); trimmed to even length before decode
_SKIP_FTYPES = {"png", "jpeg", "gif", "bmp", "tiff", "ico", "psd", "mp3", "ogg", "flac", "mkv", "mp4",
                "font", "webp", "wav", "avi", "pem", "pgp", "der", "sqlite"}
SCORES = {"exe": 45, "archive": 15, "document": 15, "script": 10}

# wasm / java classes are routinely base64-embedded in legitimate JS bundles, so they are not
# treated as "an executable hidden in text".
_EXE_EMBED = (EXECUTABLE_TYPES | {"dos"}) - {"wasm", "java_class"}

# decoded web content (data:text/html, worker scripts, srcdoc) - rescanned, never scored by itself
_WEB_SCRIPT = {"html", "javascript", "json", "xml", "text"}
# containers that are (parts of) application bundles rather than documents / droppers
_BUNDLE_EXT = {"js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts", "map", "json", "asar", "wasm", "node",
               "bundle", "chunk", "css"}
_BUNDLE_FTYPES = {"javascript", "json", "binary", "unknown"}


def _category(ft: str) -> str | None:
    if ft in _EXE_EMBED:
        return "exe"
    if ft in ARCHIVE_TYPES or ft in ("jar", "apk"):
        return "archive"
    if ft in DOCUMENT_TYPES:
        return "document"
    if ft in SCRIPT_TYPES and ft != "text":
        return "script"
    return None


def _is_bundle(obj: ScanObject) -> bool:
    """Application code/bundle container (as opposed to a document, e-mail, web page or script).

    HTML/SVG pages are never bundles here, whatever their size: HTML smuggling pages carry
    multi-megabyte base64 ZIP/ISO payloads."""
    if obj.ftype in ("html", "hta", "email") or obj.extension in ("html", "htm", "hta", "svg", "eml", "mht", "mhtml"):
        return False
    return obj.extension in _BUNDLE_EXT or obj.ftype in _BUNDLE_FTYPES


def _score(cat: str, ft: str, desc: str, obj: ScanObject, start: int, length: int) -> int:
    if cat == "exe":
        return SCORES["exe"]
    if obj.extension in ("b64", "base64") and start < 128 and length >= obj.size * 0.9:
        return 0        # a declared base64 file (e.g. an app's *.tar.b64 asset): nothing is hidden
    if cat == "script":
        if ft == "hta":
            return SCORES["script"]
        if ft in _WEB_SCRIPT:
            return 0
        # shell/PowerShell/VBS/AppleScript/... decoded from a small script, page or document
        # (the payload of a dropper); inside a bundle only a shebang-identified script counts,
        # the content sniffer's guesses ("$x = " -> PowerShell) are too weak there
        if _is_bundle(obj) and desc.endswith(" text"):
            return 0
        return SCORES["script"]
    # archive / document: HTML-smuggling pages, e-mails and scripts carry them as payloads;
    # web bundles carry zipped templates / Office samples / helper applets
    return 0 if _is_bundle(obj) else SCORES[cat]


@register
class EmbeddedBlobsAnalyzer(Analyzer):
    name = "embedded_blobs"
    order = 60

    def applies(self, obj: ScanObject) -> bool:
        return obj.size >= 256 and obj.ftype not in _SKIP_FTYPES

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        data = obj.data[:MAX_SCAN]
        found = 0
        for enc, rx, dec in (("Base64", _B64, b64decode_loose), ("Hex", _HEX, hexdecode)):
            for m in rx.finditer(data):
                if found >= MAX_BLOBS:
                    return
                blob = m.group(0)
                if len(blob) > MAX_BLOB:
                    continue
                if enc == "Hex" and len(blob) % 2:
                    blob = blob[:-1]
                raw = dec(blob)
                if not raw:
                    continue
                ft, desc = identify_bytes(raw[:1 << 20])
                cat = _category(ft)
                if cat is None:
                    continue
                found += 1
                ctx.add_child(obj, raw, f"embedded/{enc.lower()}@{m.start():#x}.{ft}", kind="decoded",
                              meta={"embedded_offset": m.start(), "encoding": enc.lower()})
                score = _score(cat, ft, desc, obj, m.start(), len(blob))
                if not score:
                    continue
                ctx.detect(obj, Detection(
                    f"Heur:Embedded.{enc}.{ft.upper()}", "heuristic",
                    Confidence.HIGH if score >= 30 else Confidence.LOW, score,
                    f"{enc}-encoded {desc} embedded in {obj.ftype} content",
                    [f"offset {m.start():#x}, {len(raw)} bytes"], offset=m.start()))

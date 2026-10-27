"""PDF analyzer.

pdfid-style keyword statistics (with #xx name normalisation) plus a structural pass over
the parsed object graph: JavaScript (incl. XFA and object streams) and embedded files are
extracted as children, auto-actions / Launch / remote actions are resolved, URIs are
collected into obj.meta["pdf"]["uris"], and exploit/obfuscation markers are scored.
"""
from __future__ import annotations

import hashlib
import re

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from ..formats import doc_pdf
from ..formats.doc_common import LOLBIN_RE, classify_payload, safe_name, short
from ..formats.doc_pdf import Name, PdfObject, PdfString, Ref
from . import register

KEYWORDS = ["JS", "JavaScript", "AA", "OpenAction", "AcroForm", "JBIG2Decode", "RichMedia", "Launch",
            "EmbeddedFile", "XFA", "URI", "SubmitForm", "GoToR", "GoToE", "ImportData", "ObjStm", "Encrypt",
            "Page", "Colors", "Flash"]
_KW_RE = re.compile(rb"/(" + b"|".join(k.encode() for k in sorted(KEYWORDS, key=len, reverse=True)) +
                    rb")(?![A-Za-z0-9#_.\-])")
_ESC_NAME_RE = re.compile(rb"/(?:[A-Za-z0-9_.+\-]|#[0-9A-Fa-f]{2})*#[0-9A-Fa-f]{2}(?:[A-Za-z0-9_.+\-]|#[0-9A-Fa-f]{2})*")
_COLORS_RE = re.compile(rb"/Colors[\x00\t\n\x0c\r ]+(\d{6,})")
_STRUCT_RE = re.compile(rb"(?<![A-Za-z])(obj|endobj|stream|endstream|xref|trailer|startxref)(?![A-Za-z])")
CRED_WORDS = re.compile(r"(?i)(log-?in|sign-?in|verify|verification|account|password|secure|update|unlock|"
                        r"wallet|office365|o365|microsoft|onedrive|sharepoint|docusign|adobe|invoice|payment|bank)")
AUTO_AA_KEYS = {"O", "PO", "PV"}
MAX_JS_CHILDREN = 200
MAX_EMBEDDED = 200


def _det(ctx, obj, name, conf, score, desc, ev=None):
    ctx.detect(obj, Detection(name, "heuristic", conf, score, desc, [short(e, 300) for e in (ev or [])][:20]))


def keyword_counts(buf: bytes, counts: dict[str, int], obfuscated: dict[str, int]) -> None:
    for m in _KW_RE.finditer(buf):
        k = m.group(1).decode()
        counts[k] = counts.get(k, 0) + 1
    for m in _ESC_NAME_RE.finditer(buf):
        raw = m.group()[1:]
        dec = re.sub(rb"#([0-9A-Fa-f]{2})", lambda x: bytes([int(x.group(1), 16)]), raw).decode("latin-1")
        if dec in KEYWORDS:
            counts[dec] = counts.get(dec, 0) + 1
            obfuscated[dec] = obfuscated.get(dec, 0) + 1


def _text(b: bytes) -> str:
    if b[:2] == b"\xfe\xff":
        return b[2:].decode("utf-16-be", "replace")
    if b[:2] == b"\xff\xfe":
        return b[2:].decode("utf-16-le", "replace")
    if b[:3] == b"\xef\xbb\xbf":
        return b[3:].decode("utf-8", "replace")
    return b.decode("latin-1")


def _walk(value, depth: int = 0):
    """Yield every (direct) dictionary nested in value."""
    if depth > 12:
        return
    if isinstance(value, dict):
        yield value
        for v in value.values():
            if isinstance(v, (dict, list)):
                yield from _walk(v, depth + 1)
    elif isinstance(value, list):
        for v in value[:5000]:
            if isinstance(v, (dict, list)):
                yield from _walk(v, depth + 1)


@register
class PDFAnalyzer(Analyzer):
    name = "pdf"
    order = 40

    def applies(self, obj: ScanObject) -> bool:
        if obj.ftype == "pdf":
            return True
        return obj.ftype in ("binary", "unknown", "text", "html", "xml", "script") and b"%PDF-" in obj.data[:1024]

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        data = obj.data
        meta: dict = obj.meta.setdefault("pdf", {})
        counts: dict[str, int] = {}
        obfuscated: dict[str, int] = {}
        keyword_counts(data, counts, obfuscated)
        try:
            doc = doc_pdf.parse(data)
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"pdf parse: {exc!r}")
            meta["keywords"] = counts
            return
        obj.errors.extend(f"pdf: {e}" for e in doc.errors[:20])
        for o in list(doc.objects.values()):
            if str(o.dict.get("Type", "")) == "ObjStm" and o.raw_stream is not None:
                keyword_counts(doc.stream(o), counts, obfuscated)
        meta.update({
            "version": doc.version, "objects": len(doc.objects), "object_streams": doc.objstm_count,
            "objects_in_objstm": doc.objects_in_objstm, "keywords": counts,
            "eof_markers": data.count(b"%%EOF"), "encrypted": doc.encrypt_ref is not None,
        })
        if doc.header_offset > 0:
            _det(ctx, obj, "Heur:PDF.HeaderOffset", Confidence.LOW, 10,
                 "PDF header is not at the start of the file (polyglot / scanner evasion)", [f"offset {doc.header_offset}"])
        if doc.security is not None:
            meta["encryption"] = {"V": doc.security.v, "R": doc.security.r, "decrypted": doc.security.ok,
                                  "reason": doc.security.reason}
            if not doc.security.ok:
                _det(ctx, obj, "Heur:PDF.Encrypted", Confidence.INFO, 5,
                     "PDF is encrypted with a user password; content could not be inspected", [doc.security.reason])
        self._structure(obj, ctx, doc, meta, counts, obfuscated)
        state = self._actions(obj, ctx, doc, meta)
        self._embedded(obj, ctx, doc, meta, state)
        self._javascript(obj, ctx, doc, meta, state, counts)

    # ------------------------------------------------------------------ structure
    def _structure(self, obj, ctx, doc, meta, counts, obfuscated) -> None:
        data = obj.data
        alnum_escapes = []
        for raw, dec in doc.escaped_names:
            if re.search(r"#(?:3[0-9]|4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa])", raw):
                alnum_escapes.append(f"/{raw} -> /{dec}")
        sus = [e for e in alnum_escapes if e.rsplit("/", 1)[-1] in doc_pdf.SUSPICIOUS_NAMES]
        if obfuscated or sus:
            _det(ctx, obj, "Heur:PDF.ObfuscatedNames", Confidence.MEDIUM, 30,
                 "Security-relevant PDF names hidden with #xx escapes", (sus or [f"{k} x{v}" for k, v in obfuscated.items()])[:10])
        elif len(set(alnum_escapes)) >= 3:
            _det(ctx, obj, "Heur:PDF.ObfuscatedNames", Confidence.LOW, 10,
                 "PDF names use needless #xx escapes", sorted(set(alnum_escapes))[:10])
        big = [int(m.group(1)) for m in _COLORS_RE.finditer(data) if int(m.group(1)) > 1 << 24]
        if big:
            _det(ctx, obj, "Heur:PDF.Exploit.Colors", Confidence.HIGH, 60,
                 "/Colors value > 2^24 (CVE-2009-3459 integer overflow)", [str(b) for b in big[:3]])
        last = data.rfind(b"%%EOF")
        if last >= 0:
            tail = data[last + 5:]
            if len(tail.strip(b"\x00\t\n\x0c\r ")) > 1024:
                ftype, reason = classify_payload(tail.lstrip(b"\x00\t\n\x0c\r "))
                ctx.add_child(obj, tail.lstrip(b"\x00\t\n\x0c\r "), "pdf/trailing.bin", kind="slice")
                _det(ctx, obj, "Heur:PDF.TrailingData", Confidence.MEDIUM if reason or ftype in ("zip", "rar", "7z") else
                     Confidence.LOW, 30 if reason or ftype in ("zip", "rar", "7z") else 10,
                     "Data appended after the final %%EOF", [f"{len(tail)} bytes ({ftype})"])
        pages = sum(1 for o, d in doc.iter_dicts() if str(d.get("Type", "")) == "Page")
        meta["pages"] = pages

    # ------------------------------------------------------------------ actions
    def _actions(self, obj, ctx, doc, meta) -> dict:
        state = {"js": [], "auto_js": [], "launch": [], "uris": [], "remote": [], "submit": [], "filespecs": {},
                 "rich": [], "link_rects": [], "auto_launch": []}
        auto_dicts: set[int] = set()
        # triggers that fire without user interaction
        for o, d in doc.iter_dicts():
            for sub in _walk(d):
                if "OpenAction" in sub:
                    for a in self._action_chain(doc, sub["OpenAction"]):
                        auto_dicts.add(id(a))
                aa = doc.resolve(sub.get("AA"))
                if isinstance(aa, dict):
                    for k, v in aa.items():
                        if k in AUTO_AA_KEYS:
                            for a in self._action_chain(doc, v):
                                auto_dicts.add(id(a))
        for o, d in doc.iter_dicts():
            for sub in _walk(d):
                s = str(sub.get("S", ""))
                auto = id(sub) in auto_dicts
                if "JS" in sub:
                    code = self._js_value(doc, sub["JS"], o)
                    if code:
                        state["js"].append((o.num, code))
                        if auto:
                            state["auto_js"].append(o.num)
                if s == "Launch":
                    cmd = self._launch_cmd(doc, sub, o)
                    state["launch"].append(cmd)
                    if auto:
                        state["auto_launch"].append(cmd)
                if "URI" in sub and s in ("URI", ""):
                    u = _text(doc.string(sub["URI"], o)).strip()
                    if u:
                        state["uris"].append(u)
                if s in ("GoToR", "GoToE", "ImportData", "Launch"):
                    target = self._filespec_name(doc, sub.get("F"), o)
                    if re.match(r"(?i)^\s*(\\\\|//|https?://|smb://|file://[^/])", target):
                        state["remote"].append(f"{s}: {target}")
                if s == "SubmitForm":
                    target = self._filespec_name(doc, sub.get("F"), o)
                    if target:
                        state["submit"].append(target)
                if "EF" in sub:
                    ef = doc.resolve(sub["EF"])
                    name = self._filespec_name(doc, sub, o)
                    if isinstance(ef, dict):
                        for key in ("UF", "F", "DOS", "Unix", "Mac"):
                            if isinstance(ef.get(key), Ref):
                                state["filespecs"][ef[key].num] = name
                                break
                if str(sub.get("Subtype", "")) in ("RichMedia", "Flash") or "RichMediaContent" in sub:
                    state["rich"].append(f"object {o.num}")
                if str(sub.get("Subtype", "")) == "Link" and isinstance(sub.get("Rect"), list):
                    a = doc.resolve(sub.get("A"))
                    if isinstance(a, dict) and "URI" in a:
                        state["link_rects"].append(sub["Rect"])
        uris = list(dict.fromkeys(state["uris"]))
        if uris:
            meta["uris"] = uris[:500]
        if state["launch"]:
            meta["launch"] = [short(c, 300) for c in state["launch"][:20]]
            exe = [c for c in state["launch"] if LOLBIN_RE.search(c) or
                   re.search(r"(?i)\.(exe|scr|com|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|lnk|pif|cpl|sh|command|app)\b", c)]
            if exe:
                _det(ctx, obj, "Heur:PDF.Launch.Exec", Confidence.HIGH, 70,
                     "Launch action starts a program/script", exe[:5])
            else:
                _det(ctx, obj, "Heur:PDF.Launch", Confidence.LOW, 20, "PDF contains a Launch action", state["launch"][:5])
            if state["auto_launch"]:
                _det(ctx, obj, "Heur:PDF.AutoLaunch", Confidence.HIGH, 30,
                     "Launch action runs automatically when the document opens", state["auto_launch"][:5])
        if state["remote"]:
            _det(ctx, obj, "Heur:PDF.RemoteFileAction", Confidence.MEDIUM, 30,
                 "Action opens a file on a remote host / network share (NTLM leak, remote payload)", state["remote"][:5])
        if state["submit"]:
            meta["submit_targets"] = state["submit"][:20]
            _det(ctx, obj, "Heur:PDF.SubmitForm", Confidence.INFO, 3, "Form submits data to a URL", state["submit"][:5])
        if state["rich"]:
            _det(ctx, obj, "Heur:PDF.RichMedia", Confidence.LOW, 10, "PDF embeds Flash/RichMedia content", state["rich"][:5])
        self._phishing(obj, ctx, doc, meta, uris, state)
        return state

    def _action_chain(self, doc, v, depth: int = 0):
        a = doc.resolve(v)
        if isinstance(a, list):
            for x in a[:20]:
                yield from self._action_chain(doc, x, depth + 1)
            return
        if not isinstance(a, dict) or depth > 16:
            return
        yield a
        if "Next" in a:
            yield from self._action_chain(doc, a["Next"], depth + 1)

    def _js_value(self, doc, v, owner: PdfObject) -> str:
        if isinstance(v, Ref):
            target = doc.objects.get(v.num)
            if target is None:
                return ""
            if target.raw_stream is not None:
                return _text(doc.stream(target))
            return _text(doc.string(v))
        if isinstance(v, PdfString):
            return _text(doc.string(v, owner))
        return ""

    def _filespec_name(self, doc, v, owner) -> str:
        v2 = doc.resolve(v)
        if isinstance(v2, dict):
            for key in ("UF", "F", "DOS", "Unix", "Mac"):
                if key in v2 and not isinstance(doc.resolve(v2[key]), dict):
                    s = doc.string(v2[key], owner if not isinstance(v2[key], Ref) else None)
                    if s:
                        return _text(s)
            return ""
        if isinstance(v2, (PdfString, Name, str)):
            return _text(doc.string(v, owner))
        return ""

    def _launch_cmd(self, doc, a: dict, owner) -> str:
        parts = []
        win = doc.resolve(a.get("Win"))
        if isinstance(win, dict):
            for k in ("F", "P", "D"):
                if k in win:
                    parts.append(_text(doc.string(win[k], owner)))
        f = self._filespec_name(doc, a.get("F"), owner)
        if f:
            parts.insert(0, f)
        for k in ("Unix", "Mac"):
            if k in a:
                parts.append(_text(doc.string(a[k], owner)) if not isinstance(doc.resolve(a[k]), dict) else "")
        return " ".join(p for p in parts if p).strip() or "<launch>"

    def _phishing(self, obj, ctx, doc, meta, uris, state) -> None:
        if meta.get("pages") != 1 or not uris or state["js"]:
            return
        page = next((d for o, d in doc.iter_dicts() if str(d.get("Type", "")) == "Page"), {})
        box = doc.resolve(page.get("MediaBox")) or [0, 0, 612, 792]
        try:
            area = abs((float(box[2]) - float(box[0])) * (float(box[3]) - float(box[1]))) or 1.0
            link_area = max((abs((float(r[2]) - float(r[0])) * (float(r[3]) - float(r[1]))) for r in state["link_rects"]
                             if len(r) == 4 and all(isinstance(x, (int, float)) for x in r)), default=0.0)
        except (TypeError, ValueError, IndexError):
            return
        ratio = link_area / area
        cred = [u for u in uris if CRED_WORDS.search(u)]
        if ratio >= 0.2 or (len(uris) <= 3 and cred):
            _det(ctx, obj, "Heur:PDF.PhishingLink", Confidence.INFO, 5,
                 "Single-page PDF whose main content is a clickable link (phishing lure pattern)",
                 [f"link covers {ratio:.0%} of the page"] + uris[:3])

    # ------------------------------------------------------------------ embedded files
    def _embedded(self, obj, ctx, doc, meta, state) -> None:
        names = state["filespecs"]
        found = []
        risky = []
        for o in doc.objects.values():
            d = o.dict
            if o.raw_stream is None:
                continue
            is_ef = str(d.get("Type", "")) == "EmbeddedFile" or o.num in names
            if not is_ef:
                continue
            if len(found) >= MAX_EMBEDDED:
                obj.errors.append("pdf: too many embedded files, rest skipped")
                break
            content = doc.stream(o)
            name = safe_name(names.get(o.num) or f"embedded_{o.num}.bin")
            found.append(f"{name} ({len(content)} bytes)")
            if content:
                ctx.add_child(obj, content, f"pdf/embedded/{name}", kind="member")
            ftype, reason = classify_payload(content, name)
            if reason:
                risky.append(f"{name}: {reason}")
        # Flash / other executable-looking streams referenced from RichMedia
        if found:
            meta["embedded_files"] = found[:100]
            _det(ctx, obj, "Heur:PDF.EmbeddedFile", Confidence.INFO, 3, "PDF carries embedded files", found[:10])
        if risky:
            _det(ctx, obj, "Heur:PDF.EmbeddedExecutable", Confidence.HIGH, 60,
                 "PDF embeds an executable or script file", risky[:10])
        state["embedded"] = found

    # ------------------------------------------------------------------ JavaScript
    def _javascript(self, obj, ctx, doc, meta, state, counts) -> None:
        scripts = []
        seen = set()
        for num, code in state["js"]:
            h = hashlib.sha1(code.encode("utf-8", "replace")).digest()
            if h in seen:
                continue
            seen.add(h)
            scripts.append((f"object {num}", code))
        # XFA forms may carry scripts too
        for o, d in doc.iter_dicts():
            xfa = d.get("XFA") if "Fields" in d or "XFA" in d else None
            if xfa is None:
                continue
            parts = doc.resolve(xfa)
            refs = [x for x in parts if isinstance(x, Ref)] if isinstance(parts, list) else [xfa] if isinstance(xfa, Ref) else []
            xml = b"".join(doc.stream(doc.objects.get(r.num)) for r in refs[:64])
            if xml:
                ctx.add_child(obj, xml, "pdf/xfa.xml", kind="decoded")
                for m in re.finditer(rb"<script\b[^>]*>(.*?)</script>", xml, re.S | re.I):
                    code = m.group(1).decode("utf-8", "replace")
                    if code.strip():
                        scripts.append(("XFA", code))
            break
        if not scripts:
            return
        meta["javascript"] = len(scripts)
        total = {"exploit": [], "spray": [], "obfuscation": [], "actions": []}
        for i, (where, code) in enumerate(scripts):
            if i < MAX_JS_CHILDREN:
                ctx.add_child(obj, code.encode("utf-8", "replace"), f"pdf/js_{i}.js", kind="decoded",
                              meta={"pdf_js_source": where})
            res = doc_pdf.analyze_js(code[:8 << 20])
            for k, v in res.items():
                total[k] += [x for x in v if x not in total[k]]
        _det(ctx, obj, "Heur:PDF.JavaScript", Confidence.LOW, 5, "PDF contains JavaScript",
             [w for w, _ in scripts[:10]])
        if state["auto_js"]:
            _det(ctx, obj, "Heur:PDF.AutoJavaScript", Confidence.MEDIUM, 20,
                 "JavaScript runs automatically when the document/page opens", [f"object {n}" for n in state["auto_js"][:10]])
        if total["exploit"]:
            _det(ctx, obj, "Heur:PDF.JS.Exploit", Confidence.HIGH, 70,
                 "JavaScript calls APIs abused by known Acrobat exploits", total["exploit"])
        if total["spray"]:
            _det(ctx, obj, "Heur:PDF.JS.HeapSpray", Confidence.HIGH, 60, "JavaScript heap-spray pattern", total["spray"])
        obf = total["obfuscation"]
        if len(obf) >= 2 and any(x in obf for x in ("eval", "unescape", "String.fromCharCode")) or \
                any(x.endswith("-char token") for x in obf):
            _det(ctx, obj, "Heur:PDF.JS.Obfuscated", Confidence.MEDIUM, 25, "JavaScript is obfuscated", obf)
        if any("nLaunch" in a for a in total["actions"]):
            _det(ctx, obj, "Heur:PDF.JS.LaunchEmbedded", Confidence.HIGH, 50,
                 "JavaScript extracts and launches an embedded file", total["actions"])
        if counts.get("JBIG2Decode"):
            _det(ctx, obj, "Heur:PDF.JBIG2.JS", Confidence.LOW, 10,
                 "JBIG2 image data combined with JavaScript (exploit pattern)", [f"/JBIG2Decode x{counts['JBIG2Decode']}"])
        if obj.data.count(b"%%EOF") >= 4:
            _det(ctx, obj, "Heur:PDF.IncrementalJS", Confidence.LOW, 10,
                 "JavaScript in a PDF with many incremental updates", [f"{obj.data.count(b'%%EOF')} %%EOF markers"])
        chains = [f"object {o.num}: {'; '.join(o.decode_notes)}" for o in doc.objects.values()
                  if o.decode_notes and any("chained" in n or "non-hex" in n or "/Length" in n for n in o.decode_notes)]
        if chains:
            _det(ctx, obj, "Heur:PDF.StreamObfuscation", Confidence.LOW, 10,
                 "Stream encoding tricks (filter chains, junk in hex data, lying /Length)", chains[:5])

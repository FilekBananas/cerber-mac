"""RTF analyzer: embedded OLE objects (objdata), Equation Editor / OLE2Link objects,
auto-updating objects, DDE fields, remote templates and parser-confusion tricks.

Object extraction uses oletools.rtfobj's Word-compatible parser (handles whitespace/garbage
inside hex data, \\bin, the \\'hh odd-digit quirk) with a subclass that keeps the work
linear on hostile inputs and records obfuscation statistics.
"""
from __future__ import annotations

import re
import struct

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from ..formats import doc_ole
from ..formats.doc_common import classify_payload, safe_name, short
from . import register
from .documents_office import classify_fields, report_dde

try:
    from oletools import rtfobj as _rtfobj
except Exception:  # noqa: BLE001
    _rtfobj = None

MAX_PARSE = 96 << 20
_NONHEX = re.compile(rb"[^0-9A-Fa-f]")
_KEEP_TEXT = {b"objdata", b"objclass", b"fldinst", b"template", b"objname"}
_OBJ_CWORDS = {b"objupdate", b"objautlink", b"objlink", b"objemb", b"objocx", b"objhtml", b"objicemb", b"objsub",
               b"objpub", b"objalink"}
_OK_HEADER = re.compile(rb"^\{\\rtf[0-9\\{\s}]")
_LONG_CWORD = re.compile(rb"\\[a-zA-Z]{48,}")
_LONG_PARAM = re.compile(rb"\\[a-zA-Z]{1,32}-?[0-9]{12,}")
_EQ_HDR = b"\x1c\x00\x00\x00\x02\x00"


def _det(ctx, obj, name, conf, score, desc, ev=None):
    ctx.detect(obj, Detection(name, "heuristic", conf, score, desc, [short(e, 300) for e in (ev or [])][:20]))


if _rtfobj is not None:
    class _Parser(_rtfobj.RtfObjParser):
        """Linear-time variant of RtfObjParser that also records obfuscation statistics."""

        def __init__(self, data):
            super().__init__(data)
            self.destinations[0].data = bytearray()
            self.cwords: dict[bytes, int] = {}
            self.bin_in_objdata = 0
            self.quote_in_objdata = 0
            self.garbage = 0
            self.texts: dict[bytes, list[bytes]] = {}
            self.classes: list[bytes] = []

        def open_destination(self, destination):
            destination.data = bytearray()
            destination._clean = 0

        def close_destination(self, destination):
            cw = destination.cword
            if cw == b"objdata":
                raw = bytes(destination.data)
                stripped = raw.translate(None, b" \t\r\n\f\v")
                self.garbage += len(_NONHEX.findall(stripped))
                destination.data = raw
                super().close_destination(destination)
            elif cw in _KEEP_TEXT and destination.data:
                lst = self.texts.setdefault(cw, [])
                if len(lst) < 1000:
                    lst.append(bytes(destination.data[:65536]))

        def _text(self, matchobject):
            if self.current_destination.cword in _KEEP_TEXT:
                self.current_destination.data += matchobject.group()

        def control_word(self, matchobject, cword, param):
            if cword in _OBJ_CWORDS:
                self.cwords[cword] = self.cwords.get(cword, 0) + 1

        def bin(self, bindata):
            if self.current_destination.cword == b"objdata":
                self.bin_in_objdata += 1
                self.current_destination.data += bindata.hex().encode()

        def control_symbol(self, matchobject):
            sym = matchobject.group()[1:2]
            dest = self.current_destination
            if sym == b"'":
                hexdigits = self.data[self.index + 2:self.index + 4]
                self.index += 2
                if dest.cword == b"objdata":
                    # Word drops the last hex digit before \'hh when an odd number was read so far
                    self.quote_in_objdata += 1
                    d = dest.data
                    start = getattr(dest, "_clean", 0)
                    new = _NONHEX.sub(b"", bytes(d[start:]))
                    del d[start:]
                    d += new
                    if len(d) & 1:
                        del d[-1]
                    dest._clean = len(d)
                elif dest.cword in _KEEP_TEXT:
                    try:
                        dest.data.append(int(hexdigits, 16))
                    except ValueError:
                        pass
            elif sym in (b"\\", b"{", b"}") and dest.cword in _KEEP_TEXT and dest.cword != b"objdata":
                dest.data += sym
else:  # pragma: no cover
    _Parser = None


def _ole1_class(raw: bytes) -> tuple[int, str]:
    """OLE1 ObjectHeader -> (format id, class name) without trusting the rest."""
    if len(raw) < 12:
        return 0, ""
    fmt = struct.unpack_from("<I", raw, 4)[0]
    n = struct.unpack_from("<I", raw, 8)[0]
    if 0 < n < 256:
        return fmt, raw[12:12 + n].rstrip(b"\x00").decode("latin-1", "replace")
    return fmt, ""


@register
class RTFAnalyzer(Analyzer):
    name = "rtf"
    order = 40

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype == "rtf"

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        data = obj.data
        meta: dict = obj.meta.setdefault("rtf", {})
        # ---- header / lexical tricks (cheap, whole file)
        if not _OK_HEADER.match(data[:8]):
            meta["header"] = data[:8].decode("latin-1", "replace")
            _det(ctx, obj, "Heur:RTF.MalformedHeader", Confidence.MEDIUM, 20,
                 "Non-standard RTF header ('{\\rt' without '{\\rtf1'), a scanner-evasion trick", [meta["header"]])
        head = data[:MAX_PARSE]
        long_cw = [m.group()[:60] for m in _LONG_CWORD.finditer(head)][:5]
        long_pr = [m.group()[:60] for m in _LONG_PARAM.finditer(head)][:5]
        if long_cw or long_pr:
            _det(ctx, obj, "Heur:RTF.OversizedControlWord", Confidence.MEDIUM, 20,
                 "Abnormally long control words / numeric parameters (parser confusion)",
                 [x.decode("latin-1") for x in long_cw + long_pr])
        if b"obj" not in head and b"fldinst" not in head and b"template" not in head:
            return
        if _Parser is None:
            obj.errors.append("rtf: oletools.rtfobj not available")
            return
        parser = _Parser(head)
        try:
            parser.parse()
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"rtf parser: {exc!r}")
        self._objects(obj, ctx, meta, parser)
        self._text_destinations(obj, ctx, meta, parser)
        cw = parser.cwords
        meta["control_words"] = {k.decode(): v for k, v in cw.items()}
        if parser.garbage > 16 or parser.bin_in_objdata or parser.quote_in_objdata:
            ev = []
            if parser.garbage > 16:
                ev.append(f"{parser.garbage} non-hex characters inside objdata")
            if parser.bin_in_objdata:
                ev.append(f"\\bin used {parser.bin_in_objdata}x inside objdata")
            if parser.quote_in_objdata:
                ev.append(f"\\'hh used {parser.quote_in_objdata}x inside objdata")
            _det(ctx, obj, "Heur:RTF.Obfuscated", Confidence.MEDIUM, 25, "Embedded object data is obfuscated", ev)

    # ------------------------------------------------------------------ objects
    def _objects(self, obj, ctx, meta, parser) -> None:
        objects = []
        classes = [t.strip().decode("latin-1", "replace") for t in parser.texts.get(b"objclass", [])]
        equation, links, execs, ocx = [], [], [], []
        for i, ro in enumerate(parser.objects[:500]):
            raw = ro.rawdata or b""
            fmt, cls = _ole1_class(raw)
            if ro.class_name:
                cls = ro.class_name.rstrip(b"\x00").decode("latin-1", "replace")
            info = {"index": i, "class": cls, "size": len(raw), "format": {1: "linked", 2: "embedded"}.get(fmt, fmt)}
            objects.append(info)
            base = f"rtf/object_{i}"
            lcls = cls.lower()
            if lcls.startswith(("equation.2", "equation.3")) or lcls in ("equation", "microsoft equation 3.0"):
                equation.append(f"object {i}: class {cls}")
            if lcls.startswith("ole2link") or fmt == 1:
                links.append(f"object {i}: class {cls or '?'} ({info['format']})")
            if ro.is_package and ro.olepkgdata:
                name = safe_name(ro.filename or "package.bin")
                info["filename"] = name
                ctx.add_child(obj, ro.olepkgdata, f"{base}/{name}", kind="member")
                ftype, reason = classify_payload(ro.olepkgdata, name)
                if reason:
                    execs.append(f"object {i}: package {name!r} ({reason}) src={ro.src_path!r}")
            elif ro.is_ole and ro.oledata:
                payload = ro.oledata
                off = payload.find(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
                if 0 < off < 4096:
                    payload = payload[off:]
                ctx.add_child(obj, payload, f"{base}.{safe_name(cls, 'ole')}.bin", kind="member")
                clsid = (ro.clsid or "").upper()
                if clsid:
                    info["clsid"] = clsid
                    cat, desc = doc_ole.clsid_risk(clsid)
                    if cat == "equation":
                        equation.append(f"object {i}: CLSID {clsid}")
                    elif cat == "moniker":
                        links.append(f"object {i}: {desc}")
                    elif cat == "activex_cve":
                        ocx.append(f"object {i}: {desc}")
                if equation and not payload.startswith(b"\xd0\xcf\x11\xe0"):
                    self._raw_equation(obj, ctx, payload)
                for kind, target in doc_ole.find_monikers(payload[:1 << 20]):
                    links.append(f"object {i}: {kind} moniker -> {target}")
            elif raw:
                off = raw.find(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
                ctx.add_child(obj, raw[off:] if off >= 0 else raw, f"{base}.bin", kind="decoded")
                if equation and _EQ_HDR in raw:
                    self._raw_equation(obj, ctx, raw)
        for c in classes:
            lc = c.lower()
            if lc.startswith(("equation.2", "equation.3")):
                equation.append(f"objclass {c}")
            elif lc.startswith("ole2link"):
                links.append(f"objclass {c}")
        meta["objects"] = objects[:100]
        if classes:
            meta["objclass"] = classes[:50]
        if objects or classes:
            _det(ctx, obj, "Heur:RTF.EmbeddedObject", Confidence.INFO, 3, "RTF embeds OLE objects",
                 [f"{o['class'] or '?'} ({o['size']} B)" for o in objects[:10]] or classes[:10])
        if equation:
            _det(ctx, obj, "Heur:RTF.EquationEditor", Confidence.MEDIUM, 25,
                 "RTF embeds a legacy Equation Editor object (CVE-2017-11882 / CVE-2018-0802 vector)", equation)
        remote_links = [l for l in links if "moniker" in l or "ole2link" in l.lower()]
        if remote_links:
            _det(ctx, obj, "Heur:RTF.OLE2Link", Confidence.HIGH, 50,
                 "RTF contains a linked OLE object that fetches remote content (CVE-2017-0199 family)", remote_links)
        if execs:
            _det(ctx, obj, "Heur:RTF.EmbeddedExecutable", Confidence.HIGH, 60,
                 "RTF packages an executable or script", execs)
        if ocx or parser.cwords.get(b"objocx"):
            _det(ctx, obj, "Heur:RTF.ActiveX", Confidence.LOW if not ocx else Confidence.MEDIUM, 10 if not ocx else 40,
                 "RTF embeds an ActiveX control" + (" with a history of exploitation" if ocx else ""), ocx or ["\\objocx"])
        auto = parser.cwords.get(b"objupdate", 0) + parser.cwords.get(b"objautlink", 0)
        if auto and (objects or classes):
            risky = bool(equation or remote_links or execs)
            _det(ctx, obj, "Heur:RTF.AutoUpdate", Confidence.HIGH if risky else Confidence.MEDIUM, 30 if risky else 15,
                 "Embedded object is forced to load/update when the document opens (\\objupdate/\\objautlink)",
                 [f"\\objupdate x{parser.cwords.get(b'objupdate', 0)}, \\objautlink x{parser.cwords.get(b'objautlink', 0)}"])

    def _raw_equation(self, obj, ctx, raw: bytes) -> None:
        i = raw.find(_EQ_HDR)
        if i < 0:
            return
        anomalies = doc_ole.equation_anomalies(raw[i:i + 65536])
        if anomalies:
            _det(ctx, obj, "Heur:Office.Exploit.EquationEditor", Confidence.HIGH, 70,
                 "Malformed Equation Editor data (CVE-2017-11882 / CVE-2018-0802 exploit pattern)", anomalies)

    # ------------------------------------------------------------------ fields / template
    def _text_destinations(self, obj, ctx, meta, parser) -> None:
        fields = [t.decode("latin-1", "replace") for t in parser.texts.get(b"fldinst", [])]
        if fields:
            dde, dde_exec, inc = classify_fields(fields)
            report_dde(ctx, obj, dde, dde_exec, inc, "RTF field")
            if dde:
                meta["dde"] = [short(d, 200) for d in dde[:20]]
        templates = [t.decode("latin-1", "replace").strip() for t in parser.texts.get(b"template", [])]
        remote = [t for t in templates if re.match(r"(?i)\s*(https?://|\\\\|//|file://[^/])", t)]
        if remote:
            meta["template"] = remote[:5]
            _det(ctx, obj, "Heur:RTF.RemoteTemplate", Confidence.HIGH, 50,
                 "RTF loads its template from a remote location (template injection)", remote)

"""Microsoft Office / OpenDocument analyzers.

  office_ole    OLE2 compound files: Word/Excel/PowerPoint 97-2003, vbaProject.bin, oleObject*.bin,
                MSI, Outlook .msg, encrypted OOXML containers
  office_ooxml  Office Open XML zips (docx/docm/xlsx/xlsm/pptx/...)
  office_odf    OpenDocument (StarBasic / Python macros, auto-run events)
  office_text   text-based Office carriers: Flat OPC XML, Word 2003 XML, MHT/ActiveMime, SYLK, IQY, CSV DDE

Everything that is extracted (VBA source, embedded objects, attachments, decrypted
packages, XLM formulas) is handed back through ctx.add_child so every engine rescans it.
"""
from __future__ import annotations

import base64
import binascii
import html
import io
import re
import struct
import zipfile
import zlib

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from ..formats import doc_ole, doc_vba
from ..formats.doc_common import (DOWNLOAD_RE, ENCODED_PS_RE, EXEC_EXTENSIONS, LOLBIN_RE, classify_payload,
                                  safe_name, short)
from . import register

try:
    import olefile
except Exception:  # noqa: BLE001
    olefile = None

MAX_STREAM = 64 << 20
MAX_XML_PART = 64 << 20
MAX_ZIP_TOTAL = 512 << 20
MAX_ZIP_MEMBERS = 20000


def _det(ctx: ScanContext, obj: ScanObject, name: str, conf: Confidence, score: int, desc: str,
         evidence: list[str] | None = None) -> None:
    ctx.detect(obj, Detection(name, "heuristic", conf, score, desc, [short(e, 300) for e in (evidence or [])][:20]))


# =========================================================================== VBA reporting

def report_vba(ctx: ScanContext, obj: ScanObject, f: doc_vba.VBAFindings, area: str = "VBA") -> None:
    exec_like = f.execs
    if f.autoexec:
        _det(ctx, obj, f"Heur:{area}.AutoExec", Confidence.LOW, 10,
             "Macro runs automatically when the document is opened/closed", f.autoexec)
    if exec_like:
        _det(ctx, obj, f"Heur:{area}.Exec", Confidence.MEDIUM, 15, "Macro can execute commands/programs", exec_like)
    if f.downloads:
        _det(ctx, obj, f"Heur:{area}.Download", Confidence.MEDIUM, 20, "Macro performs network downloads", f.downloads)
    if f.writes:
        _det(ctx, obj, f"Heur:{area}.FileWrite", Confidence.LOW, 5, "Macro writes files to disk", f.writes)
    if f.powershell:
        _det(ctx, obj, f"Heur:{area}.PowerShell", Confidence.MEDIUM, 30, "Macro invokes PowerShell", f.powershell)
    if f.obfuscation:
        _det(ctx, obj, f"Heur:{area}.Obfuscated", Confidence.MEDIUM, 30 if len(f.obfuscation) >= 2 else 20,
             "Macro source is obfuscated", f.obfuscation)
    if f.api_alloc and (f.api_copy or f.api_run):
        _det(ctx, obj, f"Heur:{area}.ShellcodeLoader", Confidence.HIGH, 70,
             "Macro declares memory allocation + copy/execute APIs (in-memory code loader)",
             f.api_alloc + f.api_copy + f.api_run + f.declares[:5])
    elif f.api_alloc or f.api_copy or f.api_run:
        _det(ctx, obj, f"Heur:{area}.Win32API", Confidence.MEDIUM, 15,
             "Macro declares low-level memory/thread APIs", f.declares[:10])
    if f.persistence:
        _det(ctx, obj, f"Heur:{area}.Persistence", Confidence.MEDIUM, 20, "Macro touches autostart locations",
             f.persistence)
    if f.evasion:
        _det(ctx, obj, f"Heur:{area}.AntiAnalysis", Confidence.LOW, 10, "Macro contains sandbox/VM checks", f.evasion)
    if f.autoexec and exec_like:
        _det(ctx, obj, f"Heur:{area}.AutoExec.Exec", Confidence.HIGH, 30,
             "Auto-run macro that executes commands", f.autoexec[:3] + exec_like[:5])
    if f.autoexec and f.downloads:
        _det(ctx, obj, f"Heur:{area}.AutoExec.Download", Confidence.HIGH, 40,
             "Auto-run macro that downloads content", f.autoexec[:3] + f.downloads[:5])
    if f.downloads and (f.writes or exec_like):
        _det(ctx, obj, f"Heur:{area}.Dropper", Confidence.HIGH, 35,
             "Macro downloads and then writes/executes a payload", f.downloads[:3] + f.writes[:3] + exec_like[:3])


def _vba_meta(meta: dict, f: doc_vba.VBAFindings) -> None:
    meta["autoexec"] = f.autoexec
    meta["suspicious"] = sorted(set(f.execs + f.downloads + f.powershell + f.persistence))[:50]
    meta["obfuscation"] = f.obfuscation
    if f.urls:
        meta["urls"] = f.urls


# =========================================================================== field / DDE helpers

_FIELD_TOKEN_RE = re.compile(
    r'<w:fldChar\b[^>]*w:fldCharType="(begin|separate|end)"|<w:instrText\b[^>]*>([^<]*)</w:instrText>|'
    r'<w:fldSimple\b[^>]*w:instr="([^"]*)"', re.I)
DDE_RE = re.compile(r"(?i)^\s*(DDEAUTO|DDE)\b\s*(.*)", re.S)
INCLUDE_RE = re.compile(r"(?i)^\s*(INCLUDEPICTURE|INCLUDETEXT|IMPORT|LINK)\b\s*(.*)", re.S)


def ooxml_fields(xml: str, limit: int = 5000) -> list[str]:
    """Reassemble complex-field instructions (instrText split across runs) and simple fields."""
    out: list[str] = []
    stack: list[list[str]] = []
    for m in _FIELD_TOKEN_RE.finditer(xml):
        kind, instr, simple = m.group(1), m.group(2), m.group(3)
        if simple is not None:
            out.append(html.unescape(simple))
        elif kind:
            k = kind.lower()
            if k == "begin":
                stack.append([])
            elif k == "separate" and stack:
                out.append("".join(stack[-1]))
                stack[-1] = ["\x00done"]
            elif k == "end" and stack:
                parts = stack.pop()
                if parts[:1] != ["\x00done"]:
                    out.append("".join(parts))
        elif instr is not None:
            if stack:
                if stack[-1][:1] != ["\x00done"]:
                    stack[-1].append(html.unescape(instr))
            else:
                out.append(html.unescape(instr))
        if len(out) >= limit:
            break
    return [o for o in out if o.strip()]


def classify_fields(fields: list[str]) -> tuple[list[str], list[str], list[str]]:
    """-> (dde, dde_exec, external includes)"""
    dde, dde_exec, inc = [], [], []
    for fld in fields:
        m = DDE_RE.match(fld)
        if m:
            dde.append(fld.strip())
            if LOLBIN_RE.search(fld) or re.search(r"(?i)\.(exe|bat|cmd|hta|vbs|js|ps1)\b", fld):
                dde_exec.append(fld.strip())
            continue
        m = INCLUDE_RE.match(fld)
        if m and re.search(r"(?i)(https?://|\\\\\\\\|\\\\[a-z0-9])", m.group(2)):
            inc.append(fld.strip())
    return dde, dde_exec, inc


def report_dde(ctx, obj, dde, dde_exec, inc, where: str) -> None:
    if dde_exec:
        _det(ctx, obj, "Heur:Office.DDE.Exec", Confidence.HIGH, 70,
             f"DDE field launching a command ({where})", dde_exec)
    elif dde:
        _det(ctx, obj, "Heur:Office.DDE", Confidence.MEDIUM, 35, f"DDE/DDEAUTO field ({where})", dde)
    if inc:
        _det(ctx, obj, "Heur:Office.ExternalFieldRef", Confidence.INFO, 5,
             f"Field pulls external content ({where})", inc)


def report_xlm_formulas(ctx, obj, text: str) -> None:
    funcs = {m.group(1).upper() for m in doc_ole.XLM_FUNC_RE.finditer(text)}
    strong = sorted(f for f in funcs if f.lower() in doc_ole.XLM_STRONG)
    if strong:
        _det(ctx, obj, "Heur:XLM.Exec", Confidence.HIGH, 50,
             "XLM macro calls code-execution / Win32 API functions", strong)
    net = [m.group() for m in re.finditer(r"(?i)(https?://[^\s\"',)]{4,200}|\\\\[\w.\-]+\\[^\s\"',)]+)", text)][:10]
    if net and funcs:
        _det(ctx, obj, "Heur:XLM.Network", Confidence.MEDIUM, 20, "XLM macro references remote resources", net)
    lol = sorted({m.group() for m in LOLBIN_RE.finditer(text)})
    if lol:
        _det(ctx, obj, "Heur:XLM.LOLBin", Confidence.MEDIUM, 25, "XLM macro references system tools", lol[:10])
    if text.upper().count("CHAR(") >= 30 or text.upper().count("FORMULA(") + text.upper().count("FORMULA.FILL(") >= 10:
        _det(ctx, obj, "Heur:XLM.Obfuscated", Confidence.MEDIUM, 20,
             "XLM macro builds code at runtime (CHAR()/FORMULA() heavy)")


# =========================================================================== relationship helpers

_REL_RE = re.compile(r"<Relationship\b([^>]*)/?>", re.I)
_ATTR_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
DANGEROUS_SCHEME_RE = re.compile(
    r"(?i)^\s*(ms-msdt:|search-ms:|search:|ms-officecmd:|ms-appinstaller:|mhtml:|ms-its:|its:|"
    r"ms-word:ofe\||ms-excel:ofe\||ms-powerpoint:ofe\||javascript:|vbscript:|ms-cxh|ms-settings:|"
    r"ms-search:|x-usc:|file:.*\.(?:exe|hta|js|vbs|bat|cmd|scr|lnk|ps1)\b)")
REMOTE_RE = re.compile(r"(?i)^\s*(https?://|\\\\|//|file://[^/]|ftp://|webdav)")


def parse_rels(xml: str) -> list[dict]:
    out = []
    for m in _REL_RE.finditer(xml):
        attrs = {k.lower(): html.unescape(v) for k, v in _ATTR_RE.findall(m.group(1))}
        attrs["type_short"] = attrs.get("type", "").rsplit("/", 1)[-1]
        out.append(attrs)
    return out


def _remote_kind(target: str) -> str:
    t = target.strip().lower()
    if t.startswith(("http://", "https://")):
        return "http"
    if t.startswith("\\\\") or t.startswith("//") or re.match(r"file://[^/]", t):
        return "unc"
    return ""


def report_relationships(obj, ctx, meta, rels_all) -> None:
    external = []
    for src, r in rels_all:
        if r.get("targetmode", "").lower() != "external":
            continue
        target = r.get("target", "")
        typ = r["type_short"].lower()
        external.append(f"{typ}: {target}")
        ev = [f"{src}: {typ} -> {target}"]
        remote = _remote_kind(target)
        if DANGEROUS_SCHEME_RE.search(target):
            _det(ctx, obj, "Heur:Office.ProtocolHandlerAbuse", Confidence.HIGH, 70,
                 "External relationship uses an abusable URI scheme (ms-msdt/search-ms/mhtml...)", ev)
        elif typ == "attachedtemplate" and remote:
            if remote == "http":
                _det(ctx, obj, "Heur:Office.RemoteTemplate", Confidence.HIGH, 50,
                     "Document loads its template from a remote URL (template injection)", ev)
            else:
                _det(ctx, obj, "Heur:Office.RemoteTemplate.UNC", Confidence.MEDIUM, 25,
                     "Document template on a network share (template injection / NTLM leak)", ev)
        elif typ in ("oleobject", "frame", "subdocument", "package") and remote:
            _det(ctx, obj, "Heur:Office.ExternalObject", Confidence.HIGH, 60,
                 "Document loads an OLE object/frame from a remote location on open", ev)
        elif remote != "http" and not target.lower().startswith(("mailto:", "ftp://")) and (
                LOLBIN_RE.search(target) or re.search(r"(?i)\.(exe|scr|hta|bat|cmd|vbs|js|jse|ps1|lnk|cpl)\b", target)):
            _det(ctx, obj, "Heur:Office.ExternalProgramLink", Confidence.HIGH, 50,
                 "Document links to a program or script (e.g. PowerPoint mouse-over action)", ev)
        elif typ in ("image", "attachedtemplate", "externallinkpath") and remote == "unc":
            _det(ctx, obj, "Heur:Office.ExternalUNC", Confidence.LOW, 10,
                 "Resource loaded from a network share (NTLM hash leak)", ev)
    if external:
        meta["external_refs"] = external[:100]



# =========================================================================== OLE2

@register
class OfficeOLEAnalyzer(Analyzer):
    name = "office_ole"
    order = 40

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype == "ole2" and olefile is not None

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        try:
            ole = olefile.OleFileIO(obj.data)
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"office_ole: cannot parse OLE2: {exc}")
            _det(ctx, obj, "Heur:Office.MalformedOLE", Confidence.LOW, 5, "OLE2 header present but container is corrupt",
                 [str(exc)])
            return
        meta: dict = obj.meta.setdefault("office", {})
        meta["container"] = "ole2"
        try:
            self._analyze(ole, obj, ctx, meta)
        finally:
            try:
                ole.close()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------ main
    def _analyze(self, ole, obj: ScanObject, ctx: ScanContext, meta: dict) -> None:
        streams = ole.listdir(streams=True, storages=False)
        storages = ole.listdir(streams=False, storages=True)
        lower = {"/".join(p).lower(): p for p in streams}
        meta["streams"] = len(streams)

        root_clsid = (ole.root.clsid or "").upper() if ole.root else ""
        kind = self._kind(lower, root_clsid)
        meta["kind"] = kind

        if kind == "encrypted_ooxml" or self._is_encrypted(ole, lower, kind):
            self._encrypted(obj, ctx, meta, kind)

        self._vba(ole, obj, ctx, meta)
        if kind == "excel":
            self._excel(ole, obj, ctx, meta, lower)
        if kind == "word":
            self._word_fields(ole, obj, ctx, lower)
        if kind == "powerpoint" and "powerpoint document" in lower:
            data = self._read(ole, lower["powerpoint document"])
            for i, blob in enumerate(doc_ole.ppt_ole_storages(data)):
                ctx.add_child(obj, blob, f"ppt/ExOleObjStg_{i}.bin", kind="decoded")
        if kind == "msg":
            self._msg(ole, obj, ctx, meta, streams)
        if kind == "msi":
            self._msi(ole, obj, ctx, meta, streams)
            return
        self._objects(ole, obj, ctx, meta, streams, storages)
        self._properties(ole, obj, ctx, lower)

    @staticmethod
    def _kind(lower: dict, root_clsid: str) -> str:
        if "encryptedpackage" in lower and "encryptioninfo" in lower:
            return "encrypted_ooxml"
        if "worddocument" in lower:
            return "word"
        if "workbook" in lower or "book" in lower:
            return "excel"
        if "powerpoint document" in lower:
            return "powerpoint"
        if any(k.startswith("__substg1.0_") or k.startswith("__properties_version1.0") for k in lower):
            return "msg"
        if root_clsid in ("000C1084-0000-0000-C000-000000000046", "000C1086-0000-0000-C000-000000000046") or \
                any(doc_ole.msi_stream_name(p[-1]).startswith("!_StringPool") for p in lower.values()):
            return "msi"
        if any(k.endswith("vba/dir") for k in lower):
            return "vba_project"
        if "\x01ole10native" in lower or "\x01ole" in lower or "\x01compobj" in lower:
            return "ole_object"
        return "ole2"

    @staticmethod
    def _read(ole, path, cap: int = MAX_STREAM) -> bytes:
        try:
            with ole.openstream(path) as fh:
                return fh.read(cap)
        except Exception:  # noqa: BLE001
            return b""

    # ------------------------------------------------------------------ encryption
    def _is_encrypted(self, ole, lower: dict, kind: str) -> bool:
        try:
            if kind == "word" and "worddocument" in lower:
                fib = self._read(ole, lower["worddocument"], 32)
                return len(fib) > 0x0B and bool(fib[0x0B] & 0x01)
            if kind == "excel":
                wb = self._read(ole, lower.get("workbook") or lower.get("book"), 4096)
                pos = 0
                for _ in range(8):
                    if pos + 4 > len(wb):
                        break
                    rt, rl = struct.unpack_from("<HH", wb, pos)
                    if rt == 0x002F:
                        return True
                    pos += 4 + rl
                return False
            if kind == "powerpoint":
                return "encryptedsummary" in lower
        except Exception:  # noqa: BLE001
            return False
        return False

    def _encrypted(self, obj, ctx, meta, kind) -> None:
        meta["encrypted"] = True
        _det(ctx, obj, "Heur:Office.Encrypted", Confidence.INFO, 5,
             "Document is password-encrypted; its content cannot be inspected without the password")
        try:
            import msoffcrypto  # type: ignore
        except Exception:  # noqa: BLE001
            return
        for pw in ("VelvetSweatshop",):
            try:
                of = msoffcrypto.OfficeFile(io.BytesIO(obj.data))
                of.load_key(password=pw)
                out = io.BytesIO()
                of.decrypt(out)
                dec = out.getvalue()
            except Exception:  # noqa: BLE001
                continue
            if dec:
                meta["decrypted_with"] = pw
                _det(ctx, obj, "Heur:Office.Encrypted.DefaultPassword", Confidence.LOW, 15,
                     "Encrypted with Excel's built-in default password (opens without a prompt, hides content "
                     "from scanners)", [pw])
                ctx.add_child(obj, dec, "decrypted/" + (obj.name or "document"), kind="decoded")
                return

    # ------------------------------------------------------------------ VBA
    def _vba(self, ole, obj, ctx, meta) -> None:
        try:
            projects = doc_vba.extract_projects(ole, obj.errors)
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"vba: {exc!r}")
            return
        if not projects:
            return
        findings = doc_vba.VBAFindings()
        mod_meta = []
        all_source = []
        hidden, orphan, stomped = [], [], []
        for proj in projects:
            for m in proj.modules:
                code_body = doc_vba.strip_comments(m.source)
                mod_meta.append({"name": m.name, "stream": m.stream_name, "source_bytes": len(m.source),
                                 "pcode_bytes": m.pcode_size, "error": m.error})
                if m.source:
                    all_source.append(m.source)
                    ctx.add_child(obj, m.source.encode("utf-8", "replace"), f"vba/{safe_name(m.name, 'module')}.bas",
                                  kind="decoded", meta={"vba_module": m.name})
                    findings = doc_vba.merge(findings, doc_vba.analyze_source(m.source))
                if m.error == "not listed in dir stream" and code_body.strip():
                    orphan.append(m.name)
                elif proj.project_modules and m.name.lower() not in proj.project_modules and code_body.strip():
                    hidden.append(m.name)
                # heuristic stomping signal: large p-code but no source
                if m.pcode_size > 16000 and not code_body.strip() and not m.error:
                    stomped.append(f"{m.name}: {m.pcode_size} bytes of p-code, empty source")
            if proj.protected:
                meta["vba_protected"] = True
        if not mod_meta:
            return
        meta["vba_modules"] = mod_meta[:100]
        code_modules = [x["name"] for x in mod_meta if x["source_bytes"]]
        if code_modules or stomped:
            _det(ctx, obj, "Heur:Office.Macros", Confidence.LOW, 5, "Document contains VBA macros", code_modules[:10])
        report_vba(ctx, obj, findings)
        _vba_meta(meta, findings)
        if hidden:
            _det(ctx, obj, "Heur:VBA.HiddenModule", Confidence.MEDIUM, 40,
                 "VBA module present in the project but hidden from the VBA editor (PROJECT stream tampering)", hidden)
        if orphan:
            _det(ctx, obj, "Heur:VBA.OrphanModule", Confidence.MEDIUM, 25,
                 "Compressed VBA source in a stream that the project directory does not reference", orphan)
        # p-code vs source comparison (VBA stomping)
        joined = "\n".join(all_source)
        try:
            for proj in projects:
                kw, n_lines = doc_vba.pcode_keywords(ole, proj)
                if n_lines <= 0:
                    continue
                missing = sorted(k for k in kw if k not in joined)
                meaningful = [k for k in missing if len(k.strip('"')) >= 3]
                susp = [k for k in meaningful if doc_vba.EXEC_RE.search(k) or doc_vba.DOWNLOAD_RE.search(k)
                        or doc_vba.POWERSHELL_RE.search(k) or doc_vba.AUTOEXEC_RE.fullmatch(k)
                        or LOLBIN_RE.search(k)]
                if susp or (len(meaningful) >= 5 and len(meaningful) > 0.3 * max(len(kw), 1)):
                    stomped.append(f"{len(meaningful)} p-code identifiers/strings absent from source: "
                                   + ", ".join((susp or meaningful)[:12]))
                    pc_text = "' VBA p-code identifiers and strings not present in the source code\n" + \
                              "\n".join(missing)
                    ctx.add_child(obj, pc_text.encode("utf-8", "replace"), "vba/pcode_only_strings.txt",
                                  kind="decoded")
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"pcode: {exc!r}")
        if stomped:
            _det(ctx, obj, "Heur:VBA.Stomped", Confidence.HIGH, 50,
                 "VBA stomping: compiled p-code does not match the visible source code", stomped)

    # ------------------------------------------------------------------ Excel 4.0 / XLM, DDE
    def _excel(self, ole, obj, ctx, meta, lower) -> None:
        wb = self._read(ole, lower.get("workbook") or lower.get("book"))
        if not wb:
            return
        try:
            sheets, names, dde = doc_ole.biff_sheets(wb)
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"biff: {exc!r}")
            return
        meta["sheets"] = [{k: v for k, v in s.items() if k != "offset"} for s in sheets[:200]]
        macro = [s for s in sheets if s["type"] == "macro sheet"]
        very_hidden = [s["name"] for s in sheets if s["state"] == "very hidden"]
        auto = [n for n in names if n.lower().startswith("auto_open") or n.lower().startswith("auto_close")]
        if macro:
            _det(ctx, obj, "Heur:XLM.MacroSheet", Confidence.MEDIUM, 20, "Workbook contains Excel 4.0 (XLM) macro sheets",
                 [f"{s['name']} ({s['state']})" for s in macro])
            if auto:
                _det(ctx, obj, "Heur:XLM.AutoOpen", Confidence.MEDIUM, 20, "XLM macro defines an Auto_Open trigger", auto)
            formulas = doc_ole.biff_formulas(wb)
            if formulas:
                ctx.add_child(obj, formulas.encode("utf-8", "replace"), "xlm/formulas.txt", kind="decoded")
                report_xlm_formulas(ctx, obj, formulas)
        hidden_macro = [s["name"] for s in macro if s["state"] != "visible"]
        if hidden_macro and very_hidden:
            _det(ctx, obj, "Heur:XLM.VeryHidden", Confidence.HIGH, 30,
                 "XLM macro sheet is 'very hidden' (not visible from the Excel UI)", very_hidden)
        elif hidden_macro:
            _det(ctx, obj, "Heur:XLM.HiddenSheet", Confidence.MEDIUM, 15, "XLM macro sheet is hidden", hidden_macro)
        # DDE links from SupBook records (server|topic), e.g. =cmd|'/c ...'!A0
        if dde:
            dde_exec = [d for d in dde if LOLBIN_RE.search(d) or d.lower().startswith(("cmd|", "msexcel|"))]
            report_dde(ctx, obj, dde, dde_exec, [], "Excel DDE link")

    # ------------------------------------------------------------------ Word binary fields
    def _word_fields(self, ole, obj, ctx, lower) -> None:
        fields = []
        for key in ("worddocument", "1table", "0table"):
            if key not in lower:
                continue
            data = self._read(ole, lower[key])
            if not data or (b"DDE" not in data and b"D\x00D\x00E\x00" not in data and b"INCLUDE" not in data
                            and b"I\x00N\x00C\x00L\x00" not in data):
                continue
            odd = data[1:]
            for text in (data.decode("latin-1"), data[: len(data) & ~1].decode("utf-16-le", "replace"),
                         odd[: len(odd) & ~1].decode("utf-16-le", "replace")):
                for m in re.finditer(r"\x13([^\x13\x14\x15]{2,2048})", text):
                    fields.append(m.group(1))
                    if len(fields) > 5000:
                        break
        if fields:
            dde, dde_exec, inc = classify_fields(fields)
            report_dde(ctx, obj, dde, dde_exec, inc, "Word 97-2003 field")

    # ------------------------------------------------------------------ embedded objects / ActiveX / links
    def _objects(self, ole, obj, ctx, meta, streams, storages) -> None:
        embedded, activex, links = [], [], []
        for st in storages[:5000]:
            try:
                clsid = (ole.getclsid(st) or "").upper()
            except Exception:  # noqa: BLE001
                continue
            self._clsid(ctx, obj, clsid, "/".join(st), activex)
        root_clsid = (ole.root.clsid or "").upper() if ole.root else ""
        self._clsid(ctx, obj, root_clsid, "<root>", activex)

        for path in streams[:20000]:
            leaf = path[-1]
            lname = leaf.lower()
            joined = "/".join(path)
            if lname == "\x01ole10native":
                data = self._read(ole, path)
                nat = doc_ole.parse_ole10native(data)
                if nat and nat["data"]:
                    self._embedded_payload(ctx, obj, nat["data"], nat["filename"] or "ole10native.bin",
                                           f"OLE Package ({nat['filename']!r} from {nat['src_path']!r})", embedded)
                elif data:
                    ctx.add_child(obj, data, f"ole/{safe_name(joined)}", kind="stream")
            elif lname == "equation native":
                data = self._read(ole, path)
                anomalies = doc_ole.equation_anomalies(data)
                embedded.append(f"Equation Editor object at {joined}")
                self._equation(ctx, obj, joined, anomalies)
            elif lname == "\x01ole":
                data = self._read(ole, path, 1 << 20)
                if len(data) >= 8 and struct.unpack_from("<I", data, 4)[0] & 1:
                    links.append(joined)
                for kind, target in doc_ole.find_monikers(data):
                    self._moniker(ctx, obj, kind, target)
            elif lname in ("package", "contents") and len(path) > 1:
                data = self._read(ole, path)
                if len(data) >= 16:
                    self._embedded_payload(ctx, obj, data, f"{leaf}.bin", f"embedded stream {joined}", embedded)
            elif lname == "\x03ocxname":
                data = self._read(ole, path, 4096)
                activex.append(data.decode("utf-16-le", "replace").strip("\x00"))
            elif lname == "\x01compobj" and len(path) > 1:
                info = doc_ole.parse_compobj(self._read(ole, path, 4096))
                if info:
                    embedded.append(f"{joined[:-9]}: {' / '.join(i for i in info if i)}")
            else:
                # any stream that is actually an executable image
                try:
                    size = ole.get_size(path)
                except Exception:  # noqa: BLE001
                    size = 0
                if size >= 512:
                    head = self._read(ole, path, 64)
                    if head[:2] == b"MZ" or head[:4] in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
                        data = self._read(ole, path)
                        self._embedded_payload(ctx, obj, data, safe_name(leaf, "stream") + ".bin",
                                               f"stream {joined}", embedded)
        if embedded:
            meta["embedded"] = embedded[:100]
            _det(ctx, obj, "Heur:Office.EmbeddedObject", Confidence.INFO, 3, "Document embeds OLE objects",
                 embedded[:10])
        if activex:
            meta["activex"] = activex[:100]
            _det(ctx, obj, "Heur:Office.ActiveX", Confidence.LOW, 10, "Document contains ActiveX controls", activex[:10])
        if links:
            meta["ole_links"] = links[:50]

    def _clsid(self, ctx, obj, clsid: str, where: str, activex: list) -> None:
        cat, desc = doc_ole.clsid_risk(clsid)
        if cat == "equation":
            self._equation(ctx, obj, where, [])
        elif cat == "moniker":
            _det(ctx, obj, "Heur:Office.OLE.MonikerObject", Confidence.HIGH, 50,
                 "OLE object of a moniker class that loads remote content (CVE-2017-0199 family)", [f"{where}: {desc}"])
        elif cat == "activex_cve":
            activex.append(f"{where}: {desc}")
            _det(ctx, obj, "Heur:Office.ActiveX.Exploitable", Confidence.MEDIUM, 40,
                 "ActiveX/OLE class with a history of exploitation", [f"{clsid} {desc}"])

    def _equation(self, ctx, obj, where: str, anomalies: list[str]) -> None:
        _det(ctx, obj, "Heur:Office.EquationEditor", Confidence.MEDIUM, 30,
             "Legacy Equation Editor 3.0 object (exploited by CVE-2017-11882 / CVE-2018-0802)", [where])
        if anomalies:
            _det(ctx, obj, "Heur:Office.Exploit.EquationEditor", Confidence.HIGH, 70,
                 "Malformed Equation Editor data (CVE-2017-11882 / CVE-2018-0802 exploit pattern)", anomalies)

    def _moniker(self, ctx, obj, kind: str, target: str) -> None:
        t = target.lower()
        if kind in ("script", "soap") or (kind == "url" and t.startswith(("http", "\\\\", "//"))):
            _det(ctx, obj, "Heur:Office.OLELink.Remote", Confidence.HIGH, 60,
                 "Linked OLE object loads remote content on open (CVE-2017-0199 / CVE-2017-8570 style)",
                 [f"{kind} moniker: {target}"])
        elif kind == "file" and (t.startswith("\\\\") or re.search(r"\.(sct|hta|exe|dll|js|vbs)\b", t)):
            _det(ctx, obj, "Heur:Office.OLELink.File", Confidence.MEDIUM, 30,
                 "Linked OLE object references a script/executable or network path", [target])

    def _embedded_payload(self, ctx, obj, data: bytes, name: str, where: str, embedded: list) -> None:
        name = safe_name(name, "embedded.bin")
        embedded.append(f"{where}: {name} ({len(data)} bytes)")
        ftype, reason = classify_payload(data, name)
        ctx.add_child(obj, data, f"embedded/{name}", kind="member")
        if reason:
            conf, score = (Confidence.HIGH, 60) if ftype in ("pe", "elf", "macho", "macho_fat", "lnk") or \
                name.lower().rsplit(".", 1)[-1] in EXEC_EXTENSIONS else (Confidence.MEDIUM, 40)
            _det(ctx, obj, "Heur:Office.EmbeddedExecutable", conf, score,
                 "Document embeds an executable or script object", [f"{name}: {reason} ({where})"])

    # ------------------------------------------------------------------ property streams
    def _properties(self, ole, obj, ctx, lower) -> None:
        hits = []
        for key in ("\x05summaryinformation", "\x05documentsummaryinformation"):
            if key not in lower:
                continue
            data = self._read(ole, lower[key], 4 << 20)
            texts = [data.decode("latin-1"), data[: len(data) & ~1].decode("utf-16-le", "replace")]
            for t in texts:
                for m in re.finditer(r"[A-Za-z0-9+/]{400,}={0,2}", t):
                    hits.append(f"{len(m.group())}-char Base64 blob in document properties")
                    break
                m = ENCODED_PS_RE.search(t) or (LOLBIN_RE.search(t) if DOWNLOAD_RE.search(t) else None)
                if m:
                    hits.append(short(t[max(0, m.start() - 40):][:200]))
        if hits:
            _det(ctx, obj, "Heur:Office.HiddenData", Confidence.MEDIUM, 20,
                 "Code or encoded payload stored in document properties", hits[:5])

    # ------------------------------------------------------------------ Outlook .msg
    def _msg(self, ole, obj, ctx, meta, streams) -> None:
        def prop(prefix: list[str], tag: str) -> str:
            for suffix, enc in (("001F", "utf-16-le"), ("001E", "latin-1")):
                p = prefix + [f"__substg1.0_{tag}{suffix}"]
                if ole.exists("/".join(p)):
                    return self._read(ole, p, 1 << 20).decode(enc, "replace").rstrip("\x00")
            return ""

        meta["msg"] = {"subject": prop([], "0037")[:300], "sender": prop([], "0C1F")[:200]}
        body = prop([], "1000")
        if body:
            ctx.add_child(obj, body.encode("utf-8", "replace"), "msg/body.txt", kind="decoded")
        if ole.exists("__substg1.0_10130102"):
            ctx.add_child(obj, self._read(ole, ["__substg1.0_10130102"]), "msg/body.html", kind="decoded")
        attachments, risky = [], []
        att_roots = sorted({p[0] for p in streams if p[0].lower().startswith("__attach_version1.0_")})
        for i, root in enumerate(att_roots[:500]):
            fname = prop([root], "3707") or prop([root], "3704") or f"attachment_{i}.bin"
            data = b""
            if ole.exists(f"{root}/__substg1.0_37010102"):
                data = self._read(ole, [root, "__substg1.0_37010102"], 512 << 20)
            nm = safe_name(fname, f"attachment_{i}.bin")
            attachments.append(f"{nm} ({len(data)} bytes)")
            if data:
                ctx.add_child(obj, data, f"attachments/{nm}", kind="member")
                _, reason = classify_payload(data, nm)
                if reason:
                    risky.append(f"{nm}: {reason}")
            elif ole.exists(f"{root}/__substg1.0_3701000D"):
                attachments[-1] = f"{nm} (embedded message)"
        meta["msg"]["attachments"] = attachments[:100]
        if risky:
            _det(ctx, obj, "Heur:MSG.ExecutableAttachment", Confidence.MEDIUM, 30,
                 "Outlook message carries an executable/script attachment", risky[:10])

    # ------------------------------------------------------------------ MSI
    def _msi(self, ole, obj, ctx, meta, streams) -> None:
        names = []
        extracted = 0
        for path in streams[:5000]:
            nm = doc_ole.msi_stream_name(path[-1])
            names.append(nm)
            try:
                size = ole.get_size(path)
            except Exception:  # noqa: BLE001
                continue
            if nm.startswith("!") or size < 64 or extracted > (1 << 30):
                continue
            head = self._read(ole, path, 64)
            interesting = nm.lower().startswith("binary.") or head[:4] == b"MSCF" or head[:2] == b"MZ" or \
                classify_payload(head, nm)[1]
            if interesting:
                data = self._read(ole, path, 512 << 20)
                extracted += len(data)
                ctx.add_child(obj, data, f"msi/{safe_name(nm, 'stream')}", kind="member")
        meta["msi_streams"] = names[:200]
        sp = next((p for p in streams if doc_ole.msi_stream_name(p[-1]) == "!_StringData"), None)
        if sp:
            text = self._read(ole, sp, 16 << 20).decode("latin-1")
            hits = [m.group() for m in ENCODED_PS_RE.finditer(text)][:3]
            if LOLBIN_RE.search(text) and DOWNLOAD_RE.search(text):
                hits.append(short(text[max(0, LOLBIN_RE.search(text).start() - 60):][:240]))
            if hits:
                _det(ctx, obj, "Heur:MSI.SuspiciousCustomAction", Confidence.MEDIUM, 20,
                     "MSI string table contains download/execute command lines", hits)


# =========================================================================== OOXML

_XLM_REL_TYPES = ("macrosheet", "xlmacrosheet", "xlintlmacrosheet", "intlmacrosheet")


@register
class OOXMLAnalyzer(Analyzer):
    name = "office_ooxml"
    order = 40

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype == "ooxml"

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        try:
            zf = zipfile.ZipFile(io.BytesIO(obj.data))
            infos = zf.infolist()
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"office_ooxml: cannot open zip: {exc}")
            return
        meta: dict = obj.meta.setdefault("office", {})
        meta["container"] = "ooxml"
        if len(infos) > MAX_ZIP_MEMBERS:
            obj.errors.append(f"office_ooxml: {len(infos)} members, only the first {MAX_ZIP_MEMBERS} checked")
            infos = infos[:MAX_ZIP_MEMBERS]
        self.budget = MAX_ZIP_TOTAL
        by_name = {i.filename.lower(): i for i in infos}
        try:
            self._run(zf, infos, by_name, obj, ctx, meta)
        finally:
            zf.close()

    def _read(self, zf, info, cap: int = MAX_XML_PART) -> bytes:
        if info.file_size > cap or self.budget <= 0:
            return b""
        if info.compress_size and info.file_size / max(info.compress_size, 1) > 1000 and info.file_size > (8 << 20):
            return b""
        try:
            with zf.open(info) as fh:
                data = fh.read(cap)
        except Exception:  # noqa: BLE001
            return b""
        self.budget -= len(data)
        return data

    def _text(self, zf, info) -> str:
        return self._read(zf, info).decode("utf-8", "replace")

    def _run(self, zf, infos, by_name, obj, ctx, meta) -> None:
        ct = by_name.get("[content_types].xml")
        ctypes = self._text(zf, ct) if ct else ""
        app = "word" if "word/" in " ".join(by_name) else "excel" if any(n.startswith("xl/") for n in by_name) else \
            "powerpoint" if any(n.startswith("ppt/") for n in by_name) else "ooxml"
        meta["kind"] = app
        meta["macro_enabled"] = "macroenabled" in ctypes.lower() or any(n.endswith("vbaproject.bin") for n in by_name)

        rels_all: list[tuple[str, dict]] = []
        for name, info in by_name.items():
            if name.endswith(".rels"):
                for r in parse_rels(self._text(zf, info)):
                    rels_all.append((name, r))
        report_relationships(obj, ctx, meta, rels_all)

        fields = []
        extracted = []
        activex_clsids = []
        for info in infos:
            name = info.filename
            low = name.lower()
            if info.is_dir():
                continue
            if low.endswith(".xml") and (low.startswith("word/") or low.startswith("xl/") or low.startswith("ppt/")):
                if low.startswith("word/") and not re.search(r"word/(styles|fonttable|numbering|theme/|stylesWithEffects)".lower(),
                                                              low):
                    xml = self._text(zf, info)
                    if "instr" in xml:
                        fields.extend(ooxml_fields(xml))
                elif "/activex/" in low:
                    xml = self._text(zf, info)
                    for m in re.finditer(r'classid="\{?([0-9A-Fa-f\-]{36})\}?"', xml):
                        activex_clsids.append(m.group(1).upper())
                elif low.startswith("xl/externallinks/"):
                    xml = self._text(zf, info)
                    for m in re.finditer(r'<ddeLink\b[^>]*ddeService="([^"]*)"[^>]*ddeTopic="([^"]*)"', xml):
                        fields.append(f"DDEAUTO {html.unescape(m.group(1))} {html.unescape(m.group(2))}")
                continue
            if low.endswith("vbaproject.bin") or "/embeddings/" in low or ("/activex/" in low and low.endswith(".bin")):
                data = self._read(zf, info)
                if data:
                    ctx.add_child(obj, data, name, kind="member")
                    extracted.append(name)
                    if "/embeddings/" in low:
                        ftype, reason = classify_payload(data, name)
                        if reason:
                            _det(ctx, obj, "Heur:Office.EmbeddedExecutable", Confidence.HIGH, 60,
                                 "Document embeds an executable or script", [f"{name}: {reason}"])
                continue
            if low.startswith(("customxml/", "docprops/")) and low.endswith(".xml"):
                self._hidden_data(zf, info, obj, ctx)
                continue
            # masquerading members (e.g. an executable named image1.png)
            if info.file_size >= 512:
                head = self._read(zf, info, 64) if info.file_size <= MAX_XML_PART else b""
                if head[:2] == b"MZ" or head[:4] in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
                    data = self._read(zf, info)
                    ctx.add_child(obj, data, name, kind="member")
                    ftype, reason = classify_payload(data, name)
                    if reason:
                        _det(ctx, obj, "Heur:Office.EmbeddedExecutable", Confidence.HIGH, 60,
                             "Package part is an executable", [f"{name}: {reason}"])
        if extracted:
            meta["binary_parts"] = extracted[:100]
        if any(n.endswith("vbaproject.bin") for n in by_name) and not ("macroenabled" in ctypes.lower()):
            meta["vba_in_non_macro_type"] = True
        if fields:
            dde, dde_exec, inc = classify_fields(fields)
            report_dde(ctx, obj, dde, dde_exec, inc, "OOXML field")
            meta["fields"] = [short(f, 200) for f in fields[:50]]
        if activex_clsids:
            meta["activex"] = activex_clsids[:100]
            _det(ctx, obj, "Heur:Office.ActiveX", Confidence.LOW, 10, "Document contains ActiveX controls",
                 sorted(set(activex_clsids))[:10])
            for c in sorted(set(activex_clsids)):
                cat, desc = doc_ole.clsid_risk(c)
                if cat in ("activex_cve", "moniker", "equation"):
                    _det(ctx, obj, "Heur:Office.ActiveX.Exploitable", Confidence.MEDIUM, 40,
                         "ActiveX class with a history of exploitation", [f"{c} {desc}"])
            if len(activex_clsids) >= 40:
                _det(ctx, obj, "Heur:Office.ActiveX.Spray", Confidence.MEDIUM, 30,
                     "Unusually many ActiveX controls (heap-spray pattern)", [f"{len(activex_clsids)} controls"])
        if app == "excel":
            self._xlm(zf, by_name, obj, ctx, meta)

    # ------------------------------------------------------------------ Excel 4.0 in xlsm
    def _xlm(self, zf, by_name, obj, ctx, meta) -> None:
        wb = by_name.get("xl/workbook.xml")
        wxml = self._text(zf, wb) if wb else ""
        rels_i = by_name.get("xl/_rels/workbook.xml.rels")
        rels = {r.get("id"): r for r in parse_rels(self._text(zf, rels_i))} if rels_i else {}
        sheets = []
        for m in re.finditer(r"<sheet\b([^>]*)/?>", wxml):
            a = {k.lower().split(":")[-1]: html.unescape(v) for k, v in _ATTR_RE.findall(m.group(1))}
            rel = rels.get(a.get("id"), {})
            sheets.append({"name": a.get("name", ""), "state": a.get("state", "visible"),
                           "type": rel.get("type_short", ""), "target": rel.get("target", "")})
        meta["sheets"] = sheets[:200]
        macro = [s for s in sheets if s["type"].lower() in _XLM_REL_TYPES]
        macro_parts = [n for n in by_name if n.startswith("xl/macrosheets/")]
        if not macro and not macro_parts:
            return
        _det(ctx, obj, "Heur:XLM.MacroSheet", Confidence.MEDIUM, 20, "Workbook contains Excel 4.0 (XLM) macro sheets",
             [f"{s['name']} ({s['state']})" for s in macro] or macro_parts[:5])
        vh = [s["name"] for s in macro if s["state"].lower() == "veryhidden"]
        hid = [s["name"] for s in macro if s["state"].lower() == "hidden"]
        if vh:
            _det(ctx, obj, "Heur:XLM.VeryHidden", Confidence.HIGH, 30, "XLM macro sheet is 'very hidden'", vh)
        elif hid:
            _det(ctx, obj, "Heur:XLM.HiddenSheet", Confidence.MEDIUM, 15, "XLM macro sheet is hidden", hid)
        auto = re.findall(r'<definedName\b[^>]*name="((?:_xlnm\.)?Auto_(?:Open|Close)\w*)"', wxml, re.I)
        if auto:
            _det(ctx, obj, "Heur:XLM.AutoOpen", Confidence.MEDIUM, 20, "XLM macro defines an Auto_Open trigger", auto)
        formulas = []
        for n in macro_parts:
            raw = self._read(zf, by_name[n])
            if n.endswith(".xml"):
                formulas += [html.unescape(f) for f in
                             re.findall(r"<(?:\w+:)?f\b[^>]*>([^<]*)</(?:\w+:)?f>", raw.decode("utf-8", "replace"))]
            else:   # xlsb: formulas are binary; keep printable strings
                formulas += [s.decode("utf-16-le", "replace") for s in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", raw)]
        if formulas:
            text = "\n".join(formulas)
            ctx.add_child(obj, text.encode("utf-8", "replace"), "xlm/formulas.txt", kind="decoded")
            report_xlm_formulas(ctx, obj, text)

    # ------------------------------------------------------------------ custom XML / properties
    def _hidden_data(self, zf, info, obj, ctx) -> None:
        text = self._text(zf, info)
        hits = []
        for m in re.finditer(r"[A-Za-z0-9+/\r\n]{800,}={0,2}", text):
            blob = re.sub(r"\s+", "", m.group())
            try:
                dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            except (binascii.Error, ValueError):
                continue
            ftype, reason = classify_payload(dec)
            hits.append(f"{info.filename}: {len(blob)}-char Base64 blob ({ftype})")
            if reason or ftype in ("ole2", "zip", "ooxml", "rtf", "pdf"):
                ctx.add_child(obj, dec, f"hidden/{safe_name(info.filename)}.b64.bin", kind="decoded")
            if reason:
                _det(ctx, obj, "Heur:Office.HiddenPayload", Confidence.HIGH, 50,
                     "Executable/script payload hidden in document properties or custom XML", [hits[-1], reason])
            if len(hits) > 5:
                break
        if ENCODED_PS_RE.search(text) or (LOLBIN_RE.search(text) and DOWNLOAD_RE.search(text)):
            hits.append(f"{info.filename}: command line in properties")
        if hits:
            _det(ctx, obj, "Heur:Office.HiddenData", Confidence.MEDIUM, 20,
                 "Encoded data or command lines stored in document properties / custom XML", hits[:5])


# =========================================================================== OpenDocument

_ODF_EVENT_RE = re.compile(
    r'script:event-name="(dom:load|office:load|office:new|OnLoad|OnNew|OnStartApp|OnFocus|OnViewCreated|'
    r'dom:DOMFocusIn|office:document-open)"[^>]*xlink:href="([^"]+)"|xlink:href="(vnd\.sun\.star\.script:[^"]+)"[^>]*'
    r'script:event-name="(dom:load|office:load|office:new|OnLoad|OnNew|OnStartApp|OnViewCreated)"', re.I)


@register
class ODFAnalyzer(Analyzer):
    name = "office_odf"
    order = 40

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype == "odf"

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        try:
            zf = zipfile.ZipFile(io.BytesIO(obj.data))
            infos = zf.infolist()[:MAX_ZIP_MEMBERS]
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"office_odf: cannot open zip: {exc}")
            return
        meta: dict = obj.meta.setdefault("office", {})
        meta["container"] = "odf"
        findings = doc_vba.VBAFindings()
        modules, events = [], []
        budget = MAX_ZIP_TOTAL
        for info in infos:
            low = info.filename.lower()
            if info.is_dir() or info.file_size > MAX_XML_PART or budget <= 0:
                continue
            is_basic = low.startswith("basic/") and low.endswith(".xml") and not low.endswith(
                ("script-lb.xml", "script-lc.xml", "dialog-lb.xml", "dialog-lc.xml"))
            is_script = low.startswith("scripts/") and not low.endswith("/")
            is_xml = low.endswith(".xml")
            if not (is_basic or is_script or is_xml):
                continue
            try:
                raw = zf.read(info)
            except Exception:  # noqa: BLE001
                continue
            budget -= len(raw)
            text = raw.decode("utf-8", "replace")
            if is_basic:
                m = re.search(r"<script:module\b[^>]*>(.*)</script:module>", text, re.S)
                code = html.unescape(m.group(1)) if m else ""
                if code.strip():
                    modules.append(info.filename)
                    ctx.add_child(obj, code.encode("utf-8", "replace"),
                                  "basic/" + safe_name(info.filename.split("/", 1)[-1], "module") + ".bas", kind="decoded")
                    findings = doc_vba.merge(findings, doc_vba.analyze_source(code))
            elif is_script:
                modules.append(info.filename)
                ctx.add_child(obj, raw, info.filename, kind="member")
            if is_xml and "event-name" in text:
                for m in _ODF_EVENT_RE.finditer(text):
                    events.append(f"{m.group(1) or m.group(4)} -> {m.group(2) or m.group(3)}")
        zf.close()
        if modules:
            meta["macros"] = modules[:100]
            _det(ctx, obj, "Heur:Office.Macros", Confidence.LOW, 5, "OpenDocument contains macros", modules[:10])
        macro_events = [e for e in events if "vnd.sun.star.script" in e.lower() or "macro:" in e.lower()]
        if macro_events:
            findings.autoexec = doc_vba._uniq(findings.autoexec + macro_events)
        report_vba(ctx, obj, findings, area="Basic")
        _vba_meta(meta, findings)


# =========================================================================== text-based carriers

_ACTIVEMIME_B64 = b"QWN0aXZlTWltZQ"
_SLK_EXEC_RE = re.compile(rb"(?im)^C;.*?;E.*\b(EXEC|CALL|REGISTER|RUN|URLDownloadToFile[AW]?)\s*\(")
_CSV_DDE_RE = re.compile(rb"(?im)(?:^|[,;\t\"])\s*[=+\-@]\s*([A-Za-z0-9_.]{2,40})\s*\|\s*'([^'\r\n]{1,512})'\s*!")


def activemime_decode(data: bytes) -> bytes | None:
    """ActiveMime (MSO) blob -> the embedded OLE2 container."""
    if not data.startswith(b"ActiveMime"):
        return None
    cands = []
    if len(data) > 0x22:
        cands.append(struct.unpack_from("<H", data, 0x1E)[0] + 46)
    cands += [0x32, 0x22A]
    cands += [m.start() for m in re.finditer(rb"\x78[\x01\x5e\x9c\xda]", data[:4096])]
    for off in cands:
        if 0 < off < len(data):
            try:
                out = zlib.decompressobj().decompress(data[off:], 256 << 20)
            except zlib.error:
                continue
            if out[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                return out
    return None


def _b64(s: bytes) -> bytes:
    s = re.sub(rb"\s+", b"", s)
    try:
        return base64.b64decode(s + b"=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        return b""


@register
class OfficeTextAnalyzer(Analyzer):
    name = "office_text"
    order = 40
    _FT = {"xml", "html", "email", "text", "binary", "unknown", "json", "hta", "javascript", "vbs"}

    def applies(self, obj: ScanObject) -> bool:
        if obj.ftype not in self._FT or obj.size < 16:
            return False
        head = obj.data[:4096]
        if head.startswith((b"ActiveMime", b"ID;P", b"WEB\r\n", b"WEB\n")):
            return True
        if obj.ftype == "binary":
            return False
        if obj.ftype == "text" and obj.extension in ("csv", "txt", "tsv", "") and b"|" in obj.data[:1 << 20]:
            return True
        if obj.ftype in ("xml", "html", "email", "text"):
            window = obj.data[:32 << 20]
            return any(k in window for k in (b"<pkg:package", b"w:binData", _ACTIVEMIME_B64, b"urn:schemas-microsoft-com:office",
                                             b"instrText", b"schemas.openxmlformats.org"))
        return False

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        data = obj.data[:64 << 20]
        meta: dict = obj.meta.setdefault("office", {})
        if data.startswith(b"ActiveMime"):
            ole = activemime_decode(data)
            meta["container"] = "activemime"
            if ole:
                ctx.add_child(obj, ole, "activemime.ole", kind="decoded")
            return
        if data.startswith(b"ID;P"):
            meta["container"] = "sylk"
            hits = sorted({m.group(1).decode() for m in _SLK_EXEC_RE.finditer(data)})
            if hits:
                _det(ctx, obj, "Heur:XLM.SYLK", Confidence.HIGH, 60, "SYLK spreadsheet with executable XLM formulas", hits)
            return
        if data.startswith((b"WEB\r\n", b"WEB\n")):
            meta["container"] = "iqy"
            url = re.search(rb"(?i)(https?|ftp)://\S+", data[:4096])
            _det(ctx, obj, "Heur:Office.IQY", Confidence.MEDIUM, 25,
                 "Excel web query file (fetches remote content into Excel)", [url.group().decode("latin-1") if url else ""])
            return
        found = False
        # Flat OPC: base64 binary parts
        for m in re.finditer(rb'<pkg:part\b[^>]*pkg:name="([^"]+)"[^>]*>\s*<pkg:binaryData>([^<]+)</pkg:binaryData>', data):
            blob = _b64(m.group(2))
            if blob:
                found = True
                ctx.add_child(obj, blob, "flatopc/" + m.group(1).decode("latin-1").strip("/"), kind="decoded")
        # Word 2003 XML: <w:binData w:name="editdata.mso">
        for m in re.finditer(rb'<w:binData\b[^>]*w:name="([^"]+)"[^>]*>([^<]+)</w:binData>', data):
            blob = _b64(m.group(2))
            ole = activemime_decode(blob) if blob else None
            if ole or blob:
                found = True
                ctx.add_child(obj, ole or blob, "word2003/" + safe_name(m.group(1).decode("latin-1")) +
                              (".ole" if ole else ""), kind="decoded")
        # MHT / HTML with ActiveMime part
        if _ACTIVEMIME_B64 in data:
            for i, m in enumerate(re.finditer(rb"QWN0aXZlTWltZQ[A-Za-z0-9+/=\r\n]{16,}", data)):
                ole = activemime_decode(_b64(m.group()))
                if ole:
                    found = True
                    ctx.add_child(obj, ole, f"mht/activemime_{i}.ole", kind="decoded")
                if i > 20:
                    break
        if found:
            meta["container"] = "office_xml"
        has_fields = b"instrText" in data or b"fldSimple" in data
        has_rels = b"<Relationship" in data
        text = data.decode("utf-8", "replace") if (has_fields or has_rels) else ""
        if has_fields:
            dde, dde_exec, inc = classify_fields(ooxml_fields(text))
            report_dde(ctx, obj, dde, dde_exec, inc, "Office XML field")
        if has_rels:
            report_relationships(obj, ctx, meta, [("flatopc", r) for r in parse_rels(text)])
        csv = [f"{m.group(1).decode('latin-1')}|'{m.group(2).decode('latin-1')}'" for m in _CSV_DDE_RE.finditer(data[:8 << 20])]
        if csv:
            execs = [c for c in csv if LOLBIN_RE.search(c) or c.lower().startswith(("cmd|", "msexcel|", "powershell|"))]
            if execs:
                _det(ctx, obj, "Heur:Office.DDE.CSV", Confidence.HIGH, 60,
                     "Spreadsheet formula injection launching a command via DDE", execs[:5])
            else:
                _det(ctx, obj, "Heur:Office.DDE", Confidence.MEDIUM, 35, "DDE formula in spreadsheet text", csv[:5])
        if not meta:
            obj.meta.pop("office", None)

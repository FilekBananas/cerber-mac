"""VBA project extraction (MS-OVBA) and VBA source heuristics.

Pure-python implementation of the parts of MS-OVBA we need:
  * RLE decompression of the compressed container (2.4.1)
  * the "dir" stream (module list, code page, text offsets)
  * the "PROJECT" stream (modules visible in the VBE, protection)
plus optional p-code disassembly through pcodedmp for VBA-stomping detection.
"""
from __future__ import annotations

import contextlib
import io
import re
import struct
from dataclasses import dataclass, field

MAX_MODULE_SOURCE = 4 << 20        # decompressed source per module
MAX_PROJECT_SOURCE = 32 << 20      # all modules together
MAX_PCODE_FOR_DISASM = 4 << 20


class VBAError(Exception):
    pass


def decompress(data: bytes, limit: int = MAX_MODULE_SOURCE) -> bytes:
    """MS-OVBA 2.4.1 CompressedContainer -> bytes (tolerant of truncation)."""
    if not data or data[0] != 1:
        raise VBAError("not a compressed container")
    out = bytearray()
    pos, n = 1, len(data)
    while pos + 2 <= n:
        header = data[pos] | (data[pos + 1] << 8)
        chunk_size = (header & 0x0FFF) + 3
        compressed = header & 0x8000
        chunk_end = min(pos + chunk_size, n)
        pos += 2
        start = len(out)
        if not compressed:
            out += data[pos:pos + 4096]
            pos += 4096
        else:
            while pos < chunk_end:
                flags = data[pos]
                pos += 1
                for bit in range(8):
                    if pos >= chunk_end:
                        break
                    if not (flags >> bit) & 1:
                        out.append(data[pos])
                        pos += 1
                        continue
                    if pos + 2 > chunk_end:
                        pos = chunk_end
                        break
                    token = data[pos] | (data[pos + 1] << 8)
                    pos += 2
                    diff = len(out) - start
                    bit_count = max((diff - 1).bit_length(), 4)
                    length_mask = 0xFFFF >> bit_count
                    length = (token & length_mask) + 3
                    offset = (token >> (16 - bit_count)) + 1
                    src = len(out) - offset
                    if src < start or offset <= 0:
                        raise VBAError("invalid copy token")
                    if offset >= length:
                        out += out[src:src + length]
                    else:
                        pat = bytes(out[src:])
                        out += (pat * (length // len(pat) + 1))[:length]
            pos = chunk_end
        if len(out) > limit:
            break
    return bytes(out[:limit])


@dataclass
class VBAModule:
    name: str
    stream_name: str
    text_offset: int = 0
    mtype: str = "standard"          # standard | document/class
    private: bool = False
    source: str = ""
    pcode_size: int = 0
    stream_size: int = 0
    error: str = ""


@dataclass
class VBAProject:
    root: list[str]
    codepage: int = 1252
    syskind: int = 1
    name: str = ""
    modules: list[VBAModule] = field(default_factory=list)
    project_modules: set[str] = field(default_factory=set)   # names listed in PROJECT stream
    project_text: str = ""
    protected: bool = False
    vba_project_data: bytes = b""
    errors: list[str] = field(default_factory=list)


def _codec(cp: int) -> str:
    if cp in (65001,):
        return "utf-8"
    if cp == 10000:
        return "mac_roman"
    name = f"cp{cp}"
    try:
        "".encode(name)
        return name
    except LookupError:
        return "cp1252"


def parse_dir(dir_data: bytes) -> tuple[dict, list[VBAModule]]:
    info: dict = {"codepage": 1252, "syskind": 1, "name": ""}
    modules: list[VBAModule] = []
    cur: VBAModule | None = None
    pos, n = 0, len(dir_data)
    raw_name = b""
    while pos + 6 <= n:
        rid, size = struct.unpack_from("<HI", dir_data, pos)
        pos += 6
        if rid == 0x0009:          # PROJECTVERSION: size says 4 but 6 bytes follow
            size = 6
        if size > n - pos:
            break
        val = dir_data[pos:pos + size]
        pos += size
        if rid == 0x0001 and size >= 4:
            info["syskind"] = struct.unpack_from("<I", val)[0]
        elif rid == 0x0003 and size >= 2:
            info["codepage"] = struct.unpack_from("<H", val)[0]
        elif rid == 0x0004:
            info["name"] = val.decode(_codec(info["codepage"]), "replace")
        elif rid == 0x0019:        # MODULENAME starts a module record
            raw_name = val
            cur = VBAModule(name=val.decode(_codec(info["codepage"]), "replace"), stream_name="")
            modules.append(cur)
        elif cur is not None:
            if rid == 0x0047 and size:
                cur.name = val.decode("utf-16-le", "replace") or cur.name
            elif rid == 0x001A:
                cur.stream_name = val.decode(_codec(info["codepage"]), "replace")
            elif rid == 0x0032 and size:
                cur.stream_name = val.decode("utf-16-le", "replace") or cur.stream_name
            elif rid == 0x0031 and size >= 4:
                cur.text_offset = struct.unpack_from("<I", val)[0]
            elif rid == 0x0022:
                cur.mtype = "document/class"
            elif rid == 0x0028:
                cur.private = True
        if rid == 0x0010:          # dir terminator
            break
    for m in modules:
        if not m.stream_name:
            m.stream_name = m.name
    del raw_name
    return info, modules


_PROJ_MOD_RE = re.compile(r"(?im)^(Module|Document|Class|BaseClass)=([^/\r\n]+)")


def parse_project_stream(text: str) -> tuple[set[str], bool]:
    names = {m.group(2).strip().lower() for m in _PROJ_MOD_RE.finditer(text)}
    # DPB = password protection; an unprotected project has DPB="0E0CD1ECDFF4E7F5E7F5E7" style short value
    dpb = re.search(r'(?im)^DPB="([0-9A-F]+)"', text)
    protected = bool(dpb and len(dpb.group(1)) > 30)
    return names, protected


def _find(ole, path: list[str]) -> list[str] | None:
    """Case-insensitive path lookup in an olefile.OleFileIO."""
    want = [p.lower() for p in path]
    for entry in ole.listdir(streams=True, storages=False):
        if [e.lower() for e in entry] == want:
            return entry
    return None


def find_projects(ole) -> list[list[str]]:
    roots = []
    for entry in ole.listdir(streams=True, storages=False):
        if len(entry) >= 2 and entry[-1].lower() == "dir" and entry[-2].lower() == "vba":
            roots.append(entry[:-2])
    return roots


def extract_projects(ole, errors: list[str]) -> list[VBAProject]:
    projects = []
    total = 0
    for root in find_projects(ole):
        proj = VBAProject(root=root)
        projects.append(proj)
        try:
            dir_data = decompress(ole.openstream(root + ["VBA", "dir"]).read(), 1 << 20)
            info, modules = parse_dir(dir_data)
        except Exception as exc:  # noqa: BLE001
            proj.errors.append(f"dir stream: {exc}")
            info, modules = {"codepage": 1252, "syskind": 1, "name": ""}, []
        proj.codepage, proj.syskind, proj.name = info["codepage"], info["syskind"], info["name"]
        codec = _codec(proj.codepage)
        p = _find(ole, root + ["PROJECT"])
        if p:
            try:
                proj.project_text = ole.openstream(p).read(1 << 20).decode(codec, "replace")
                proj.project_modules, proj.protected = parse_project_stream(proj.project_text)
            except Exception as exc:  # noqa: BLE001
                proj.errors.append(f"PROJECT stream: {exc}")
        p = _find(ole, root + ["VBA", "_VBA_PROJECT"])
        if p:
            try:
                proj.vba_project_data = ole.openstream(p).read(8 << 20)
            except Exception:  # noqa: BLE001
                pass
        seen_streams = set()
        for m in modules:
            sp = _find(ole, root + ["VBA", m.stream_name])
            if not sp:
                m.error = "module stream missing"
                continue
            seen_streams.add(sp[-1].lower())
            try:
                data = ole.openstream(sp).read()
                m.stream_size = len(data)
                m.pcode_size = min(m.text_offset, len(data))
                if total < MAX_PROJECT_SOURCE and m.text_offset < len(data):
                    src = decompress(data[m.text_offset:])
                    total += len(src)
                    m.source = src.decode(codec, "replace")
            except Exception as exc:  # noqa: BLE001
                m.error = str(exc)
        # orphan/unlisted streams in the VBA storage that still hold compressed source
        for entry in ole.listdir(streams=True, storages=False):
            if len(entry) != len(root) + 2 or [e.lower() for e in entry[:-1]] != \
                    [e.lower() for e in root] + ["vba"]:
                continue
            nm = entry[-1].lower()
            if nm in seen_streams or nm in ("dir", "_vba_project") or nm.startswith("__srp_"):
                continue
            try:
                data = ole.openstream(entry).read()
            except Exception:  # noqa: BLE001
                continue
            mt = re.search(rb"\x00Attribut[^e]", data, re.I)
            if mt and mt.start() >= 3:
                try:
                    src = decompress(data[mt.start() - 3:]).decode(codec, "replace")
                except Exception:  # noqa: BLE001
                    continue
                mod = VBAModule(name=entry[-1], stream_name=entry[-1], text_offset=mt.start() - 3,
                                source=src, pcode_size=mt.start() - 3, stream_size=len(data),
                                error="not listed in dir stream")
                proj.modules.append(mod)
        proj.modules[:0] = modules
        errors.extend(proj.errors)
    return projects


# --------------------------------------------------------------------------- p-code

class _Args:
    verbose = False
    disasmOnly = True


_PCODE_NAME_OPS = ("ArgsCall", "ArgsLd", "St", "Ld", "MemSt", "Label", "MemLd", "MemCall")


def pcode_keywords(ole, proj: VBAProject) -> tuple[set[str], int]:
    """Disassemble p-code with pcodedmp; return (identifiers/strings used, n_lines)."""
    try:
        from pcodedmp import pcodedmp  # type: ignore
    except Exception:  # noqa: BLE001
        return set(), -1
    if not proj.vba_project_data:
        return set(), -1
    keywords: set[str] = set()
    lines = 0
    buf = io.StringIO()
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            identifiers = pcodedmp.getTheIdentifiers(proj.vba_project_data)
            for m in proj.modules:
                sp = _find(ole, proj.root + ["VBA", m.stream_name])
                if not sp or m.stream_size > MAX_PCODE_FOR_DISASM:
                    continue
                data = ole.openstream(sp).read()
                pcodedmp.pcodeDump(data, proj.vba_project_data, b"", identifiers, proj.syskind == 3,
                                   _Args(), output_file=buf)
    except Exception:  # noqa: BLE001
        return set(), -1
    for line in buf.getvalue().splitlines():
        if not line.startswith("\t"):
            continue
        tokens = line.split(None, 1)
        mnem = tokens[0]
        args = tokens[1].strip() if len(tokens) == 2 else ""
        lines += 1
        if mnem in _PCODE_NAME_OPS and args:
            if args.startswith("(Call) "):
                args = args[7:]
            name = args.split(None, 1)[0]
            if not name.startswith("id_") and re.match(r"^[A-Za-z_]\w*$", name):
                keywords.add(name)
        elif mnem == "LitStr" and args:
            parts = args.split(None, 1)
            if len(parts) == 2 and len(parts[1]) >= 2 and parts[1][0] == '"' and parts[1][-1] == '"':
                s = parts[1][1:-1]
                if len(s) >= 4:
                    keywords.add('"' + s.replace('"', '""') + '"')
    return keywords, lines


# --------------------------------------------------------------------------- heuristics

def _rx(words: list[str], prefix: str = r"\b", suffix: str = r"\b") -> re.Pattern[str]:
    return re.compile(prefix + "(" + "|".join(words) + ")" + suffix, re.I)


AUTOEXEC_RE = _rx([
    "AutoExec", "AutoOpen", "Auto_Open", "AutoClose", "Auto_Close", "AutoNew", "Auto_New", "AutoExit",
    "Document_Open", "Document_Close", "Document_New", "Document_BeforeClose",
    "Document_ContentControlOnEnter", "Document_ContentControlOnExit", "DocumentOpen", "DocumentBeforeClose",
    "Workbook_Open", "Workbook_Activate", "Workbook_Close", "Workbook_BeforeClose", "Workbook_Deactivate",
    "Workbook_WindowActivate", "Auto_Activate", "Presentation_Open", "App_WorkbookOpen", "App_DocumentOpen",
    r"\w+_Layout", r"\w+_Painted", r"\w+_Resize", r"\w+_GotFocus",
])
_SUB_DEF_RE = re.compile(r"(?im)^\s*(?:(?:Public|Private|Friend)\s+)?(?:Static\s+)?(?:Sub|Function)\s+(\w+)")

EXEC_PATTERNS = [
    r"(?<![.\w])Shell\s*[\(\s]", r"WScript\.Shell", r"Shell\.Application", r"ShellExecute[AW]?\b",
    r"\bWinExec\b", r"\bCreateProcess[AW]?\b", r"\bMacScript\b", r"\bAppleScriptTask\b",
    r"\bpopen\b", r"\bexecve\b", r"\.Exec\s*\(", r"Lib\s+\"(?:/usr/lib/)?libc\.dylib\"", r"Win32_Process\b",
    r"\bwinmgmts\b", r"\bExecuteExcel4Macro\b", r"Schedule\.Service", r"\bInvokeVerb(?:Ex)?\b",
    r"\bShellExecuteEx\b", r"\.ShellExecute\b",
]
DOWNLOAD_PATTERNS = [
    r"\bURLDownloadToFile[AW]?\b", r"MSXML2\.(?:Server)?XMLHTTP", r"Microsoft\.XMLHTTP", r"WinHttp\.WinHttpRequest",
    r"\bInternetOpen(?:Url)?[AW]?\b", r"\bInternetReadFile\b", r"\bHttpSendRequest[AW]?\b", r"Net\.WebClient",
    r"\bDownloadFile\b", r"\bDownloadString\b", r"\bURLMon\b", r"\bcurl\s+-", r"\bbitsadmin\b", r"certutil[^\"]{0,40}-urlcache",
]
WRITE_PATTERNS = [
    r"ADODB\.Stream", r"\.SaveToFile\b", r"\bCreateTextFile\b", r"\bOpen\s+.{1,120}\s+For\s+(?:Binary|Output|Append)\b",
    r"\bPut\s+#", r"\bFileCopy\b", r"\.CopyFile\b", r"\.CopyHere\b",
]
POWERSHELL_PATTERNS = [
    r"\bpowershell(?:\.exe)?\b", r"\bpwsh\b", r"-EncodedCommand\b", r"\bIEX\b", r"Invoke-Expression",
    r"-(?:w|windowstyle)\s+hidden", r"-exec(?:utionpolicy)?\s+bypass", r"FromBase64String",
]
API_ALLOC = r"\b(VirtualAlloc(?:Ex)?|NtAllocateVirtualMemory|HeapCreate|VirtualProtect(?:Ex)?|mprotect|mmap)\b"
API_COPY = r"\b(RtlMoveMemory|WriteProcessMemory|RtlCopyMemory|memcpy|CopyMemory)\b"
API_RUN = (r"\b(CreateThread|CreateRemoteThread|QueueUserAPC|EnumSystemLocales[AW]?|EnumDateFormats[AW]?|"
           r"EnumTimeFormats[AW]?|CallWindowProc[AW]?|EnumWindows|EnumChildWindows|EnumSystemCodePages[AW]?|"
           r"SetTimer|EnumResourceTypes[AW]?|EnumUILanguages[AW]?|pthread_create)\b")
PERSIST_PATTERNS = [
    r"\.RegWrite\b", r"CurrentVersion\\\\?Run", r"\\Startup\\", r"\bschtasks\b", r"LaunchAgents",
    r"Schedule\.Service",
]
EVASION_PATTERNS = [
    r"RecentFiles\.Count", r"\bVMware\b", r"\bVirtualBox\b", r"\bvbox\w*", r"Application\.DisplayAlerts\s*=\s*False",
    r"\.ShowWindow\s*=\s*0", r"Win32_ComputerSystem", r"\bGetTickCount\b",
]

EXEC_RE = _rx(EXEC_PATTERNS, "", "")
DOWNLOAD_RE = _rx(DOWNLOAD_PATTERNS, "", "")
WRITE_RE = _rx(WRITE_PATTERNS, "", "")
POWERSHELL_RE = _rx(POWERSHELL_PATTERNS, "", "")
API_ALLOC_RE = re.compile(API_ALLOC, re.I)
API_COPY_RE = re.compile(API_COPY, re.I)
API_RUN_RE = re.compile(API_RUN, re.I)
DECLARE_RE = re.compile(r"(?im)^\s*(?:Public\s+|Private\s+)?Declare\s+(?:PtrSafe\s+)?(?:Function|Sub)\s+(\w+)"
                        r"\s+Lib\s+\"([^\"]+)\"(?:\s+Alias\s+\"([^\"]+)\")?")
PERSIST_RE = _rx(PERSIST_PATTERNS, "", "")
EVASION_RE = _rx(EVASION_PATTERNS, "", "")
CHR_RE = re.compile(r"\bChr[BW]?\$?\s*\(", re.I)
STRREV_RE = re.compile(r"\bStrReverse\s*\(", re.I)
CALLBYNAME_RE = re.compile(r"\bCallByName\b", re.I)
B64DOM_RE = re.compile(r"bin\.base64|nodeTypedValue|Base64Decode|DecodeBase64", re.I)
ENVIRON_RE = re.compile(r"\bEnviron\$?\s*\(", re.I)
STRING_LIT_RE = re.compile(r'"((?:[^"\r\n]|"")*)"')
B64_LIT_RE = re.compile(r"^[A-Za-z0-9+/]{120,}={0,2}$")
HEX_LIT_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}){80,}$")
URL_IN_VBA_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>)]{4,300}")


@dataclass
class VBAFindings:
    autoexec: list[str] = field(default_factory=list)
    execs: list[str] = field(default_factory=list)
    downloads: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)
    powershell: list[str] = field(default_factory=list)
    api_alloc: list[str] = field(default_factory=list)
    api_copy: list[str] = field(default_factory=list)
    api_run: list[str] = field(default_factory=list)
    declares: list[str] = field(default_factory=list)
    persistence: list[str] = field(default_factory=list)
    evasion: list[str] = field(default_factory=list)
    obfuscation: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    environ: int = 0
    chr_calls: int = 0


def _uniq(items, limit=20):
    out = []
    seen = set()
    for i in items:
        k = i.lower()
        if k not in seen:
            seen.add(k)
            out.append(i)
            if len(out) >= limit:
                break
    return out


def strip_comments(code: str) -> str:
    """Drop whole-line comments and Attribute lines (keeps strings intact)."""
    out = []
    for line in code.splitlines():
        s = line.lstrip()
        if not s or s.startswith("'") or s[:4].lower() == "rem " or s.lower().startswith("attribute vb_"):
            continue
        out.append(line)
    return "\n".join(out)


def analyze_source(code: str) -> VBAFindings:
    f = VBAFindings()
    body = strip_comments(code)
    if not body.strip():
        return f
    defined = {m.group(1) for m in _SUB_DEF_RE.finditer(body)}
    f.autoexec = _uniq(n for n in defined if AUTOEXEC_RE.fullmatch(n))
    f.execs = _uniq(m.group().strip(" (") for m in EXEC_RE.finditer(body))
    f.downloads = _uniq(m.group() for m in DOWNLOAD_RE.finditer(body))
    f.writes = _uniq(m.group()[:60] for m in WRITE_RE.finditer(body))
    f.powershell = _uniq(m.group() for m in POWERSHELL_RE.finditer(body))
    decl_names = []
    for m in DECLARE_RE.finditer(body):
        decl_names.append(m.group(3) or m.group(1))
        f.declares.append(f"{m.group(1)} Lib {m.group(2)}" + (f" Alias {m.group(3)}" if m.group(3) else ""))
    decl_text = " ".join(decl_names)
    f.api_alloc = _uniq(m.group() for m in API_ALLOC_RE.finditer(decl_text))
    f.api_copy = _uniq(m.group() for m in API_COPY_RE.finditer(decl_text))
    f.api_run = _uniq(m.group() for m in API_RUN_RE.finditer(decl_text))
    f.persistence = _uniq(m.group() for m in PERSIST_RE.finditer(body))
    f.evasion = _uniq(m.group() for m in EVASION_RE.finditer(body))
    f.environ = len(ENVIRON_RE.findall(body))
    f.chr_calls = len(CHR_RE.findall(body))
    if f.chr_calls >= 40:
        f.obfuscation.append(f"{f.chr_calls} Chr() calls")
    if STRREV_RE.search(body):
        f.obfuscation.append("StrReverse")
    if CALLBYNAME_RE.search(body):
        f.obfuscation.append("CallByName")
    if B64DOM_RE.search(body):
        f.obfuscation.append("Base64 decoding")
    n_concat = body.count('" & "') + body.count('"&"') + body.count('" + "')
    if n_concat >= 150:
        f.obfuscation.append(f"{n_concat} string concatenations")
    long_b64 = long_hex = 0
    for m in STRING_LIT_RE.finditer(body):
        s = m.group(1)
        if len(s) >= 120:
            if B64_LIT_RE.match(s):
                long_b64 += 1
            elif HEX_LIT_RE.match(s):
                long_hex += 1
    if long_b64:
        f.obfuscation.append(f"{long_b64} long Base64 string(s)")
    if long_hex:
        f.obfuscation.append(f"{long_hex} long hex string(s)")
    longest_line = max((len(x) for x in body.splitlines()), default=0)
    if longest_line > 4000:
        f.obfuscation.append(f"very long code line ({longest_line} chars)")
    f.urls = _uniq((m.group() for m in URL_IN_VBA_RE.finditer(body)), 50)
    return f


def merge(a: VBAFindings, b: VBAFindings) -> VBAFindings:
    for name in ("autoexec", "execs", "downloads", "writes", "powershell", "api_alloc", "api_copy", "api_run",
                 "declares", "persistence", "evasion", "obfuscation", "urls"):
        setattr(a, name, _uniq(getattr(a, name) + getattr(b, name), 50))
    a.environ += b.environ
    a.chr_calls += b.chr_calls
    return a

"""Windows PE heuristics (pefile).

Analyzer "exe_pe" (order 40) for ftype "pe". Section info, imphash, imports, signature,
version info, .NET/toolchain info go to obj.meta["pe"].

Detections (engine "heuristic"):
    Heur:PE.Malformed                      15  headers pefile cannot parse / impossible header values
    Heur:PE.Packed.UPX                     10  UPX section names (see exe_unpack for unpacking)
    Heur:PE.Packer.<Name>                  15  known packer section names (ASPack, MPRESS, PECompact, ...)
    Heur:PE.Protector.<Name>               10  commercial protectors (VMProtect, Themida, Enigma, ...)
    Heur:PE.Virus.Ramnit                   60  .rmnet section (Ramnit file infector)
    Heur:PE.PUA.Firseria                   30 pua  Firseria bundler sections
    Heur:PE.Packed.HighEntropy          15/25  executable section entropy >= 7.4 (+ tiny import table)
    Heur:PE.Section.RWX                    10  section mapped read+write+execute (not for drivers/EFI)
    Heur:PE.Section.OddName                 5  non-printable / empty section names
    Heur:PE.EntryPoint.OutsideSections     20  EP not inside any section (or inside the headers)
    Heur:PE.EntryPoint.NonExecSection      15  EP in a section without IMAGE_SCN_MEM_EXECUTE
    Heur:PE.EntryPoint.LastSection         10  EP in the last of several sections (packer stub)
    Heur:PE.EntryPoint.InOverlay           25  EP maps beyond the raw data of the file
    Heur:PE.NoImports                      10  EXE without any import (shellcode loader / packed; not drivers/EFI)
    Heur:PE.Imports.DynamicResolveOnly     15  <= 8 imports incl. LoadLibrary + GetProcAddress
    Heur:PE.API.ProcessInjection           25  OpenProcess + VirtualAllocEx + WriteProcessMemory + remote thread/APC
    Heur:PE.API.ProcessHollowing           35  CreateProcess + NtUnmapViewOfSection + WriteProcessMemory + SetThreadContext + ResumeThread
    Heur:PE.API.Keylogger                  15  SetWindowsHookEx + key state + foreground window title
    Heur:PE.API.AntiDebug                  10  >= 3 anti-debug APIs (IsDebuggerPresent ignored)
    Heur:PE.API.DownloadExecute            15  URLDownloadToFile + ShellExecute/WinExec/CreateProcess
    Heur:PE.API.RansomwareLike             10  crypto API + file enumeration + drive enumeration
    Heur:PE.API.ScreenCapture               5  BitBlt + GetDIBits + CreateCompatibleBitmap
    Heur:PE.API.CredentialAccess           15  LSA secrets / credential manager enumeration
    Heur:PE.API.TokenManipulation           5  token duplication + impersonation
    Heur:PE.TLSCallbacks                    2  TLS callbacks (5 when the file also looks packed)
    Heur:PE.Timestamp.Future                3  link time in the future (not a /Brepro build)
    Heur:PE.Checksum.Mismatch            5/10  non-zero header checksum that does not match (10 for drivers)
    Heur:PE.Authenticode.HashMismatch      25  embedded signature digest does not match the file (tampered)
    Heur:PE.Authenticode.AppendedData      10  non-zero data hidden inside the certificate table padding
    Heur:PE.RichHeader.Tampered            15  Rich header checksum mismatch (forged/copied header)
    Heur:PE.Masquerade.VersionInfo         25  claims to be a Windows system binary / Microsoft file but is not
    Heur:PE.DotNet.Obfuscator.<Name>    10/20  .NET obfuscator markers (ConfuserEx 20)
    Heur:PE.DotNet.ReflectiveLoad          15  unsigned assembly: Assembly.Load + EntryPoint.Invoke + decrypt/decompress
    Heur:PE.ReflectiveDLL                  40  exports ReflectiveLoader
    Heur:PE.PDB.SuspiciousPath             20  PDB path with stealer/crypter/rat/... component
    Heur:PE.AutoIt                          5  compiled AutoIt script
    Heur:PE.Toolchain.<Name>                0  info: Go / Rust / Nim / NSIS / Inno / .NET / Delphi / ...
    + shared string rules from exe_misc (Heur:PE.Ransom.*, Heur:PE.Stealer.*, Heur:PE.UACBypass, ...)
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import re
import struct
import time

from ..core import Analyzer, Confidence, ScanContext, ScanObject
from . import register
from .exe_misc import apply_rules, det, onion_rule, runtime_cap, sampled_entropy, string_hits

try:
    import pefile  # type: ignore
except Exception:  # pragma: no cover
    pefile = None

MAX_PARSE = 256 << 20            # don't hand gigantic PEs to pefile
TOKEN_BUDGET = 24 << 20          # identifier-token scan budget (dynamic API names)

SCN_CODE = 0x20
SCN_EXEC = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000

MACHINES = {0x14C: "i386", 0x8664: "x86_64", 0xAA64: "arm64", 0x1C0: "arm", 0x1C4: "armnt", 0x200: "ia64",
            0xEBC: "efi-bytecode", 0x5064: "riscv64", 0xA641: "arm64ec"}
SUBSYSTEMS = {1: "native", 2: "gui", 3: "console", 9: "wince", 10: "efi_app", 11: "efi_boot", 12: "efi_runtime",
              16: "boot_app"}

# section name -> (kind, label, score); kind: packer | protector | virus | pua | upx | installer
SECTION_NAMES: dict[str, tuple[str, str, int]] = {
    "upx0": ("upx", "UPX", 10), "upx1": ("upx", "UPX", 10), "upx2": ("upx", "UPX", 10), ".upx0": ("upx", "UPX", 10),
    ".upx1": ("upx", "UPX", 10), "upx!": ("upx", "UPX", 10),
    ".aspack": ("packer", "ASPack", 15), ".adata": ("packer", "ASPack", 15), ".asspck": ("packer", "ASPack", 15),
    ".mpress1": ("packer", "MPRESS", 15), ".mpress2": ("packer", "MPRESS", 15),
    "pec1": ("packer", "PECompact", 15), "pec2": ("packer", "PECompact", 15), "pecompact2": ("packer", "PECompact", 15),
    "pec2to": ("packer", "PECompact", 15), "pec2mo": ("packer", "PECompact", 15),
    ".petite": ("packer", "Petite", 15), "petite": ("packer", "Petite", 15),
    ".nsp0": ("packer", "NsPack", 15), ".nsp1": ("packer", "NsPack", 15), ".nsp2": ("packer", "NsPack", 15),
    "nsp0": ("packer", "NsPack", 15), "nsp1": ("packer", "NsPack", 15),
    "fsg!": ("packer", "FSG", 15), "mew": ("packer", "MEW", 15), ".mew": ("packer", "MEW", 15),
    ".upack": ("packer", "Upack", 15), ".bydwing": ("packer", "Upack", 15),
    ".rlpack": ("packer", "RLPack", 15), "kkrunchy": ("packer", "kkrunchy", 15),
    ".packed": ("packer", "Generic", 15), ".spack": ("packer", "SimplePack", 15), ".yp": ("packer", "YodaProtector", 15),
    ".y0da": ("packer", "YodaCrypter", 15), ".ccg": ("packer", "CCG", 15), ".charmve": ("packer", "PIN", 15),
    "pebundle": ("packer", "PEBundle", 15), "pelocknt": ("packer", "PELock", 15), ".perplex": ("packer", "Perplex", 15),
    "peshield": ("packer", "PEShield", 15), ".neolit": ("packer", "NeoLite", 15), ".neolite": ("packer", "NeoLite", 15),
    "procrypt": ("packer", "ProCrypt", 15), ".svkp": ("packer", "SVKP", 15), ".boom": ("packer", "Boomerang", 15),
    ".maskpe": ("packer", "MaskPE", 15), "!epack": ("packer", "EPack", 15), "eyepack": ("packer", "EyePack", 15),
    ".wwpack": ("packer", "WWPack", 15), ".sforce3": ("protector", "StarForce", 10),
    ".vmp0": ("protector", "VMProtect", 10), ".vmp1": ("protector", "VMProtect", 10), ".vmp2": ("protector", "VMProtect", 10),
    ".themida": ("protector", "Themida", 10), ".winlice": ("protector", "WinLicense", 10),
    ".enigma1": ("protector", "Enigma", 10), ".enigma2": ("protector", "Enigma", 10),
    ".arch": ("protector", "Armadillo", 10), ".securom": ("protector", "SecuROM", 10),
    ".rmnet": ("virus", "Ramnit", 60),
    ".mnbvcx1": ("pua", "Firseria", 30), ".mnbvcx2": ("pua", "Firseria", 30),
    ".ndata": ("installer", "NSIS", 0), ".wixburn": ("installer", "WiX-Burn", 0),
}

API_GROUPS: dict[str, tuple[str, ...]] = {
    "open": ("OpenProcess", "NtOpenProcess", "ZwOpenProcess"),
    "alloc_remote": ("VirtualAllocEx", "VirtualAlloc2", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory",
                     "NtMapViewOfSection", "ZwMapViewOfSection", "VirtualAllocExNuma"),
    "write_remote": ("WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory"),
    "remote_exec": ("CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "ZwCreateThreadEx",
                    "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread", "NtQueueApcThreadEx"),
    "unmap": ("NtUnmapViewOfSection", "ZwUnmapViewOfSection"),
    "set_ctx": ("SetThreadContext", "Wow64SetThreadContext", "NtSetContextThread"),
    "resume": ("ResumeThread", "NtResumeThread"),
    "create_proc": ("CreateProcessA", "CreateProcessW", "CreateProcessInternalW", "NtCreateUserProcess",
                    "CreateProcessAsUserW", "CreateProcessAsUserA"),
    "hook": ("SetWindowsHookExA", "SetWindowsHookExW"),
    "keystate": ("GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "MapVirtualKeyA", "MapVirtualKeyW",
                 "ToUnicode", "ToAscii", "GetRawInputData"),
    "fgwin": ("GetForegroundWindow",),
    "wintext": ("GetWindowTextA", "GetWindowTextW"),
    "antidebug": ("CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "ZwQueryInformationProcess",
                  "NtSetInformationThread", "ZwSetInformationThread", "OutputDebugStringA", "DebugActiveProcess",
                  "BlockInput", "NtQueryObject", "NtQuerySystemInformation"),
    "download": ("URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileA", "URLDownloadToCacheFileW"),
    "exec": ("ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW", "WinExec", "CreateProcessA",
             "CreateProcessW"),
    "crypto": ("CryptEncrypt", "BCryptEncrypt", "CryptGenKey", "CryptImportKey", "BCryptGenerateSymmetricKey"),
    "findfile": ("FindFirstFileA", "FindFirstFileW", "FindFirstFileExA", "FindFirstFileExW"),
    "findnext": ("FindNextFileA", "FindNextFileW"),
    "drives": ("GetLogicalDrives", "GetLogicalDriveStringsA", "GetLogicalDriveStringsW"),
    "screen": ("BitBlt",), "dibits": ("GetDIBits",), "compatbmp": ("CreateCompatibleBitmap",),
    "lsa": ("LsaRetrievePrivateData", "LsaEnumerateLogonSessions", "SamIConnect", "SamrQueryInformationUser",
            "CredEnumerateA", "CredEnumerateW"),
    "dup_token": ("DuplicateTokenEx", "DuplicateToken", "NtDuplicateToken"),
    "impersonate": ("ImpersonateLoggedOnUser", "SetThreadToken", "CreateProcessWithTokenW", "NtSetInformationThread"),
    "getproc": ("GetProcAddress", "LdrGetProcedureAddress"),
    "loadlib": ("LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll"),
}
_API_ALL = {n for g in API_GROUPS.values() for n in g}

SYSTEM_BINARIES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "explorer.exe", "services.exe", "smss.exe",
    "spoolsv.exe", "taskhost.exe", "taskhostw.exe", "dllhost.exe", "rundll32.exe", "conhost.exe", "wininit.exe",
    "ctfmon.exe", "dwm.exe", "searchindexer.exe", "runtimebroker.exe", "sihost.exe", "lsm.exe", "taskmgr.exe",
    "regsvr32.exe", "msiexec.exe", "cmd.exe", "powershell.exe", "notepad.exe", "calc.exe", "wuauclt.exe",
    "audiodg.exe", "fontdrvhost.exe", "smartscreen.exe", "securityhealthservice.exe", "msmpeng.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "werfault.exe", "userinit.exe", "logonui.exe", "winver.exe",
}
PDB_BAD = re.compile(r"(?i)(?:^|[\\/_.\- ])(stub|crypter|crypted|stealer|keylogger|ransom\w*|injector|shellcode|"
                     r"backdoor|botnet|trojan|malware|rootkit|grabber|clipper|dropper|rat|hvnc|loader_?bot)"
                     r"(?:$|[\\/_.\- ])")
DOTNET_OBF = [
    (b"ConfuserEx v", "ConfuserEx", 20), (b"ConfusedByAttribute", "ConfuserEx", 20),
    (b"Eziriz", "NETReactor", 10), (b".NET Reactor", "NETReactor", 10),
    (b"SmartAssembly.Attributes", "SmartAssembly", 10), (b"DotfuscatorAttribute", "Dotfuscator", 10),
    (b"BabelObfuscatorAttribute", "Babel", 10), (b"AgileDotNetRT", "AgileNET", 10), (b"CliSecureRT", "AgileNET", 10),
    (b"CryptoObfuscator", "CryptoObfuscator", 10), (b"DeepSeaObfuscator", "DeepSea", 10),
    (b"ObfuscatedByGoliath", "Goliath", 10), (b"Xenocode.Client", "Xenocode", 10), (b"YanoAttribute", "Yano", 10),
    (b"ObfuscatedByAgileDotNetAttribute", "AgileNET", 10), (b"EazfuscatorNet", "Eazfuscator", 10),
    (b"Beds-Protector", "BedsProtector", 20), (b"KoiVM", "KoiVM", 20),
]

_MISSING = object()
_TOKEN_RE = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{3,60}")


def load_pe(obj: ScanObject):
    """Parse (once) and cache a pefile.PE for the object; None if not parseable."""
    cached = obj.__dict__.get("_cerber_pe", _MISSING)
    if cached is not _MISSING:
        return cached or None
    pe = None
    if pefile is not None and obj.size <= MAX_PARSE:
        try:
            pe = pefile.PE(data=obj.data, fast_load=True)
            d = pefile.DIRECTORY_ENTRY
            pe.parse_data_directories(directories=[
                d["IMAGE_DIRECTORY_ENTRY_IMPORT"], d["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                d["IMAGE_DIRECTORY_ENTRY_RESOURCE"], d["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                d["IMAGE_DIRECTORY_ENTRY_TLS"], d["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]])
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"pefile: {exc}")
            pe = None
    obj.__dict__["_cerber_pe"] = pe if pe is not None else False
    return pe


def section_name(s) -> str:
    return s.Name.rstrip(b"\x00").decode("latin-1", "replace")


def data_dir(pe, idx: int) -> tuple[int, int]:
    try:
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
        return dd.VirtualAddress, dd.Size
    except Exception:  # noqa: BLE001
        return 0, 0


def security_dir(pe, size: int) -> tuple[int, int] | None:
    off, sz = data_dir(pe, 4)
    if off and sz and off + 8 <= size:
        return off, min(sz, size - off)
    return None


def pe_checksum(data: bytes, checksum_off: int) -> int:
    """PE checksum via big-int arithmetic (ones-complement sum of 16-bit words == value mod 0xFFFF)."""
    d = data[:checksum_off] + b"\x00\x00\x00\x00" + data[checksum_off + 4:]
    if len(d) % 2:
        d += b"\x00"
    s = int.from_bytes(d, "little") % 0xFFFF if d else 0
    if s == 0 and any(d[:64]):
        s = 0xFFFF
    return (s + len(data)) & 0xFFFFFFFF


def rich_info(data: bytes, lfanew: int) -> dict | None:
    end = min(lfanew, len(data), 0x1000)
    ri = data.find(b"Rich", 0x80, end)
    if ri < 0 or ri + 8 > len(data):
        return None
    key = struct.unpack_from("<I", data, ri + 4)[0]
    dans = None
    for o in range(ri - 4, 0x3F, -4):
        if struct.unpack_from("<I", data, o)[0] ^ key == 0x536E6144:
            dans = o
            break
    if dans is None:
        return {"valid": False, "reason": "no DanS"}
    vals = []
    for o in range(dans + 16, ri, 8):
        compid = struct.unpack_from("<I", data, o)[0] ^ key
        count = struct.unpack_from("<I", data, o + 4)[0] ^ key
        vals.append((compid, count))
    cs = dans
    for i in range(dans):
        if 0x3C <= i < 0x40:
            continue
        b = data[i]
        r = i % 32
        cs += ((b << r) | (b >> (32 - r))) & 0xFFFFFFFF
    for compid, count in vals:
        r = count % 32
        cs += ((compid << r) | (compid >> (32 - r))) & 0xFFFFFFFF
    cs &= 0xFFFFFFFF
    return {"valid": cs == key, "key": f"{key:08x}", "computed": f"{cs:08x}", "entries": len(vals),
            "products": sorted({c >> 16 for c, _ in vals})[:32]}


_CN_RE = re.compile(rb"\x06\x03\x55\x04\x03[\x0c\x13\x14\x16\x1e](.)", re.S)


def cert_common_names(blob: bytes, limit: int = 12) -> list[str]:
    out: list[str] = []
    for m in _CN_RE.finditer(blob):
        ln = m.group(1)[0]
        if ln & 0x80:
            continue
        s = blob[m.end():m.end() + ln]
        tag = blob[m.start() + 5]
        try:
            v = s.decode("utf-16-be") if tag == 0x1E else s.decode("utf-8")
        except Exception:  # noqa: BLE001
            v = s.decode("latin-1")
        if v and v not in out:
            out.append(v)
        if len(out) >= limit:
            break
    return out


_DIGEST_PATTERNS = [
    ("sha256", re.compile(rb"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20(.{32})", re.S)),
    ("sha1", re.compile(rb"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14(.{20})", re.S)),
    ("sha384", re.compile(rb"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30(.{48})", re.S)),
    ("sha512", re.compile(rb"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40(.{64})", re.S)),
    ("md5", re.compile(rb"\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10(.{16})", re.S)),
]
_SPC_INDIRECT = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x04"   # 1.3.6.1.4.1.311.2.1.4


def authenticode_check(data: bytes, pe, sec: tuple[int, int]) -> dict:
    """Recompute the Authenticode image hash and compare with SpcIndirectDataContent's digest."""
    cert_off, cert_size = sec
    blob = data[cert_off + 8:cert_off + cert_size]
    res: dict = {"signers": cert_common_names(blob)}
    i = blob.find(_SPC_INDIRECT)
    if i < 0:
        res["status"] = "no-spc"
        return res
    for algo, rx in _DIGEST_PATTERNS:
        m = rx.search(blob, i, i + 512)
        if m:
            break
    else:
        res["status"] = "no-digest"
        return res
    expected = m.group(1)
    opt = pe.OPTIONAL_HEADER.get_file_offset()
    cs_off = opt + 0x40
    sec_entry = opt + (0x80 if pe.OPTIONAL_HEADER.Magic == 0x10B else 0x90)
    h = hashlib.new(algo)
    h.update(data[:cs_off])
    h.update(data[cs_off + 4:sec_entry])
    h.update(data[sec_entry + 8:cert_off])
    tail = data[cert_off + cert_size:]
    if tail:
        h.update(tail)
    ok = h.digest() == expected
    if not ok and tail:
        # some signers do not hash trailing padding after the table
        h2 = hashlib.new(algo)
        h2.update(data[:cs_off])
        h2.update(data[cs_off + 4:sec_entry])
        h2.update(data[sec_entry + 8:cert_off])
        ok = h2.digest() == expected
    if not ok:
        # sections-only variant (gap between last section and certificate table is padded with zeros)
        h3 = hashlib.new(algo)
        h3.update(data[:cs_off])
        h3.update(data[cs_off + 4:sec_entry])
        h3.update(data[sec_entry + 8:cert_off])
        pad = (8 - (cert_off % 8)) % 8
        if pad:
            h3.update(b"\x00" * pad)
            ok = h3.digest() == expected
    res["status"] = "valid-digest" if ok else "digest-mismatch"
    res["algo"] = algo
    app = cert_padding(data, sec)
    if app:
        res["appended"] = app
    return res


def cert_padding(data: bytes, sec: tuple[int, int]) -> tuple[int, int] | None:
    """(offset, length) of non-zero data hidden in WIN_CERTIFICATE after the PKCS#7 DER blob."""
    cert_off, cert_size = sec
    blob = data[cert_off + 8:cert_off + cert_size]
    if len(blob) >= 4 and blob[0] == 0x30 and blob[1] in (0x82, 0x83):
        if blob[1] == 0x82:
            der_len = 4 + struct.unpack(">H", blob[2:4])[0]
        else:
            der_len = 5 + int.from_bytes(blob[2:5], "big")
        extra = blob[der_len:]
        if len(extra) > 16 and extra.count(0) != len(extra):
            return cert_off + 8 + der_len, len(extra)
    return None


def version_strings(pe) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in fi:
                for st in getattr(entry, "StringTable", []) or []:
                    for k, v in st.entries.items():
                        ks = k.decode("utf-8", "replace") if isinstance(k, bytes) else str(k)
                        vs = v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
                        if ks and ks not in out:
                            out[ks] = vs[:200]
    except Exception:  # noqa: BLE001
        pass
    return out


def debug_info(pe) -> tuple[str | None, bool]:
    pdb, repro = None, False
    for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        try:
            t = dbg.struct.Type
            if t == 16:
                repro = True
            if t == 2 and dbg.entry is not None and pdb is None:
                p = getattr(dbg.entry, "PdbFileName", None)
                if p:
                    pdb = p.rstrip(b"\x00").decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue
    return pdb, repro


def imports_of(pe) -> tuple[list[tuple[str, str]], list[str]]:
    funcs: list[tuple[str, str]] = []
    dlls: list[str] = []
    for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in getattr(pe, attr, []) or []:
            try:
                dll = entry.dll.decode("latin-1", "replace") if entry.dll else "?"
            except Exception:  # noqa: BLE001
                dll = "?"
            dlls.append(dll)
            for imp in entry.imports or []:
                if imp.name:
                    funcs.append((dll.lower(), imp.name.decode("latin-1", "replace")))
                else:
                    funcs.append((dll.lower(), f"#{imp.ordinal}"))
    return funcs, dlls


@register
class PEAnalyzer(Analyzer):
    name = "exe_pe"
    order = 40

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype == "pe"

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        data = obj.data
        pe = load_pe(obj)
        meta: dict = obj.meta.setdefault("pe", {})
        if pe is None:
            if obj.size <= MAX_PARSE:
                ctx.detect(obj, det("Heur:PE.Malformed", Confidence.MEDIUM, 15,
                                    "PE headers cannot be parsed (malformed / anti-analysis)", obj.errors[-1:]))
            return
        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        is_dll = bool(fh.Characteristics & 0x2000)
        firmware = oh.Subsystem in (1, 10, 11, 12, 13, 16)   # drivers / EFI / boot apps: no Win32 imports by design
        ep = oh.AddressOfEntryPoint
        meta.update({
            "machine": MACHINES.get(fh.Machine, hex(fh.Machine)), "dll": is_dll,
            "subsystem": SUBSYSTEMS.get(oh.Subsystem, str(oh.Subsystem)),
            "timestamp": fh.TimeDateStamp, "entry_point": hex(ep), "image_base": hex(oh.ImageBase),
        })
        clr_rva, clr_size = data_dir(pe, 14)
        dotnet = bool(clr_rva and clr_size)
        meta["dotnet"] = dotnet
        try:
            meta["imphash"] = pe.get_imphash() or None
        except Exception:  # noqa: BLE001
            meta["imphash"] = None

        # ---- sections -----------------------------------------------------------
        secs = []
        packed_hint = False
        size = len(data)
        ep_sec = None
        truncated = False
        for idx, s in enumerate(pe.sections[:96]):
            nm = section_name(s)
            ch = s.Characteristics
            raw_off, raw_sz = s.PointerToRawData, s.SizeOfRawData
            if raw_off + raw_sz > size and raw_sz:
                truncated = True
            ent = sampled_entropy(data, raw_off, raw_off + raw_sz) if raw_sz and raw_off < size else 0.0
            flags = ("R" if ch & SCN_READ else "-") + ("W" if ch & SCN_WRITE else "-") + ("X" if ch & SCN_EXEC else "-")
            secs.append({"name": nm, "vaddr": hex(s.VirtualAddress), "vsize": s.Misc_VirtualSize, "rsize": raw_sz,
                         "entropy": round(ent, 3), "flags": flags})
            vs = max(s.Misc_VirtualSize, raw_sz)
            if s.VirtualAddress <= ep < s.VirtualAddress + vs:
                ep_sec = (idx, s, nm, ent)
        meta["sections"] = secs
        if truncated:
            meta["truncated"] = True
            obj.errors.append("pe: section data extends beyond end of file (truncated)")

        low_names = [x["name"].lower() for x in secs]
        seen_labels = set()
        for nm in low_names:
            hit = SECTION_NAMES.get(nm)
            if not hit or hit[1] in seen_labels:
                continue
            kind, label, score = hit
            seen_labels.add(label)
            if kind == "upx":
                packed_hint = True
                ctx.detect(obj, det("Heur:PE.Packed.UPX", Confidence.LOW, 10, "UPX-packed executable", [nm]))
            elif kind == "packer":
                packed_hint = True
                ctx.detect(obj, det(f"Heur:PE.Packer.{label}", Confidence.LOW, score,
                                    f"Packed with {label} (section {nm})", [nm]))
            elif kind == "protector":
                packed_hint = True
                ctx.detect(obj, det(f"Heur:PE.Protector.{label}", Confidence.LOW, score,
                                    f"Protected with {label} (section {nm})", [nm]))
            elif kind == "virus":
                ctx.detect(obj, det(f"Heur:PE.Virus.{label}", Confidence.HIGH, score,
                                    f"Section {nm} added by the {label} file infector", [nm]))
            elif kind == "pua":
                ctx.detect(obj, det(f"Heur:PE.PUA.{label}", Confidence.MEDIUM, score,
                                    f"{label} bundler section", [nm], pua=True))
        odd = [x["name"] for x in secs if not x["name"] or any(ord(c) < 0x20 or ord(c) > 0x7E for c in x["name"])]
        if odd:
            ctx.detect(obj, det("Heur:PE.Section.OddName", Confidence.LOW, 5, "Empty or non-printable section names",
                                [repr(n) for n in odd]))
        rwx = [x["name"] for x in secs if x["flags"] == "RWX"]
        if rwx and not firmware:
            ctx.detect(obj, det("Heur:PE.Section.RWX", Confidence.LOW, 10,
                                "Section mapped readable, writable and executable (self-modifying/packed)", rwx))

        # ---- imports / exports ------------------------------------------------------
        funcs, dlls = imports_of(pe)
        fnames = {f for _, f in funcs}
        meta["imports"] = len(funcs)
        meta["import_dlls"] = sorted(set(d.lower() for d in dlls))[:64]
        exports = []
        try:
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols[:20000]:  # type: ignore[attr-defined]
                if sym.name:
                    exports.append(sym.name.decode("latin-1", "replace"))
        except Exception:  # noqa: BLE001
            pass
        meta["exports"] = len(exports)
        if any(e == "ReflectiveLoader" or e.startswith("_ReflectiveLoader@") or e.endswith("ReflectiveLoader")
               for e in exports):
            ctx.detect(obj, det("Heur:PE.ReflectiveDLL", Confidence.HIGH, 40,
                                "Exports ReflectiveLoader (reflective DLL injection payload: Meterpreter/Cobalt Strike)",
                                [e for e in exports if "ReflectiveLoader" in e][:3]))

        # dynamic API names (identifier tokens) = imports ∪ strings used with GetProcAddress
        tokens = set(_TOKEN_RE.findall(data, 0, min(size, TOKEN_BUDGET)))
        exp_set = set(exports)
        apis = {f for f in fnames if f in _API_ALL}
        for a in _API_ALL:
            if a.encode() in tokens and a not in exp_set:
                apis.add(a)

        def grp(g: str) -> list[str]:
            return [a for a in API_GROUPS[g] if a in apis]

        if not dotnet:
            self._api_rules(obj, ctx, grp)

        n_imp = len(funcs)
        has_ep = ep != 0
        if not dotnet and not is_dll and has_ep and n_imp == 0 and not firmware:
            ctx.detect(obj, det("Heur:PE.NoImports", Confidence.LOW, 10,
                                "Executable without an import table (resolves APIs manually / packed)"))
        elif not dotnet and 0 < n_imp <= 8 and any(f in fnames for f in API_GROUPS["getproc"]) and \
                any(f in fnames for f in API_GROUPS["loadlib"]):
            packed_hint = True
            ctx.detect(obj, det("Heur:PE.Imports.DynamicResolveOnly", Confidence.MEDIUM, 15,
                                "Tiny import table with LoadLibrary + GetProcAddress (APIs resolved at runtime)",
                                sorted(fnames)[:10]))

        # ---- entry point ---------------------------------------------------------------
        if has_ep and not dotnet:
            if ep_sec is None:
                if ep < oh.SizeOfHeaders:
                    ctx.detect(obj, det("Heur:PE.EntryPoint.OutsideSections", Confidence.MEDIUM, 20,
                                        "Entry point inside the PE headers", [hex(ep)]))
                else:
                    ctx.detect(obj, det("Heur:PE.EntryPoint.OutsideSections", Confidence.MEDIUM, 20,
                                        "Entry point outside every section", [hex(ep)]))
            else:
                idx, s, nm, ent = ep_sec
                if not s.Characteristics & (SCN_EXEC | SCN_CODE):
                    ctx.detect(obj, det("Heur:PE.EntryPoint.NonExecSection", Confidence.MEDIUM, 15,
                                        "Entry point in a non-executable section", [nm]))
                if len(pe.sections) > 1 and idx == len(pe.sections) - 1 and nm.lower() not in (".text", "code", ".code"):
                    packed_hint = True
                    ctx.detect(obj, det("Heur:PE.EntryPoint.LastSection", Confidence.LOW, 10,
                                        "Entry point in the last section (typical packer stub)", [nm]))
                raw_ep = ep - s.VirtualAddress + s.PointerToRawData
                if ep - s.VirtualAddress >= s.SizeOfRawData and s.Misc_VirtualSize > s.SizeOfRawData:
                    pass  # EP in the zero-filled tail (virtual-only) – decompressed at runtime; covered by packer rules
                elif raw_ep >= size and not truncated:
                    ctx.detect(obj, det("Heur:PE.EntryPoint.InOverlay", Confidence.MEDIUM, 25,
                                        "Entry point maps beyond the file's raw data", [hex(ep)]))

        # ---- entropy / packing -------------------------------------------------------
        hi = [x for x, s in zip(secs, pe.sections) if (s.Characteristics & (SCN_EXEC | SCN_CODE))
              and x["rsize"] >= 16384 and x["entropy"] >= (7.6 if fh.Machine in (0x1C0, 0x1C4) else 7.4) and not dotnet]  # .NET keeps resources in .text
        if hi:
            packed_hint = True
            few = not dotnet and n_imp <= 20
            ctx.detect(obj, det("Heur:PE.Packed.HighEntropy", Confidence.MEDIUM if few else Confidence.LOW,
                                25 if few else 15,
                                "Executable section with near-random content (compressed/encrypted code)",
                                [f"{x['name']} H={x['entropy']}" for x in hi]))

        # ---- TLS ---------------------------------------------------------------------
        tls_cb = 0
        try:
            tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
            if tls and tls.struct.AddressOfCallBacks:
                tls_cb = 1
        except Exception:  # noqa: BLE001
            pass
        meta["tls_callbacks"] = bool(tls_cb)
        if tls_cb:
            ctx.detect(obj, det("Heur:PE.TLSCallbacks", Confidence.LOW, 5 if packed_hint else 2,
                                "TLS callbacks run code before the entry point"))

        # ---- timestamp / checksum ----------------------------------------------------
        pdb, repro = debug_info(pe)
        meta["pdb"] = pdb
        ts = fh.TimeDateStamp
        if ts and ts > time.time() + 2 * 86400 and not repro:
            ctx.detect(obj, det("Heur:PE.Timestamp.Future", Confidence.LOW, 3, "Link timestamp lies in the future",
                                [_dt.datetime.fromtimestamp(ts, _dt.timezone.utc).isoformat()]))
        carved = bool(obj.meta.get("carved"))
        if oh.CheckSum and size <= (64 << 20) and not carved:
            calc = pe_checksum(data, oh.get_file_offset() + 0x40)
            meta["checksum_ok"] = calc == oh.CheckSum
            if calc != oh.CheckSum:
                drv = oh.Subsystem == 1
                ctx.detect(obj, det("Heur:PE.Checksum.Mismatch", Confidence.LOW, 10 if drv else 5,
                                    "PE checksum does not match the file (modified after linking)",
                                    [f"header={oh.CheckSum:#x} computed={calc:#x}"]))

        # ---- Authenticode ------------------------------------------------------------
        sec = security_dir(pe, size)
        meta["signed"] = bool(sec)
        if sec:
            try:
                ac = authenticode_check(data, pe, sec)
            except Exception as exc:  # noqa: BLE001
                ac = {"status": f"error {exc!r}"}
            meta["authenticode"] = {k: v for k, v in ac.items() if k != "appended"}
            meta["signers"] = ac.get("signers", [])
            if ac.get("status") == "digest-mismatch" and not carved:
                ctx.detect(obj, det("Heur:PE.Authenticode.HashMismatch", Confidence.MEDIUM, 25,
                                    "Embedded Authenticode digest does not match the file (modified after signing)",
                                    ac.get("signers", [])[:3]))
            if ac.get("appended"):
                off, ln = ac["appended"]
                ctx.detect(obj, det("Heur:PE.Authenticode.AppendedData", Confidence.LOW, 10,
                                    "Data hidden in the certificate table after the PKCS#7 signature",
                                    [f"{ln} bytes at {off:#x}"], offset=off))
                meta["cert_appended"] = [off, ln]

        # ---- Rich header ---------------------------------------------------------------
        try:
            ri = rich_info(data, pe.DOS_HEADER.e_lfanew)
        except Exception:  # noqa: BLE001
            ri = None
        if ri:
            meta["rich"] = ri
            if ri.get("valid") is False and ri.get("reason") != "no DanS":
                ctx.detect(obj, det("Heur:PE.RichHeader.Tampered", Confidence.MEDIUM, 15,
                                    "Rich header checksum mismatch (forged or transplanted header)",
                                    [f"key={ri.get('key')} computed={ri.get('computed')}"]))

        # ---- version info masquerading -----------------------------------------------------
        vi = version_strings(pe)
        if vi:
            meta["version_info"] = {k: vi[k] for k in ("CompanyName", "ProductName", "FileDescription",
                                                       "OriginalFilename", "InternalName", "FileVersion",
                                                       "LegalCopyright") if k in vi}
            self._masquerade(obj, ctx, vi, bool(sec), meta.get("signers") or [], pdb, ri, dotnet)

        # ---- PDB -----------------------------------------------------------------------
        if pdb:
            m = PDB_BAD.search(pdb)
            if m:
                ctx.detect(obj, det("Heur:PE.PDB.SuspiciousPath", Confidence.MEDIUM, 20,
                                    "Debug (PDB) path names a malware component", [pdb]))

        # ---- .NET --------------------------------------------------------------------
        if dotnet:
            self._dotnet(obj, ctx, pe, tokens, meta, bool(sec))

        # ---- strings ----------------------------------------------------------------------
        hits, text = string_hits(data, "pe", wide=True)
        tool = hits.labels("toolchain")
        if dotnet:
            tool.append(".NET")
        meta["toolchain"] = tool
        for t in tool:
            if t == "AutoIt":
                ctx.detect(obj, det("Heur:PE.AutoIt", Confidence.LOW, 5, "Compiled AutoIt script",
                                    hits.labels("toolchain")))
            else:
                ctx.detect(obj, det(f"Heur:PE.Toolchain.{t.replace(' ', '')}", Confidence.INFO, 0,
                                    f"Built with / packaged by {t}"))
        apply_rules(obj, ctx, "PE", hits, cap=runtime_cap(tool))
        onion_rule(obj, ctx, "PE", text, hits)

    # ----------------------------------------------------------------------------------
    @staticmethod
    def _api_rules(obj: ScanObject, ctx: ScanContext, grp) -> None:
        def fire(name, score, conf, desc, ev):
            ctx.detect(obj, det(f"Heur:PE.API.{name}", conf, score, desc, ev))

        if grp("open") and grp("alloc_remote") and grp("write_remote") and grp("remote_exec"):
            fire("ProcessInjection", 25, Confidence.MEDIUM, "Remote process memory write + remote thread/APC",
                 grp("open") + grp("alloc_remote") + grp("write_remote") + grp("remote_exec"))
        if grp("create_proc") and grp("unmap") and grp("write_remote") and grp("set_ctx") and grp("resume"):
            fire("ProcessHollowing", 35, Confidence.HIGH, "Process hollowing API sequence",
                 grp("create_proc") + grp("unmap") + grp("write_remote") + grp("set_ctx") + grp("resume"))
        if grp("hook") and grp("keystate") and grp("fgwin") and grp("wintext"):
            fire("Keylogger", 15, Confidence.LOW, "Keyboard hook + key state + foreground window title",
                 grp("hook") + grp("keystate") + grp("fgwin") + grp("wintext"))
        ad = grp("antidebug")
        if len(ad) >= 3:
            fire("AntiDebug", 10, Confidence.LOW, "Several anti-debugging APIs", ad)
        if grp("download") and grp("exec"):
            fire("DownloadExecute", 15, Confidence.LOW, "Downloads a file and executes it", grp("download") + grp("exec"))
        if grp("crypto") and grp("findfile") and grp("findnext") and grp("drives"):
            fire("RansomwareLike", 10, Confidence.LOW, "Encryption API + recursive file and drive enumeration",
                 grp("crypto") + grp("drives"))
        if grp("screen") and grp("dibits") and grp("compatbmp"):
            fire("ScreenCapture", 5, Confidence.LOW, "Screen capture APIs", grp("screen") + grp("dibits"))
        lsa = grp("lsa")
        if "LsaRetrievePrivateData" in lsa or "SamIConnect" in lsa or len(lsa) >= 2:
            fire("CredentialAccess", 15, Confidence.LOW, "LSA secrets / SAM / credential manager access", lsa)
        if grp("dup_token") and grp("impersonate"):
            fire("TokenManipulation", 5, Confidence.LOW, "Token duplication + impersonation",
                 grp("dup_token") + grp("impersonate"))

    @staticmethod
    def _masquerade(obj, ctx, vi: dict, signed: bool, signers: list[str], pdb: str | None, ri,
                    dotnet: bool = False) -> None:
        orig = (vi.get("OriginalFilename") or "").strip().lower()
        internal = (vi.get("InternalName") or "").strip().lower()
        company = (vi.get("CompanyName") or "").strip().lower()
        claims_sys = orig in SYSTEM_BINARIES or internal in SYSTEM_BINARIES or \
            (internal and internal + ".exe" in SYSTEM_BINARIES)
        # CompanyName-only claims: native, non-carved files (IL assemblies inside .NET bundles lose signatures)
        claims_ms = company in ("microsoft corporation", "microsoft corp.", "microsoft") and not dotnet and \
            not obj.meta.get("carved")
        if not (claims_sys or claims_ms):
            return
        if signed and any("microsoft" in s.lower() for s in signers):
            return
        # genuine catalog-signed Windows binaries: MS PDB name (no path) matching the file, valid Rich header
        genuine_pdb = bool(pdb) and "\\" not in pdb and "/" not in pdb
        if genuine_pdb and ri and ri.get("valid"):
            return
        if not claims_sys and signed:
            return  # third party signed file that merely mentions Microsoft in CompanyName
        ev = [f"{k}={vi[k]}" for k in ("OriginalFilename", "InternalName", "CompanyName") if k in vi]
        ev.append("signed by: " + (", ".join(signers[:2]) if signers else "nobody"))
        ctx.detect(obj, det("Heur:PE.Masquerade.VersionInfo", Confidence.MEDIUM, 25 if claims_sys else 15,
                            "Version info claims a Windows/Microsoft binary but the file is not Microsoft-signed", ev))

    @staticmethod
    def _dotnet(obj, ctx, pe, tokens: set[bytes], meta: dict, signed: bool) -> None:
        data = obj.data
        found = {}
        for needle, label, score in DOTNET_OBF:
            if label not in found and data.find(needle, 0, 64 << 20) >= 0:
                found[label] = score
        for label, score in found.items():
            ctx.detect(obj, det(f"Heur:PE.DotNet.Obfuscator.{label}", Confidence.LOW, score,
                                f".NET assembly protected with {label}", [label]))
        meta["dotnet_obfuscators"] = sorted(found)
        need = [b"Load", b"EntryPoint", b"Invoke"]
        if not signed and all(t in tokens for t in need) and ({b"GetManifestResourceStream", b"FromBase64String"} & tokens) and \
                ({b"CreateDecryptor", b"GZipStream", b"DeflateStream", b"RijndaelManaged", b"TripleDESCryptoServiceProvider"}
                 & tokens):
            ctx.detect(obj, det("Heur:PE.DotNet.ReflectiveLoad", Confidence.LOW, 15,
                                "Decrypts/decompresses an embedded assembly and invokes its entry point",
                                [t.decode() for t in need]))

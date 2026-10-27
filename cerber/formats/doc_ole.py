"""OLE2 / OLE1 helpers: embedded objects, CLSIDs, monikers, BIFF sheets, MSI names, PPT storages."""
from __future__ import annotations

import contextlib
import io
import re
import struct
import uuid
import zlib

try:
    from oletools.common.clsid import KNOWN_CLSIDS as _KNOWN
except Exception:  # noqa: BLE001
    _KNOWN = {}

KNOWN_CLSIDS: dict[str, str] = {k.upper(): v for k, v in _KNOWN.items()}

EQUATION_CLSIDS = {
    "0002CE02-0000-0000-C000-000000000046", "00021700-0000-0000-C000-000000000046",
    "0003000B-0000-0000-C000-000000000046", "0004A6B0-0000-0000-C000-000000000046",
}
PACKAGE_CLSID = "0003000C-0000-0000-C000-000000000046"
URL_MONIKER = "79EAC9E0-BAF9-11CE-8C82-00AA004BA90B"
FILE_MONIKER = "00000303-0000-0000-C000-000000000046"
SCRIPT_MONIKER = "06290BD3-48AA-11D2-8432-006008C3FBFC"
SOAP_MONIKER = "ECABB0C7-7F19-11D2-978E-0000F8757E2A"
HTA_CLSID = "3050F4D8-98B5-11CF-BB82-00AA00BDCE0B"
MONIKER_CLSIDS = {URL_MONIKER, SCRIPT_MONIKER, SOAP_MONIKER, HTA_CLSID,
                  "00000309-0000-0000-C000-000000000046"}


def clsid_bytes(s: str) -> bytes:
    return uuid.UUID(s).bytes_le


URL_MONIKER_B = clsid_bytes(URL_MONIKER)
FILE_MONIKER_B = clsid_bytes(FILE_MONIKER)
SCRIPT_MONIKER_B = clsid_bytes(SCRIPT_MONIKER)
SOAP_MONIKER_B = clsid_bytes(SOAP_MONIKER)
EQUATION_CLSIDS_B = {clsid_bytes(c) for c in EQUATION_CLSIDS}


def clsid_risk(clsid: str) -> tuple[str, str]:
    """-> (category, description); category in equation|moniker|activex_cve|known|unknown|''"""
    c = (clsid or "").upper().strip("{}")
    if not c or c == "00000000-0000-0000-0000-000000000000":
        return "", ""
    desc = KNOWN_CLSIDS.get(c, "")
    if c in EQUATION_CLSIDS:
        return "equation", desc or "Microsoft Equation Editor"
    if c in MONIKER_CLSIDS:
        return "moniker", desc
    if "CVE" in desc:
        return "activex_cve", desc
    if desc:
        return "known", desc
    return "unknown", ""


def parse_ole10native(data: bytes, package: bool = False) -> dict | None:
    """MS-OLEDS 2.3.6 OLENativeStream / Package -> {filename, src_path, temp_path, data}."""
    try:
        pos = 0
        if not package:
            if len(data) < 6:
                return None
            pos = 4
        pos += 2

        def zstr(p: int) -> tuple[str, int]:
            end = data.find(b"\x00", p, p + 4096)
            if end < 0:
                raise ValueError("unterminated string")
            return data[p:end].decode("latin-1", "replace"), end + 1

        label, pos = zstr(pos)
        src, pos = zstr(pos)
        pos += 8
        temp, pos = zstr(pos)
        if pos + 4 > len(data):
            return {"filename": label, "src_path": src, "temp_path": temp, "data": b"", "link": True}
        size = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        payload = data[pos:pos + size]
        # the unicode names (optional) follow the payload
        return {"filename": label, "src_path": src, "temp_path": temp, "data": payload, "link": False,
                "declared_size": size}
    except Exception:  # noqa: BLE001
        return None


def parse_compobj(data: bytes) -> list[str]:
    """\\x01CompObj -> [user type, clipboard format, progid] (best effort)."""
    out = []
    pos = 28
    try:
        for _ in range(3):
            if pos + 4 > len(data):
                break
            n = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if n in (0xFFFFFFFF, 0xFFFFFFFE):
                pos += 4
                out.append("")
                continue
            if n > 4096:
                break
            out.append(data[pos:pos + n].rstrip(b"\x00").decode("latin-1", "replace"))
            pos += n
    except Exception:  # noqa: BLE001
        pass
    return out


def find_monikers(data: bytes) -> list[tuple[str, str]]:
    """Find URL / file / script monikers in an \\x01Ole stream or OLE1 object -> [(kind, target)]."""
    out = []
    for kind, marker in (("url", URL_MONIKER_B), ("script", SCRIPT_MONIKER_B), ("soap", SOAP_MONIKER_B)):
        start = 0
        while len(out) < 20:
            i = data.find(marker, start)
            if i < 0:
                break
            start = i + 16
            if i + 20 <= len(data):
                n = struct.unpack_from("<I", data, i + 16)[0]
                s = data[i + 20:i + 20 + min(n, 8192)].decode("utf-16-le", "replace").split("\x00", 1)[0]
                out.append((kind, s))
    i = data.find(FILE_MONIKER_B)
    if i >= 0 and i + 22 <= len(data):
        n = struct.unpack_from("<I", data, i + 18)[0]
        s = data[i + 22:i + 22 + min(n, 4096)].split(b"\x00", 1)[0].decode("latin-1", "replace")
        out.append(("file", s))
    return out


# ------------------------------------------------------------------ Equation Editor (MTEF)

def equation_anomalies(data: bytes) -> list[str]:
    """Structural sanity checks on an Equation Native stream / OLE1 equation payload.

    Legitimate MTEF data has a 28-byte EQNOLEFILEHDR followed by an MTEF v2/3 header and
    records with short printable font names.  Returned strings describe what deviates.
    """
    out = []
    if len(data) < 33:
        return ["truncated Equation data"]
    cb_hdr = struct.unpack_from("<H", data, 0)[0]
    if cb_hdr != 0x1C:
        out.append(f"unexpected EQNOLEFILEHDR size {cb_hdr:#x}")
    cb_obj = struct.unpack_from("<I", data, 8)[0]
    if cb_obj > len(data) - cb_hdr + 16 or cb_obj == 0:
        out.append(f"MTEF size field {cb_obj} inconsistent with stream size {len(data)}")
    mtef = data[cb_hdr:cb_hdr + 5] if cb_hdr < len(data) else b""
    if mtef and mtef[0] not in (2, 3, 4, 5):
        out.append(f"unknown MTEF version {mtef[0]}")
    body = data[cb_hdr + 5:cb_hdr + 5 + 4096]
    # FONT records: tag 0x08, then tface, style, zero-terminated name
    for m in re.finditer(rb"\x08[\x00-\x10][\x00-\x10]([^\x00]{33,})", body):
        out.append(f"oversized font name in MTEF record ({len(m.group(1))} bytes)")
        break
    for m in re.finditer(rb"\x08[\x00-\x10][\x00-\x10]([^\x00]{4,32})\x00", body):
        if sum(1 for b in m.group(1) if b < 0x20 or b > 0x7e) > 2:
            out.append("non-printable font name in MTEF record")
            break
    return out


# ------------------------------------------------------------------ BIFF (xls)

def biff_sheets(wb: bytes) -> tuple[list[dict], list[str], list[str]]:
    """Parse BOUNDSHEET8, Lbl and SupBook records of the globals substream.
    -> ([{name, state, type, offset}], [defined names], [DDE links "server|topic"])"""
    sheets: list[dict] = []
    names: list[str] = []
    dde: list[str] = []
    pos, n = 0, len(wb)
    records = 0
    while pos + 4 <= n and records < 200_000:
        rtype, rlen = struct.unpack_from("<HH", wb, pos)
        body = wb[pos + 4:pos + 4 + rlen]
        pos += 4 + rlen
        records += 1
        if rtype == 0x0085 and len(body) >= 8:
            off, state, dt, cch, high = struct.unpack_from("<IBBBB", body)
            raw = body[8:8 + (cch * 2 if high & 1 else cch)]
            name = raw.decode("utf-16-le" if high & 1 else "latin-1", "replace")
            sheets.append({"name": name, "state": {0: "visible", 1: "hidden", 2: "very hidden"}.get(state & 3, "?"),
                           "type": {0: "worksheet", 1: "macro sheet", 2: "chart", 6: "vba module"}.get(dt, f"type {dt}"),
                           "offset": off})
        elif rtype == 0x0018 and len(body) >= 15:
            grbit, _key, cch = struct.unpack_from("<HBB", body)
            high = body[14]
            raw = body[15:15 + (cch * 2 if high & 1 else cch)]
            nm = raw.decode("utf-16-le" if high & 1 else "latin-1", "replace")
            if grbit & 0x20 and nm:
                nm = {"\x01": "Auto_Open", "\x02": "Auto_Close"}.get(nm[0], f"builtin#{ord(nm[0])}")
            names.append(nm)
        elif rtype == 0x01AE and len(body) >= 5:
            # SupBook: ctab, cch, virtPath; a DDE source is "server\x03topic"
            cch = struct.unpack_from("<H", body, 2)[0]
            if 0 < cch < 0x0401:
                high = body[4]
                raw = body[5:5 + (cch * 2 if high & 1 else cch)]
                vp = raw.decode("utf-16-le" if high & 1 else "latin-1", "replace")
                if "\x03" in vp:
                    server, topic = vp.split("\x03", 1)
                    dde.append(f"{server}|{topic}")
        elif rtype == 0x000A and sheets:   # EOF of globals substream
            break
    return sheets, names, dde


XLM_FUNC_RE = re.compile(
    r"(?i)\b(EXEC|CALL|REGISTER|REGISTER\.ID|URLDownloadToFile[AW]?|FORMULA(?:\.FILL|\.ARRAY)?|RUN|HALT|"
    r"CreateThread|VirtualAlloc|WriteProcessMemory|RtlCopyMemory|ShellExecute[AW]?|FOPEN|FWRITE(?:LN)?|"
    r"FILE\.DELETE|GET\.WORKSPACE|GET\.DOCUMENT|GET\.WINDOW|APP\.MAXIMIZE|SET\.NAME|EVALUATE|CHAR|"
    r"WAIT|ALERT|ON\.TIME|DIRECTORY|FILES)\s*\("
)
XLM_STRONG = {"exec", "call", "register", "register.id", "urldownloadtofile", "urldownloadtofilea",
              "urldownloadtofilew", "createthread", "virtualalloc", "writeprocessmemory", "rtlcopymemory",
              "shellexecute", "shellexecutea", "shellexecutew"}


def biff_formulas(wb: bytes) -> str:
    """Dump cell formulas of an xls workbook as text using oledump's plugin_biff (if present)."""
    try:
        from oletools.thirdparty.oledump.plugin_biff import cBIFF  # type: ignore
    except Exception:  # noqa: BLE001
        return ""
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            res = cBIFF(name=["Workbook"], stream=wb, options="-c -r LN").Analyze()
        return "\n".join(res)[:4 << 20]
    except Exception:  # noqa: BLE001
        return ""


# ------------------------------------------------------------------ MSI

_MSI_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"


def msi_stream_name(name: str) -> str:
    out = []
    for ch in name:
        c = ord(ch)
        if 0x3800 <= c < 0x4800:
            c -= 0x3800
            out.append(_MSI_CHARS[c & 0x3F])
            out.append(_MSI_CHARS[(c >> 6) & 0x3F])
        elif 0x4800 <= c < 0x4840:
            out.append(_MSI_CHARS[c - 0x4800])
        elif c == 0x4840:
            out.append("!")
        else:
            out.append(ch)
    return "".join(out)


# ------------------------------------------------------------------ PowerPoint 97-2003

def ppt_ole_storages(ppt_doc: bytes, limit: int = 64) -> list[bytes]:
    """Decompress ExOleObjStg compressed atoms (embedded OLE objects / VBA storage) of a PPT stream."""
    out = []
    marker = b"\x10\x00\x11\x10"
    start = 0
    while len(out) < limit:
        i = ppt_doc.find(marker, start)
        if i < 0:
            break
        start = i + 4
        if i + 12 > len(ppt_doc):
            break
        rec_len, usize = struct.unpack_from("<II", ppt_doc, i + 4)
        if rec_len < 4 or rec_len > len(ppt_doc) - i - 8 or usize > (256 << 20):
            continue
        try:
            d = zlib.decompressobj().decompress(ppt_doc[i + 12:i + 8 + rec_len], usize + 1)
        except zlib.error:
            continue
        if d:
            out.append(d)
            start = i + 8 + rec_len
    return out

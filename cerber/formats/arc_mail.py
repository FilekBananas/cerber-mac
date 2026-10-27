"""E-mail (.eml / .emlx / mbox) extraction: every text part and every attachment becomes a child."""
from __future__ import annotations

import email
import io
import re
import zipfile
from email import policy
from typing import Any

from ..core import Confidence, ScanContext, ScanObject
from .arc_common import (DISKIMAGE_EXT, NATIVE_EXEC_EXT, SCRIPT_EXT, Sink, clean_name, ext_of, harvest_passwords,
                         looks_executable_name, name_findings, vis)

MBOX_SPLIT = re.compile(rb"(?m)^From \S+[ \t]+[^\r\n]*\d{1,2}:\d{2}[^\r\n]*\r?\n")
MAX_MESSAGES = 20000

EMAIL_EXEC_EXT = (NATIVE_EXEC_EXT | SCRIPT_EXT) - {"bin", "class", "run", "elf", "inf"}
HTML_EXT = {"html", "htm", "xhtml", "shtml", "svg", "mht", "mhtml", "hta"}
ARCHIVE_PEEK_EXT = {"zip", "rar", "7z", "iso", "img", "cab", "ace", "arj", "gz", "tgz", "tar", "z", "bz2", "xz", "lzh",
                    "vhd", "dmg", "udf", "wim"}
EXEC_CTYPES = {"application/x-msdownload", "application/x-dosexec", "application/x-msdos-program",
               "application/x-executable", "application/x-sh", "application/x-bat", "application/x-msi",
               "application/x-ms-installer", "application/vnd.microsoft.portable-executable"}

_TAG_RE = re.compile(rb"<[^>]{0,2000}>")


def _split_mbox(data: bytes) -> list[bytes]:
    ms = list(MBOX_SPLIT.finditer(data))
    if not ms:
        return [data]
    out = []
    for i, m in enumerate(ms[:MAX_MESSAGES]):
        end = ms[i + 1].start() if i + 1 < len(ms) else len(data)
        out.append(data[m.end():end])
    return out


def _parse(raw: bytes):
    for pol in (policy.default, policy.compat32):
        try:
            return email.message_from_bytes(raw, policy=pol)
        except Exception:  # noqa: BLE001
            continue
    return None


def _peek_names(ctx: ScanContext, sink: Sink, payload: bytes, ext: str, tool: str | None) -> list[str]:
    """Member names of an archive attachment (without extracting anything)."""
    if payload[:4] == b"PK\x03\x04" or ext == "zip":
        try:
            return [z.orig_filename for z in zipfile.ZipFile(io.BytesIO(payload)).infolist()][:5000]
        except Exception:  # noqa: BLE001
            pass
    if tool and len(payload) <= (200 << 20):
        from .arc_cli import prepare_input, sz_list
        from .arc_common import safe_rmtree
        tmp = ScanObject(data=payload, display_path="attachment")
        path, d = prepare_input(ctx, tmp, ext or "bin", payload)
        try:
            lst = sz_list(tool, path, None, min(30.0, sink.budget.time_left()))
            if lst.listed and lst.type.lower() not in ("pe", "elf", "macho"):
                return [e.path for e in lst.entries if not e.is_dir][:5000]
        finally:
            safe_rmtree(d)
    return []


def extract_email(obj: ScanObject, ctx: ScanContext, sink: Sink, tool: str | None = None) -> None:
    data = obj.data
    limits = ctx.limits
    if obj.extension == "emlx":
        m = re.match(rb"\s*(\d{1,9})\s*\r?\n", data)
        if m:
            data = data[m.end():m.end() + int(m.group(1))]
    if data[:5] == b"From ":
        messages = _split_mbox(data)
        sink.fmt = "mbox" if len(messages) > 1 else "eml"
    else:
        messages = [data]
    multi = len(messages) > 1
    info: list[dict[str, Any]] = []
    body_idx = 0
    for mi, raw in enumerate(messages, 1):
        if sink.limit_reached():
            sink.skip("*", "max children reached")
            break
        msg = _parse(raw)
        if msg is None:
            obj.errors.append(f"email: message {mi} could not be parsed")
            continue
        pref = f"msg{mi}/" if multi else ""
        mi_info: dict[str, Any] = {}
        for h in ("from", "to", "subject", "date", "message-id", "reply-to", "return-path"):
            try:
                v = msg.get(h)
                if v:
                    mi_info[h] = str(v)[:300]
            except Exception:  # noqa: BLE001
                pass
        atts: list[str] = []
        try:
            parts = list(msg.walk())
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"email: walk failed: {exc}")
            parts = [msg]
        used: set[str] = set()
        for pi, part in enumerate(parts):
            try:
                if part.is_multipart():
                    continue
                ctype = (part.get_content_type() or "application/octet-stream").lower()
                try:
                    fname = part.get_filename()
                except Exception:  # noqa: BLE001
                    fname = None
                try:
                    disp = part.get_content_disposition()
                except Exception:  # noqa: BLE001
                    disp = None
                payload = part.get_payload(decode=True)
            except Exception as exc:  # noqa: BLE001
                obj.errors.append(f"email: part {pi} of message {mi}: {exc!r}")
                continue
            if payload is None:
                continue
            if isinstance(payload, str):
                payload = payload.encode("utf-8", "replace")
            if not payload:
                continue
            sink.members += 1
            is_body = ctype.startswith("text/") and not fname and disp != "attachment"
            if is_body:
                body_idx += 1
                sub = ctype.split("/", 1)[1]
                ext = {"html": "html", "plain": "txt", "calendar": "ics", "xml": "xml", "css": "css"}.get(sub, "txt")
                name = f"body-{body_idx}.{ext}"
                # 'password: xyz' hints for encrypted attachments
                text = payload if sub != "html" else _TAG_RE.sub(b" ", payload)
                hints = harvest_passwords(text[:40000].decode("utf-8", "replace"))
                if hints:
                    cur = obj.meta.setdefault("archive_passwords", [])
                    cur.extend(h for h in hints if h not in cur)
            else:
                if not fname:
                    sub = ctype.split("/", 1)[1] if "/" in ctype else "bin"
                    fname = f"part-{pi}.{re.sub(r'[^a-z0-9]+', '', sub)[:8] or 'bin'}"
                name = fname
                atts.append(fname)
                self_checks(sink, ctx, name, ctype, payload, tool)
            base = name
            k = 2
            while pref + base in used:
                base = f"{k}_{name}"
                k += 1
            used.add(pref + base)
            sink.add(pref + base, payload, {"size": len(payload), "content_type": ctype,
                                            "disposition": disp or "", "part": pi})
        mi_info["attachments"] = atts[:50]
        if len(info) < 50:
            info.append(mi_info)
    obj.meta["email"] = info[0] if len(info) == 1 else {"messages": info}


def self_checks(sink: Sink, ctx: ScanContext, name: str, ctype: str, payload: bytes, tool: str | None) -> None:
    """Attachment-level heuristics (name, type, contents of archive attachments)."""
    for det, conf, score, desc in name_findings(name, "Email", zip_like=True):
        sink.flag(det, conf, score, desc, [vis(name)[:200]])
    ext = ext_of(name)
    if ext in EMAIL_EXEC_EXT or ctype in EXEC_CTYPES:
        sink.flag("Heur:Email.ExecutableAttachment", Confidence.MEDIUM, 30,
                  "e-mail carries an executable/script attachment", [f"{vis(name)[:160]} ({ctype})"])
    elif ext in DISKIMAGE_EXT:
        sink.flag("Heur:Email.DiskImageAttachment", Confidence.LOW, 15,
                  "e-mail carries a disk image (used to bypass mark-of-the-web / mail filters)",
                  [f"{vis(name)[:160]} ({ctype})"])
    elif ext in HTML_EXT:
        sink.flag("Heur:Email.HtmlAttachment", Confidence.INFO, 5,
                  "e-mail carries an HTML attachment (common phishing vehicle)", [vis(name)[:160]])
    if ext in ARCHIVE_PEEK_EXT or payload[:4] in (b"PK\x03\x04", b"Rar!", b"7z\xbc\xaf"):
        try:
            names = _peek_names(ctx, sink, payload, ext, tool)
        except Exception:  # noqa: BLE001
            names = []
        bad = [n for n in names if looks_executable_name(n) and ext_of(n) in EMAIL_EXEC_EXT]
        if bad:
            sink.flag("Heur:Email.ArchivedExecutable", Confidence.MEDIUM, 20,
                      "archive attachment contains an executable/script", [f"{vis(name)[:80]} -> {vis(n)[:100]}"
                                                                            for n in bad[:5]])

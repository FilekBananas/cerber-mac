"""Windows shortcut (.lnk) analyzer.

Parses the Shell Link structure, reconstructs the command line the shortcut runs and
hands it back as a decoded child (lnk/cmdline.txt) so script analyzers and signature
engines see it. Flags LOLBin targets, download/encoded arguments, argument padding,
document-icon masquerading and payloads appended after the LNK structure.
"""
from __future__ import annotations

import re

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from ..formats import doc_lnk
from ..formats.doc_common import DOWNLOAD_RE, ENCODED_PS_RE, LOLBIN_RE, SCRIPT_EXTENSIONS, classify_payload, short
from . import register

LOLBINS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "wscript.exe", "cscript.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "msiexec.exe", "forfiles.exe",
    "conhost.exe", "schtasks.exe", "wmic.exe", "hh.exe", "cmstp.exe", "msbuild.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "odbcconf.exe", "pcalua.exe", "scriptrunner.exe", "msdt.exe", "bash.exe",
    "wsl.exe", "finger.exe", "ftp.exe", "syncappvpublishingserver.exe", "control.exe", "mavinject.exe",
    "presentationhost.exe", "ieexec.exe", "msxsl.exe", "cmdl32.exe", "expand.exe", "extrac32.exe",
    "replace.exe", "esentutl.exe", "xwizard.exe", "infdefaultinstall.exe", "diskshadow.exe", "tar.exe",
}
SUSP_ARGS_RE = re.compile(
    r"(?i)(\biex\b|invoke-expression|invoke-webrequest|frombase64string|-w(?:indowstyle)?\s+h(?:idden)?\b|"
    r"-nop\b|-noni\b|-ep\s+bypass|-exec(?:utionpolicy)?\s+bypass|javascript:|vbscript:|\bhttps?://|"
    r"\\\\[\w.\-]+@(?:ssl|\d+)\\|\bstart\s+/b\b|%comspec%|copy\s+/b|\bcertutil\b.*-decode|"
    r"\bscrobj\.dll\b|/i:https?|\bfindstr\b.*\.lnk|\bexpand\b.*\.cab|\btype\b.*\.lnk)")
DOC_ICON_RE = re.compile(r"(?i)(\.(pdf|docx?|xlsx?|pptx?|rtf|txt|jpe?g|png|gif|zip)\b|acrord32\.exe|acrobat\.exe|"
                         r"msedge\.exe|chrome\.exe|firefox\.exe|winword\.exe|excel\.exe|powerpnt\.exe|notepad\.exe|"
                         r"wordpad\.exe|explorer\.exe|imageres\.dll|shell32\.dll|moricons\.dll)")
SUSP_DIRS_RE = re.compile(r"(?i)(\\temp\\|%temp%|\\appdata\\|%appdata%|%localappdata%|\\programdata\\|"
                          r"\\users\\public\\|\\downloads\\)")


def _det(ctx, obj, name, conf, score, desc, ev=None):
    ctx.detect(obj, Detection(name, "heuristic", conf, score, desc, [short(e, 400) for e in (ev or [])][:20]))


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip().strip('"'))[-1].lower()


@register
class LNKAnalyzer(Analyzer):
    name = "lnk"
    order = 40

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype == "lnk"

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        try:
            lnk = doc_lnk.parse(obj.data)
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"lnk: {exc}")
            _det(ctx, obj, "Heur:LNK.Malformed", Confidence.LOW, 10, "Shell link header present but unparseable",
                 [str(exc)])
            return
        target = lnk.target
        args = lnk.arguments
        cmdline = lnk.command_line
        obj.meta["lnk"] = {
            "target": target, "arguments": short(args, 2000), "working_dir": lnk.working_dir,
            "icon": lnk.icon_location or lnk.icon_env, "icon_index": lnk.icon_index, "name": lnk.name,
            "relative_path": lnk.relative_path, "env_target": lnk.env_target, "machine_id": lnk.machine_id,
            "network_path": lnk.net_name, "show": doc_lnk.SHOW.get(lnk.show_command, lnk.show_command),
            "flags": lnk.flag_names, "target_size": lnk.file_size, "idlist": lnk.idlist_strings[:20],
        }
        if lnk.errors:
            obj.errors.extend(f"lnk: {e}" for e in lnk.errors)
        if cmdline:
            ctx.add_child(obj, cmdline.encode("utf-8", "replace"), "lnk/cmdline.txt", kind="decoded",
                          meta={"lnk_cmdline": True})

        base = _basename(target) if target else ""
        full = f"{target} {args}"
        lolbin = base in LOLBINS or bool(LOLBIN_RE.search(target))
        ext = base.rsplit(".", 1)[-1] if "." in base else ""
        if lolbin:
            _det(ctx, obj, "Heur:LNK.LOLBinTarget", Confidence.MEDIUM, 30 if args.strip() else 15,
                 "Shortcut launches a system interpreter / LOLBin", [cmdline])
        elif ext in SCRIPT_EXTENSIONS:
            _det(ctx, obj, "Heur:LNK.ScriptTarget", Confidence.MEDIUM, 25, "Shortcut launches a script file", [target])
        if args and (lolbin or LOLBIN_RE.search(args)):
            hits = sorted({m.group() for m in SUSP_ARGS_RE.finditer(args)} | {m.group() for m in DOWNLOAD_RE.finditer(args)})
            if hits:
                _det(ctx, obj, "Heur:LNK.SuspiciousArguments", Confidence.HIGH, 50,
                     "Shortcut command line downloads or runs hidden/obfuscated code", hits[:10] + [short(args, 300)])
            elif LOLBIN_RE.search(args):
                _det(ctx, obj, "Heur:LNK.ChainedCommand", Confidence.MEDIUM, 25,
                     "Shortcut arguments launch another interpreter", [short(args, 300)])
        if ENCODED_PS_RE.search(args):
            _det(ctx, obj, "Heur:LNK.EncodedCommand", Confidence.HIGH, 50, "Shortcut runs an encoded PowerShell command",
                 [ENCODED_PS_RE.search(args).group()[:200]])
        stripped = args.lstrip(" \t\r\n")
        pad = len(args) - len(stripped)
        if pad >= 50 or len(args) > 1024 or re.search(r"[ \t]{100,}|(?:\r?\n){5,}", args):
            _det(ctx, obj, "Heur:LNK.HiddenArguments", Confidence.MEDIUM, 30,
                 "Shortcut arguments are padded/oversized to hide them from the Properties dialog",
                 [f"{len(args)} chars, {pad} leading whitespace"])
        icon = lnk.icon_location or lnk.icon_env
        if icon and (lolbin or ext in SCRIPT_EXTENSIONS) and DOC_ICON_RE.search(icon):
            _det(ctx, obj, "Heur:LNK.IconMasquerade", Confidence.MEDIUM, 30,
                 "Shortcut to an interpreter/script disguised with a document or browser icon",
                 [f"icon={icon},{lnk.icon_index} target={target}"])
        if lolbin and lnk.show_command == 7:
            _det(ctx, obj, "Heur:LNK.Minimized", Confidence.LOW, 5, "Interpreter shortcut starts minimized", [cmdline])
        if re.match(r"^\s*(\\\\|//)", target) and (lolbin or ext in SCRIPT_EXTENSIONS or ext in ("exe", "dll", "cpl", "msi")):
            _det(ctx, obj, "Heur:LNK.RemoteTarget", Confidence.MEDIUM, 25,
                 "Shortcut executes a program from a network share / WebDAV", [target])
        if ext in SCRIPT_EXTENSIONS and SUSP_DIRS_RE.search(full):
            _det(ctx, obj, "Heur:LNK.UserWritableTarget", Confidence.LOW, 10,
                 "Shortcut runs a script from a user-writable directory", [target])

        # data appended after the LNK structure
        end = lnk.end_offset
        tail = obj.data[end:]
        if len(tail.strip(b"\x00")) >= 64:
            ftype, reason = classify_payload(tail)
            ctx.add_child(obj, tail, "lnk/appended.bin", kind="slice")
            obj.meta["lnk"]["appended_bytes"] = len(tail)
            _det(ctx, obj, "Heur:LNK.AppendedData", Confidence.MEDIUM if not reason else Confidence.HIGH,
                 25 if not reason else 40, "Data appended after the shortcut structure (embedded payload)",
                 [f"{len(tail)} bytes at offset {end} ({ftype})"])

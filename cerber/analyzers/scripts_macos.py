"""AppleScript / JXA (incl. compiled .scpt / .app osascript) and macOS stealer behaviour chains.

Compiled scripts (FasdUAS / JsOsaDAS) are turned into a pseudo-source by the deobf library so
the same rules apply. do-shell-script bodies are handed back as shell children AND folded into
this object's corpus, so a password prompt + keychain access + upload score as one stealer chain.
"""
from __future__ import annotations

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from ..deobf import applescript as _as
from . import register
from .scripts_common import (COMBOS, C, R, deobf_and_feed, emit, is_documentation, layer_signals, routed_lang,
                             scan_text)
from .scripts_shell import RULES as SHELL_RULES, STEALER_COMBOS

APPLE_RULES = [
    R("FakePasswordPrompt",
      r"display dialog[^\n]{0,240}(?:password|passcode|touch ?id|app ?store|icloud|unlock|credential|keychain)"
      r"[^\n]{0,240}(?:hidden answer|default answer)|"
      r"(?:password|passcode|unlock|credential)[^\n]{0,160}display dialog[^\n]{0,240}hidden answer", 30,
      "Fake password prompt (credential phishing)", "prompt,cred", need="display dialog"),
    # installers and helpers (e.g. the sudo-prompt applet bundled by Electron apps) legitimately
    # elevate via AppleScript; elevation only weighs in combined with a download or a fake prompt
    R("AdminPrivileges", r"do shell script[^\n]{0,200}with administrator privileges|"
      r"with administrator privileges", 5, "Requests administrator privileges", "exec,admin",
      need="administrator privileges"),
    R("DoShellScript", r"do shell script\b|run script\b", 0, "Runs a shell/AppleScript command", "exec",
      need="do shell script|run script"),
    R("Keystroke", r"tell application ['\"]?System Events['\"]?[^\n]{0,120}(?:keystroke|key code)", 10,
      "Synthesizes keystrokes (UI automation)", "exec", need="system events"),
    R("Clipboard", r"the clipboard\b|set the clipboard to\b", 5, "Reads/writes the clipboard", "clipboard",
      need="clipboard"),
    R("JxaObjC", r"ObjC\.import|\$\.NSString|Application\s*\([^)]{0,40}\)\.doShellScript|"
      r"\.currentApplication\s*\(\s*\)", 10, "JXA Objective-C bridge / doShellScript", "exec",
      need="objc.import|nsstring|doshellscript|currentapplication"),
]

OSA_COMBOS = [
    C("PromptAndShell", "prompt,exec", 15, "Fake password prompt followed by shell command execution",
      window=4000),
    C("AdminDownload", "admin,download", 20, "Downloads remote content and runs it with administrator privileges",
      window=1200),
]


@register
class AppleScriptAnalyzer(Analyzer):
    name = "applescript"
    order = 55

    def applies(self, obj: ScanObject) -> bool:
        if obj.size < 8 or obj.size > (64 << 20):
            return False
        if _as.is_compiled(obj.data[:8]):
            return True
        route = routed_lang(obj)
        if route is not None:
            return route == "applescript"
        if is_documentation(obj):
            return False
        return obj.ftype == "applescript" or obj.meta.get("script_lang") == "applescript"

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        lang = "applescript"
        if _as.is_compiled(obj.data[:8]):
            try:
                lang, source = _as.compiled_to_source(obj.data)
            except Exception as exc:  # noqa: BLE001
                obj.errors.append(f"applescript: compiled decode {exc!r}")
                return
            obj.meta["compiled_osa"] = lang
            # hand the reconstructed source back so ClamAV/YARA and the JS/AS rules rescan it
            ext = "js" if lang == "javascript" else "applescript"
            ctx.add_child(obj, source.encode("utf-8", "replace"), f"osa/decompiled.{ext}", kind="decoded",
                          meta={"script_lang": lang})
            text = source
        else:
            text = obj.text(4 << 20)
        if not text.strip():
            return
        res, corpus = deobf_and_feed(ctx, obj, text, lang)
        # shell rules catch `do shell script` / JXA doShellScript payloads embedded in the source
        hits = scan_text(corpus, APPLE_RULES + SHELL_RULES)
        emit(ctx, obj, "OSA", hits, STEALER_COMBOS + COMBOS + OSA_COMBOS)
        layer_signals(ctx, obj, "OSA", res.layers)

"""Developer-tool JSON configs that run commands automatically (supply-chain / "contagious interview" lures).

Many editor / agent / MCP configs execute a shell command with no user action: a VS Code task with
runOptions.runOn == "folderOpen" runs when the project is opened, an AI-agent SessionStart/tool hook runs
when the agent starts, an MCP server is launched when the client starts. A command that downloads, decodes
or executes remote code from such an auto-run slot is a supply-chain backdoor.

Every command string found in an auto-run slot is handed back as a shell child (so the shell rules run on
it too) and, when it fetches/decodes/executes code, reported:

    Heur:Config.VSCodeFolderOpenTask   45  folder-open task downloads/decodes/executes code
    Heur:Config.AgentHookCommand       40  AI-agent hook (session start / tool use) fetches and runs code
    Heur:Config.MCPServerShell         35  MCP server launched through a shell one-liner that fetches/decodes code

Only JSON files are considered. Legitimate tasks (npm run build, eslint, tsc, …) do not match the
download/decode/exec pattern and are not reported.
"""
from __future__ import annotations

import json
import re

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from . import register

MAX_JSON = 4 << 20

# remote fetch / decode / code-exec inside an auto-run command (shared shape with the npm install-hook rule)
_BAD_CMD = re.compile(
    r"(?i)\b(?:curl|wget|fetch)\b[^\n]{0,200}https?://|"
    r"(?<!\|)\|(?!\|)\s*(?:sudo\s+)?(?:bash|sh|zsh|node|python[0-9.]*|perl|ruby|osascript)(?![\w.-])|"
    r"(?:base64|base32)\s+(?:-d|-D|--decode)|\bxxd\s+-r|openssl\b[^\n]{0,40}\benc\b[^\n]{0,40}-d\b|/dev/tcp/|"
    r"python[0-9.]*\s+-c\b|osascript\b[^\n]{0,40}-e\b|powershell\b[^\n]{0,80}(?:-enc|-w\s+hidden|iex|downloadstring)|"
    r"node\s+-e\b[^\n]{0,200}(?:https?://|atob|child_process|Buffer\.from)|"
    r"\beval\s*\(\s*(?:atob|Buffer\.from|require)\b|require\s*\(\s*['\"]https?:")
_INTERP = re.compile(r"(?i)^(?:/[\w./-]*)?(?:ba|z|k)?sh$|^/bin/(?:ba|z|k)?sh$|^(?:ba|z|k)?sh$")
_MAX_CMDS = 64


def _as_command(cmd, args=None) -> str | None:
    """Flatten a command + optional args list into one string."""
    if isinstance(cmd, list):
        parts = [str(x) for x in cmd if isinstance(x, (str, int, float))]
    elif isinstance(cmd, str):
        parts = [cmd]
    else:
        return None
    if isinstance(args, list):
        parts += [str(x) for x in args if isinstance(x, (str, int, float))]
    s = " ".join(parts).strip()
    return s or None


def _iter_hook_commands(node, depth=0):
    """Yield command strings from agent "hooks" blocks: nested dicts/lists holding
    {"type": "command", "command": "..."} (Claude Code / Cursor / generic agent hook shape)."""
    if depth > 8:
        return
    if isinstance(node, dict):
        if node.get("type") == "command" and isinstance(node.get("command"), str):
            yield node["command"]
        for v in node.values():
            yield from _iter_hook_commands(v, depth + 1)
    elif isinstance(node, list):
        for v in node:
            yield from _iter_hook_commands(v, depth + 1)


@register
class ConfigAutorunAnalyzer(Analyzer):
    name = "config_autorun"
    order = 56

    def applies(self, obj: ScanObject) -> bool:
        # also accept a .json file mis-sniffed as a script because of script-like strings in its values
        return 2 <= obj.size < MAX_JSON and (
            obj.ftype == "json" or (obj.extension == "json" and obj.data[:512].lstrip()[:1] == b"{"))

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        text = obj.text(MAX_JSON)
        low = text.lower()
        # cheap pre-filter: only parse configs that could carry an auto-run slot
        if not any(k in low for k in ('"tasks"', '"hooks"', '"mcpservers"', "folderopen", "runoptions")):
            return
        try:
            doc = json.loads(text)
        except Exception:
            return
        if not isinstance(doc, dict):
            return
        n = 0

        def feed(cmd: str, tag: str) -> None:
            nonlocal n
            if n >= _MAX_CMDS:
                return
            n += 1
            ctx.add_child(obj, cmd.encode("utf-8", "replace"), f"config/{tag}{n}.sh", kind="decoded",
                          meta={"script_lang": "shell"})

        # ---- VS Code / editor tasks that run on folder open ----------------------------
        tasks = doc.get("tasks")
        if isinstance(tasks, list):
            for t in tasks:
                if not isinstance(t, dict):
                    continue
                run_on = str(((t.get("runOptions") or {}) if isinstance(t.get("runOptions"), dict) else {})
                             .get("runOn", "")).lower()
                auto = run_on == "folderopen"
                cmds = []
                base = _as_command(t.get("command"), t.get("args"))
                if base:
                    cmds.append(base)
                for plat in ("osx", "linux", "windows"):
                    pv = t.get(plat)
                    if isinstance(pv, dict):
                        c = _as_command(pv.get("command"), pv.get("args"))
                        if c:
                            cmds.append(c)
                for c in cmds:
                    feed(c, "task")
                    if auto and _BAD_CMD.search(c):
                        ctx.detect(obj, Detection(
                            "Heur:Config.VSCodeFolderOpenTask", "heuristic", Confidence.HIGH, 45,
                            "Editor task runs a download/decode/exec command automatically when the folder is opened",
                            [f"{t.get('label', 'task')}: {c[:200]}"]))

        # ---- AI-agent hooks (SessionStart / tool-use / …) ------------------------------
        hooks = doc.get("hooks")
        if hooks is not None:
            for c in list(_iter_hook_commands(hooks))[:_MAX_CMDS]:
                feed(c, "hook")
                if _BAD_CMD.search(c):
                    ctx.detect(obj, Detection(
                        "Heur:Config.AgentHookCommand", "heuristic", Confidence.HIGH, 40,
                        "Agent hook runs a download/decode/exec command automatically (session start / tool use)",
                        [c[:200]]))

        # ---- MCP servers launched through a shell one-liner ----------------------------
        servers = doc.get("mcpServers")
        if isinstance(servers, dict):
            for name, spec in list(servers.items())[:_MAX_CMDS]:
                if not isinstance(spec, dict):
                    continue
                cmd0 = spec.get("command")
                full = _as_command(cmd0, spec.get("args"))
                if not full:
                    continue
                feed(full, "mcp")
                shell_launch = isinstance(cmd0, str) and _INTERP.match(cmd0.strip())
                if shell_launch and _BAD_CMD.search(full):
                    ctx.detect(obj, Detection(
                        "Heur:Config.MCPServerShell", "heuristic", Confidence.HIGH, 35,
                        "MCP server is started through a shell one-liner that fetches/decodes code",
                        [f"{name}: {full[:200]}"]))

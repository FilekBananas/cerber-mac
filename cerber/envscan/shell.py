"""Shell startup files (zsh/bash/sh/fish), /etc/paths(.d) and the launchd user environment."""
from __future__ import annotations

import os
import re

from ..core import Confidence
from .model import Signal
from .patterns import classify_path, command_signals, expand, redact
from .util import EnvContext, lstat_info, read_text, run, safe_listdir

E = "Heur:Env.Shell"

USER_RC = (".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout", ".bash_profile", ".bashrc", ".bash_login",
           ".bash_logout", ".profile", ".kshrc", ".mkshrc", ".config/fish/config.fish", ".ssh/rc", ".xprofile")
SYSTEM_RC = ("/etc/zshrc", "/etc/zprofile", "/etc/zshenv", "/etc/zlogin", "/etc/zlogout", "/etc/profile",
             "/etc/bashrc", "/etc/zshrc_Apple_Terminal", "/etc/bashrc_Apple_Terminal", "/etc/ssh/sshrc",
             "/etc/csh.cshrc", "/etc/csh.login")
# large frameworks sourced from rc files: not followed (their code is not user configuration)
SKIP_SOURCES = re.compile(r"(?:oh-my-zsh\.sh|/\.oh-my-zsh/|/nvm\.sh|/conda\.sh|/\.p10k\.zsh|powerlevel10k|"
                          r"/\.iterm2_shell_integration|/google-cloud-sdk/|/\.fzf\.|/zsh-syntax-highlighting|"
                          r"/zsh-autosuggestions|/\.bun/_bun|/completion|/\.cargo/env|/\.ghcup/env|/\.local/bin/env|"
                          r"/sdkman-init\.sh|/asdf\.sh|/\.orbstack/shell/)")

LINE_RULES: tuple[tuple[str, int, Confidence, str, re.Pattern], ...] = (
    ("SudoHijack", 50, Confidence.HIGH, "przedefiniowuje sudo/su (przechwytywanie haseł)",
     re.compile(r"^\s*(?:alias\s+(?:sudo|su|doas)\s*=\s*(?!['\"]?sudo\s*['\"]?\s*$)|(?:function\s+)?(?:sudo|su)\s*\(\)\s*\{)")),
    ("DyldInsert", 45, Confidence.HIGH, "ustawia DYLD_INSERT_LIBRARIES (wstrzykiwanie kodu do każdego programu)",
     re.compile(r"^\s*(?:export\s+|setenv\s+|launchctl\s+setenv\s+)?DYLD_INSERT_LIBRARIES\b")),
    ("DyldEnv", 5, Confidence.LOW, "ustawia zmienne wyszukiwania bibliotek dyld",
     re.compile(r"^\s*(?:export\s+|setenv\s+)?DYLD_(?:LIBRARY_PATH|FALLBACK_LIBRARY_PATH|FRAMEWORK_PATH|FALLBACK_FRAMEWORK_PATH)\b")),
    ("PathHijack", 25, Confidence.MEDIUM, "stawia katalog tymczasowy lub ukryty na początku PATH",
     re.compile(r"^\s*(?:export\s+)?PATH\s*=\s*['\"]?(?:(?:/private)?/(?:tmp|var/tmp)|/Users/Shared|\.)(?:/[^:'\"]*)?:")),
    ("HistoryDisabled", 5, Confidence.LOW, "wyłącza historię powłoki (antyforensyka lub preferencja prywatności)",
     re.compile(r"^\s*(?:unset\s+HISTFILE|(?:export\s+)?HISTFILE\s*=\s*/dev/null|(?:export\s+)?HISTSIZE\s*=\s*0\b)")),
    ("SetuidShell", 50, Confidence.HIGH, "tworzy kopię powłoki z bitem setuid",
     re.compile(r"\bchmod\s+(?:u\+s|[2467][0-7]{3})\s+\S*(?:sh|bash|zsh)\b")),
)
HOOK_RX = re.compile(r"^\s*(?:(?:export\s+)?PROMPT_COMMAND\s*=|precmd\s*\(\)|preexec\s*\(\)|precmd_functions\+?=|"
                     r"preexec_functions\+?=|add-zsh-hook\s+(?:precmd|preexec|chpwd)|trap\s+.+\s+DEBUG\b)")
NET_RX = re.compile(r"\b(?:curl|wget|nc|ncat|socat|telnet)\b|/dev/tcp/|https?://")
SOURCE_RX = re.compile(r"^\s*(?:source|\.)\s+['\"]?([^\s'\";|&]+)")


def _scan_rc(ctx: EnvContext, path: str, home: str, depth: int, seen: set, files_out: list) -> None:
    if path in seen or len(seen) > 60:
        return
    seen.add(path)
    body = read_text(path, 1 << 20)
    if body is None:
        return
    st = lstat_info(path)
    files_out.append({"path": path, "lines": body.count("\n") + 1, "mtime": st.get("mtime"), "owner": st.get("owner")})
    sigs: list[Signal] = []
    hooks: list[str] = []
    sources: list[str] = []
    cont = ""
    for raw in body.splitlines():
        line = cont + raw
        if line.endswith("\\"):
            cont = line[:-1] + " "
            continue
        cont = ""
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        for name, score, conf, desc, rx in LINE_RULES:
            if rx.search(line):
                sigs.append(Signal(f"{E}.{name}", score, conf, f"{os.path.basename(path)}: {desc}", [redact(s)]))
        if HOOK_RX.search(line):
            hooks.append(redact(s, 160))
            if NET_RX.search(line):
                sigs.append(Signal(f"{E}.HookNetwork", 40, Confidence.HIGH,
                                   f"{os.path.basename(path)}: hook prompt/exec wykonuje aktywność sieciową", [redact(s)]))
        for sig in command_signals(line, E, os.path.basename(path), skip=("LaunchctlLoad",)):
            sigs.append(sig)
        m = SOURCE_RX.match(line)
        if m:
            src = expand(m.group(1).strip("'\""), home)
            if src.startswith("/") and "$" not in src:
                sources.append(src)
                ci = classify_path(src, home)
                if ci.has("tmp", "shared", "trash") or ci.has("hidden_file") and not ci.has("pkgmgr"):
                    if ci.has("tmp", "shared", "trash"):
                        sigs.append(Signal(f"{E}.SourceTemp", 35, Confidence.MEDIUM,
                                           f"{os.path.basename(path)} wczytuje (source) plik z lokalizacji tymczasowej/współdzielonej", [src]))
    rel = {}
    if hooks:
        rel["hooks"] = hooks[:10]
    if sources:
        rel["sources"] = sources[:20]
    ctx.add_finding("shell", f"Podejrzany plik startowy powłoki {path.replace(home, '~') if home else path}", path, sigs,
                    dict(rel, file=st))
    if sigs:
        ctx.add_target(path, "shell startup file with suspicious lines", 2)
    if depth < 1:
        for src in sources:
            if SKIP_SOURCES.search(src):
                continue
            if os.path.isfile(src) and os.path.getsize(src) < (1 << 20):
                _scan_rc(ctx, src, home, depth + 1, seen, files_out)


def collect_shell(ctx: EnvContext) -> None:
    ctx.progress("pliki startowe powłoki")
    files: list[dict] = ctx.inv("shell_files")
    seen: set[str] = set()
    for h in ctx.homes:
        for rel in USER_RC:
            p = os.path.join(h.home, rel)
            if os.path.isfile(p):
                _scan_rc(ctx, p, h.home, 0, seen, files)
        for d in (".config/fish/conf.d", ".oh-my-zsh/custom", ".zshrc.d", ".bashrc.d"):
            names, _ = safe_listdir(os.path.join(h.home, d))
            for n in names:
                p = os.path.join(h.home, d, n)
                if os.path.isfile(p) and n.endswith((".zsh", ".fish", ".sh", ".bash")):
                    _scan_rc(ctx, p, h.home, 1, seen, files)
    home0 = ctx.homes[0].home if ctx.homes else ""
    for p in SYSTEM_RC:
        if os.path.isfile(p):
            _scan_rc(ctx, p, home0, 1, seen, files)

    # PATH entries from /etc/paths and /etc/paths.d
    entries: list[tuple[str, str]] = []
    for f in ["/etc/paths"] + [os.path.join("/etc/paths.d", n) for n in safe_listdir("/etc/paths.d")[0]]:
        for line in (read_text(f) or "").splitlines():
            if line.strip() and not line.startswith("#"):
                entries.append((f, line.strip()))
    ctx.inventory["path_entries"] = [e[1] for e in entries]
    for f, e in entries:
        ci = classify_path(e.rstrip("/") + "/", home0)
        if ci.has("tmp", "shared", "trash", "varfolders") or e in (".", "./"):
            ctx.add_finding("shell", f"Niebezpieczny wpis PATH w {f}", f,
                            [Signal(f"{E}.PathHijack", 30, Confidence.MEDIUM,
                                    "systemowy PATH zawiera katalog tymczasowy/zapisywalny dla wszystkich", [e])], {"entry": e})
        elif ci.has("hidden") and not ci.has("pkgmgr"):
            ctx.add_finding("shell", f"Ukryty katalog w systemowym PATH ({f})", f,
                            [Signal(f"{E}.PathHidden", 20, Confidence.MEDIUM,
                                    "systemowy PATH zawiera ukryty katalog", [e])], {"entry": e})

    # launchd user-session environment (inherited by every GUI app)
    for var in ("DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"):
        r = run(["/bin/launchctl", "getenv", var], timeout=5)
        val = r.out.strip() if r.ok else ""
        if val:
            score = 50 if var == "DYLD_INSERT_LIBRARIES" else 15
            ctx.add_finding("shell", f"Środowisko sesji launchd ustawia {var}", f"launchctl getenv {var}",
                            [Signal(f"{E}.LaunchdEnvDyld", score, Confidence.HIGH if score >= 50 else Confidence.MEDIUM,
                                    f"{var} jest ustawione dla każdej aplikacji sesji logowania", [redact(val)])],
                            {"variable": var, "value": redact(val)})

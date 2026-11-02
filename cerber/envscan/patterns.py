"""Pure pattern logic shared by the live scanner and the file analyzers.

No filesystem access, no subprocesses: everything here works on strings so it
can be applied to a LaunchAgent on disk, one extracted from a pkg, a shell rc
line or a process command line alike.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from ..core import Confidence
from .model import Signal

# --------------------------------------------------------------------------- paths

TMP_PREFIXES = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/")
SHARED_PREFIXES = ("/Users/Shared/", "/private/Users/Shared/")
VARFOLDERS_PREFIXES = ("/var/folders/", "/private/var/folders/")
# Sealed system volume + SIP-protected Apple locations on the data volume.
APPLE_PREFIXES = ("/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/", "/usr/share/",
                  "/bin/", "/sbin/", "/Library/Apple/", "/private/var/db/com.apple.")
# Package managers: their binaries are ad-hoc/linker signed by design.
PKG_PREFIXES = ("/opt/homebrew/", "/usr/local/Cellar/", "/usr/local/opt/", "/usr/local/Homebrew/",
                "/usr/local/Caskroom/", "/opt/local/", "/nix/store/", "/nix/var/", "/opt/miniconda3/",
                "/opt/anaconda3/", "/opt/miniforge3/")
PKG_HOME_DIRS = (".cargo", ".rustup", ".pyenv", ".nvm", ".volta", ".bun", ".deno", ".asdf", ".rbenv",
                 ".sdkman", ".conda", ".juliaup", ".ghcup", ".dotnet", ".npm-global", ".foundry", ".go",
                 ".local", ".orbstack", ".lmstudio", ".ollama", ".docker", ".colima", ".lima", ".rd",
                 "miniconda3", "anaconda3", "miniforge3", "mambaforge", "homebrew", "go", ".pnpm",
                 ".gem", ".swiftpm", ".pub-cache", ".platformio", ".elan", ".opam", ".cabal", ".stack",
                 ".wasmtime", ".wasmer", ".moon", ".proto", ".rye", ".pixi", ".modular", ".mint")

# Hidden directories that legitimate developer tooling creates in $HOME (or inside projects).
KNOWN_DOT_DIRS = frozenset({
    ".local", ".config", ".cache", ".cargo", ".rustup", ".nvm", ".volta", ".pyenv", ".rbenv", ".asdf", ".bun",
    ".deno", ".sdkman", ".npm", ".npm-global", ".pnpm", ".pnpm-store", ".yarn", ".nix-profile", ".nix-defexpr",
    ".docker", ".orbstack", ".colima", ".lima", ".rd", ".lmstudio", ".ollama", ".codex", ".claude", ".cursor",
    ".cursor-server", ".vscode", ".vscode-insiders", ".vscode-server", ".vscode-shared", ".windsurf", ".zed",
    ".gem", ".m2", ".gradle", ".sbt", ".ivy2", ".conda", ".mamba", ".jenv", ".goenv", ".dotnet", ".oh-my-zsh",
    ".zinit", ".antigen", ".zplug", ".tmux", ".vim", ".emacs.d", ".pub-cache", ".android", ".swiftpm",
    ".cocoapods", ".dartServer", ".dart-tool", ".dart_tool", ".matplotlib", ".copilot", ".cline", ".continue",
    ".aider", ".kube", ".krew", ".terraform.d", ".tfenv", ".node-gyp", ".bin", ".venv", ".git", ".github",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".next", ".nuxt", ".expo", ".build",
    ".idea", ".fleet", ".eclipse", ".metadata", ".juliaup", ".julia", ".ghcup", ".cabal", ".stack", ".opam",
    ".elan", ".foundry", ".wasmtime", ".wasmer", ".moon", ".proto", ".rye", ".pixi", ".poetry", ".pipx",
    ".platformio", ".arduino15", ".espressif", ".spicetify", ".dropbox", ".dropbox-dist", ".gsutil",
    ".azure", ".aws", ".gcloud", ".oci", ".ssh", ".gnupg", ".password-store", ".fzf", ".oh-my-posh",
    ".starship", ".warp", ".iterm2", ".hammerspoon", ".chrome-cdp-data", ".chrome-cdp-profile",
    ".playwright", ".playwright-mcp", ".cache-loader", ".u2net", ".keras", ".nv", ".huggingface",
    ".ipython", ".jupyter", ".streamlit", ".modular", ".mint", ".localcode", ".gsd", ".planning",
    ".slack", ".zsh_sessions", ".cups", ".cmake", ".conan", ".conan2", ".vcpkg", ".xmake", ".bundle",
    ".app-store", ".store", ".vagrant.d", ".minikube", ".helm", ".pulumi", ".serverless", ".netlify",
    ".vercel", ".supabase", ".firebase", ".expo-shared", ".turbo", ".parcel-cache", ".svelte-kit",
    ".angular", ".ollama-models", ".lmstudio-home", ".cursor-tutor", ".openai", ".anthropic", ".gemini",
    ".qwen", ".ssh-agent", ".kiro", ".trae", ".augment", ".codeium", ".tabnine", ".sourcegraph", ".homebrew",
    ".linuxbrew", ".sdkman", ".jbang", ".coursier", ".nimble", ".rustup-home", ".cargo-home", ".uv", ".python_history",
})
_MKDTEMP_RX = re.compile(r"^\.(?:tmp|_tmp|temp)[A-Za-z0-9_.-]{0,16}$", re.I)

STANDARD_LIBRARY_DIRS = frozenset({
    "Application Support", "Caches", "Preferences", "Logs", "Containers", "Group Containers", "LaunchAgents",
    "Application Scripts", "Frameworks", "Keychains", "Mail", "Messages", "Safari", "Cookies", "WebKit",
    "Saved Application State", "HTTPStorages", "Developer", "Fonts", "Services", "Scripts", "Sounds",
    "Autosave Information", "Calendars", "Contacts", "Accounts", "Assistants", "Audio", "ColorPickers",
    "ColorSync", "Compositions", "Favorites", "FileProvider", "Input Methods", "Internet Plug-Ins",
    "Keyboard Layouts", "PreferencePanes", "Printers", "QuickLook", "Screen Savers", "Spotlight", "Metadata",
    "Mobile Documents", "PDF Services", "Passes", "Photos", "Reminders", "Sharing", "Shortcuts", "Suggestions",
    "Weather", "Biome", "CloudStorage", "DuetExpertCenter", "IdentityServices", "Intents", "Staging",
    "Trial", "PrivateCloudCompute", "StatusKit", "Daemon Containers", "Translation", "Dictionaries",
    "Application Support/", "Printers", "iTunes", "Music", "Parallels", "Python", "Java", "Google",
    "Mozilla", "Steam", "Updates", "Extensions", "SystemExtensions", "PrivilegedHelperTools", "Security",
    "LaunchDaemons", "Filesystems", "Receipts", "Image Capture", "Modem Scripts", "Perl", "Ruby", "Sandbox",
    "CoreMediaIO", "DirectoryServices", "Documentation", "OpenDirectory", "Graphics", "Widgets", "Video",
    "User Pictures", "Desktop Pictures", "Automator", "Workflows", "Components", "Contextual Menu Items",
    "Address Book Plug-Ins", "Bundles", "CoreAnalytics", "Managed Preferences", "Managed Installs",
})

_UUID_RX = re.compile(r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$", re.I)
_HEX_RX = re.compile(r"^[0-9a-f]{12,}$", re.I)


def looks_random(name: str) -> bool:
    """Heuristic for machine-generated names (UUIDs, hex, consonant soup, letter/digit mixes)."""
    n = name.lstrip(".")
    if "." in n and not _UUID_RX.match(n):
        n = n.split(".")[0] if len(n.split(".")[0]) >= 6 else n.replace(".", "")
    if len(n) < 6:
        return False
    if _UUID_RX.match(n) or _HEX_RX.match(n):
        return True
    if not re.fullmatch(r"[A-Za-z0-9_-]+", n):
        return False
    letters = [c for c in n if c.isalpha()]
    digits = sum(c.isdigit() for c in n)
    if len(n) >= 8 and letters:
        vowels = sum(c in "aeiouyAEIOUY" for c in letters)
        if len(letters) >= 7 and vowels / len(letters) < 0.15:
            return True
    trans = sum(1 for a, b in zip(n, n[1:]) if a.isdigit() != b.isdigit() and a.isalnum() and b.isalnum())
    if digits >= 3 and len(letters) >= 3 and trans >= 3:
        return True
    # mixed-case gibberish like "xKqPzTrW" (camelCase words are allowed: they contain vowels)
    upper_inner = sum(1 for c in n[1:] if c.isupper())
    if len(n) >= 8 and n.isalnum() and upper_inner >= 3 and letters and \
            sum(c in "aeiouAEIOU" for c in letters) / len(letters) < 0.15:
        return True
    return False


def expand(path: str, home: str | None = None) -> str:
    if not path:
        return path
    home = home or os.path.expanduser("~")
    if path.startswith("~/") or path == "~":
        path = home + path[1:]
    path = path.replace("$HOME", home).replace("${HOME}", home)
    return os.path.normpath(path) if path.startswith("/") else path


def is_apple_path(path: str) -> bool:
    if path.startswith("/usr/local/"):
        return False
    return path.startswith(APPLE_PREFIXES) or path.startswith("/System/Volumes/Preboot/Cryptexes/")


def is_pkg_manager_path(path: str, home: str | None = None) -> bool:
    if path.startswith(PKG_PREFIXES):
        return True
    m = re.match(r"^/(?:Users/[^/]+|var/root|private/var/root)/([^/]+)/", path)
    if m and m.group(1) in PKG_HOME_DIRS:
        return True
    if re.match(r"^/Users/[^/]+/Library/pnpm/", path):
        return True
    return "/node_modules/" in path or "/site-packages/" in path or "/.venv/" in path or "/venv/bin/" in path


def hidden_component(path: str) -> str | None:
    """First hidden path component that is not a well-known tooling directory."""
    parts = [p for p in path.split("/") if p]
    in_temp = path.startswith(TMP_PREFIXES + VARFOLDERS_PREFIXES)
    for p in parts:
        if p.startswith(".") and p not in (".", ".."):
            if p in KNOWN_DOT_DIRS or p.startswith("._"):
                return None  # whole subtree belongs to known tooling / AppleDouble
            if in_temp and _MKDTEMP_RX.match(p):
                continue     # mkdtemp()/tempfile naming (.tmpAbC123) inside a temp folder
            return p
    return None


@dataclass
class PathInfo:
    path: str
    tags: set

    def has(self, *tags: str) -> bool:
        return any(t in self.tags for t in tags)


def classify_path(path: str, home: str | None = None) -> PathInfo:
    p = expand(path, home)
    tags: set[str] = set()
    if not p.startswith("/"):
        tags.add("relative")
        return PathInfo(p, tags)
    if p.startswith(TMP_PREFIXES):
        tags.add("tmp")
    if p.startswith(SHARED_PREFIXES):
        tags.add("shared")
    if p.startswith(VARFOLDERS_PREFIXES):
        tags.add("varfolders")
        if "/AppTranslocation/" in p or "code_sign_clone" in p:
            tags.add("translocated")
    if is_apple_path(p):
        tags.add("apple")
    if is_pkg_manager_path(p, home):
        tags.add("pkgmgr")
    if "/.Trash/" in p or "/.Trashes/" in p:
        tags.add("trash")
    if p.startswith("/Volumes/"):
        tags.add("volume")
    hc = hidden_component(p)
    if hc and "trash" not in tags:
        tags.add("hidden")
        if os.path.basename(p).startswith(".") and not os.path.basename(p).startswith("._"):
            tags.add("hidden_file")
    m = re.match(r"^(?:/Users/[^/]+|/private/var/root|/var/root)?/Library/Application Support/([^/]+)/", p)
    if m and (looks_random(m.group(1)) or (m.group(1).startswith(".") and m.group(1) not in KNOWN_DOT_DIRS)):
        tags.add("random_appsupport")
    m = re.match(r"^(?:/Users/[^/]+|/private/var/root|/var/root)/Library/([^/]+)/", p)
    if m and m.group(1) not in STANDARD_LIBRARY_DIRS and looks_random(m.group(1)):
        tags.add("random_library")
    if re.match(r"^/Users/[^/]+/(Downloads|Desktop|Documents)/", p):
        tags.add("user_docs")
    if re.search(r"\.app/Contents/", p) or p.endswith(".app"):
        tags.add("app_bundle")
    return PathInfo(p, tags)


def path_signals(path: str, prefix: str, what: str = "program", home: str | None = None) -> list[Signal]:
    """Location-based indicators for an executable/script/library referenced by persistence."""
    info = classify_path(path, home)
    p = info.path
    out: list[Signal] = []
    if info.has("tmp"):
        out.append(Signal(f"{prefix}.TempPath", 50, Confidence.HIGH,
                          f"{what}: uruchamiany z katalogu tymczasowego", [p]))
    elif info.has("varfolders") and not info.has("translocated"):
        out.append(Signal(f"{prefix}.TempPath", 30, Confidence.MEDIUM,
                          f"{what}: uruchamiany z folderu tymczasowego użytkownika (/var/folders)", [p]))
    if info.has("shared"):
        out.append(Signal(f"{prefix}.SharedPath", 40, Confidence.MEDIUM,
                          f"{what}: uruchamiany z /Users/Shared (lokalizacja zapisywalna dla wszystkich)", [p]))
    if info.has("trash"):
        out.append(Signal(f"{prefix}.TrashPath", 45, Confidence.HIGH, f"{what}: uruchamiany z Kosza", [p]))
    if info.has("hidden_file"):
        out.append(Signal(f"{prefix}.HiddenFile", 35, Confidence.MEDIUM, f"{what}: plik ukryty", [p]))
    elif info.has("hidden"):
        out.append(Signal(f"{prefix}.HiddenPath", 30, Confidence.MEDIUM,
                          f"{what}: w ukrytym katalogu ({hidden_component(p)})", [p]))
    if info.has("random_appsupport"):
        out.append(Signal(f"{prefix}.RandomDir", 25, Confidence.MEDIUM,
                          f"{what}: w losowo wyglądającym folderze Application Support", [p]))
    elif info.has("random_library"):
        out.append(Signal(f"{prefix}.RandomDir", 20, Confidence.MEDIUM,
                          f"{what}: w losowo wyglądającym folderze ~/Library", [p]))
    if info.has("volume"):
        out.append(Signal(f"{prefix}.VolumePath", 25, Confidence.MEDIUM,
                          f"{what}: uruchamiany z zamontowanego woluminu", [p]))
    if info.has("user_docs"):
        out.append(Signal(f"{prefix}.UserDocsPath", 10, Confidence.LOW,
                          f"{what}: uruchamiany z Pobranych/Pulpitu/Dokumentów", [p]))
    return out


LOCATION_SIGNALS = ("TempPath", "SharedPath", "HiddenFile", "HiddenPath", "RandomDir", "VolumePath",
                    "UserDocsPath", "TrashPath")


def is_location_signal(sig: Signal) -> bool:
    return sig.name.rsplit(".", 1)[-1] in LOCATION_SIGNALS


# --------------------------------------------------------------------------- redaction

_SECRET_KV = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:api[_-]?key|token|secret|passw(?:or)?d|passwd|pwd|auth|bearer|credential|"
    r"private[_-]?key|access[_-]?key|session)[A-Z0-9_]*)(\s*[=:]\s*|\s+)(['\"]?)([^\s'\"]{4,})")
_URL_CRED = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")
_LONG_BLOB = re.compile(r"[A-Za-z0-9+/=_-]{48,}")
_HEADER = re.compile(r"(?i)(authorization:\s*(?:bearer|basic|token)?\s*)\S+")


def redact(text: str, limit: int = 240) -> str:
    """Strip secrets from a line before it goes into a report."""
    t = text.replace("\n", " ").replace("\r", " ")
    t = _URL_CRED.sub(r"\1***:***@", t)
    t = _HEADER.sub(r"\1***", t)
    t = _SECRET_KV.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}***", t)
    t = _LONG_BLOB.sub(lambda m: m.group(0)[:16] + f"…[{len(m.group(0))} chars]", t)
    t = t.strip()
    return t if len(t) <= limit else t[:limit] + "…"


# --------------------------------------------------------------------------- command content

_SH = r"(?:/usr/bin/|/bin/|/usr/local/bin/|/opt/homebrew/bin/)?(?:env\s+)?(?:ba|z|da|k|c|tc|fi)?sh\b"
_INTERP = r"(?:/usr/bin/|/bin/|/usr/local/bin/|/opt/homebrew/bin/)?(?:env\s+)?(?:python[\d.]*|perl|ruby|osascript|php|node|bun|deno)\b"
_FETCH = r"\b(?:curl|wget|fetch)\b"


@dataclass(frozen=True)
class CmdRule:
    name: str
    score: int
    confidence: Confidence
    description: str
    regexes: tuple
    pua: bool = False
    requires: tuple = ()      # additional regexes that must also match (anywhere)


def _rx(*pats: str) -> tuple:
    return tuple(re.compile(p, re.I | re.S) for p in pats)


CMD_RULES: tuple[CmdRule, ...] = (
    CmdRule("ReverseShell", 70, Confidence.HIGH, "konstrukcja reverse shell", _rx(
        r"/dev/(?:tcp|udp)/[\w.-]+/\d+",
        r"\bn(?:c|cat|etcat)\b[^\n|;]*\s-[a-z]*[ec]\s+/?\S*(?:sh|bash|zsh)\b",
        r"\b(?:ba|z)?sh\s+-i\s*[<>]&",
        r"\bsocat\b[^\n]*\bexec:",
        r"\bmkfifo\b[^\n]*\|\s*n(?:c|cat)\b",
        r"socket\.socket\([^\n]*\.connect\([^\n]*(?:dup2|pty\.spawn|subprocess)",
        r"\bpty\.spawn\(\s*['\"]/bin/(?:ba|z)?sh",
        r"perl\s+-e\s+['\"][^\n]*\bsocket\s*\([^\n]*exec",
        r"\bruby\s+-rsocket\b",
        r"\bphp\s+-r\s+['\"][^\n]*fsockopen",
    )),
    CmdRule("DownloadExec", 55, Confidence.HIGH, "pobiera kod i od razu go wykonuje", _rx(
        _FETCH + r"[^\n|;&]*\|\s*(?:sudo\s+)?(?:-\S+\s+)*" + _SH,
        _FETCH + r"[^\n|;&]*\|\s*(?:sudo\s+)?" + _INTERP,
        r"(?:\beval|\bsource|(?:^|[;&|]\s*)\.|" + _SH + r"\s+-c|" + _INTERP + r"\s+-[ce])\s*[\"']?\s*\$\(\s*" + _FETCH,
        r"(?:\bsource|(?:^|[;&|]\s*)\.)\s+<\(\s*" + _FETCH,
        r"\bdo shell script\b[^\n]*" + _FETCH + r"[^\n]*\|\s*" + _SH,
        _FETCH + r"[^\n;&|]*\s-o\s*['\"]?(?:/private)?/(?:tmp|var/tmp|Users/Shared)/\S+[^\n]{0,80}?(?:;|&&)\s*"
        r"(?:chmod\s+\+?[0-7x+]+\s+\S+\s*(?:;|&&)\s*)?(?:open\s|(?:/private)?/(?:tmp|var/tmp|Users/Shared)/|"
        + _SH + r"|" + _INTERP + r")",
        r"(?:urlopen|urllib\.request\.urlopen|requests\.get)\([^\n]*\)[^\n]*\.(?:read|text|content)[^\n]*\bexec\(",
        r"\bexec\([^\n]*(?:urlopen|requests\.get)\(",
    )),
    CmdRule("EncodedExec", 50, Confidence.HIGH, "dekoduje zakodowany ładunek i wykonuje go", _rx(
        r"(?:base64\s+(?:-d|-D|--decode|-di)\b|\bb64decode\b|\batob\(|openssl\s+(?:enc\s+)?[^\n|;]*-(?:base64|a)\b[^\n|;]*-d\b)"
        r"[^\n]*(?:\|\s*(?:sudo\s+)?(?:" + _SH + r"|" + _INTERP + r")|\bexec\s*\(|\beval\b|\bsource\b|\bmarshal\.loads)",
        r"(?:\beval\b|\bexec\s*\(|\|\s*" + _SH + r")[^\n]*(?:base64\s+(?:-d|-D|--decode)|\bb64decode\b|\batob\()",
        r"echo\s+['\"]?[A-Za-z0-9+/=]{60,}['\"]?\s*\|\s*base64\s+(?:-d|-D|--decode)",
        r"openssl\s+enc\s+[^\n]*-aes-256-cbc[^\n]*-d[^\n]*\|\s*(?:" + _SH + r"|" + _INTERP + r")",
    )),
    CmdRule("PasswordPrompt", 55, Confidence.HIGH, "fałszywe okno hasła (wyłudzanie danych logowania)", _rx(
        r"display dialog[^\n]{0,300}?(?:password|passcode|hasło|passwort|contraseña|mot de passe)[^\n]{0,300}?hidden answer",
        r"display dialog[^\n]{0,300}?hidden answer\s+(?:true|yes)[^\n]{0,300}?(?:password|passcode)",
    )),
    CmdRule("CredentialCheck", 50, Confidence.HIGH, "weryfikuje wykradzione hasło przez dscl authonly", _rx(
        r"\bdscl\s+(?:\.|/Local/Default|localhost)\s+-authonly\b",
    )),
    CmdRule("KeychainDump", 40, Confidence.MEDIUM, "zrzuca zawartość pęku kluczy", _rx(
        r"\bsecurity\s+dump-keychain\b[^\n]*-d",
        r"\bchainbreaker\b",
        r"\bcp\s+[^\n]*login\.keychain(?:-db)?\s+(?:/private)?/(?:tmp|var/tmp|Users/Shared)",
    )),
    CmdRule("Miner", 60, Confidence.HIGH, "koparka kryptowalut", _rx(
        r"\b(?:xmrig|xmr-stak|minerd|cpuminer|ccminer|nbminer|lolminer|t-rex|nanominer|srbminer|cgminer|bfgminer)\b",
        r"--donate-level\b",
        r"\bstratum\+(?:tcp|ssl|tls)://",
        r"(?:\s-a|--algo)[= ](?:randomx|rx/0|cryptonight|cn/r|kawpow|ethash|ghostrider)\b",
    ), pua=True),
    CmdRule("GatekeeperDisable", 35, Confidence.MEDIUM, "wyłącza Gatekeeper", _rx(
        r"\bspctl\s+(?:--master-disable|--global-disable|--disable)\b",
        r"\bdefaults\s+write\s+com\.apple\.LaunchServices\s+LSQuarantine\s+-bool\s+(?:NO|false)",
    )),
    CmdRule("QuarantineStrip", 20, Confidence.MEDIUM, "usuwa atrybut kwarantanny (obejście Gatekeepera)", _rx(
        r"\bxattr\s+(?:-[a-z]*\s+)*-?[a-z]*[dc][a-z]*\s+(?:-[a-z]+\s+)*com\.apple\.quarantine",
        r"\bxattr\s+-[a-z]*c[a-z]*r?\s+['\"]?/",
    )),
    CmdRule("TempChmodExec", 30, Confidence.MEDIUM, "nadaje plikowi w katalogu tymczasowym prawo wykonywania", _rx(
        r"\bchmod\s+(?:\+x|[0-7]*[1357][0-7]{0,2}|a\+x|u\+x|755|777)\s+['\"]?(?:/private)?/(?:tmp|var/tmp|Users/Shared)/",
    )),
    CmdRule("KillTerminal", 25, Confidence.MEDIUM, "zamyka Terminal (ukrywa wykonanie ClickFix/stealera)", _rx(
        r"\bkillall\s+(?:-\S+\s+)*Terminal\b",
        r"\bosascript\s+-e\s+['\"]?tell application \"Terminal\" to (?:quit|close)",
    )),
    CmdRule("Exfil", 45, Confidence.HIGH, "wysyła archiwum z katalogu tymczasowego", _rx(
        r"\bcurl\b[^\n]*(?:-F|--form)\s*['\"]?[\w-]*=@['\"]?(?:/private)?/(?:tmp|var/tmp|Users/Shared)/",
        r"\bcurl\b[^\n]*(?:-T|--upload-file|--data-binary)\s*['\"]?@?(?:/private)?/(?:tmp|var/tmp)/[^\s'\"]+\.(?:zip|tar|gz|7z)",
    )),
    CmdRule("HiddenBackground", 25, Confidence.MEDIUM, "uruchamia w tle ukryty/tymczasowy ładunek", _rx(
        r"\b(?:nohup|setsid|screen\s+-dm\S*|disown)\b[^\n]*(?:(?:/private)?/(?:tmp|var/tmp)/|/Users/Shared/|/\.[a-z0-9][\w-]*/[^\s]*\.(?:sh|py|js|bin)\b)",
    )),
    CmdRule("RawIPFetch", 20, Confidence.MEDIUM, "pobiera z surowego adresu IP", _rx(
        _FETCH + r"\s[^\n]*https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/",
    )),
    CmdRule("EncodedData", 10, Confidence.LOW, "dekoduje dane base64", _rx(
        r"base64\s+(?:-d|-D|--decode)\b", r"\bb64decode\(",
    )),
    CmdRule("InlineAppleScript", 10, Confidence.LOW, "uruchamia wbudowany AppleScript z dostępem do powłoki", _rx(
        r"\bosascript\s+(?:-l\s+JavaScript\s+)?-e\b[^\n]*(?:do shell script|doShellScript)",
    )),
    CmdRule("LaunchctlLoad", 10, Confidence.LOW, "ładuje zadanie launchd", _rx(
        r"\blaunchctl\s+(?:load|bootstrap|submit)\b",
    )),
)

# rules that make the lower "EncodedData"/"InlineAppleScript" ones redundant
_SUPERSEDES = {"EncodedExec": ("EncodedData",), "DownloadExec": ("RawIPFetch",),
               "PasswordPrompt": ("InlineAppleScript",)}


def command_signals(text: str, prefix: str, where: str = "command", max_len: int = 200_000,
                    skip: tuple = ()) -> list[Signal]:
    """Apply CMD_RULES to a command line / script body."""
    if not text:
        return []
    t = text[:max_len]
    hits: dict[str, Signal] = {}
    for rule in CMD_RULES:
        if rule.name in skip:
            continue
        for rx in rule.regexes:
            m = rx.search(t)
            if m:
                if rule.requires and not all(r.search(t) for r in rule.requires):
                    continue
                start = max(0, m.start() - 40)
                snippet = redact(t[start:m.end() + 40], 200)
                hits[rule.name] = Signal(f"{prefix}.{rule.name}", rule.score, rule.confidence,
                                         f"{where}: {rule.description}", [snippet], rule.pua)
                break
    for strong, weak in _SUPERSEDES.items():
        if strong in hits:
            for w in weak:
                hits.pop(w, None)
    return list(hits.values())


# --------------------------------------------------------------------------- interpreters

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish"}
INTERPRETERS = SHELLS | {"python", "perl", "ruby", "node", "php", "osascript", "tclsh", "pwsh", "lua",
                         "deno", "bun", "osacompile", "swift"}
INLINE_FLAGS = {"osascript": ("-e",), "python": ("-c",), "perl": ("-e", "-E"), "ruby": ("-e",),
                "node": ("-e", "--eval", "-p", "--print"), "php": ("-r",), "pwsh": ("-c", "-Command",
                "-EncodedCommand", "-e", "-enc"), "lua": ("-e",), "deno": ("eval",), "bun": ("-e", "--eval"),
                "tclsh": (), "swift": ("-e",)}


def interpreter_of(path: str) -> str | None:
    base = os.path.basename(path or "")
    base = re.sub(r"(?:[\d.]+|-[\d.]+)$", "", base)  # python3.12 -> python, perl5.30 -> perl
    if base == "Python":        # macOS framework launcher: …/Python.framework/…/Python.app/Contents/MacOS/Python
        base = "python"
    return base if base in INTERPRETERS else None


@dataclass
class CommandInfo:
    exe: str
    args: list
    interpreter: str | None = None
    inline_code: str | None = None
    script: str | None = None       # script file passed to an interpreter


def analyze_command(argv: list[str]) -> CommandInfo:
    """Understand `/usr/bin/env python3 -c ...`, `/bin/sh -c ...`, `osascript -e ...`, `bash script.sh`."""
    argv = [a for a in argv if isinstance(a, str)]
    if not argv:
        return CommandInfo("", [])
    i = 0
    exe = argv[0]
    # /usr/bin/env [-i] [VAR=val ...] prog ...
    if os.path.basename(exe) == "env":
        i = 1
        while i < len(argv) and (argv[i].startswith("-") or ("=" in argv[i] and not argv[i].startswith("/"))):
            i += 1
        if i >= len(argv):
            return CommandInfo(exe, argv)
    prog = argv[i]
    rest = argv[i + 1:]
    interp = interpreter_of(prog)
    info = CommandInfo(prog, argv[i:], interp)
    if not interp:
        return info
    if interp in SHELLS:
        for j, a in enumerate(rest):
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
                info.inline_code = " ".join(rest[j + 1:j + 2]) if j + 1 < len(rest) else ""
                return info
            if a.startswith("-"):
                continue
            info.script = a
            return info
        return info
    flags = INLINE_FLAGS.get(interp, ())
    codes: list[str] = []
    j = 0
    while j < len(rest):
        a = rest[j]
        if a in flags and j + 1 < len(rest):
            codes.append(rest[j + 1])
            j += 2
            continue
        if a.startswith("-"):
            if interp == "python" and a in ("-m",) and j + 1 < len(rest):
                break  # python -m module
            if interp == "osascript" and a in ("-l", "-s") and j + 1 < len(rest):
                j += 2
                continue
            j += 1
            continue
        if not codes:
            info.script = a
        break
    if codes:
        info.inline_code = "\n".join(codes)
    return info

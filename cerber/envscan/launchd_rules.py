"""launchd / persistence-plist heuristics shared by the live scanner (envscan.persistence)
and the file-level analyzer (cerber.analyzers.plist_persistence).

Pure logic: works on an already-parsed plist dict plus the path it came from.
Live-only checks (does the binary exist, is it signed, is it writable) are done
by the caller on top of `JobAnalysis.program`.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from ..core import Confidence
from .model import Signal
from .patterns import (analyze_command, classify_path, command_signals, expand, is_apple_path, looks_random,
                       path_signals, redact)

P = "Heur:Launchd"

TRIGGER_KEYS = ("RunAtLoad", "KeepAlive", "StartInterval", "StartCalendarInterval", "WatchPaths",
                "QueueDirectories", "StartOnMount", "MachServices", "Sockets", "LaunchEvents", "LaunchOnlyOnce")

# scopes: user_agent | global_agent | global_daemon | system | app_bundle | submitted | file
SYSTEM_SCOPES = ("system",)

# Where Apple's own device / developer disk images put their daemons: the legacy DeveloperDiskImage.dmg is
# mounted at /Developer on the device, personalized DDIs and cryptexes under /System/Developer and
# /private/preboot/Cryptexes, internal builds under /AppleInternal. None of these can be created on a Mac
# (sealed, read-only root volume), so they only count as Apple locations for a plist found INSIDE a
# container (disk image / package), never for a job installed on this Mac (envscan keeps is_apple_path).
APPLE_IMAGE_PREFIXES = ("/Developer/", "/System/Developer/", "/System/Cryptexes/", "/AppleInternal/",
                        "/usr/appleinternal/", "/private/preboot/Cryptexes/")


def is_apple_image_path(path: str | None) -> bool:
    """Program location of an Apple (device) disk image. Temp / user / Application Support paths never are."""
    return bool(path) and path.startswith(APPLE_IMAGE_PREFIXES) and "/../" not in path


# --------------------------------------------------------------------------- IOCs
# (family, label regex, program/path regex). Sources: Objective-See Mac malware reports,
# SentinelOne / Moonlock write-ups. Label + path match = 80, one of them = 60.
IOCS: tuple[tuple[str, str | None, str | None], ...] = (
    ("EvilQuest", r"^com\.apple\.questd$", r"/AppQuest/com\.apple\.questd$"),
    ("CloudMensis", r"^com\.apple\.WindowServer$", r"/Library/Application Support/com\.apple\.WindowServer/WindowServer$"),
    ("DazzleSpy", r"^com\.apple\.softwareupdate$", r"/\.local/softwareupdate$"),
    ("Keydnap", r"^com\.apple\.iCloud\.sync\.daemon$", r"/icloudsyncd$"),
    ("Proton", r"^com\.apple\.xpcd$", r"/Library/Application Support/\.xpcd/"),
    ("SilverSparrow", r"^init_verx$", r"(?:/verx_updater/verx\.sh|^/tmp/agent\.sh)$"),
    ("AtomicStealer.Backdoor", r"^com\.finder\.helper$", r"^/(?:Users/[^/]+|var/root)/\.(?:helper|agent)$"),
    ("MacMa", r"^com\.UserAgent\.va$", r"/Library/Preferences/UserAgent/lib/UserAgent$"),
    ("Dummy", r"^com\.startup$", r"^/var/root/script\.sh$"),
    ("FruitFly", r"^com\.client\.client$", r"^/(?:Users/[^/]+|var/root)/\.client$"),
    ("Coldroot", r"^com\.apple\.audio\.driver$", r"/com\.apple\.audio\.driver\.app/"),
    ("Mokes", None, r"/Library/(?:App Store/storeuserd|com\.apple\.spotlight/SpotlightHelper|Dock/com\.apple\.dock\.cache|"
                    r"Skype/SkypeHelper|Google/Chrome/nacld|Firefox/Profiles/profiled)$"),
    ("WindTail", None, r"/Library/Final_Presentation\.app/"),
)
_IOC_RX = [(fam, re.compile(l) if l else None, re.compile(p) if p else None) for fam, l, p in IOCS]

# Adware/PUA product names that show up in labels, program paths and bundle ids.
ADWARE_NAME_RX = re.compile(
    r"(?i)(?:genieo|installmac|vsearch|conduit\.|spigot|search[\s_-]?baron|search[\s_-]?marquis|crossrider|mughthesec|"
    r"pcvark|advanced[\s_-]?mac[\s_-]?cleaner|mackeeper|zeobit|macbooster|weknow\.|bundlore|shlayer|pirrit|adload|"
    r"mybrowserhelper|safefinder|operatorsearch|searchpulse|chumsearch|smartsearchnow|trovi|mplayerx)")
# Adload: com.<CamelCaseWords>.<agent|system|service|...> pointing into a hidden/uuid App Support folder.
ADLOAD_LABEL_RX = re.compile(r"^com\.(?:[A-Z][a-z0-9]+){2,5}\.(?:agent|system|service|update|helper|daemon)$")
ADLOAD_PATH_RX = re.compile(
    r"/Library/Application Support/\.[0-9A-Za-z-]{8,}/|/Services/com\.[A-Za-z]+\.helper/|"
    r"/Library/Application Support/[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/")


# --------------------------------------------------------------------------- job model

@dataclass
class JobInfo:
    label: str | None
    program: str | None              # what launchd will execute (resolved, ~ expanded)
    args: list[str]
    run_at_load: bool = False
    keep_alive: Any = None
    env: dict = field(default_factory=dict)
    user_name: str | None = None
    triggers: list[str] = field(default_factory=list)
    disabled: bool = False
    bundle_program: str | None = None

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "program": self.program,
            "arguments": [redact(a, 300) for a in self.args[:20]],
            "run_at_load": self.run_at_load,
            "keep_alive": bool(self.keep_alive) if not isinstance(self.keep_alive, dict) else "conditional",
            "env_keys": sorted(self.env)[:20],
            "user_name": self.user_name,
            "triggers": self.triggers,
            "disabled": self.disabled,
        }


def is_launchd_job(d: Any) -> bool:
    if not isinstance(d, dict):
        return False
    pa = d.get("ProgramArguments")
    has_prog = isinstance(d.get("Program"), str) or (isinstance(pa, list) and pa and isinstance(pa[0], str)) \
        or isinstance(d.get("BundleProgram"), str)
    return bool(has_prog) and (isinstance(d.get("Label"), str) or any(k in d for k in TRIGGER_KEYS))


def parse_job(d: dict, home: str | None = None, bundle_root: str | None = None) -> JobInfo:
    args = [a for a in (d.get("ProgramArguments") or []) if isinstance(a, str)] \
        if isinstance(d.get("ProgramArguments"), list) else []
    program = d.get("Program") if isinstance(d.get("Program"), str) else None
    bundle_program = d.get("BundleProgram") if isinstance(d.get("BundleProgram"), str) else None
    if not program and bundle_program:
        program = os.path.join(bundle_root, bundle_program) if bundle_root else bundle_program
    if not program and args:
        program = args[0]
    if program:
        program = expand(program, home)
    env = d.get("EnvironmentVariables") if isinstance(d.get("EnvironmentVariables"), dict) else {}
    return JobInfo(
        label=d.get("Label") if isinstance(d.get("Label"), str) else None,
        program=program,
        args=args,
        run_at_load=d.get("RunAtLoad") is True,
        keep_alive=d.get("KeepAlive"),
        env={str(k): str(v) for k, v in env.items()},
        user_name=d.get("UserName") if isinstance(d.get("UserName"), str) else None,
        triggers=[k for k in TRIGGER_KEYS if k in d],
        disabled=d.get("Disabled") is True,
        bundle_program=bundle_program,
    )


@dataclass
class JobAnalysis:
    job: JobInfo
    signals: list[Signal]
    program: str | None               # executable to check on a live system
    script: str | None = None         # script file passed to an interpreter
    inline_code: str | None = None    # bash -c / osascript -e payload
    interpreter: str | None = None
    paths: list[str] = field(default_factory=list)   # every absolute path worth scanning


def scope_for_path(path: str | None) -> str:
    if not path:
        return "file"
    p = path
    if p.startswith(("/System/Library/", "/Library/Apple/System/Library/")):
        return "system"
    if re.search(r"^/(?:Users/[^/]+|var/root|private/var/root)/Library/LaunchAgents/", p):
        return "user_agent"
    if p.startswith("/Library/LaunchAgents/"):
        return "global_agent"
    if p.startswith("/Library/LaunchDaemons/"):
        return "global_daemon"
    if re.search(r"\.app/Contents/Library/(?:LaunchAgents|LaunchDaemons)/", p):
        return "app_bundle"
    return "file"


def _ioc_signals(label: str | None, paths: list[str]) -> list[Signal]:
    out = []
    for fam, lrx, prx in _IOC_RX:
        lm = bool(lrx and label and lrx.search(label))
        pm = next((p for p in paths if prx and prx.search(p)), None)
        if lm or pm:
            score = 80 if (lm and (pm or prx is None)) or (pm and lrx is None) else 60
            ev = [f"label={label}"] if lm else []
            if pm:
                ev.append(f"path={pm}")
            out.append(Signal(f"{P}.IOC.{fam}", score, Confidence.HIGH,
                              f"pasuje do znanej persystencji {fam} ({'etykieta i ścieżka' if lm and pm else 'etykieta' if lm else 'ścieżka'})",
                              ev))
    return out


def _adware_signals(label: str | None, paths: list[str]) -> list[Signal]:
    out = []
    blob = " ".join([label or ""] + paths)
    m = ADWARE_NAME_RX.search(blob)
    if m:
        out.append(Signal(f"{P}.Adware.KnownName", 45, Confidence.MEDIUM,
                          f"odwołuje się do znanej nazwy adware/PUA '{m.group(0)}'", [redact(blob, 200)], pua=True))
    if label and ADLOAD_LABEL_RX.match(label):
        if any(ADLOAD_PATH_RX.search(p) for p in paths):
            out.append(Signal(f"{P}.Adware.Adload", 60, Confidence.HIGH,
                              "etykieta w stylu Adload wskazująca na ukryty folder/UUID w Application Support",
                              [label] + paths[:1], pua=True))
        else:
            out.append(Signal(f"{P}.Adware.AdloadLabel", 15, Confidence.LOW,
                              "etykieta CamelCase w stylu Adload (com.<Słowa>.agent|system|service)", [label], pua=True))
    return out


def analyze_job(d: dict, plist_path: str | None = None, scope: str | None = None, home: str | None = None,
                bundle_root: str | None = None, embedded: bool = False) -> JobAnalysis:
    """Static heuristics for one launchd job definition.

    embedded: the plist was found inside a container (disk image, package, archive) rather than installed on
    this Mac; programs in Apple device-image locations (APPLE_IMAGE_PREFIXES) then count as Apple's own."""
    scope = scope or scope_for_path(plist_path)

    def apple_loc(p: str | None) -> bool:
        return bool(p) and (is_apple_path(p) or (embedded and is_apple_image_path(p)))

    if bundle_root is None and plist_path:
        m = re.match(r"^(.*?\.app)/Contents/Library/", plist_path)
        if m:
            bundle_root = m.group(1)
    job = parse_job(d, home, bundle_root)
    sigs: list[Signal] = []
    argv = ([job.program] + job.args[1:]) if job.program else list(job.args)
    cmd = analyze_command(argv)
    program = job.program
    paths: list[str] = []
    if program and program.startswith("/"):
        paths.append(program)
    script = None
    if cmd.script:
        s = expand(cmd.script, home)
        if s.startswith("/"):
            script = s
            paths.append(s)
    # absolute path arguments (scripts, dylibs, payloads passed as parameters)
    for a in job.args[1:]:
        a2 = expand(a, home) if a.startswith(("~", "/", "$HOME")) else ""
        if a2.startswith("/") and a2 not in paths and re.search(r"\.(?:sh|command|py|pl|rb|js|scpt|app|dylib|bin|so)$|/\.",
                                                              a2):
            paths.append(a2)

    if scope in SYSTEM_SCOPES:
        # sealed/SIP-protected: only structural anomalies are interesting
        if program and program.startswith("/") and not apple_loc(program):
            sigs.append(Signal(f"{P}.SystemJobNonSystemBinary", 40, Confidence.HIGH,
                               "systemowe zadanie launchd Apple uruchamia program spoza zapieczętowanego woluminu systemowego",
                               [program]))
        if "DYLD_INSERT_LIBRARIES" in job.env:
            sigs.append(Signal(f"{P}.DyldInsert", 50, Confidence.HIGH,
                               "zadanie systemowe wstrzykuje bibliotekę przez DYLD_INSERT_LIBRARIES", [job.env["DYLD_INSERT_LIBRARIES"]]))
        return JobAnalysis(job, sigs, program, script, cmd.inline_code, cmd.interpreter, paths)

    # --- location of the executable / script
    seen_loc: set[str] = set()
    for p, what in ([(program, "program")] if program else []) + ([(script, "skrypt")] if script else []):
        if not p or not p.startswith("/"):
            continue
        for s in path_signals(p, P, what, home):
            if s.name not in seen_loc:
                seen_loc.add(s.name)
                sigs.append(s)
    if program and not program.startswith("/") and not job.bundle_program:
        sigs.append(Signal(f"{P}.RelativeProgram", 10, Confidence.LOW,
                           "program nie ma ścieżki bezwzględnej (szukany przez PATH)", [program]))

    # --- inline interpreter code
    if cmd.interpreter and cmd.inline_code is not None:
        code = cmd.inline_code
        sigs.append(Signal(f"{P}.InlineScript", 8, Confidence.LOW,
                           f"uruchamia wbudowany kod {cmd.interpreter}", [redact(code, 200)]))
        sigs.extend(command_signals(code, f"{P}.Cmd", "wbudowane polecenie launchd"))
        # absolute paths used inside the inline code (e.g. sh -c "~/.x/run &")
        for m in re.finditer(r"(?:(?<=[\s'\";(=])|^)((?:~|/)[^\s'\";|&<>()]+)", code):
            ip = expand(m.group(1), home)
            if ip.startswith("/") and ip not in paths and len(paths) < 20:
                paths.append(ip)
                for s in path_signals(ip, P, "ścieżka we wbudowanym kodzie", home):
                    if s.name not in seen_loc and not s.name.endswith("UserDocsPath"):
                        seen_loc.add(s.name)
                        sigs.append(s.scaled(0.8))
    else:
        sigs.extend(command_signals(" ".join(job.args), f"{P}.Cmd", "wiersz poleceń launchd"))
    if any(s.name.startswith(f"{P}.Cmd.") and s.score >= 45 for s in sigs) and \
            (job.run_at_load or job.keep_alive or "StartInterval" in job.triggers or "StartCalendarInterval" in job.triggers
             or "WatchPaths" in job.triggers):
        sigs.append(Signal(f"{P}.PersistentPayload", 20, Confidence.HIGH,
                           "podejrzane polecenie jest automatycznie uruchamiane ponownie przez launchd", []))

    # --- label checks
    label = job.label
    fname = os.path.basename(plist_path) if plist_path else ""
    if label and label.lower().startswith("com.apple."):
        if program and program.startswith("/") and not apple_loc(program):
            sigs.append(Signal(f"{P}.AppleMasquerade", 45, Confidence.HIGH,
                               "używa etykiety Apple (com.apple.*), ale uruchamia program nie od Apple",
                               [f"label={label}", f"program={program}"]))
        elif cmd.interpreter and (cmd.inline_code is not None or (script and not apple_loc(script))) \
                and scope not in SYSTEM_SCOPES:
            sigs.append(Signal(f"{P}.AppleMasqueradeScript", 45, Confidence.HIGH,
                               "używa etykiety Apple (com.apple.*), ale uruchamia ładunek powłoki/interpretera",
                               [f"label={label}", redact(" ".join(argv), 200)]))
        elif embedded and is_apple_image_path(program):
            pass  # an Apple device image's own daemon (e.g. DeveloperDiskImage /Developer/usr/bin/debugserver)
        elif scope in ("user_agent", "global_agent", "global_daemon"):
            sigs.append(Signal(f"{P}.AppleLabelOutsideSystem", 5, Confidence.LOW,
                               "zadanie com.apple.* zainstalowane poza /System", [label]))
    if fname.startswith(".") and fname.endswith(".plist"):
        sigs.append(Signal(f"{P}.HiddenPlist", 35, Confidence.MEDIUM, "plik plist launchd jest ukryty", [fname]))
    if label and fname.endswith(".plist") and scope != "app_bundle":
        stem = fname[:-6].lstrip(".")
        if stem != label:
            sigs.append(Signal(f"{P}.LabelMismatch", 5, Confidence.LOW,
                               "nazwa pliku plist nie zgadza się z jego Label", [f"{fname} vs {label}"]))
    if label:
        last = [c for c in label.split(".") if c]
        if last and (looks_random(last[-1]) or (len(last) == 1 and looks_random(label))) and \
                not re.search(r"\d+\.\d+$", label):
            sigs.append(Signal(f"{P}.RandomLabel", 15, Confidence.LOW, "losowo wyglądająca etykieta zadania", [label]))
    elif scope != "file":
        sigs.append(Signal(f"{P}.NoLabel", 5, Confidence.LOW, "zadanie nie ma Label", []))

    # --- behaviour
    if job.run_at_load and job.keep_alive is True:
        sigs.append(Signal(f"{P}.AlwaysOn", 5, Confidence.LOW, "RunAtLoad + KeepAlive (stale działa, uruchamiany ponownie)", []))
    if "DYLD_INSERT_LIBRARIES" in job.env:
        lib = job.env["DYLD_INSERT_LIBRARIES"]
        sc = 15 if is_apple_path(lib) else 50
        sigs.append(Signal(f"{P}.DyldInsert", sc, Confidence.HIGH if sc >= 50 else Confidence.MEDIUM,
                           "wstrzykuje bibliotekę do zadania przez DYLD_INSERT_LIBRARIES", [lib]))
        if lib.startswith("/"):
            paths.append(expand(lib, home))
    other_dyld = [k for k in job.env if k.startswith("DYLD_") and k != "DYLD_INSERT_LIBRARIES"]
    if other_dyld:
        sigs.append(Signal(f"{P}.DyldEnv", 10, Confidence.LOW, "ustawia zmienne środowiskowe dyld", other_dyld))
    if isinstance(d.get("Program"), str) and job.args:
        a0 = job.args[0]
        if os.path.basename(a0) != os.path.basename(d["Program"]) and (is_apple_path(a0) or a0.startswith("com.apple")):
            sigs.append(Signal(f"{P}.Argv0Spoof", 30, Confidence.MEDIUM,
                               "argv[0] podszywa się pod inny program (Apple) niż uruchamiany",
                               [f"Program={d['Program']}", f"argv0={a0}"]))
    if scope == "global_agent" and job.user_name == "root":
        pass  # agents ignore UserName; not interesting

    sigs.extend(_ioc_signals(label, paths))
    sigs.extend(_adware_signals(label, paths))
    return JobAnalysis(job, sigs, program, script, cmd.inline_code, cmd.interpreter, paths)


# --------------------------------------------------------------------------- other persistence plists

@dataclass
class PlistAnalysis:
    kind: str                                  # launchd | info_plist | loginwindow | emond | none
    signals: list[Signal]
    meta: dict
    inline_codes: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    job: JobAnalysis | None = None


def analyze_plist(d: Any, path: str | None = None, scope: str | None = None, home: str | None = None,
                  embedded: bool = False) -> PlistAnalysis:
    """Dispatch on the kind of persistence-relevant plist and apply the matching rules
    (embedded: found inside a container, see analyze_job)."""
    if is_launchd_job(d):
        ja = analyze_job(d, path, scope, home, embedded=embedded)
        codes = [ja.inline_code] if ja.inline_code and len(ja.inline_code) >= 16 else []
        return PlistAnalysis("launchd", ja.signals, ja.job.to_dict(), codes, ja.paths, ja)
    sigs: list[Signal] = []
    meta: dict = {}
    paths: list[str] = []
    if isinstance(d, dict):
        # application Info.plist: LSEnvironment is applied to the app by LaunchServices
        lsenv = d.get("LSEnvironment")
        if isinstance(lsenv, dict):
            meta["LSEnvironment"] = sorted(str(k) for k in lsenv)[:20]
            lib = lsenv.get("DYLD_INSERT_LIBRARIES")
            if isinstance(lib, str):
                sigs.append(Signal("Heur:Plist.LSEnvironmentDyld", 45, Confidence.HIGH,
                                   "Info.plist wstrzykuje bibliotekę przez LSEnvironment DYLD_INSERT_LIBRARIES", [lib]))
                if lib.startswith("/"):
                    paths.append(lib)
                    sigs.extend(s.scaled(0.6) for s in path_signals(lib, "Heur:Plist", "wstrzyknięta biblioteka", home))
            elif any(str(k).startswith("DYLD_") for k in lsenv):
                sigs.append(Signal("Heur:Plist.LSEnvironmentDyldVar", 10, Confidence.LOW,
                                   "Info.plist ustawia zmienne dyld przez LSEnvironment",
                                   [k for k in lsenv if str(k).startswith("DYLD_")]))
        # loginwindow hooks (deprecated, run as root at every login)
        hooks = {k: d[k] for k in ("LoginHook", "LogoutHook") if isinstance(d.get(k), str)}
        if hooks:
            meta["hooks"] = hooks
            for k, v in hooks.items():
                sigs.append(Signal("Heur:Plist.LoginHook", 30, Confidence.MEDIUM,
                                   f"skonfigurowano loginwindow {k} (przestarzała persystencja roota)", [v]))
                vp = expand(v, home)
                if vp.startswith("/"):
                    paths.append(vp)
                    sigs.extend(path_signals(vp, "Heur:Plist", f"skrypt {k}", home))
        auto = d.get("AutoLaunchedApplicationDictionary")
        if isinstance(auto, list):
            items = [a.get("Path") for a in auto if isinstance(a, dict) and isinstance(a.get("Path"), str)]
            meta["auto_launched"] = items[:50]
            for it in items:
                paths.append(expand(it, home))
                sigs.extend(path_signals(expand(it, home), "Heur:Plist", "element logowania", home))
    # emond rules: list of dicts with "actions"
    if isinstance(d, list) and d and all(isinstance(x, dict) for x in d) and any("actions" in x for x in d):
        cmds = []
        for rule in d:
            for act in rule.get("actions") or []:
                if isinstance(act, dict) and str(act.get("type", "")).lower() == "runcommand":
                    cmd = act.get("command")
                    argv = [cmd] + [a for a in (act.get("arguments") or []) if isinstance(a, str)]
                    cmds.append(" ".join(str(c) for c in argv if c))
        if cmds:
            meta["emond_commands"] = [redact(c) for c in cmds[:10]]
            sigs.append(Signal("Heur:Plist.EmondRunCommand", 30, Confidence.MEDIUM,
                               "reguła emond wykonuje polecenie (persystencja przez monitor zdarzeń)", meta["emond_commands"][:3]))
            for c in cmds:
                sigs.extend(command_signals(c, "Heur:Plist.Cmd", "polecenie emond"))
            return PlistAnalysis("emond", sigs, meta, [c for c in cmds if len(c) >= 16], paths)
    kind = "info_plist" if "LSEnvironment" in meta else "loginwindow" if ("hooks" in meta or "auto_launched" in meta) \
        else "none"
    return PlistAnalysis(kind, sigs, meta, [], paths)


def signal_classification(sig: Signal) -> str:
    """For callers that want to dampen location signals for trusted binaries."""
    tail = sig.name.rsplit(".", 1)[-1]
    return "location" if tail in ("TempPath", "SharedPath", "HiddenFile", "HiddenPath", "RandomDir",
                                  "VolumePath", "UserDocsPath", "TrashPath") else "other"


__all__ = ["APPLE_IMAGE_PREFIXES", "IOCS", "JobInfo", "JobAnalysis", "PlistAnalysis", "analyze_job", "analyze_plist",
           "classify_path", "is_apple_image_path", "is_launchd_job", "parse_job", "scope_for_path",
           "signal_classification"]

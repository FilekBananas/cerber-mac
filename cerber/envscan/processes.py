"""Running processes: executable location & signature, command lines, parent/child chains."""
from __future__ import annotations

import os
import re
import time
from collections import defaultdict

from ..core import Confidence
from .model import Signal
from .patterns import analyze_command, classify_path, command_signals, is_apple_path, path_signals, redact
from .live import script_signals
from .provenance import TRUSTED, name_signals, origin, origin_signals, quarantine_events
from .util import EnvContext

P = "Heur:Env.Process"

APPLE_DAEMON_NAMES = frozenset({
    "launchd", "kernel_task", "WindowServer", "loginwindow", "Finder", "Dock", "SystemUIServer", "ControlCenter",
    "mds", "mds_stores", "mdworker", "mdworker_shared", "mdsync", "mdbulkimport", "cfprefsd", "distnoted", "trustd",
    "securityd", "syspolicyd", "XprotectService", "XProtect", "XProtectRemediator", "MRT", "softwareupdated",
    "softwareupdate", "coreaudiod", "bluetoothd", "airportd", "configd", "notifyd", "opendirectoryd", "sharingd",
    "rapportd", "identityservicesd", "cloudd", "bird", "nsurlsessiond", "apsd", "powerd", "logd", "syslogd",
    "kextd", "kernelmanagerd", "amfid", "sandboxd", "taskgated", "tccd", "usernoted", "UserEventAgent",
    "fseventsd", "diskarbitrationd", "hidd", "coreservicesd", "lsd", "secd", "akd", "parsecd", "spindump",
    "ReportCrash", "iTunesHelper", "xpcproxy", "runningboardd", "symptomsd", "mediaremoted", "locationd",
    "corespotlightd", "backupd", "coreduetd", "suggestd", "photoanalysisd", "nehelper", "networkserviceproxy",
    "systemstats", "watchdogd", "sysmond", "endpointsecurityd", "keybagd", "biometrickitd", "storeaccountd",
    "commerce", "storedownloadd", "familycircled", "accountsd", "remindd", "calaccessd", "callservicesd",
    "screensharingd", "ARDAgent", "sshd", "ssh-agent", "cron", "atrun", "periodic", "emond", "installd",
    "system_installd", "softwareupdate_notify_agent", "Spotlight", "SecurityAgent", "authorizationhost",
    "coreauthd", "ctkd", "pboard", "universalaccessd", "talagent", "ViewBridgeAuxiliary", "AirPlayXPCHelper",
})
CHAIN_CHILDREN = {"curl", "wget", "sh", "bash", "zsh", "dash", "python", "python3", "perl", "ruby", "osascript",
                  "dscl", "security", "ditto", "zip", "nc", "ncat", "base64", "openssl", "sqlite3", "screencapture"}
DOCUMENT_APPS = {"Microsoft Word", "Microsoft Excel", "Microsoft PowerPoint", "Microsoft Outlook", "Pages",
                 "Numbers", "Keynote", "Preview", "Mail", "Adobe Acrobat Reader", "AdobeReader", "TextEdit"}
BROWSER_EXES = re.compile(r"/(?:Google Chrome|Chromium|Brave Browser|Microsoft Edge|Arc|Opera|Vivaldi|"
                          r"Google Chrome Canary|Google Chrome Beta|Thorium)(?:\.app)?/Contents/MacOS/[^/]+$")
BROWSER_MAIN = re.compile(r"/(?:Safari|Firefox[^/]*|LibreWolf|Waterfox[^/]*|Orion|Zen[^/]*)\.app/Contents/MacOS/[^/]+$")
# native messaging hosts (password managers, Claude …) and Chrome's own updater are started by the browser itself
BROWSER_CHILD_OK = re.compile(r"chrome-extension://|moz-extension://|NativeMessagingHosts|[Kk]eystone|GoogleUpdater")
# Apple apps whose names a fake program likes to borrow (daemons: APPLE_DAEMON_NAMES)
APPLE_APP_NAMES = frozenset({"Safari", "System Settings", "System Preferences", "Software Update", "Keychain Access",
                             "App Store", "Activity Monitor"})
AUTOMATION_FLAGS = ("--enable-automation", "--remote-debugging-pipe", "--test-type", "--headless")


def _base(n: str | None) -> str:
    return re.sub(r"(?:[\d.]+)$", "", os.path.basename(n or ""))


def snapshot(ctx: EnvContext) -> dict[int, dict]:
    """psutil snapshot shared by the process and network collectors (cached on the context)."""
    cached = getattr(ctx, "_procs", None)
    if cached is not None:
        return cached
    procs: dict[int, dict] = {}
    try:
        import psutil
    except ImportError:
        ctx.limit("brak psutil: uruchomione procesy nie zostały sprawdzone")
        ctx._procs = procs  # type: ignore[attr-defined]
        return procs
    for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
        info = dict(p.info)
        if info.get("pid") is None:
            continue
        procs[info["pid"]] = info
    ctx._procs = procs  # type: ignore[attr-defined]
    return procs


def _own_lineage() -> set[int]:
    pids = {os.getpid()}
    try:
        import psutil
        for pp in psutil.Process().parents():
            pids.add(pp.pid)
    except Exception:  # noqa: BLE001
        pass
    return pids


def _is_cerber_app(exe: str | None) -> bool:
    """Cerber.app itself (ad-hoc signed, built locally from this project) – not something to report."""
    suffix = "/Contents/MacOS/Cerber"
    if not exe or not exe.endswith(suffix):
        return False
    try:
        import plistlib
        from .. import config
        with open(exe[:-len(suffix)] + "/Contents/Info.plist", "rb") as fh:
            info = plistlib.load(fh)
        return info.get("CFBundleIdentifier") == "pl.cerber.app" and \
            os.path.realpath(str(info.get("CerberRoot", ""))) == os.path.realpath(config.ROOT)
    except (OSError, ValueError, plistlib.InvalidFileException):
        return False


def collect_processes(ctx: EnvContext) -> None:
    ctx.progress("uruchomione procesy")
    procs = snapshot(ctx)
    if not procs:
        return
    skip_pids = _own_lineage() | {pid for pid, i in procs.items() if _is_cerber_app(i.get("exe"))}
    children: dict[int, list[int]] = defaultdict(list)
    for pid, info in procs.items():
        if info.get("ppid") is not None:
            children[info["ppid"]].append(pid)
    no_exe = [pid for pid, i in procs.items() if not i.get("exe") and pid not in (0,)]
    no_cmd = [pid for pid, i in procs.items() if i.get("cmdline") is None and pid not in (0,)]
    my_user = ctx.homes[0].name if ctx.homes else None
    if no_cmd and not ctx.is_root:
        ctx.limit(f"nie można w pełni sprawdzić {len(no_cmd)} procesów innych użytkowników (głównie root/system) "
                  f"(wiersz poleceń/środowisko wymagają roota)")

    # prefetch signatures of every non-Apple executable
    exes = sorted({i["exe"] for i in procs.values() if i.get("exe") and not is_apple_path(i["exe"])
                   and os.path.exists(i["exe"])})
    ctx.codesign.prefetch(exes)

    by_exe: dict[str, list[int]] = defaultdict(list)
    for pid, i in procs.items():
        if i.get("exe"):
            by_exe[i["exe"]].append(pid)

    inv = ctx.inv("processes")
    home = ctx.homes[0].home if ctx.homes else None
    qevents = quarantine_events(home) if home else {}
    # ---- executable-level checks (one finding per executable)
    for exe, pids in sorted(by_exe.items()):
        if all(pid in skip_pids for pid in pids):
            continue
        info0 = procs[pids[0]]
        pi = classify_path(exe, home)
        exists = os.path.exists(exe)
        entry = {"exe": exe, "pids": pids[:20], "count": len(pids), "user": info0.get("username"),
                 "name": info0.get("name")}
        sigs: list[Signal] = []
        sinfo = None
        if pi.has("apple"):
            entry["signer"] = "Apple (system volume)"
            if exists:
                inv.append(entry)
                continue
        if not exists:
            if pi.has("apple", "pkgmgr", "app_bundle") or "/Caches/" in exe:
                sigs.append(Signal(f"{P}.DeletedExec", 5, Confidence.LOW,
                                   "program został podmieniony lub usunięty podczas działania (aktualizacja?)", [exe]))
            else:
                sigs.append(Signal(f"{P}.DeletedExec", 25, Confidence.MEDIUM,
                                   "działający program nie istnieje już na dysku (ładunek usuwający sam siebie?)", [exe]))
            sigs += path_signals(exe, P, "program procesu", home)
        else:
            sinfo = ctx.sign(exe)
            entry["signer"] = sinfo.signer
            sigs += path_signals(exe, P, "program procesu", home)
            sev = 1.0
            if sinfo.status == "adhoc" and "linker-signed" in (sinfo.flags or ""):
                sev = 0.7  # locally compiled code (cargo/go/clang output) is linker-signed ad-hoc
            sigs += ctx.signing_signals(exe, P, "program procesu", sev=sev, info=sinfo)
            if pi.has("volume") and sinfo.trusted:
                sigs = [s for s in sigs if not s.name.endswith("VolumePath")]  # signed installers run from DMGs
        names = {_base(exe), info0.get("name") or ""}
        if (names & (APPLE_DAEMON_NAMES | APPLE_APP_NAMES) or any(n.startswith("com.apple.") for n in names)) \
                and not pi.has("apple") and not (sinfo and sinfo.is_apple):
            if pi.has("pkgmgr"):          # Homebrew's `lsd` (ls replacement), `cron` ports …: a name clash, no disguise
                sigs.append(Signal(f"{P}.AppleNameClash", 5, Confidence.LOW,
                                   "program z menedżera pakietów nosi nazwę jak element systemu Apple",
                                   [f"name={info0.get('name')}", f"exe={exe}"]))
            else:
                sigs.append(Signal(f"{P}.AppleMasquerade", 50, Confidence.HIGH,
                                   "proces o nazwie jak demon systemowy lub aplikacja Apple działa spoza systemu "
                                   "i nie jest podpisany przez Apple (podszywanie się)",
                                   [f"name={info0.get('name')}", f"exe={exe}"]))
        if re.search(r"(?i)\b(?:xmrig|xmr-stak|minerd|cpuminer|ccminer|nbminer|lolminer|nanominer|srbminer)\b",
                     os.path.basename(exe)):
            sigs.append(Signal(f"{P}.MinerBinary", 60, Confidence.HIGH, "program koparki kryptowalut", [exe],
                               pua=True))
        sigs = EnvContext.dampen_trusted(sigs, sinfo)
        # provenance: how this program got here and how far to trust it; names malware likes
        org = origin(exe, sinfo, home, qevents=qevents)
        entry["origin"] = org
        trusted = org["trust"] in TRUSTED
        sigs += origin_signals(org, P, "program procesu")
        seen_names: set[str] = set()
        for nm in (info0.get("name"), os.path.basename(exe), os.path.basename(org.get("bundle") or "")):
            if nm and nm.lower() not in seen_names:
                seen_names.add(nm.lower())
                sigs += name_signals(nm, P, "nazwa procesu", trusted=trusted, untrusted=org["trust"] == "untrusted")
        f = ctx.add_finding("process", f"Proces {info0.get('name') or os.path.basename(exe)}", exe, sigs,
                            {"pids": pids[:20], "user": info0.get("username"),
                             "signature": sinfo.to_dict() if sinfo else None, "exists": exists, "origin": org})
        entry["score"] = f.score if f else 0
        inv.append(entry)
        if exists and not (sinfo and sinfo.is_apple) and not pi.has("apple"):
            ctx.add_target(exe, "running process executable", 2 if f and f.score >= 10 else 0)

    # ---- per-process checks: command line, interpreter scripts, chains, browser flags
    for pid, info in procs.items():
        if pid in skip_pids:
            continue
        cmd = info.get("cmdline")
        if not cmd:
            continue
        exe = info.get("exe") or cmd[0]
        text = " ".join(cmd)
        sigs = command_signals(text, P, "wiersz poleceń", skip=("LaunchctlLoad", "EncodedData"))
        try:                                    # the static script heuristics on what the interpreter runs
            sigs += script_signals(cmd, P, home or os.path.expanduser("~"),
                                   have={s.name.rsplit(".", 1)[-1] for s in sigs})
        except Exception:  # noqa: BLE001
            pass
        ci = analyze_command(cmd)
        if ci.interpreter and ci.script:
            sp = ci.script
            if sp.startswith("/") and os.path.isfile(sp) and "/PKInstallSandbox." not in sp:
                spi = classify_path(sp, home)
                isig = ctx.sign(exe) if exe and exe.startswith("/") and os.path.exists(exe) and \
                    not is_apple_path(exe) else None
                app_interp = bool(isig and isig.trusted and "app_bundle" in classify_path(exe).tags)
                ssig = []
                for s in path_signals(sp, f"{P}.Script", f"skrypt {ci.interpreter}", home):
                    tail = s.name.rsplit(".", 1)[-1]
                    if tail == "UserDocsPath":
                        continue
                    if app_interp and spi.has("varfolders"):
                        continue  # an app's own bundled runtime executing its temp scripts
                    if tail == "TempPath" and spi.has("varfolders"):
                        s = Signal(s.name, 15, Confidence.LOW, s.description, s.evidence)
                    else:
                        s = s.scaled(0.6, "skrypt przejściowy, nie persystencja")
                    if app_interp:
                        s = s.scaled(0.5, f"interpreter wbudowany w aplikację podpisaną przez {isig.signer}")
                    ssig.append(s)
                sigs += ssig
                if not spi.has("apple", "pkgmgr"):
                    try:
                        small = os.path.getsize(sp) < (8 << 20)
                    except OSError:
                        small = False
                    if small:
                        ctx.add_target(sp, f"script run by {ci.interpreter} (pid {pid})", 2 if ssig else 0)
        if BROWSER_EXES.search(exe or "") and not any(a.startswith("--type=") for a in cmd):
            automated = any(a.startswith(AUTOMATION_FLAGS) for a in cmd)
            for a in cmd:
                if a.startswith("--load-extension="):
                    dirs = [d for d in a.split("=", 1)[1].split(",") if d]
                    sigs.append(Signal(f"{P}.BrowserLoadExtension", 5 if automated else 30,
                                       Confidence.LOW if automated else Confidence.MEDIUM,
                                       "przeglądarka uruchomiona z rozszerzeniem wczytanym z wiersza poleceń"
                                       + (" (sesja automatyzacji)" if automated else " (styl ChromeLoader)"), dirs[:3]))
                    for dd in dirs:
                        sigs += [s.scaled(0.8) for s in path_signals(dd, f"{P}.Extension", "wczytane rozszerzenie", home)]
                        if os.path.isdir(dd):
                            ctx.add_target(dd, "extension loaded via --load-extension", 2)
                if a.startswith("--remote-debugging-port") and not automated:
                    sigs.append(Signal(f"{P}.BrowserRemoteDebugging", 10, Confidence.LOW,
                                       "przeglądarka udostępnia port zdalnego debugowania DevTools (wektor kradzieży ciasteczek)", [a]))
        # parent / child chains
        chain = []
        cur = info.get("ppid")
        for _ in range(4):
            if not cur or cur not in procs:
                break
            chain.append(procs[cur])
            cur = procs[cur].get("ppid")
        me = _base(info.get("name") or exe)
        parent = _base(chain[0].get("name")) if chain else ""
        if me in CHAIN_CHILDREN and chain:
            if parent == "osascript":
                sc = 55 if me in ("dscl", "security", "sqlite3", "ditto", "zip") else 30
                sigs.append(Signal(f"{P}.OsascriptChild", sc, Confidence.HIGH if sc >= 50 else Confidence.MEDIUM,
                                   f"'{me}' uruchomiony przez osascript (wzorzec stealera AppleScript)",
                                   [" > ".join(_base(c.get('name')) for c in reversed(chain)) + f" > {me}"]))
            if parent in DOCUMENT_APPS or (chain and os.path.basename(chain[0].get("exe") or "") in DOCUMENT_APPS):
                sigs.append(Signal(f"{P}.DocumentAppSpawn", 40, Confidence.HIGH,
                                   f"przeglądarka/edytor dokumentów uruchomił '{me}'", [f"{parent} > {me}"]))
            pexe = chain[0].get("exe") or ""
            if (BROWSER_EXES.search(pexe) or BROWSER_MAIN.search(pexe)) and not any(
                    BROWSER_CHILD_OK.search(str(a)) for a in cmd):
                sigs.append(Signal(f"{P}.BrowserSpawn", 35, Confidence.MEDIUM,
                                   f"przeglądarka uruchomiła '{me}' (nie jako dodatek rozszerzenia) – tak działa "
                                   "exploit lub fałszywa aktualizacja/CAPTCHA", [f"{parent} > {me}", redact(text, 160)]))
        if not sigs:
            continue
        details = {"pid": pid, "ppid": info.get("ppid"), "user": info.get("username"), "exe": exe,
                   "cmdline": redact(text, 400), "parents": [
                       {"pid": c.get("pid"), "name": c.get("name")} for c in chain]}
        f = ctx.add_finding("process", f"Proces {info.get('name')} (pid {pid})", f"pid {pid}", sigs, details)
        if f and exe and exe.startswith("/") and os.path.exists(exe) and not is_apple_path(exe):
            ctx.add_target(exe, f"executable of flagged process {pid}", 2)

    # ---- DYLD injection through the environment (own processes only without root)
    try:
        import psutil
        checked = 0
        t0 = time.monotonic()
        for pid, info in procs.items():
            if pid in skip_pids or (not ctx.is_root and info.get("username") != my_user):
                continue
            if time.monotonic() - t0 > 20:
                ctx.limit("sprawdzanie środowiska procesów przerwano po 20 s")
                break
            try:
                env = psutil.Process(pid).environ()
            except Exception:  # noqa: BLE001
                continue
            checked += 1
            lib = env.get("DYLD_INSERT_LIBRARIES")
            if not lib:
                continue
            benign = all(is_apple_path(x) or "/Xcode" in x or x.endswith(("libgmalloc.dylib", "libMainThreadChecker.dylib"))
                         or (x.startswith("/") and os.path.exists(x) and ctx.sign(x).trusted)
                         for x in lib.split(":") if x)
            sc = 5 if benign else 50
            ctx.add_finding("process", f"DYLD_INSERT_LIBRARIES w procesie {info.get('name')} (pid {pid})", f"pid {pid}",
                            [Signal(f"{P}.DyldInsert", sc, Confidence.HIGH if sc >= 50 else Confidence.LOW,
                                    "proces działa ze wstrzykniętą biblioteką (DYLD_INSERT_LIBRARIES)", [redact(lib)])],
                            {"pid": pid, "exe": info.get("exe"), "library": redact(lib)})
            for x in lib.split(":"):
                if x.startswith("/") and os.path.exists(x) and not is_apple_path(x):
                    ctx.add_target(x, f"library injected into pid {pid}", 2)
        ctx.inventory["process_env_checked"] = checked
    except ImportError:
        pass
    ctx.inventory["process_summary"] = {"total": len(procs), "without_exe": len(no_exe),
                                        "without_cmdline": len(no_cmd), "unique_executables": len(by_exe)}

"""Isolated unpacking and scanning of untrusted archives / downloaded repositories.

Layers of isolation (outer to inner):

1. Workspace – a fresh private directory (0700) under $TMPDIR, removed afterwards. Downloads land
   there; local archives are only *read* (a single file the sandbox may open).
2. macOS Seatbelt profile (sandbox-exec), deny-by-default:
   * no network of any kind (not even DNS),
   * writes only inside the workspace,
   * reads only of the system, the Python runtime, Cerber's code and signature databases,
     the workspace and the one input file – the rest of the disk, incl. the user's home, is invisible,
   * exec only of Python and 7-Zip – nothing that was extracted can ever be started,
   * no Mach/XPC services, no IOKit, no AppleEvents, signals only within the sandbox.
3. Resource limits (setrlimit): no core dumps, max file size, open files, CPU time; the parent adds a
   wall-clock timeout and kills the whole process group.
4. Extraction hygiene: a watchdog stops 7-Zip at a total size / file count / free-disk limit (zip
   bombs), symlinks and special files are removed (only recorded), every file becomes read-only and
   non-executable, passwords commonly used for malware samples are tried.

Nested archives inside the extracted tree are unpacked again by the scan pipeline itself – in memory,
inside the same sandbox.

Defence in depth on top of Seatbelt (in case the macOS sandbox itself had a hole):
5. The workspace is a separate disk-image volume mounted noexec,nosuid,nodev: the KERNEL refuses to run
   anything stored there, and the volume size caps how much an archive can unpack.
6. Self-check: before touching any untrusted byte, the sandboxed process tries forbidden things (network,
   writing outside the workspace, starting a shell, asking tccd for a permission prompt, reading the user's
   home) and aborts the scan if any of them works.
7. A Python audit hook inside the sandbox blocks unexpected subprocesses, sockets and library loads.
8. Permission prompts, AppleEvents, the clipboard, the window server, the keychain, camera/microphone/
   location and authorization dialogs are denied in every profile.
9. Every process started inside the sandbox is tracked and killed when the job ends.
"""
from __future__ import annotations

import argparse
import json
import os
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Callable

from . import config

MAX_TOTAL_BYTES = 8 << 30          # unpacked size limit (zip bomb guard)
MAX_FILES = 200_000
MIN_FREE_BYTES = 4 << 30           # never fill the disk
MAX_FILE_BYTES = 4 << 30           # RLIMIT_FSIZE
CPU_SECONDS = 4 * 3600
WALL_SECONDS = 3 * 3600
PASSWORDS = ["", "infected", "malware", "virus", "virussign", "password", "123456"]
ISOLATION_PL = [
    "brak dostępu do sieci (także DNS)",
    "zapis wyłącznie do izolowanego katalogu roboczego",
    "odczyt tylko systemu, Cerbera i badanego pliku – reszta dysku i katalog domowy są niewidoczne",
    "zakaz uruchamiania czegokolwiek poza Pythonem i 7-Zip (rozpakowane pliki nie mogą się uruchomić)",
    "brak usług systemowych (Mach/XPC), IOKit i AppleEvents",
    f"limity: {MAX_TOTAL_BYTES >> 30} GB rozpakowanych danych, {MAX_FILES:,} plików, "
    f"{WALL_SECONDS // 3600} h czasu".replace(",", " "),
    "dowiązania symboliczne usuwane, pliki bez prawa wykonywania, ścieżki „..” odrzucane",
    "katalog roboczy usuwany po skanie",
]


# ------------------------------------------------------------------ Seatbelt profiles
#
# strict – archives / downloaded repos: reads only the system, Python, Cerber and the one input file
# scan   – files and folders in place: the whole disk READ-ONLY, plus Apple's code-signing tools
# env    – environment & network audit: read-only, system diagnostic tools, no internet connections
# net    – downloading a link / repository: internet, but none of the user's files and no exec

SIGN_TOOLS = ["/usr/bin/codesign", "/usr/sbin/spctl", "/usr/bin/xattr", "/usr/bin/mdls"]
SIGN_MACH = ["com.apple.system.opendirectoryd.libinfo", "com.apple.logd", "com.apple.system.notification_center",
             "com.apple.trustd.agent", "com.apple.trustd", "com.apple.security.syspolicy", "com.apple.metadata.mds",
             "com.apple.SecurityServer", "com.apple.CoreServices.coreservicesd", "com.apple.lsd.mapdb"]
NET_MACH = ["com.apple.dnssd.service", "com.apple.trustd", "com.apple.trustd.agent", "com.apple.SecurityServer",
            "com.apple.SystemConfiguration.configd", "com.apple.SystemConfiguration.DNSConfiguration",
            "com.apple.system.opendirectoryd.libinfo", "com.apple.logd", "com.apple.system.notification_center",
            "com.apple.networkd", "com.apple.symptomsd", "com.apple.usymptomsd"]
# never reachable from any profile: permission prompts, UI, automation, secrets, sensors, auth dialogs
DENY_MACH_PREFIXES = ["com.apple.tccd", "com.apple.pasteboard", "com.apple.windowserver", "com.apple.coreservices.appleevents",
                      "com.apple.coreservices.launchservicesd", "com.apple.cmio", "com.apple.audio", "com.apple.coreaudio",
                      "com.apple.locationd", "com.apple.CoreLocation", "com.apple.screencapture", "com.apple.replayd",
                      "com.apple.accessibility", "com.apple.AddressBook", "com.apple.contactsd", "com.apple.CalendarAgent",
                      "com.apple.photos", "com.apple.usernotifications", "com.apple.notificationcenterui",
                      "com.apple.dock", "com.apple.authd", "com.apple.security.authhost", "com.apple.SecurityAgent",
                      "com.apple.CoreAuthentication", "com.apple.securityd.xpc", "com.apple.security.keychain",
                      "com.apple.sharingd", "com.apple.bluetoothd", "com.apple.nehelper", "com.apple.speech",
                      "com.apple.hiservices", "com.apple.inputmethodkit", "com.apple.FileProvider",
                      "com.apple.xpc.launchd.domain", "com.apple.lsd.open"]
ISOLATION = {
    "strict": ISOLATION_PL,
    "scan": [
        "cały dysk dostępny WYŁĄCZNIE do odczytu – skaner nie może niczego zmienić ani usunąć",
        "brak dostępu do sieci (także DNS)",
        "zapis tylko do tymczasowego katalogu roboczego, usuwanego po skanie",
        "uruchamiać wolno tylko 7-Zip, UPX i systemowe narzędzia Apple do sprawdzania podpisów",
        "obrazy DMG rozpakowywane przez 7-Zip zamiast montowania w systemie",
        "skanowane pliki nigdy nie są uruchamiane; limity czasu i zasobów",
    ],
    "env": [
        "przegląd środowiska w osobnym sandboksie: dysk tylko do odczytu",
        "brak połączeń z internetem (wyjątek: systemowe odwrotne zapytania DNS o adresy połączeń)",
        "zapis tylko do katalogu roboczego; uruchamiane wyłącznie narzędzia diagnostyczne macOS",
    ],
    "net": [
        "pobieranie w osobnym sandboksie: dostęp do internetu, ale NIE do Twoich plików",
        "zapis tylko do izolowanego katalogu roboczego",
        "zakaz uruchamiania czegokolwiek poza Pythonem – pobrane pliki nie mogą się uruchomić",
    ],
}


def _q(path: str) -> str:
    return '"' + os.path.realpath(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _tool(name: str) -> str | None:
    p = config.tools().get(name)
    return os.path.realpath(p) if p else None


def _lit(paths) -> str:
    return " ".join(f"(literal {_q(p)})" for p in paths if os.path.exists(p))


def build_profile(work: str, input_path: str | None = None, kind: str = "strict") -> str:
    py_real = os.path.realpath(sys.executable)
    py_prefix = os.path.realpath(sys.base_prefix)
    venv = os.path.join(config.ROOT, ".venv")
    reads = [
        "/System", "/usr/lib", "/usr/share", "/private/etc", "/private/var/db/timezone", "/Library/Apple",
        "/opt/homebrew/Cellar", "/opt/homebrew/opt", "/opt/homebrew/lib", "/opt/homebrew/etc/openssl@3",
        "/opt/homebrew/etc/ca-certificates",
        py_prefix, venv, os.path.join(config.ROOT, "cerber"), config.COMPILED,
    ]
    execs = [py_real, os.path.join(py_prefix, "Resources/Python.app/Contents/MacOS/Python"),
             os.path.join(venv, "bin/python"), os.path.join(venv, "bin/python3"), os.path.join(venv, "bin/python3.14")]
    if kind in ("strict", "scan"):
        execs += [t for t in (_tool("7z"), _tool("upx")) if t]
    if kind == "scan":
        execs += SIGN_TOOLS
    lines = [
        "(version 1)",
        "(deny default)",
        "(allow process-fork)",
        f"(allow process-exec {_lit(execs)})",
        "(allow signal (target same-sandbox))",
        "(allow sysctl-read)",
        "(allow ipc-posix-sem)",
        "(allow ipc-posix-shm-read-data ipc-posix-shm-write-data ipc-posix-shm-write-create ipc-posix-shm-write-unlink)",
        "(allow file-read-metadata)",
        "(allow file-read* (literal \"/\") (literal \"/dev/null\") (literal \"/dev/urandom\") (literal \"/dev/random\")"
        " (literal \"/dev/zero\") (literal \"/dev/fd\") (subpath \"/dev/fd\"))",
        "(allow file-read* " + " ".join(f"(subpath {_q(p)})" for p in reads if os.path.exists(p)) + ")",
        f"(allow file-read* (literal {_q(config.ROOT)}))",          # import path lookup (names only)
        f"(allow file-read* file-write* (subpath {_q(work)}))",
        "(allow file-write-data file-ioctl (literal \"/dev/null\") (literal \"/dev/dtracehelper\"))",
        "(deny appleevent-send)",
    ]
    if kind in ("scan", "env"):
        lines.append("(allow file-read*)")                                  # whole disk, read-only
    if kind == "scan":
        lines.append("(allow mach-lookup " + " ".join(f'(global-name "{m}")' for m in SIGN_MACH) + ")")
    if kind == "env":
        lines += [
            '(allow process-exec (subpath "/usr/bin") (subpath "/usr/sbin") (subpath "/bin") (subpath "/sbin")'
            ' (subpath "/usr/libexec") (subpath "/System/Library") (subpath "/Library/Apple"))',
            "(allow mach-lookup)", "(allow iokit-open)", "(allow iokit-get-properties)",
            "(allow user-preference-read)", "(allow system-socket)", "(allow ipc-posix-shm)",
            "(allow distributed-notification-post)",
            '(allow network-outbound (literal "/private/var/run/mDNSResponder"))',
            '(allow network-outbound (control-name "com.apple.network.statistics"))',
            '(allow network-outbound (control-name "com.apple.netsrc"))',
            "(allow file-write-data (subpath \"/dev\"))",
        ]
    if kind == "net":
        lines += [
            "(allow mach-lookup " + " ".join(f'(global-name "{m}")' for m in NET_MACH) + ")",
            "(allow system-socket)",
            "(allow network-outbound (remote tcp))",
            '(allow network-outbound (literal "/private/var/run/mDNSResponder"))',
            "(allow user-preference-read)",
        ]
    if input_path:
        lines.append(f"(allow file-read* (literal {_q(input_path)}))")
    # deny rules win over allow rules in SBPL – these hold whatever was allowed above
    home = os.path.expanduser("~")
    lines += [
        f"(deny process-exec (subpath {_q(work)}))",
        "(deny mach-lookup " + " ".join(f'(global-name-prefix "{m}")' for m in DENY_MACH_PREFIXES) + ")",
        f"(deny file-read-data (subpath {_q(os.path.join(home, 'Library/Keychains'))})"
        ' (subpath "/Library/Keychains") (subpath "/private/var/db/SystemKey"))',
        f"(deny file-write* (subpath {_q(config.ROOT)}) (subpath {_q(home)}) (subpath \"/Applications\")"
        ' (subpath "/Library") (subpath "/usr/local") (subpath "/opt"))',
    ]
    if kind != "net":
        lines.append("(deny network-outbound (remote ip))")
        lines.append("(deny network-bind network-inbound)")
    return "\n".join(lines) + "\n"


def _limits() -> None:
    os.setsid()
    os.umask(0o077)
    try:
        os.nice(5)
    except OSError:
        pass
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS * 4, CPU_SECONDS * 4))
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
    except (ValueError, OSError):
        pass


VOLUME_SIZE = "16g"
_VOLUMES: dict[str, tuple[str, str]] = {}     # mountpoint -> (whole disk device, image path)


def _mount_noexec(work: str) -> bool:
    """Back the workspace with a private sparse disk image mounted noexec,nosuid,nodev (no root needed)."""
    import plistlib
    image = work + ".sparseimage"
    try:
        r = subprocess.run(["/usr/bin/hdiutil", "create", "-quiet", "-size", VOLUME_SIZE, "-type", "SPARSE",
                            "-fs", "HFS+", "-volname", "CerberSandbox", work], capture_output=True, timeout=60)
        if r.returncode != 0 or not os.path.exists(image):
            return False
        r = subprocess.run(["/usr/bin/hdiutil", "attach", "-nobrowse", "-noautoopen", "-nomount", "-plist", image],
                           capture_output=True, timeout=60)
        ents = plistlib.loads(r.stdout).get("system-entities", []) if r.returncode == 0 else []
        vol = next((e["dev-entry"] for e in ents if e.get("content-hint") == "Apple_HFS"), None)
        whole = min((e["dev-entry"] for e in ents), default=None, key=len)
        if not vol or not whole:
            if whole:
                subprocess.run(["/usr/bin/hdiutil", "detach", "-force", whole], capture_output=True, timeout=60)
            os.remove(image)
            return False
        _VOLUMES[work] = (whole, image)
        with open(work + ".owner", "w") as fh:
            fh.write(str(os.getpid()))
        r = subprocess.run(["/usr/sbin/diskutil", "mount", "-mountOptions", "noexec,nosuid,nodev,nobrowse",
                            "-mountPoint", work, vol], capture_output=True, text=True, timeout=60)
        mounted = any(work in line and "noexec" in line for line in
                      subprocess.run(["/sbin/mount"], capture_output=True, text=True, timeout=20).stdout.splitlines())
        if r.returncode != 0 or not mounted:
            _unmount(work)
            return False
        open(os.path.join(work, ".metadata_never_index"), "w").close()     # keep Spotlight out
        return True
    except (OSError, subprocess.SubprocessError, ValueError):
        _unmount(work)
        return False


def _unmount(work: str) -> None:
    whole, image = _VOLUMES.pop(work, (None, work + ".sparseimage"))
    if whole:
        for _ in range(3):
            r = subprocess.run(["/usr/bin/hdiutil", "detach", "-force", whole], capture_output=True, timeout=120)
            if r.returncode == 0:
                break
            time.sleep(1)
    for leftover in (image, work + ".owner"):
        if os.path.exists(leftover):
            os.remove(leftover)


def _owner_alive(path: str) -> bool:
    try:
        with open(path[:-len(".sparseimage")] + ".owner") as fh:
            pid = int(fh.read().strip())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def cleanup_stale() -> None:
    """Detach workspaces left behind by a crashed run."""
    import plistlib
    try:
        r = subprocess.run(["/usr/bin/hdiutil", "info", "-plist"], capture_output=True, timeout=30)
        for img in plistlib.loads(r.stdout).get("images", []):
            path = img.get("image-path", "")
            if "cerber-sandbox-" in path and path.endswith(".sparseimage") and not _owner_alive(path):
                devs = [e.get("dev-entry") for e in img.get("system-entities", []) if e.get("dev-entry")]
                if devs:
                    subprocess.run(["/usr/bin/hdiutil", "detach", "-force", min(devs, key=len)],
                                   capture_output=True, timeout=120)
                try:
                    os.remove(path)
                except OSError:
                    pass
    except (OSError, subprocess.SubprocessError, ValueError):
        pass


def new_workspace() -> str:
    work = os.path.realpath(tempfile.mkdtemp(prefix="cerber-sandbox-"))
    noexec = os.environ.get("CERBER_NO_NOEXEC") != "1" and _mount_noexec(work)
    os.chmod(work, 0o700)
    for sub in ("in", "x", "tmp", "home", "out"):
        os.makedirs(os.path.join(work, sub), mode=0o700, exist_ok=True)
    with open(os.path.join(work, "out", "volume.json"), "w") as fh:
        json.dump({"noexec_volume": noexec}, fh)
    return work


def workspace_noexec(work: str) -> bool:
    return work in _VOLUMES


def remove_workspace(work: str) -> None:
    if not work or "cerber-sandbox-" not in os.path.basename(work):
        return
    for root, dirs, files in os.walk(work):     # extracted files are read-only on purpose
        for d in dirs:
            try:
                os.chmod(os.path.join(root, d), 0o700)
            except OSError:
                pass
    if work in _VOLUMES:
        _unmount(work)
    shutil.rmtree(work, ignore_errors=True)


def run_inner(work: str, kind: str, inner_args: list[str], on_event: Callable[[dict], None],
              cancel: threading.Event | None = None, input_path: str | None = None,
              out_name: str = "report.json", wall: int = WALL_SECONDS, track_every: float = 2.0) -> dict | None:
    """Run `python -m cerber.sandbox <inner_args>` under the `kind` profile; relay JSON events; return out/<out_name>.
    `track_every`: how often descendants are recorded (a `ps` call; long-running watches use a longer interval)."""
    profile = build_profile(work, input_path if input_path and not input_path.startswith(work) else None, kind)
    with open(os.path.join(work, f"sandbox-{kind}.sb"), "w") as fh:
        fh.write(profile)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.path.join(work, "home"),
           "TMPDIR": os.path.join(work, "tmp"), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
           "PYTHONUNBUFFERED": "1", "PYTHONPATH": config.ROOT, "LANG": "pl_PL.UTF-8", "CERBER_HOME": config.HOME,
           "CERBER_DISABLE_TOOLS": "hdiutil", "CERBER_SANDBOX": kind, "CERBER_REAL_HOME": os.path.expanduser("~"),
           "CERBER_NOEXEC": "1" if workspace_noexec(work) else "0"}
    if kind == "env":
        env["HOME"] = os.path.expanduser("~")       # the environment scan inspects the real home (read-only)
        if os.environ.get("CERBER_PRECOMPUTED"):
            env["CERBER_PRECOMPUTED"] = os.environ["CERBER_PRECOMPUTED"]
    cmd = ["/usr/bin/sandbox-exec", "-f", os.path.join(work, f"sandbox-{kind}.sb"),
           os.path.join(config.ROOT, ".venv", "bin", "python"), "-m", "cerber.sandbox"] + inner_args
    out_path = os.path.join(work, "out", out_name)
    if os.path.exists(out_path):
        os.remove(out_path)
    proc = subprocess.Popen(cmd, cwd=work, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1, preexec_fn=_limits)
    errs: list[str] = []

    def drain_err() -> None:
        for line in proc.stderr:
            errs.append(line.rstrip())
            del errs[:-200]
    threading.Thread(target=drain_err, daemon=True).start()

    killer_state = {"why": None}
    tracked: dict[int, str] = {}

    def track() -> None:
        """Remember every descendant (pid + start time) – even ones that call setsid() to escape the group."""
        try:
            out = subprocess.run(["/bin/ps", "-axo", "pid=,ppid=,lstart="], capture_output=True, text=True,
                                 timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            return
        rows = {}
        for line in out.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
                rows[int(parts[0])] = (int(parts[1]), parts[2])
        known = {proc.pid} | set(tracked)
        changed = True
        while changed:
            changed = False
            for pid, (ppid, start) in rows.items():
                if ppid in known and pid not in known:
                    known.add(pid)
                    tracked[pid] = start
                    changed = True

    def killer() -> None:
        t0 = time.time()
        last_track = 0.0
        while proc.poll() is None:
            if time.time() - last_track > track_every:
                last_track = time.time()
                track()
            if cancel is not None and cancel.is_set() and killer_state["why"] is None:
                killer_state["why"] = "cancel"
                _killpg(proc, signal.SIGINT)
                t_cancel = time.time()
                while proc.poll() is None and time.time() - t_cancel < 20:
                    time.sleep(0.2)
                _killpg(proc, signal.SIGKILL)
            if time.time() - t0 > wall:
                killer_state["why"] = "timeout"
                _killpg(proc, signal.SIGKILL)
            time.sleep(0.5)
    threading.Thread(target=killer, daemon=True).start()

    for line in proc.stdout:
        if len(line) > (4 << 20):            # a compromised child must not be able to flood the parent
            errs.append("zbyt długie zdarzenie pominięte")
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            errs.append(line.rstrip()[:300])
            continue
        if isinstance(ev, dict) and isinstance(ev.get("ev"), str):
            if ev.get("ev") == "sandbox_violation":
                killer_state["why"] = "violation"
            on_event(ev)
    rc = proc.wait()
    _killpg(proc, signal.SIGKILL)                 # nothing started inside may outlive the job
    track()
    _kill_tracked(tracked)
    data = None
    if os.path.exists(out_path):
        try:
            with open(out_path) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            data = None
    if data is None:
        why = killer_state["why"]
        msg = ("przerwano" if why == "cancel" else "przekroczono limit czasu" if why == "timeout"
               else "samosprawdzenie izolacji nie powiodło się – skan przerwany dla bezpieczeństwa" if why == "violation"
               else f"proces w sandboksie zakończył się kodem {rc}")
        on_event({"ev": "error", "fatal": why != "cancel", "msg": f"Sandbox: {msg}. " + " | ".join(errs[-5:])[:800]})
    return data


def run_sandboxed(work: str, input_path: str, args: list[str], on_event: Callable[[dict], None],
                  cancel: threading.Event | None = None) -> dict | None:
    """Archive / downloaded repository: unpack and scan under the strict profile."""
    return run_inner(work, "strict", ["inner", "--work", work, "--input", input_path] + args, on_event, cancel,
                     input_path=input_path)


def _kill_tracked(tracked: dict[int, str]) -> None:
    if not tracked:
        return
    try:
        out = subprocess.run(["/bin/ps", "-axo", "pid=,lstart="], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return
    alive = {}
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            alive[int(parts[0])] = parts[1]
    for pid, start in tracked.items():
        if alive.get(pid) == start:          # same process (not a recycled pid)
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


def _killpg(proc: subprocess.Popen, sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


# ------------------------------------------------------------------ inner side (runs INSIDE the sandbox)

def _mach_reachable(name: str) -> bool:
    """bootstrap_look_up – True when this process could talk to the Mach service `name`."""
    import ctypes
    try:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        bp = ctypes.c_uint32.in_dll(lib, "bootstrap_port")
        port = ctypes.c_uint32(0)
        return lib.bootstrap_look_up(bp, name.encode(), ctypes.byref(port)) == 0
    except (OSError, ValueError, AttributeError):
        return False


def self_check(kind: str, work: str) -> tuple[list[str], list[str]]:
    """Try forbidden operations BEFORE reading any untrusted data. Returns (problems, verified)."""
    import socket
    problems: list[str] = []
    verified: list[str] = []
    real_home = os.environ.get("CERBER_REAL_HOME") or os.path.expanduser("~")

    def expect_blocked(label: str, fn) -> None:
        try:
            fn()
        except OSError:
            verified.append(label)
            return
        except Exception:  # noqa: BLE001
            verified.append(label)
            return
        problems.append(label)

    def write_outside() -> None:
        for d in (config.ROOT, real_home):
            p = os.path.join(d, f".cerber-canary-{os.getpid()}")
            try:
                with open(p, "w") as fh:
                    fh.write("x")
            except OSError:
                continue
            os.remove(p)
            return                      # one write succeeded → not blocked
        raise PermissionError("blocked")

    expect_blocked("zapis poza sandboksem zablokowany", write_outside)
    if kind != "net":
        expect_blocked("połączenia sieciowe zablokowane",
                       lambda: socket.create_connection(("1.1.1.1", 443), timeout=3).close())
    if kind != "env":
        expect_blocked("uruchamianie programów (np. powłoki) zablokowane",
                       lambda: subprocess.run(["/bin/sh", "-c", "true"], timeout=5, check=True))
    script = os.path.join(work, "tmp", f"canary-{os.getpid()}.sh")
    try:
        with open(script, "w") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        os.chmod(script, 0o700)
        expect_blocked("uruchamianie plików z katalogu roboczego zablokowane",
                       lambda: subprocess.run([script], timeout=5, check=True))
    finally:
        try:
            os.remove(script)
        except OSError:
            pass
    for svc, label in (("com.apple.tccd", "prośby o uprawnienia (TCC) zablokowane"),
                       ("com.apple.pasteboard.1", "dostęp do schowka zablokowany"),
                       ("com.apple.windowserver.active", "dostęp do ekranu/okien zablokowany"),
                       ("com.apple.coreservices.appleevents", "sterowanie innymi aplikacjami (AppleEvents) zablokowane"),
                       ("com.apple.authd", "okna autoryzacji (hasło administratora) zablokowane")):
        (problems if _mach_reachable(svc) else verified).append(label)
    kc = os.path.join(real_home, "Library/Keychains")
    if os.path.isdir(kc) or kind in ("strict", "net"):
        expect_blocked("pęk kluczy (Keychain) niedostępny", lambda: os.listdir(kc))
    if kind in ("strict", "net"):
        expect_blocked("Twoje pliki (katalog domowy) niewidoczne", lambda: os.listdir(os.path.join(real_home, "Desktop")))
    if os.environ.get("CERBER_NOEXEC") == "1":
        verified.append("katalog roboczy na osobnym woluminie noexec (jądro nie uruchomi z niego niczego)")
    return problems, verified


def install_audit_hook(kind: str) -> None:
    """Python-level tripwire: unexpected subprocesses, sockets, exec or library loads raise inside the sandbox."""
    allowed = {os.path.realpath(sys.executable)}
    for t in (_tool("7z"), _tool("upx")):
        if t:
            allowed.add(t)
    allowed.update(os.path.realpath(t) for t in SIGN_TOOLS if os.path.exists(t))
    sys_prefixes = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/", "/System/Library/", "/Library/Apple/")

    def exe_ok(exe) -> bool:
        if not exe:
            return False
        exe = os.fsdecode(exe)
        if not exe.startswith("/"):
            exe = shutil.which(exe, path="/usr/bin:/bin:/usr/sbin:/sbin") or exe
        real = os.path.realpath(exe)
        if real in allowed:
            return True
        return kind == "env" and real.startswith(sys_prefixes)

    def hook(event: str, args) -> None:
        if event == "subprocess.Popen":
            exe = args[0] or (args[1][0] if args[1] else None)
            if not exe_ok(exe):
                raise PermissionError(f"Cerber sandbox: zablokowano uruchomienie {exe!r}")
        elif event in ("os.posix_spawn", "os.exec", "os.spawn"):
            if not exe_ok(args[0]):
                raise PermissionError(f"Cerber sandbox: zablokowano uruchomienie {args[0]!r}")
        elif event in ("os.system", "pty.spawn", "webbrowser.open", "os.startfile"):
            raise PermissionError(f"Cerber sandbox: zablokowano {event}")
        elif event == "socket.connect" and kind != "net":
            sock, addr = args[0], args[1]
            if not (isinstance(addr, (str, bytes)) and kind == "env"):        # env: only unix sockets (DNS daemon)
                raise PermissionError("Cerber sandbox: zablokowano połączenie sieciowe")
        elif event in ("socket.bind", "socket.listen") and kind != "env":
            raise PermissionError("Cerber sandbox: zablokowano nasłuchiwanie na porcie")
        elif event == "ctypes.dlopen":
            name = os.fsdecode(args[0]) if args[0] else ""
            if name and not re_lib_ok(name):
                raise PermissionError(f"Cerber sandbox: zablokowano ładowanie biblioteki {name!r}")

    def re_lib_ok(name: str) -> bool:
        base = os.path.basename(name)
        return base.startswith(("libc.", "libSystem", "libc++")) or name.startswith(("/usr/lib/", "/System/Library/"))

    sys.addaudithook(hook)


def harden(kind: str, work: str, emit) -> list[str]:
    """Run at the very start of every inner command."""
    problems, verified = self_check(kind, work)
    if problems:
        emit({"ev": "sandbox_violation", "problems": problems})
        emit({"ev": "error", "fatal": True, "msg": "Samosprawdzenie sandboksa nie powiodło się – skan przerwany dla "
                                                     "bezpieczeństwa: " + "; ".join(problems)})
        sys.stdout.flush()
        os._exit(3)
    from .dataless import materialization_off, never_materialize
    never_materialize()
    if materialization_off():
        verified.append("pliki trzymane tylko w iCloud/chmurze nie są pobierane (pomijane)")
    install_audit_hook(kind)
    emit({"ev": "log", "msg": "Sandbox zweryfikowany przed skanem: " + "; ".join(verified)})
    try:
        with open(os.path.join(work, "out", f"selfcheck-{kind}.json"), "w") as fh:
            json.dump(verified, fh, ensure_ascii=False)
    except OSError:
        pass
    return verified


class _Emitter:
    def __init__(self):
        self.out = os.fdopen(os.dup(1), "w", buffering=1)
        os.dup2(2, 1)           # stray prints go to stderr, stdout carries only events

    def __call__(self, obj: dict) -> None:
        self.out.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
        self.out.flush()


def _dir_usage(path: str, cap_files: int) -> tuple[int, int]:
    total = n = 0
    for root, dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
            n += 1
            if n > cap_files:
                return total, n
    return total, n


def extract(archive: str, dest: str, emit: Callable[[dict], None]) -> dict:
    """7-Zip extraction with bomb guard and password attempts. Returns stats."""
    seven = _tool("7z")
    stats = {"ok": False, "password": None, "limits_hit": [], "removed_links": 0, "removed_special": 0,
             "files": 0, "bytes": 0, "tool": "7-Zip"}
    if not seven:
        stats["error"] = "brak 7-Zip (brew install sevenzip)"
        return stats
    for pw in PASSWORDS:
        shutil.rmtree(dest, ignore_errors=True)
        os.makedirs(dest, mode=0o700, exist_ok=True)
        cmd = [seven, "x", "-y", "-bso0", "-bsp0", "-bse1", f"-p{pw}", f"-o{dest}", "--", archive]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             env={"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/tmp")})
        out_lines: list[str] = []
        t = threading.Thread(target=lambda: out_lines.extend(p.stdout), daemon=True)
        t.start()
        hit = None
        while p.poll() is None:
            time.sleep(0.5)
            used, n = _dir_usage(dest, MAX_FILES)
            emit({"ev": "progress", "stage": "extract", "files": n, "bytes": used})
            free = shutil.disk_usage(dest).free
            if used > MAX_TOTAL_BYTES:
                hit = f"przekroczono limit {MAX_TOTAL_BYTES >> 30} GB rozpakowanych danych (bomba ZIP?)"
            elif n > MAX_FILES:
                hit = f"przekroczono limit {MAX_FILES} plików"
            elif free < MIN_FREE_BYTES:
                hit = "za mało wolnego miejsca na dysku"
            if hit:
                p.kill()
                break
        p.wait()
        t.join(timeout=2)
        text = "".join(out_lines)
        if hit:
            stats["limits_hit"].append(hit)
            stats["ok"] = True          # partial extraction is still worth scanning
            break
        wrong_pw = "Wrong password" in text or "Cannot open encrypted archive" in text
        if wrong_pw and pw != PASSWORDS[-1]:
            continue
        if p.returncode in (0, 1):      # 1 = warnings (e.g. some files skipped)
            stats["ok"] = True
            stats["password"] = pw or None
        else:
            stats["error"] = (text.strip().splitlines() or [f"kod {p.returncode}"])[-1][:300]
            if wrong_pw:
                stats["error"] = "archiwum zaszyfrowane nieznanym hasłem"
        break
    if stats["ok"] and not stats["limits_hit"]:
        _unwrap(dest, seven, stats)
    _sanitize(dest, stats)
    return stats


def _unwrap(dest: str, seven: str, stats: dict) -> None:
    """.tar.gz / .tar.xz / .tgz … : 7-Zip removes one layer per run – unpack the inner tar too."""
    for _layer in range(3):
        entries = os.listdir(dest)
        if len(entries) != 1:
            return
        only = os.path.join(dest, entries[0])
        if not os.path.isfile(only) or os.path.islink(only):
            return
        with open(only, "rb") as fh:
            head = fh.read(512)
        if head[257:262] != b"ustar" and not entries[0].lower().endswith(".tar"):
            return
        inner = os.path.join(os.path.dirname(dest), f"layer{_layer}.tar")
        os.replace(only, inner)
        r = subprocess.run([seven, "x", "-y", "-bso0", "-bsp0", "-bse1", f"-o{dest}", "--", inner],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=WALL_SECONDS)
        used, n = _dir_usage(dest, MAX_FILES)
        if r.returncode not in (0, 1) or not n:
            os.replace(inner, only)
            return
        os.remove(inner)
        stats["layers"] = _layer + 2
        if used > MAX_TOTAL_BYTES or n > MAX_FILES:
            stats["limits_hit"].append("przekroczono limit rozmiaru/liczby plików po rozpakowaniu tar")
            return


def _sanitize(dest: str, stats: dict) -> None:
    """Remove links / special files, make everything read-only and non-executable."""
    total = n = 0
    for root, dirs, files in os.walk(dest, topdown=True):
        for name in list(dirs):
            p = os.path.join(root, name)
            if os.path.islink(p):
                os.unlink(p)
                dirs.remove(name)
                stats["removed_links"] += 1
        for name in files:
            p = os.path.join(root, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                os.unlink(p)
                stats["removed_links"] += 1
            elif not stat.S_ISREG(st.st_mode):
                os.unlink(p)
                stats["removed_special"] += 1
            else:
                os.chmod(p, 0o400)
                total += st.st_size
                n += 1
    for root, dirs, _files in os.walk(dest):
        for d in dirs:
            os.chmod(os.path.join(root, d), 0o500)
    os.chmod(dest, 0o500)
    stats["files"], stats["bytes"] = n, total


ARCHIVE_EXT = (".zip", ".7z", ".rar", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".zst", ".tbz", ".txz", ".dmg", ".pkg",
               ".mpkg", ".iso", ".cab", ".xar", ".xip", ".jar", ".apk", ".deb", ".rpm", ".cpio", ".wim", ".lz",
               ".lzma", ".z", ".arj", ".lzh", ".vhd", ".vhdx", ".img")
ARCHIVE_MAGIC = (b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00",
                 b"\x28\xb5\x2f\xfd", b"xar!", b"MSCF")


def _looks_like_archive(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return False
    if head.startswith(ARCHIVE_MAGIC) or head[257:262] == b"ustar":
        return True
    return path.lower().endswith(ARCHIVE_EXT)


def inner_main(a) -> int:
    emit = _Emitter()
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    verified = harden("strict", a.work, emit)
    from .pipeline import Pipeline
    from .scanner import ScanOptions, load_engines, result_dict, scan_paths

    work, inp = a.work, a.input
    out_dir = os.path.join(work, "out")
    xdir = os.path.join(work, "x")
    sandbox_info: dict = {"isolation": ISOLATION_PL, "verified": verified, "limits_hit": [], "extracted_files": 0,
                          "extracted_bytes": 0, "depth": 0, "tree": []}
    opts = ScanOptions(deep=True, level=a.level, macos_checks=False, defer_ai=a.ai, workers=a.workers or 0)
    opts.file_timeout = 900

    def log(msg: str) -> None:
        emit({"ev": "log", "msg": msg})

    targets: list[str]
    archive_check = None
    archives_checked: list[str] = []
    if os.path.isdir(inp) and a.unpack_top:
        # downloaded files: every archive among them is unpacked into x/<name>/, everything else scanned as is
        emit({"ev": "stage", "id": "extract", "title": "Rozpakowywanie pobranych archiwów w sandboksie…"})
        targets, base = [], work + "/view"
        os.makedirs(base, mode=0o700, exist_ok=True)
        for name in sorted(os.listdir(inp)):
            src = os.path.join(inp, name)
            if not os.path.isfile(src):
                continue
            if _looks_like_archive(src):
                dest = os.path.join(base, name)
                st = extract(src, dest, emit)
                sandbox_info["limits_hit"] += st["limits_hit"]
                if st["ok"] and st["files"]:
                    sandbox_info["extracted_files"] += st["files"]
                    sandbox_info["extracted_bytes"] += st["bytes"]
                    sandbox_info["depth"] = 1
                    targets.append(dest)
                    archives_checked.append(src)
                    log(f"{name}: rozpakowano {st['files']} plików"
                        + (f" (hasło „{st['password']}”)" if st.get("password") else ""))
                    continue
                shutil.rmtree(dest, ignore_errors=True)
                log(f"{name}: nie rozpakowano ({st.get('error') or 'nieznany format'}) – skanuję w całości")
            link = os.path.join(base, name)
            os.link(src, link)
            targets.append(link)
    elif os.path.isdir(inp):
        targets = [inp]
        base = inp
    else:
        emit({"ev": "stage", "id": "extract", "title": "Rozpakowywanie w sandboksie…"})
        st = extract(inp, xdir, emit)
        sandbox_info["limits_hit"] += st["limits_hit"]
        sandbox_info.update(extracted_files=st["files"], extracted_bytes=st["bytes"],
                            removed_links=st["removed_links"], password=st.get("password"))
        if st["ok"] and st["files"]:
            sandbox_info["depth"] = 1
            targets, base = [xdir], xdir
            archive_check = inp
            log(f"Rozpakowano {st['files']} plików ({st['bytes'] / 1e6:.1f} MB)"
                + (f", hasło: „{st['password']}”" if st.get("password") else ""))
        else:
            log("Nie udało się rozpakować tym narzędziem" + (f": {st['error']}" if st.get("error") else "")
                + " – skanuję plik w całości (silnik rozpakuje w pamięci, co rozpozna)")
            targets, base = [inp], os.path.dirname(inp)

    emit({"ev": "stage", "id": "load", "title": "Ładowanie baz sygnatur…"})
    bundle = load_engines(opts, log)

    def on_result(r: dict) -> None:
        emit({"ev": "finding", "item": _public(r, base)})

    emit({"ev": "stage", "id": "scan", "title": "Skanowanie…"})
    try:
        report = scan_paths(targets, opts, log=log, engines_bundle=bundle, progress=False, on_result=on_result,
                            on_progress=lambda p: emit({"ev": "progress", **_rel_progress(p, base)}))
    except KeyboardInterrupt:
        report = {"results": [], "counts": {}, "files": 0, "cancelled": True}
    if archive_check:
        archives_checked.append(archive_check)
    for arc in archives_checked:
        # the archive as a whole (hash / container signatures) – without unpacking it a second time
        engines, services, _info = bundle
        pipe = Pipeline(engines=engines, analyzers=[], services=services, options={"deep": False, "macos": False})
        try:
            r = result_dict(pipe.scan_file(arc), opts.defer_ai)
            if r["verdict"] != "CLEAN":
                r["container_only"] = True
                report["results"].insert(0, r)
                report["counts"][r["verdict"]] = report["counts"].get(r["verdict"], 0) + 1
                emit({"ev": "finding", "item": _public(r, os.path.dirname(arc))})
        except Exception as exc:  # noqa: BLE001
            log(f"Sprawdzenie całego archiwum nie powiodło się: {exc!r}")
    verdicts = {r["path"]: r["verdict"] for r in report.get("results", [])}
    tree = []
    for root, dirs, files in os.walk(base):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(root, f)
            try:
                size = os.lstat(p).st_size
            except OSError:
                continue
            tree.append({"path": os.path.relpath(p, base), "size": size, "verdict": verdicts.get(p, "CLEAN")})
            if len(tree) >= 2000:
                break
        if len(tree) >= 2000:
            sandbox_info["tree_truncated"] = True
            break
    sandbox_info["tree"] = tree
    report["sandbox"] = sandbox_info
    report["base"] = base
    with open(os.path.join(out_dir, "report.json"), "w") as fh:
        json.dump(report, fh, ensure_ascii=False, default=str)
    emit({"ev": "inner_done"})
    sys.stdout.flush()
    os._exit(0)


def _rel_progress(p: dict, base: str) -> dict:
    cur = p.get("current")
    if cur and cur.startswith(base.rstrip("/") + "/"):
        p = {**p, "current": os.path.relpath(cur, base)}
    return p


def _public(r: dict, base: str) -> dict:
    """RESULT for the app: paths relative to the sandbox, never quarantinable (copies get deleted)."""
    def rel(p: str) -> str:
        return os.path.relpath(p, base) if p.startswith(base + "/") else os.path.basename(p) if p.startswith("/") else p

    x = {k: v for k, v in r.items() if k not in ("ai_context", "meta", "tree")}
    x["display_path"] = rel(r["path"])
    wo = (r.get("meta") or {}).get("worst_object")
    x["worst_object"] = rel(wo) if wo else None
    x["detections"] = [{**d, "object": rel(str(d.get("object", "")))} for d in r.get("detections", [])]
    if r.get("container_only"):
        x["display_path"] += " (całe archiwum)"
    x["can_quarantine"] = False
    return x


def _strip(r: dict) -> dict:
    x = {k: v for k, v in r.items() if k not in ("ai_context", "meta", "tree")}
    x["worst_object"] = (r.get("meta") or {}).get("worst_object")
    return x


def inner_scan(a) -> int:
    """Files/folders in place under the read-only `scan` profile."""
    emit = _Emitter()
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    harden("scan", a.work, emit)
    from .scanner import ScanOptions, load_engines, scan_paths
    with open(a.job) as fh:
        job = json.load(fh)
    opts = ScanOptions(deep=True, level=job.get("level", "deep"), defer_ai=bool(job.get("ai")),
                       workers=job.get("workers") or 0)
    opts.exclude = job.get("exclude") or []
    if job.get("max_file_size"):
        opts.max_file_size = int(job["max_file_size"])
    if job.get("file_timeout"):
        opts.file_timeout = int(job["file_timeout"])
    opts.collect_cloud = bool(job.get("collect_cloud"))
    out = os.path.join(a.work, "out", "report.json")
    found: list[dict] = []

    def log(msg: str) -> None:
        emit({"ev": "log", "msg": msg})

    def finish(report: dict) -> None:
        with open(out, "w") as fh:
            json.dump(report, fh, ensure_ascii=False, default=str)
        emit({"ev": "inner_done"})
        sys.stdout.flush()
        os._exit(0)

    def partial() -> dict:
        counts = {k: 0 for k in ("CLEAN", "INFO", "SUSPICIOUS", "PUA", "MALICIOUS")}
        for r in found:
            counts[r["verdict"]] += 1
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        return {"started": now, "finished": now, "seconds": 0, "files": len(found), "bytes": 0, "objects": 0,
                "counts": counts, "results": found, "patterns_total": 0, "skipped_count": 0, "errors": [],
                "cancelled": True}

    try:
        emit({"ev": "stage", "id": "load", "title": "Ładowanie baz sygnatur (7 mln wzorców)…"})
        bundle = load_engines(opts, log)
        emit({"ev": "stage", "id": "enumerate", "title": "Szukanie plików…"})
        seen_scan = {"v": False}

        def on_progress(p: dict) -> None:
            if p.get("stage") == "scan" and not seen_scan["v"]:
                seen_scan["v"] = True
                emit({"ev": "stage", "id": "scan", "title": "Skanowanie…"})
            emit({"ev": "progress", **p})

        def on_result(r: dict) -> None:
            found.append(r)
            emit({"ev": "finding", "item": _strip(r)})

        report = scan_paths(job["paths"], opts, log=log, engines_bundle=bundle, progress=False,
                            on_result=on_result, on_progress=on_progress)
        if job.get("follow"):
            _scan_followups(a.work, opts, bundle, report, log, on_result)
    except KeyboardInterrupt:
        report = partial()
    finish(report)
    return 0


def _scan_followups(work: str, opts, bundle, report: dict, log, on_result) -> None:
    """Mega: new files/programs the live watch saw during the session (in/extra.jsonl, appended by the parent)
    are scanned with the engines already loaded. Stops once the feed stays quiet for ~2 s."""
    from .scanner import merge_reports, scan_paths
    feed = os.path.join(work, "in", "extra.jsonl")
    done: set[str] = set()
    pos = 0
    idle = 0
    while idle < 2:
        new: list[str] = []
        try:
            with open(feed) as fh:
                fh.seek(pos)
                chunk = fh.read()
            complete = chunk[:chunk.rfind("\n") + 1]
            pos += len(complete.encode())
            for ln in complete.splitlines():
                try:
                    p = json.loads(ln).get("path")
                except ValueError:
                    continue
                if isinstance(p, str) and p.startswith("/") and p not in done:
                    done.add(p)
                    new.append(p)
        except OSError:
            pass
        if not new:
            idle += 1
            time.sleep(1)
            continue
        idle = 0
        log(f"Skanowanie {len(new)} nowych plików i programów, które pojawiły się w trakcie skanu…")
        sub = scan_paths(new, opts, log=lambda m: None, engines_bundle=bundle, progress=False, on_result=on_result)
        merge_reports(report, sub)
        report.setdefault("extra_scanned", []).extend(new)


NETWORK_STAGE_PL = "Sieć, zdalny dostęp i logi systemowe (porty, połączenia, ruch, logowania)…"


def inner_env(a) -> int:
    """Environment (+ network audit for mega) under the `env` profile."""
    emit = _Emitter()
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    harden("env", a.work, emit)
    from .cli import _env_to_dict
    from .envscan import scan_environment
    level = a.level
    options: dict = {"deep": True}
    if level != "mega":
        from .envscan import COLLECTORS
        options["skip"] = [c[0] for c in COLLECTORS if c[0].startswith("netaudit")]
    net_stage = {"on": False}

    def on_module(name: str) -> None:
        if name.startswith("netaudit") and not net_stage["on"]:
            net_stage["on"] = True
            emit({"ev": "stage", "id": "network", "title": NETWORK_STAGE_PL})

    try:
        rep = scan_environment(options, progress=lambda m: emit({"ev": "log", "msg": f"środowisko: {m}"}),
                               on_module=on_module)
    except KeyboardInterrupt:
        sys.stdout.flush()
        os._exit(130)
    findings = []
    for f in rep.findings:
        d = f.detection
        findings.append({"category": f.category, "title": f.title, "location": f.location, "severity": f.severity,
                         "score": d.score, "description": d.description, "evidence": d.evidence[:8]})
    data = {"raw": _env_to_dict(rep), "findings": findings, "posture": rep.posture, "limitations": list(rep.limitations),
            "targets": list(rep.targets),
            "network": rep.inventory.get("network_audit") if level == "mega" else None}
    with open(os.path.join(a.work, "out", "env.json"), "w") as fh:
        json.dump(data, fh, ensure_ascii=False, default=str)
    emit({"ev": "inner_done"})
    sys.stdout.flush()
    os._exit(0)


def inner_fetch(a) -> int:
    """Downloads under the `net` profile (internet yes, user files no)."""
    emit = _Emitter()
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    harden("net", a.work, emit)
    from .fetch import FetchError, fetch_github, fetch_hf, fetch_url
    fn = {"github": fetch_github, "huggingface": fetch_hf, "url": fetch_url}[a.kind]
    out = os.path.join(a.work, "out", "fetch.json")
    try:
        path, info = fn(a.url, a.work, emit)
        data = {"ok": True, "input": path, "info": info}
    except FetchError as exc:
        data = {"ok": False, "error": str(exc)}
    except KeyboardInterrupt:
        data = {"ok": False, "error": "przerwano", "cancelled": True}
    with open(out, "w") as fh:
        json.dump(data, fh, ensure_ascii=False, default=str)
    emit({"ev": "inner_done"})
    sys.stdout.flush()
    os._exit(0)


def inner_netwatch(a) -> int:
    """Mega (and background protection with --guard): live network & behaviour watch under the `env` profile
    until the parent sends SIGINT. --inbox: unified-log batches written by the unsandboxed parent."""
    emit = _Emitter()
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    harden("env", a.work, emit)
    from .envscan.netwatch import NetWatch
    from .envscan.util import EnvContext
    ctx = EnvContext({"deep": True})
    w = NetWatch(ctx, emit, root_pid=a.root_pid, guard=a.guard, inbox=a.inbox)
    try:
        w.loop()
    except KeyboardInterrupt:
        pass
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    data = w.summary()
    data["findings"] = [{"category": f.category, "title": f.title, "location": f.location, "severity": f.severity,
                         "score": f.detection.score, "description": f.detection.description,
                         "evidence": f.detection.evidence[:8]} for f in ctx.findings]
    with open(os.path.join(a.work, "out", "netwatch.json"), "w") as fh:
        json.dump(data, fh, ensure_ascii=False, default=str)
    emit(w.status(False))
    emit({"ev": "inner_done"})
    sys.stdout.flush()
    os._exit(0)


def _inner_iphone(a) -> int:
    """iPhone backup / device data analysis under the read-only `scan` profile (cerber/iphone.py)."""
    from .iphone import inner_iphone
    return inner_iphone(a)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cerber.sandbox")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("inner")
    p.add_argument("--work", required=True)
    p.add_argument("--input", required=True)
    p.add_argument("--level", default="deep")
    p.add_argument("--ai", action="store_true")
    p.add_argument("--workers", type=int, default=0)
    p.add_argument("--unpack-top", action="store_true")
    p = sub.add_parser("inner-scan")
    p.add_argument("--work", required=True)
    p.add_argument("--job", required=True)
    p = sub.add_parser("inner-env")
    p.add_argument("--work", required=True)
    p.add_argument("--level", default="deep")
    p = sub.add_parser("inner-netwatch")
    p.add_argument("--work", required=True)
    p.add_argument("--root-pid", type=int, default=None)
    p.add_argument("--guard", action="store_true")
    p.add_argument("--inbox", default=None)
    p = sub.add_parser("inner-iphone")
    p.add_argument("--work", required=True)
    p.add_argument("--job", required=True)
    p = sub.add_parser("inner-fetch")
    p.add_argument("--work", required=True)
    p.add_argument("--kind", required=True, choices=["github", "huggingface", "url"])
    p.add_argument("--url", required=True)
    a = ap.parse_args(argv)
    return {"inner": inner_main, "inner-scan": inner_scan, "inner-env": inner_env,
            "inner-fetch": inner_fetch, "inner-netwatch": inner_netwatch, "inner-iphone": _inner_iphone}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())

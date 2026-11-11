"""Active defense: what background protection may do on its own when an attack is certain.

The owner's decision (2026-11-03): with the switch on, Cerber does not only warn. It moves the malicious
file to quarantine and stops the processes running it, which also cuts their network connections. It must
never harm the Mac. These hard limits are checked before every action:

  * only certain detections: a file scan verdict MALICIOUS, or a live attack (envscan.live) with
    confidence "high" (severity "malicious": evidence legitimate software does not produce);
  * never touched: macOS itself (SIP locations), Apple-signed code, Cerber, processes of other users
    or root, the session's essential processes (Finder, Dock, WindowServer, loginwindow, terminals …);
  * a program signed by a known developer (valid Developer ID / App Store signature, not revoked) is
    neither moved nor stopped: the user decides. Interpreters are the exception for stopping: python3 or
    zsh running the attacker's script or a remote shell is the attack, whoever signed the interpreter;
  * freeze → re-check → kill, so a recycled pid or another program is never hit;
  * at most MAX_ACTIONS actions per WINDOW_S: beyond that only alerts. A flood of hits means something
    is off, not that Cerber should stop everything;
  * every action is logged, announced and (quarantine) reversible: "Przywróć" in the app,
    `./cerber.sh quarantine restore <id>`.

Nothing runs as root, no firewall rule is added, nothing is deleted.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time

from . import config

MAX_ACTIONS = 8
WINDOW_S = 600.0
CODESIGN_TIMEOUT = 20
KILL_WAIT_S = 3.0

# what a live attack may trigger (not "suspicious_chain", "miner": unwanted ≠ an attack to stop)
ACT_ATTACKS = frozenset({"remote_shell", "credential_theft", "c2", "download_exec", "injection", "masquerade",
                         "deleted_exe"})

# SIP-protected or Apple-only locations (/usr/local is the user's: Homebrew on Intel, npm -g …)
SYSTEM_PREFIXES = ("/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/", "/private/var/db/",
                   "/Library/Developer/CommandLineTools/", "/Applications/Xcode.app/", "/Applications/Safari.app/")
USER_SYSTEM_OK = ("/usr/local/",)

# processes whose loss breaks the session, or that hold the user's work (a terminal hosts many shells)
CRITICAL_NAMES = frozenset({
    "launchd", "kernel_task", "WindowServer", "loginwindow", "Finder", "Dock", "SystemUIServer", "ControlCenter",
    "NotificationCenter", "Spotlight", "cfprefsd", "distnoted", "trustd", "securityd", "syspolicyd", "tccd",
    "coreservicesd", "lsd", "secd", "sharingd", "usernoted", "UserEventAgent", "runningboardd", "xpcproxy",
    "Terminal", "iTerm2", "Warp", "Ghostty", "ghostty", "Alacritty", "alacritty", "kitty", "WezTerm", "wezterm-gui",
    "Hyper", "tmux", "screen", "sshd", "login", "Code", "Electron", "Xcode", "Activity Monitor",
})


# ------------------------------------------------------------------ what must never be touched

def _real(path: str) -> str:
    try:
        return os.path.realpath(path)
    except (OSError, ValueError):
        return path


def _cerber_roots() -> list[str]:
    roots = {_real(config.ROOT), _real(config.HOME)}
    return [r.rstrip("/") + "/" for r in roots if r and r != "/"]


def _is_cerber_bundle(path: str) -> bool:
    i = path.find("/Cerber.app/")
    if i < 0:
        return False
    try:
        from .envscan.processes import _is_cerber_app
        return _is_cerber_app(path[:i] + "/Cerber.app/Contents/MacOS/Cerber")
    except Exception:  # noqa: BLE001
        return True                            # cannot tell: leave it alone


def system_path(path: str) -> str | None:
    """Reason why `path` belongs to macOS or Cerber (never moved, its processes never stopped), else None."""
    rp = _real(path)
    if not rp.startswith("/"):
        return "ścieżka nie jest bezwzględna"
    if rp.startswith(SYSTEM_PREFIXES) and not rp.startswith(USER_SYSTEM_OK):
        return "plik systemu macOS"
    if any(rp.startswith(r) for r in _cerber_roots()) or _is_cerber_bundle(rp):
        return "plik Cerbera"
    return None


def _codesign(args: list[str]) -> tuple[int, str]:
    try:
        r = subprocess.run(["/usr/bin/codesign", *args], capture_output=True, timeout=CODESIGN_TIMEOUT,
                           stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"})
        return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -9, "timeout"
    except OSError as exc:
        return -1, str(exc)


def apple_signed(path: str) -> bool | None:
    """True = valid Apple signature (part of macOS / an Apple app); None = could not check."""
    rc, out = _codesign(["--verify", "-R=anchor apple", path])
    if rc == 0:
        return True
    if rc in (-9, -1):
        return None
    return False


def developer_signer(path: str) -> str | None:
    """Name of the known developer when `path` carries a valid, non-revoked Developer ID / App Store signature.
    "?" when codesign could not answer (treated like a known developer: do not move it)."""
    rc, out = _codesign(["--verify", "--strict", path])
    if rc in (-9, -1):
        return "?"
    if rc != 0:
        return None                            # unsigned, ad-hoc, broken or revoked: not a known developer
    rc, out = _codesign(["-dv", "--verbose=2", path])
    if rc in (-9, -1):
        return "?"
    for line in out.splitlines():
        if line.startswith("Authority="):
            auth = line.split("=", 1)[1].strip()
            if auth.startswith(("Developer ID Application:", "Apple Mac OS Application Signing", "Apple Distribution:",
                                "Software Signing", "Apple iPhone OS Application Signing")):
                return auth.split(":", 1)[-1].strip() or auth
            return None                        # the first Authority is the leaf; anything else is not enough
    return None


def protected_file(path: str) -> str | None:
    """Reason why `path` must not be moved to quarantine automatically, else None."""
    why = system_path(path)
    if why:
        return why
    a = apple_signed(path)
    if a is None:
        return "nie udało się sprawdzić podpisu"
    if a:
        return "podpisany przez Apple"
    dev = developer_signer(path)
    if dev == "?":
        return "nie udało się sprawdzić podpisu"
    if dev:
        return f"podpisany przez znanego producenta ({dev}) – decyzja należy do Ciebie"
    return None


# ------------------------------------------------------------------ processes

def _psutil():
    try:
        import psutil
        return psutil
    except ImportError:
        return None


def _own_lineage() -> set[int]:
    pids = {os.getpid()}
    ps = _psutil()
    if ps:
        try:
            pids.update(p.pid for p in ps.Process().parents())
        except Exception:  # noqa: BLE001
            pass
    return pids


def critical_process(proc, allow_interpreter: bool = False, allow_system: bool = False) -> str | None:
    """Reason why this psutil.Process must never be stopped, else None.

    allow_interpreter: a macOS interpreter (sh, zsh, python3, osascript …) may be stopped – it is running the
    attacker's script or is the remote shell itself; any other macOS program never is. allow_system: a child
    of a stopped malicious process (curl, zip … doing its work) may be stopped although it is a macOS tool."""
    try:
        pid = proc.pid
        if pid <= 1 or pid in _own_lineage():
            return "proces systemowy lub Cerbera"
        if proc.uids().real != os.getuid():
            return "proces innego użytkownika lub systemu"
        name = proc.name() or ""
        exe = proc.exe() or ""
    except Exception as exc:  # noqa: BLE001
        return f"brak dostępu do procesu ({type(exc).__name__})"
    if name in CRITICAL_NAMES or os.path.basename(exe) in CRITICAL_NAMES:
        return f"ważny proces sesji ({name})"
    if not exe:
        return "nieznany plik programu"
    try:
        from .envscan.live import is_cerber_process
        procs = {}
        cur = proc
        for _ in range(14):
            procs[cur.pid] = {"pid": cur.pid, "ppid": cur.ppid(), "exe": cur.exe(), "cmdline": cur.cmdline()}
            par = cur.parent()
            if par is None or par.pid <= 1:
                break
            cur = par
        if is_cerber_process(pid, procs):
            return "proces Cerbera"
    except Exception:  # noqa: BLE001
        pass
    why = system_path(exe)
    if why == "plik systemu macOS":
        from .envscan.patterns import interpreter_of
        if allow_system or (allow_interpreter and interpreter_of(exe)):
            return None
    return why


def processes_running(path: str) -> list:
    """Processes executing `path`: its program file, or an interpreter running it as a script."""
    ps = _psutil()
    if ps is None:
        return []
    from .envscan.patterns import analyze_command, interpreter_of
    target = _real(path)
    out = []
    for p in ps.process_iter(["pid", "exe", "cmdline"]):
        exe = p.info.get("exe") or ""
        try:
            if exe and _real(exe) == target:
                out.append(p)
                continue
            if exe and interpreter_of(exe):
                ci = analyze_command([str(a) for a in p.info.get("cmdline") or []])
                if ci.script and _real(ci.script if ci.script.startswith("/") else
                                       os.path.join(p.cwd(), ci.script)) == target:
                    out.append(p)
        except Exception:  # noqa: BLE001
            continue
    return out


def stop_processes(procs: list, expect_exe: str | None = None) -> tuple[list, list]:
    """Freeze every process (and its children), re-check it is still the same program, then kill.
    Returns ([{pid, name}], [refusal reasons])."""
    ps = _psutil()
    if ps is None:
        return [], ["brak psutil"]
    frozen, refused = [], []
    for p in procs:
        why = critical_process(p, allow_interpreter=True)
        if why:
            refused.append(f"pid {p.pid}: {why}")
            continue
        try:
            created = p.create_time()
            p.suspend()
        except Exception as exc:  # noqa: BLE001
            refused.append(f"pid {p.pid}: {type(exc).__name__}")
            continue
        frozen.append((p, created))
        try:
            for c in p.children(recursive=True):
                if critical_process(c, allow_system=True) is None:
                    c.suspend()
                    frozen.append((c, c.create_time()))
        except Exception:  # noqa: BLE001
            pass
    stopped = []
    main = frozen[0][0] if frozen else None
    for p, created in frozen:
        try:
            same = abs(p.create_time() - created) < 0.01
            if same and expect_exe and p is main:
                same = _real(p.exe() or "") == _real(expect_exe)
            if not same:
                p.resume()
                refused.append(f"pid {p.pid}: proces się zmienił – nie zatrzymuję")
                continue
            name = p.name()
            p.kill()
            stopped.append({"pid": p.pid, "name": name})
        except ps.NoSuchProcess:
            stopped.append({"pid": p.pid, "name": "?"})
        except Exception as exc:  # noqa: BLE001
            refused.append(f"pid {p.pid}: {type(exc).__name__}")
            try:
                p.resume()
            except Exception:  # noqa: BLE001
                pass
    if stopped:
        ps.wait_procs([p for p, _ in frozen], timeout=KILL_WAIT_S)
    return stopped, refused


# ------------------------------------------------------------------ the defender

class Defender:
    """Used by the background watcher. `kill` = stop processes too (active defense); `quarantine` alone is the
    older automatic quarantine. `emit(dict)` receives every action for the app and the log."""

    def __init__(self, emit, quarantine: bool = True, kill: bool = False):
        self.emit = emit
        self.quarantine = quarantine
        self.kill = kill
        self.lock = threading.Lock()
        self.actions: list[float] = []
        self.limit_noted = 0.0

    @property
    def enabled(self) -> bool:
        return self.quarantine or self.kill

    def _budget(self) -> bool:
        now = time.time()
        with self.lock:
            self.actions = [t for t in self.actions if now - t < WINDOW_S]
            if len(self.actions) >= MAX_ACTIONS:
                return False
            self.actions.append(now)
            return True

    def _limit(self, what: str, **extra) -> dict | None:
        """Over the limit: say so once per window (a scan with 500 hits must not flood the feed)."""
        now = time.time()
        with self.lock:
            if now - self.limit_noted < WINDOW_S:
                return None
            self.limit_noted = now
        return self._report("skipped", "Limit automatycznych działań",
                            f"{what}: dalsze zagrożenia z ostatnich {int(WINDOW_S // 60)} min tylko zgłaszam – "
                            "zdecyduj sam", **extra)

    def _report(self, action: str, title: str, detail: str, **extra) -> dict:
        ev = {"ev": "watch_defense", "action": action, "title": title, "detail": detail,
              "time": time.strftime("%Y-%m-%d %H:%M:%S"), **extra}
        self.emit(ev)
        return ev

    def _quarantine(self, path: str, result: dict) -> tuple[str | None, str | None]:
        from .quarantine import quarantine_file
        try:
            return quarantine_file(path, result), None
        except (OSError, ValueError) as exc:
            return None, str(getattr(exc, "strerror", None) or exc)

    def on_malicious_file(self, path: str, result: dict) -> dict:
        """A file scan said MALICIOUS. → {quarantined, quarantine_error, stopped, skipped}."""
        out: dict = {"quarantined": None, "quarantine_error": None, "stopped": [], "skipped": None}
        if not self.enabled:
            return out
        why = protected_file(path)
        if why:
            out["skipped"] = why
            self._report("skipped", f"Nie ruszam: {os.path.basename(path)}", why, path=path)
            return out
        if not self._budget():
            out["skipped"] = "limit automatycznych działań – zdecyduj sam"
            self._limit(os.path.basename(path), path=path)
            return out
        procs = processes_running(path) if self.kill else []
        frozen_first: list = []
        if procs:                              # freeze before the file disappears under it
            for p in procs:
                if critical_process(p, allow_interpreter=True) is None:
                    try:
                        p.suspend()
                        frozen_first.append(p)
                    except Exception:  # noqa: BLE001
                        pass
        if self.quarantine or self.kill:
            out["quarantined"], out["quarantine_error"] = self._quarantine(path, result)
        stopped, refused = stop_processes(frozen_first) if frozen_first else ([], [])
        out["stopped"] = stopped
        name = os.path.basename(path)
        parts = []
        if out["quarantined"]:
            parts.append("przeniesiono do kwarantanny")
        elif out["quarantine_error"]:
            parts.append(f"kwarantanna nieudana: {out['quarantine_error']}")
        if stopped:
            parts.append(f"zatrzymano {len(stopped)} {'proces' if len(stopped) == 1 else 'procesy'}")
        if refused:
            parts.append("pominięto: " + "; ".join(refused[:3]))
        self._report("quarantined" if out["quarantined"] else "failed",
                     f"Zneutralizowano: {name}" if out["quarantined"] else f"Nie udało się zneutralizować: {name}",
                     ", ".join(parts) or "brak działań", path=path, qid=out["quarantined"],
                     verdict=result.get("verdict"), primary=result.get("primary"),
                     pids=[s["pid"] for s in stopped])
        return out

    def on_live_attack(self, item: dict) -> dict | None:
        """A network guard event (already cleaned by watch.clean_net_item). Acts only on certain attacks."""
        if not self.kill:
            return None
        if item.get("severity") != "malicious" or item.get("confidence") != "high" or \
                item.get("attack") not in ACT_ATTACKS:
            return None
        pid, exe = item.get("pid"), item.get("exe")
        ps = _psutil()
        if ps is None or not isinstance(pid, int) or pid <= 1 or not isinstance(exe, str) or not exe.startswith("/"):
            return None
        try:
            proc = ps.Process(pid)
            if _real(proc.exe() or "") != _real(exe):
                return None                    # the pid is already another program
        except Exception:  # noqa: BLE001
            return None
        why = critical_process(proc, allow_interpreter=True)
        if why is None:
            from .envscan.patterns import interpreter_of
            if not interpreter_of(exe):        # an interpreter runs the attacker's code whoever signed it
                dev = developer_signer(exe)
                if dev:
                    why = ("nie udało się sprawdzić podpisu" if dev == "?" else
                           f"podpisany przez znanego producenta ({dev}) – decyzja należy do Ciebie")
        title = item.get("title") or "atak"
        if why:
            return self._report("skipped", "Nie zatrzymuję procesu", f"{title}: {why}", pid=pid)
        if not self._budget():
            return self._limit(title, pid=pid)
        stopped, refused = stop_processes([proc], expect_exe=exe)
        qid = qerr = None
        target = item.get("target")
        if isinstance(target, str) and target.startswith("/") and os.path.isfile(target) and \
                not os.path.islink(target):
            if protected_file(target) is None:
                qid, qerr = self._quarantine(target, {"verdict": "MALICIOUS", "primary": item.get("signals", [None])[0]
                                                      if item.get("signals") else None,
                                                      "detections": [{"name": s} for s in item.get("signals") or []]})
        parts = []
        if stopped:
            parts.append(f"zatrzymano {', '.join(f'{s['name']} (pid {s['pid']})' for s in stopped[:4])} – "
                         "połączenia zerwane")
        if qid:
            parts.append(f"{os.path.basename(target)} w kwarantannie")
        elif qerr:
            parts.append(f"kwarantanna nieudana: {qerr}")
        if refused:
            parts.append("pominięto: " + "; ".join(refused[:3]))
        return self._report("stopped" if stopped else "failed",
                            "Atak przerwany" if stopped else "Nie udało się przerwać ataku",
                            f"{title}. " + ", ".join(parts), pid=pid, path=target if qid else None, qid=qid,
                            pids=[s["pid"] for s in stopped])

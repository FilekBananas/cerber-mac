"""Keyboard event taps: which programs can see keystrokes (like Objective-See's ReiKey).

`CGGetEventTapList` (CoreGraphics, via ctypes) lists every Quartz event tap on this Mac. A tap whose event mask
includes kCGEventKeyDown / kCGEventKeyUp / kCGEventFlagsChanged (or every event) receives keystrokes; that is how
hotkey tools, remappers and accessibility utilities work – and how keyloggers work. Each tapping pid is resolved
to its executable (proc_pidpath) and judged with the shared signing / provenance helpers:

    Apple-signed program                                      inventory only, never a finding
    Developer ID / App Store, notarised, normal location      INFO line ("Program X może odczytywać ...")
    Homebrew-style tool or a local build (ad-hoc by design)   LOW (same exemption as signing_signals)
    unsigned / ad-hoc / not notarised / odd location          SUSPICIOUS (one capped MEDIUM signal)
    script interpreter (python, osascript, ...)               judged by the script it runs

A listen-only tap only observes; an active filter can also change or swallow keystrokes (scored a bit higher).
This collector never decides "malicious" on its own: the program's signature and location are also scored by the
process collector, and correlation adds things up.

Sandbox: the `env` Seatbelt profile denies com.apple.windowserver*, so the call fails inside it (mach error
0x10000003). The unsandboxed parent runs `python -m cerber.envscan.eventtaps` (the same read-only call, nothing
else) before starting the sandboxed scan and leaves the JSON in $CERBER_PRECOMPUTED/event_taps.json.
Read-only: lists taps and reads metadata; never touches a process.
"""
from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import sys

from ..core import Confidence
from .model import Signal
from .patterns import classify_path, interpreter_of, path_signals
from .provenance import bundle_of, dev_context, is_local_build, origin, script_of
from .util import EnvContext, run, world_writable

T = "Heur:Env.EventTap"
CG_PATH = "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"
LIBPROC_PATH = "/usr/lib/libproc.dylib"
PRECOMPUTED_NAME = "event_taps.json"
MAX_TAPS = 1024
PROC_PIDPATHINFO_MAXSIZE = 4 * 1024             # sys/proc_info.h: 4 * MAXPATHLEN

# CoreGraphics/CGEventTypes.h: kCGEventKeyDown = NX_KEYDOWN (10), kCGEventKeyUp = NX_KEYUP (11),
# kCGEventFlagsChanged = NX_FLAGSCHANGED (12) (IOKit/hidsystem/IOLLEvent.h); kCGEventMaskForAllEvents = ~0
KEY_DOWN, KEY_UP, FLAGS_CHANGED = 10, 11, 12
KEYBOARD_MASK = (1 << KEY_DOWN) | (1 << KEY_UP) | (1 << FLAGS_CHANGED)
ALL_EVENTS = (1 << 64) - 1
OPT_LISTEN_ONLY = 0x1                           # kCGEventTapOptionListenOnly; kCGEventTapOptionDefault = 0 (filter)
TAP_POINT_PL = {0: "HID (przed sesją użytkownika)", 1: "sesja użytkownika", 2: "sesja (zdarzenia z adnotacjami)"}
MODE_PL = {"listen_only": "tylko nasłuch (listen-only): widzi naciśnięcia klawiszy, ale nie może ich zmieniać",
           "active_filter": "aktywny filtr: może odczytywać, zmieniać i blokować naciśnięcia klawiszy"}
SIGNER_PL = {"apple": "Apple", "adhoc": "ad-hoc, bez tożsamości dewelopera", "unsigned": "brak podpisu",
             "development": "certyfikat deweloperski", "error": "nie sprawdzono", "missing": "brak pliku",
             "notcode": "to nie jest program"}
# where a program that reads the keyboard has no business running from (path_signals names)
ODD_LOCATIONS = ("TempPath", "SharedPath", "TrashPath", "HiddenFile", "HiddenPath", "RandomDir", "VolumePath")
SUSPICIOUS_LEAD = {"NotNotarized": "program bez notaryzacji Apple", "OddLocation": "program z nietypowego miejsca",
                   "Script": "skrypt spoza folderu projektu", "Script.OddLocation": "skrypt z nietypowego miejsca"}
# CGError (CGError.h) codes worth explaining; anything >= 0x10000000 is a Mach IPC error from the WindowServer link
CG_ERRORS = {1000: "kCGErrorFailure", 1001: "kCGErrorIllegalArgument", 1002: "kCGErrorInvalidConnection",
             1004: "kCGErrorCannotComplete", 1010: "kCGErrorInvalidOperation", 1011: "kCGErrorNoneAvailable"}


class CGEventTapInformation(ctypes.Structure):
    """struct __CGEventTapInformation from CoreGraphics/CGEventTypes.h (macOS SDK). Natural alignment gives
    48 bytes on arm64 and x86_64: 4 bytes of padding before `eventsOfInterest`, 3 after `enabled` (checked
    against offsetof() in a C build with the SDK; tests assert the offsets)."""
    _fields_ = [
        ("eventTapID", ctypes.c_uint32),
        ("tapPoint", ctypes.c_uint32),              # CGEventTapLocation: CF_ENUM(uint32_t)
        ("options", ctypes.c_uint32),               # CGEventTapOptions: CF_ENUM(uint32_t)
        ("eventsOfInterest", ctypes.c_uint64),      # CGEventMask: uint64_t
        ("tappingProcess", ctypes.c_int32),         # pid_t
        ("processBeingTapped", ctypes.c_int32),     # pid_t, 0 = not a per-process tap
        ("enabled", ctypes.c_bool),
        ("minUsecLatency", ctypes.c_float),
        ("avgUsecLatency", ctypes.c_float),
        ("maxUsecLatency", ctypes.c_float),
    ]


# --------------------------------------------------------------------------- enumeration (ctypes)

def is_keyboard_mask(mask: int | str) -> bool:
    """mask: CGEventMask as int or as the "0x…" string the snapshot stores (JSON-safe for 64-bit values)."""
    try:
        mask = (int(mask, 16) if isinstance(mask, str) else int(mask)) & ALL_EVENTS
    except (TypeError, ValueError):
        return False
    return mask == ALL_EVENTS or bool(mask & KEYBOARD_MASK)


def _load_cg():
    """CGError CGGetEventTapList(uint32_t max, CGEventTapInformation *list, uint32_t *count)."""
    fn = ctypes.CDLL(CG_PATH).CGGetEventTapList
    fn.argtypes = [ctypes.c_uint32, ctypes.POINTER(CGEventTapInformation), ctypes.POINTER(ctypes.c_uint32)]
    fn.restype = ctypes.c_int32
    return fn


def _error_text(err: int) -> str:
    name = CG_ERRORS.get(err)
    if err & 0xFFFFFFFF >= 0x10000000:
        name = "błąd Mach: brak połączenia z WindowServerem"
    return f"CGGetEventTapList zwrócił błąd {err} (0x{err & 0xFFFFFFFF:x}{', ' + name if name else ''})"


def _tap_dict(t: CGEventTapInformation) -> dict:
    mask = int(t.eventsOfInterest) & ALL_EVENTS
    return {"id": int(t.eventTapID), "tap_point": int(t.tapPoint), "options": int(t.options),
            "mode": "listen_only" if t.options & OPT_LISTEN_ONLY else "active_filter",
            "mask": f"0x{mask:016x}", "keyboard": is_keyboard_mask(mask), "pid": int(t.tappingProcess),
            "target_pid": int(t.processBeingTapped), "enabled": bool(t.enabled),
            "latency_us": [round(float(x), 1) for x in (t.minUsecLatency, t.avgUsecLatency, t.maxUsecLatency)]}


def list_taps(fn=None) -> tuple[list[dict], str | None]:
    """Every event tap as a dict. `fn` replaces CGGetEventTapList (tests). Never raises."""
    try:
        fn = fn or _load_cg()
        count = ctypes.c_uint32(0)
        err = int(fn(0, None, ctypes.pointer(count)))
        if err:
            return [], _error_text(err)
        if not count.value:
            return [], None
        cap = min(count.value + 16, MAX_TAPS)      # headroom: taps created between the two calls
        buf = (CGEventTapInformation * cap)()
        got = ctypes.c_uint32(0)
        err = int(fn(cap, buf, ctypes.pointer(got)))
        if err:
            return [], _error_text(err)
        return [_tap_dict(buf[i]) for i in range(min(got.value, cap))], None
    except (OSError, AttributeError, TypeError, ValueError) as e:
        return [], f"CoreGraphics niedostępne ({type(e).__name__}: {e})"


_proc_pidpath = None


def pid_path(pid: int) -> str | None:
    """Executable of a pid via libproc's proc_pidpath (the call psutil uses too)."""
    global _proc_pidpath
    if pid <= 0:
        return None
    try:
        if _proc_pidpath is None:
            f = ctypes.CDLL(LIBPROC_PATH, use_errno=True).proc_pidpath
            f.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
            f.restype = ctypes.c_int
            _proc_pidpath = f
        buf = ctypes.create_string_buffer(PROC_PIDPATHINFO_MAXSIZE)
        n = _proc_pidpath(int(pid), buf, PROC_PIDPATHINFO_MAXSIZE)
        return os.fsdecode(buf.raw[:n]) if n > 0 else None
    except (OSError, AttributeError, ValueError):
        return None


def snapshot(fn=None) -> dict:
    """{ok, error, taps: [... + "path"]} – what the parent hands to the sandboxed scan."""
    taps, err = list_taps(fn)
    for t in taps:
        t["path"] = pid_path(t["pid"])
    return {"ok": err is None, "error": err, "taps": taps}


def precompute(pre_dir: str, timeout: float = 20.0) -> None:
    """Parent side (unsandboxed): list the taps in a short-lived child (CoreGraphics stays out of the backend,
    a hung WindowServer cannot block it) and leave the JSON for the sandboxed collector. Never raises."""
    try:
        from ..sandbox import python_env
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C",
               "HOME": os.path.expanduser("~"), **python_env()}
        p = subprocess.run([sys.executable, "-m", "cerber.envscan.eventtaps"], capture_output=True, timeout=timeout,
                           env=env, cwd="/", stdin=subprocess.DEVNULL, check=False, close_fds=True)
        data = json.loads(p.stdout.decode("utf-8", "replace") or "null")
        if not isinstance(data, dict):
            raise ValueError(f"kod wyjścia {p.returncode}")
    except subprocess.TimeoutExpired:
        data = {"ok": False, "error": f"odczyt listy przekroczył {timeout:.0f} s", "taps": []}
    except Exception as e:  # noqa: BLE001 - the env scan must start anyway
        data = {"ok": False, "error": f"proces nadrzędny nie odczytał listy ({type(e).__name__}: {e})", "taps": []}
    path = os.path.join(pre_dir, PRECOMPUTED_NAME)
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, path)
    except OSError:
        pass


def _load() -> tuple[dict, str]:
    pre = os.environ.get("CERBER_PRECOMPUTED")
    if pre:
        try:
            with open(os.path.join(pre, PRECOMPUTED_NAME)) as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data, "parent"
        except (OSError, ValueError):
            pass
    return snapshot(), "direct"


# --------------------------------------------------------------------------- judgement

def _program_name(exe: str) -> str:
    apps = re.findall(r"([^/]+)\.app(?=/)", exe)
    base = os.path.basename(exe)
    if not apps:
        return base
    return apps[0] if len(apps) == 1 else f"{apps[-1]} ({apps[0]})"


def _signer_pl(si) -> str:
    if si is None:
        return "nie sprawdzono"
    if si.status in ("devid", "appstore"):
        return si.signer
    if si.status == "other":
        return f"nieznany urząd ({si.authority or '?'})"
    return SIGNER_PL.get(si.status, si.status)


def _notarized(exe: str, si) -> bool | None:
    """Developer ID: hardened runtime ⇒ notarised (provenance convention); otherwise ask Gatekeeper once."""
    if si.runtime:
        return True
    app = bundle_of(exe)
    argv = (["/usr/sbin/spctl", "--assess", "--type", "execute", "-vv", app] if app else
            ["/usr/sbin/spctl", "--assess", "-vv", "--type", "open", "--context", "context:primary-signature", exe])
    r = run(argv, timeout=10)
    m = re.search(r"^source=(.+)$", r.out + "\n" + r.err, re.M)
    if r.timed_out or r.missing or not m:
        return None
    return m.group(1).strip() == "Notarized Developer ID"


def _odd_location(path: str, home: str, trusted: bool) -> list[str]:
    reasons = [s.description for s in path_signals(path, T, "program", home)
               if s.name.rsplit(".", 1)[-1] in ODD_LOCATIONS
               and not (trusted and s.name.endswith("VolumePath"))]    # signed apps run from their DMG
    if world_writable(path):
        reasons.append("program: plik zapisywalny dla wszystkich (każdy może go podmienić)")
    return reasons


def _assess(ctx: EnvContext, exe: str | None, pid: int, cmdline: list | None, home: str) -> dict:
    """kind: apple | trusted | tool | suspicious | unknown, + name, signer, reasons, signal name suffix."""
    if not exe:
        return {"kind": "unknown", "name": f"pid {pid}", "signer": "nie ustalono", "reasons": [], "sig": "UnknownProcess"}
    interp = interpreter_of(exe)
    pi = classify_path(exe, home)
    si = ctx.sign(exe) if interp or not pi.has("apple") else None
    apple = pi.has("apple") or bool(si and si.is_apple)
    out = {"name": _program_name(exe), "signer": "Apple" if apple else _signer_pl(si), "sign": si, "reasons": []}
    if interp:
        # the program that reads the keyboard is the script; the (often Apple-signed) interpreter says nothing
        script = script_of(cmdline)
        out["interpreter"] = interp
        if not script:
            return {**out, "kind": "tool", "sig": "Interpreter",
                    "reasons": [f"interpreter {interp}: nie udało się ustalić, jaki kod wykonuje"]}
        out.update(name=os.path.basename(script), script=script)
        odd = _odd_location(script, home, trusted=False)
        if odd:
            return {**out, "kind": "suspicious", "sig": "Script.OddLocation", "reasons": odd}
        if dev_context(exe, cmdline, si, home):
            return {**out, "kind": "tool", "sig": "Script.Project",
                    "reasons": [f"skrypt {interp} z folderu projektu lub pakietu"]}
        return {**out, "kind": "suspicious", "sig": "Script",
                "reasons": [f"skrypt {interp} (kod bez podpisu) spoza folderu projektu lub pakietu"]}
    if apple:
        return {**out, "kind": "apple"}
    odd = _odd_location(exe, home, trusted=si.trusted)
    if si.trusted:
        notarized = True if si.status == "appstore" else _notarized(exe, si)
        out["notarized"] = notarized
        if odd:
            return {**out, "kind": "suspicious", "sig": "OddLocation", "reasons": odd}
        if notarized is False:
            return {**out, "kind": "suspicious", "sig": "NotNotarized",
                    "reasons": [f"program podpisany ({si.signer}), ale bez notaryzacji Apple"]}
        return {**out, "kind": "trusted", "sig": ""}
    weak = {"unsigned": ("Unsigned", "program: brak podpisu kodu"),
            "adhoc": ("AdhocSigned", "program: podpisany tylko ad-hoc (bez tożsamości dewelopera)"),
            "development": ("DevSigned", "program: podpisany certyfikatem deweloperskim (bez notaryzacji)"),
            "other": ("UnknownSigner", f"program: podpisany przez nieznany urząd ({si.authority or '?'})")}
    if si.status not in weak:                       # codesign failed / disabled / file gone
        return {**out, "kind": "tool", "sig": "UnverifiedSignature",
                "reasons": [f"nie udało się sprawdzić podpisu programu ({si.error or si.status})"]}
    sig, why = weak[si.status]
    if not odd and pi.has("pkgmgr"):
        return {**out, "kind": "tool", "sig": "PackageManager",
                "reasons": [f"narzędzie z menedżera pakietów (np. Homebrew), {why.split(': ', 1)[1]}"]}
    if not odd and is_local_build(exe, si.flags, si.status, home):
        return {**out, "kind": "tool", "sig": "LocalBuild", "reasons": ["program zbudowany na tym Macu (linker-signed)"]}
    return {**out, "kind": "suspicious", "sig": sig, "reasons": [why] + odd}


def _signal(a: dict, mode: str, taps: list[dict]) -> Signal:
    kind, reasons = a["kind"], a["reasons"]
    active = mode == "active_filter"
    flags = []
    if not any(t["enabled"] for t in taps):
        flags.append("obecnie wyłączony")
    if all(t["target_pid"] for t in taps):
        flags.append("tylko zdarzenia wybranych procesów")
    tail = f"; {MODE_PL[mode]}" + (f" ({', '.join(flags)})" if flags else "")
    if kind == "trusted":
        return Signal(f"{T}.Keyboard", 4 if active else 2, Confidence.INFO,
                      f"program podpisany przez {a['signer']} ma podsłuch zdarzeń klawiatury (event tap){tail}",
                      [a.get("exe") or ""])
    if kind in ("tool", "unknown"):
        why = reasons[0] if reasons else "nie ustalono programu, który założył podsłuch"
        return Signal(f"{T}.Keyboard.{a['sig']}", 18 if active else 12, Confidence.LOW,
                      f"podsłuch zdarzeń klawiatury (event tap): {why}{tail}", reasons[:3] or [a["name"]])
    # suspicious: one capped MEDIUM signal – the item reads as "suspicious", never "malicious" from this alone
    score = min(55, (45 if active else 35) + 5 * (len(reasons) - 1))
    lead = SUSPICIOUS_LEAD.get(a["sig"], "program bez podpisu dewelopera")
    desc = f"{lead} może odczytywać naciśnięcia klawiszy: {'; '.join(reasons[:3])}{tail}"
    if a["sig"] in ("Unsigned", "AdhocSigned"):
        desc += " – tak działają też rejestratory klawiszy (keyloggery); sprawdź, czy znasz ten program"
    return Signal(f"{T}.Keyboard.{a['sig']}", score, Confidence.MEDIUM, desc, reasons[:3])


def collect_event_taps(ctx: EnvContext) -> None:
    ctx.progress("programy odczytujące klawiaturę (event taps)")
    data, source = _load()
    if not data.get("ok"):
        err = str(data.get("error") or "nieznany błąd")
        if source == "direct" and os.environ.get("CERBER_SANDBOX"):
            err += "; sandbox blokuje WindowServer, a proces nadrzędny nie przekazał listy"
        ctx.limit(f"nie sprawdzono, które programy mogą odczytywać naciśnięcia klawiszy (event taps): {err}")
        return
    taps = [t for t in data.get("taps") or [] if isinstance(t, dict) and isinstance(t.get("pid"), int)]
    home = ctx.homes[0].home if ctx.homes else os.path.expanduser("~")
    procs = None
    groups: dict[str, dict] = {}
    for t in taps:
        t["keyboard"] = is_keyboard_mask(t.get("mask") or 0)
        t["mode"] = "listen_only" if t.get("mode") == "listen_only" else "active_filter"
        t["enabled"], t["target_pid"] = bool(t.get("enabled", True)), int(t.get("target_pid") or 0)
        if not t["keyboard"]:
            continue
        exe = t.get("path") if isinstance(t.get("path"), str) and t["path"].startswith("/") else None
        if exe is None or interpreter_of(exe):
            if procs is None:
                from .processes import snapshot as proc_snapshot
                procs = proc_snapshot(ctx)
            exe = exe or (procs.get(t["pid"]) or {}).get("exe")
        g = groups.setdefault(exe or f"pid:{t['pid']}", {"exe": exe, "pids": [], "taps": []})
        if t["pid"] not in g["pids"]:
            g["pids"].append(t["pid"])
        g["taps"].append(t)
    ctx.codesign.prefetch([g["exe"] for g in groups.values() if g["exe"]])
    kinds: dict[str, int] = {}
    for _, g in sorted(groups.items()):
        exe, pid = g["exe"], g["pids"][0]
        cmdline = ((procs or {}).get(pid) or {}).get("cmdline")
        a = _assess(ctx, exe, pid, cmdline, home)
        a["exe"] = exe
        kinds[a["kind"]] = kinds.get(a["kind"], 0) + 1
        mode = "active_filter" if any(t["mode"] == "active_filter" for t in g["taps"]) else "listen_only"
        for t in g["taps"]:
            t["kind"] = a["kind"]
        if a["kind"] == "apple":
            continue
        details = {"exe": exe, "pids": g["pids"][:20], "mode": mode, "kind": a["kind"], "signer": a["signer"],
                   "taps": [{k: t.get(k) for k in ("id", "tap_point", "mode", "mask", "enabled", "target_pid",
                                                   "latency_us")} for t in g["taps"][:10]],
                   "tap_points": sorted({TAP_POINT_PL.get(t.get("tap_point"), str(t.get("tap_point")))
                                         for t in g["taps"]})}
        if a.get("sign") is not None:
            details["signature"] = a["sign"].to_dict()
        for k in ("notarized", "interpreter", "script"):
            if k in a:
                details[k] = a[k]
        if exe and a["kind"] != "unknown":
            org = origin(a.get("script") or exe, a.get("sign") if not a.get("script") else None, home)
            details["origin"] = org
            details["origin_label"] = org.get("label")
        sig = _signal(a, mode, g["taps"])
        if a["kind"] == "suspicious" and details.get("origin_label"):
            sig.evidence.append(f"pochodzenie: {details['origin_label']}")
        if a.get("script"):         # the interpreter's signature (often Apple's) says nothing about the script
            title = f"Skrypt {a['name']} może odczytywać naciśnięcia klawiszy (bez podpisu, uruchamia go " \
                    f"{a['interpreter']})"
        else:
            title = f"{'Proces' if a['kind'] == 'unknown' else 'Program'} {a['name']} może odczytywać " \
                    f"naciśnięcia klawiszy (podpis: {a['signer']})"
        ctx.add_finding("keyboard", title, a.get("script") or exe or f"pid {pid}", [sig], details, allow_zero=True)
        target = a.get("script") or exe
        if target and a["kind"] in ("suspicious", "tool", "trusted"):
            ctx.add_target(target, "program reading the keyboard (event tap)", 2 if a["kind"] == "suspicious" else 1)
    ctx.inventory["event_taps"] = [{k: t.get(k) for k in ("id", "pid", "path", "keyboard", "mode", "tap_point",
                                                         "enabled", "kind")} for t in taps]
    ctx.inventory["event_tap_summary"] = {"total": len(taps), "keyboard": sum(1 for t in taps if t["keyboard"]),
                                          "keyboard_programs": kinds, "source": source}


if __name__ == "__main__":          # parent-side helper for the sandboxed scan (see precompute)
    print(json.dumps(snapshot()))

"""Tests for the keyboard event-tap inventory (cerber.envscan.eventtaps, modelled on ReiKey).

Offline and deterministic: CGGetEventTapList is replaced by a fake that fills the ctypes buffer with
CGEventTapInformation structs, pid -> path and codesign results are fixed tables, nothing is executed.

    python -m unittest tests.test_event_taps -v
"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from cerber.envscan import COLLECTORS  # noqa: E402
from cerber.envscan import eventtaps as et  # noqa: E402
from cerber.envscan.util import CmdResult, EnvContext, SignInfo, UserHome  # noqa: E402

KEYS = (1 << et.KEY_DOWN) | (1 << et.KEY_UP)
FLAGS_ONLY = 1 << et.FLAGS_CHANGED
MOUSE = (1 << 1) | (1 << 2) | (1 << 5)                 # left down/up, mouse moved
LISTEN, FILTER = 1, 0

APPLE = "/System/Library/CoreServices/TextInputMenuAgent"
DEVID = "/Applications/KeyTool.app/Contents/MacOS/KeyTool"
DEVID_OLD = "/Applications/OldKeys.app/Contents/MacOS/OldKeys"
DEVID_SHARED = "/Users/Shared/Helper.app/Contents/MacOS/Helper"
TMP = "/tmp/kbd"
HIDDEN = "/tmp/.x/kbd"
MOUSER = "/tmp/mouser"
BREW = "/opt/homebrew/Cellar/skhd/0.3.9/bin/skhd"
OSA = "/usr/bin/osascript"
SIGNS = {
    DEVID: SignInfo(DEVID, "devid", authority="Developer ID Application: Example Corp (ABCDE12345)",
                    team_id="ABCDE12345", runtime=True),
    DEVID_OLD: SignInfo(DEVID_OLD, "devid", authority="Developer ID Application: Old Corp (ZZZZZ99999)",
                        team_id="ZZZZZ99999", runtime=False),
    DEVID_SHARED: SignInfo(DEVID_SHARED, "devid", authority="Developer ID Application: Example Corp (ABCDE12345)",
                           team_id="ABCDE12345", runtime=True),
    TMP: SignInfo(TMP, "unsigned"),
    HIDDEN: SignInfo(HIDDEN, "unsigned"),
    MOUSER: SignInfo(MOUSER, "unsigned"),
    BREW: SignInfo(BREW, "adhoc", flags="0x20002(adhoc,linker-signed)"),
    OSA: SignInfo(OSA, "apple", authority="Software Signing", platform=True),
}


def tap(tid: int, pid: int, mask: int, options: int = FILTER, enabled: bool = True, target: int = 0):
    return et.CGEventTapInformation(eventTapID=tid, tapPoint=1, options=options, eventsOfInterest=mask,
                                    tappingProcess=pid, processBeingTapped=target, enabled=enabled,
                                    minUsecLatency=1.0, avgUsecLatency=2.0, maxUsecLatency=3.0)


def fake_cg(structs: list, err: int = 0):
    """Same contract as CGGetEventTapList(max, list, count): count-only call with max=0 / list=NULL."""
    calls = []

    def fn(max_n, buf, count_ptr):
        calls.append(max_n)
        if err:
            return err
        n = len(structs) if not max_n else min(max_n, len(structs))
        count_ptr.contents.value = n
        if buf is not None:
            for i, s in enumerate(structs[:n]):
                buf[i] = s
        return 0
    fn.calls = calls
    return fn


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = mock.patch.dict(os.environ, {"CERBER_PRECOMPUTED": "", "CERBER_SANDBOX": ""})
        self.env.start()
        self.addCleanup(self.env.stop)

    def ctx(self, procs: dict | None = None) -> EnvContext:
        ctx = EnvContext({"homes_override": [UserHome("tester", 501, self.tmp.name)]})
        ctx.codesign.info = lambda p: SIGNS.get(p, SignInfo(p, "missing"))      # no codesign runs
        ctx._procs = procs or {}                                                  # no psutil snapshot
        return ctx

    def scan(self, structs: list, paths: dict, procs: dict | None = None, spctl: str | None = None):
        ctx = self.ctx(procs)
        spctl_calls = []

        def fake_run(argv, timeout=20.0, env=None):
            spctl_calls.append(argv)
            return CmdResult(argv, 0, "", spctl or "", timed_out=spctl is None)
        with mock.patch.object(et, "_load_cg", return_value=fake_cg(structs)), \
                mock.patch.object(et, "pid_path", side_effect=lambda pid: paths.get(pid)), \
                mock.patch.object(et, "run", fake_run):
            et.collect_event_taps(ctx)
        ctx.spctl_calls = spctl_calls
        return ctx

    @staticmethod
    def by_loc(ctx) -> dict:
        return {f.location: f for f in ctx.findings}


class Layout(unittest.TestCase):
    def test_struct_matches_sdk_header(self):
        # offsetof() from a C build against CoreGraphics/CGEventTypes.h (arm64 and x86_64 alike)
        S = et.CGEventTapInformation
        self.assertEqual(ctypes.sizeof(S), 48)
        self.assertEqual({n: getattr(S, n).offset for n, _ in S._fields_},
                         {"eventTapID": 0, "tapPoint": 4, "options": 8, "eventsOfInterest": 16, "tappingProcess": 24,
                          "processBeingTapped": 28, "enabled": 32, "minUsecLatency": 36, "avgUsecLatency": 40,
                          "maxUsecLatency": 44})

    def test_keyboard_mask(self):
        for m in (1 << 10, 1 << 11, 1 << 12, KEYS, FLAGS_ONLY | MOUSE, et.ALL_EVENTS, f"0x{et.ALL_EVENTS:x}",
                  "0x0000000000000400"):
            self.assertTrue(et.is_keyboard_mask(m), m)
        for m in (0, MOUSE, 1 << 22, "0x0000000000000026", "junk", None):
            self.assertFalse(et.is_keyboard_mask(m), m)


class Enumeration(unittest.TestCase):
    def test_two_call_protocol_and_fields(self):
        fn = fake_cg([tap(7, 101, KEYS, LISTEN), tap(8, 404, MOUSE, FILTER, enabled=False, target=55)])
        taps, err = et.list_taps(fn)
        self.assertIsNone(err)
        self.assertEqual(fn.calls[0], 0)                       # count first, then fill
        self.assertGreaterEqual(fn.calls[1], 2)
        self.assertEqual([t["id"] for t in taps], [7, 8])
        a, b = taps
        self.assertEqual((a["pid"], a["mode"], a["keyboard"], a["enabled"]), (101, "listen_only", True, True))
        self.assertEqual(a["mask"], f"0x{KEYS:016x}")
        self.assertEqual((b["mode"], b["keyboard"], b["enabled"], b["target_pid"]), ("active_filter", False, False, 55))
        self.assertEqual(a["latency_us"], [1.0, 2.0, 3.0])
        json.dumps(taps)                                       # 64-bit masks stay JSON-safe

    def test_error_is_reported_not_raised(self):
        taps, err = et.list_taps(fake_cg([], err=0x10000003))
        self.assertEqual(taps, [])
        self.assertIn("WindowServer", err)
        taps, err = et.list_taps(fake_cg([]))
        self.assertEqual((taps, err), ([], None))


class Classification(Base):
    STRUCTS = [tap(1, 101, et.ALL_EVENTS, FILTER),            # Apple input agent, every event
               tap(2, 202, KEYS, LISTEN),                     # Developer ID, notarised (hardened runtime)
               tap(3, 303, KEYS | FLAGS_ONLY, FILTER),        # unsigned binary in /tmp
               tap(4, 404, MOUSE, FILTER)]                    # unsigned, but mouse only
    PATHS = {101: APPLE, 202: DEVID, 303: TMP, 404: MOUSER}

    def test_classification(self):
        ctx = self.scan(self.STRUCTS, self.PATHS)
        f = self.by_loc(ctx)
        self.assertEqual(set(f), {DEVID, TMP})                # no Apple finding, no mouse-only finding
        info = f[DEVID]
        self.assertEqual(info.severity, "info")
        self.assertEqual(info.category, "keyboard")
        self.assertEqual(info.title, "Program KeyTool może odczytywać naciśnięcia klawiszy "
                                     "(podpis: Developer ID: Example Corp (ABCDE12345))")
        self.assertIn("tylko nasłuch", info.detection.description)
        self.assertNotIn("keylogger", info.detection.description)
        self.assertLess(info.score, 10)
        bad = f[TMP]
        self.assertEqual(bad.severity, "suspicious")
        self.assertEqual(bad.detection.name, "Heur:Env.EventTap.Keyboard.Unsigned")
        self.assertGreaterEqual(bad.score, 35)
        self.assertIn("aktywny filtr", bad.detection.description)
        self.assertIn("katalogu tymczasowego", bad.detection.description)
        self.assertIn("keylogger", bad.detection.description)
        self.assertNotIn("attack", bad.details)                # never handed to active defense
        inv = {t["pid"]: t for t in ctx.inventory["event_taps"]}
        self.assertEqual(len(inv), 4)
        self.assertEqual(inv[101]["kind"], "apple")
        self.assertFalse(inv[404]["keyboard"])
        self.assertEqual(ctx.inventory["event_tap_summary"]["keyboard"], 3)
        self.assertEqual(ctx.inventory["event_tap_summary"]["keyboard_programs"],
                         {"apple": 1, "trusted": 1, "suspicious": 1})
        self.assertEqual(ctx.targets[TMP]["priority"], 2)
        self.assertEqual(ctx.spctl_calls, [])                  # hardened runtime: no Gatekeeper query

    def test_listen_only_scores_below_active_filter(self):
        a = self.by_loc(self.scan([tap(1, 303, KEYS, LISTEN)], {303: TMP}))[TMP]
        b = self.by_loc(self.scan([tap(1, 303, KEYS, FILTER)], {303: TMP}))[TMP]
        self.assertLess(a.score, b.score)
        self.assertEqual(a.severity, "suspicious")

    def test_suspicious_never_malicious(self):
        # unsigned + hidden + /tmp + world-writable: still one capped MEDIUM signal
        with mock.patch.object(et, "world_writable", return_value=True):
            f = self.by_loc(self.scan([tap(1, 9, et.ALL_EVENTS)], {9: HIDDEN}))[HIDDEN]
        self.assertEqual(f.severity, "suspicious")
        self.assertLessEqual(f.score, 55)

    def test_developer_id_odd_location_is_suspicious_but_no_keylogger_wording(self):
        f = self.by_loc(self.scan([tap(1, 5, KEYS)], {5: DEVID_SHARED}))[DEVID_SHARED]
        self.assertEqual(f.severity, "suspicious")
        self.assertEqual(f.detection.name, "Heur:Env.EventTap.Keyboard.OddLocation")
        self.assertNotIn("keylogger", f.detection.description)

    def test_not_notarized_developer_id(self):
        ctx = self.scan([tap(1, 6, KEYS)], {6: DEVID_OLD}, spctl="/Applications/OldKeys.app: accepted\nsource=Developer ID\n")
        f = self.by_loc(ctx)[DEVID_OLD]
        self.assertEqual(f.severity, "suspicious")
        self.assertEqual(f.detection.name, "Heur:Env.EventTap.Keyboard.NotNotarized")
        self.assertNotIn("keylogger", f.detection.description)
        self.assertEqual(ctx.spctl_calls[0][:2], ["/usr/sbin/spctl", "--assess"])
        ok = self.scan([tap(1, 6, KEYS)], {6: DEVID_OLD}, spctl="accepted\nsource=Notarized Developer ID\n")
        self.assertEqual(self.by_loc(ok)[DEVID_OLD].severity, "info")
        unknown = self.scan([tap(1, 6, KEYS)], {6: DEVID_OLD}, spctl=None)       # spctl timed out
        self.assertEqual(self.by_loc(unknown)[DEVID_OLD].severity, "info")

    def test_package_manager_tool_is_low(self):
        f = self.by_loc(self.scan([tap(1, 7, KEYS)], {7: BREW}))[BREW]
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.detection.name, "Heur:Env.EventTap.Keyboard.PackageManager")

    def test_apple_interpreter_is_judged_by_its_script(self):
        script = "/Users/Shared/kl.js"
        procs = {8: {"pid": 8, "exe": OSA, "cmdline": [OSA, "-l", "JavaScript", script]}}
        f = self.by_loc(self.scan([tap(1, 8, KEYS)], {8: OSA}, procs=procs))
        self.assertEqual(set(f), {script})
        self.assertEqual(f[script].severity, "suspicious")
        self.assertEqual(f[script].title, "Skrypt kl.js może odczytywać naciśnięcia klawiszy "
                                          "(bez podpisu, uruchamia go osascript)")
        self.assertEqual(f[script].detection.name, "Heur:Env.EventTap.Keyboard.Script.OddLocation")

    def test_unresolved_pid(self):
        f = self.by_loc(self.scan([tap(1, 99, KEYS)], {}))
        self.assertEqual(set(f), {"pid 99"})
        self.assertEqual(f["pid 99"].severity, "low")


class SandboxPath(Base):
    def test_parent_data_is_used_inside_the_sandbox(self):
        pre = os.path.join(self.tmp.name, "pre")
        os.makedirs(pre)
        fn = fake_cg([tap(3, 303, KEYS, FILTER), tap(4, 101, KEYS)])
        with mock.patch.object(et, "pid_path", side_effect={303: TMP, 101: APPLE}.get):
            data = et.snapshot(fn)
        with open(os.path.join(pre, et.PRECOMPUTED_NAME), "w") as fh:
            json.dump(data, fh)
        ctx = self.ctx()
        with mock.patch.dict(os.environ, {"CERBER_PRECOMPUTED": pre, "CERBER_SANDBOX": "env"}), \
                mock.patch.object(et, "_load_cg", side_effect=AssertionError("CoreGraphics called in the sandbox")):
            et.collect_event_taps(ctx)
        self.assertEqual(ctx.inventory["event_tap_summary"]["source"], "parent")
        self.assertEqual(self.by_loc(ctx)[TMP].severity, "suspicious")

    def test_sandbox_without_parent_data_degrades(self):
        ctx = self.ctx()
        with mock.patch.dict(os.environ, {"CERBER_SANDBOX": "env"}), \
                mock.patch.object(et, "_load_cg", return_value=fake_cg([], err=0x10000003)):
            et.collect_event_taps(ctx)
        self.assertEqual(ctx.findings, [])
        lines = [l for l in ctx.limitations if "event taps" in l]
        self.assertEqual(len(lines), 1)
        self.assertIn("nie sprawdzono", lines[0])
        self.assertIn("sandbox", lines[0])

    def test_missing_coregraphics_degrades(self):
        ctx = self.ctx()
        with mock.patch.object(et, "_load_cg", side_effect=OSError("no such image")):
            et.collect_event_taps(ctx)
        self.assertEqual(ctx.findings, [])
        self.assertTrue(any("CoreGraphics" in l for l in ctx.limitations))

    def test_precompute_writes_child_output_or_error(self):
        pre = os.path.join(self.tmp.name, "pre2")
        os.makedirs(pre)
        good = {"ok": True, "error": None, "taps": []}
        done = subprocess.CompletedProcess([], 0, json.dumps(good).encode(), b"")
        with mock.patch.object(et.subprocess, "run", return_value=done) as r:
            et.precompute(pre)
        argv = r.call_args[0][0]
        self.assertEqual(argv[1:], ["-m", "cerber.envscan.eventtaps"])
        with open(os.path.join(pre, et.PRECOMPUTED_NAME)) as fh:
            self.assertEqual(json.load(fh), good)
        with mock.patch.object(et.subprocess, "run", side_effect=subprocess.TimeoutExpired("x", 20)):
            et.precompute(pre)
        with open(os.path.join(pre, et.PRECOMPUTED_NAME)) as fh:
            d = json.load(fh)
        self.assertFalse(d["ok"])
        self.assertIn("20 s", d["error"])


class Registration(unittest.TestCase):
    def test_registered_with_the_system_collectors(self):
        self.assertIn(("event_taps", "eventtaps", "collect_event_taps"), COLLECTORS)
        names = [c[0] for c in COLLECTORS]
        self.assertGreater(names.index("event_taps"), names.index("tcc"))
        self.assertFalse(names[names.index("event_taps")].startswith("netaudit"))   # runs at Dokładny and Mega


if __name__ == "__main__":
    unittest.main()

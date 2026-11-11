"""Active defense (cerber/defense.py): acts only on certain attacks and never harms the Mac.

* hard limits: macOS files, Apple-signed code (even a copy outside /System), Cerber, own process, pid 1;
* a malicious script being run: quarantined and its interpreter process stopped (with its children);
* a copy of an Apple binary: neither moved nor stopped;
* live attack (network guard): only severity malicious + confidence high + an attack kind it acts on; a pid
  that is already another program is left alone; switched off without --defend;
* at most MAX_ACTIONS per window; watch.py flags and the NetGuard → defender hand-off.

    .venv/bin/python -m unittest tests.test_defense -v
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import psutil  # noqa: E402

from cerber import config, defense, watch  # noqa: E402


def _wait_running(proc: subprocess.Popen, script: str | None = None, timeout: float = 5.0) -> None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            p = psutil.Process(proc.pid)
            if script is None or any(script in a for a in p.cmdline()):
                return
        except psutil.Error:
            pass
        time.sleep(0.05)


class DefenseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cerber-defense-test-")
        self.qdir = os.path.join(self.tmp, "quarantine")
        os.makedirs(self.qdir)
        self.patches = [mock.patch.object(config, "QUARANTINE", self.qdir)]
        for p in self.patches:
            p.start()
        self.events: list[dict] = []
        self.procs: list[subprocess.Popen] = []

    def tearDown(self):
        for p in self.procs:
            try:
                psutil.Process(p.pid).resume()
            except psutil.Error:
                pass
            p.kill()
            p.wait(5)
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _spawn(self, argv: list[str]) -> subprocess.Popen:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(p)
        return p

    def _script(self, name: str = "payload.sh") -> str:
        path = os.path.join(self.tmp, name)
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\nsleep 30\ntrue\n")
        return path

    # ---------------------------------------------------------------- hard limits

    def test_system_and_cerber_paths(self):
        self.assertEqual(defense.system_path("/bin/zsh"), "plik systemu macOS")
        self.assertEqual(defense.system_path("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"),
                         "plik systemu macOS")
        self.assertIsNone(defense.system_path("/usr/local/bin/nie-ma-takiego"))
        self.assertEqual(defense.system_path(os.path.join(config.ROOT, "cerber", "defense.py")), "plik Cerbera")
        self.assertIsNone(defense.system_path(self._script()))

    def test_protected_file(self):
        self.assertTrue(defense.protected_file("/bin/ls"))
        copy = os.path.join(self.tmp, "ls-copy")
        shutil.copy("/bin/ls", copy)
        self.assertEqual(defense.protected_file(copy), "podpisany przez Apple")
        self.assertIsNone(defense.protected_file(self._script()))

    def test_critical_processes(self):
        self.assertTrue(defense.critical_process(psutil.Process(os.getpid())))
        self.assertTrue(defense.critical_process(psutil.Process(1)))
        p = self._spawn(["/bin/sleep", "30"])
        _wait_running(p)
        proc = psutil.Process(p.pid)
        self.assertEqual(defense.critical_process(proc), "plik systemu macOS")          # an Apple tool
        self.assertEqual(defense.critical_process(proc, allow_interpreter=True), "plik systemu macOS")
        self.assertIsNone(defense.critical_process(proc, allow_system=True))            # child of malware
        sh = self._spawn(["/bin/sh", "-c", "sleep 30; true"])
        _wait_running(sh)
        self.assertIsNone(defense.critical_process(psutil.Process(sh.pid), allow_interpreter=True))

    # ---------------------------------------------------------------- malicious file

    def test_malicious_script_quarantined_and_stopped(self):
        script = self._script()
        p = self._spawn(["/bin/sh", script])
        _wait_running(p, script)
        time.sleep(0.2)
        d = defense.Defender(self.events.append, quarantine=True, kill=True)
        out = d.on_malicious_file(script, {"verdict": "MALICIOUS", "primary": "Test.Payload"})
        self.assertTrue(out["quarantined"], out)
        self.assertFalse(os.path.exists(script))
        self.assertTrue(os.path.exists(os.path.join(self.qdir, out["quarantined"] + ".cq")))
        self.assertIn(p.pid, [s["pid"] for s in out["stopped"]])
        self.assertIsNotNone(p.wait(5))
        self.assertEqual(self.events[-1]["action"], "quarantined")
        self.assertEqual(self.events[-1]["qid"], out["quarantined"])
        # reversible: back in place, without the executable bit
        from cerber.quarantine import restore
        self.assertEqual(restore(out["quarantined"]), script)
        self.assertFalse(os.stat(script).st_mode & 0o111)

    def test_quarantine_only_does_not_stop(self):
        script = self._script()
        p = self._spawn(["/bin/sh", script])
        _wait_running(p, script)
        out = defense.Defender(self.events.append, quarantine=True, kill=False).on_malicious_file(
            script, {"verdict": "MALICIOUS"})
        self.assertTrue(out["quarantined"])
        self.assertEqual(out["stopped"], [])
        self.assertIsNone(p.poll())

    def test_apple_binary_copy_left_alone(self):
        copy = os.path.join(self.tmp, "sleep")
        shutil.copy("/bin/sleep", copy)
        p = self._spawn([copy, "30"])
        _wait_running(p)
        time.sleep(0.3)
        alive = p.poll() is None              # macOS itself may kill a relocated platform binary (AMFI)
        out = defense.Defender(self.events.append, quarantine=True, kill=True).on_malicious_file(
            copy, {"verdict": "MALICIOUS"})
        self.assertEqual(out["skipped"], "podpisany przez Apple")
        self.assertIsNone(out["quarantined"])
        self.assertEqual(out["stopped"], [])
        self.assertTrue(os.path.exists(copy))
        if alive:
            self.assertIsNone(p.poll())
        self.assertEqual(self.events[-1]["action"], "skipped")

    def test_rate_limit(self):
        d = defense.Defender(self.events.append, quarantine=True, kill=False)
        with mock.patch.object(defense, "MAX_ACTIONS", 1):
            a = d.on_malicious_file(self._script("a.sh"), {"verdict": "MALICIOUS"})
            b = d.on_malicious_file(self._script("b.sh"), {"verdict": "MALICIOUS"})
        self.assertTrue(a["quarantined"])
        self.assertIsNone(b["quarantined"])
        self.assertIn("limit", b["skipped"])
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "b.sh")))

    def test_disabled_does_nothing(self):
        script = self._script()
        out = defense.Defender(self.events.append, quarantine=False, kill=False).on_malicious_file(
            script, {"verdict": "MALICIOUS"})
        self.assertIsNone(out["quarantined"])
        self.assertTrue(os.path.exists(script))
        self.assertEqual(self.events, [])

    # ---------------------------------------------------------------- live attack

    def _shell(self) -> subprocess.Popen:
        p = self._spawn(["/bin/sh", "-c", "sleep 30; true"])
        _wait_running(p)
        t0 = time.time()
        while time.time() - t0 < 5 and not psutil.Process(p.pid).children():
            time.sleep(0.05)
        return p

    def test_live_remote_shell_stopped(self):
        p = self._shell()
        kid = psutil.Process(p.pid).children()[0].pid
        exe = psutil.Process(p.pid).exe()          # /bin/sh re-executes the real shell (bash/zsh/dash)
        item = {"severity": "malicious", "confidence": "high", "attack": "remote_shell", "pid": p.pid,
                "exe": exe, "title": "Zdalna powłoka"}
        ev = defense.Defender(self.events.append, kill=True).on_live_attack(item)
        self.assertEqual(ev["action"], "stopped", ev)
        self.assertIsNotNone(p.wait(5))
        self.assertIn(kid, ev["pids"])
        self.assertFalse(psutil.pid_exists(kid) and psutil.Process(kid).status() != psutil.STATUS_ZOMBIE)

    def test_live_only_certain_attacks(self):
        p = self._shell()
        d = defense.Defender(self.events.append, kill=True)
        base = {"severity": "malicious", "confidence": "high", "attack": "remote_shell", "pid": p.pid,
                "exe": psutil.Process(p.pid).exe()}
        for change in ({"confidence": "medium"}, {"severity": "suspicious"}, {"attack": "suspicious_chain"},
                       {"attack": "miner"}, {"attack": None}, {"exe": "/usr/bin/python3"}, {"pid": None},
                       {"exe": "sh"}):
            self.assertIsNone(d.on_live_attack({**base, **change}), change)
        self.assertIsNone(defense.Defender(self.events.append, kill=False).on_live_attack(base))
        self.assertIsNone(p.poll())
        self.assertEqual(self.events, [])

    def test_live_never_stops_apple_tools(self):
        p = self._spawn(["/bin/sleep", "30"])
        _wait_running(p)
        ev = defense.Defender(self.events.append, kill=True).on_live_attack(
            {"severity": "malicious", "confidence": "high", "attack": "c2", "pid": p.pid, "exe": "/bin/sleep",
             "title": "x"})
        self.assertEqual(ev["action"], "skipped")
        self.assertIsNone(p.poll())

    # ---------------------------------------------------------------- watch.py wiring

    def test_watch_flags(self):
        ns = SimpleNamespace
        self.assertFalse(watch.auto_quarantine(ns()))
        self.assertTrue(watch.auto_quarantine(ns(quarantine=True)))
        self.assertTrue(watch.auto_quarantine(ns(defend=True)))
        self.assertTrue(watch.active_defense(ns(defend=True)))
        self.assertFalse(watch.active_defense(ns(quarantine=True)))
        self.assertFalse(watch.active_defense(ns(defend=True, no_quarantine=True)))

    def test_netguard_hands_malicious_events_to_defender(self):
        seen = []
        fake = SimpleNamespace(on_live_attack=seen.append)
        with mock.patch.object(watch.NetGuard, "_load_day", lambda self: None):
            g = watch.NetGuard(watch.Notifier(False), __import__("queue").Queue(), fake)
        g._on_event(watch.clean_net_item({"severity": "suspicious", "title": "a"}))
        g._on_event(watch.clean_net_item({"severity": "malicious", "confidence": "high", "attack": "remote_shell",
                                          "pid": 123, "exe": "/bin/sh", "title": "b"}))
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["pid"], 123)
        self.assertEqual(seen[0]["attack"], "remote_shell")

    # ---------------------------------------------------------------- scans (gui_backend --defend)

    def test_scan_defense_streamed_and_final_result_agree(self):
        from cerber import gui_backend as gb
        script = self._script()
        calls = []

        class Fake:
            def on_malicious_file(self, path, r):
                calls.append(path)
                return {"quarantined": "0123456789abcdef", "stopped": [{"pid": 7, "name": "x"}]}

        with mock.patch.object(gb, "DEFENDER", Fake()), mock.patch.object(gb, "DEFENDED", {}), \
                mock.patch.object(gb, "SCAN_ROOTS", [self.tmp]):
            streamed = {"path": script, "verdict": "MALICIOUS"}
            gb.defend_result(streamed)
            final = {"path": script, "verdict": "MALICIOUS"}          # the report's own copy of the result
            gb.defend_result(final)
            outside = {"path": "/etc/hosts", "verdict": "MALICIOUS"}   # not under what was scanned
            gb.defend_result(outside)
            gb.defend_result({"path": self._script("s.sh"), "verdict": "SUSPICIOUS"})
        self.assertEqual(calls, [script])
        self.assertEqual(streamed["quarantined"], final["quarantined"])
        self.assertEqual(final["stopped"], [7])
        self.assertNotIn("quarantined", outside)

    def test_scan_defense_off_by_default(self):
        from cerber import gui_backend as gb
        r = {"path": self._script(), "verdict": "MALICIOUS"}
        with mock.patch.object(gb, "DEFENDER", None), mock.patch.object(gb, "SCAN_ROOTS", [self.tmp]):
            gb.defend_result(r)
        self.assertNotIn("quarantined", r)
        self.assertTrue(os.path.exists(r["path"]))


if __name__ == "__main__":
    unittest.main()

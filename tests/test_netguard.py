"""Background protection – network & remote-access guard (watch --net) and the in-app report's quarantine links."""
from __future__ import annotations

import argparse
import io
import json
import os
import queue
import sqlite3
import tempfile
import time
import unittest
from unittest import mock

from cerber import config, report, watch
from cerber.envscan import netwatch as nw
from cerber.envscan.netaudit import match_remote_tool
from cerber.envscan.util import EnvContext

from tests.test_netwatch import FakeSign, items


def make_guard(events: list, inbox: str | None = None, home: str | None = None) -> nw.NetWatch:
    with mock.patch.object(nw, "_ioc_lookup", return_value=lambda ip: None), mock.patch.object(nw.threading, "Thread"):
        w = nw.NetWatch(EnvContext({"deep": True}), events.append, root_pid=None, guard=True, inbox=inbox)
    w.baseline = True
    w._sign = lambda exe: ("brak podpisu", FakeSign("unsigned")) if exe and "/tmp/" in exe else ("Apple", None)
    w._is_cerber = lambda pid: False
    w._process_heuristics = lambda judge: None
    if home:
        w.home = home
    return w


def log_line(t: str, proc: str, msg: str) -> str:
    return json.dumps({"timestamp": t + ".000000+0200", "processImagePath": f"/usr/sbin/{proc}", "eventMessage": msg,
                       "eventType": "logEvent", "subsystem": "", "category": "", "formatString": "%s",
                       "processID": 10, "messageType": "Default"})


class GuardModeTest(unittest.TestCase):
    def setUp(self):
        self.events: list = []
        self.w = make_guard(self.events)

    def test_defaults(self):
        self.assertEqual(self.w.poll_s, nw.GUARD_POLL_S)
        self.assertEqual(self.w.watch_dirs, nw.GUARD_WATCH_DIRS)
        self.assertNotIn("~/Downloads", self.w.watch_dirs)              # the file watch has them
        self.assertNotIn("~/Library/LaunchAgents", self.w.persist_dirs)
        self.w._resolve("198.51.100.1")                                  # no reverse DNS in guard mode
        self.assertEqual(self.w.hosts, {})
        st = self.w.status()
        self.assertTrue(st["guard"])
        self.assertIn("log_checked", st)

    def test_wording_is_not_about_a_scan(self):
        self.w.procs[700] = {"pid": 700, "name": "AnyDesk", "exe": "/private/tmp/AnyDesk.app/Contents/MacOS/AnyDesk",
                             "cmdline": ["AnyDesk"]}
        self.w._check_processes([700])
        it = items(self.events)
        self.assertTrue(it)
        for x in it:
            self.assertNotIn("skanu", x["title"] + " " + (x["detail"] or ""))
        self.assertTrue(any("przed chwilą" in (x["detail"] or "") for x in it))

    def test_apple_signed_lookalike_is_not_a_remote_tool(self):
        """iOS simulator runtimes: Apple's parsec-fbf / nanosystemsettingsd were taken for Parsec / Supremo."""
        root = "/Library/Developer/CoreSimulator/Volumes/iOS/RuntimeRoot/System/Library/PrivateFrameworks/"
        self.w.procs[701] = {"pid": 701, "name": "parsec-fbf", "exe": root + "CoreParsec.framework/parsec-fbf"}
        self.w.procs[702] = {"pid": 702, "name": "nanosystemsettingsd",
                             "exe": root + "NanoSystemSettings.framework/nanosystemsettingsd"}
        self.w._check_processes([701, 702])
        self.assertEqual([x for x in items(self.events) if "zdalnego" in x["title"]], [])
        self.assertIsNone(match_remote_tool("nanosystemsettingsd " + root))
        self.assertEqual(match_remote_tool("it.nanosystems.supremo")[1], "Supremo")

    def test_targets_only_after_an_alarm(self):
        with tempfile.NamedTemporaryFile() as f:
            self.w._target(f.name, "x")
            self.assertEqual(self.w.targets, {})
            self.w._event("process", "t", "d", [nw.Signal("X", 30, nw.Confidence.MEDIUM, "d")], extra={"exe": f.name})
            self.w._target(f.name, "program uruchomiony w trakcie skanu")
            self.assertIn(f.name, self.w.targets)
            self.assertEqual(self.w.targets[f.name], "program uruchomiony przed chwilą")
        with tempfile.NamedTemporaryFile() as g:
            self.w._target(g.name, "nowy plik", force=True)
            self.assertIn(g.name, self.w.targets)

    def test_housekeeping(self):
        self.w.group_n["x"] = 5
        self.w.alarmed["/a"] = 50
        self.w.targets["/a"] = "r"
        self.w.events.append({"id": 1})
        self.w.ctx.add_finding("network_live", "t", "l", [nw.Signal("X", 40, nw.Confidence.MEDIUM, "d")])
        self.w.log_seen = {("c", "t", "2000-01-01 00:00:00"), ("c", "t", time.strftime("%Y-%m-%d %H:%M:%S"))}
        self.w.beacon_times = {("a", "1.2.3.4"): [time.time() - 7200], ("b", "1.2.3.5"): [time.time()]}
        self.w.housekeep()
        self.assertEqual((self.w.group_n, self.w.alarmed, self.w.targets, self.w.events, self.w.ctx.findings),
                         ({}, {}, {}, [], []))
        self.assertEqual(len(self.w.log_seen), 1)
        self.assertEqual(list(self.w.beacon_times), [("b", "1.2.3.5")])


class GuardCorrelationTest(unittest.TestCase):
    def test_two_dimensions_make_one_alarm(self):
        events: list = []
        w = make_guard(events)
        exe = "/private/tmp/agent"
        w._event("process", "p", "d", [nw.Signal("A", 25, nw.Confidence.MEDIUM, "x")], extra={"exe": exe})
        self.assertFalse([x for x in items(events) if x["kind"] == "correlation"])
        w._event("connection", "c", "d", [nw.Signal("B", 35, nw.Confidence.MEDIUM, "x")], extra={"exe": exe})
        corr = [x for x in items(events) if x["kind"] == "correlation"]
        self.assertEqual(len(corr), 1)
        self.assertIn(corr[0]["severity"], ("suspicious", "malicious"))
        w._event("connection", "c2", "d", [nw.Signal("B", 36, nw.Confidence.MEDIUM, "x")], extra={"exe": exe})
        self.assertEqual(len([x for x in items(events) if x["kind"] == "correlation"]), 1)   # no repeats


class LogInboxTest(unittest.TestCase):
    def test_batches_are_judged_once(self):
        with tempfile.TemporaryDirectory() as inbox:
            events: list = []
            w = make_guard(events, inbox=inbox)
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            lines = [log_line(now, "sshd-session", f"Failed password for root from 203.0.113.9 port {4000 + i} ssh2")
                     for i in range(12)]
            lines += [log_line(now, "sshd-session", "Accepted publickey for filip from 192.168.1.20 port 5000 ssh2"),
                      log_line(now, "sshd-session", "Accepted password for root from 203.0.113.9 port 5001 ssh2")]
            batch = {"from": now, "to": now, "texts": ["\n".join(lines)]}
            with open(os.path.join(inbox, "00000001.json"), "w") as fh:
                json.dump(batch, fh)
            w._check_log_inbox()
            self.assertEqual(os.listdir(inbox), [])                     # consumed
            it = items(events)
            titles = [x["title"] for x in it]
            self.assertTrue(any("nieudanych prób logowania SSH z 203.0.113.9" in t for t in titles), titles)
            brute = next(x for x in it if "Zalogowano przez SSH: root" in x["title"])
            self.assertEqual(brute["severity"], "malicious")             # success after 12 failures
            lan = next(x for x in it if "192.168.1.20" in x["title"])
            self.assertEqual(lan["severity"], "info")                   # remote login from LAN: shown, no alarm
            self.assertTrue(all(x["kind"] == "log" for x in it))
            self.assertEqual(w.log_checked, now)
            n = len(it)
            with open(os.path.join(inbox, "00000002.json"), "w") as fh:     # the same entries again (overlap)
                json.dump(batch, fh)
            w._check_log_inbox()
            self.assertEqual(len(items(events)), n)

    def test_error_batch_becomes_a_limitation(self):
        with tempfile.TemporaryDirectory() as inbox:
            w = make_guard([], inbox=inbox)
            with open(os.path.join(inbox, "00000001.json"), "w") as fh:
                json.dump({"error": "przekroczono limit czasu odczytu dziennika"}, fh)
            w._check_log_inbox()
            self.assertTrue(any("dziennik systemowy" in x for x in w.limitations))


class PermissionsTest(unittest.TestCase):
    def _db(self, home: str, rows: list[tuple]) -> None:
        d = os.path.join(home, "Library/Application Support/com.apple.TCC")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, "TCC.db")
        if os.path.exists(p):
            os.remove(p)
        con = sqlite3.connect(p)
        con.execute("CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER)")
        con.executemany("INSERT INTO access VALUES (?,?,?,?)", rows)
        con.commit()
        con.close()

    def test_new_grants(self):
        with tempfile.TemporaryDirectory() as home, mock.patch.object(nw, "TCC_SYSTEM_DB", "/nonexistent/TCC.db"):
            zoom = ("kTCCServiceScreenCapture", "us.zoom.xos", 0, 2)
            self._db(home, [zoom, ("kTCCServiceAccessibility", "com.apple.Terminal", 0, 2)])
            events: list = []
            w = make_guard(events, home=home)
            w.tcc = w._tcc_grants()
            self.assertEqual(w.tcc, {("kTCCServiceScreenCapture", "us.zoom.xos", 0)})   # Apple's own skipped
            self._db(home, [zoom, ("kTCCServiceAccessibility", "com.philandro.anydesk", 0, 2),
                            ("kTCCServiceMicrophone", "com.example.app", 0, 2),
                            ("kTCCServiceCamera", "com.example.denied", 0, 0)])
            w._check_permissions()
            it = {x["title"]: x for x in items(events)}
            self.assertEqual(len(it), 2, list(it))
            any_desk = next(x for t, x in it.items() if "anydesk" in t)
            self.assertIn(any_desk["severity"], ("suspicious", "malicious"))
            mic = next(x for t, x in it.items() if "com.example.app" in t)
            self.assertEqual(mic["severity"], "low")
            w._check_permissions()                                        # nothing new
            self.assertEqual(len(items(events)), 2)

    def test_unreadable_is_a_limitation(self):
        with tempfile.TemporaryDirectory() as home, mock.patch.object(nw, "TCC_SYSTEM_DB", "/nonexistent/TCC.db"):
            w = make_guard([], home=home)
            self.assertIsNone(w._tcc_grants())
            w._check_permissions()
            self.assertTrue(any("Pełnego dostępu do dysku" in x for x in w.limitations))


class Notes:
    def __init__(self):
        self.sent: list = []

    def notify(self, title, msg, subtitle="", sound=None):
        self.sent.append((title, msg, subtitle, sound))


class NetGuardRelayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = io.StringIO()
        self.patches = [mock.patch.object(config, "REPORTS", self.tmp.name), mock.patch.object(watch, "_APP_OUT", self.out),
                        mock.patch.object(watch, "LOG_PATH", os.path.join(self.tmp.name, "watch.log")),
                        mock.patch.object(watch, "LOG_DIR", self.tmp.name)]
        for p in self.patches:
            p.start()
        self.notes = Notes()
        self.targets: queue.Queue = queue.Queue()
        self.g = watch.NetGuard(self.notes, self.targets)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def app_events(self) -> list[dict]:
        return [json.loads(x) for x in self.out.getvalue().splitlines()]

    def test_clean_item(self):
        x = watch.clean_net_item({"id": "ne-1", "severity": "evil", "title": "t" * 5000, "pid": "12", "score": True,
                                  "extra": "dropped"})
        self.assertEqual(x["severity"], "info")
        self.assertEqual(len(x["title"]), 600)
        self.assertIsNone(x["pid"])
        self.assertIsNone(x["score"])
        self.assertNotIn("extra", x)

    def test_alarm_goes_to_app_notification_and_report(self):
        item = {"id": "ne-1", "time": "10:00:00", "kind": "inbound", "severity": "suspicious", "score": 45,
                "title": "Ktoś połączył się z Twoim Makiem: <VNC>", "detail": "Udostępnianie ekranu (VNC)"}
        self.g.relay({"ev": "net_event", "item": item})
        self.g.relay({"ev": "net_event", "item": {**item, "id": "ne-2", "severity": "info", "title": "zwykłe"}})
        evs = self.app_events()
        self.assertEqual([e["ev"] for e in evs], ["watch_net", "watch_net"])
        self.assertTrue(evs[0]["report"].endswith(".html"))
        self.assertEqual(len(self.notes.sent), 1)                        # info: feed only
        self.g.tick()
        jp, hp = watch.net_report_paths()
        with open(jp) as fh:
            data = json.load(fh)
        self.assertEqual([e["id"] for e in data["events"]], ["ne-2", "ne-1"])
        with open(hp) as fh:
            page = fh.read()
        self.assertIn("&lt;VNC&gt;", page)                               # escaped
        self.assertNotIn("<VNC>", page)
        g2 = watch.NetGuard(self.notes, self.targets)                    # restart the same day: report continues
        self.assertEqual(len(g2.events), 2)

    def test_notifications_are_rate_limited(self):
        for i in range(watch.NET_NOTIFY_MAX + 5):
            self.g.relay({"ev": "net_event", "item": {"id": f"ne-{i}", "severity": "suspicious", "title": f"t{i}"}})
        self.assertEqual(len(self.notes.sent), watch.NET_NOTIFY_MAX)
        self.assertEqual(len(self.g.events), watch.NET_NOTIFY_MAX + 5)

    def test_status_and_targets(self):
        self.g.relay({"ev": "net_status", "polls": 3, "public_new": 2, "interval_s": 10.0, "permissions": True,
                      "log_checked": "2026-10-10 10:00:00", "limitations": ["a", 5], "bogus": "x"})
        st = self.app_events()[-1]
        self.assertEqual((st["ev"], st["polls"], st["public_new"], st["limitations"]), ("watch_net_status", 3, 2, ["a"]))
        self.assertNotIn("bogus", st)
        self.g.relay({"ev": "watch_target", "path": "/private/tmp/x", "reason": "alarm"})
        self.g.relay({"ev": "watch_target", "path": "relative/x"})
        self.g.relay({"ev": "watch_target", "path": "/a\nb"})
        self.assertEqual(self.targets.get_nowait(), ("/private/tmp/x", "alarm"))
        self.assertTrue(self.targets.empty())

    def test_log_window(self):
        with mock.patch.object(watch, "NET_STATE", os.path.join(self.tmp.name, "s.json")):
            now = time.time()
            self.assertAlmostEqual(self.g._since(), now - watch.NET_LOG_FIRST, delta=5)
            self.g._save_since(now - 10 * 86400)
            self.assertAlmostEqual(self.g._since(), now - watch.NET_LOG_MAX_BACK, delta=5)
            self.g._save_since(now - 60)
            self.assertAlmostEqual(self.g._since(), now - 60, delta=1)

    def test_query_log_argv(self):
        calls = []

        class P:
            returncode = 0

            def __init__(self, argv, **kw):
                calls.append(argv)

            def communicate(self, timeout=None):
                return '{"x": 1}\n', ""

        with mock.patch.object(watch.subprocess, "Popen", P):
            b = watch.query_log(time.time() - 300, time.time())
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(a[:2] == ["/usr/bin/log", "show"] and "--start" in a and "--end" in a for a in calls))
        self.assertEqual(len(b["texts"]), 2)

    def test_cli_flag(self):
        ap = argparse.ArgumentParser()
        watch.add_parser(ap.add_subparsers())
        self.assertTrue(ap.parse_args(["watch", "run", "--net"]).net)
        self.assertFalse(ap.parse_args(["watch", "run"]).net)


class ReportQuarantineLinkTest(unittest.TestCase):
    LINK = '<a class="qbtn" data-i="{i}" href="cerber-report://quarantine/{i}">Do kwarantanny</a>'

    def test_links_only_for_high_risk_real_files(self):
        res = [{"path": "/x/evil.sh", "verdict": "MALICIOUS", "score": 120},
               {"path": "/x/meh.sh", "verdict": "SUSPICIOUS", "score": 40},
               {"path": "/x/sus.sh", "verdict": "SUSPICIOUS", "score": 60},
               {"path": "/x/a.zip>>inner.js", "verdict": "MALICIOUS", "score": 90},
               {"path": "/x/q.sh", "verdict": "MALICIOUS", "score": 90, "quarantined": "abc"}]
        rep = {"counts": {}, "results": [{**r, "detections": [], "size": 1, "ftype": "sh"} for r in res],
               "started": "s", "finished": "f", "seconds": 1, "files": 5, "bytes": 5, "objects": 5}
        with tempfile.TemporaryDirectory() as d:
            p = report.write_html(rep, os.path.join(d, "r.html"))
            with open(p) as fh:
                page = fh.read()
        self.assertIn(".qbtn{display:none", page)                         # hidden outside Cerber's window
        self.assertIn(self.LINK.format(i=0), page)
        self.assertIn(self.LINK.format(i=2), page)
        for i in (1, 3, 4):
            self.assertNotIn(self.LINK.format(i=i), page)
        self.assertIn("✓ w kwarantannie", page)


if __name__ == "__main__":
    unittest.main()

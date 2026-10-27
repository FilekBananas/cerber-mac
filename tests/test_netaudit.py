"""Tests for the network & remote-access audit (cerber.envscan.netaudit).

Pure-function tests on canned command output plus one end-to-end run of both collectors with every
command, socket table, process list, signature and IOC lookup replaced by fakes (no live network,
no system state is read except temporary folders created by the test).

    python -m unittest tests.test_netaudit -v
"""
from __future__ import annotations

import os
import plistlib
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from cerber.envscan import COLLECTORS, netaudit as na  # noqa: E402
from cerber.envscan.model import combine, severity_of  # noqa: E402
from cerber.envscan.util import CmdResult, EnvContext, SignInfo, UserHome  # noqa: E402

PROTOCOL_KEYS = ["boot_time", "summary", "listening", "connections", "traffic", "traffic_history",
                 "remote_access", "sessions", "logins"]
SUMMARY_KEYS = {"listening_all_interfaces", "public_connections", "processes_online", "remote_tools", "ioc_hits",
                "uploaded_bytes_since_boot"}

NETSTAT_TCP = """Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
tcp4       0      0  192.168.1.10.52423                            160.79.104.10.443                             ESTABLISHED         2664       284127  131200  141120       claude.exe:6316   00102 00000000 00000000003dc932 00000081 04000900      2      0 000000
tcp4       0      0  192.168.1.10.52424                            160.79.104.10.443                             TIME_WAIT           2664       284127  131200  141120       claude.exe:6316   00102 00000000 00000000003dc932 00000081 04000900      2      0 000000
tcp6       0      0  fe80::c4b:e7de:95f2:6c4d%en0.50026            fe80::444:b82a:8ca7:de0b%en0.49152            ESTABLISHED         3330         1580  131072  131376         rapportd:638    00102 00000008 00000000003b9c1f 00080083 04000900      2      0 000000
tcp6       0      0  2a02:a311::1.50100                            2a00:1450:4001:82a::200e.443                  ESTABLISHED         3330         1580  131072  131376 Google Chrome He:75052  00102 00000008 00000000003b9c1f 00080083 04000900      2      0 000000
tcp46      0      0  *.5900                                        *.*                                           LISTEN                 0            0  131072  131072         launchd:1      00100 00000006 000000000036d3a9 00000001 00000800      1      0 000000
tcp4       0      0  127.0.0.1.8021                                *.*                                           LISTEN                 0            0  131072  131072         launchd:1      00100 00000006 000000000036d3a9 00000001 00000800      1      0 000000
tcp4       0      0  127.0.0.1.52000                               127.0.0.1.8021                                ESTABLISHED            0            0  131072  131072         curl:777       00100 00000006 000000000036d3a9 00000001 00000800      1      0 000000
"""
NETSTAT_UDP = """Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
udp4       0      0  192.168.1.10.64872                            142.250.109.94.443                                               14770         6222 1048576   29040 Google Chrome He:75052  00102 00000000 00000000003dd065 00000000 04200900      1      0 000002
udp46      0      0  *.5353                                        *.*                                                                  0            0  786896    9216 mDNSResponder:459  00100 00000000 00000000003dd065 00000000 04200900      1      0 000002
udp4       0      0  *.*                                           *.*                                                                  0            0  786896    9216       wifip2pd:6778  00100 00000000 00000000003dd065 00000000 04200900      1      0 000002
"""
NETTOP = """,bytes_in,bytes_out,
kernel_task.0,289080,220224,
mDNSResponder.459,315872241,20575097,
Google Chrome H.56847,3869113,1531028,
claude.exe.6066,147520,17361129,
Adobe Desktop S.1324,0,0,
garbage line
"""
WHO = """jan            console      Oct  3 16:25
jan            ttys000      Oct  3 16:25
jan            ttys003      Oct  6 10:00 (45.33.32.156)
jan            ttys004      Oct  6 10:01 (tmux(1234).%0)
jan            ttys005      Oct  6 10:02 (:0)
"""
LAST = """jan      ttys007                         Tue Oct  6 15:47   still logged in
admin      ttys003   45.33.32.156          Tue Oct  6 10:00   still logged in
jan      ttys006   192.168.1.20          Sat Oct  3 16:26 - 16:30  (00:04)
reboot time                                Sat Oct  3 16:25
shutdown time                              Sat Oct  3 16:24
jan      console                         Thu Jan  2 09:00 - crash (4+04:07)
jan      ttys002   mac-mini.local        Mon Dec 30 18:33 - 18:40  (00:07)

wtmp begins Mon Dec 30 18:00:00 2024
"""
NOW = time.mktime((2026, 10, 6, 16, 0, 0, 0, 0, -1))


def _ctx(home: str, **opts) -> EnvContext:
    o = {"codesign": False, "reverse_dns": False, "homes_override": [UserHome("jan", 501, home)]}
    o.update(opts)
    return EnvContext(o)


class PureParsers(unittest.TestCase):
    def test_parse_netstat_full_ipv6_and_bytes(self):
        socks = na.parse_netstat(NETSTAT_TCP) + na.parse_netstat(NETSTAT_UDP)
        self.assertEqual(len(socks), 10)
        chrome6 = [s for s in socks if s["pid"] == 75052 and s["proto"] == "tcp6"][0]
        self.assertEqual(chrome6["remote"], "2a00:1450:4001:82a::200e")
        self.assertEqual(chrome6["rport"], 443)
        self.assertEqual(chrome6["pname"], "Google Chrome He")
        first = socks[0]
        self.assertEqual((first["local"], first["lport"], first["remote"], first["rport"]),
                         ("192.168.1.10", 52423, "160.79.104.10", 443))
        self.assertEqual((first["rx"], first["tx"], first["state"]), (2664, 284127, "ESTABLISHED"))
        udp = [s for s in socks if s["pid"] == 459][0]
        self.assertEqual((udp["local"], udp["lport"], udp["remote"], udp["state"]), ("*", 5353, "*", ""))

    def test_exposure(self):
        self.assertEqual(na.exposure_of("*"), "all")
        self.assertEqual(na.exposure_of("0.0.0.0"), "all")
        self.assertEqual(na.exposure_of("::"), "all")
        self.assertEqual(na.exposure_of("127.0.0.1"), "localhost")
        self.assertEqual(na.exposure_of("::1"), "localhost")
        self.assertEqual(na.exposure_of("fe80::1%lo0"), "localhost")
        self.assertEqual(na.exposure_of("192.168.1.10"), "specific")

    def test_listening_and_connections(self):
        socks = na.parse_netstat(NETSTAT_TCP) + na.parse_netstat(NETSTAT_UDP)
        socks.append(dict(socks[4]))   # duplicate LISTEN row must be collapsed
        procs = {1: {"name": "launchd", "exe": "/sbin/launchd"},
                 6316: {"name": "claude.exe", "exe": None},
                 75052: {"name": "Google Chrome Helper", "exe": "/Applications/Google Chrome.app/Contents/x"}}
        listening = na.build_listening(socks, procs)
        self.assertEqual([(d["port"], d["exposure"]) for d in listening], [(5900, "all"), (5353, "all"),
                                                                            (8021, "localhost")])
        vnc = listening[0]
        self.assertEqual(vnc["service"], "Udostępnianie ekranu (VNC)")
        self.assertEqual(set(vnc), {"proto", "address", "port", "exposure", "process", "pid", "exe", "signer",
                                    "service"})
        self.assertEqual(listening[1]["service"], "Bonjour (mDNS)")
        conns = na.build_connections(socks, procs)
        # loopback curl -> launchd skipped; claude TIME_WAIT+ESTABLISHED collapsed into one live entry
        self.assertFalse(any(c["remote"].startswith("127.") for c in conns))
        claude = [c for c in conns if c["pid"] == 6316]
        self.assertEqual(len(claude), 1)
        self.assertEqual(claude[0]["state"], "ESTABLISHED")
        self.assertEqual(set(claude[0]), {"process", "pid", "exe", "remote", "port", "host", "state", "public", "ioc"})
        self.assertTrue(conns[0]["public"])           # public first
        self.assertFalse([c for c in conns if c["pid"] == 638][0]["public"])   # link-local
        quic = [c for c in conns if c["port"] == 443 and c["pid"] == 75052 and c["state"] == "UDP"]
        self.assertEqual(len(quic), 1)

    def test_public_ip_rules(self):
        self.assertTrue(na.is_public_ip("8.8.8.8"))
        self.assertFalse(na.is_public_ip("100.101.102.103"))     # Tailscale / CGNAT
        self.assertFalse(na.is_public_ip("192.168.0.1"))
        self.assertEqual(na.normalize_ip("::ffff:8.8.8.8"), "8.8.8.8")
        self.assertTrue(na.is_shared_ip("104.21.10.163"))        # Cloudflare anycast
        self.assertFalse(na.is_shared_ip("1.117.61.9"))

    def test_nettop_and_boottime(self):
        rows = na.parse_nettop(NETTOP)
        self.assertEqual(rows[0], {"name": "mDNSResponder", "pid": 459, "bytes_in": 315872241, "bytes_out": 20575097})
        self.assertIn({"name": "claude.exe", "pid": 6066, "bytes_in": 147520, "bytes_out": 17361129}, rows)
        self.assertIn("Adobe Desktop S", [r["name"] for r in rows])
        self.assertEqual(len(rows), 5)
        self.assertEqual(na.parse_boottime("{ sec = 1791037525, usec = 31710 } Sat Oct  3 16:25:25 2026"),
                         1791037525.0)
        self.assertIsNone(na.parse_boottime(""))

    def test_ioc_format(self):
        self.assertEqual(na.format_ioc("ThreatFox.win.cobalt_strike"),
                         "ThreatFox: win.cobalt_strike – serwer C2 / infrastruktura złośliwego oprogramowania")
        self.assertTrue(na.format_ioc("URLhaus.malware_download.Mozi").startswith("URLhaus: malware_download.Mozi"))

    def test_who(self):
        s = na.parse_who(WHO, now=NOW)
        self.assertEqual(len(s), 5)
        self.assertEqual(s[0], {"user": "jan", "tty": "console", "from": None, "since": "2026-10-03 16:25"})
        self.assertEqual(s[2]["from"], "45.33.32.156")
        self.assertIsNone(s[3]["from"])       # tmux
        self.assertIsNone(s[4]["from"])       # X display

    def test_last_year_inference_and_remote(self):
        logins = na.parse_last(LAST, now=NOW)
        self.assertEqual([x["user"] for x in logins], ["jan", "admin", "jan", "jan", "jan"])
        self.assertEqual(logins[0]["when"], "2026-10-06 15:47")
        self.assertEqual(logins[1], {"user": "admin", "tty": "ttys003", "from": "45.33.32.156",
                                     "when": "2026-10-06 10:00", "remote": True})
        self.assertEqual(logins[3]["when"], "2026-01-02 09:00")
        self.assertEqual(logins[4]["when"], "2025-12-30 18:33")    # wrapped into the previous year
        self.assertEqual(na.host_kind("45.33.32.156"), "public")
        self.assertEqual(na.host_kind("192.168.1.20"), "lan")
        self.assertEqual(na.host_kind("mac-mini.local"), "lan")
        self.assertEqual(na.host_kind("vps.example.com"), "unknown")

    def test_enrollment(self):
        self.assertEqual(na.parse_enrollment("Enrolled via DEP: No\nMDM enrollment: No\n"), (False, False))
        self.assertEqual(na.parse_enrollment("Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\n"),
                         (True, True))

    def test_remote_tool_catalog(self):
        self.assertEqual(na.match_remote_tool("TeamViewer.app")[0], "TeamViewer")
        self.assertEqual(na.match_remote_tool("com.philandro.anydesk.service.plist")[0], "AnyDesk")
        self.assertEqual(na.match_remote_tool("org.chromium.chromoting.plist")[0], "ChromeRemoteDesktop")
        self.assertEqual(na.match_remote_tool("ChromeRemoteDesktopHost")[0], "ChromeRemoteDesktop")
        self.assertEqual(na.match_remote_tool("rustdesk /Applications/RustDesk.app/Contents/MacOS/rustdesk")[0],
                         "RustDesk")
        for benign in ("Google Chrome.app", "Slack.app", "zoom.us.app", "GoToMeeting.app", "LogMeIn Hamachi.app",
                       "com.logmein.GoToMeeting.G2MUpdate.plist", "OrbStack.app", "LM Studio.app", "Codex.app"):
            self.assertIsNone(na.match_remote_tool(benign), benign)
        self.assertEqual(na.match_vpn("Tailscale.app")[0], "Tailscale")
        self.assertEqual(na.match_vpn("LogMeIn Hamachi.app")[0], "Hamachi")

    def test_tunnels(self):
        t = na.classify_tunnel(["ngrok", "http", "8080"], "ngrok", "/opt/homebrew/bin/ngrok")
        self.assertEqual((t["name"], t["score"], t["info"]), ("ngrok", 40, False))
        t = na.classify_tunnel(["/usr/bin/ssh", "-fNR", "8080:localhost:22", "user@vps.example.com"], "ssh",
                               "/usr/bin/ssh")
        self.assertEqual(t["score"], 40)
        t = na.classify_tunnel(["ssh", "-R", "80:localhost:3000", "a.pinggy.io"], "ssh", "/usr/bin/ssh")
        self.assertEqual(t["score"], 45)
        self.assertIn("pinggy.io", t["name"])
        t = na.classify_tunnel(["ssh", "-D", "1080", "host"], "ssh", "/usr/bin/ssh")
        self.assertEqual(t["score"], 25)
        self.assertIsNone(na.classify_tunnel(["ssh", "-L", "8080:localhost:80", "-l", "Root", "host"], "ssh",
                                             "/usr/bin/ssh"))
        self.assertIsNone(na.classify_tunnel(["ssh", "git@github.com"], "ssh", "/usr/bin/ssh"))
        self.assertTrue(na.classify_tunnel(["cloudflared", "proxy-dns"], "cloudflared", None)["info"])
        self.assertFalse(na.classify_tunnel(["cloudflared", "tunnel", "run"], "cloudflared", None)["info"])
        self.assertEqual(na.classify_tunnel(["nc", "-lvp", "4444"], "nc", "/usr/bin/nc")["score"], 40)
        self.assertIsNone(na.classify_tunnel(["nc", "-z", "host", "22"], "nc", "/usr/bin/nc"))
        self.assertEqual(na.classify_tunnel(["socat", "TCP-LISTEN:9000,fork", "TCP:10.0.0.1:22"], "socat",
                                            "/opt/homebrew/bin/socat")["score"], 40)
        self.assertIsNone(na.classify_tunnel(["lt"], "lt", None))
        self.assertIsNotNone(na.classify_tunnel(["lt", "--port", "3000"], "lt", None))
        self.assertIsNotNone(na.classify_tunnel(["node", "/usr/local/lib/node_modules/localtunnel/bin/lt.js",
                                                 "--port", "3000"], "node", "/opt/homebrew/bin/node"))
        self.assertIsNone(na.classify_tunnel(["rg", "localtunnel", "."], "rg", "/opt/homebrew/bin/rg"))

    def test_exfil_heuristics(self):
        def sev(sigs):
            d = combine(sigs)
            return severity_of(d) if d else None
        MB = na.MB
        # unsigned binary uploading 60 MB (more than it downloaded) -> suspicious, not malicious
        s = na.exfil_signals("/Users/x/bin/agent", 60 * MB, 1 * MB, "unsigned")
        self.assertEqual(sev(s), "suspicious")
        # ... from /tmp: still capped below "malicious"
        s = na.exfil_signals("/tmp/.x/agent", 60 * MB, 1 * MB, "unsigned")
        self.assertEqual(sev(s), "suspicious")
        # ad-hoc helper in ~/Library uploading 10 MB -> suspicious
        s = na.exfil_signals("/Users/x/Library/Application Support/helper/agentd", 10 * MB, 1 * MB, "adhoc")
        self.assertEqual(sev(s), "suspicious")
        # downloads dominate -> nothing
        self.assertEqual(na.exfil_signals("/Users/x/bin/agent", 60 * MB, 600 * MB, "unsigned"), [])
        # browsers / cloud sync / Developer ID apps: nothing or info only
        self.assertEqual(na.exfil_signals("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                                          5000 * MB, 100 * MB, "devid", "Developer ID: Google LLC"), [])
        self.assertEqual(na.exfil_signals("/Applications/Dropbox.app/Contents/MacOS/Dropbox", 9000 * MB, 1 * MB,
                                          "devid"), [])
        self.assertIn(sev(na.exfil_signals("/Applications/Foo.app/Contents/MacOS/Foo", 2000 * MB, 1 * MB, "devid")),
                      ("info", None))
        steam = "/Users/x/Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/MacOS/steam_osx"
        self.assertIn(sev(na.exfil_signals(steam, 80 * MB, 1 * MB, "devid", "Developer ID: Valve")),
                      ("info", "low", None))
        # Homebrew interpreters: info at most
        self.assertIn(sev(na.exfil_signals("/opt/homebrew/Cellar/python@3.12/3.12.1/bin/python3.12", 900 * MB,
                                           1 * MB, "adhoc")), ("info", None))
        # Apple system daemons are never judged here, Apple's upload tools are (low)
        self.assertEqual(na.exfil_signals("/usr/sbin/mDNSResponder", 900 * MB, 1, "apple"), [])
        self.assertEqual(sev(na.exfil_signals("/usr/bin/curl", 60 * MB, 1 * MB, "apple")), "low")
        self.assertEqual(na.exfil_signals("/usr/bin/curl", 60 * MB, 600 * MB, "apple"), [])

    def test_script_connections(self):
        conns = [{"remote": "185.220.101.1", "port": 4444}, {"remote": "8.8.8.8", "port": 443}]
        s = na.script_connection_signals("/usr/bin/python3", "python3", "apple", False, conns)
        self.assertEqual(s[0].score, 35)
        s = na.script_connection_signals("/usr/bin/curl", "curl", "apple", False,
                                         [{"remote": "185.220.101.1", "port": 8333}])
        self.assertEqual(s[0].score, 20)
        self.assertEqual(na.script_connection_signals("/usr/bin/curl", "curl", "apple", False,
                                                      [{"remote": "8.8.8.8", "port": 443}]), [])
        self.assertEqual(na.script_connection_signals("/opt/homebrew/bin/node", "node", "adhoc", True,
                                                      [{"remote": "8.8.8.8", "port": 5432}]), [])
        self.assertEqual(na.script_connection_signals("/Applications/X.app/Contents/MacOS/X", "X", "devid", False,
                                                      [{"remote": "8.8.8.8", "port": 7777}]), [])

    def test_netusage_history(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "netusage.sqlite")
            con = sqlite3.connect(db)
            con.executescript("""
                CREATE TABLE ZPROCESS (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, ZFIRSTTIMESTAMP TIMESTAMP,
                                       ZTIMESTAMP TIMESTAMP, ZBUNDLENAME VARCHAR, ZPROCNAME VARCHAR);
                CREATE TABLE ZLIVEUSAGE (Z_PK INTEGER PRIMARY KEY, ZHASPROCESS INTEGER, ZTIMESTAMP TIMESTAMP,
                                         ZWIFIIN FLOAT, ZWIFIOUT FLOAT, ZWIREDIN FLOAT, ZWIREDOUT FLOAT,
                                         ZWWANIN FLOAT, ZWWANOUT FLOAT);
                INSERT INTO ZPROCESS VALUES (1, 1, 780000000, 780500000, 'com.google.Chrome', 'Google Chrome');
                INSERT INTO ZPROCESS VALUES (2, 1, 781000000, 781000100, NULL, 'agentd/com.evil.agent');
                INSERT INTO ZLIVEUSAGE VALUES (1, 1, 780100000, 1000, 50, 0, 0, NULL, NULL);
                INSERT INTO ZLIVEUSAGE VALUES (2, 1, 780400000, 2000, 25, 10, 5, 0, 0);
                INSERT INTO ZLIVEUSAGE VALUES (3, 2, 781000050, 10, 900000, 0, 0, 0, 0);
            """)
            con.commit()
            con.close()
            items, err = na.read_netusage(db)
            self.assertIsNone(err)
            self.assertEqual(len(items), 2)
            self.assertEqual(set(items[0]), {"process", "bytes_out", "bytes_in", "first_seen", "last_seen"})
            self.assertEqual(items[0]["process"], "agentd (com.evil.agent)")
            self.assertEqual(items[0]["bytes_out"], 900000)
            chrome = items[1]
            self.assertEqual((chrome["bytes_in"], chrome["bytes_out"]), (3010, 80))
            self.assertEqual(chrome["process"], "Google Chrome (com.google.Chrome)")
            self.assertEqual(chrome["first_seen"], na.fmt_ts(na.CORE_DATA_EPOCH + 780000000))
            self.assertEqual(chrome["last_seen"], na.fmt_ts(na.CORE_DATA_EPOCH + 780500000))
            items, err = na.read_netusage(os.path.join(d, "missing-dir", "netusage.sqlite"))
            self.assertEqual(items, [])
            self.assertIn("nie istnieje", err)
            bad = os.path.join(d, "other.sqlite")
            sqlite3.connect(bad).execute("CREATE TABLE t(x)").connection.close()
            self.assertIn("nieznany format", na.read_netusage(bad)[1])

    def test_registered(self):
        names = [c[0] for c in COLLECTORS]
        self.assertIn(("netaudit_traffic", "netaudit", "collect_traffic"), COLLECTORS)
        self.assertIn(("netaudit_remote", "netaudit", "collect_remote"), COLLECTORS)
        self.assertGreater(names.index("netaudit_traffic"), names.index("network"))
        self.assertGreater(names.index("netaudit_remote"), names.index("ssh"))


class EndToEnd(unittest.TestCase):
    """Both collectors on a fake machine: TeamViewer connected, ngrok, SSH session from the Internet,
    a live connection to a ThreatFox C2 address and an unsigned uploader."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.home = os.path.join(t, "Users", "jan")
        os.makedirs(os.path.join(self.home, ".ssh"))
        with open(os.path.join(self.home, ".ssh", "authorized_keys"), "w") as fh:
            fh.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEtoFakeKeyMaterialForTests0123456789abcdefgh laptop@home\n")
        self.apps = os.path.join(t, "Applications")
        os.makedirs(os.path.join(self.apps, "TeamViewer.app", "Contents", "MacOS"))
        os.makedirs(os.path.join(self.apps, "Tailscale.app"))
        os.makedirs(os.path.join(self.apps, "Google Chrome.app"))
        self.launch = os.path.join(t, "LaunchDaemons")
        os.makedirs(self.launch)
        with open(os.path.join(self.launch, "com.teamviewer.teamviewer_service.plist"), "wb") as fh:
            plistlib.dump({"Label": "com.teamviewer.teamviewer_service",
                           "Program": "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer_Service"}, fh)
        db = os.path.join(t, "netusage-missing", "netusage.sqlite")
        self.ctx = _ctx(self.home, netusage_db=db)
        tv = "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer_Service"
        self.ctx._procs = {
            1: {"pid": 1, "ppid": 0, "name": "launchd", "exe": "/sbin/launchd", "cmdline": None},
            200: {"pid": 200, "ppid": 1, "name": "TeamViewer_Service", "exe": tv, "cmdline": None},
            300: {"pid": 300, "ppid": 1, "name": "ngrok", "exe": "/opt/homebrew/bin/ngrok",
                  "cmdline": ["ngrok", "tcp", "22"], "username": "jan"},
            400: {"pid": 400, "ppid": 1, "name": "updater", "exe": "/Users/jan/Library/.cache/updater",
                  "cmdline": ["updater"]},
            500: {"pid": 500, "ppid": 1, "name": "Google Chrome",
                  "exe": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "cmdline": None},
            600: {"pid": 600, "ppid": 1, "name": "sshd-session", "exe": "/usr/libexec/sshd-session", "cmdline": None},
            700: {"pid": 700, "ppid": 1, "name": "curl", "exe": "/usr/bin/curl", "cmdline": ["curl", "-T", "x.zip"]},
        }

        def sock(proto, local, lport, remote, rport, state, pid, pname):
            return {"proto": proto, "local": local, "lport": lport, "remote": remote, "rport": rport, "state": state,
                    "pid": pid, "pname": pname, "rx": 0, "tx": 0}
        self.ctx._netaudit_socks = [
            sock("tcp46", "*", 22, "*", None, "LISTEN", 1, "launchd"),
            sock("tcp4", "192.168.1.10", 22, "45.33.32.156", 51000, "ESTABLISHED", 600, "sshd-session"),
            sock("tcp4", "192.168.1.10", 50001, "185.188.32.10", 5938, "ESTABLISHED", 200, "TeamViewer_Servi"),
            sock("tcp4", "192.168.1.10", 50002, "1.117.61.9", 443, "ESTABLISHED", 400, "updater"),
            sock("tcp4", "192.168.1.10", 50003, "142.250.1.1", 443, "ESTABLISHED", 500, "Google Chrome"),
            sock("tcp4", "192.168.1.10", 50004, "3.125.102.39", 443, "ESTABLISHED", 300, "ngrok"),
            sock("tcp4", "192.168.1.10", 50005, "185.220.101.1", 8333, "ESTABLISHED", 700, "curl"),
            sock("udp4", "*", 5353, "*", None, "", 500, "Google Chrome"),
        ]
        self.ctx.posture.update({"mdm_enrolled": True, "dep_enrolled": False})

    def tearDown(self):
        self.tmp.cleanup()

    def fake_run(self, argv, timeout=20.0, env=None):
        cmd = os.path.basename(argv[0])
        out, rc = "", 0
        if cmd == "nettop":
            out = (",bytes_in,bytes_out,\nupdater.400,1048576,125829120,\nGoogle Chrome.500,900000000,3000000000,\n"
                   "TeamViewer_Servi.200,1000,2000,\n")
        elif cmd == "sysctl":
            out = "{ sec = 1791037525, usec = 31710 } Sat Oct  3 16:25:25 2026\n"
        elif cmd == "who":
            out = "jan            console      Oct  3 16:25 \nadmin            ttys003      Oct  6 10:00 (45.33.32.156)\n"
        elif cmd == "last":
            out = "admin      ttys003   45.33.32.156          Tue Oct  6 10:00   still logged in\n"
        elif cmd == "launchctl":
            rc = 0 if argv[-1] == "system/com.openssh.sshd" else 113
        else:
            rc = 1
        return CmdResult(list(argv), rc, out, "")

    @staticmethod
    def fake_sign(ctx, exe):
        if not exe:
            return None, None
        if na.is_apple_path(exe):
            return "Apple", None
        if "TeamViewer" in exe:
            si = SignInfo(exe, "devid", authority="Developer ID Application: TeamViewer Germany GmbH (H7UGFBUGV6)")
        elif "Google Chrome" in exe:
            si = SignInfo(exe, "devid", authority="Developer ID Application: Google LLC (EQHXZ8M8AV)")
        elif "homebrew" in exe:
            si = SignInfo(exe, "adhoc")
        else:
            si = SignInfo(exe, "unsigned")
        return na.signer_label(si), si

    def test_collectors(self):
        threat = {"1.117.61.9": "ThreatFox.win.cobalt_strike"}
        with mock.patch.object(na, "run", self.fake_run), \
                mock.patch.object(na, "_sign", self.fake_sign), \
                mock.patch.object(na, "_ioc_lookup", lambda ctx: threat.get), \
                mock.patch.object(na, "APP_DIRS", [self.apps]), \
                mock.patch.object(na, "SYSTEM_LAUNCH_DIRS", [self.launch]), \
                mock.patch.object(na, "EXTRA_DIRS", []), \
                mock.patch.object(na, "ARD_LAUNCHD_FLAG", os.path.join(self.tmp.name, "nope")):
            na.collect_traffic(self.ctx)
            na.collect_remote(self.ctx)
        a = self.ctx.inventory["network_audit"]
        self.assertEqual(list(a), PROTOCOL_KEYS)
        self.assertEqual(set(a["summary"]), SUMMARY_KEYS)
        self.assertEqual(a["boot_time"], na.fmt_ts(1791037525))
        s = a["summary"]
        self.assertEqual(s["ioc_hits"], 1)
        self.assertEqual(s["listening_all_interfaces"], 1)
        self.assertEqual(s["public_connections"], 6)                 # incl. the inbound SSH peer
        self.assertEqual(s["processes_online"], 6)
        self.assertEqual(s["uploaded_bytes_since_boot"], 125829120 + 3000000000 + 2000)
        self.assertEqual(s["remote_tools"], 2)                       # TeamViewer + ngrok (Tailscale is info)
        self.assertEqual(a["traffic"][0]["process"], "Google Chrome")
        self.assertEqual(set(a["traffic"][0]), {"process", "pid", "exe", "bytes_out", "bytes_in", "signer"})
        self.assertEqual(a["traffic_history"]["available"], False)
        self.assertTrue(a["traffic_history"]["reason"])
        ioc = [c for c in a["connections"] if c["ioc"]]
        self.assertEqual(len(ioc), 1)
        self.assertTrue(ioc[0]["ioc"].startswith("ThreatFox: win.cobalt_strike"))
        self.assertEqual(a["listening"][0]["service"], "Zdalne logowanie (SSH)")
        self.assertEqual(a["sessions"][1]["from"], "45.33.32.156")
        self.assertTrue(a["logins"][0]["remote"])
        for item in a["remote_access"]:
            self.assertEqual(set(item), {"name", "kind", "status", "detail", "risk"})
            self.assertIn(item["kind"], {"macos_service", "app", "tunnel", "mdm", "ssh_keys", "session"})
            self.assertIn(item["status"], {"enabled", "running", "installed", "disabled", "present"})
            self.assertIn(item["risk"], {"info", "low", "suspicious", "malicious"})
        by_name = {i["name"]: i for i in a["remote_access"]}
        self.assertEqual(by_name["TeamViewer"]["status"], "running")
        self.assertEqual(by_name["TeamViewer"]["risk"], "suspicious")
        self.assertEqual(by_name["ngrok"]["kind"], "tunnel")
        self.assertEqual(by_name["Tailscale (VPN / sieć mesh)"]["risk"], "info")
        self.assertEqual(by_name["Zdalne logowanie (SSH)"]["status"], "enabled")
        self.assertEqual(by_name["Udostępnianie ekranu (VNC)"]["status"], "disabled")
        self.assertEqual(by_name["Zarządzanie urządzeniem (MDM)"]["status"], "enabled")
        self.assertEqual(by_name["Klucze SSH (authorized_keys) – jan"]["risk"], "low")
        self.assertNotIn("Google Chrome", by_name)

        f = {x.title: x for x in self.ctx.findings}
        c2 = [x for x in self.ctx.findings if x.detection.name.endswith("IocConnection")]
        self.assertEqual(len(c2), 1)
        self.assertEqual(c2[0].severity, "malicious")
        self.assertEqual(c2[0].category, "network")
        leak = [x for x in self.ctx.findings if x.title.startswith("Możliwy wyciek danych: updater")]
        self.assertEqual(len(leak), 1)
        self.assertEqual(leak[0].severity, "suspicious")
        self.assertFalse([x for x in self.ctx.findings if "Google Chrome" in x.title])
        curl = f["Nietypowe połączenia wychodzące: curl (pid 700)"]      # Apple's curl is not exempt
        self.assertEqual((curl.severity, curl.detection.name), ("low", "Heur:Env.NetAudit.ScriptUnusualPort"))
        tv = f["Narzędzie zdalnego dostępu: TeamViewer (działa)"]
        self.assertEqual((tv.severity, tv.category), ("suspicious", "remote_access"))
        self.assertTrue(tv.detection.name.startswith("Heur:Env.Remote.TeamViewer"))
        self.assertEqual(f["Tunel sieciowy: ngrok (pid 300)"].severity, "suspicious")
        self.assertEqual(f["Aktywna sesja zdalna: admin z 45.33.32.156"].severity, "suspicious")
        # the same SSH login is not reported a second time as an inbound connection
        self.assertEqual(f["Włączona usługa zdalnego dostępu: Zdalne logowanie (SSH)"].severity, "low")
        self.assertNotIn("Aktywne połączenie zdalne: Zdalne logowanie (SSH)", f)
        self.assertIn(f["Zdalne logowania w historii (last)"].severity, ("low", "suspicious"))
        self.assertEqual(f["Logowanie kluczem SSH bez hasła: jan"].severity, "low")
        self.assertIn(f["Komputer zarządzany przez MDM"].severity, ("info", "low"))
        self.assertTrue(any("netusage" in x for x in self.ctx.limitations))
        for x in self.ctx.findings:
            self.assertIn(x.category, ("network", "remote_access"))
        # everything must be JSON-serialisable for the app
        import json
        from cerber.envscan.model import jsonable
        json.dumps(jsonable(self.ctx.inventory), ensure_ascii=False)
        json.dumps([x.to_dict() for x in self.ctx.findings], ensure_ascii=False)

    def test_missing_commands_do_not_raise(self):
        def broken_run(argv, timeout=20.0, env=None):
            return CmdResult(list(argv), None, "", "command not found", missing=True)
        self.ctx._netaudit_socks = []
        with mock.patch.object(na, "run", broken_run), mock.patch.object(na, "_ioc_lookup", lambda ctx: None), \
                mock.patch.object(na, "APP_DIRS", []), mock.patch.object(na, "SYSTEM_LAUNCH_DIRS", []), \
                mock.patch.object(na, "EXTRA_DIRS", []):
            na.collect_traffic(self.ctx)
            na.collect_remote(self.ctx)
        a = self.ctx.inventory["network_audit"]
        self.assertEqual(list(a), PROTOCOL_KEYS)
        self.assertEqual(a["traffic"], [])
        self.assertTrue(any("nettop" in x for x in self.ctx.limitations))
        self.assertTrue(any("who" in x for x in self.ctx.limitations))


if __name__ == "__main__":
    unittest.main()

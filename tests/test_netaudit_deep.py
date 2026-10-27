"""Tests for the deep network & behaviour audit (cerber.envscan.netaudit_deep).

Fixtures are real outputs captured on macOS 26 (anonymised: user names, MAC addresses and IPs replaced) plus
lines in the exact format of the log messages / tools for events that did not occur on the test Mac (XProtect
detections, SSH brute force, new launch agents …). Commands are never run for real except the trivial
/bin/echo used by the precompute round-trip test; certificates are generated in memory.

    python -m unittest tests.test_netaudit_deep -v
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from cerber.envscan import COLLECTORS, netaudit_deep as nd  # noqa: E402
from cerber.envscan.model import combine, severity_of  # noqa: E402
from cerber.envscan.util import CmdResult, EnvContext, UserHome, precomputed_key  # noqa: E402


def L(ts, proc, subsystem, category, fmt, msg, pid=100):
    """One `log show --style ndjson` line (same keys as the real output)."""
    return json.dumps({"timezoneName": "", "messageType": "Default", "eventType": "logEvent", "source": None,
                       "formatString": fmt, "subsystem": subsystem, "category": category,
                       "processImagePath": proc, "timestamp": ts + ".123456+0200", "eventMessage": msg,
                       "processID": pid, "traceID": 1, "parentActivityIdentifier": 0})


XPR = "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediator"
AUTHD = "/System/Library/Frameworks/Security.framework/Versions/A/XPCServices/authd.xpc/Contents/MacOS/authd"
TCCD = "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd"
BTMD = "/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd"
SPD = "/usr/libexec/syspolicyd"
AUTH_OK = "Succeeded authorizing right '%{public}s' by client '%{public}s' [%d] for authorization created by '%{public}s' [%d] (%X,%d) (engine %llu)"
AUTH_FAIL = "Failed to authorize right '%{public}s' by client '%{public}s' [%d] for authorization created by '%{public}s' [%d] (%X,%d) (%d) (engine %llu)"
TCC_FMT = "AUTHREQ_PROMPTING: msgID=%{public}@, service=%{public}@, subject=%{public}@, "

# --- captured on the test Mac (clean machine): only routine events
REAL_LOG = "\n".join([
    L("2026-10-07 04:34:19", XPR + "Eicar", "com.apple.XProtectFramework.PluginAPI", "XPEvent.structured", "%{public}s",
      '{"caused_by":[],"execution_duration":8.702278137207031e-05,"status_message":"NoThreatDetected","status_code":20}'),
    L("2026-10-07 04:54:51", XPR + "MRTv3", "com.apple.XProtectFramework.PluginAPI", "XPEvent.structured", "%{public}s",
      '{"caused_by":[],"status_code":0,"status_message":"Success","execution_duration":0.00010192394256591797}'),
    L("2026-10-06 20:24:36", AUTHD, "com.apple.Authorization", "authd", AUTH_OK,
      "Succeeded authorizing right 'com.apple.ServiceManagement.daemons.modify' by client '/usr/libexec/mdmclient' [54789] "
      "for authorization created by '/usr/libexec/mdmclient' [54789] (2,0) (engine 359)"),
    L("2026-10-07 07:36:52", AUTHD, "com.apple.Authorization", "authd", AUTH_OK,
      "Succeeded authorizing right 'system.login.screensaver' by client '/System/Library/CoreServices/loginwindow.app' [406] "
      "for authorization created by '/System/Library/CoreServices/loginwindow.app' [406] (202,0) (engine 439)"),
    L("2026-10-06 21:53:34", TCCD, "com.apple.TCC", "access", TCC_FMT,
      "AUTHREQ_PROMPTING: msgID=7436.89, service=kTCCServiceSystemPolicyDownloadsFolder, subject=Sub:{pl.cerber.app}"
      "Resp:{TCCDProcess: identifier=pl.cerber.app, pid=73727, auid=501, euid=501, responsible_path=/Applications/"
      "Cerber.app/Contents/MacOS/Cerber, binary_path=/Applications/Cerber.app/Contents/MacOS/Cerber},"),
    L("2026-10-06 20:07:50", TCCD, "com.apple.TCC", "access", TCC_FMT,
      "AUTHREQ_PROMPTING: msgID=7436.44, service=kTCCServiceSystemPolicyDocumentsFolder, subject=Sub:{com.localcode.app}"
      "Resp:{TCCDProcess: identifier=com.localcode.app, pid=6143, auid=501, euid=501, responsible_path=/Applications/"
      "LocalCode.app/Contents/MacOS/LocalCode, binary_path=/Applications/LocalCode.app/Contents/MacOS/LocalCode},"),
    L("2026-10-06 16:59:43", BTMD, "com.apple.backgroundtaskmanagement", "main",
      "registerLaunchItem: found existing item: %{public}@",
      "registerLaunchItem: found existing item: uuid=FBE9D4A3-F7F7-43BF-9ACC-57CB9DCDD277, name=GarageBandSpotlightImporter"
      ".mdimporter, type=spotlight, disposition=[enabled, allowed, notified], identifier=64.com.apple.garageband."
      "spotlightimporter, url=Contents/Library/Spotlight/GarageBandSpotlightImporter.mdimporter -- file:///Applications/"
      "GarageBand.app/"),
    L("2026-10-07 00:32:16", SPD, "com.apple.syspolicy.exec", "default",
      "GK evaluateScanResult: %lu, %@, %d, %d, %d, %d, %lu, %lu, %d",
      "GK evaluateScanResult: 3, PST: (path: 6665eb3f17a1911a), (team: Q6L2SF6YDW), (id: com.anthropic.claudefordesktop), "
      "(bundle_id: com.anthropic.claudefordesktop), 0, 0, 1, 0, 4, 4, 1"),
    '{"count":8,"finished":1}',
])

# --- an infected / attacked Mac (message formats from the binaries: sshd, authd, syspolicyd, BTM, tccd)
SSHD = "/usr/libexec/sshd-session"
ATTACK_LOG = "\n".join(
    [L("2026-10-05 10:00:%02d" % i, SSHD, "", "", "%s",
       f"Failed password for {'invalid user ' if i % 2 else ''}{'admin' if i % 2 else 'jan'} from 45.33.32.156 port {50000 + i} ssh2")
     for i in range(14)]
    + [L("2026-10-05 10:01:00", SSHD, "", "", "%s", "Accepted password for jan from 45.33.32.156 port 50100 ssh2"),
       L("2026-10-05 11:00:00", SSHD, "", "", "%s", "Failed none for jan from 192.168.1.20 port 51000 ssh2"),
       L("2026-10-05 11:00:01", SSHD, "", "", "%s", "Invalid user test from 192.168.1.20 port 51001"),
       L("2026-10-06 03:10:00", XPR + "Adload", "com.apple.XProtectFramework.PluginAPI", "XPEvent.structured",
         "%{public}s", '{"caused_by":["/Users/jan/Library/Application Support/.mdworker/mdworker"],"status_code":30,'
                       '"status_message":"ThreatDetected","execution_duration":0.01}'),
       L("2026-10-06 03:20:00", SPD, "com.apple.syspolicy.exec", "default", "Attempting to move malware to trash: %@",
         "Attempting to move malware to trash: <private>"),
       L("2026-10-06 03:20:01", SPD, "com.apple.syspolicy.exec", "default",
         "Successfully moved malware to trash, trashed URL is %@", "Successfully moved malware to trash, trashed URL is <private>"),
       L("2026-10-06 09:00:00", SPD, "com.apple.syspolicy.exec", "default", "Adding user intent: %@",
         "Adding user intent: PST: (path: 1a2b3c), (team: (null)), (id: com.free.cracked), (bundle_id: com.free.cracked)"),
       L("2026-10-06 09:00:00", SPD, "com.apple.syspolicy.exec", "default", "Adding user intent: %@",
         "Adding user intent: PST: (path: 1a2b3c), (team: (null)), (id: com.free.cracked), (bundle_id: com.free.cracked)"),
       L("2026-10-06 08:59:00", SPD, "com.apple.syspolicy.exec", "default", "Prompting user about blocked executable: %@",
         "Prompting user about blocked executable: <private>"),
       L("2026-10-06 09:05:00", BTMD, "com.apple.backgroundtaskmanagement", "main",
         "registerLaunchItem: result=%{public}@, new item=%{public}@",
         "registerLaunchItem: result=no error, new item=uuid=0A1B2C3D-0000-4000-8000-000000000001, name=com.apple.updater, "
         "type=legacy agent, disposition=[enabled, allowed, notified], identifier=8.com.apple.updater, "
         "url=file:///Users/jan/Library/LaunchAgents/com.apple.updater.plist"),
       L("2026-10-06 09:06:00", BTMD, "com.apple.backgroundtaskmanagement", "main", "addItem: %{public}@ uid=%d",
         "addItem: uuid=0A1B2C3D-0000-4000-8000-000000000002, name=Helper, type=app, disposition=[enabled, allowed, "
         "notified], identifier=2.com.example.helper, url=file:///Users/Shared/.x/Helper.app/ uid=501"),
       L("2026-10-06 09:07:00", BTMD, "com.apple.backgroundtaskmanagement", "main",
         "registerLaunchItem: result=%{public}@, new item=%{public}@",
         "registerLaunchItem: result=no error, new item=uuid=0A1B2C3D-0000-4000-8000-000000000003, name=Docker, type=app, "
         "disposition=[enabled, allowed, notified], identifier=2.com.docker.docker, url=file:///Applications/Docker.app/"),
       L("2026-10-06 09:10:00", AUTHD, "com.apple.Authorization", "authd", AUTH_OK,
         "Succeeded authorizing right 'system.privilege.admin' by client '/usr/bin/osascript' [999] for authorization "
         "created by '/usr/bin/osascript' [999] (3,0) (engine 501)"),
       L("2026-10-06 09:11:00", AUTHD, "com.apple.Authorization", "authd", AUTH_OK,
         "Succeeded authorizing right 'system.privilege.admin' by client '/usr/libexec/security_authtrampoline' [998] for "
         "authorization created by '/private/tmp/.inst/Installer' [997] (3,0) (engine 502)"),
       ]
    + [L("2026-10-06 22:%02d:00" % i, AUTHD, "com.apple.Authorization", "authd", AUTH_FAIL,
         "Failed to authorize right 'system.login.screensaver' by client '/System/Library/CoreServices/loginwindow.app' "
         "[406] for authorization created by '/System/Library/CoreServices/loginwindow.app' [406] (100013,0) (-60005) "
         f"(engine {600 + i})") for i in range(11)]
    + [L("2026-10-06 22:30:00", AUTHD, "com.apple.Authorization", "authd", AUTH_FAIL,
         "Failed to authorize right 'system.preferences' by client '/System/Applications/System Settings.app' [1] for "
         "authorization created by '/System/Applications/System Settings.app' [1] (3,0) (-60006) (engine 700)"),
       L("2026-10-06 23:00:00", TCCD, "com.apple.TCC", "access", TCC_FMT,
         "AUTHREQ_PROMPTING: msgID=1.2, service=kTCCServiceScreenCapture, subject=Sub:{/private/tmp/.x/agent}Resp:"
         "{TCCDProcess: identifier=agent, pid=4242, auid=501, euid=501, responsible_path=/private/tmp/.x/agent, "
         "binary_path=/private/tmp/.x/agent},"),
       L("2026-10-06 23:01:00", TCCD, "com.apple.TCC", "access", TCC_FMT,
         "AUTHREQ_PROMPTING: msgID=1.3, service=kTCCServiceAppleEvents, subject=Sub:{com.apple.osascript}Resp:"
         "{TCCDProcess: identifier=com.apple.osascript, pid=4243, auid=501, euid=501, responsible_path=/usr/bin/osascript, "
         "binary_path=/usr/bin/osascript},"),
       L("2026-10-06 23:02:00", "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/"
         "screensharingd", "", "", "%s", "Authentication: SUCCEEDED :: User Name: jan :: Viewer Address: 81.2.3.4 :: Type: DH"),
       ])

ROUTE = """   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
"""
ARP_CLEAN = """? (192.168.1.1) at 00:00:5e:00:53:04 on en0 ifscope [ethernet]
? (192.168.1.28) at 00:00:5e:00:53:05 on en0 ifscope [ethernet]
? (192.168.1.29) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.40) at 02:00:00:00:00:06 on en0 ifscope [ethernet]
? (192.168.1.41) at 02:00:00:00:00:06 on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (192.168.139.255) at ff:ff:ff:ff:ff:ff on bridge100 ifscope [bridge]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""
ARP_SPOOF = ARP_CLEAN.replace("192.168.1.28) at 00:00:5e:00:53:05", "192.168.1.28) at 00:00:5e:00:53:04")
IPCONFIG = """<dictionary> {
  BSSID : <redacted>
  ConnectionID : 46
  IPv4 : <array> {
    0 : <dictionary> {
      Addresses : <array> {
        0 : 192.168.1.57
      }
      ConfigMethod : DHCP
      DHCP : <dictionary> {
        Packet : op = BOOTREPLY
options:
dhcp_message_type (uint8): ACK 0x5
server_identifier (ip): 192.168.1.1
router (ip_mult): {192.168.1.1}
domain_name_server (ip_mult): {192.168.1.1, 1.1.1.1}
domain_name (string): home.example
end (none):

        State : BOUND
      }
      IsPublished : TRUE
      Router : 192.168.1.1
      RouterARPVerified : TRUE
    }
  }
  InterfaceType : WiFi
  LinkStatusActive : TRUE
  NetworkID : <redacted>
  SSID : <redacted>
  Security : WPA2_PSK
}
"""
AIRPORT = json.dumps({"SPAirPortDataType": [{"spairport_airport_interfaces": [
    {"_name": "en0", "spairport_status_information": "spairport_status_connected",
     "spairport_current_network_information": {"_name": "<redacted>", "spairport_network_channel": "104 (5GHz, 80MHz)",
                                               "spairport_network_phymode": "802.11ax",
                                               "spairport_security_mode": "spairport_security_mode_wpa2_personal"}},
    {"_name": "awdl0", "spairport_current_network_information": {"spairport_network_type": "spairport_network_type_station"}}]}]})
NDP = """fe80::%utun0 if=utun0, flags=IST, pref=medium, expire=Never
fe80::2037:a5ff:fe09:7564%en0 if=en0, flags=, pref=medium, expire=1h59m38s
fe80::1%en0 if=en0, flags=, pref=high, expire=29m
"""
TRUST = """Number of trusted certs = 4
Cert 0: mitmproxy
   Number of trust settings : 0
Cert 1: COMODO RSA Certification Authority
   Number of trust settings : 2
   Trust Setting 0:
      Policy OID            : SSL
      Allowed Error         : CSSMERR_TP_CERT_EXPIRED
      Result Type           : kSecTrustSettingsResultTrustRoot
   Trust Setting 1:
      Policy OID            : Apple X509 Basic
      Result Type           : kSecTrustSettingsResultTrustRoot
Cert 2: mkcert development CA
   Number of trust settings : 1
   Trust Setting 0:
      Policy OID            : SSL
      Result Type           : kSecTrustSettingsResultTrustRoot
Cert 3: Old Mail Signer
   Number of trust settings : 1
   Trust Setting 0:
      Policy OID            : S/MIME
      Result Type           : kSecTrustSettingsResultDeny
"""


def make_ca(cn: str, org: str | None = None, ca: bool = True, days: int = 365) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)] + ([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org)]
                                                            if org else [])
    name = x509.Name(attrs)
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def cert_dump(pems: list[str]) -> str:
    out = []
    for i, p in enumerate(pems):
        out.append(f"SHA-256 hash: {'%064X' % (i + 1)}\nSHA-1 hash: {'%040X' % (i + 1)}\n{p}")
    return "".join(out)


def _ctx(home: str = "/Users/jan", **opts) -> EnvContext:
    o = {"codesign": False, "homes_override": [UserHome("jan", 501, home)]}
    o.update(opts)
    return EnvContext(o)


def _sev(sigs):
    d = combine(sigs)
    return severity_of(d) if d else None


class LogParsing(unittest.TestCase):
    def test_parse_ndjson(self):
        evs = nd.parse_log_ndjson(REAL_LOG + "\ngarbage\n{\"not\": \"an event\"}")
        self.assertEqual(len(evs), 8)
        self.assertEqual(evs[0]["process"], "XProtectRemediatorEicar")
        self.assertEqual(evs[0]["time"], "2026-10-07 04:34:19")
        self.assertEqual(evs[2]["subsystem"], "com.apple.Authorization")

    def test_clean_mac_no_findings(self):
        res = nd.analyze_syslog(nd.parse_log_ndjson(REAL_LOG))
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["counts"]["xprotect_scans"], 2)
        self.assertEqual(res["counts"]["privileged_authorizations"], 0)    # Apple's own mdmclient is not reported
        self.assertEqual(res["counts"]["new_login_items"], 0)              # "found existing item" is not new
        self.assertEqual(res["counts"]["privacy_prompts"], 1)                     # LocalCode; Cerber's own skipped
        self.assertFalse(any("pl.cerber" in e["title"] for e in res["events"]))
        kinds = {e["category"] for e in res["events"]}
        self.assertEqual(kinds, {"xprotect", "privacy"})
        self.assertTrue(all(e["severity"] == "info" for e in res["events"]))
        for e in res["events"]:
            self.assertEqual(set(e), {"time", "category", "title", "detail", "severity", "process"})

    def test_attacked_mac(self):
        res = nd.analyze_syslog(nd.parse_log_ndjson(ATTACK_LOG), home="/Users/jan")
        by_title = {t: (loc, sigs, det) for t, loc, sigs, det in res["findings"]}
        c = res["counts"]
        # XProtect Remediator detection -> malicious
        xpr = [v for t, v in by_title.items() if t.startswith("XProtect Remediator wykrył")]
        self.assertEqual(len(xpr), 1)
        self.assertEqual(_sev(xpr[0][1]), "malicious")
        self.assertIn(".mdworker", xpr[0][2]["caused_by"][0])
        # XProtect block at launch: both syspolicyd lines form one incident
        self.assertEqual(c["xprotect_blocks"], 1)
        blk = [v for t, v in by_title.items() if t.startswith("XProtect zablokował")][0]
        self.assertEqual(_sev(blk[1]), "suspicious")
        self.assertTrue(blk[2]["moved_to_trash"])
        # SSH: brute force from one public IP followed by a successful login
        self.assertEqual(c["ssh_failed"], 15)          # 14 + "Invalid user" from the LAN ("Failed none" ignored)
        self.assertEqual(c["ssh_accepted"], 1)
        bf = [v for t, v in by_title.items() if t.startswith("Próby włamania przez SSH")][0]
        self.assertEqual(_sev(bf[1]), "suspicious")
        self.assertEqual(bf[2]["attempts"], 14)
        self.assertEqual(sorted(bf[2]["users"]), ["admin", "jan"])
        succ = [v for t, v in by_title.items() if t.startswith("Udane logowanie SSH po serii")][0]
        self.assertEqual(_sev(succ[1]), "malicious")
        self.assertFalse(any("192.168.1.20" in t for t in by_title))      # one LAN typo: event only
        # Gatekeeper: duplicated override line counted once; block is info
        self.assertEqual(c["gatekeeper_overrides"], 1)
        self.assertEqual(c["gatekeeper_blocks"], 1)
        ov = [v for t, v in by_title.items() if "mimo ostrzeżenia Gatekeeper" in t][0]
        self.assertEqual(_sev(ov[1]), "low")
        self.assertIn("com.free.cracked", ov[1][0].evidence[0])
        # new persistence: launch agent (low) + app in a hidden /Users/Shared folder (suspicious); Docker is benign
        self.assertEqual(c["new_login_items"], 3)
        per = [v for t, v in by_title.items() if t.startswith("Nowe elementy autostartu")][0]
        self.assertEqual(_sev(per[1]), "suspicious")
        odd = " ".join(per[1][0].evidence)
        self.assertIn("/Users/Shared/.x/Helper.app", odd)                           # hidden folder in /Users/Shared
        self.assertIn("LaunchAgents/com.apple.updater.plist", odd)                   # fake "com.apple" agent
        self.assertNotIn("Docker", odd)
        # 11 wrong passwords at the lock screen within an hour -> suspicious; the cancelled dialog is ignored
        self.assertEqual(c["auth_failures"], 11)
        pw = [v for t, v in by_title.items() if "podania hasła" in t][0]
        self.assertEqual(_sev(pw[1]), "suspicious")
        # admin rights: osascript (low) and an installer from /tmp (suspicious)
        self.assertEqual(_sev(by_title["Program skryptowy uzyskał uprawnienia administratora: osascript"][1]), "low")
        tmp = [v for t, v in by_title.items() if "z nietypowego miejsca uzyskał" in t][0]
        self.assertEqual(_sev(tmp[1]), "suspicious")
        self.assertEqual(tmp[0], "/private/tmp/.inst/Installer")
        # privacy prompts: screen recording from /tmp (suspicious), osascript automation (low)
        self.assertEqual(_sev(by_title["agent prosi o dostęp: Nagrywanie ekranu"][1]), "suspicious")
        self.assertEqual(_sev(by_title["osascript prosi o dostęp: Automatyzacja (sterowanie innymi aplikacjami)"][1]),
                         "low")
        # screen sharing from the Internet
        self.assertEqual(_sev(by_title["Zdalny podgląd ekranu z 81.2.3.4"][1]), "low")
        # events: capped schema, most severe first
        ev = res["events"]
        self.assertEqual(ev[0]["severity"], "malicious")
        order = {"malicious": 0, "suspicious": 1, "low": 2, "info": 3}
        self.assertEqual([order[e["severity"]] for e in ev], sorted(order[e["severity"]] for e in ev))

    def test_btm_item_parser(self):
        it = nd.parse_btm_item("uuid=X, name=GarageBandSpotlightImporter.mdimporter, type=spotlight, disposition=[enabled, "
                               "allowed, notified], identifier=64.com.apple.garageband.spotlightimporter, url=Contents/"
                               "Library/Spotlight/GarageBandSpotlightImporter.mdimporter -- file:///Applications/Garage"
                               "Band.app/")
        self.assertEqual(it["type"], "spotlight")
        self.assertEqual(it["disposition"], "enabled, allowed, notified")
        self.assertEqual(it["path"], "/Applications/GarageBand.app/Contents/Library/Spotlight/GarageBandSpotlightImporter"
                                     ".mdimporter")
        it = nd.parse_btm_item("uuid=Y, name=My App, type=legacy agent, disposition=[enabled, allowed, not notified], "
                               "identifier=8.com.x, url=file:///Users/jan/Library/LaunchAgents/com.x%20y.plist")
        self.assertEqual(it["name"], "My App")
        self.assertEqual(it["path"], "/Users/jan/Library/LaunchAgents/com.x y.plist")

    def test_subject_of(self):
        self.assertEqual(nd._subject_of("Adding user intent: <private>"), "nazwa ukryta przez macOS")
        self.assertEqual(nd._subject_of("GK x: PST: (path: ab), (team: ABCD1234), (id: com.x), (bundle_id: (null))"),
                         "com.x (zespół ABCD1234)")

    def test_log_store_since(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "Persist"))
            p = os.path.join(d, "Persist", "0000000000000001.tracev3")
            open(p, "w").close()
            r = nd.log_store_since(d)
            self.assertIsNotNone(r["persist_since"])
            self.assertIsNone(r["special_since"])

    def test_queries_avoid_slow_predicates(self):
        for _, pred, _, _ in nd.LOG_QUERIES.values():
            self.assertNotIn(" IN {", pred)                       # `process IN {…}` costs ~150 s CPU per day
            self.assertNotIn("eventMessage", pred)                # needs every message composed
        self.assertIn('process == "sshd-session"', nd.LOG_QUERIES["security"][1])


class Lan(unittest.TestCase):
    def test_route_and_arp(self):
        self.assertEqual(nd.parse_route_get(ROUTE), {"gateway": "192.168.1.1", "interface": "en0"})
        e = nd.parse_arp(ARP_CLEAN)
        self.assertEqual(len(e), 8)
        self.assertTrue(e[2]["incomplete"])
        self.assertEqual(e[-1]["mac"], "01:00:5e:00:00:fb")
        a = nd.analyze_arp(e, "192.168.1.1", "en0")
        self.assertEqual(a["gateway_mac"], "00:00:5e:00:53:04")
        self.assertEqual(a["gateway_shared_with"], [])
        self.assertEqual(a["multi_ip_macs"], [{"mac": "02:00:00:00:00:06", "interface": "en0",
                                               "ips": ["192.168.1.40", "192.168.1.41"]}])
        a = nd.analyze_arp(nd.parse_arp(ARP_SPOOF), "192.168.1.1", "en0")
        self.assertEqual(a["gateway_shared_with"], ["192.168.1.28"])
        self.assertTrue(nd.mac_is_local("02:00:00:00:00:06"))
        self.assertFalse(nd.mac_is_local("00:00:5e:00:53:04"))
        self.assertEqual(nd.normalize_mac("0:1b:2:aa:b:c"), "00:1b:02:aa:0b:0c")

    def test_wifi(self):
        s = nd.parse_ipconfig_summary(IPCONFIG)
        self.assertEqual((s["interface_type"], s["security"], s["ssid"], s["link_active"]), ("WiFi", "WPA2_PSK", None, True))
        self.assertEqual(s["dns"], ["192.168.1.1", "1.1.1.1"])
        self.assertEqual((s["dhcp_server"], s["router"], s["domain"], s["router_arp_verified"]),
                         ("192.168.1.1", "192.168.1.1", "home.example", True))
        ap = nd.parse_airport_json(AIRPORT)
        self.assertEqual((ap["interface"], ap["security"], ap["ssid"], ap["connected"]), ("en0", "WPA2_PSK", None, True))
        self.assertEqual(nd.parse_airport_json("not json"), {})
        self.assertEqual(nd.classify_wifi_security("None")[0], "open")
        self.assertEqual(nd.classify_wifi_security("WEP")[0], "wep")
        self.assertEqual(nd.classify_wifi_security("WPA_PSK")[0], "wpa")
        self.assertEqual(nd.classify_wifi_security("WPA2_PSK")[2], 0)
        self.assertEqual(nd.classify_wifi_security("WPA3_SAE")[0], "wpa3")
        self.assertEqual(nd.classify_wifi_security("WPA2_Enterprise")[0], "enterprise")
        self.assertEqual(nd.classify_wifi_security("OWE")[2], 0)
        self.assertEqual(nd.classify_wifi_security(None)[0], "unknown")

    def test_ndp(self):
        r = nd.parse_ndp_routers(NDP)
        self.assertEqual([x["router"] for x in r], ["fe80::2037:a5ff:fe09:7564", "fe80::1"])
        self.assertEqual(r[1]["pref"], "high")

    def _run_lan(self, arp: str, security: str = "WPA2_PSK"):
        ctx = _ctx()

        def fake(argv, timeout=20.0, env=None):
            cmd = " ".join(argv[1:])
            out = {"-n get default": ROUTE, "-an": arp, "getsummary en0": IPCONFIG.replace("WPA2_PSK", security),
                   "-rn": NDP}.get(cmd)
            return CmdResult(argv, 0 if out is not None else 1, out or "", "")
        with mock.patch.object(nd, "run", fake):
            nd.collect_lan(ctx)
        return ctx

    def test_collect_lan(self):
        ctx = self._run_lan(ARP_CLEAN)
        lan = ctx.inventory["network_audit"]["lan"]
        self.assertEqual(set(lan), {"gateway", "wifi", "dhcp", "arp_entries", "arp_suspicious", "arp_multi_ip",
                                    "ipv6_routers"})
        self.assertEqual(lan["gateway"], {"ip": "192.168.1.1", "mac": "00:00:5e:00:53:04", "interface": "en0",
                                          "mac_randomized": False})
        self.assertEqual(lan["wifi"]["security_level"], "wpa2")
        self.assertEqual(lan["wifi"]["source"], "ipconfig")
        # two IPv6 routers on en0 -> low finding; nothing else on a normal home network
        self.assertEqual([(f.category, f.severity) for f in ctx.findings], [("lan", "low")])
        ctx = self._run_lan(ARP_SPOOF, security="None")
        titles = {f.title: f.severity for f in ctx.findings}
        self.assertEqual(titles["Możliwe podszywanie się pod router (ARP spoofing)"], "low")
        self.assertEqual(titles["Połączenie z otwartą siecią Wi-Fi (bez szyfrowania)"], "low")
        self.assertEqual(ctx.inventory["network_audit"]["lan"]["arp_suspicious"][0]["ips"],
                         ["192.168.1.1", "192.168.1.28"])


class Certs(unittest.TestCase):
    def test_trust_parser_and_scope(self):
        t = nd.parse_trust_settings(TRUST)
        self.assertEqual([c["name"] for c in t], ["mitmproxy", "COMODO RSA Certification Authority",
                                                  "mkcert development CA", "Old Mail Signer"])
        self.assertEqual(t[1]["settings"][0]["allowed_errors"], ["CSSMERR_TP_CERT_EXPIRED"])
        self.assertEqual([nd.trust_scope(c) for c in t], ["all", "ssl", "ssl", "deny"])
        self.assertEqual(nd.parse_trust_settings("SecTrustSettingsCopyCertificates: No Trust Settings were found."), [])

    def test_cert_dump_and_details(self):
        pem = make_ca("mitmproxy", "mitmproxy")
        dump = nd.parse_cert_dump(cert_dump([pem, make_ca("leaf.example", ca=False)]))
        self.assertEqual(len(dump), 2)
        self.assertEqual(dump[0]["sha256"], "%064X" % 1)
        d = nd.cert_details(dump[0]["pem"])
        self.assertEqual((d["subject_cn"], d["subject_o"], d["is_ca"], d["self_signed"], d["expired"]),
                         ("mitmproxy", "mitmproxy", True, True, False))
        self.assertEqual(len(d["sha256"]), 64)
        self.assertFalse(nd.cert_details(dump[1]["pem"])["is_ca"])
        self.assertIsNone(nd.cert_details("garbage"))

    def test_classification(self):
        ca = {"subject": "CN=x", "issuer": "CN=x", "is_ca": True, "self_signed": True, "expired": False}
        k = lambda name, scope="all", dom="user", dup=False: nd.classify_trusted_cert(name, ca, scope, dom, dup)  # noqa
        self.assertEqual(k("mitmproxy")["kind"], "interception_tool")
        self.assertEqual(k("Charles Proxy CA (7 Oct 2026, MacBook)")["tool"], "Charles Proxy")
        self.assertEqual(k("DO_NOT_TRUST_FiddlerRoot")["tool"], "Fiddler")
        self.assertEqual(k("PortSwigger CA")["tool"], "Burp Suite")
        self.assertEqual(k("Proxyman CA (1 Jan 2026, mac)")["tool"], "Proxyman")
        self.assertEqual(k("HTTP Toolkit CA")["tool"], "HTTP Toolkit")
        self.assertEqual(k("Superfish, Inc.")["kind"], "adware")
        self.assertEqual(k("mkcert development CA")["kind"], "dev")
        self.assertEqual(k("Zscaler Root CA")["kind"], "enterprise")
        self.assertEqual(k("Securly SSL CA")["kind"], "enterprise")
        self.assertEqual(k("ESET SSL Filter CA")["kind"], "antivirus_filter")
        self.assertEqual(k("COMODO RSA Certification Authority")["kind"], "impersonation")
        self.assertEqual(k("COMODO RSA Certification Authority", dup=True)["kind"], "system_duplicate")
        self.assertEqual(k("Totally Unknown Root")["kind"], "unknown")
        self.assertEqual(k("Totally Unknown Root", scope="deny")["kind"], "distrusted")
        self.assertGreaterEqual(k("Totally Unknown Root")["score"], 35)
        self.assertLess(nd.classify_trusted_cert("Mail Signer", {**ca, "is_ca": False, "self_signed": False},
                                                 "other", "user")["score"], 35)
        self.assertGreater(k("mitmproxy", dom="admin")["score"], k("mitmproxy")["score"])
        for name in ("mitmproxy", "Charles Proxy CA"):
            self.assertIn("ktoś może czytać Twój ruch HTTPS", k(name)["explanation"])

    def test_collect_certs(self):
        pems = [make_ca("mitmproxy", "mitmproxy"), make_ca("COMODO RSA Certification Authority", "COMODO CA Limited"),
                make_ca("mkcert development CA", "mkcert development CA"), make_ca("Old Mail Signer", ca=False)]
        dump = cert_dump(pems)
        ctx = _ctx()

        def fake(argv, timeout=20.0, env=None):
            if argv == nd.TRUST_ARGV["user"]:
                return CmdResult(argv, 0, TRUST, "")
            if argv == nd.TRUST_ARGV["admin"]:
                return CmdResult(argv, 1, "", "SecTrustSettingsCopyCertificates: No Trust Settings were found.")
            if argv == nd.CERT_ARGV:
                return CmdResult(argv, 0, dump, "")
            if argv == nd.ROOTS_ARGV:
                return CmdResult(argv, 0, "SHA-256 hash: " + "AB" * 32 + "\n", "")
            return CmdResult(argv, 1, "", "unexpected")
        with mock.patch.object(nd, "run", fake), mock.patch.dict(os.environ, {"CERBER_PRECOMPUTED": ""}), \
                mock.patch.object(nd, "system_root_hashes", lambda: set()):
            nd.collect_certs(ctx)
        certs = ctx.inventory["network_audit"]["certificates"]
        self.assertEqual(len(certs), 4)
        self.assertEqual(set(certs[0]), {"name", "domain", "trust", "policies", "subject", "issuer", "not_before",
                                         "not_after", "expired", "is_ca", "self_signed", "sha256", "kind", "tool",
                                         "risk", "explanation"})
        by = {c["name"]: c for c in certs}
        self.assertEqual(by["COMODO RSA Certification Authority"]["kind"], "impersonation")
        self.assertEqual(by["COMODO RSA Certification Authority"]["risk"], "suspicious")
        self.assertEqual(certs[0]["name"], "COMODO RSA Certification Authority")       # sorted by risk
        self.assertEqual(by["mitmproxy"]["risk"], "low")
        self.assertTrue(by["mitmproxy"]["is_ca"])
        self.assertEqual(by["Old Mail Signer"]["kind"], "distrusted")
        sev = {f.title: f.severity for f in ctx.findings}
        self.assertEqual(sev["Zaufany certyfikat narzędzia do podglądu HTTPS: mitmproxy"], "low")
        self.assertEqual(sev["Certyfikat podszywający się pod urząd certyfikacji: COMODO RSA Certification Authority"],
                         "suspicious")
        self.assertEqual(sev["Lokalny certyfikat deweloperski: mkcert development CA"], "info")
        self.assertTrue(all(f.category == "certs" for f in ctx.findings))
        self.assertEqual(len(ctx.findings), 3)                                       # distrusted cert: no finding

    def test_system_roots(self):
        with tempfile.TemporaryDirectory() as d:
            der = b"\x30\x03\x02\x01\x01"
            with open(os.path.join(d, "x.cer"), "wb") as fh:
                fh.write(der)
            import hashlib
            self.assertEqual(nd.system_root_hashes(d), {hashlib.sha256(der).hexdigest().upper()})
        self.assertEqual(nd.system_root_hashes("/nonexistent"), set())
        if os.path.isdir(nd.ANCHORS):                                    # real macOS trust store
            self.assertGreater(len(nd.system_root_hashes()), 100)

    def test_no_trust_settings(self):
        ctx = _ctx()
        none = lambda argv, timeout=20.0, env=None: CmdResult(argv, 1, "", "No Trust Settings were found.")  # noqa
        with mock.patch.object(nd, "run", none), mock.patch.dict(os.environ, {"CERBER_PRECOMPUTED": ""}):
            nd.collect_certs(ctx)
        self.assertEqual(ctx.inventory["network_audit"]["certificates"], [])
        self.assertEqual(ctx.findings, [])
        self.assertEqual(ctx.limitations, [])


class SyslogCollector(unittest.TestCase):
    def _collect(self, results: dict, env: dict | None = None):
        ctx = _ctx(log_store="/nonexistent")

        def fake(argv, timeout=20.0, env=None):
            key = next((k for k, (w, p, *_rest) in nd.LOG_QUERIES.items() if argv == nd.log_argv(w, p)), None)
            return results.get(key) or CmdResult(argv, 0, '{"count":0,"finished":1}\n', "")
        with mock.patch.object(nd, "run", fake), mock.patch.dict(os.environ, env or {"CERBER_PRECOMPUTED": ""}):
            nd.collect_syslog(ctx)
        return ctx

    def test_collect_syslog_shape(self):
        ctx = self._collect({"security": CmdResult([], 0, ATTACK_LOG, "")})
        sl = ctx.inventory["network_audit"]["syslog"]
        self.assertEqual(set(sl), {"window", "events", "counts", "available", "reason"})
        self.assertTrue(sl["available"])
        self.assertIsNone(sl["reason"])
        self.assertEqual(set(sl["window"]), {"from", "to", "days", "persist_since", "special_since"})
        self.assertLessEqual(len(sl["events"]), nd.MAX_EVENTS)
        self.assertEqual(sl["counts"]["events_total"], len(sl["events"]))
        self.assertTrue(all(f.category == "syslog" for f in ctx.findings))
        self.assertIn("malicious", {f.severity for f in ctx.findings})

    def test_sandboxed_log_degrades(self):
        refused = CmdResult([], 64, "", "log: Cannot run while sandboxed\n")
        ctx = self._collect({"security": refused, "privacy": refused})
        sl = ctx.inventory["network_audit"]["syslog"]
        self.assertFalse(sl["available"])
        self.assertIn("sandboksie", sl["reason"])
        self.assertEqual(ctx.findings, [])
        self.assertTrue(any("niedostępna" in x for x in ctx.limitations))

    def test_timeout_keeps_partial_output(self):
        ctx = self._collect({"security": CmdResult([], None, ATTACK_LOG, "", timed_out=True)})
        self.assertTrue(ctx.inventory["network_audit"]["syslog"]["available"])
        self.assertTrue(ctx.findings)
        self.assertTrue(any("limit czasu" in x for x in ctx.limitations))


class Precompute(unittest.TestCase):
    def test_round_trip_and_wait(self):
        with tempfile.TemporaryDirectory() as d:
            fast = ["/bin/echo", "cerber"]
            slow = ["/bin/sh", "-c", "sleep 0.6; echo late"]
            h = nd.start_precompute(d, [(fast, 5), (slow, 5)])
            with mock.patch.dict(os.environ, {"CERBER_PRECOMPUTED": d}):
                r = nd._precomputed(slow, max_wait=10)          # pending in the manifest -> waits for it
                self.assertIsNotNone(r)
                self.assertEqual((r.rc, r.out), (0, "late\n"))
                r = nd._precomputed(fast, max_wait=10)
                self.assertEqual(r.out, "cerber\n")
                self.assertIsNone(nd._precomputed(["/bin/echo", "not", "listed"], max_wait=1))
                self.assertTrue(os.path.exists(os.path.join(d, precomputed_key(fast) + ".json")))
            h.join(5)
            h.cancel()

    def test_cancel_kills(self):
        with tempfile.TemporaryDirectory() as d:
            t0 = time.monotonic()
            h = nd.start_precompute(d, [(["/bin/sleep", "30"], 60)])
            time.sleep(0.3)
            h.cancel()
            h.join(5)
            self.assertLess(time.monotonic() - t0, 10)

    def test_precompute_list(self):
        argvs = [a for a, _ in nd.PRECOMPUTE]
        self.assertIn(nd.CERT_ARGV, argvs)
        self.assertIn(nd.TRUST_ARGV["user"], argvs)
        self.assertEqual(sum(1 for a in argvs if a[0] == nd.LOG), len(nd.LOG_QUERIES))

    def test_registered_after_remote(self):
        names = [c[0] for c in COLLECTORS]
        i = names.index("netaudit_remote")
        self.assertEqual(names[i + 1:i + 4], ["netaudit_syslog", "netaudit_lan", "netaudit_certs"])
        self.assertTrue(all(n.startswith("netaudit") for n in names[i + 1:i + 4]))


if __name__ == "__main__":
    unittest.main()

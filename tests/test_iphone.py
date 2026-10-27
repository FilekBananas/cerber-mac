"""iPhone check (cerber/iphone.py) on synthetic data: a tiny fake backup (Manifest.db + sms.db + plists), an
encrypted backup, the no-device case and – once – the whole `gui_backend iphone backup` flow inside the sandbox."""
import datetime as dt
import hashlib
import json
import os
import plistlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from cerber import iphone  # noqa: E402
from cerber.feeds_ios import build_db  # noqa: E402

UDID = "00008110-0012345678ABCDEF"
PEGASUS = "free247downloads.com"          # published Pegasus infrastructure (Amnesty 2021)
PROFILE_UUID = "0a1b2c3d-1111-2222-3333-444455556666"


def fid(domain: str, rel: str) -> str:
    return hashlib.sha1(f"{domain}-{rel}".encode()).hexdigest()


def _write(p: str, data: bytes) -> None:
    with open(p, "wb") as fh:
        fh.write(data)


def make_backup(root: str, encrypted: bool = False) -> str:
    """A minimal Finder-style backup: Info/Manifest/Status plists, Manifest.db and a few databases."""
    b = os.path.join(root, UDID)
    os.makedirs(b)
    now = dt.datetime.now().replace(microsecond=0)
    store_meta = plistlib.dumps({"itemName": "Notatnik", "artistName": "Example", "sourceApp": "com.apple.AppStore",
                                 "com.apple.iTunesStore.downloadInfo": {"purchaseDate": "2024-01-02T10:00:00Z"}})
    info = {"Device Name": "iPhone testowy", "Product Type": "iPhone14,5", "Product Name": "iPhone 13",
            "Product Version": "17.4", "Last Backup Date": now, "Target Identifier": UDID,
            "Installed Applications": ["com.example.notes", "com.mspy.lite", "com.corp.helper", "com.saurik.Cydia"],
            "Applications": {"com.example.notes": {"iTunesMetadata": store_meta}}}
    manifest = {"IsEncrypted": encrypted, "WasPasscodeSet": True, "Version": "10.0",
                "Lockdown": {"UniqueDeviceID": UDID, "ProductVersion": "17.4", "DeviceName": "iPhone testowy"},
                "Applications": {"com.example.notes": {"CFBundleVersion": "1"}}}
    for name, data in (("Info.plist", info), ("Manifest.plist", manifest),
                       ("Status.plist", {"SnapshotState": "finished", "IsFullBackup": False, "Date": now})):
        with open(os.path.join(b, name), "wb") as fh:
            plistlib.dump(data, fh)
    if encrypted:
        with open(os.path.join(b, "Manifest.db"), "wb") as fh:
            fh.write(os.urandom(4096))          # encrypted Manifest.db is not a SQLite file
        return b

    files: list[tuple[str, str]] = []

    def put(domain: str, rel: str, maker) -> None:
        f = fid(domain, rel)
        os.makedirs(os.path.join(b, f[:2]), exist_ok=True)
        maker(os.path.join(b, f[:2], f))
        files.append((domain, rel))

    def sms(p: str) -> None:
        con = sqlite3.connect(p)
        con.executescript("""
            CREATE TABLE handle(ROWID INTEGER PRIMARY KEY, id TEXT);
            CREATE TABLE message(ROWID INTEGER PRIMARY KEY, text TEXT, attributedBody BLOB, date INTEGER,
                                 handle_id INTEGER, is_from_me INTEGER);
            CREATE TABLE attachment(ROWID INTEGER PRIMARY KEY, filename TEXT, mime_type TEXT, uti TEXT,
                                    transfer_name TEXT);""")
        con.execute("INSERT INTO handle VALUES (1, '+48600100200')")
        con.execute("INSERT INTO message VALUES (1, ?, NULL, 700000000000000000, 1, 0)",
                    (f"Twoja paczka czeka: https://{PEGASUS}/a1b2c3 sprawdz",))
        con.execute("INSERT INTO message VALUES (2, 'zwykla wiadomosc https://example.org/x', NULL, 1, 1, 1)")
        con.execute("INSERT INTO attachment VALUES (1, '~/Library/SMS/Attachments/ab/01/x/image.gif', "
                    "'application/pdf', 'com.adobe.pdf', 'image.gif')")
        con.commit()
        con.close()

    def datausage(p: str) -> None:
        con = sqlite3.connect(p)
        con.executescript("""
            CREATE TABLE ZPROCESS(Z_PK INTEGER PRIMARY KEY, ZPROCNAME TEXT, ZBUNDLENAME TEXT, ZFIRSTTIMESTAMP REAL,
                                  ZTIMESTAMP REAL);
            CREATE TABLE ZLIVEUSAGE(Z_PK INTEGER PRIMARY KEY, ZHASPROCESS INTEGER, ZWIFIIN REAL, ZWIFIOUT REAL,
                                    ZWWANIN REAL, ZWWANOUT REAL);
            INSERT INTO ZPROCESS VALUES (1, 'com.apple.WebKit.Networking/com.apple.WebKit.Networking', NULL, 1, 2);
            INSERT INTO ZPROCESS VALUES (2, 'bh/bh', NULL, 700000000, 700000100);
            INSERT INTO ZPROCESS VALUES (3, 'BackupAgent/BackupAgent', NULL, 700000000, 700000100);
            INSERT INTO ZLIVEUSAGE VALUES (1, 3, 1000, 2000, 0, 0);""")
        con.commit()
        con.close()

    def profile(p: str) -> None:
        with open(p, "wb") as fh:
            plistlib.dump({"PayloadDisplayName": "Ustawienia sieci", "PayloadIdentifier": "net.evil.profile",
                           "PayloadUUID": PROFILE_UUID, "PayloadOrganization": "Nieznana firma",
                           "InstallDate": now, "PayloadContent": [{"PayloadType": "com.apple.mdm"},
                                                                  {"PayloadType": "com.apple.security.root"}]}, fh)

    def prefs(p: str) -> None:
        with open(p, "wb") as fh:
            plistlib.dump({"LDMGlobalEnabled": False}, fh)

    put("HomeDomain", "Library/SMS/sms.db", sms)
    put("WirelessDomain", "Library/Databases/DataUsage.sqlite", datausage)
    put(iphone.PROFILE_DOMAIN, "Library/ConfigurationProfiles/profile-abc.stub", profile)
    put("HomeDomain", "Library/Preferences/.GlobalPreferences.plist", prefs)
    put("MediaDomain", "Library/SMS/Attachments/ab/01/x/image.gif", lambda p: _write(p, b"%PDF-1.7 x"))
    con = sqlite3.connect(os.path.join(b, "Manifest.db"))
    con.execute("CREATE TABLE Files(fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    rows = [(fid(d, r), d, r, 1, None) for d, r in files]
    rows += [(fid("AppDomain-com.mspy.lite", "Documents"), "AppDomain-com.mspy.lite", "Documents", 2, None),
             (fid("HomeDomain", "Library/WebKit/WebsiteData/LocalStorage/https_" + PEGASUS + "_0.localstorage"),
              "HomeDomain", "Library/WebKit/WebsiteData/LocalStorage/https_" + PEGASUS + "_0.localstorage", 1, None)]
    con.executemany("INSERT INTO Files VALUES (?,?,?,?,?)", rows)
    con.commit()
    con.close()
    return b


def make_ioc_db(path: str) -> None:
    build_db(path, {
        "Amnesty Tech": [("domain", PEGASUS, "Pegasus (NSO Group)", "infra"),
                         ("process", "bh", "Pegasus (NSO Group)", "infra"),
                         ("process", "backupagent", "Operation Triangulation", "infra")],
        "Echap": [("bundle_id", "com.mspy.lite", "Stalkerware: mSpy", "app"),
                  ("domain", "mspy.com", "Stalkerware: mSpy", "website")],
        "MVT": [("profile_id", PROFILE_UUID, "Test profile", "infra")],
    })


class BackupAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cerber-iphone-test-")
        cls.db = os.path.join(cls.tmp, "ios_ioc.sqlite")
        make_ioc_db(cls.db)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def matcher(self):
        m = iphone.Matcher(ios_path=self.db, mac_path="")
        self.addCleanup(m.close)
        return m

    def test_full_backup(self):
        b = make_backup(os.path.join(self.tmp, "plain"))
        events = []
        r = iphone.analyze(b, None, matcher=self.matcher(), emit=events.append)
        titles = [f["title"] for f in r["findings"]]
        sev = {f["title"]: f["severity"] for f in r["findings"]}
        sms = [f for f in r["findings"] if "Pegasus" in f["title"] and "SMS" in f["title"]]
        self.assertTrue(sms, titles)
        self.assertEqual(sms[0]["severity"], "malicious")
        self.assertTrue(any(PEGASUS in e for e in sms[0]["evidence"]))
        self.assertTrue(any("WebKit" in t and "Pegasus" in t for t in titles), titles)        # website data origin
        self.assertTrue(any("DataUsage" in t and "Pegasus" in t for t in titles), titles)     # process bh
        self.assertTrue(any("mSpy" in t and sev[t] == "malicious" for t in titles), titles)   # stalkerware app
        self.assertTrue(any("FORCEDENTRY" in t for t in titles), titles)
        self.assertTrue(any("Triangulation" in t and "BackupAgent" in t for t in titles), titles)
        weak = [f for f in r["findings"] if f["title"].startswith("Możliwy ślad Operation Triangulation")]
        self.assertTrue(weak and weak[0]["severity"] == "suspicious", titles)   # generic name alone: not malicious
        prof = [f for f in r["findings"] if f["category"] == "profile"]
        self.assertTrue(prof and prof[0]["severity"] in ("suspicious", "malicious"), titles)
        self.assertTrue(any("profilach" in t for t in titles), titles)                      # profile UUID indicator
        self.assertTrue(any("jailbreak" in t.lower() for t in titles), titles)
        self.assertTrue(any("spoza App Store" in t for t in titles), titles)                 # com.corp.helper
        self.assertFalse(any("example.org" in e for f in r["findings"] for e in f["evidence"]))
        self.assertEqual(r["posture"].get("lockdown_mode"), False)
        self.assertEqual(r["device"].get("name"), "iPhone testowy")
        self.assertEqual({c["id"]: c["status"] for c in r["checks"]}.get("sms"), "ok")
        self.assertTrue(any(e.get("ev") == "iphone_finding" for e in events))
        self.assertTrue(any(e.get("ev") == "progress" and e.get("stage") == "analyze" for e in events))
        self.assertTrue(iphone.advice_for(r["findings"], r["posture"]))
        html_path = iphone.write_html({"verdict": "MALICIOUS", "title": "t", **r}, os.path.join(self.tmp, "r.html"))
        with open(html_path, encoding="utf-8") as fh:
            self.assertIn("Pegasus", fh.read())

    def test_backup_not_modified(self):
        b = make_backup(os.path.join(self.tmp, "ro"))
        before = {os.path.relpath(os.path.join(r, f), b): os.path.getmtime(os.path.join(r, f))
                  for r, _d, fs in os.walk(b) for f in fs}
        iphone.analyze(b, None, matcher=self.matcher())
        after = {os.path.relpath(os.path.join(r, f), b): os.path.getmtime(os.path.join(r, f))
                 for r, _d, fs in os.walk(b) for f in fs}
        self.assertEqual(before, after)          # no -journal/-wal files, nothing touched

    def test_encrypted_backup(self):
        b = make_backup(os.path.join(self.tmp, "enc"), encrypted=True)
        meta = iphone.backup_meta(b)
        self.assertTrue(meta["encrypted"])
        r = iphone.analyze(b, None, matcher=self.matcher())
        self.assertTrue(any("zaszyfrowana" in x for x in r["limitations"]))
        self.assertEqual({c["id"]: c["status"] for c in r["checks"]}.get("manifest"), "skipped")
        self.assertTrue(any("mSpy" in f["title"] for f in r["findings"]))      # app list still works (Info.plist)
        self.assertFalse(any("SMS" in f["title"] for f in r["findings"]))

    def test_no_indicator_db(self):
        b = make_backup(os.path.join(self.tmp, "noioc"))
        r = iphone.analyze(b, None, matcher=iphone.Matcher(ios_path=os.path.join(self.tmp, "missing.sqlite"),
                                                           mac_path=""))
        self.assertTrue(any("Brak bazy wskaźników" in x for x in r["limitations"]))
        self.assertTrue(any(f["category"] == "profile" for f in r["findings"]))   # heuristics still run

    def test_url_extraction_and_validation(self):
        self.assertEqual(iphone.extract_urls("a https://x.example.com/p?q=1). b www.foo.pl,"),
                         ["https://x.example.com/p?q=1", "www.foo.pl"])
        self.assertTrue(iphone.valid_udid(UDID))
        self.assertFalse(iphone.valid_udid("-x; rm -rf /"))
        self.assertFalse(iphone.valid_udid("--help"))


class NoDevice(unittest.TestCase):
    def test_devices_event_without_tools_or_backups(self):
        tmp = tempfile.mkdtemp(prefix="cerber-iphone-nodev-")
        events = []
        try:
            with mock.patch.object(iphone, "find_tools", return_value={}), \
                    mock.patch.object(iphone, "_usb_iphones", return_value=[]), \
                    mock.patch.object(iphone, "mobilesync_access", return_value="missing"), \
                    mock.patch.object(iphone, "BACKUP_DIR", os.path.join(tmp, "none")):
                ev = iphone.devices_event(events.append)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertEqual(ev["ev"], "iphone_devices")
        self.assertEqual(ev["devices"], [])
        self.assertEqual(ev["backups"], [])
        self.assertIsNone(ev["can_backup"])
        self.assertTrue(any("libimobiledevice" in n for n in ev["notes"]))
        self.assertTrue(any("Finderze" in n for n in ev["notes"]))

    def test_scan_without_anything_is_an_error(self):
        events = []
        with mock.patch.object(iphone, "find_tools", return_value={}), \
                mock.patch.dict(os.environ, {"CERBER_NO_SANDBOX": "1"}):
            rc = iphone.scan(events.append)
        self.assertEqual(rc, 1)
        self.assertTrue(any(e.get("ev") == "error" and e.get("fatal") for e in events))


class SandboxedFlow(unittest.TestCase):
    """The real app path: gui_backend iphone backup PATH -> inner-iphone in the read-only sandbox."""

    def test_gui_backend_backup(self):
        tmp = tempfile.mkdtemp(prefix="cerber-iphone-e2e-")
        try:
            b = make_backup(os.path.join(tmp, "bk"))
            home = os.path.join(tmp, "home")
            os.makedirs(os.path.join(home, "db", "compiled"))
            make_ioc_db(os.path.join(home, "db", "compiled", "ios_ioc.sqlite"))
            env = {**os.environ, "CERBER_HOME": home}
            p = subprocess.run([sys.executable, "-m", "cerber.gui_backend", "iphone", "backup", b], cwd=ROOT,
                               env=env, capture_output=True, text=True, timeout=600)
            events = [json.loads(ln) for ln in p.stdout.splitlines() if ln.strip()]
            done = [e for e in events if e.get("ev") == "iphone_done"]
            self.assertEqual(p.returncode, 0, p.stderr[-2000:])
            self.assertTrue(done, [e.get("ev") for e in events])
            s = done[0]["summary"]
            self.assertEqual(s["verdict"], "MALICIOUS")
            self.assertTrue(s["sandbox"]["verified"])                  # self-check ran inside the sandbox
            self.assertTrue(os.path.isfile(s["report_html"]))
            self.assertTrue(any(e.get("ev") == "iphone_finding" for e in events))
            self.assertTrue(any(e.get("ev") == "stage" and e.get("id") == "analyze" for e in events))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

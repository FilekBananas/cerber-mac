"""Offline tests of the iOS indicator feeds (synthetic STIX2 / Echap / csv data, no network)."""
import json
import os
import sqlite3
import tempfile
import unittest
import zipfile
from unittest import mock

from cerber import feeds_ios as fi

H256 = "ab" * 32
H1 = "cd" * 20


def _bundle():
    return {"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "malware", "id": "malware--p", "name": "Pegasus"},
        {"type": "malware", "id": "malware--x", "name": "Some_New_Thing"},
        {"type": "indicator", "id": "indicator--1", "pattern_type": "stix",
         "pattern": "[domain-name:value = 'Evil-Cdn[.]Example-Spy.com' OR domain-name:value = '*.c2.badspy.net']"},
        {"type": "indicator", "id": "indicator--2", "pattern_type": "stix",
         "pattern": "[process:name = 'roleaboutd'] AND [file:path = '/private/var/db/X.plist']"},
        {"type": "indicator", "id": "indicator--3", "pattern_type": "stix",
         "pattern": f"[file:hashes.'SHA-256' = '{H256.upper()}' OR file:hashes.sha1 = '{H1}' OR file:hashes.md5 = 'zz']"},
        {"type": "indicator", "id": "indicator--4", "pattern_type": "stix",
         "pattern": "[url:value = 'hxxps://spy-link[.]com/a/b'] OR [ipv4-addr:value = '45.9.148.3'] "
                    "OR [ipv4-addr:value = '10.0.0.1'] OR [email-addr:value = 'Bad@Mail[.]com']"},
        {"type": "indicator", "id": "indicator--5", "pattern_type": "stix",
         "pattern": "[app:id = 'com.evil.Agent' OR configuration-profile:id = 'ABC-123' "
                    "OR android-property:name = 'sys.x' OR domain-name:value = 'www.apple.com' "
                    "OR domain-name:value = 'cdn.cloudfront.net' OR domain-name:value LIKE '%.foo.com' "
                    f"OR app:cert.sha1 = '{H1}']"},
        {"type": "indicator", "id": "indicator--6", "pattern_type": "stix",
         "pattern": "[domain-name:value = '185.86.148.174']"},
        {"type": "indicator", "id": "indicator--7", "pattern_type": "stix",
         "pattern": "[domain-name:value = 'other-thing.org']"},
        *[{"type": "relationship", "id": f"relationship--{i}", "relationship_type": "indicates",
           "source_ref": f"indicator--{i}", "target_ref": "malware--p"} for i in range(1, 7)],
        {"type": "relationship", "id": "relationship--7", "relationship_type": "indicates",
         "source_ref": "indicator--7", "target_ref": "malware--x"},
    ]}


ECHAP = """\
- name: mSpy
  names:
  - mSpy
  type: stalkerware
  packages:
  - com.mspy.lite   # comment
  - med.mspy.mspy
  certificates:
  - 31A6ECECD97CF39BC4126B8745CD94A7C30BF81C
  websites:
  - mspy.com
  - www.mspy.com
  distribution:
    - dl.mspy-files.com
  c2:
    ips:
    - 69.64.74.239
    domains:
    - cp.mspyonline.com
    - abc.appspot.com

- name : OtherSpy
  type: stalkerware
  websites:
  - otherspy.net
  c2:
    ip:
    - 5.79.71.114
    domains:
    - otherspy.net

- name: FamiSafe
  type: watchware
  websites:
  - famisafe.com
"""

MVT_INDEX = """\
indicators:
  -
    type: github
    name: NSO Group Pegasus Indicators of Compromise
    sources:
      - Amnesty International
    github:
      owner: AmnestyTech
      repo: investigations
      branch: master
      path: 2021-07-18_nso/pegasus.stix2

  -
    type: github
    name: Fancy Spyware Indicators of Compromise
    github:
      owner: mvt-project
      repo: mvt-indicators
      branch: main
      path: fancy/fancy.stix2
"""


class ParseTests(unittest.TestCase):
    def test_stix_bundle(self):
        rows = set(fi.parse_stix2(json.dumps(_bundle())))
        P = "Pegasus (NSO Group)"
        expect = {("domain", "evil-cdn.example-spy.com", P), ("domain", "c2.badspy.net", P),
                  ("process", "roleaboutd", P), ("file_path", "/private/var/db/x.plist", P),
                  ("sha256", H256, P), ("sha1", H1, P), ("url", "https://spy-link.com/a/b", P),
                  ("ip", "45.9.148.3", P), ("email", "bad@mail.com", P), ("bundle_id", "com.evil.agent", P),
                  ("profile_id", "abc-123", P), ("cert", H1, P), ("ip", "185.86.148.174", P),
                  ("domain", "other-thing.org", "Some/New/Thing")}
        self.assertEqual(rows, expect)

    def test_stix_single_malware_fallback_and_default(self):
        b = {"objects": [{"type": "malware", "id": "malware--1", "name": "OperationTriangulation"},
                         {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value='backuprabbit.com']"}]}
        self.assertEqual(fi.parse_stix2(b), [("domain", "backuprabbit.com", "Operation Triangulation")])
        b = {"objects": [{"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value='x-spy.com']"}]}
        self.assertEqual(fi.parse_stix2(b, "Fancy"), [("domain", "x-spy.com", "Fancy")])
        self.assertEqual(fi.parse_stix2(b), [])          # no threat name at all -> dropped

    def test_normalize(self):
        n = fi.normalize
        self.assertEqual(n("domain", " *.Evil[.]Com. "), "evil.com")
        self.assertEqual(n("domain", "https://evil.com:8443/path"), "evil.com")
        for legit in ("apple.com", "www.icloud.com", "google.com", "github.com", "x.amazonaws.com",
                      "d1.cloudfront.net", "firebaseio.com", "localhost", "com", "-bad-.com", ""):
            self.assertIsNone(n("domain", legit), legit)
        self.assertEqual(n("domain", "a.b.firebaseio.com"), "a.b.firebaseio.com")
        self.assertIsNone(n("ip", "192.168.1.1"))
        self.assertIsNone(n("ip", "not-an-ip"))
        self.assertEqual(n("ip", "2001:4860::1/128"), "2001:4860::1")
        self.assertEqual(n("url", "hxxp://evil[.]com/x"), "http://evil.com/x")
        self.assertIsNone(n("url", "evil.com"))
        self.assertEqual(n("url", "nation-news.com/4077017s/"), "nation-news.com/4077017s/")
        self.assertIsNone(n("sha256", "abc"))
        self.assertEqual(n("cert", "AA:BB:" + "cc" * 18), "aabb" + "cc" * 18)
        self.assertEqual(n("process", "BackupAgent"), "backupagent")
        self.assertIsNone(n("process", "x"))
        self.assertIsNone(n("bundle_id", "not a bundle"))

    def test_echap(self):
        rows = set(fi.parse_echap(ECHAP))
        M, O = "Stalkerware: mSpy", "Stalkerware: OtherSpy"
        self.assertIn(("bundle_id", "com.mspy.lite", M, "app"), rows)
        self.assertIn(("bundle_id", "med.mspy.mspy", M, "app"), rows)
        self.assertIn(("cert", "31a6ececd97cf39bc4126b8745cd94a7c30bf81c", M, "app"), rows)
        self.assertIn(("domain", "mspy.com", M, "website"), rows)
        self.assertIn(("domain", "www.mspy.com", M, "website"), rows)
        self.assertIn(("domain", "dl.mspy-files.com", M, "website"), rows)
        self.assertIn(("ip", "69.64.74.239", M, "c2"), rows)
        self.assertIn(("domain", "cp.mspyonline.com", M, "c2"), rows)
        self.assertIn(("ip", "5.79.71.114", O, "c2"), rows)          # 'name :' and singular 'ip:'
        self.assertIn(("domain", "otherspy.net", O, "c2"), rows)
        self.assertNotIn("abc.appspot.com", {r[1] for r in rows})   # shared platform
        self.assertFalse(any("famisafe" in r[1] for r in rows))      # watchware ignored

    def test_mvt_index(self):
        e = fi.parse_mvt_index(MVT_INDEX)
        self.assertEqual([(x["owner"], x["path"]) for x in e],
                         [("AmnestyTech", "2021-07-18_nso/pegasus.stix2"), ("mvt-project", "fancy/fancy.stix2")])
        self.assertEqual(fi._index_threat(e[1]["name"]), "Fancy Spyware")

    def test_csvs(self):
        rows = fi.parse_amnesty_csv('domain_name,ip_address\n"14-tracking.com","191.101.31.25"\n"apple.com","1.2.3.4"\n',
                                    "Pegasus (NSO Group)")
        self.assertEqual(rows, [("domain", "14-tracking.com", "Pegasus (NSO Group)")])
        cl = ("uuid,event_id,category,type,value,comment,to_ids,date\n"
              '1,10,Network activity,domain,"smser.net","",1,2016\n'
              '2,10,Network activity,ip-dst,"52.8.153.44","",1,2016\n'
              '3,10,Payload delivery,url,"https://sms.webadv.co/3589003s/","",1,2016\n'
              '4,10,Network activity,domain,"skip.me","",0,2016\n')
        self.assertEqual(fi.parse_misp_csv(cl, "P"), [("domain", "smser.net", "P"),
                                                     ("url", "https://sms.webadv.co/3589003s/", "P")])


class DbTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "ios_ioc.sqlite")

    def tearDown(self):
        self.tmp.cleanup()

    def _build(self):
        rows = {"MVT": [("domain", "evil.com", "Predator (Intellexa/Cytrox)", "infra"),
                        ("url", "https://sms.webadv.co/3589003s/", "Pegasus (NSO Group)", "infra"),
                        ("ip", "45.9.148.3", "Pegasus (NSO Group)", "infra"),
                        ("process", "roleaboutd", "Pegasus (NSO Group)", "infra"),
                        ("bogus", "x", "y", "infra")],
                "Echap": [("domain", "mspy.com", "Stalkerware: mSpy", "website"),
                          ("domain", "mspy.com", "Stalkerware: mSpy", "c2"),      # strongest role wins
                          ("bundle_id", "com.mspy.lite", "Stalkerware: mSpy", "app")]}
        return fi.build_db(self.path, rows, {"MVT": {"fetched": "2026-01-01 00:00:00"}})

    def test_schema_and_stats(self):
        st = self._build()
        self.assertFalse(os.path.exists(self.path + ".new"))
        self.assertEqual(st["total"], 6)
        self.assertEqual(st["kinds"], {"bundle_id": 1, "domain": 2, "ip": 1, "process": 1, "url": 1})
        self.assertTrue(st["built"])
        src = {s["name"]: s for s in st["sources"]}
        self.assertEqual(src["MVT"]["counts"], {"domain": 1, "ip": 1, "process": 1, "url": 1})
        self.assertEqual(src["MVT"]["license"], fi.SOURCE_META["MVT"][1])
        self.assertEqual(src["MVT"]["fetched"], "2026-01-01 00:00:00")
        con = sqlite3.connect(self.path)
        self.assertEqual(con.execute("SELECT value FROM meta WHERE key='version'").fetchone()[0], "1")
        cols = [r[1] for r in con.execute("PRAGMA table_info(ioc)")]
        self.assertEqual(cols, ["kind", "value", "threat", "source", "role"])
        con.close()

    def test_lookups(self):
        self._build()
        db = fi.IOSIndicators(self.path)
        self.assertTrue(db.available)
        r = db.lookup("process", "RoleAboutD")
        self.assertEqual(r, [{"kind": "process", "value": "roleaboutd", "threat": "Pegasus (NSO Group)",
                              "source": "MVT", "role": "infra"}])
        self.assertEqual(db.lookup("domain", "mspy.com")[0]["role"], "c2")
        self.assertEqual(db.lookup("bundle_id", "com.mspy.lite")[0]["role"], "app")
        self.assertEqual([x["value"] for x in db.match_domain("a.b.Evil.com.")], ["evil.com"])
        self.assertEqual(db.match_domain("notevil.com"), [])
        self.assertEqual(db.match_domain("com"), [])
        self.assertEqual(db.match_domain("45.9.148.3")[0]["kind"], "ip")
        self.assertEqual(len(db.match_url("https://sms.webadv.co/3589003s")), 1)
        self.assertEqual(len(db.match_url("sms.webadv.co/3589003s/")), 1)
        self.assertEqual(len(db.match_url("http://sms.webadv.co/3589003s/?x=1#f")), 1)
        self.assertEqual(db.match_url("https://other.com/3589003s/"), [])
        self.assertEqual([x["value"] for x in db.match_url("https://x.evil.com/p?q")], ["evil.com"])
        self.assertEqual([x["kind"] for x in db.match_url("http://45.9.148.3:8080/a")], ["ip"])
        db.close()

    def test_missing_db(self):
        db = fi.IOSIndicators(os.path.join(self.tmp.name, "nope.sqlite"))
        self.assertFalse(db.available)
        self.assertEqual(db.lookup("domain", "evil.com"), [])
        self.assertEqual(db.match_domain("evil.com"), [])
        self.assertEqual(db.match_url("https://evil.com/"), [])
        self.assertEqual(db.stats(), {"total": 0, "built": "", "kinds": {}, "sources": []})

    def test_update_offline_with_failing_source(self):
        """Offline rebuild from cached zips; a failing source keeps its rows from the previous DB."""
        feeds = os.path.join(self.tmp.name, "feeds")
        os.makedirs(feeds)
        with zipfile.ZipFile(os.path.join(feeds, "ios_mvt-indicators.zip"), "w") as z:
            z.writestr("mvt-indicators-main/indicators.yaml", MVT_INDEX)
            z.writestr("mvt-indicators-main/fancy/fancy.stix2", json.dumps(
                {"objects": [{"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value='fancy-spy.net']"}]}))
        with zipfile.ZipFile(os.path.join(feeds, "ios_amnesty-investigations.zip"), "w") as z:
            z.writestr("investigations-master/2021-07-18_nso/pegasus.stix2", json.dumps(_bundle()))
            z.writestr("investigations-master/2019-10-10_nso_morocco/domains.txt", "stopsms.biz\napple.com\n")
        with zipfile.ZipFile(os.path.join(feeds, "ios_echap-stalkerware.zip"), "w") as z:
            z.writestr("stalkerware-indicators-master/ioc.yaml", ECHAP)
        # Citizen Lab csv missing from cache -> that source fails; seed an old DB holding one of its rows
        fi.build_db(self.path, {"Citizen Lab": [("domain", "smser.net", "Pegasus (NSO Group)", "infra")]})
        logs = []
        with mock.patch.object(fi.config, "FEEDS", feeds), mock.patch.object(fi, "_get", side_effect=AssertionError):
            st = fi.update_ios_indicators(logs.append, offline=True, path=self.path)
        self.assertIn("Citizen Lab", st["errors"])
        db = fi.IOSIndicators(self.path)
        self.assertEqual(db.lookup("domain", "fancy-spy.net")[0]["threat"], "Fancy Spyware")
        self.assertEqual(db.lookup("domain", "stopsms.biz")[0]["source"], "Amnesty Tech")
        self.assertEqual(db.lookup("process", "roleaboutd")[0]["threat"], "Pegasus (NSO Group)")
        self.assertEqual(db.lookup("ip", "69.64.74.239")[0]["role"], "c2")
        self.assertEqual(db.lookup("domain", "smser.net")[0]["source"], "Citizen Lab")   # carried over
        self.assertEqual(db.lookup("domain", "apple.com"), [])
        self.assertTrue(any("Citizen Lab" in m and "poprzedniej" in m for m in logs))
        db.close()


if __name__ == "__main__":
    unittest.main()

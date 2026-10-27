"""Tests for the known-malware artefact collector (cerber.envscan.artifacts).

Everything runs against a temporary fake file system: system paths are redirected with
options["artifacts_root"], home folders with homes_override, processes with a pre-filled
ctx._procs. The live system is never read.

    python -m unittest tests.test_artifacts -v
"""
from __future__ import annotations

import os
import plistlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from cerber.envscan import COLLECTORS, scan_environment  # noqa: E402
from cerber.envscan import artifacts as art  # noqa: E402
from cerber.envscan.util import EnvContext, UserHome  # noqa: E402

MACHO = bytes.fromhex("cffaedfe0c00000100000000") + b"\0" * 52


class FakeFS(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cerber-art-")
        self.root = os.path.join(self.tmp, "root")
        self.home = os.path.join(self.tmp, "Users", "victim")
        os.makedirs(self.root)
        os.makedirs(self.home)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # helpers -----------------------------------------------------------------
    def sys_path(self, p: str) -> str:
        return self.root + p

    def put(self, path: str, data: bytes = b"x\n") -> str:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def mkdir(self, path: str) -> str:
        os.makedirs(path, exist_ok=True)
        return path

    def plist(self, path: str, d: dict) -> str:
        return self.put(path, plistlib.dumps(d))

    def options(self, **extra) -> dict:
        o = {"categories": ["artifacts"], "artifacts_root": self.root, "artifacts_skip_processes": True,
             "homes_override": [UserHome("victim", 501, self.home)], "codesign": False}
        o.update(extra)
        return o

    def scan(self, **extra):
        rep = scan_environment(self.options(**extra))
        return [f for f in rep.findings if f.category == "artifacts"], rep

    def family(self, findings, fam):
        return [f for f in findings if f.details.get("family") == fam]


class Registration(unittest.TestCase):
    def test_registered_collector(self):
        names = {c[0]: (c[1], c[2]) for c in COLLECTORS}
        self.assertIn("artifacts", names)
        self.assertEqual(names["artifacts"], ("artifacts", "collect_artifacts"))
        order = [c[0] for c in COLLECTORS]
        self.assertGreater(order.index("artifacts"), order.index("processes"))

    def test_tables_consistent(self):
        for a in art.ARTIFACTS:
            self.assertIn(a.family, art.FAMILIES, a)
            self.assertIn(a.kind, ("any", "file", "dir", "macho"), a)
            self.assertTrue(a.path.startswith(("/", "~/")), a)
            self.assertTrue(0 < a.score <= 100, a)
        for d in art.DIR_PATTERNS:
            self.assertIn(d.family, art.FAMILIES, d)
        for fam, *_ in list(art.LABELS.values()) + list(art.BUNDLE_IDS.values()) + list(art.PROCESS_NAMES.values()):
            self.assertIn(fam, art.FAMILIES)
        paths = [a.path for a in art.ARTIFACTS]
        self.assertEqual(len(paths), len(set(paths)), "duplicate artefact paths")


class Clean(FakeFS):
    def test_empty_system_has_no_findings(self):
        # a normal developer home: dotfiles and folders that look a bit like the IOCs but are not them
        self.put(os.path.join(self.home, ".zshrc"), b"export PATH=$PATH\n")
        self.mkdir(os.path.join(self.home, ".local", "bin"))
        self.mkdir(os.path.join(self.home, ".config"))
        self.put(os.path.join(self.home, "Library/LaunchAgents/com.google.keystone.agent.plist"),
                 plistlib.dumps({"Label": "com.google.keystone.agent", "ProgramArguments": ["/x/ksagent"]}))
        self.put(os.path.join(self.home, "Library/Application Support/.ACCC_Lock"))
        self.mkdir(self.sys_path("/Applications/Discord.app/Contents/MacOS"))
        self.put(self.sys_path("/Applications/Discord.app/Contents/MacOS/Discord"), MACHO)
        findings, rep = self.scan()
        self.assertEqual(findings, [])
        self.assertEqual(rep.inventory.get("known_artifacts", []), [])

    def test_weak_only_is_not_reported_but_scanned(self):
        self.put(os.path.join(self.home, ".pass"))
        self.put(os.path.join(self.home, ".id"))
        findings, rep = self.scan()
        self.assertEqual(findings, [])
        self.assertTrue(any(os.path.join(self.home, ".pass") == t for t in rep.targets))
        inv = rep.inventory["known_artifacts"]
        self.assertTrue(inv and inv[0]["family"] == "AMOS" and inv[0].get("weak_only"))

    def test_macho_kind_is_enforced(self):
        self.put(self.sys_path("/Users/Shared/.log"), b"plain text log line\n")
        findings, _ = self.scan()
        self.assertEqual(findings, [])
        self.put(self.sys_path("/Users/Shared/.log"), MACHO)
        findings, _ = self.scan()
        kk = self.family(findings, "KandyKorn")
        self.assertEqual(len(kk), 1)
        self.assertEqual(kk[0].severity, "suspicious")


class Families(FakeFS):
    def test_amos_backdoor_is_malicious(self):
        helper = self.put(os.path.join(self.home, ".helper"), MACHO)
        self.put(os.path.join(self.home, ".agent"), b"#!/bin/bash\nwhile true; do sleep 1; done\n")
        self.plist(self.sys_path("/Library/LaunchDaemons/com.finder.helper.plist"),
                   {"Label": "com.finder.helper", "ProgramArguments": ["/bin/bash", "~/.agent"], "RunAtLoad": True})
        findings, rep = self.scan()
        amos = self.family(findings, "AMOS")
        self.assertTrue(amos)
        self.assertTrue(all(f.severity == "malicious" for f in amos), [(f.title, f.severity) for f in amos])
        self.assertTrue(any("Atomic Stealer (AMOS)" in f.title for f in amos))
        self.assertIn(helper, rep.targets)
        # the system daemon also points at ~/.agent -> evidence merged into the home finding
        home_f = [f for f in amos if f.details.get("home") == self.home][0]
        self.assertTrue(any(".launchd" in e for e in home_f.detection.evidence))

    def test_single_unique_artifact_is_malicious(self):
        self.put(self.sys_path("/Library/Caches/com.apple.safari.ck"))
        findings, _ = self.scan()
        kk = self.family(findings, "KandyKorn")
        self.assertEqual(len(kk), 1)
        self.assertEqual(kk[0].severity, "malicious")
        self.assertIn("KandyKorn", kk[0].title)
        self.assertEqual(kk[0].location, "/Library/Caches/com.apple.safari.ck")

    def test_nimdoor_and_chillyhell_paths(self):
        self.put(os.path.join(self.home, "Library/Application Support/Google LLC/GoogIe LLC"), MACHO)
        self.put(os.path.join(self.home, "Library/CoreKit/CoreKitAgent"), MACHO)
        self.put(os.path.join(self.home, "Library/com.apple.qtop/qtop"), MACHO)
        findings, _ = self.scan()
        nd = self.family(findings, "NimDoor")
        ch = self.family(findings, "ChillyHell")
        self.assertEqual(len(nd), 1)
        self.assertEqual(nd[0].severity, "malicious")
        self.assertIn("2 znane artefakty", nd[0].title)
        self.assertEqual(ch[0].severity, "malicious")

    def test_renamed_plist_found_by_label(self):
        self.plist(os.path.join(self.home, "Library/LaunchAgents/innocent.plist"),
                   {"Label": "com.apple.qtop", "ProgramArguments": ["/Users/x/Library/com.apple.qtop/qtop"]})
        findings, _ = self.scan()
        ch = self.family(findings, "ChillyHell")
        self.assertEqual(len(ch), 1)
        self.assertEqual(ch[0].severity, "malicious")

    def test_tutorial_label_alone_is_weak(self):
        # "com.user.loginscript" is Cuckoo's label but also the label of countless how-to articles
        self.plist(os.path.join(self.home, "Library/LaunchAgents/com.user.loginscript.plist"),
                   {"Label": "com.user.loginscript", "ProgramArguments": ["/Users/victim/bin/login.sh"]})
        findings, _ = self.scan()
        self.assertEqual(self.family(findings, "Cuckoo"), [])

    def test_cuckoo_hidden_uuid_folder(self):
        d = self.mkdir(os.path.join(self.home, ".local-6635DD81-94DD-59E3-9D84-20BD41C51999"))
        self.put(os.path.join(d, "pw.dat"))
        self.plist(os.path.join(self.home, "Library/LaunchAgents/com.dumpmedia.spotifymusicconverter.plist"),
                   {"Label": "com.user.loginscript", "ProgramArguments": ["/x/upd"]})
        findings, _ = self.scan()
        ck = self.family(findings, "Cuckoo")
        self.assertEqual(len(ck), 1)
        self.assertEqual(ck[0].severity, "malicious")

    def test_dir_patterns(self):
        self.put(self.sys_path("/tmp/.sys-1234567890123456"), MACHO)
        self.put(self.sys_path("/Library/LaunchAgents/launched.0A1B2C3D-0000-1111-2222-333344445555.plist"),
                 plistlib.dumps({"Label": "x", "ProgramArguments": ["/x"]}))
        self.mkdir(os.path.join(self.home, "Library/Caches/com.apple.finder/Launchpad.app"))
        findings, _ = self.scan()
        fams = {f.details.get("family") for f in findings}
        self.assertTrue({"MacSync", "Activator", "XCSSET"} <= fams, fams)

    def test_three_weak_artifacts_are_reported(self):
        for n in (".n", ".f", ".i"):
            self.put(self.sys_path(f"/tmp/{n}"))
        findings, _ = self.scan()
        x = self.family(findings, "XCSSET")
        self.assertEqual(len(x), 1)
        self.assertIn(x[0].severity, ("suspicious", "low"))

    def test_bundle_identifier(self):
        app = os.path.join(self.home, "Applications/Lesson.app")
        self.plist(os.path.join(app, "Contents/Info.plist"), {"CFBundleIdentifier": "Education.LessonOne"})
        findings, _ = self.scan()
        hr = self.family(findings, "HiddenRisk")
        self.assertEqual(len(hr), 1)
        self.assertEqual(hr[0].severity, "malicious")

    def test_adware_is_pua(self):
        self.mkdir(os.path.join(self.home, "Library/Application Support/.0A1B2C3D-0000-1111-2222-333344445555"))
        findings, _ = self.scan()
        ad = self.family(findings, "Adload")
        self.assertEqual(len(ad), 1)
        self.assertTrue(ad[0].detection.pua)

    def test_running_process_name(self):
        ctx = EnvContext(self.options(artifacts_skip_processes=False))
        ctx._procs = {4242: {"pid": 4242, "name": "GoogIe LLC", "exe": "/private/var/x/GoogIe LLC"},
                      1: {"pid": 1, "name": "launchd", "exe": "/sbin/launchd"}}
        art.collect_artifacts(ctx)
        nd = [f for f in ctx.findings if f.details.get("family") == "NimDoor"]
        self.assertEqual(len(nd), 1)
        self.assertEqual(nd[0].severity, "malicious")
        self.assertTrue(any("pid=4242" in e for e in nd[0].detection.evidence))

    def test_running_known_artifact_path(self):
        exe = self.put(self.sys_path("/tmp/.fseventsd"), MACHO)
        ctx = EnvContext(self.options(artifacts_skip_processes=False))
        ctx._procs = {77: {"pid": 77, "name": "x", "exe": "/tmp/.fseventsd"}}
        art.collect_artifacts(ctx)
        zr = [f for f in ctx.findings if f.details.get("family") == "ZuRu"]
        self.assertEqual(len(zr), 1)
        self.assertTrue(any(".running" in e for e in zr[0].detection.evidence))
        self.assertIn(exe, ctx.targets)


if __name__ == "__main__":
    unittest.main()

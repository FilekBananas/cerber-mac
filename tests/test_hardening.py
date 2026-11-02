"""Hardening of Cerber itself (it runs with Full Disk Access: any way to make it run foreign code is a
full-machine compromise). Covers:

* integrity seal (cerber/integrity.py): manifest pass, and every tamper kind detected – changed / new / removed
  file, planted __pycache__ ignored, directory swapped for a symlink, symlink retargeted, file appearing where
  nothing may exist, percent-escaping of odd file names;
* notifications: hostile file/process names reach osascript only as argv items (proved with a real osascript);
* HTML reports: names, paths, evidence, numbers and URLs from (possibly sandbox-produced) results are escaped,
  no javascript:/data: links, a Content-Security-Policy that blocks scripts even in a browser;
* local API: token on every /api endpoint, Host (DNS rebinding) / Origin / CORS checks, reports only from
  Cerber's reports folder;
* downloads: Hugging Face / link file names can't leave the workspace, redirects or links from a public page
  into localhost / the LAN are refused, feed downloads are https-only;
* sandbox extraction hygiene (symlinks / special files removed, read-only) and the hardened interpreter env;
* quarantine: id traversal, restore over an existing file or through a planted symlink, symlink "quarantine";
* llama-server sandbox profile: home unreadable (live sandbox-exec check), no network/exec, strict mode;
* compiled ClamAV databases: the restricted unpickler refuses every way a .pkl could import or call code
  (GLOBAL, STACK_GLOBAL, INST, EXT*, persistent ids) and still loads what the compiler writes;
* events from sandboxed children: allow-list per child kind, report paths only inside the reports folder;
* detonation: inline profile (`sandbox-exec -p`), `python -I -B -X pycache_prefix=<sealed tree>`.

    .venv/bin/python -m unittest tests.test_hardening -v
"""
from __future__ import annotations

import array
import io
import json
import os
import pickle
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cerber import config, integrity, quarantine, report  # noqa: E402

NASTY = [
    '" & (do shell script "touch /tmp/cerber-pwned") & "',
    'evil\\" & do shell script \\"id\\" & \\"',
    "line1\nline2\r\n\" & beep",
    "<script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "żółć – „cudzysłów” \\ back\\slash",
]


class IntegritySealTest(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cerber-seal-"))
        t = os.path.join(self.tmp, "tree")
        os.makedirs(os.path.join(t, "pkg", "sub"))
        for rel, body in (("pkg/__init__.py", b""), ("pkg/mod.py", b"print(1)\n"), ("pkg/sub/x.so", b"\xcf\xfa")):
            with open(os.path.join(t, rel), "wb") as fh:
                fh.write(body)
        os.chmod(os.path.join(t, "pkg/sub/x.so"), 0o755)
        os.symlink("mod.py", os.path.join(t, "pkg", "alias.py"))
        with open(os.path.join(t, "pkg", "dziwna nazwa%\tż.py"), "wb") as fh:
            fh.write(b"# odd name\n")
        self.extra = os.path.join(self.tmp, "tool")
        with open(self.extra, "wb") as fh:
            fh.write(b"#!/bin/sh\n")
        os.makedirs(os.path.join(self.tmp, "bin"))
        self.link = os.path.join(self.tmp, "bin", "tool")
        os.symlink("../tool", self.link)
        self.absent = os.path.join(self.tmp, "bin", "upx")
        spec = integrity.Spec(os.fsencode(self.tmp))
        spec.trees.add(os.fsencode(t))
        spec.files.add(os.fsencode(self.extra))
        spec.links.add(os.fsencode(self.link))
        spec.absent.add(os.fsencode(self.absent))
        self.tree = t
        self.text = integrity.manifest_text(spec)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def problems(self):
        return integrity.verify(self.text)

    def test_intact_and_parse_roundtrip(self):
        self.assertEqual(self.problems(), [])
        spec, entries = integrity.parse(self.text)
        self.assertEqual(integrity.manifest_text(spec), self.text)
        self.assertTrue(any("dziwna%20nazwa%25%09" in e for e in entries), "odd names are percent-escaped")
        self.assertTrue(self.text.isascii())
        self.assertTrue(any(e.startswith("f ") and e.split(" ")[2] == "x" for e in entries if "x.so" in e))

    def test_changed_file(self):
        with open(os.path.join(self.tree, "pkg", "mod.py"), "ab") as fh:
            fh.write(b"import os; os.system('id')\n")
        self.assertTrue(any(p.startswith("zmieniony:") and p.endswith("mod.py") for p in self.problems()))

    def test_new_module_and_pth(self):
        with open(os.path.join(self.tree, "pkg", "sitecustomize.py"), "w") as fh:
            fh.write("import os\n")
        self.assertTrue(any(p.startswith("nowy plik:") for p in self.problems()))

    def test_removed_file(self):
        os.remove(os.path.join(self.tree, "pkg", "__init__.py"))
        self.assertTrue(any(p.startswith("brak:") for p in self.problems()))

    def test_pycache_and_ds_store_ignored(self):
        os.makedirs(os.path.join(self.tree, "pkg", "__pycache__"))
        with open(os.path.join(self.tree, "pkg", "__pycache__", "mod.cpython-314.pyc"), "wb") as fh:
            fh.write(b"planted")
        open(os.path.join(self.tree, "pkg", ".DS_Store"), "wb").close()
        self.assertEqual(self.problems(), [])

    def test_directory_swapped_for_symlink(self):
        sub = os.path.join(self.tree, "pkg", "sub")
        shutil.move(sub, os.path.join(self.tmp, "elsewhere"))
        os.symlink(os.path.join(self.tmp, "elsewhere"), sub)
        self.assertTrue(self.problems())

    def test_symlink_retargeted(self):
        os.remove(self.link)
        os.symlink("/bin/sh", self.link)
        self.assertTrue(any("tool" in p for p in self.problems()))

    def test_file_where_nothing_may_exist(self):
        with open(self.absent, "w") as fh:
            fh.write("#!/bin/sh\n")
        self.assertTrue(any("upx" in p for p in self.problems()))

    def test_extra_file_replaced_by_symlink(self):
        os.rename(self.extra, self.extra + ".real")
        os.symlink(self.extra + ".real", self.extra)
        self.assertTrue(any("niepoprawny" in p for p in self.problems()))

    def test_manifest_itself_tamper_changes_digest(self):
        d = integrity.digest(self.text)
        line = next(ln for ln in self.text.splitlines() if ln.startswith("f ") and "mod.py" in ln)
        forged = self.text.replace(line, line[:-1] + ("0" if line[-1] != "0" else "1"))
        self.assertNotEqual(d, integrity.digest(forged))
        self.assertTrue(integrity.verify(forged), "a forged manifest no longer matches the disk")
        self.assertEqual(len(d), 64)

    def test_escape_roundtrip(self):
        raw = bytes(range(256))
        self.assertEqual(integrity.unesc(integrity.esc(raw)), raw)
        self.assertNotIn(" ", integrity.esc(raw))

    def test_chain_records_every_symlink(self):
        a = os.path.join(self.tmp, "a")
        os.symlink("bin", a)
        links: set[bytes] = set()
        real = integrity.chain(os.fsencode(os.path.join(a, "tool")), links)
        self.assertEqual(real, os.fsencode(self.extra))
        self.assertEqual(links, {os.fsencode(a), os.fsencode(self.link)})

    def test_pypath_holds_only_cerber(self):
        d = integrity.ensure_pypath(str(ROOT))
        self.assertEqual(os.listdir(d), ["cerber"])
        self.assertEqual(os.path.realpath(os.path.join(d, "cerber")), str(ROOT / "cerber"))


class NotifierTest(unittest.TestCase):
    def test_texts_only_as_argv(self):
        from cerber import watch
        n = watch.Notifier(True)
        with mock.patch.object(watch, "_APP_OUT", None), mock.patch.object(watch.subprocess, "Popen") as popen:
            for s in NASTY:
                n.notify(s, s, subtitle=s, sound="Basso")
        self.assertEqual(popen.call_count, len(NASTY))
        for call, s in zip(popen.call_args_list, NASTY):
            argv = call.args[0]
            self.assertEqual(argv[0], "/usr/bin/osascript")
            sep = argv.index("--")
            source = " ".join(argv[:sep])
            self.assertNotIn(s[:8], source, "a name leaked into the AppleScript source")
            self.assertEqual(argv[sep + 1], s[:230])

    @unittest.skipUnless(os.access("/usr/bin/osascript", os.X_OK), "osascript")
    def test_real_osascript_gets_text_verbatim(self):
        from cerber import watch
        marker = os.path.join(tempfile.gettempdir(), "cerber-pwned")
        for s in NASTY:
            argv = watch.Notifier._osascript("return (item 1 of argv)", [s])
            out = subprocess.run(argv, capture_output=True, text=True, timeout=30).stdout
            self.assertEqual(out.rstrip("\n").replace("\r", "\n"), s.replace("\r\n", "\n").replace("\r", "\n"))
        self.assertFalse(os.path.exists(marker))


class ReportEscapingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cerber-rep-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def hostile_report(self) -> dict:
        evil = NASTY[3] + NASTY[4]
        det = {"name": evil, "engine": evil, "confidence": "HIGH", "score": "<b>9</b>", "object": "a>>" + evil,
               "description": evil}
        res = {"path": "/tmp/" + evil, "verdict": "MALICIOUS", "score": '"><script>x()</script>', "ftype": evil,
               "size": "<i>", "sha256": evil, "detections": [det],
               "ai": {"family": evil, "summary_pl": evil, "points": "<svg onload=x>", "points_raw": 3, "cap": "<u>",
                      "confidence": "<u>", "accusations": [{"name": evil, "verdict": "confirmed", "quote": evil,
                                                            "reason_pl": evil, "confidence": evil, "points": evil}]},
               "detonation": {"ran": True, "kind": evil, "seconds": evil, "verdict": evil,
                              "behaviors": [{"title": evil, "detail": evil, "evidence": [evil]}],
                              "network": [{"url": evil}], "files_read": [evil], "stages": [{"source_preview": evil}]}}
        return {"counts": {"MALICIOUS": "<x>"}, "results": [res], "started": evil, "finished": evil, "seconds": evil,
                "files": evil, "bytes": evil, "objects": evil, "patterns_total": evil, "cloud_only": evil,
                "repo": {"url": "javascript:alert(document.domain)", "owner": evil, "name": evil, "ref": evil},
                "sandbox": {"isolation": [evil], "limits_hit": [evil], "extracted_files": evil},
                "network": {"summary": {"listening_all_interfaces": evil}, "boot_time": evil,
                            "monitor": {"started": evil, "polls": evil, "interval_s": evil, "stats": {"alerts": evil},
                                        "events": [{"title": evil, "process": evil}]}}}

    def assertInert(self, text: str):
        low = text.lower()
        self.assertNotIn("<script", low)
        self.assertNotIn("<img", low)
        self.assertNotIn("<svg", low)
        self.assertNotIn("<b>9</b>", low)
        self.assertNotIn('href="javascript:', low)
        self.assertIn("content-security-policy", low)
        self.assertIn("default-src 'none'", low)

    def test_scan_report(self):
        out = report.write_html(self.hostile_report(), os.path.join(self.tmp, "r.html"),
                                env={"findings": [{"category": NASTY[3], "title": NASTY[4], "location": NASTY[3],
                                                   "score": "<img src=1>"}], "posture": {NASTY[3]: NASTY[4]}})
        with open(out) as fh:
            text = fh.read()
        self.assertInert(text)
        self.assertIn('href="#"', text)

    def test_netguard_report(self):
        evil = NASTY[3]
        out = report.write_netguard_html({"date": evil, "status": {"interval_s": evil, "public_new": "<img>",
                                                                   "limitations": [evil]},
                                          "events": [{"severity": '"><script>', "kind": evil, "title": evil,
                                                      "process": evil, "exe": evil, "host": evil}]},
                                         os.path.join(self.tmp, "n.html"))
        with open(out) as fh:
            self.assertInert(fh.read())

    def test_href_scheme_filter(self):
        for bad in ("javascript:alert(1)", "data:text/html,<script>", "file:///etc/passwd", " JavaScript:x",
                    "https://ok.example/\nx"):
            self.assertEqual(report._safe_href(bad), "#")
        self.assertEqual(report._safe_href("https://github.com/a/b"), "https://github.com/a/b")

    def test_numbers(self):
        self.assertEqual(report._n(1234, ","), "1,234")
        self.assertEqual(report._n("<b>", ","), "&lt;b&gt;")
        self.assertEqual(report.human_bytes("<x>"), "?")


class ApiSecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_api_server import ApiServer, free_port
        cls.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cerber-api-hard-"))
        cls.srv = ApiServer(cls.tmp, args=("--port", str(free_port())))

    @classmethod
    def tearDownClass(cls):
        try:
            cls.srv.stop()
        finally:
            shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_every_api_route_needs_token(self):
        from cerber.api_server import ROUTES
        for method, rx, _name in ROUTES:
            path = rx.pattern.strip("^$").replace("(?P<hid>[A-Za-z0-9._-]{1,128})", "x").replace(
                "(?P<jid>[A-Za-z0-9_-]{1,64})", "x")
            if not path.startswith("/api"):
                continue
            r = self.srv.request(method, path, token=False, body={} if method == "POST" else None)
            self.assertEqual(r.status, 401, f"{method} {path}")
            r = self.srv.request(method, path, token=False, headers={"Authorization": "Bearer " + "x" * 43},
                                 body={} if method == "POST" else None)
            self.assertEqual(r.status, 401, f"{method} {path} (wrong token)")

    def test_host_origin_cors(self):
        self.assertEqual(self.srv.get("/api/info", headers={"Host": "evil.example:80"}).status, 403)
        self.assertEqual(self.srv.get("/api/info", headers={"Host": f"rebind.example:{self.srv.port}"}).status, 403)
        self.assertEqual(self.srv.get("/api/info", headers={"Origin": "https://evil.example"}).status, 403)
        r = self.srv.request("OPTIONS", "/api/info", token=False, headers={"Origin": "https://evil.example",
                                                                            "Access-Control-Request-Method": "GET"})
        self.assertGreaterEqual(r.status, 400)
        self.assertFalse(any(k.lower().startswith("access-control-") for k in r.headers.keys()))
        self.assertEqual(self.srv.get("/", headers={"Sec-Fetch-Site": "cross-site"}).status, 200)   # docs only

    def test_bound_to_loopback_only(self):
        self.assertTrue(self.srv.url.startswith("http://127.0.0.1:"))
        from cerber import api_server
        self.assertNotEqual(api_server.main(["--host", "0.0.0.0", "--port", "0"]), 0)

    def test_report_only_from_reports_folder(self):
        from cerber import api_server
        h = object.__new__(api_server.Handler)
        h.query = {}
        for path in ("/etc/passwd.html", os.path.join(self.tmp, "x.html"), str(ROOT / "README.md") + ".html"):
            with self.assertRaises(api_server.ApiError) as cm:
                h._send_report({"report_html": path}, "x")
            self.assertEqual(cm.exception.status, 404)


class DownloadSafetyTest(unittest.TestCase):
    def test_hf_paths_cannot_escape(self):
        from cerber import fetch
        for bad in ("../../etc/passwd", "a/../../b", "..", "/..", "a/..\\..\\b"):
            r = fetch._safe_rel(bad)
            self.assertTrue(r is None or ".." not in r.split("/"), bad)
        self.assertEqual(fetch._safe_rel("/abs/x.bin"), "abs/x.bin")

    def test_link_filenames_flat(self):
        from cerber import fetch

        class R:
            def __init__(self, cd):
                self.headers = {"Content-Disposition": cd}
        for cd in ('attachment; filename="../../.zshrc"', "attachment; filename*=UTF-8''..%2F..%2Fx",
                   'attachment; filename="/etc/passwd"', 'attachment; filename=".."'):
            name = fetch._filename(R(cd), "https://x.example/", "plik")
            self.assertNotIn("/", name)
            self.assertNotIn("\\", name)
            self.assertFalse(name.startswith("."), name)

    def test_no_redirect_into_localhost(self):
        from cerber import fetch
        for ip in ("127.0.0.1", "localhost", "10.1.2.3", "192.168.0.1", "169.254.169.254", "[::1]", "0.0.0.0"):
            self.assertTrue(fetch._local_host(ip), ip)
        self.assertFalse(fetch._local_host("8.8.8.8"))
        red = fetch._Redirects(allow_local=False)
        for target in ("http://127.0.0.1:8765/api/info", "http://localhost:1/", "file:///etc/passwd",
                       "ftp://example.com/x"):
            with self.assertRaises(fetch.FetchError):
                red.redirect_request(None, None, 302, "Found", {}, target)

    def test_feeds_https_only(self):
        from cerber import feeds_ios, feeds_macos, feeds_macos_yara
        for fn in (feeds_ios._get, feeds_macos._get, feeds_macos_yara._http):
            for url in ("file:///etc/passwd", "http://example.com/x", "ftp://example.com/x"):
                with self.assertRaises(ValueError):
                    fn(url)

    def test_model_hash_pinned(self):
        from cerber import ai_install
        self.assertRegex(ai_install.SHA256, r"^[0-9a-f]{64}$")
        self.assertTrue(ai_install.URL.startswith("https://huggingface.co/"))


class SandboxHygieneTest(unittest.TestCase):
    def test_extracted_tree_sanitised(self):
        from cerber import sandbox
        d = tempfile.mkdtemp(prefix="cerber-x-")
        try:
            os.makedirs(os.path.join(d, "sub"))
            with open(os.path.join(d, "sub", "run.sh"), "w") as fh:
                fh.write("#!/bin/sh\n")
            os.chmod(os.path.join(d, "sub", "run.sh"), 0o755)
            os.symlink("/etc/passwd", os.path.join(d, "link"))
            os.symlink("/Users", os.path.join(d, "dirlink"))
            os.mkfifo(os.path.join(d, "fifo"))
            stats = {"removed_links": 0, "removed_special": 0}
            sandbox._sanitize(d, stats)
            self.assertEqual(stats["removed_links"], 2)
            self.assertEqual(stats["removed_special"], 1)
            mode = os.stat(os.path.join(d, "sub", "run.sh")).st_mode & 0o777
            self.assertEqual(mode, 0o400)
        finally:
            for root, dirs, _ in os.walk(d):
                for x in dirs:
                    os.chmod(os.path.join(root, x), 0o700)
            os.chmod(d, 0o700)
            shutil.rmtree(d, ignore_errors=True)

    def test_interpreter_env(self):
        from cerber import sandbox
        with mock.patch.dict(os.environ, {"CERBER_PYPATH": "/x/.venv/cerber-path", "PYTHONPYCACHEPREFIX": "/x/pyc"}):
            env = sandbox.python_env()
        self.assertEqual(env["PYTHONSAFEPATH"], "1")
        self.assertEqual(env["PYTHONPATH"], "/x/.venv/cerber-path")
        self.assertEqual(env["PYTHONPYCACHEPREFIX"], "/x/pyc")
        self.assertEqual(env["PYTHONNOUSERSITE"], "1")

    def test_profiles_deny_network_and_workspace_exec(self):
        from cerber import sandbox
        work = tempfile.mkdtemp(prefix="cerber-sandbox-")
        try:
            for kind in ("strict", "scan", "env"):
                prof = sandbox.build_profile(work, None, kind)
                self.assertIn("(deny network-outbound (remote ip))", prof)
                self.assertIn(f"(deny process-exec (subpath {sandbox._q(work)}))", prof)
                self.assertIn('global-name-prefix "com.apple.tccd"', prof)
            net = sandbox.build_profile(work, None, "net")
            self.assertNotIn("(allow file-read*)\n", net)
        finally:
            shutil.rmtree(work, ignore_errors=True)


class QuarantineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cerber-q-"))
        self.qdir = os.path.join(self.tmp, "quarantine")
        self.patch = mock.patch.multiple(config, QUARANTINE=self.qdir, REPORTS=os.path.join(self.tmp, "reports"),
                                         DB=os.path.join(self.tmp, "db"), CLAMAV_RAW=os.path.join(self.tmp, "db/c"),
                                         COMPILED=os.path.join(self.tmp, "db/x"), YARA_SOURCES=os.path.join(self.tmp, "db/y"),
                                         FEEDS=os.path.join(self.tmp, "db/f"))
        self.patch.start()
        self.victim = os.path.join(self.tmp, "evil.bin")
        with open(self.victim, "wb") as fh:
            fh.write(b"MZ" + os.urandom(64))

    def tearDown(self):
        self.patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_store_permissions_and_roundtrip(self):
        qid = quarantine.quarantine_file(self.victim, {"verdict": "MALICIOUS"})
        self.assertFalse(os.path.exists(self.victim))
        self.assertEqual(os.stat(self.qdir).st_mode & 0o777, 0o700)
        for ext in (".cq", ".json"):
            self.assertEqual(os.stat(os.path.join(self.qdir, qid + ext)).st_mode & 0o777, 0o600)
        self.assertEqual(quarantine.restore(qid), self.victim)
        self.assertEqual(os.stat(self.victim).st_mode & 0o111, 0)

    def test_id_traversal_rejected(self):
        for bad in ("../../etc/passwd", "../x", "a" * 16 + "/../b", "", "ABCDEF0123456789"):
            with self.assertRaises(ValueError):
                quarantine.restore(bad)
            with self.assertRaises(ValueError):
                quarantine.delete(bad)

    def test_restore_never_overwrites(self):
        qid = quarantine.quarantine_file(self.victim)
        with open(self.victim, "w") as fh:
            fh.write("user's new file")
        with self.assertRaises(FileExistsError):
            quarantine.restore(qid)
        with open(self.victim) as fh:
            self.assertEqual(fh.read(), "user's new file")

    def test_restore_through_planted_symlink_rejected(self):
        qid = quarantine.quarantine_file(self.victim)
        target_dir = os.path.join(self.tmp, "protected")
        os.makedirs(target_dir)
        redirect = os.path.join(self.tmp, "downloads")
        os.symlink(target_dir, redirect)
        with self.assertRaises(ValueError):
            quarantine.restore(qid, os.path.join(redirect, "evil.bin"))
        self.assertEqual(os.listdir(target_dir), [])
        with self.assertRaises(ValueError):
            quarantine.restore(qid, os.path.join(self.tmp, "a", "..", "b"))

    def test_symlink_is_not_quarantined(self):
        secret = os.path.join(self.tmp, "secret.db")
        with open(secret, "w") as fh:
            fh.write("private")
        link = os.path.join(self.tmp, "looks-bad.exe")
        os.symlink(secret, link)
        with self.assertRaises(ValueError):
            quarantine.quarantine_file(link)
        self.assertTrue(os.path.exists(secret))
        self.assertFalse(os.path.exists(self.qdir) and any(f.endswith(".cq") for f in os.listdir(self.qdir)))

    def test_broken_entry_does_not_hide_list(self):
        quarantine.quarantine_file(self.victim)
        with open(os.path.join(self.qdir, "0123456789abcdef.json"), "w") as fh:
            fh.write("{broken")
        self.assertEqual(len(quarantine.list_quarantine()), 1)

    def test_private_dir_refuses_symlink(self):
        real = os.path.join(self.tmp, "real")
        os.makedirs(real)
        link = os.path.join(self.tmp, "fake")
        os.symlink(real, link)
        with self.assertRaises(OSError):
            config.private_dir(link)


class LlmSandboxTest(unittest.TestCase):
    def test_profile(self):
        from cerber.llm import sandbox as lsb
        model_dir = ROOT / "models"
        prof = lsb.build_profile(["/bin/cat", "-n"], lsb.SandboxPlan(read=[model_dir]))
        home = os.path.realpath(os.path.expanduser("~"))
        self.assertIn(f'(deny file-read-data (subpath "{home}")', prof)
        self.assertIn("(deny process-exec*)", prof)
        self.assertIn('(allow process-exec (literal "/bin/cat"))', prof)
        self.assertIn("(deny network-outbound (remote ip))", prof)
        self.assertIn('(allow network-bind (local ip "localhost:*"))', prof)
        self.assertEqual(lsb.mode(), "strict")
        argv, sandboxed, _ = lsb.wrap(["/bin/cat"], lsb.SandboxPlan())
        self.assertTrue(sandboxed)
        self.assertEqual(argv[:2], ["/usr/bin/sandbox-exec", "-p"])

    @unittest.skipUnless(os.access("/usr/bin/sandbox-exec", os.X_OK), "sandbox-exec")
    def test_live_home_unreadable(self):
        from cerber.llm import sandbox as lsb
        secret = ROOT / "README.md"
        argv, _, _ = lsb.wrap(["/bin/cat", str(secret)], lsb.SandboxPlan(read=[ROOT / "models"]))
        r = subprocess.run(argv, capture_output=True, timeout=30, cwd="/")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, b"")
        argv, _, _ = lsb.wrap(["/bin/sh", "-c", "true"], lsb.SandboxPlan())
        self.assertEqual(subprocess.run(["/bin/sh", "-c", "true"]).returncode, 0)
        r = subprocess.run(argv[:3] + ["/bin/cat", "/etc/hosts"], capture_output=True, timeout=30, cwd="/")
        self.assertNotEqual(r.returncode, 0, "only the engine binary may be executed")


class ClamDbUnpicklerTest(unittest.TestCase):
    """db/compiled/clamav/*.pkl are read with a restricted unpickler – a swapped file must never run code."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cerber-pkl-"))
        self.marker = os.path.join(self.tmp, "pwned")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def hostile(self) -> list[bytes]:
        """Each one runs `touch <marker>` under a plain pickle.load (EXT1 code 0xC3 needs the copyreg entry)."""
        marker = self.marker
        cmd = f"touch {marker}".encode()
        n = len(cmd).to_bytes(4, "little")

        class Reduce:
            def __reduce__(self):
                return (os.system, (cmd.decode(),))

        class Eval:
            def __reduce__(self):
                return (eval, (f"__import__('os').system('touch {marker}')",))

        out = [b"cos\nsystem\n(S'" + cmd + b"'\ntR.",                        # protocol 0 GLOBAL + REDUCE
               b"(S'" + cmd + b"'\nios\nsystem\n.",                          # INST
               b"\x80\x02X\x01\x00\x00\x00aQ.",                              # BINPERSID
               b"\x80\x02c__builtin__\nexec\nX" + n + cmd + b"\x85R."]       # protocol 2, old builtins name
        for proto in (2, 4, 5):
            out.append(pickle.dumps(Reduce(), protocol=proto))                 # STACK_GLOBAL for 4/5
        out.append(pickle.dumps(Eval(), protocol=5))
        out.append(b"\x80\x02\x82\xc3X" + n + cmd + b"\x85R.")              # EXT1 → copyreg registry
        # an allowed global used the wrong way: only a TypeError, never a call into anything else
        out.append(b"\x80\x03carray\n_array_reconstructor\n(cbuiltins\nset\nX\x01\x00\x00\x00IK\x01C\x00tR.")
        return out

    def test_hostile_pickles_refused(self):
        import copyreg
        from cerber.engines.clamav_db import load_pickle
        copyreg.add_extension("os", "system", 0xC3)
        try:
            for blob in self.hostile():
                with self.assertRaises((pickle.UnpicklingError, TypeError), msg=blob[:40]):
                    load_pickle(io.BytesIO(blob))
        finally:
            copyreg.remove_extension("os", "system", 0xC3)
        self.assertFalse(os.path.exists(self.marker), "a hostile pickle ran a command")

    def test_hostile_samples_are_real(self):
        """The samples above really execute under an unrestricted pickle.load (so the test proves something)."""
        blob = self.hostile()[5]
        pickle.loads(blob)
        self.assertTrue(os.path.exists(self.marker))

    def test_writer_formats_still_load(self):
        from cerber.engines.clamav_db import load_pickle
        data = ([("Eicar", 0, False, 0, None, [("hex", [0])], None)],
                (array.array("I", [1, 2]), [("41424344", "*", False, False, False)], bytearray(b"\x01"),
                 array.array("H", [4])),
                [(0, 1)], {0: [3]}, ([b"ABCD"], array.array("I", [0])), {1, 2}, frozenset({3}))
        for proto in (3, 4, 5):           # protocol 2 writes bytes through _codecs.encode – refused, never used
            self.assertEqual(load_pickle(io.BytesIO(pickle.dumps(data, protocol=proto))), data, proto)

    def test_compiled_db_roundtrip_and_tampered_db(self):
        from cerber.engines import clamav_db
        from cerber.engines.clamav import ClamAVEngine
        comp = clamav_db.Compiler(log=lambda m: None)
        comp.load_files([("t.ndb", b"Cerber.Test.Ndb:0:*:4345524245525f544553545f4e4442\n"),
                         ("t.ldb", b"Cerber.Test.Ldb;Engine:51-255,Target:0;0&1;4142434445464748;6162636465666768\n")])
        out = os.path.join(self.tmp, "clamav")
        comp.save(out, {})
        eng = ClamAVEngine(out)
        eng.preload()
        self.assertEqual(eng.signature_count, 2)
        self.assertTrue(eng.ac)
        with open(os.path.join(out, "slow.pkl"), "wb") as fh:
            fh.write(self.hostile()[4])
        with self.assertRaises(pickle.UnpicklingError):
            ClamAVEngine(out)
        self.assertFalse(os.path.exists(self.marker))

    def test_real_compiled_db_small_files(self):
        from cerber.engines.clamav_db import load_pickle
        d = config.CLAMAV_COMPILED
        if not os.path.isdir(d):
            self.skipTest("brak db/compiled/clamav")
        small = [f for f in os.listdir(d) if f.endswith(".pkl") and os.path.getsize(os.path.join(d, f)) < (2 << 20)]
        self.assertTrue(small)
        for f in small:
            with open(os.path.join(d, f), "rb") as fh, open(os.path.join(d, f), "rb") as fh2:
                self.assertEqual(load_pickle(fh), pickle.load(fh2), f)


class ChildEventFilterTest(unittest.TestCase):
    """Events from sandboxed children reach the app only through an allow-list (cerber/gui_backend.py)."""

    def setUp(self):
        from cerber import gui_backend
        self.gb = gui_backend
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cerber-relay-"))
        self.reports = os.path.join(self.tmp, "reports")
        os.makedirs(self.reports)
        self.out: list[dict] = []
        self.err = io.StringIO()                        # dropped events are noted on stderr
        self.patches = [mock.patch.object(config, "REPORTS", self.reports),
                        mock.patch.object(gui_backend, "emit", self.out.append, create=True),
                        mock.patch.object(gui_backend, "SCAN_ROOTS", [self.tmp]),
                        mock.patch.object(sys, "stderr", self.err)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def finding(self, **extra) -> dict:
        return {"ev": "finding", "item": {"path": os.path.join(self.tmp, "x.sh"), "verdict": "MALICIOUS", "score": 99,
                                          "detections": [], **extra}}

    def test_allow_list(self):
        relay = self.gb._relay(False)
        ok = [{"ev": "log", "msg": "a"}, {"ev": "stage", "id": "scan", "title": "t"},
              {"ev": "progress", "stage": "scan", "done": 1}, {"ev": "error", "msg": "e", "fatal": False},
              {"ev": "sandbox_violation", "problems": ["x"]}]
        bad = [{"ev": "done", "summary": {"report_html": os.path.join(self.reports, "a.html")}},
               {"ev": "quarantined", "path": "/etc/hosts", "id": "0123456789abcdef"},
               {"ev": "ai_installed", "model": "m", "path": "/tmp/m", "llama_server": "/tmp/evil"},
               {"ev": "api_ready", "url": "http://evil.example", "token": "t"},
               {"ev": "history", "items": []}, {"ev": "info"}, {"ev": "inner_done"},
               {"ev": "iphone_done", "summary": {}}, {"ev": "watch_target", "path": "/bin/sh"},
               {"ev": "net_event", "item": {}}, {"ev": "watch_alert", "title": "x"}, {"ev": 5}, {"no": "ev"},
               {"ev": "finding", "item": "not a dict"}, {"ev": "finding", "item": {"verdict": "MALICIOUS"}},
               {"ev": "finding", "item": {"path": ["x"], "verdict": "MALICIOUS"}}]
        for ev in ok + bad:
            relay(ev)
        self.assertEqual(self.out, ok)
        self.assertIn("'ai_installed'", self.err.getvalue())
        self.assertNotIn("inner_done", self.err.getvalue(), "the normal end marker is dropped silently")
        relay(self.finding())
        self.assertEqual(self.out[-1]["ev"], "finding")
        self.assertEqual(self.out[-1]["item"]["verdict"], "MALICIOUS")

    def test_report_paths_only_inside_reports(self):
        relay = self.gb._relay(True)
        outside = os.path.join(self.tmp, "evil.html")
        link = os.path.join(self.reports, "link.html")
        os.symlink(outside, link)
        for ev in ({"ev": "log", "msg": "x", "report_html": "/etc/passwd"},
                   {"ev": "progress", "stage": "scan", "report_json": os.path.join(self.reports, "..", "x.json")},
                   {"ev": "log", "msg": "x", "report_html": link},                       # symlink out of reports
                   {"ev": "log", "msg": "x", "report_html": 7},
                   {"ev": "stage", "id": "x", "deep": [[{"report_json": "/tmp/x.json"}]]},
                   self.finding(ai={"accusations": [{"report_html": "/Users/x/a.html"}]})):
            relay(ev)
        self.assertEqual(self.out, [])
        nested = {"ev": "log", "msg": "x"}
        for _ in range(40):
            nested = {"ev": "log", "msg": "x", "n": nested}
        relay(nested)
        self.assertEqual(self.out, [], "absurd nesting is dropped")
        good = {"ev": "log", "msg": "ok", "report_html": os.path.join(self.reports, "gui-1.html"), "report_json": None}
        relay(good)
        self.assertEqual(self.out, [good])

    def test_netwatch_and_iphone_children(self):
        live = self.gb.LiveWatch()
        live._relay({"ev": "net_event", "item": {"id": "ne-1", "severity": "suspicious", "title": "t", "x": "drop",
                                                 "evidence": ["a" * 900, 3, "b"], "confidence": "high", "ioc": 1}})
        live._relay({"ev": "watch_target", "path": "/Applications/X.app"})
        for ev in ({"ev": "done", "summary": {}}, {"ev": "finding", "item": {}}, {"ev": "quarantined"},
                   {"ev": "net_status", "active": True, "report_html": "/etc/passwd"}):
            live._relay(ev)
        self.assertEqual([e["ev"] for e in self.out], ["net_event"])
        item = self.out[0]["item"]
        self.assertNotIn("x", item)
        self.assertEqual(item["evidence"], ["a" * 300, "b"])
        self.assertEqual(item["confidence"], "high")
        self.assertFalse(item["ioc"], "only a real JSON true counts")
        self.assertIn("/Applications/X.app", live.targets)
        self.assertIsNotNone(self.gb.child_event({"ev": "iphone_finding", "item": {}}, self.gb.IPHONE_EVENTS))
        for kind in ("iphone_done", "iphone_devices", "finding", "done"):
            self.assertIsNone(self.gb.child_event({"ev": kind}, self.gb.IPHONE_EVENTS), kind)

    def test_net_item_types(self):
        from cerber import watch
        x = watch.clean_net_item({"id": "ne-1", "severity": "malicious", "confidence": "HIGH; rm -rf",
                                  "attack": "remote_shell", "trust": "untrusted", "target": "/tmp/x.sh",
                                  "evidence": "not a list", "signals": ["Live.RemoteShell"] * 30, "ioc": True})
        self.assertIsNone(x["confidence"])
        self.assertEqual((x["attack"], x["trust"], x["target"], x["ioc"]), ("remote_shell", "untrusted", "/tmp/x.sh", True))
        self.assertEqual(x["evidence"], [])
        self.assertEqual(len(x["signals"]), 12)
        old = watch.clean_net_item({"id": "ne-2", "severity": "info", "title": "t"})
        self.assertEqual((old["evidence"], old["signals"], old["ioc"], old["confidence"]), ([], [], False, None))


class DetonationLaunchTest(unittest.TestCase):
    """The detonation interpreter keeps the sealed-.pyc rule under -I, and the profile is passed inline."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cerber-det-"))
        self.pyc = os.path.join(self.tmp, "pycache")
        os.makedirs(self.pyc)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_options_and_profile(self):
        from cerber import detonate
        with mock.patch.dict(os.environ, {"PYTHONPYCACHEPREFIX": self.pyc}):
            self.assertEqual(detonate._py_options(), ["-I", "-B", "-X", f"pycache_prefix={self.pyc}"])
            prof = detonate.build_profile(self.tmp, os.path.join(self.tmp, "run", "s.py"), "python")
        self.assertIn(f"(subpath {detonate._q(self.pyc)})", prof)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPYCACHEPREFIX"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(detonate._py_options(), ["-I", "-B"])

    def test_command_line(self):
        from cerber import detonate
        script = os.path.join(self.tmp, "s.py")
        with open(script, "w") as fh:
            fh.write("print(1)\n")
        seen: list[list[str]] = []

        def popen(cmd, **_kw):
            if cmd[0] == "/usr/bin/sandbox-exec":
                seen.append(list(cmd))
            raise OSError("stop here")

        class NoLog:
            ok, _proc = False, None

            def __init__(self, *_a):
                pass

        with mock.patch.dict(os.environ, {"PYTHONPYCACHEPREFIX": self.pyc, "CERBER_NO_NOEXEC": "1"}), \
                mock.patch.object(detonate, "_LogStream", NoLog), \
                mock.patch.object(detonate.subprocess, "Popen", popen):
            res = detonate.detonate_file(script, "python", timeout=5)
        self.assertEqual(len(seen), 1)
        cmd = seen[0]
        self.assertEqual(cmd[:2], ["/usr/bin/sandbox-exec", "-p"])
        self.assertTrue(cmd[2].startswith("(version 1)"), "the profile itself, not a file path")
        self.assertEqual(cmd[4:], ["-I", "-B", "-X", f"pycache_prefix={self.pyc}", "_wrapper.py"])
        self.assertTrue(any("stop here" in x for x in res["limitations"]))

    def test_watch_worker_command_line(self):
        from cerber import watch
        seen: dict = {}

        class P:
            pid, stdout = 0, io.StringIO("")

            def wait(self):
                return 0

        def popen(cmd, **kw):
            seen.update(cmd=list(cmd), env=kw["env"])
            return P()

        with mock.patch.dict(os.environ, {"PYTHONPYCACHEPREFIX": self.pyc, "CERBER_PYPATH": "/x/.venv/cerber-path",
                                          "CERBER_NO_NOEXEC": "1"}), \
                mock.patch.object(watch, "app_event", lambda ev: None), \
                mock.patch.object(watch.subprocess, "Popen", popen):
            w = watch.WorkerClient(["--level", "quick"], __import__("queue").Queue())
            w._start()
            from cerber.sandbox import remove_workspace
            remove_workspace(w.work)
        self.assertEqual(seen["cmd"][:2], ["/usr/bin/sandbox-exec", "-p"])
        self.assertTrue(seen["cmd"][2].startswith("(version 1)"))
        env = seen["env"]
        self.assertEqual((env["PYTHONPATH"], env["PYTHONSAFEPATH"], env["PYTHONPYCACHEPREFIX"]),
                         ("/x/.venv/cerber-path", "1", self.pyc))
        self.assertNotEqual(env["PYTHONPATH"], config.ROOT)


if __name__ == "__main__":
    unittest.main()

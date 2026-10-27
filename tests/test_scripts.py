"""Tests for the script analyzers (cerber.analyzers.scripts_*, ioc, embedded_blobs).

Samples live in tests/samples/scripts/ and are short, inert snippets that merely exhibit an
indicator (placeholders example.invalid / 192.0.2.1 / echo hello). Nothing is executed.

    python -m unittest tests.test_scripts -v            (from the project root)
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))              # project root

from cerber.analyzers import load_all  # noqa: E402
from cerber.analyzers.ioc import extract_iocs  # noqa: E402
from cerber.core import Verdict  # noqa: E402
from cerber.pipeline import Pipeline  # noqa: E402

SAMPLES = HERE / "samples" / "scripts"


def scan(name: str):
    pipe = Pipeline(analyzers=load_all(), options={"deep": True})
    return pipe.scan_file(str(SAMPLES / name))


def names(root):
    return {d.name for o in root.iter_tree() for d in o.detections}


class MaliciousSamples(unittest.TestCase):
    def _v(self, name, min_verdict, must=()):
        root = scan(name)
        self.assertGreaterEqual(root.meta["verdict"], min_verdict,
                                f"{name}: verdict {root.meta['verdict'].name} score {root.meta['score']}")
        got = names(root)
        for needle in must:
            self.assertTrue(any(needle in n for n in got), f"{name}: missing {needle} in {sorted(got)}")

    def test_powershell(self):
        self._v("ps_amsi.ps1", Verdict.MALICIOUS, ("AmsiBypass", "DisableDefender", "DownloadExecute"))

    def test_ps_encoded(self):
        self._v("ps_encoded.ps1", Verdict.SUSPICIOUS, ("EncodedCommand",))

    def test_shell_pipe(self):
        self._v("shell_pipe.sh", Verdict.SUSPICIOUS, ("PipeToShell",))

    def test_shell_decode(self):
        self._v("shell_decode.sh", Verdict.SUSPICIOUS, ("DecodePipe",))

    def test_mac_stealer(self):
        self._v("stealer.command", Verdict.MALICIOUS, ("MacStealer",))

    def test_reverse_shell(self):
        self._v("revshell.sh", Verdict.SUSPICIOUS, ("ReverseShellDevTcp",))

    def test_applescript_prompt(self):
        self._v("prompt.applescript", Verdict.SUSPICIOUS, ("FakePasswordPrompt",))

    def test_php_webshell(self):
        self._v("shell.php", Verdict.MALICIOUS, ("EvalSuperglobal",))

    def test_clickfix(self):
        self._v("clickfix.html", Verdict.SUSPICIOUS, ("ClickFixClipboard",))

    def test_npm_hook(self):
        self._v("package.json", Verdict.SUSPICIOUS, ("NPM.InstallHook",))

    def test_desktop(self):
        self._v("run.desktop", Verdict.SUSPICIOUS, ("DesktopExec",))

    def test_url_shortcut(self):
        self._v("bad.url", Verdict.SUSPICIOUS, ("UrlToPayload",))

    def test_python(self):
        self._v("py_mal.py", Verdict.SUSPICIOUS, ("ReverseShell",))

    def test_embedded_macho(self):
        self._v("embedded.txt", Verdict.SUSPICIOUS, ("Embedded.Base64.MACHO",))

    def test_iocs(self):
        self._v("iocs.txt", Verdict.MALICIOUS, ("TelegramToken", "DiscordWebhook"))


class CleanSamples(unittest.TestCase):
    def _clean(self, name):
        root = scan(name)
        self.assertLess(root.meta["score"], 10, f"{name}: score {root.meta['score']} dets {sorted(names(root))}")

    def test_clean_sh(self):
        self._clean("clean.sh")

    def test_clean_py(self):
        self._clean("clean.py")

    def test_clean_js(self):
        self._clean("clean.js")

    def test_clean_package(self):
        self._clean("clean_package.json")


class IocUnit(unittest.TestCase):
    def test_extract(self):
        bag = extract_iocs("go to https://good.example.com and abc.duckdns.org, ip 203.0.113.9")
        self.assertIn("good.example.com", bag.get("domain", []))
        self.assertIn("abc.duckdns.org", bag.get("tunnel_host", []))

    def test_loopback_not_flagged(self):
        bag = extract_iocs("server http://127.0.0.1:8080/api and http://192.168.1.1/x")
        self.assertNotIn("raw_ip_url", bag)


class Sanity(unittest.TestCase):
    def test_all_analyzers_load(self):
        self.assertGreaterEqual(len(load_all()), 30)


if __name__ == "__main__":
    unittest.main(verbosity=2)

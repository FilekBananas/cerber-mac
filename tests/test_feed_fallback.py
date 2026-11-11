"""Database update resilience: a feed that cannot be downloaded (abuse.ch 410 since 2026-10, no key, offline)
must fall back to the copy on disk instead of rebuilding the database without it; the abuse.ch key is read from
$CERBER_ABUSECH_KEY or abusech.key, validated, and never appears in the log.

    .venv/bin/python -m unittest tests.test_feed_fallback -v
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerber import config, updater  # noqa: E402


class FeedFallbackTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cerber-feed-test-")
        self.logs: list[str] = []

    def _old_copy(self) -> str:
        p = os.path.join(self.tmp, "feed.zip")
        with open(p, "w") as fh:
            fh.write("old")
        os.utime(p, (0, 0))
        return p

    def test_failed_download_uses_copy_on_disk(self):
        p = self._old_copy()
        with mock.patch.object(updater, "_download", side_effect=OSError("410")):
            self.assertEqual(updater.fetch_feed(["https://x-api.abuse.ch/v2/files/exports/SECRETKEY123456789/f"],
                                                p, self.logs.append, "Test"), p)
        self.assertEqual(open(p).read(), "old")
        self.assertIn("kopii z dysku", self.logs[-1])
        self.assertNotIn("SECRETKEY", " ".join(self.logs))

    def test_no_copy_raises(self):
        with self.assertRaises(RuntimeError):
            updater.fetch_feed([], os.path.join(self.tmp, "none.zip"), self.logs.append, "Test")

    def test_fresh_copy_not_downloaded_again(self):
        p = os.path.join(self.tmp, "fresh.zip")
        open(p, "w").write("new")
        with mock.patch.object(updater, "_download") as dl:
            updater.fetch_feed(["https://a"], p, self.logs.append, "Test")
        dl.assert_not_called()

    def test_key_sources_and_validation(self):
        with mock.patch.dict(os.environ, {"CERBER_ABUSECH_KEY": "abcdEFGH12345678abcd"}):
            self.assertEqual(config.abusech_key(), "abcdEFGH12345678abcd")
            self.assertTrue(updater.abusech_urls("mb", ["full.csv.zip"])[0].startswith(
                "https://mb-api.abuse.ch/v2/files/exports/abcdEFGH12345678abcd/"))
        for bad in ("short", "../../etc/passwd/xxxxxxxxxx", "a b c d e f g h i j k l m n o p", "x" * 300):
            with mock.patch.dict(os.environ, {"CERBER_ABUSECH_KEY": bad}):
                self.assertIsNone(config.abusech_key(), bad)
        kf = os.path.join(self.tmp, "abusech.key")
        open(kf, "w").write("fileKEY_0123456789abc\n")
        with mock.patch.dict(os.environ, {"CERBER_ABUSECH_KEY": ""}), \
                mock.patch.object(config, "ABUSECH_KEY_FILE", kf):
            self.assertEqual(config.abusech_key(), "fileKEY_0123456789abc")
        with mock.patch.dict(os.environ, {"CERBER_ABUSECH_KEY": ""}), \
                mock.patch.object(config, "ABUSECH_KEY_FILE", os.path.join(self.tmp, "missing")):
            self.assertIsNone(config.abusech_key())
            self.assertEqual(updater.abusech_urls("mb", ["full.csv.zip"]), [])


class _Flaky:
    """Local HTTP server: the first response is cut after `cut` bytes, later ones honour Range (206)."""

    def __init__(self, body: bytes, cut: int, ranges: bool = True):
        import http.server
        import threading
        outer = self
        self.body, self.cut, self.ranges, self.requests = body, cut, ranges, []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                rng = self.headers.get("Range")
                outer.requests.append(rng)
                if rng and outer.ranges:
                    start = int(rng.split("=")[1].rstrip("-"))
                    part = outer.body[start:]
                    self.send_response(206)
                    self.send_header("Content-Range", f"bytes {start}-{len(outer.body) - 1}/{len(outer.body)}")
                    self.send_header("Content-Length", str(len(part)))
                    self.end_headers()
                    self.wfile.write(part)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                if len(outer.requests) == 1:
                    self.wfile.write(outer.body[:outer.cut])      # connection dropped mid-way
                    self.wfile.flush()
                    self.close_connection = True
                    return
                self.wfile.write(outer.body)

        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}/feed.zip"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


class ResumeTest(unittest.TestCase):
    def setUp(self):
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("full.csv", os.urandom(300_000).hex())
        self.zip = buf.getvalue()
        self.tmp = tempfile.mkdtemp(prefix="cerber-resume-test-")
        self.logs: list[str] = []
        self.sleep = mock.patch.object(updater.time, "sleep", lambda s: None)
        self.sleep.start()

    def tearDown(self):
        self.sleep.stop()

    def test_dropped_connection_is_resumed(self):
        srv = _Flaky(self.zip, cut=len(self.zip) // 3)
        try:
            dest = os.path.join(self.tmp, "feed.zip")
            updater._download(srv.url, dest, self.logs.append)
            self.assertEqual(open(dest, "rb").read(), self.zip)
            self.assertEqual(srv.requests[0], None)
            self.assertEqual(srv.requests[1], f"bytes={len(self.zip) // 3}-")      # resumed, not restarted
        finally:
            srv.close()

    def test_no_range_support_restarts(self):
        srv = _Flaky(self.zip, cut=1000, ranges=False)
        try:
            dest = os.path.join(self.tmp, "feed.zip")
            updater._download(srv.url, dest, self.logs.append)
            self.assertEqual(open(dest, "rb").read(), self.zip)
        finally:
            srv.close()

    def test_broken_zip_keeps_old_copy(self):
        srv = _Flaky(b"not a zip at all" * 100, cut=10 ** 9)
        try:
            dest = os.path.join(self.tmp, "feed.zip")
            open(dest, "wb").write(self.zip)
            with self.assertRaises(updater.IncompleteDownload):
                updater._download(srv.url, dest, self.logs.append)
            self.assertEqual(open(dest, "rb").read(), self.zip)
            self.assertFalse(os.path.exists(dest + ".part"))
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()

"""Tests for the local HTTP API (cerber.api_server).

The server runs as a real subprocess on a free port. Most tests use the fake backend app/mock_backend.py
(injected with CERBER_API_BACKEND), which prints realistic protocol events for every command without
scanning or moving anything: auth, Host/Origin/CSRF protection, validation, info/history/quarantine,
the job lifecycle with NDJSON follow + SSE streaming, cancel, queue order, upload, reports and shutdown.
One smoke test runs `info` through the real backend. Every process started here is stopped again;
all temporary files (mock reports, uploads) live in a private TMPDIR that is deleted at the end.

    python -m unittest tests.test_api_server -v
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
MOCK = str(ROOT / "app" / "mock_backend.py")
TERMINAL = ("done", "failed", "cancelled")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Resp:
    def __init__(self, status: int, headers, body: bytes):
        self.status, self.headers, self.body = status, headers, body

    def json(self):
        return json.loads(self.body.decode("utf-8"))

    def __repr__(self) -> str:
        return f"<{self.status} {self.body[:300]!r}>"


class ApiServer:
    """`python -m cerber.api_server` as a child process."""

    def __init__(self, tmp: str, env: dict | None = None, args: tuple = (), mock: bool = True):
        e = {k: v for k, v in os.environ.items() if not k.startswith(("CERBER_API_", "CERBER_MOCK_"))}
        e["TMPDIR"] = tmp                       # mock reports + uploads stay inside the test's temp dir
        if mock:
            e.update({"CERBER_API_BACKEND": MOCK, "CERBER_MOCK_SYNTHETIC": "1", "CERBER_MOCK_SPEED": "3"})
        e.update(env or {})
        self.errpath = os.path.join(tmp, f"server-{time.time_ns()}.log")
        self.errlog = open(self.errpath, "wb")  # noqa: SIM115
        self.proc = subprocess.Popen([PY, "-m", "cerber.api_server", *args], cwd=ROOT, env=e,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=self.errlog)
        box: list[bytes] = []
        t = threading.Thread(target=lambda: box.append(self.proc.stdout.readline()), daemon=True)
        t.start()
        t.join(60)
        if not box or not box[0]:
            self.stop()
            raise RuntimeError("server did not print api_ready: " + self.stderr())
        self.ready = json.loads(box[0])
        if self.ready.get("ev") == "api_ready":
            self.url, self.token = self.ready["url"], self.ready["token"]
            self.port = int(self.url.rsplit(":", 1)[1])

    def stderr(self) -> str:
        try:
            with open(self.errpath, "rb") as fh:
                return fh.read().decode("utf-8", "replace")[-3000:]
        except OSError:
            return ""

    def stop(self, sig: int = signal.SIGINT, timeout: float = 60) -> int:
        if self.proc.poll() is None:
            self.proc.send_signal(sig)
            try:
                self.proc.wait(timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(10)
        if self.proc.stdout:
            self.proc.stdout.close()
        self.errlog.close()
        return self.proc.returncode

    # ---- HTTP helpers
    def request(self, method: str, path: str, body=None, headers: dict | None = None, token: bool = True,
                timeout: float = 60) -> Resp:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        h = {"Authorization": f"Bearer {self.token}"} if token else {}
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            return Resp(r.status, r.headers, r.read())
        finally:
            conn.close()

    def get(self, path: str, **kw) -> Resp:
        return self.request("GET", path, **kw)

    def post(self, path: str, body=None, **kw) -> Resp:
        return self.request("POST", path, body, **kw)

    def raw(self, data: bytes, then: bytes | None = None, timeout: float = 30) -> bytes:
        """Raw socket exchange (for requests http.client cannot produce)."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as s:
            s.sendall(data)
            first = s.recv(65536)
            if then is None:
                out = first
            else:
                s.sendall(then)
                out = first
            while True:
                try:
                    chunk = s.recv(65536)
                except (TimeoutError, ConnectionResetError):
                    break
                if not chunk:
                    break
                out += chunk
                if then is None and b"\r\n\r\n" in out and b"Content-Length" in out:
                    head, _, rest = out.partition(b"\r\n\r\n")
                    n = int(head.split(b"Content-Length:")[1].split(b"\r\n")[0])
                    if len(rest) >= n:
                        break
        return out

    def job(self, jid: str) -> dict:
        r = self.get(f"/api/jobs/{jid}")
        assert r.status == 200, r
        return r.json()["job"]

    def wait(self, jid: str, states=TERMINAL, timeout: float = 120) -> dict:
        end = time.time() + timeout
        while time.time() < end:
            j = self.job(jid)
            if j["state"] in states:
                return j
            time.sleep(0.05)
        raise AssertionError(f"job {jid} did not reach {states}: {self.job(jid)}")

    def wait_stage(self, jid: str, stage: str | None = None, timeout: float = 120) -> dict:
        """Until the backend has emitted a stage (its SIGINT handler is installed by then)."""
        end = time.time() + timeout
        while time.time() < end:
            j = self.job(jid)
            if j["state"] in TERMINAL or (j["stage"] and (stage is None or j["stage"]["id"] == stage)):
                return j
            time.sleep(0.03)
        raise AssertionError(f"job {jid} never reached stage {stage}: {self.job(jid)}")

    def drain(self) -> None:
        """Cancel whatever is left and wait until the queue is empty (test isolation)."""
        for j in self.get("/api/jobs").json()["jobs"]:
            if j["state"] in ("queued", "running"):
                self.post(f"/api/jobs/{j['id']}/cancel")
        for j in self.get("/api/jobs").json()["jobs"]:
            if j["state"] not in TERMINAL:
                self.wait(j["id"])


def read_stream(srv: ApiServer, path: str, out: dict, key: str, headers: dict | None = None) -> threading.Thread:
    def run() -> None:
        conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=120)
        h = {"Authorization": f"Bearer {srv.token}", **(headers or {})}
        try:
            conn.request("GET", path, headers=h)
            r = conn.getresponse()
            out[key + "_status"] = r.status
            out[key + "_headers"] = r.headers
            out[key] = r.read()                     # http.client decodes the chunked encoding
        except Exception as exc:  # noqa: BLE001
            out[key + "_error"] = exc
        finally:
            conn.close()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def parse_sse(body: bytes) -> list[dict]:
    blocks = []
    for block in body.decode("utf-8").split("\n\n"):
        fields: dict = {}
        for line in block.split("\n"):
            if not line or line.startswith(":"):
                continue
            k, _, v = line.partition(":")
            fields[k] = v[1:] if v.startswith(" ") else v
        if fields:
            blocks.append(fields)
    return blocks


class MockBackendApiTest(unittest.TestCase):
    srv: ApiServer
    tmp: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cerber-api-test-"))
        cls.target = os.path.join(cls.tmp, "target")
        os.makedirs(cls.target)
        for i in range(3):
            with open(os.path.join(cls.target, f"plik{i}.txt"), "w") as fh:
                fh.write("x" * (i + 1))
        cls.archive = os.path.join(cls.tmp, "archiwum.zip")
        with open(cls.archive, "wb") as fh:
            fh.write(b"PK\x05\x06" + b"\0" * 18)
        cls.srv = ApiServer(cls.tmp, args=("--port", str(free_port())))

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            rc = cls.srv.stop()
            assert rc == 0, f"server exit code {rc}: {cls.srv.stderr()}"
        finally:
            shutil.rmtree(cls.tmp, ignore_errors=True)

    def tearDown(self) -> None:
        self.srv.drain()

    # ------------------------------------------------------------ docs, auth, Host/Origin
    def test_docs_page(self) -> None:
        r = self.srv.get("/", token=False)
        self.assertEqual(r.status, 200)
        self.assertTrue(r.headers["Content-Type"].startswith("text/html"))
        page = r.body.decode()
        for needle in ("Authorization: Bearer", "api_ready", "/api/sandbox/upload", "/api/jobs/{id}/stream",
                       "curl", "127.0.0.1", "Bezpieczeństwo", "token"):
            self.assertIn(needle, page)
        self.assertNotIn(self.srv.token, page)
        self.assertIn("default-src 'none'", r.headers["Content-Security-Policy"])
        self.assertIsNone(r.headers.get("Access-Control-Allow-Origin"))

    def test_auth_required(self) -> None:
        r = self.srv.get("/api/info", token=False)
        self.assertEqual(r.status, 401)
        self.assertIn("Bearer", r.headers["WWW-Authenticate"])
        self.assertIn("token", r.json()["error"])
        self.assertEqual(self.srv.get("/api/info", token=False,
                                      headers={"Authorization": "Bearer zly-token-1234567890"}).status, 401)
        self.assertEqual(self.srv.get("/api/info", token=False,
                                      headers={"Authorization": f"Basic {self.srv.token}"}).status, 401)
        self.assertEqual(self.srv.get(f"/api/info?token={self.srv.token}", token=False).status, 401)
        # nothing about jobs or routes leaks before authentication
        self.assertEqual(self.srv.get("/api/jobs/abc", token=False).status, 401)
        self.assertEqual(self.srv.get("/api/nonexistent", token=False).status, 401)
        self.assertEqual(self.srv.post("/api/scan", {"paths": [self.target]}, token=False).status, 401)
        r = self.srv.get("/api/info", token=False, headers={"X-Cerber-Token": self.srv.token})
        self.assertEqual(r.status, 200)
        r = self.srv.get("/api/info", token=False, headers={"Authorization": f"bearer {self.srv.token}"})
        self.assertEqual(r.status, 200)

    def test_host_header_dns_rebinding(self) -> None:
        p = self.srv.port
        for host in ("evil.example", f"evil.example:{p}", f"127.0.0.1:{p + 1}", "127.0.0.1", f"0.0.0.0:{p}",
                     f"127.0.0.1.evil.example:{p}"):
            self.assertEqual(self.srv.get("/api/info", headers={"Host": host}).status, 403, host)
            self.assertEqual(self.srv.get("/", headers={"Host": host}, token=False).status, 403, host)
        for host in (f"127.0.0.1:{p}", f"localhost:{p}", f"LOCALHOST:{p}"):
            self.assertEqual(self.srv.get("/api/info", headers={"Host": host}).status, 200, host)
        # HTTP/1.0 without Host at all
        out = self.srv.raw(f"GET /api/info HTTP/1.0\r\nAuthorization: Bearer {self.srv.token}\r\n\r\n".encode())
        self.assertTrue(out.startswith(b"HTTP/1.1 403"), out[:100])

    def test_origin_and_cross_site(self) -> None:
        p = self.srv.port
        for origin in ("https://evil.example", "null", f"http://127.0.0.1:{p + 1}", f"https://127.0.0.1:{p}",
                       f"http://localhost:{p}.evil.example"):
            r = self.srv.get("/api/info", headers={"Origin": origin})
            self.assertEqual(r.status, 403, origin)
            self.assertIsNone(r.headers.get("Access-Control-Allow-Origin"))
        for origin in (f"http://127.0.0.1:{p}", f"http://localhost:{p}"):
            self.assertEqual(self.srv.get("/api/info", headers={"Origin": origin}).status, 200, origin)
        self.assertEqual(self.srv.get("/api/info", headers={"Sec-Fetch-Site": "cross-site"}).status, 403)
        self.assertEqual(self.srv.get("/api/info", headers={"Sec-Fetch-Site": "same-site"}).status, 403)
        self.assertEqual(self.srv.get("/api/info", headers={"Sec-Fetch-Site": "same-origin"}).status, 200)
        # CORS preflight is never answered positively
        r = self.srv.request("OPTIONS", "/api/scan", token=False,
                             headers={"Origin": f"http://127.0.0.1:{p}", "Access-Control-Request-Method": "POST"})
        self.assertIn(r.status, (401, 405))
        r = self.srv.request("OPTIONS", "/api/scan")
        self.assertEqual(r.status, 405)
        self.assertFalse([k for k in r.headers if k.lower().startswith("access-control")])
        # simple-form CSRF: a browser form can only send these content types
        for ctype in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"):
            r = self.srv.post("/api/scan", json.dumps({"paths": [self.target]}).encode(),
                              headers={"Content-Type": ctype})
            self.assertEqual(r.status, 415, ctype)
        self.assertEqual(self.srv.post("/api/ai-install", b"x=1",
                                       headers={"Content-Type": "application/x-www-form-urlencoded"}).status, 415)

    # ------------------------------------------------------------ quick commands
    def test_info_history_quarantine(self) -> None:
        r = self.srv.get("/api/info")
        self.assertEqual(r.status, 200)
        info = r.json()
        self.assertEqual(info["ev"], "info")
        self.assertGreater(info["patterns_total"], 0)
        h = self.srv.get("/api/history").json()
        self.assertEqual(h["ev"], "history")
        self.assertTrue(h["items"])
        rid = h["items"][0]["id"]
        r = self.srv.get(f"/api/history/{rid}/report")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.headers["Content-Type"].startswith("text/html"))
        self.assertIn("sandbox", r.headers["Content-Security-Policy"])
        self.assertEqual(self.srv.get("/api/history/gui-00000000-000000/report").status, 404)
        victim = os.path.join(self.target, "plik0.txt")
        r = self.srv.post("/api/quarantine", {"path": victim})
        self.assertEqual(r.status, 200, r)
        self.assertEqual(r.json()["ev"], "quarantined")
        self.assertEqual(r.json()["path"], victim)
        self.assertEqual(self.srv.post("/api/quarantine", {"path": self.target}).status, 400)
        self.assertEqual(self.srv.post("/api/quarantine", {"path": "plik0.txt"}).status, 400)
        self.assertEqual(self.srv.post("/api/quarantine", {}).status, 400)

    def test_validation(self) -> None:
        before = {j["id"] for j in self.srv.get("/api/jobs").json()["jobs"]}
        f = os.path.join(self.target, "plik1.txt")
        cases = [
            ("/api/scan", {"paths": ["wzgledna/sciezka"]}, 400, "bezwzględna"),
            ("/api/scan", {"paths": ["/nie/ma/takiej/sciezki"]}, 400, "Nie ma takiej"),
            ("/api/scan", {"paths": []}, 400, "paths"),
            ("/api/scan", {"paths": "x" * 10}, 400, "bezwzględna"),
            ("/api/scan", {"paths": [123]}, 400, "ścieżką"),
            ("/api/scan", {"paths": [self.target + "\x00x"]}, 400, "ścieżka"),
            ("/api/scan", {"paths": [self.target], "path": self.target}, 400, "nie oba"),
            ("/api/scan", {"paths": [self.target], "ai": "tak"}, 400, "true albo false"),
            ("/api/scan", {"pathz": [self.target]}, 400, "Nieznane pole"),
            ("/api/sandbox", {"path": self.target}, 400, "zwykły plik"),
            ("/api/sandbox", {"path": "-rf"}, 400, "bezwzględna"),
            ("/api/github", {"url": "ftp://github.com/a/b"}, 400, "http"),
            ("/api/github", {"url": "https://gitlab.com/a/b"}, 400, "github.com"),
            ("/api/github", {"url": "https://github.com/tylko-wlasciciel"}, 400, "repozytorium"),
            ("/api/github", {"url": "https://user:pass@github.com/a/b"}, 400, "logowania"),
            ("/api/github", {"url": "--help"}, 400, ""),
            ("/api/huggingface", {"url": "https://github.com/a/b"}, 400, "huggingface.co"),
            ("/api/url", {"url": "file:///etc/passwd"}, 400, "http"),
            ("/api/url", {"url": "javascript:alert(1)"}, 400, ""),
            ("/api/url", {"url": "data:text/html,<b>x</b>"}, 400, ""),
            ("/api/url", {"url": "https://exa mple.com/"}, 400, "spacje"),
            ("/api/url", {"url": "https://" + "a" * 5000 + ".com/"}, 400, "4096"),
            ("/api/url", {"url": 5}, 400, "url"),
            ("/api/url", {}, 400, "url"),
            ("/api/laptop", {"level": "ultra"}, 400, "quick"),
            ("/api/laptop", {"level": "quick", "ai": 1}, 400, "true albo false"),
            ("/api/quarantine", {"path": f, "extra": 1}, 400, "Nieznane pole"),
            ("/api/ai-install", {"x": 1}, 400, "Nieznane pole"),
        ]
        for path, body, status, needle in cases:
            r = self.srv.post(path, body)
            self.assertEqual(r.status, status, (path, body, r))
            self.assertIn(needle, r.json()["error"], (path, body))
        bad_json = [(b"{nie json", 400), (b"[1, 2]", 400), (b'"tekst"', 400), (b"\xff\xfe", 400)]
        for raw, status in bad_json:
            r = self.srv.post("/api/scan", raw, headers={"Content-Type": "application/json"})
            self.assertEqual(r.status, status, raw)
        big = json.dumps({"paths": ["/" + "a" * (1 << 20)]}).encode()
        self.assertEqual(self.srv.post("/api/scan", big, headers={"Content-Type": "application/json"}).status, 413)
        self.assertEqual(self.srv.get("/api/nie-ma").status, 404)
        self.assertEqual(self.srv.get("/favicon.ico", token=False).status, 404)
        r = self.srv.get("/api/scan")
        self.assertEqual(r.status, 405)
        self.assertEqual(r.headers["Allow"], "POST")
        self.assertEqual(self.srv.request("DELETE", "/api/jobs").status, 405)
        self.assertEqual(self.srv.get("/api/jobs?state=dziwny").status, 400)
        for path in ("/api/jobs/brak", "/api/jobs/brak/events", "/api/jobs/brak/stream", "/api/jobs/brak/report"):
            self.assertEqual(self.srv.get(path).status, 404, path)
        self.assertEqual(self.srv.post("/api/jobs/brak/cancel").status, 404)
        # nothing was queued by any of the invalid requests
        self.assertEqual({j["id"] for j in self.srv.get("/api/jobs").json()["jobs"]}, before)

    # ------------------------------------------------------------ jobs
    def test_scan_job_lifecycle_and_streams(self) -> None:
        r = self.srv.post("/api/scan", {"paths": [self.target], "ai": False})
        self.assertEqual(r.status, 202, r)
        d = r.json()
        job, links = d["job"], d["links"]
        jid = job["id"]
        self.assertEqual(job["state"], "queued")
        self.assertEqual(job["command"], "scan")
        self.assertEqual(job["args"], {"paths": [self.target], "ai": False})
        self.assertEqual(r.headers["Location"], links["status"])
        for k in ("status", "events", "stream", "cancel", "report"):
            self.assertTrue(links[k].startswith(self.srv.url + f"/api/jobs/{jid}"), links[k])
        out: dict = {}
        threads = [read_stream(self.srv, f"/api/jobs/{jid}/events?follow=1", out, "ndjson"),
                   read_stream(self.srv, f"/api/jobs/{jid}/stream", out, "sse")]
        seen = []
        end = time.time() + 120
        while time.time() < end:
            j = self.srv.job(jid)
            if not seen or seen[-1] != j["state"]:
                seen.append(j["state"])
            if j["state"] == "running" and j["stage"] and j["stage"]["id"] == "scan":
                self.assertEqual(self.srv.get(f"/api/jobs/{jid}/report").status, 404)
            if j["state"] in TERMINAL:
                break
            time.sleep(0.03)
        self.assertEqual(seen[-1], "done", (seen, j))
        self.assertIn("running", seen)
        self.assertEqual(j["exit_code"], 0)
        self.assertEqual(j["verdict"], "MALICIOUS")
        self.assertEqual(j["findings"], 3)
        self.assertEqual(j["summary"]["mode"], "scan")
        self.assertFalse(j["summary"]["cancelled"])
        self.assertIsNone(j["pid"])
        self.assertLessEqual(j["created"], j["started"])
        self.assertLessEqual(j["started"], j["finished"])
        # all events, then from=N
        r = self.srv.get(f"/api/jobs/{jid}/events")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.headers["Content-Type"].startswith("application/x-ndjson"))
        lines = r.body.splitlines()
        events = [json.loads(x) for x in lines]
        self.assertEqual(len(events), j["events"])
        self.assertEqual(int(r.headers["X-Cerber-Next"]), len(events))
        self.assertEqual(r.headers["X-Cerber-Job-State"], "done")
        self.assertEqual(events[0]["ev"], "stage")
        self.assertEqual(events[-1]["ev"], "done")
        # a file may be re-sent with a raised verdict after the behaviour (detonation) stage: count files
        self.assertEqual(len({e["item"]["path"] for e in events if e["ev"] == "finding"}), 3)
        self.assertIn("scan", [e["id"] for e in events if e["ev"] == "stage"])
        tail = self.srv.get(f"/api/jobs/{jid}/events?from={len(events) - 1}")
        self.assertEqual([json.loads(x)["ev"] for x in tail.body.splitlines()], ["done"])
        self.assertEqual(self.srv.get(f"/api/jobs/{jid}/events?from={len(events) + 5}").body, b"")
        self.assertEqual(self.srv.get(f"/api/jobs/{jid}/events?from=-1").status, 400)
        # the follow stream and the SSE stream delivered exactly the same events, in order
        for t in threads:
            t.join(60)
        self.assertEqual(out.get("ndjson_status"), 200, out)
        self.assertEqual(out["ndjson"].splitlines(), lines)
        self.assertEqual(out.get("sse_status"), 200, out)
        self.assertTrue(out["sse_headers"]["Content-Type"].startswith("text/event-stream"))
        blocks = [b for b in parse_sse(out["sse"]) if "data" in b]
        self.assertEqual(blocks[-1].get("event"), "end")
        self.assertEqual(json.loads(blocks[-1]["data"])["state"], "done")
        data_blocks = blocks[:-1]
        self.assertEqual([int(b["id"]) for b in data_blocks], list(range(len(events))))
        self.assertEqual([json.loads(b["data"]) for b in data_blocks], events)
        # SSE resume with Last-Event-ID
        out2: dict = {}
        read_stream(self.srv, f"/api/jobs/{jid}/stream", out2, "sse", {"Last-Event-ID": str(len(events) - 2)}).join(30)
        resumed = [b for b in parse_sse(out2["sse"]) if "id" in b]
        self.assertEqual([int(b["id"]) for b in resumed], [len(events) - 1])
        # report
        r = self.srv.get(f"/api/jobs/{jid}/report")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.headers["Content-Type"].startswith("text/html"))
        self.assertIn("sandbox", r.headers["Content-Security-Policy"])
        self.assertIn(b"Raport Cerbera", r.body)
        r = self.srv.get(f"/api/jobs/{jid}/report?format=json")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.json()["verdict"], "MALICIOUS")
        listed = self.srv.get("/api/jobs").json()
        self.assertIn(jid, [x["id"] for x in listed["jobs"]])
        self.assertEqual([x["id"] for x in self.srv.get("/api/jobs?state=done").json()["jobs"]].count(jid), 1)

    def test_cancel_running_job(self) -> None:
        r = self.srv.post("/api/laptop", {"level": "quick"})
        self.assertEqual(r.status, 202, r)
        jid = r.json()["job"]["id"]
        self.assertEqual(r.json()["job"]["args"], {"level": "quick", "ai": False})
        j = self.srv.wait_stage(jid)
        self.assertEqual(j["state"], "running")
        pid = j["pid"]
        self.assertIsInstance(pid, int)
        r = self.srv.get(f"/api/jobs/{jid}/report")
        self.assertEqual(r.status, 404)
        self.assertIn("po zakończeniu", r.json()["error"])
        r = self.srv.post(f"/api/jobs/{jid}/cancel")
        self.assertEqual(r.status, 202, r)
        self.assertEqual(r.json()["cancel"], "signalled")
        self.assertTrue(r.json()["job"]["cancel_requested"])
        j = self.srv.wait(jid)
        self.assertEqual(j["state"], "cancelled", j)
        self.assertTrue(j["summary"]["cancelled"])          # SIGINT → partial results + `done`
        self.assertEqual(j["exit_code"], 130)
        self.assertIsNone(j["pid"])
        with self.assertRaises(ProcessLookupError):         # exited and reaped
            os.kill(pid, 0)
        r = self.srv.post(f"/api/jobs/{jid}/cancel")
        self.assertEqual(r.status, 409)
        self.assertEqual(r.json()["job"]["state"], "cancelled")
        # the partial report of a cancelled scan is still available
        self.assertEqual(self.srv.get(f"/api/jobs/{jid}/report").status, 200)

    def test_failed_job(self) -> None:
        r = self.srv.post("/api/github", {"url": "https://github.com/nieistnieje/repo"})
        self.assertEqual(r.status, 202, r)
        j = self.srv.wait(r.json()["job"]["id"])
        self.assertEqual(j["state"], "failed")
        self.assertEqual(j["exit_code"], 1)
        self.assertIn("nie istnieje", j["error"])
        self.assertIsNone(j["summary"])

    def test_queue_order_parallel_ai_and_cancel_queued(self) -> None:
        a = self.srv.post("/api/scan", {"paths": [self.target], "ai": False}).json()["job"]
        b = self.srv.post("/api/sandbox", {"path": self.archive, "ai": False}).json()["job"]
        c = self.srv.post("/api/github", {"url": "psf/requests"}).json()["job"]
        u = self.srv.post("/api/url", {"url": "example.com/narzedzie.zip"}).json()["job"]
        self.assertEqual(c["args"]["url"], "https://github.com/psf/requests")
        self.assertEqual(u["args"]["url"], "https://example.com/narzedzie.zip")
        self.assertEqual(a["queue_position"], 1)
        self.assertIn(b["queue_position"], (1, 2))           # 1 if the worker already took `a`
        self.assertEqual([c["queue_position"], u["queue_position"]],
                         [b["queue_position"] + 1, b["queue_position"] + 2])
        # cancel a queued job: it never starts
        r = self.srv.post(f"/api/jobs/{c['id']}/cancel")
        self.assertEqual(r.status, 200, r)
        self.assertEqual(r.json()["cancel"], "dequeued")
        cj = self.srv.job(c["id"])
        self.assertEqual(cj["state"], "cancelled")
        self.assertIsNone(cj["started"])
        self.assertEqual(cj["events"], 0)
        # ai-install runs next to the scan instead of waiting in the queue
        self.srv.wait(a["id"], ("running",) + TERMINAL)
        r = self.srv.post("/api/ai-install")
        self.assertEqual(r.status, 202, r)
        ai = self.srv.wait(r.json()["job"]["id"])
        self.assertEqual(ai["state"], "done", ai)
        self.assertEqual(ai["result"]["ev"], "ai_installed")
        # one heavy job at a time, FIFO
        max_running = 0
        end = time.time() + 180
        while time.time() < end:
            jobs = {x["id"]: x for x in self.srv.get("/api/jobs").json()["jobs"]}
            running = [x for x in jobs.values() if x["state"] == "running" and x["command"] != "ai-install"]
            max_running = max(max_running, len(running))
            if all(jobs[x["id"]]["state"] in TERMINAL for x in (a, b, u)):
                break
            time.sleep(0.03)
        self.assertEqual(max_running, 1)
        ja, jb, ju = (self.srv.job(x["id"]) for x in (a, b, u))
        self.assertEqual([ja["state"], jb["state"], ju["state"]], ["done", "done", "done"])
        self.assertLess(ai["started"], ja["finished"])          # parallel to the scan
        self.assertLessEqual(ja["finished"], jb["started"])
        self.assertLessEqual(jb["finished"], ju["started"])
        self.assertEqual(jb["summary"]["mode"], "sandbox")
        self.assertEqual(ju["summary"]["mode"], "url")

    def test_upload(self) -> None:
        payload = b"PK\x03\x04" + os.urandom(300_000)
        name = quote("../../tajne/próbka zip.zip")
        r = self.srv.post(f"/api/sandbox/upload?filename={name}&ai=false", payload,
                          headers={"Content-Type": "application/octet-stream"})
        self.assertEqual(r.status, 202, r)
        job = r.json()["job"]
        args = job["args"]
        self.assertEqual(args["filename"], "próbka zip.zip")
        self.assertEqual(args["size"], len(payload))
        self.assertFalse(args["ai"])
        path = args["path"]
        folder = os.path.dirname(path)
        self.assertTrue(os.path.basename(folder).startswith("cerber-api-upload-"))
        if os.path.exists(path):                 # may already be gone if the mock was very fast
            self.assertEqual(stat.S_IMODE(os.stat(folder).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        j = self.srv.wait(job["id"])
        self.assertEqual(j["state"], "done", j)
        self.assertEqual(j["summary"]["title"], "próbka zip.zip")
        self.assertFalse(os.path.exists(path))
        self.assertFalse(os.path.exists(folder))
        # rejected uploads
        octet = {"Content-Type": "application/octet-stream"}
        self.assertEqual(self.srv.post("/api/sandbox/upload?filename=a.zip", payload,
                                       headers={"Content-Type": "application/x-www-form-urlencoded"}).status, 415)
        self.assertEqual(self.srv.post("/api/sandbox/upload?filename=a.zip", payload,
                                       headers={"Content-Type": "application/json"}).status, 415)
        self.assertEqual(self.srv.post("/api/sandbox/upload?filename=a.zip", b"", headers=octet).status, 400)
        self.assertEqual(self.srv.post("/api/sandbox/upload?filename=a.zip&ai=moze", payload,
                                       headers=octet).status, 400)
        self.assertEqual(self.srv.post("/api/sandbox/upload?filename=a.zip", payload, headers=octet,
                                       token=False).status, 401)
        host = f"127.0.0.1:{self.srv.port}"
        auth = f"Authorization: Bearer {self.srv.token}\r\n"
        # over 4 GB: refused from the headers alone, nothing is read
        out = self.srv.raw((f"POST /api/sandbox/upload?filename=a.zip HTTP/1.1\r\nHost: {host}\r\n{auth}"
                            "Content-Type: application/octet-stream\r\nContent-Length: 5000000000\r\n\r\n").encode())
        self.assertTrue(out.startswith(b"HTTP/1.1 413"), out[:200])
        # chunked uploads are not accepted
        out = self.srv.raw((f"POST /api/sandbox/upload?filename=a.zip HTTP/1.1\r\nHost: {host}\r\n{auth}"
                            "Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
                            "4\r\nPK34\r\n0\r\n\r\n").encode())
        self.assertTrue(out.startswith(b"HTTP/1.1 411"), out[:200])
        # Expect: 100-continue (what curl does for big files) – only after the token was checked
        head = (f"POST /api/sandbox/upload?filename=b.zip&ai=0 HTTP/1.1\r\nHost: {host}\r\n{{auth}}"
                f"Content-Type: application/octet-stream\r\nContent-Length: {len(payload)}\r\n"
                "Expect: 100-continue\r\nConnection: close\r\n\r\n")
        out = self.srv.raw(head.replace("{auth}", "").encode())
        self.assertTrue(out.startswith(b"HTTP/1.1 401"), out[:200])
        self.assertNotIn(b"100 Continue", out)
        out = self.srv.raw(head.replace("{auth}", auth).encode(), then=payload)
        self.assertTrue(out.startswith(b"HTTP/1.1 100 Continue"), out[:200])
        self.assertIn(b"HTTP/1.1 202", out)
        jid = json.loads(out.split(b"\r\n\r\n", 2)[-1])["job"]["id"]
        self.assertEqual(self.srv.wait(jid)["state"], "done")

    def test_job_listing_and_pruned_ids(self) -> None:
        r = self.srv.post("/api/laptop", {"level": "patterns", "ai": True})
        self.assertEqual(r.status, 202)
        job = r.json()["job"]
        self.assertEqual(job["args"], {"level": "patterns", "ai": True})   # the mock reports the model as present
        listing = self.srv.get("/api/jobs").json()
        self.assertEqual(listing["jobs"][0]["id"], job["id"])             # newest first
        for k in ("id", "command", "args", "state", "created", "started", "finished", "verdict"):
            self.assertIn(k, listing["jobs"][0])
        r = self.srv.post(f"/api/jobs/{job['id']}/cancel", {"force": True})   # force: SIGTERM right away
        self.assertIn(r.status, (200, 202), r)
        self.assertIn(r.json()["cancel"], ("dequeued", "pending", "signalled"))
        self.assertEqual(self.srv.wait(job["id"])["state"], "cancelled")


class ServerProcessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cerber-api-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _refused(self, *args: str) -> dict:
        p = subprocess.run([PY, "-m", "cerber.api_server", *args], cwd=ROOT, capture_output=True, text=True,
                           timeout=60, env={**os.environ, "TMPDIR": self.tmp})
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        ev = json.loads(p.stdout.splitlines()[0])
        self.assertEqual(ev["ev"], "error")
        return ev

    def test_refuses_non_loopback_and_weak_token(self) -> None:
        for host in ("0.0.0.0", "192.168.1.10", "::", "example.com"):
            self.assertIn("127.0.0.1", self._refused("--host", host, "--port", "0")["msg"])
        self.assertIn("Token", self._refused("--port", "0", "--token", "krotki")["msg"])

    def test_port_fallback_and_shutdown_kills_jobs(self) -> None:
        busy = socket.socket()
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        taken = busy.getsockname()[1]
        try:
            srv = ApiServer(self.tmp, env={"CERBER_MOCK_SPEED": "0.2"}, args=("--port", str(taken)))
        finally:
            busy.close()
        try:
            self.assertNotEqual(srv.port, taken)
            self.assertTrue(taken < srv.port <= taken + 10, srv.url)
            self.assertEqual(srv.get("/api/info").status, 200)
            jid = srv.post("/api/laptop", {"level": "deep"}).json()["job"]["id"]
            queued = srv.post("/api/scan", {"paths": [self.tmp]}).json()["job"]["id"]
            j = srv.wait_stage(jid, "env")
            self.assertEqual(j["state"], "running")
            pid = j["pid"]
            out: dict = {}
            t = read_stream(srv, f"/api/jobs/{jid}/events?follow=1", out, "follow")
            time.sleep(0.5)
        except BaseException:
            srv.stop(signal.SIGKILL)
            raise
        t0 = time.time()
        rc = srv.stop(signal.SIGTERM)
        self.assertEqual(rc, 0, srv.stderr())
        self.assertLess(time.time() - t0, 45)
        end = time.time() + 10
        while time.time() < end:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            self.fail(f"backend process {pid} still alive after the server exited")
        t.join(10)
        lines = out.get("follow", b"").splitlines()
        self.assertTrue(lines, out)
        last = json.loads(lines[-1])
        self.assertEqual(last["ev"], "done")                # the follower got the cancelled summary
        self.assertTrue(last["summary"]["cancelled"])
        self.assertTrue(queued)


class RealBackendSmokeTest(unittest.TestCase):
    """`info` through the real cerber.gui_backend (fast: does not load the engines)."""

    def test_info_real_backend(self) -> None:
        tmp = os.path.realpath(tempfile.mkdtemp(prefix="cerber-api-test-"))
        token = "smoke-" + os.urandom(12).hex()
        srv = ApiServer(tmp, env={"CERBER_API_TOKEN": token}, args=("--port", "0"), mock=False)
        try:
            self.assertEqual(srv.token, token)
            r = srv.get("/api/info")
            self.assertEqual(r.status, 200, r)
            info = r.json()
            self.assertEqual(info["ev"], "info")
            for k in ("patterns_total", "ai_model", "missing"):
                self.assertIn(k, info)
            self.assertEqual(srv.get("/api/info", token=False).status, 401)
        finally:
            rc = srv.stop()
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()

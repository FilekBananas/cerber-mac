"""Cerber local HTTP API: everything the Cerber.app GUI can do, on http://127.0.0.1 only.

    python -m cerber.api_server [--host 127.0.0.1] [--port 8765] [--token TOKEN]

When ready it prints ONE JSON line on stdout and serves until SIGINT/SIGTERM:

    {"ev": "api_ready", "url": "http://127.0.0.1:8765", "token": "…", "docs": "http://127.0.0.1:8765/"}

The API never scans by itself. Every operation runs the GUI backend exactly like Cerber.app does
(`python -m cerber.gui_backend <command> … [--level L] [--ai]`, cwd = project root, app/PROTOCOL.md) and
keeps its JSON-Lines events. Scans are jobs in a FIFO queue (one at a time – a scan needs ~2.6 GB RAM);
`ai-install` has its own lane and may run next to a scan; info/history/quarantine answer immediately.

Security (a local API is reachable by every web page the user opens): loopback only; a bearer token on
every /api/* request (hmac.compare_digest); the Host header must be 127.0.0.1:PORT or localhost:PORT
(DNS rebinding); no CORS headers at all; foreign Origin / Sec-Fetch-Site: cross-site are rejected; JSON
endpoints accept only Content-Type: application/json (no simple-form CSRF); every input is validated and
passed to the backend as an argument list (never through a shell).

Environment: CERBER_API_TOKEN – token to use instead of a random one (safer than --token, which is
visible in `ps`); CERBER_API_BACKEND – backend command for tests (a .py file is run with the venv Python,
e.g. app/mock_backend.py; anything else is split like a shell command line, without a shell).
Stdlib only.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hmac
import html
import json
import os
import re
import secrets
import select
import shlex
import shutil
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
REPORTS = os.path.join(os.environ.get("CERBER_HOME", ROOT), "reports")      # same as cerber/config.py

DEFAULT_PORT = 8765
PORT_TRIES = 10                     # the requested port, then the next 10
MAX_EVENTS = 50_000                 # stored events per job (progress/log beyond that are dropped, `done` never)
MAX_JOBS = 100                      # finished jobs kept in memory
MAX_QUEUED = 50
MAX_JSON_BODY = 1 << 20
MAX_UPLOAD = 4 << 30                # 4 GB
UPLOAD_SPARE = 1 << 30              # free disk space that must remain after an upload
MAX_PARALLEL_UPLOADS = 2
MAX_PATHS = 1000
MAX_URL = 4096
CHUNK = 1 << 20
DRAIN_LIMIT = 16 << 20              # unread request bodies up to this size are read and discarded after an error
LEVELS = ("quick", "patterns", "deep", "mega")
DONE_COMMANDS = ("scan", "sandbox", "github", "huggingface", "url", "laptop")   # finish with a `done` event
RESULT_EVENTS = ("info", "history", "quarantined", "ai_installed")
TERMINAL = ("done", "failed", "cancelled")
CANCEL_SIGTERM_AFTER = 20.0         # SIGINT first (partial results), then SIGTERM, then SIGKILL of the tree
CANCEL_SIGKILL_AFTER = 10.0
SHUTDOWN_GRACE = 15.0
KEEPALIVE = 15.0
INFO_TTL = 60.0
QUICK_TIMEOUT = {"info": 60, "history": 60, "quarantine": 120}
FORM_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data", "text/plain")
GITHUB_HOSTS = ("github.com", "www.github.com")
HF_HOSTS = ("huggingface.co", "www.huggingface.co", "hf.co")
GITHUB_SHORT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]+$")
HF_SHORT = re.compile(r"^(?:(?:datasets|spaces)/)?[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{16,512}$")


def _iso(t: float | None) -> str | None:
    return _dt.datetime.fromtimestamp(t).astimezone().isoformat(timespec="milliseconds") if t else None


def _log(msg: str) -> None:
    try:
        sys.stderr.write(f"[cerber-api {time.strftime('%H:%M:%S')}] {msg}\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


def _dumps(obj) -> bytes:
    try:
        return (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
    except UnicodeEncodeError:         # lone surrogates from odd file names
        return (json.dumps(obj, ensure_ascii=True) + "\n").encode("ascii")


class ApiError(Exception):
    def __init__(self, status: int, msg: str, headers: dict | None = None, **extra):
        super().__init__(msg)
        self.status, self.msg, self.headers, self.extra = status, msg, headers or {}, extra


# ------------------------------------------------------------------ backend process helpers

def _python() -> str:
    venv = os.path.join(ROOT, ".venv", "bin", "python")
    return venv if os.access(venv, os.X_OK) else sys.executable


def backend_command() -> list[str]:
    override = os.environ.get("CERBER_API_BACKEND", "").strip()
    if override:
        if override.endswith(".py"):
            return [_python(), override if os.path.isabs(override) else os.path.join(ROOT, override)]
        return shlex.split(override)
    return [_python(), "-m", "cerber.gui_backend"]


def backend_env() -> dict[str, str]:
    env = dict(os.environ)
    env.pop("CERBER_API_TOKEN", None)          # the backend never needs the API token
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("LANG", "pl_PL.UTF-8")
    cur = [p for p in env.get("PATH", "").split(":") if p]
    extra = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    env["PATH"] = ":".join(cur + [p for p in extra if p not in cur])
    return env


def _descendants(pid: int) -> list[int]:
    """All descendants of pid (the sandboxed scanners call setsid, so the process group is not enough)."""
    try:
        out = subprocess.run(["/bin/ps", "-axo", "pid=,ppid="], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    children: dict[int, list[int]] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            children.setdefault(int(parts[1]), []).append(int(parts[0]))
    found: list[int] = []
    stack = [pid]
    while stack:
        for c in children.get(stack.pop(), []):
            if c not in found and c != os.getpid():
                found.append(c)
                stack.append(c)
    return found


def _kill_tree(proc: subprocess.Popen) -> None:
    kids = _descendants(proc.pid) if proc.poll() is None else []
    if proc.returncode is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)       # started with start_new_session → pgid == pid
        except (ProcessLookupError, PermissionError):
            pass
        proc.send_signal(signal.SIGKILL)
    for k in kids:
        try:
            os.kill(k, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def _wait(proc: subprocess.Popen, seconds: float, abort: threading.Event | None = None) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if proc.poll() is not None:
            return True
        if abort is not None and abort.is_set():
            break
        time.sleep(0.1)
    return proc.poll() is not None


# ------------------------------------------------------------------ jobs

class Job:
    def __init__(self, command: str, argv: list[str], args: dict, notes: list[str] | None = None,
                 cleanup_dir: str | None = None):
        self.id = secrets.token_hex(6)
        self.command = command
        self.argv = argv
        self.args = args
        self.lane = "ai" if command == "ai-install" else "scan"
        self.notes = list(notes or [])
        self.cleanup_dir = cleanup_dir
        self.state = "queued"
        self.created = time.time()
        self.started: float | None = None
        self.finished: float | None = None
        self.cond = threading.Condition()
        self.lines: list[bytes] = []
        self.dropped = 0
        self.stage: dict | None = None
        self.progress: dict | None = None
        self.findings = 0
        self._finding_paths: set = set()       # a file may be re-sent with a raised verdict
        self.summary: dict | None = None
        self.result: dict | None = None
        self.error: str | None = None
        self.warnings: list[str] = []
        self.exit_code: int | None = None
        self.cancel_requested = False
        self.cancel_count = 0
        self.proc: subprocess.Popen | None = None
        self.pid: int | None = None
        self.stderr_tail: deque[str] = deque(maxlen=200)

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL

    def add_event(self, ev: dict, raw: bytes | None = None) -> None:
        kind = ev.get("ev")
        line = (raw.strip() + b"\n") if raw is not None else _dumps(ev)
        with self.cond:
            if self.terminal:                 # a straggler after the job was finalised
                return
            if kind == "stage":
                self.stage = {"id": ev.get("id"), "title": ev.get("title")}
            elif kind == "progress":
                self.progress = ev
            elif kind == "finding":
                item = ev.get("item") if isinstance(ev.get("item"), dict) else {}
                key = item.get("path") or item.get("display_path") or len(self._finding_paths)
                if key not in self._finding_paths:
                    self._finding_paths.add(key)
                    self.findings += 1
            elif kind == "done":
                self.summary = ev.get("summary") if isinstance(ev.get("summary"), dict) else {}
            elif kind == "error":
                msg = str(ev.get("msg") or "")
                if ev.get("fatal"):
                    self.error = msg
                else:
                    self.warnings.append(msg)
                    del self.warnings[:-20]
            elif kind in RESULT_EVENTS:
                self.result = ev
            n = len(self.lines)
            if kind not in ("done", "error") and (n >= MAX_EVENTS + 5000
                                                   or (n >= MAX_EVENTS and kind in ("progress", "log", "net_status"))):
                self.dropped += 1
            else:
                self.lines.append(line)
            self.cond.notify_all()

    def public(self, detail: bool = False, queue_position: int | None = None) -> dict:
        with self.cond:
            s = self.summary
            results = s.get("results") if isinstance(s, dict) else None
            d = {"id": self.id, "command": self.command, "args": self.args, "state": self.state,
                 "created": _iso(self.created), "started": _iso(self.started), "finished": _iso(self.finished),
                 "queue_position": queue_position, "stage": self.stage,
                 "findings": len(results) if isinstance(results, list) else self.findings,
                 "verdict": s.get("verdict") if isinstance(s, dict) else None, "error": self.error}
            if detail:
                d.update({"progress": self.progress, "events": len(self.lines), "events_dropped": self.dropped,
                          "warnings": list(self.warnings), "notes": list(self.notes), "exit_code": self.exit_code,
                          "cancel_requested": self.cancel_requested,
                          "pid": self.pid if self.state == "running" else None,
                          "result": self.result, "summary": s, "stderr_tail": list(self.stderr_tail)[-30:]})
        return d


class Scheduler:
    """FIFO lanes: "scan" (one heavy scan at a time) and "ai" (model download, parallel to scans)."""

    def __init__(self, cmd: list[str], env: dict[str, str]):
        self.cmd = cmd
        self.env = env
        self.lock = threading.Lock()
        self.wake = threading.Condition(self.lock)
        self.jobs: dict[str, Job] = {}
        self.queues: dict[str, deque[Job]] = {"scan": deque(), "ai": deque()}
        self.running: dict[str, Job | None] = {"scan": None, "ai": None}
        self.stopping = False
        self.force = threading.Event()
        self.quick_procs: set[subprocess.Popen] = set()
        self.quick_sem = threading.BoundedSemaphore(4)
        self._info: tuple[float, dict | None] = (0.0, None)
        self.workers = [threading.Thread(target=self._worker, args=(lane,), name=f"cerber-api-{lane}", daemon=True)
                        for lane in self.queues]
        for w in self.workers:
            w.start()

    # ---- queue
    def check_capacity(self) -> None:
        with self.lock:
            self._check_capacity()

    def _check_capacity(self) -> None:
        if self.stopping:
            raise ApiError(503, "Serwer API jest właśnie zamykany – nie przyjmuje nowych zadań.")
        if sum(len(q) for q in self.queues.values()) >= MAX_QUEUED:
            raise ApiError(429, f"W kolejce czeka już {MAX_QUEUED} zadań – poczekaj albo anuluj część z nich.")

    def submit(self, job: Job) -> dict:
        with self.lock:
            self._check_capacity()
            self.jobs[job.id] = job
            self.queues[job.lane].append(job)
            snapshot = job.public(queue_position=len(self.queues[job.lane]))
            self._prune()
            self.wake.notify_all()
        _log(f"zadanie {job.id}: {job.command} w kolejce")
        return snapshot

    def _prune(self) -> None:
        excess = len(self.jobs) - MAX_JOBS
        for jid, j in list(self.jobs.items()):
            if excess <= 0:
                break
            if j.terminal:
                del self.jobs[jid]
                excess -= 1

    def get(self, jid: str) -> Job:
        with self.lock:
            job = self.jobs.get(jid)
        if job is None:
            raise ApiError(404, f"Nie ma zadania o identyfikatorze {jid} (przechowywane jest ostatnie {MAX_JOBS}).")
        return job

    def active(self, command: str) -> Job | None:
        with self.lock:
            for j in [*self.queues["ai"], *self.queues["scan"], *self.running.values()]:
                if j is not None and j.command == command and not j.terminal:
                    return j
        return None

    def describe(self, job: Job, detail: bool = False) -> dict:
        with self.lock:
            pos = None
            q = self.queues[job.lane]
            if job in q:
                pos = list(q).index(job) + 1
        return job.public(detail, pos)

    def listing(self, state: str | None = None) -> dict:
        with self.lock:
            jobs = list(self.jobs.values())
            pos = {j.id: i + 1 for q in self.queues.values() for i, j in enumerate(q)}
            running = [j.id for j in self.running.values() if j is not None]
        out = [j.public(queue_position=pos.get(j.id)) for j in reversed(jobs)]
        if state:
            out = [d for d in out if d["state"] == state]
        return {"jobs": out, "running": running, "queued": len(pos)}

    # ---- cancel
    def cancel(self, job: Job, force: bool = False) -> str:
        with self.lock:
            if job in self.queues[job.lane]:
                self.queues[job.lane].remove(job)
                with job.cond:
                    job.cancel_requested = True
                    job.state = "cancelled"
                    job.finished = time.time()
                    job.cond.notify_all()
                dequeued = True
            else:
                dequeued = False
        if dequeued:
            self._cleanup(job)
            _log(f"zadanie {job.id}: anulowane w kolejce")
            return "dequeued"
        with job.cond:
            if job.terminal:
                return "finished"
            job.cancel_requested = True
            job.cancel_count += 1
            count, proc = job.cancel_count, job.proc
        if proc is None:
            return "pending"                 # the worker sees cancel_requested right after starting the process
        if count == 1:
            self._escalate(job, proc)
        if count == 1 and not force:
            _log(f"zadanie {job.id}: SIGINT (anulowanie)")
            proc.send_signal(signal.SIGINT)
        else:                                # like the app's second press: stop now
            _log(f"zadanie {job.id}: SIGTERM (anulowanie wymuszone)")
            proc.send_signal(signal.SIGTERM)
        return "signalled"

    def _escalate(self, job: Job, proc: subprocess.Popen) -> None:
        def run() -> None:
            if _wait(proc, CANCEL_SIGTERM_AFTER, self.force):
                return
            _log(f"zadanie {job.id}: brak reakcji na SIGINT – SIGTERM")
            proc.send_signal(signal.SIGTERM)
            if _wait(proc, CANCEL_SIGKILL_AFTER, self.force):
                return
            _log(f"zadanie {job.id}: SIGKILL całego drzewa procesów")
            _kill_tree(proc)
        threading.Thread(target=run, name=f"cerber-api-cancel-{job.id}", daemon=True).start()

    # ---- running
    def _worker(self, lane: str) -> None:
        while True:
            with self.lock:
                while not self.queues[lane] and not self.stopping:
                    self.wake.wait()
                if self.stopping:
                    return
                job = self.queues[lane].popleft()
                self.running[lane] = job
            try:
                self._run(job)
            except Exception:  # noqa: BLE001
                traceback.print_exc()
                with job.cond:
                    if not job.terminal:
                        job.state, job.finished = "failed", time.time()
                        job.error = job.error or "Wewnętrzny błąd serwera API podczas uruchamiania zadania."
                        job.cond.notify_all()
                self._cleanup(job)
            finally:
                with self.lock:
                    self.running[lane] = None
                    self.wake.notify_all()

    def _run(self, job: Job) -> None:
        with job.cond:
            if job.state != "queued":
                return
            early = job.cancel_requested
            job.state = "cancelled" if early else "running"
            job.started = None if early else time.time()
            job.finished = time.time() if early else None
            job.cond.notify_all()
        if early:
            self._cleanup(job)
            return
        _log(f"zadanie {job.id}: start {job.command}")
        try:
            proc = subprocess.Popen(self.cmd + job.argv, cwd=ROOT, env=self.env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                                    close_fds=True)
        except OSError as exc:
            job.add_event({"ev": "error", "fatal": True, "msg": f"Nie udało się uruchomić skanera: {exc}"})
            self._finish(job, None)
            return
        with job.cond:
            job.proc, job.pid = proc, proc.pid
            pending = job.cancel_requested
        if pending:
            proc.send_signal(signal.SIGINT)
            self._escalate(job, proc)
        t_out = threading.Thread(target=self._read_stdout, args=(job, proc), daemon=True)
        t_err = threading.Thread(target=self._read_stderr, args=(job, proc), daemon=True)
        t_out.start()
        t_err.start()
        rc = proc.wait()
        t_out.join(timeout=10)      # a grandchild may keep the pipe open – do not wait forever
        t_err.join(timeout=2)
        self._finish(job, rc)

    @staticmethod
    def _read_stdout(job: Job, proc: subprocess.Popen) -> None:
        assert proc.stdout is not None
        for raw in proc.stdout:
            text = raw.decode("utf-8", "replace").strip()
            if not text:
                continue
            try:
                ev = json.loads(text)
            except ValueError:
                ev = None
            if isinstance(ev, dict) and isinstance(ev.get("ev"), str):
                job.add_event(ev, raw)
            else:
                job.stderr_tail.append("[stdout] " + text[:500])

    @staticmethod
    def _read_stderr(job: Job, proc: subprocess.Popen) -> None:
        assert proc.stderr is not None
        for raw in proc.stderr:
            text = raw.decode("utf-8", "replace").rstrip()
            if text:
                job.stderr_tail.append(text[:1000])

    def _finish(self, job: Job, rc: int | None) -> None:
        with job.cond:
            job.exit_code = rc
            s = job.summary
            if s is not None:
                state = "cancelled" if s.get("cancelled") else "done"
            elif job.cancel_requested or rc == 130:
                state = "cancelled"
            elif job.command in DONE_COMMANDS:
                state = "failed"
            else:
                state = "done" if rc == 0 and job.error is None else "failed"
            if state == "failed" and not job.error:
                tail = next((ln for ln in reversed(job.stderr_tail) if ln.strip()), "")
                job.error = f"Skaner zakończył się kodem {rc} bez wyniku" + (f": {tail[:300]}" if tail else ".")
            job.state = state
            job.finished = time.time()
            job.proc = None
            job.cond.notify_all()
        self._cleanup(job)
        if job.command == "ai-install":
            with self.lock:
                self._info = (0.0, None)
        _log(f"zadanie {job.id}: {state} (kod {rc})")

    @staticmethod
    def _cleanup(job: Job) -> None:
        d, job.cleanup_dir = job.cleanup_dir, None
        if d:
            shutil.rmtree(d, ignore_errors=True)

    # ---- quick commands (info, history, quarantine): run now, return the result event
    def run_quick(self, argv: list[str], expect: str) -> dict:
        if not self.quick_sem.acquire(timeout=30):
            raise ApiError(503, "Zbyt wiele równoczesnych zapytań – spróbuj ponownie za chwilę.")
        try:
            with self.lock:
                if self.stopping:
                    raise ApiError(503, "Serwer API jest właśnie zamykany.")
            timeout = QUICK_TIMEOUT.get(argv[0], 60)
            try:
                proc = subprocess.Popen(self.cmd + argv, cwd=ROOT, env=self.env, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                                        close_fds=True)
            except OSError as exc:
                raise ApiError(500, f"Nie udało się uruchomić backendu Cerbera: {exc}") from None
            with self.lock:
                self.quick_procs.add(proc)
            try:
                out, err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                _kill_tree(proc)
                proc.communicate()
                raise ApiError(504, f"Backend Cerbera nie odpowiedział w ciągu {timeout} s.") from None
            finally:
                with self.lock:
                    self.quick_procs.discard(proc)
        finally:
            self.quick_sem.release()
        events = []
        for raw in out.splitlines():
            try:
                ev = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                continue
            if isinstance(ev, dict):
                events.append(ev)
        for ev in events:
            if ev.get("ev") == expect:
                if expect == "info":
                    with self.lock:
                        self._info = (time.time(), ev)
                return ev
        msg = next((str(e.get("msg")) for e in events if e.get("ev") == "error" and e.get("msg")), None)
        if msg:
            raise ApiError(422, msg)
        tail = err.decode("utf-8", "replace").strip().splitlines()[-1:] if err else []
        raise ApiError(500, f"Backend Cerbera zakończył się kodem {proc.returncode} bez wyniku"
                            + (f": {tail[0][:300]}" if tail else "."))

    def ai_available(self) -> bool:
        with self.lock:
            t, info = self._info
        if info is None or time.time() - t > INFO_TTL:
            try:
                info = self.run_quick(["info"], "info")
            except ApiError:
                return False
        return bool(info.get("ai_model")) and info.get("llama_server") is not False

    # ---- shutdown
    def shutdown(self, grace: float = SHUTDOWN_GRACE) -> None:
        with self.lock:
            self.stopping = True
            queued = [j for q in self.queues.values() for j in q]
            for q in self.queues.values():
                q.clear()
            running = [j for j in self.running.values() if j is not None]
            quick = list(self.quick_procs)
            self.wake.notify_all()
        for j in queued:
            with j.cond:
                j.cancel_requested = True
                j.state, j.finished = "cancelled", time.time()
                j.cond.notify_all()
            self._cleanup(j)
        procs = []
        for j in running:
            with j.cond:
                j.cancel_requested = True
                p = j.proc
            if p is not None:
                _log(f"zadanie {j.id}: zamykanie serwera – SIGINT")
                p.send_signal(signal.SIGINT)
                procs.append(p)
        for p in quick:
            _kill_tree(p)
        end = time.monotonic() + grace
        while procs and time.monotonic() < end and not self.force.is_set():
            if all(p.poll() is not None for p in procs):
                break
            time.sleep(0.1)
        alive = [p for p in procs if p.poll() is None]
        for p in alive:
            p.send_signal(signal.SIGTERM)
        end = time.monotonic() + (0 if self.force.is_set() else 5.0)
        while alive and time.monotonic() < end and not all(p.poll() is not None for p in alive):
            time.sleep(0.1)
        for p in alive:
            if p.poll() is None:
                _log(f"proces {p.pid}: SIGKILL całego drzewa")
                _kill_tree(p)
        self.force.set()                    # cancel-escalation threads stop waiting
        for w in self.workers:
            w.join(timeout=15)
        for j in list(self.jobs.values()):  # a job that was just starting while we shut down
            with j.cond:
                p = j.proc
            if p is not None and p.poll() is None:
                _kill_tree(p)
            self._cleanup(j)


# ------------------------------------------------------------------ input validation

def _opt_bool(value, field: str) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    raise ApiError(400, f"Pole „{field}” musi mieć wartość true albo false.")


def _abs_path(value, field: str, want_file: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ApiError(400, f"Pole „{field}” musi być niepustą ścieżką (tekst).")
    if "\x00" in value or len(value) > 4096:
        raise ApiError(400, f"Nieprawidłowa ścieżka w polu „{field}”.")
    if not os.path.isabs(value):
        raise ApiError(400, f"Ścieżka musi być bezwzględna (zaczynać się od /): {value}")
    p = os.path.normpath(value)
    if not os.path.exists(p):
        raise ApiError(400, f"Nie ma takiej ścieżki (albo brak do niej dostępu): {p}")
    if want_file and not os.path.isfile(p):
        raise ApiError(400, f"To nie jest zwykły plik: {p}")
    return p


def _http_url(value, field: str = "url", hosts: tuple[str, ...] | None = None,
              short: re.Pattern | None = None, short_base: str = "") -> str:
    if not isinstance(value, str) or not value.strip():
        raise ApiError(400, f"Pole „{field}” musi być niepustym adresem http(s).")
    s = value.strip()
    if len(s) > MAX_URL or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in s):
        raise ApiError(400, "Nieprawidłowy adres (spacje, znaki sterujące albo ponad 4096 znaków).")
    if short is not None and short.match(s):
        s = short_base + s
    elif "://" not in s:
        s = "https://" + s                       # like the app: a missing scheme becomes https://
    try:
        u = urlsplit(s)
        port = u.port                            # raises ValueError on garbage such as "javascript:alert(1)"
    except ValueError:
        raise ApiError(400, f"Nieprawidłowy adres: {value}") from None
    if u.scheme.lower() not in ("http", "https"):
        raise ApiError(400, "Dozwolone są tylko adresy http:// i https://.")
    host = (u.hostname or "").lower()
    if not host or ("." not in host and host != "localhost") or (port is not None and not 0 < port < 65536):
        raise ApiError(400, f"Nieprawidłowy adres (brak poprawnej nazwy serwera): {value}")
    if u.username is not None or u.password is not None:
        raise ApiError(400, "Adres nie może zawierać danych logowania (użytkownik:hasło@).")
    if hosts is not None:
        if host not in hosts:
            raise ApiError(400, f"Oczekiwano adresu z {hosts[0]}, a podano: {host}")
        if len([p for p in u.path.split("/") if p]) < 2:
            raise ApiError(400, f"Adres musi wskazywać repozytorium: https://{hosts[0]}/właściciel/nazwa")
    return s


def _safe_filename(name: str) -> str:
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(c for c in name if c.isprintable()).strip().lstrip(".").strip()
    base, ext = os.path.splitext(name)
    ext = ext[:20]
    raw = base.encode("utf-8")[: 200 - len(ext.encode("utf-8"))]
    name = raw.decode("utf-8", "ignore").strip() + ext
    return name if name and name not in (".", "..") and not name.startswith(".") else "upload.bin"


def _mime(ctype: str | None) -> str:
    return (ctype or "").split(";", 1)[0].strip().lower()


def _query_bool(q: dict, key: str) -> bool | None:
    vals = q.get(key)
    if not vals:
        return None
    v = vals[-1].strip().lower()
    if v in ("1", "true", "yes", "tak"):
        return True
    if v in ("0", "false", "no", "nie"):
        return False
    raise ApiError(400, f"Parametr „{key}” musi mieć wartość true albo false.")


# ------------------------------------------------------------------ HTTP

ROUTES: list[tuple[str, re.Pattern, str]] = [(m, re.compile(p), h) for m, p, h in [
    ("GET", r"^/$", "h_docs"),
    ("GET", r"^/api/info$", "h_info"),
    ("GET", r"^/api/history$", "h_history"),
    ("GET", r"^/api/history/(?P<hid>[A-Za-z0-9._-]{1,128})/report$", "h_history_report"),
    ("POST", r"^/api/scan$", "h_scan"),
    ("POST", r"^/api/sandbox$", "h_sandbox"),
    ("POST", r"^/api/sandbox/upload$", "h_upload"),
    ("POST", r"^/api/github$", "h_github"),
    ("POST", r"^/api/huggingface$", "h_huggingface"),
    ("POST", r"^/api/url$", "h_url"),
    ("POST", r"^/api/laptop$", "h_laptop"),
    ("POST", r"^/api/quarantine$", "h_quarantine"),
    ("POST", r"^/api/ai-install$", "h_ai_install"),
    ("GET", r"^/api/jobs$", "h_jobs"),
    ("GET", r"^/api/jobs/(?P<jid>[A-Za-z0-9_-]{1,64})$", "h_job"),
    ("GET", r"^/api/jobs/(?P<jid>[A-Za-z0-9_-]{1,64})/events$", "h_events"),
    ("GET", r"^/api/jobs/(?P<jid>[A-Za-z0-9_-]{1,64})/stream$", "h_stream"),
    ("POST", r"^/api/jobs/(?P<jid>[A-Za-z0-9_-]{1,64})/cancel$", "h_cancel"),
    ("GET", r"^/api/jobs/(?P<jid>[A-Za-z0-9_-]{1,64})/report$", "h_report"),
]]

ERROR_TEXT = {400: "Nieprawidłowe żądanie HTTP.", 404: "Nie znaleziono.", 408: "Przekroczono czas oczekiwania.",
              414: "Za długi adres żądania.", 431: "Za duże nagłówki żądania.", 501: "Nieobsługiwana metoda HTTP.",
              505: "Nieobsługiwana wersja HTTP."}
JSON_CSP = "default-src 'none'; frame-ancestors 'none'"
DOCS_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; sandbox"


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True          # TIME_WAIT after a restart; a live listener is detected by _port_in_use
    allow_reuse_port = False
    request_queue_size = 64

    token: str
    scheduler: Scheduler
    base_url: str
    allowed_hosts: frozenset[str]
    allowed_origins: frozenset[str]
    upload_sem: threading.BoundedSemaphore
    streams = 0                         # open follow/SSE responses (flushed before exit)
    streams_lock = threading.Lock()

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)        # skip HTTPServer's reverse-DNS getfqdn()
        self.server_name, self.server_port = self.server_address[:2]

    def handle_error(self, request, client_address) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, TimeoutError)):
            return
        _log(f"błąd obsługi połączenia: {exc!r}")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Cerber-API/1"
    sys_version = ""
    timeout = 120                       # idle socket timeout (slow uploads, idle keep-alive)
    server: Server

    # ---- plumbing
    def version_string(self) -> str:
        return self.server_version

    def parse_request(self) -> bool:
        self._expect_100 = False
        self._body_read = False
        self._headers_sent = False
        return super().parse_request()

    def handle_expect_100(self) -> bool:
        self._expect_100 = True         # answered only after the token and the request were validated
        return True

    def _continue(self) -> None:
        if self._expect_100:
            self._expect_100 = False
            self.send_response_only(HTTPStatus.CONTINUE)
            self.end_headers()

    def log_request(self, code="-", size="-") -> None:
        path = urlsplit(getattr(self, "path", "") or "").path
        self.log_message("%s %s -> %s", self.command or "-", path or "-", int(code) if str(code).isdigit() or
                         isinstance(code, int) else code)

    def log_message(self, format, *args) -> None:  # noqa: A002
        _log(f"{self.client_address[0]} " + (format % args))

    def send_error(self, code, message=None, explain=None) -> None:
        try:
            self.close_connection = True
            body = _dumps({"error": ERROR_TEXT.get(int(code), "Błąd żądania HTTP.")})
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self._common_headers()
            self.end_headers()
            if self.command != "HEAD" and int(code) >= 200 and int(code) not in (204, 304):
                self.wfile.write(body)
        except OSError:
            pass

    def _common_headers(self, csp: str = JSON_CSP) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", csp)

    def _content_length(self) -> int | None:
        raw = self.headers.get("Content-Length")
        if raw is None:
            return None
        if not raw.strip().isdigit():
            raise ApiError(400, "Nieprawidłowy nagłówek Content-Length.")
        return int(raw.strip())

    def _unread_body(self) -> bool:
        if self._body_read:
            return False
        if self.headers.get("Transfer-Encoding"):
            return True
        raw = (self.headers.get("Content-Length") or "0").strip()
        return not raw.isdigit() or int(raw) > 0

    def _discard_body(self) -> None:
        """After an early error response: read a small unsent body so clients that write the whole request
        before reading (http.client, requests) get the response instead of a broken pipe."""
        if self._body_read or self._expect_100 or self.headers.get("Transfer-Encoding"):
            return
        raw = (self.headers.get("Content-Length") or "0").strip()
        n = int(raw) if raw.isdigit() else 0
        if not 0 < n <= DRAIN_LIMIT:
            return
        try:
            self.connection.settimeout(5)
            while n > 0:
                chunk = self.rfile.read(min(CHUNK, n))
                if not chunk:
                    break
                n -= len(chunk)
        except OSError:
            pass

    def _send(self, status: int, body: bytes, ctype: str, headers: dict | None = None, csp: str = JSON_CSP) -> None:
        close = self._unread_body()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._common_headers(csp)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self._headers_sent = True
        self.wfile.write(body)

    def _send_json(self, status: int, obj, headers: dict | None = None) -> None:
        self._send(status, _dumps(obj), "application/json; charset=utf-8", headers)

    # ---- dispatch
    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def do_OPTIONS(self) -> None:       # CORS preflight: always refused, never any Access-Control-* header
        self._dispatch("OPTIONS")

    def _dispatch(self, method: str) -> None:
        try:
            if not self.path.startswith("/"):
                raise ApiError(400, "Nieprawidłowy adres żądania.")
            url = urlsplit(self.path)
            self._check_host()
            self._check_origin()
            path = url.path
            self.query = parse_qs(url.query, keep_blank_values=True)
            if path == "/api" or path.startswith("/api/"):
                self._check_fetch_site()
                self._check_auth()
            allowed = []
            for m, rx, name in ROUTES:
                g = rx.match(path)
                if g:
                    if m == method:
                        getattr(self, name)(**g.groupdict())
                        return
                    allowed.append(m)
            if allowed:
                raise ApiError(405, f"Metoda {method} nie jest obsługiwana dla {path} (dozwolone: "
                                    f"{', '.join(allowed)}).", headers={"Allow": ", ".join(allowed)})
            raise ApiError(404, f"Nie ma takiego zasobu: {path}. Opis API: {self.server.base_url}/")
        except ApiError as e:
            if self._headers_sent:
                self.close_connection = True
                return
            try:
                self._send_json(e.status, {"error": e.msg, **e.extra}, e.headers)
                self._discard_body()
            except OSError:
                self.close_connection = True
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            self.close_connection = True
            if not self._headers_sent:
                try:
                    self._send_json(500, {"error": "Wewnętrzny błąd serwera API Cerbera."})
                except OSError:
                    pass

    # ---- security checks
    def _check_host(self) -> None:
        hosts = self.headers.get_all("Host") or []
        if len(hosts) != 1 or hosts[0].strip().lower() not in self.server.allowed_hosts:
            raise ApiError(403, "Odrzucono: nieprawidłowy nagłówek Host. Dozwolone są tylko "
                                f"{' i '.join(sorted(self.server.allowed_hosts))} (ochrona przed DNS rebinding).")

    def _check_origin(self) -> None:
        origins = self.headers.get_all("Origin") or []
        if origins and (len(origins) != 1 or origins[0].strip().lower() not in self.server.allowed_origins):
            raise ApiError(403, "Odrzucono żądanie wysłane z innej strony internetowej (nagłówek Origin). "
                                "API Cerbera jest dostępne tylko dla programów na tym komputerze.")

    def _check_fetch_site(self) -> None:
        if (self.headers.get("Sec-Fetch-Site") or "").strip().lower() in ("cross-site", "same-site"):
            raise ApiError(403, "Odrzucono żądanie wysłane przez przeglądarkę z innej strony (Sec-Fetch-Site).")

    def _check_auth(self) -> None:
        token = None
        auth = self.headers.get("Authorization")
        if auth:
            scheme, _, value = auth.strip().partition(" ")
            if scheme.lower() == "bearer":
                token = value.strip()
        if token is None:
            token = (self.headers.get("X-Cerber-Token") or "").strip() or None
        if not token or not hmac.compare_digest(token.encode("utf-8", "replace"),
                                                self.server.token.encode("utf-8")):
            raise ApiError(401, "Brak tokenu albo token jest nieprawidłowy. Dodaj nagłówek "
                                "„Authorization: Bearer <token>” (token jest w linii api_ready, którą serwer "
                                "wypisał przy starcie).", headers={"WWW-Authenticate": 'Bearer realm="cerber"'})

    # ---- request bodies
    def _json_body(self, allowed: tuple[str, ...] = ()) -> dict:
        if self.headers.get("Transfer-Encoding"):
            raise ApiError(411, "Wymagany nagłówek Content-Length (Transfer-Encoding nie jest obsługiwane).")
        length = self._content_length() or 0
        ctype = self.headers.get("Content-Type")
        if (ctype is not None or length) and _mime(ctype) != "application/json":
            raise ApiError(415, "Wymagany nagłówek Content-Type: application/json.")
        if length == 0:
            self._body_read = True
            return {}
        if length > MAX_JSON_BODY:
            raise ApiError(413, f"Treść żądania jest za duża (limit {MAX_JSON_BODY // 1024} KB).")
        self._continue()
        raw = self.rfile.read(length)
        if len(raw) != length:
            self.close_connection = True
            raise ApiError(400, "Niekompletna treść żądania.")
        self._body_read = True
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ApiError(400, "Treść żądania nie jest poprawnym JSON-em (UTF-8).") from None
        if not isinstance(data, dict):
            raise ApiError(400, "Treść żądania musi być obiektem JSON, np. {\"path\": \"/Users/…\"}.")
        unknown = sorted(k for k in data if k not in allowed)
        if unknown:
            raise ApiError(400, f"Nieznane pole: „{unknown[0]}”. Dozwolone: "
                                f"{', '.join(allowed) if allowed else '(brak pól)'}.")
        return data

    # ---- responses for jobs
    def _links(self, jid: str) -> dict:
        b = f"{self.server.base_url}/api/jobs/{jid}"
        return {"status": b, "events": f"{b}/events", "follow": f"{b}/events?follow=1", "stream": f"{b}/stream",
                "cancel": f"{b}/cancel", "report": f"{b}/report"}

    def _submit(self, job: Job, extra: dict | None = None) -> None:
        try:
            snapshot = self.server.scheduler.submit(job)
        except ApiError:
            Scheduler._cleanup(job)
            raise
        links = self._links(job.id)
        extra = {**({"notes": job.notes} if job.notes else {}), **(extra or {})}
        self._send_json(202, {"job": snapshot, "links": links, **extra}, {"Location": links["status"]})

    def _ai(self, requested: bool | None, default_on: bool) -> tuple[bool, list[str]]:
        """Like the app: AI only when the model and llama-server are there; by default only for `mega`."""
        if requested is False or (requested is None and not default_on):
            return False, []
        if self.server.scheduler.ai_available():
            return True, []
        if requested:
            return False, ["Model AI albo silnik llama-server nie jest dostępny – skan bez analizy AI "
                           "(model zainstalujesz przez POST /api/ai-install)."]
        return False, []

    @staticmethod
    def _flags(ai: bool) -> list[str]:
        return ["--ai"] if ai else []

    # ---- handlers: docs, quick commands
    def h_docs(self) -> None:
        self._send(200, docs_html(self.server.base_url).encode("utf-8"), "text/html; charset=utf-8", csp=DOCS_CSP)

    def h_info(self) -> None:
        self._send_json(200, self.server.scheduler.run_quick(["info"], "info"))

    def h_history(self) -> None:
        self._send_json(200, self.server.scheduler.run_quick(["history"], "history"))

    def h_history_report(self, hid: str) -> None:
        hist = self.server.scheduler.run_quick(["history"], "history")
        for it in hist.get("items") or []:
            if isinstance(it, dict) and it.get("id") == hid:
                self._send_report(it, f"cerber-{hid}")
                return
        raise ApiError(404, f"W historii nie ma raportu {hid}.")

    def h_quarantine(self) -> None:
        data = self._json_body(("path",))
        path = _abs_path(data.get("path"), "path", want_file=True)
        self._send_json(200, self.server.scheduler.run_quick(["quarantine", path], "quarantined"))

    # ---- handlers: jobs
    def h_scan(self) -> None:
        data = self._json_body(("paths", "path", "ai"))
        raw = data.get("paths", data.get("path"))
        if "paths" in data and "path" in data:
            raise ApiError(400, "Podaj „paths” (lista) albo „path”, nie oba.")
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, list) or not raw:
            raise ApiError(400, "Pole „paths” musi być niepustą listą ścieżek bezwzględnych.")
        if len(raw) > MAX_PATHS:
            raise ApiError(400, f"Za dużo ścieżek (limit {MAX_PATHS}).")
        paths = list(dict.fromkeys(_abs_path(p, "paths") for p in raw))
        ai, notes = self._ai(_opt_bool(data.get("ai"), "ai"), False)
        self._submit(Job("scan", ["scan", *paths, *self._flags(ai)], {"paths": paths, "ai": ai}, notes))

    def h_sandbox(self) -> None:
        data = self._json_body(("path", "ai"))
        path = _abs_path(data.get("path"), "path", want_file=True)
        ai, notes = self._ai(_opt_bool(data.get("ai"), "ai"), False)
        self._submit(Job("sandbox", ["sandbox", path, *self._flags(ai)], {"path": path, "ai": ai}, notes))

    def h_upload(self) -> None:
        q = self.query
        fname = _safe_filename((q.get("filename") or [""])[-1])
        ai_req = _query_bool(q, "ai")
        ctype = self.headers.get("Content-Type")
        if not ctype or _mime(ctype) in FORM_TYPES or _mime(ctype) == "application/json":
            raise ApiError(415, "Wyślij surową zawartość pliku z nagłówkiem Content-Type: application/octet-stream.")
        if self.headers.get("Transfer-Encoding"):
            raise ApiError(411, "Wymagany nagłówek Content-Length (Transfer-Encoding nie jest obsługiwane).")
        length = self._content_length()
        if length is None:
            raise ApiError(411, "Wymagany nagłówek Content-Length.")
        if length <= 0:
            raise ApiError(400, "Wysłany plik jest pusty.")
        if length > MAX_UPLOAD:
            raise ApiError(413, "Plik jest za duży – limit to 4 GB.")
        sched = self.server.scheduler
        sched.check_capacity()
        if not self.server.upload_sem.acquire(blocking=False):
            raise ApiError(429, "Trwa już wysyłanie innych plików – spróbuj za chwilę.")
        tmp = None
        try:
            tmp = tempfile.mkdtemp(prefix="cerber-api-upload-")
            os.chmod(tmp, 0o700)
            if shutil.disk_usage(tmp).free < length + UPLOAD_SPARE:
                raise ApiError(507, "Za mało wolnego miejsca na dysku, żeby przyjąć ten plik.")
            path = os.path.join(tmp, fname)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            remaining = length
            with os.fdopen(fd, "wb") as fh:
                self._continue()
                while remaining > 0:
                    try:
                        chunk = self.rfile.read(min(CHUNK, remaining))
                    except OSError:
                        break
                    if not chunk:
                        break
                    try:
                        fh.write(chunk)
                    except OSError as exc:
                        self.close_connection = True
                        raise ApiError(507, f"Nie udało się zapisać wysłanego pliku: {exc.strerror or exc}") from None
                    remaining -= len(chunk)
            if remaining:
                self.close_connection = True
                raise ApiError(400, f"Połączenie zerwane w trakcie wysyłania (odebrano {length - remaining} "
                                    f"z {length} bajtów).")
            self._body_read = True
        except BaseException:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)
            raise
        finally:
            self.server.upload_sem.release()
        ai, notes = self._ai(ai_req, False)
        self._submit(Job("sandbox", ["sandbox", path, *self._flags(ai)],
                         {"path": path, "filename": fname, "size": length, "uploaded": True, "ai": ai},
                         notes, cleanup_dir=tmp))

    def _remote(self, command: str, hosts: tuple[str, ...], short: re.Pattern, base: str) -> None:
        data = self._json_body(("url", "ai"))
        url = _http_url(data.get("url"), "url", hosts, short, base)
        ai, notes = self._ai(_opt_bool(data.get("ai"), "ai"), False)
        self._submit(Job(command, [command, url, *self._flags(ai)], {"url": url, "ai": ai}, notes))

    def h_github(self) -> None:
        self._remote("github", GITHUB_HOSTS, GITHUB_SHORT, "https://github.com/")

    def h_huggingface(self) -> None:
        self._remote("huggingface", HF_HOSTS, HF_SHORT, "https://huggingface.co/")

    def h_url(self) -> None:
        data = self._json_body(("url", "ai"))
        url = _http_url(data.get("url"), "url")
        ai, notes = self._ai(_opt_bool(data.get("ai"), "ai"), False)
        self._submit(Job("url", ["url", url, *self._flags(ai)], {"url": url, "ai": ai}, notes))

    def h_laptop(self) -> None:
        data = self._json_body(("level", "ai"))
        level = data.get("level", "deep")
        if level not in LEVELS:
            raise ApiError(400, f"Pole „level” musi mieć jedną z wartości: {', '.join(LEVELS)}.")
        ai, notes = self._ai(_opt_bool(data.get("ai"), "ai"), level == "mega")
        self._submit(Job("laptop", ["laptop", "--level", level, *self._flags(ai)], {"level": level, "ai": ai},
                         notes))

    def h_ai_install(self) -> None:
        self._json_body(())
        sched = self.server.scheduler
        existing = sched.active("ai-install")
        if existing is not None:
            links = self._links(existing.id)
            self._send_json(202, {"job": sched.describe(existing), "links": links,
                                  "note": "Instalacja modelu AI już trwa – zwrócono istniejące zadanie."},
                            {"Location": links["status"]})
            return
        self._submit(Job("ai-install", ["ai-install"], {}))

    def h_jobs(self) -> None:
        state = (self.query.get("state") or [None])[-1]
        if state is not None and state not in ("queued", "running", *TERMINAL):
            raise ApiError(400, "Parametr „state” musi być jednym z: queued, running, done, failed, cancelled.")
        self._send_json(200, self.server.scheduler.listing(state))

    def h_job(self, jid: str) -> None:
        sched = self.server.scheduler
        job = sched.get(jid)
        self._send_json(200, {"job": sched.describe(job, detail=True), "links": self._links(jid)})

    def h_cancel(self, jid: str) -> None:
        data = self._json_body(("force",))
        force = bool(_opt_bool(data.get("force"), "force"))
        sched = self.server.scheduler
        job = sched.get(jid)
        how = sched.cancel(job, force)
        if how == "finished":
            raise ApiError(409, f"Zadanie już się zakończyło (stan: {job.state}).", job=sched.describe(job))
        note = {"dequeued": "Zadanie usunięto z kolejki.",
                "pending": "Zadanie właśnie startuje – zostanie przerwane zaraz po uruchomieniu.",
                "signalled": "Wysłano sygnał przerwania – skaner kończy pracę i zapisuje częściowe wyniki; bez "
                             "reakcji zostanie zatrzymany siłą (SIGTERM po 20 s, potem SIGKILL)."}[how]
        self._send_json(200 if how == "dequeued" else 202,
                        {"job": sched.describe(job, detail=True), "cancel": how, "note": note})

    def _from_index(self) -> int:
        raw = (self.query.get("from") or ["0"])[-1].strip()
        last = self.headers.get("Last-Event-ID")
        if last is not None and last.strip().isdigit() and "from" not in self.query:
            return int(last.strip()) + 1
        if not raw.isdigit():
            raise ApiError(400, "Parametr „from” musi być liczbą całkowitą ≥ 0.")
        return int(raw)

    def h_events(self, jid: str) -> None:
        job = self.server.scheduler.get(jid)
        start = self._from_index()
        follow = _query_bool(self.query, "follow")
        if not follow:
            with job.cond:
                lines = job.lines[start:]
                state = job.state
                nxt = start + len(lines) if start <= len(job.lines) else len(job.lines)
            self._send(200, b"".join(lines), "application/x-ndjson; charset=utf-8",
                       {"X-Cerber-Next": str(nxt), "X-Cerber-Job-State": state})
            return
        self._stream(job, start, "application/x-ndjson; charset=utf-8",
                     lambda i, ln: ln, keepalive=None, end=None)

    def h_stream(self, jid: str) -> None:
        job = self.server.scheduler.get(jid)
        start = self._from_index()

        def end() -> bytes:
            d = job.public()
            return b"event: end\ndata: " + _dumps({"state": d["state"], "verdict": d["verdict"],
                                                    "error": d["error"]}).rstrip(b"\n") + b"\n\n"
        self._stream(job, start, "text/event-stream; charset=utf-8",
                     lambda i, ln: b"id: %d\ndata: %s\n\n" % (i, ln.rstrip(b"\n")),
                     keepalive=b": ping\n\n", end=end, prelude=b"retry: 3000\n\n")

    def _stream(self, job: Job, start: int, ctype: str, fmt, keepalive: bytes | None, end,
                prelude: bytes = b"") -> None:
        srv = self.server
        with srv.streams_lock:
            srv.streams += 1
        try:
            self._stream_body(job, start, ctype, fmt, keepalive, end, prelude)
        finally:
            with srv.streams_lock:
                srv.streams -= 1

    def _stream_body(self, job: Job, start: int, ctype: str, fmt, keepalive: bytes | None, end,
                     prelude: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("X-Accel-Buffering", "no")
        self._common_headers()
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        self._headers_sent = True
        if prelude:
            self._chunk(prelude)
        idx = start
        last = time.monotonic()
        while True:
            with job.cond:
                if idx >= len(job.lines) and not job.terminal:
                    job.cond.wait(timeout=1.0)
                batch = job.lines[idx:]
                terminal = job.terminal
            if batch:
                self._chunk(b"".join(fmt(idx + k, ln) for k, ln in enumerate(batch)))
                idx += len(batch)
                last = time.monotonic()
            if terminal:
                break
            if not batch:
                if self._client_gone():
                    return
                if keepalive and time.monotonic() - last >= KEEPALIVE:
                    self._chunk(keepalive)
                    last = time.monotonic()
        if end is not None:
            self._chunk(end())
        self.wfile.write(b"0\r\n\r\n")

    def _chunk(self, data: bytes) -> None:
        if data:
            self.wfile.write(b"%X\r\n%s\r\n" % (len(data), data))

    def _client_gone(self) -> bool:
        try:
            r, _, _ = select.select([self.connection], [], [], 0)
            return bool(r) and self.connection.recv(1, socket.MSG_PEEK) == b""
        except (OSError, ValueError):
            return True

    def h_report(self, jid: str) -> None:
        job = self.server.scheduler.get(jid)
        with job.cond:
            s, state = job.summary, job.state
        if s is None:
            raise ApiError(404, f"Raport będzie dostępny po zakończeniu skanu (stan zadania: {state}).")
        self._send_report(s, f"cerber-{jid}")

    def _send_report(self, src: dict, name: str) -> None:
        as_json = (self.query.get("format") or ["html"])[-1].lower() == "json"
        key, ext = ("report_json", ".json") if as_json else ("report_html", ".html")
        path = src.get(key)
        if not isinstance(path, str) or not path or not path.endswith(ext) or "\x00" in path:
            raise ApiError(404, "Ten skan nie zapisał raportu.")
        # only Cerber's own reports folder: a history entry or event naming another file (e.g. a planted
        # report JSON pointing at a private file) must not turn the API into a file reader
        real = os.path.realpath(path)
        bases = [os.path.realpath(REPORTS)]
        if os.environ.get("CERBER_API_BACKEND"):          # test/dev backend (app/mock_backend.py writes here)
            bases.append(os.path.realpath(os.path.join(tempfile.gettempdir(), "cerber-mock-reports")))
        if not any(real.startswith(b + os.sep) for b in bases):
            raise ApiError(404, "Raport spoza katalogu raportów Cerbera – odmowa.")
        try:
            fh = os.fdopen(os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb")
        except OSError:
            raise ApiError(404, "Plik raportu nie istnieje (mógł zostać usunięty).") from None
        with fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise ApiError(404, "Plik raportu nie istnieje.")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8" if as_json else "text/html; charset=utf-8")
            self.send_header("Content-Length", str(st.st_size))
            self.send_header("Content-Disposition", f'inline; filename="{name}{ext}"')
            self._common_headers(JSON_CSP if as_json else REPORT_CSP)
            if self._unread_body():
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self._headers_sent = True
            shutil.copyfileobj(fh, self.wfile, CHUNK)


# ------------------------------------------------------------------ docs page

def docs_html(base: str) -> str:
    a = '-H "$AUTH"'
    j = "-H 'Content-Type: application/json'"
    eps = [
        ("GET", "/api/info", "Stan baz sygnatur i modelu AI (zdarzenie <code>info</code>).",
         f"curl -s {a} $API/api/info"),
        ("GET", "/api/history", "Lista raportów z wcześniejszych skanów (zdarzenie <code>history</code>).",
         f"curl -s {a} $API/api/history"),
        ("GET", "/api/history/{id}/report", "Raport HTML skanu z historii (<code>?format=json</code> – raport JSON).",
         f"curl -s {a} -o raport.html $API/api/history/gui-20261006-101500/report"),
        ("POST", "/api/scan", "Skan plików/folderów na miejscu (tryby „Plik lub folder” i „Lokalizacja”). "
         "Opcjonalne pole <code>ai</code> (domyślnie false) – dodatkowa analiza lokalnym modelem AI plików "
         "z szarej strefy (działa, gdy model jest zainstalowany; dotyczy też sandbox/github/huggingface/url).",
         f"curl -s {a} {j} -d '{{\"paths\": [\"/Users/ja/Downloads\"], \"ai\": true}}' $API/api/scan"),
        ("POST", "/api/sandbox", "Archiwum leżące na dysku – rozpakowanie i skan w izolowanym sandboksie.",
         f"curl -s {a} {j} -d '{{\"path\": \"/Users/ja/Downloads/archiwum.zip\"}}' $API/api/sandbox"),
        ("POST", "/api/sandbox/upload?filename=x.zip", "Wysłanie pliku (surowa treść żądania, do 4 GB) i skan "
         "w sandboksie. Plik trafia do prywatnego katalogu tymczasowego (0700) i jest usuwany po zadaniu. "
         "Opcjonalnie <code>&amp;ai=false</code>.",
         f"curl -s {a} -H 'Content-Type: application/octet-stream' --data-binary @archiwum.zip "
         "\"$API/api/sandbox/upload?filename=archiwum.zip\""),
        ("POST", "/api/github", "Publiczne repozytorium GitHub (pobranie archiwum i skan w sandboksie).",
         f"curl -s {a} {j} -d '{{\"url\": \"https://github.com/psf/requests\"}}' $API/api/github"),
        ("POST", "/api/huggingface", "Model, zbiór danych albo Space z Hugging Face.",
         f"curl -s {a} {j} -d '{{\"url\": \"https://huggingface.co/org/model\"}}' $API/api/huggingface"),
        ("POST", "/api/url", "„Sprawdź link” – rozpoznanie adresu i pobranie wskazanych plików w sandboksie.",
         f"curl -s {a} {j} -d '{{\"url\": \"https://example.com/plik.zip\"}}' $API/api/url"),
        ("POST", "/api/laptop", "Skan komputera: <code>level</code> = quick | patterns | deep | mega "
         "(domyślnie deep; deep i mega trwają godzinami; mega zawsze z AI, jeśli model jest dostępny, "
         "dla pozostałych opcjonalnie <code>\"ai\": true</code>).",
         f"curl -s {a} {j} -d '{{\"level\": \"quick\"}}' $API/api/laptop"),
        ("POST", "/api/quarantine", "Przeniesienie jednego pliku do kwarantanny Cerbera (od razu, bez kolejki).",
         f"curl -s {a} {j} -d '{{\"path\": \"/Users/ja/Downloads/podejrzany.sh\"}}' $API/api/quarantine"),
        ("POST", "/api/ai-install", "Pobranie lokalnego modelu AI (~4,2 GB, wznawialne). Działa równolegle ze skanem.",
         f"curl -s -X POST {a} $API/api/ai-install"),
        ("GET", "/api/jobs", "Lista zadań (najnowsze pierwsze; opcjonalnie <code>?state=running</code>).",
         f"curl -s {a} $API/api/jobs"),
        ("GET", "/api/jobs/{id}", "Stan zadania: etap, ostatni postęp, liczba znalezisk, a po zakończeniu "
         "pełne podsumowanie (<code>summary</code>).", f"curl -s {a} $API/api/jobs/ID"),
        ("GET", "/api/jobs/{id}/events?from=N", "Zdarzenia od numeru N jako NDJSON (jedna linia = jedno "
         "zdarzenie). Nagłówek <code>X-Cerber-Next</code> podaje numer następnego. <code>&amp;follow=1</code> "
         "utrzymuje połączenie i dosyła nowe zdarzenia do końca zadania.",
         f"curl -sN {a} \"$API/api/jobs/ID/events?from=0&follow=1\""),
        ("GET", "/api/jobs/{id}/stream", "To samo jako Server-Sent Events (<code>id:</code> = numer zdarzenia, "
         "na końcu <code>event: end</code>; obsługuje <code>Last-Event-ID</code>).",
         f"curl -sN {a} $API/api/jobs/ID/stream"),
        ("POST", "/api/jobs/{id}/cancel", "Anulowanie: z kolejki od razu; uruchomione dostaje SIGINT (częściowe "
         "wyniki), po 20 s SIGTERM. Ponowne wywołanie albo <code>{\"force\": true}</code> – od razu SIGTERM.",
         f"curl -s -X POST {a} $API/api/jobs/ID/cancel"),
        ("GET", "/api/jobs/{id}/report", "Raport HTML skanu (404 do czasu zakończenia; "
         "<code>?format=json</code> – raport JSON).", f"curl -s {a} -o raport.html $API/api/jobs/ID/report"),
    ]
    rows = "\n".join(
        f"<section><h3><span class=m>{m}</span> <code>{html.escape(p)}</code></h3><p>{d}</p>"
        f"<pre>{html.escape(c)}</pre></section>" for m, p, d, c in eps)
    b = html.escape(base)
    return f"""<!doctype html>
<html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cerber API</title>
<style>
:root{{--bg:#fbfbfd;--fg:#1d1d1f;--mut:#6e6e73;--card:#fff;--line:#e3e3e8;--acc:#b3261e;--code:#f2f2f5}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151517;--fg:#f2f2f5;--mut:#a1a1a6;--card:#1d1d20;--line:#333338;--acc:#ff6b5f;--code:#26262a}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;padding:24px 16px}}
main{{max-width:880px;margin:0 auto}}h1{{margin:0 0 4px}}h2{{margin-top:36px;border-bottom:1px solid var(--line);padding-bottom:6px}}
h3{{font-size:15px;margin:0 0 4px}}.m{{color:var(--acc);font-weight:700}}.sub{{color:var(--mut);margin-top:0}}
section{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:10px 0}}
section p{{margin:2px 0 8px}}code{{background:var(--code);padding:1px 5px;border-radius:5px;font:13px ui-monospace,Menlo,monospace}}
pre{{background:var(--code);padding:10px 12px;border-radius:8px;overflow-x:auto;font:13px/1.45 ui-monospace,Menlo,monospace;margin:0;white-space:pre-wrap;word-break:break-all}}
li{{margin:4px 0}}
</style></head><body><main>
<h1>Cerber – lokalne API</h1>
<p class="sub">Działa pod adresem <code>{b}</code> – tylko na tym komputerze.</p>

<h2>Co to jest</h2>
<p>To API udostępnia wszystko, co potrafi aplikacja Cerber: skan plików i folderów, skan archiwum
w izolowanym sandboksie (także wysłanego przez API), repozytoria GitHub i Hugging Face, sprawdzanie linku,
skan całego laptopa (poziomy quick, patterns, deep, mega), kwarantannę, historię raportów i instalację
lokalnego modelu AI. Każde polecenie uruchamia ten sam backend co aplikacja
(<code>python -m cerber.gui_backend</code>), więc zdarzenia i podsumowania są identyczne jak w aplikacji
(opis formatu: <code>app/PROTOCOL.md</code>).</p>
<p>Skany są ciężkie (kilka GB pamięci), dlatego trafiają do kolejki i wykonują się po kolei, jeden naraz.
Instalacja modelu AI ma osobną kolejkę i może trwać równolegle ze skanem. <code>info</code>,
<code>history</code> i <code>quarantine</code> odpowiadają od razu. Zadanie ma stan
<code>queued</code> → <code>running</code> → <code>done</code> / <code>failed</code> / <code>cancelled</code>.
Serwer pamięta ostatnie 100 zadań (tylko w pamięci, do zamknięcia).</p>

<h2>Uruchomienie i token</h2>
<pre>cd {html.escape(ROOT)}
.venv/bin/python -m cerber.api_server            # opcje: --port 8765  --token …</pre>
<p>Przy starcie serwer wypisuje na standardowe wyjście <b>jedną linię JSON</b>
<code>{{"ev": "api_ready", "url": …, "token": …, "docs": …}}</code>. <b>Token znajdziesz w polu
<code>token</code> tej linii</b> – w terminalu, w którym uruchomiono serwer. Token jest losowy przy każdym
uruchomieniu, nie jest zapisywany na dysku i celowo nie ma go na tej stronie. Stały token można podać w
zmiennej środowiskowej <code>CERBER_API_TOKEN</code> (bezpieczniej niż <code>--token</code>, które widać
w liście procesów). Jeśli port jest zajęty, serwer próbuje kolejnych 10 portów – właściwy adres jest
w polu <code>url</code>. Ctrl+C (SIGINT) lub SIGTERM zamyka serwer: anuluje zadania i zatrzymuje ich procesy.</p>
<p>Każde żądanie do <code>/api/…</code> musi mieć nagłówek <code>Authorization: Bearer &lt;token&gt;</code>
(albo <code>X-Cerber-Token: &lt;token&gt;</code>). Przykłady poniżej zakładają:</p>
<pre>export CERBER_TOKEN='…token z linii api_ready…'
API={b}
AUTH="Authorization: Bearer $CERBER_TOKEN"</pre>

<h2>Endpointy</h2>
<p>Dane wejściowe i wyjściowe to JSON (UTF-8). Ścieżki muszą być bezwzględne i istnieć; adresy – tylko
http(s). Polecenia skanujące odpowiadają <code>202</code> z obiektem <code>job</code> i linkami
(<code>links.status</code>, <code>events</code>, <code>stream</code>, <code>cancel</code>,
<code>report</code>).</p>
{rows}

<h2>Błędy</h2>
<p>Każdy błąd to JSON <code>{{"error": "opis po polsku"}}</code> z kodem HTTP: 400 – złe dane,
401 – brak/zły token, 403 – odrzucony nagłówek Host/Origin, 404 – brak zasobu (albo raport jeszcze nie
gotowy), 405 – zła metoda, 409 – zadanie już zakończone, 411/413/415 – brak długości, za duża treść,
zły Content-Type, 422 – backend odmówił (np. kwarantanna pliku systemowego), 429 – pełna kolejka,
503 – serwer się zamyka, 507 – brak miejsca na dysku.</p>

<h2>Bezpieczeństwo</h2>
<ul>
<li>Serwer nasłuchuje wyłącznie na <code>127.0.0.1</code> – nie jest dostępny z sieci (inne adresy są odrzucane).</li>
<li>Kto zna token, może uruchamiać skany i przenosić pliki do kwarantanny na Twoim koncie – nie udostępniaj go.</li>
<li>Strony internetowe otwarte w przeglądarce nie mogą sterować API: brak nagłówków CORS, odrzucane są
żądania z obcym nagłówkiem <code>Origin</code> lub <code>Sec-Fetch-Site: cross-site</code>, nagłówek
<code>Host</code> musi być <code>127.0.0.1:PORT</code> lub <code>localhost:PORT</code> (ochrona przed
DNS rebinding), a polecenia JSON wymagają <code>Content-Type: application/json</code> (zwykły formularz
HTML ich nie wyśle).</li>
<li>Dane wejściowe są sprawdzane i przekazywane do skanera jako lista argumentów – nigdy przez powłokę.</li>
<li>Wszystkie skany działają w sandboksie, tak jak w aplikacji. Raporty HTML są serwowane z polityką CSP
<code>sandbox</code> (bez skryptów).</li>
<li>Serwer nic nie instaluje, nie startuje sam przy logowaniu i kończy pracę po Ctrl+C. Żądania są logowane
na stderr (metoda, ścieżka, kod – bez tokenu).</li>
</ul>
</main></body></html>
"""


# ------------------------------------------------------------------ main

def _port_in_use(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def _bind(port: int) -> Server:
    ports = [0] if port == 0 else list(range(port, min(port + PORT_TRIES, 65535) + 1))
    last: Exception | None = None
    for p in ports:
        if p and _port_in_use(p):
            last = OSError(f"port {p} jest zajęty")
            continue
        try:
            return Server(("127.0.0.1", p), Handler)
        except OSError as exc:
            last = exc
    raise OSError(f"Nie udało się otworzyć portu {ports[0]}–{ports[-1]}: {last}")


def _fatal(msg: str, code: int = 1) -> int:
    print(json.dumps({"ev": "error", "fatal": True, "msg": msg}, ensure_ascii=False), flush=True)
    _log(msg)
    return code


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m cerber.api_server",
                                 description="Lokalne API Cerbera (tylko 127.0.0.1, wymaga tokenu).")
    ap.add_argument("--host", default="127.0.0.1", help="tylko 127.0.0.1 lub localhost")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="port (zajęty → kolejne 10; 0 = dowolny wolny)")
    ap.add_argument("--token", default=None, help="stały token (lepiej: zmienna CERBER_API_TOKEN)")
    a = ap.parse_args(argv)
    if a.host.strip().lower() not in ("127.0.0.1", "localhost"):
        return _fatal(f"Odmowa: API Cerbera może nasłuchiwać tylko na 127.0.0.1 (podano: {a.host}). "
                      "Udostępnianie w sieci nie jest obsługiwane.", 2)
    if not 0 <= a.port <= 65535:
        return _fatal(f"Nieprawidłowy port: {a.port}", 2)
    token = a.token or os.environ.get("CERBER_API_TOKEN") or secrets.token_urlsafe(32)
    if not TOKEN_RE.match(token):
        return _fatal("Token musi mieć 16–512 znaków: litery, cyfry i - _ . ~ + / =", 2)
    try:
        server = _bind(a.port)
    except OSError as exc:
        return _fatal(str(exc))
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    server.token = token
    server.base_url = base
    server.allowed_hosts = frozenset({f"127.0.0.1:{port}", f"localhost:{port}"})
    server.allowed_origins = frozenset({f"http://127.0.0.1:{port}", f"http://localhost:{port}"})
    server.upload_sem = threading.BoundedSemaphore(MAX_PARALLEL_UPLOADS)
    server.scheduler = Scheduler(backend_command(), backend_env())

    stop = threading.Event()

    def on_signal(signum, _frame) -> None:
        if stop.is_set():
            server.scheduler.force.set()        # second Ctrl+C: kill now
        stop.set()
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.5}, name="cerber-api-http",
                         daemon=True)
    t.start()
    print(json.dumps({"ev": "api_ready", "url": base, "token": token, "docs": base + "/"}), flush=True)
    _log(f"API Cerbera działa: {base}/ (opis). Token jest w linii api_ready na stdout. Ctrl+C kończy.")
    try:
        while not stop.wait(0.5):
            pass
    except KeyboardInterrupt:
        pass
    _log("zamykanie: anulowanie zadań…")
    server.scheduler.shutdown()
    end = time.monotonic() + 3.0                # let open event streams deliver the final events
    while server.streams and time.monotonic() < end:
        time.sleep(0.05)
    server.shutdown()
    server.server_close()
    _log("zamknięto")
    return 0


if __name__ == "__main__":
    _rc = main()
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.flush()
        except (OSError, ValueError):
            pass
    os._exit(_rc)       # all jobs are finished; skip interpreter teardown racing with idle daemon threads

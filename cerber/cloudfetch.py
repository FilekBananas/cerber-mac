"""Mega: download risky cloud-only files (iCloud Drive / File Provider placeholders), scan them, give them back.

Everywhere else Cerber refuses to touch placeholders (cerber/dataless.py) – listing the cloud would pull the whole
of it onto the disk. Mega's walk instead remembers the risky ones (`dataless.cloud_rank`: programs, scripts,
installers, archives, documents with active content) and the folders it could not list. This module:

  1. lists those folders (names only) – a few minutes at most,
  2. downloads the chosen files, most dangerous kinds and smallest first, within a count/size/time budget,
  3. after the sandboxed scan, evicts the copies it downloaded so they are cloud-only again.

The downloads happen in a tiny helper process – the only Cerber process with materialization switched back on.
It opens each file and reads ONE byte (that is what makes macOS fetch it); the content is never parsed outside the
scan sandbox, so a malicious file gains nothing from being downloaded.
"""
from __future__ import annotations

import json
import os
import queue
import stat
import subprocess
import sys
import threading
import time
from typing import Callable

from . import config
from .dataless import allow_materialize, cloud_rank, is_dataless

FETCH_MAX_FILES = 1500
FETCH_MAX_BYTES = 3 << 30           # 3 GB downloaded at most
FETCH_MAX_FILE = 512 << 20
FETCH_BUDGET_S = 30 * 60
LIST_MAX_DIRS = 3000
LIST_BUDGET_S = 5 * 60
LIST_MAX_ENTRIES = 20000            # per folder
LOCAL_MAX = 5000                    # files already on disk found in folders the walk could not list
STALL_LIMIT = 3                     # consecutive timeouts → the cloud is not answering, stop downloading

Progress = Callable[[int, int, str], None]


# ------------------------------------------------------------------ helper process (materialization on)

def _open(path: str) -> dict:
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        return {"ok": False, "err": "nie jest zwykłym plikiem"}
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.read(fd, 1)                   # makes macOS download the whole file; the byte itself is ignored
        st = os.fstat(fd)
    finally:
        os.close(fd)
    return {"ok": not is_dataless(st), "size": st.st_size}


def _list(path: str) -> dict:
    entries = []
    with os.scandir(path) as it:
        for e in it:
            if len(entries) >= LIST_MAX_ENTRIES:
                break
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            kind = "d" if stat.S_ISDIR(st.st_mode) else "f" if stat.S_ISREG(st.st_mode) else "o"
            entries.append([e.name, kind, is_dataless(st), st.st_size, st.st_mode])
    return {"ok": True, "entries": entries}


_objc: dict = {}


def _evict(path: str) -> dict:
    """NSFileManager -evictUbiquitousItemAtURL:error: through the Objective-C runtime (no PyObjC needed)."""
    import ctypes
    from ctypes import POINTER, c_bool, c_char_p, c_void_p
    if not _objc:
        lib = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
        ctypes.CDLL("/System/Library/Frameworks/Foundation.framework/Foundation")
        lib.objc_getClass.restype, lib.objc_getClass.argtypes = c_void_p, [c_char_p]
        lib.sel_registerName.restype, lib.sel_registerName.argtypes = c_void_p, [c_char_p]
        lib.objc_autoreleasePoolPush.restype = c_void_p
        lib.objc_autoreleasePoolPop.argtypes = [c_void_p]
        addr = ctypes.cast(lib.objc_msgSend, c_void_p).value
        _objc.update(lib=lib, id=ctypes.CFUNCTYPE(c_void_p, c_void_p, c_void_p)(addr),
                     id_str=ctypes.CFUNCTYPE(c_void_p, c_void_p, c_void_p, c_char_p)(addr),
                     id_id=ctypes.CFUNCTYPE(c_void_p, c_void_p, c_void_p, c_void_p)(addr),
                     cstr=ctypes.CFUNCTYPE(c_char_p, c_void_p, c_void_p)(addr),
                     evict=ctypes.CFUNCTYPE(c_bool, c_void_p, c_void_p, c_void_p, POINTER(c_void_p))(addr))
    o = _objc
    lib = o["lib"]

    def sel(name: bytes) -> int:
        return lib.sel_registerName(name)

    pool = lib.objc_autoreleasePoolPush()
    try:
        s = o["id_str"](lib.objc_getClass(b"NSString"), sel(b"stringWithUTF8String:"), path.encode())
        url = o["id_id"](lib.objc_getClass(b"NSURL"), sel(b"fileURLWithPath:"), s)
        fm = o["id"](lib.objc_getClass(b"NSFileManager"), sel(b"defaultManager"))
        err = c_void_p()
        ok = o["evict"](fm, sel(b"evictUbiquitousItemAtURL:error:"), url, ctypes.byref(err))
        msg = None
        if not ok and err.value:
            desc = o["id"](err.value, sel(b"localizedDescription"))
            raw = o["cstr"](desc, sel(b"UTF8String")) if desc else None
            msg = raw.decode("utf-8", "replace")[:200] if raw else "nieznany błąd"
        return {"ok": bool(ok), "err": msg}
    finally:
        lib.objc_autoreleasePoolPop(pool)


def serve() -> int:
    """`python -m cerber.cloudfetch serve`: one JSON request per stdin line → one JSON answer per stdout line."""
    allow_materialize()
    for line in sys.stdin:
        try:
            req = json.loads(line)
            op, path = req["op"], req["path"]
            if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
                raise ValueError("zła ścieżka")
            out = {"open": _open, "list": _list, "evict": _evict}[op](path)
        except Exception as exc:  # noqa: BLE001 - every request gets an answer
            out = {"ok": False, "err": (getattr(exc, "strerror", None) or repr(exc))[:200]}
        sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    return 0


# ------------------------------------------------------------------ client

class Helper:
    """Talks to the helper; a request that does not finish in time kills it (the next one starts a new one)."""

    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.q: queue.Queue | None = None

    def _start(self) -> None:
        py = os.path.join(config.ROOT, ".venv", "bin", "python")
        self.proc = subprocess.Popen([py if os.access(py, os.X_OK) else sys.executable, "-m", "cerber.cloudfetch",
                                      "serve"], cwd=config.ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.q = q = queue.Queue()

        def read(fh) -> None:
            for ln in fh:
                q.put(ln)
            q.put(None)
        threading.Thread(target=read, args=(self.proc.stdout,), daemon=True, name="cerber-cloudfetch").start()

    def call(self, op: str, path: str, timeout: float) -> dict | None:
        if self.proc is None or self.proc.poll() is not None:
            self._start()
        try:
            self.proc.stdin.write(json.dumps({"op": op, "path": path}, ensure_ascii=False) + "\n")
            self.proc.stdin.flush()
            line = self.q.get(timeout=timeout)
        except (OSError, queue.Empty):
            line = None
        if line is None:
            self.close()
            return None
        try:
            return json.loads(line)
        except ValueError:
            return None

    def close(self) -> None:
        p, self.proc = self.proc, None
        if p is None:
            return
        try:
            p.stdin.close()
        except OSError:
            pass
        try:
            p.wait(2)
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                pass

    def __enter__(self) -> "Helper":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def _expand(helper: Helper, dirs: list[str], files: list, local: list[str], st: dict, cancel: threading.Event,
            progress: Progress) -> None:
    """Folders the walk could not list (their listing lives in the cloud): list them, breadth-first."""
    todo = list(dirs)
    t0 = time.time()
    while todo and st["dirs_listed"] < LIST_MAX_DIRS and time.time() - t0 < LIST_BUDGET_S and not cancel.is_set():
        d = todo.pop(0)
        progress(st["dirs_listed"], st["dirs_listed"] + len(todo) + 1, "folder: " + os.path.basename(d))
        res = helper.call("list", d, timeout=60)
        if not res or not res.get("ok"):
            st["dirs_failed"] += 1
            continue
        st["dirs_listed"] += 1
        for name, kind, dataless, size, mode in res.get("entries") or []:
            if not isinstance(name, str) or "/" in name or name in (".", ".."):
                continue
            p = d.rstrip("/") + "/" + name
            if kind == "d":
                todo.append(p)
            elif kind == "f":
                if not dataless:
                    if size and len(local) < LOCAL_MAX:
                        local.append(p)
                elif (rank := cloud_rank(p, mode)) is not None:
                    files.append([p, size, rank])
    st["dirs_left"] = len(todo)


def fetch(files: list, dirs: list[str], cancel: threading.Event, progress: Progress,
          log: Callable[[str], None], max_file: int = FETCH_MAX_FILE) -> dict:
    """→ {"fetched": [downloaded now], "local": [already on disk, never scanned], "stats": {...}}."""
    st = {"candidates": 0, "fetched": 0, "bytes": 0, "failed": 0, "too_big": 0, "over_limit": 0,
          "dirs_listed": 0, "dirs_failed": 0, "dirs_left": 0, "stalled": False, "kinds": {}}
    files = [f for f in files if isinstance(f, list) and len(f) == 3 and isinstance(f[0], str)]
    local: list[str] = []
    fetched: list[str] = []
    with Helper() as helper:
        if dirs:
            _expand(helper, dirs, files, local, st, cancel, progress)
            if st["dirs_listed"]:
                log(f"Chmura: odczytano listę {st['dirs_listed']} folderów, których nie było na dysku")
        seen: set[str] = set()
        plan = []
        planned = 0
        for p, size, rank in sorted(files, key=lambda f: (f[2], f[1])):     # most dangerous kinds, smallest first
            if p in seen:
                continue
            seen.add(p)
            if size > max_file:
                st["too_big"] += 1
            elif len(plan) >= FETCH_MAX_FILES or planned + size > FETCH_MAX_BYTES:
                st["over_limit"] += 1
            else:
                plan.append((p, size, rank))
                planned += size
        st["candidates"] = len(seen)
        if plan:
            log(f"Chmura: pobieranie {len(plan)} ryzykownych plików (programy, skrypty, instalatory, archiwa, "
                f"dokumenty z aktywną treścią) do skanu – potem wrócą tylko do chmury")
        t0 = time.time()
        stalls = 0
        for i, (p, size, rank) in enumerate(plan):
            if cancel.is_set() or time.time() - t0 > FETCH_BUDGET_S:
                st["over_limit"] += len(plan) - i
                break
            progress(i, len(plan), os.path.basename(p))
            res = helper.call("open", p, timeout=min(900.0, 60 + size / 1_000_000))
            if res is None:
                stalls += 1
                st["failed"] += 1
                if stalls >= STALL_LIMIT:
                    st["stalled"] = True
                    st["over_limit"] += len(plan) - i - 1
                    log("Chmura nie odpowiada (kilka pobrań bez skutku) – pozostałe pliki zostają w chmurze")
                    break
                continue
            stalls = 0
            if res.get("ok"):
                fetched.append(p)
                st["fetched"] += 1
                st["bytes"] += size
                kind = ("programy i skrypty", "instalatory i archiwa", "dokumenty")[rank]
                st["kinds"][kind] = st["kinds"].get(kind, 0) + 1
            else:
                st["failed"] += 1
        progress(len(plan), len(plan), "")
    st["local"] = len(local)
    return {"fetched": fetched, "local": local, "stats": st}


def evict(paths: list[str], log: Callable[[str], None] = lambda m: None) -> int:
    """Hand downloaded copies back to the cloud. Best effort: returns how many are cloud-only again."""
    n = 0
    if not paths:
        return 0
    with Helper() as helper:
        for p in paths:
            res = helper.call("evict", p, timeout=30)
            if res and res.get("ok"):
                n += 1
    if n < len(paths):
        log(f"Chmura: {len(paths) - n} pobranych plików zostaje na dysku (macOS odda je do chmury, gdy zabraknie "
            f"miejsca; w Finderze: prawy klik → „Usuń pobrany plik”)")
    return n


if __name__ == "__main__":
    if sys.argv[1:] == ["serve"]:
        raise SystemExit(serve())
    raise SystemExit("użycie: python -m cerber.cloudfetch serve")

"""Quarantine: move a detected file into an inert, obfuscated container and restore it on demand."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
import uuid

from . import config

MAGIC = b"CERBERQ1"
QID_RE = re.compile(r"^[0-9a-f]{16}$")
_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


def _qid(qid: str) -> str:
    """Quarantine ids are 16 hex digits – anything else (../, /, NUL) never reaches a path."""
    if not isinstance(qid, str) or not QID_RE.match(qid):
        raise ValueError(f"nieprawidłowy identyfikator kwarantanny: {qid!r}")
    return qid


def _write_new(path: str, data: bytes, mode: int = 0o600) -> None:
    """Create `path` (never overwrite, never through a symlink) and write `data`."""
    fd = os.open(path, _CREATE, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except BaseException:
        try:
            os.remove(path)
        except OSError:
            pass
        raise


def _safe_target(target) -> str:
    """Restore destination: absolute, no '..', and no symlink planted by a user process on the way (a fake
    quarantine entry must not let Cerber's Full Disk Access write through a redirect)."""
    if not isinstance(target, str) or not target.startswith("/") or "\x00" in target:
        raise ValueError(f"nieprawidłowa ścieżka przywracania: {target!r}")
    if os.path.normpath(target) != target.rstrip("/") or "/../" in target + "/":
        raise ValueError(f"ścieżka przywracania nie może zawierać „..”: {target}")
    cur = ""
    for comp in target.split("/")[1:-1]:
        cur += "/" + comp
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(st.st_mode) and st.st_uid != 0:      # /tmp, /var, /etc belong to root – fine
            raise ValueError(f"przywracanie przez dowiązanie symboliczne odrzucone: {cur}")
    return target


def _keystream_xor(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    block = 0
    pos = 0
    while pos < len(data):
        ks = hashlib.sha256(key + block.to_bytes(8, "little")).digest()
        chunk = data[pos:pos + 32]
        for i, b in enumerate(chunk):
            out[pos + i] = b ^ ks[i]
        pos += 32
        block += 1
    return bytes(out)


def quarantine_file(path: str, result: dict | None = None) -> str:
    config.ensure_dirs()
    # O_NOFOLLOW: a symlink is never "quarantined" – that would copy the file it points to (possibly one only
    # Cerber's Full Disk Access can read) into the quarantine folder and remove just the link
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if os.path.islink(path):
            raise ValueError(f"to dowiązanie symboliczne, nie plik – nie przenoszę do kwarantanny: {path}") from exc
        raise
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"to nie jest zwykły plik: {path}")
        data = fh.read()
    qid = uuid.uuid4().hex[:16]
    key = os.urandom(16)
    blob = MAGIC + key + _keystream_xor(data, key)
    qpath = os.path.join(config.QUARANTINE, qid + ".cq")
    _write_new(qpath, blob)
    meta = {
        "id": qid, "original_path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "mode": st.st_mode & 0o7777, "quarantined": time.strftime("%Y-%m-%d %H:%M:%S"),
        "verdict": (result or {}).get("verdict"), "primary": (result or {}).get("primary"),
        "detections": [d.get("name") for d in (result or {}).get("detections", [])][:30],
    }
    _write_new(os.path.join(config.QUARANTINE, qid + ".json"), json.dumps(meta, indent=1).encode())
    try:
        os.remove(path)
    except OSError:
        delete(qid)  # e.g. root-owned file in /Applications: don't leave a copy that looks quarantined
        raise
    return qid


def list_quarantine() -> list[dict]:
    if not os.path.isdir(config.QUARANTINE):
        return []
    out = []
    for fn in sorted(os.listdir(config.QUARANTINE)):
        if fn.endswith(".json") and QID_RE.match(fn[:-5]):
            try:
                with open(os.path.join(config.QUARANTINE, fn)) as fh:
                    meta = json.load(fh)
            except (OSError, ValueError):
                continue                              # one damaged entry must not hide the others
            if isinstance(meta, dict):
                out.append(meta)
    return out


def restore(qid: str, dest: str | None = None) -> str:
    _qid(qid)
    with open(os.path.join(config.QUARANTINE, qid + ".json")) as fh:
        meta = json.load(fh)
    with open(os.path.join(config.QUARANTINE, qid + ".cq"), "rb") as fh:
        blob = fh.read()
    if blob[:8] != MAGIC:
        raise ValueError("uszkodzony plik kwarantanny")
    data = _keystream_xor(blob[24:], blob[8:24])
    if hashlib.sha256(data).hexdigest() != meta["sha256"]:
        raise ValueError("suma kontrolna się nie zgadza")
    target = _safe_target(dest or meta.get("original_path"))
    if os.path.lexists(target):
        raise FileExistsError(target)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    _safe_target(target)                              # re-check after creating the parents
    mode = meta.get("mode", 0o644)
    _write_new(target, data, 0o600)                   # O_EXCL|O_NOFOLLOW: never over an existing file or link
    os.chmod(target, (mode if isinstance(mode, int) else 0o644) & 0o666)  # never restore the executable bit
    delete(qid)
    return target


def delete(qid: str) -> None:
    _qid(qid)
    for ext in (".cq", ".json"):
        p = os.path.join(config.QUARANTINE, qid + ext)
        if os.path.exists(p):
            os.remove(p)

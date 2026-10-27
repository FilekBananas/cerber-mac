"""Quarantine: move a detected file into an inert, obfuscated container and restore it on demand."""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid

from . import config

MAGIC = b"CERBERQ1"


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
    with open(path, "rb") as fh:
        data = fh.read()
    st = os.stat(path)
    qid = uuid.uuid4().hex[:16]
    key = os.urandom(16)
    blob = MAGIC + key + _keystream_xor(data, key)
    qpath = os.path.join(config.QUARANTINE, qid + ".cq")
    with open(qpath, "wb") as fh:
        fh.write(blob)
    os.chmod(qpath, 0o600)
    meta = {
        "id": qid, "original_path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "mode": st.st_mode & 0o7777, "quarantined": time.strftime("%Y-%m-%d %H:%M:%S"),
        "verdict": (result or {}).get("verdict"), "primary": (result or {}).get("primary"),
        "detections": [d.get("name") for d in (result or {}).get("detections", [])][:30],
    }
    with open(os.path.join(config.QUARANTINE, qid + ".json"), "w") as fh:
        json.dump(meta, fh, indent=1)
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
        if fn.endswith(".json"):
            with open(os.path.join(config.QUARANTINE, fn)) as fh:
                out.append(json.load(fh))
    return out


def restore(qid: str, dest: str | None = None) -> str:
    with open(os.path.join(config.QUARANTINE, qid + ".json")) as fh:
        meta = json.load(fh)
    with open(os.path.join(config.QUARANTINE, qid + ".cq"), "rb") as fh:
        blob = fh.read()
    if blob[:8] != MAGIC:
        raise ValueError("uszkodzony plik kwarantanny")
    data = _keystream_xor(blob[24:], blob[8:24])
    if hashlib.sha256(data).hexdigest() != meta["sha256"]:
        raise ValueError("suma kontrolna się nie zgadza")
    target = dest or meta["original_path"]
    if os.path.exists(target):
        raise FileExistsError(target)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as fh:
        fh.write(data)
    os.chmod(target, meta.get("mode", 0o644) & 0o666)  # never restore the executable bit automatically
    delete(qid)
    return target


def delete(qid: str) -> None:
    for ext in (".cq", ".json"):
        p = os.path.join(config.QUARANTINE, qid + ext)
        if os.path.exists(p):
            os.remove(p)

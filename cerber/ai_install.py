"""Download the default local AI model (Cisco Foundation-Sec 1.1 8B Instruct, Q4_K_M GGUF – a Llama-3.1-8B
continued-pretrained on security text; Apache-2.0 for Cisco's changes + Llama 3.1 Community License) into
Cerber's own models/ folder. It verifies the engines' accusations (cerber/engines/ai.py). Only on the user's
explicit request (the app's "Pobierz model AI" button / `gui_backend ai-install`) – never automatically.
An older model already on disk (Granite 4.0 H Tiny) keeps working until the new one is there and is never
deleted here.

* resumable (HTTP Range on a .part file), SHA-256 verified against the value published by Hugging Face,
* one download at a time (file lock); a second caller just follows the running download's progress,
* the model is only data for llama-server – nothing downloaded here is executed.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import shutil
import time
import urllib.error
import urllib.request
from typing import Callable

from . import config

REPO = "fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF"          # official Cisco Foundation AI repo
FILE = "foundation-sec-1.1-8b-instruct-q4_k_m.gguf"
LABEL = "Foundation-Sec 1.1 8B"
SIZE = 4920780160
SHA256 = "5813d725b38f0da1eac34486e44b70b0f728c2e2881c96873def69e76f8421ed"    # published by Hugging Face (LFS)
URL = f"https://huggingface.co/{REPO}/resolve/main/{FILE}"
MODELS = os.path.join(config.HOME, "models")
TARGET = os.path.join(MODELS, FILE)
PART = TARGET + ".part"
LOCK = os.path.join(MODELS, ".install.lock")


class InstallError(Exception):
    pass


def llama_server() -> str | None:
    p = os.environ.get("CERBER_LLAMA_SERVER") or shutil.which("llama-server")
    for cand in (p, "/opt/homebrew/bin/llama-server", "/usr/local/bin/llama-server"):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def installed() -> str | None:
    return TARGET if os.path.isfile(TARGET) and os.path.getsize(TARGET) == SIZE else None


def install(emit: Callable[[dict], None], cancel=None) -> str:
    os.makedirs(MODELS, exist_ok=True)
    if installed():
        return TARGET
    if shutil.disk_usage(MODELS).free < SIZE + (2 << 30):
        raise InstallError(f"za mało miejsca na dysku – model potrzebuje {SIZE / 1e9:.1f} GB (+2 GB zapasu)")
    lock = open(LOCK, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return _follow(lock, emit, cancel)
    try:
        return _download(emit, cancel)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


def _follow(lock, emit, cancel) -> str:
    """Another process is downloading: report its progress until it finishes."""
    emit({"ev": "log", "msg": "Model jest już pobierany przez inny proces – śledzę postęp"})
    while True:
        if cancel is not None and cancel.is_set():
            raise InstallError("przerwano")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(lock, fcntl.LOCK_UN)
            break
        except BlockingIOError:
            got = os.path.getsize(PART) if os.path.exists(PART) else 0
            emit({"ev": "progress", "stage": "download", "bytes": got, "total": SIZE})
            time.sleep(1)
    if installed():
        return TARGET
    raise InstallError("pobieranie w drugim procesie nie zakończyło się powodzeniem")


def _download(emit, cancel) -> str:
    h = hashlib.sha256()
    have = os.path.getsize(PART) if os.path.exists(PART) else 0
    if have > SIZE:
        os.remove(PART)
        have = 0
    if have:
        with open(PART, "rb") as fh:          # resume: hash what is already there
            for chunk in iter(lambda: fh.read(8 << 20), b""):
                h.update(chunk)
        emit({"ev": "log", "msg": f"Wznawiam pobieranie od {have / 1e9:.2f} GB"})
    for attempt in range(1, 6):
        try:
            req = urllib.request.Request(URL, headers={"User-Agent": config.USER_AGENT,
                                                       **({"Range": f"bytes={have}-"} if have else {})})
            with urllib.request.urlopen(req, timeout=60) as r, open(PART, "ab") as out:
                if have and r.status != 206:
                    raise InstallError("serwer nie wznowił pobierania")
                last = 0.0
                while True:
                    if cancel is not None and cancel.is_set():
                        raise InstallError("przerwano")
                    chunk = r.read(4 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
                    h.update(chunk)
                    have += len(chunk)
                    if time.time() - last > 0.5:
                        last = time.time()
                        emit({"ev": "progress", "stage": "download", "bytes": have, "total": SIZE})
            break
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            if isinstance(exc, InstallError):
                raise
            emit({"ev": "log", "msg": f"Przerwane połączenie ({exc}) – ponawiam ({attempt}/5)"})
            time.sleep(min(30, 3 * attempt))
    else:
        raise InstallError("nie udało się pobrać modelu po 5 próbach – sprawdź internet i spróbuj ponownie")
    emit({"ev": "progress", "stage": "download", "bytes": have, "total": SIZE})
    if have != SIZE:
        raise InstallError(f"pobrano {have} z {SIZE} bajtów – spróbuj ponownie (pobieranie zostanie wznowione)")
    if h.hexdigest() != SHA256:
        os.remove(PART)
        raise InstallError("suma kontrolna SHA-256 się nie zgadza – plik usunięty, spróbuj ponownie")
    os.replace(PART, TARGET)
    return TARGET

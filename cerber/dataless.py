"""iCloud Drive / File Provider placeholders ("dataless" files and folders).

With "Optimize Mac Storage", iCloud Drive (and Dropbox/Google Drive/OneDrive via File Provider) keep only a
placeholder on disk. Merely listing such a folder or opening such a file makes macOS download it first — a whole-disk
scan would crawl (seconds per folder) and pull the user's entire cloud onto the laptop. A placeholder holds no code
that could run, so scanners skip it and switch materialization off for the whole process (inherited by children).
"""
from __future__ import annotations

import errno
import sys

SF_DATALESS = 0x40000000          # <sys/stat.h>: the content (or folder listing) lives only in the cloud
_IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES = 3
_IOPOL_SCOPE_PROCESS = 0
_IOPOL_MATERIALIZE_DATALESS_FILES_OFF = 1
_IOPOL_MATERIALIZE_DATALESS_FILES_ON = 2
# what the kernel returns when a process with materialization off touches a placeholder
NOT_MATERIALIZED = {errno.EDEADLK}

_state = {"done": False}


def is_dataless(st) -> bool:
    return bool(getattr(st, "st_flags", 0) & SF_DATALESS)


def never_materialize() -> bool:
    """Process-wide: touching a cloud-only item fails fast instead of downloading it. Idempotent."""
    if _state["done"] or sys.platform != "darwin":
        return _state["done"]
    _state["done"] = _set_policy(_IOPOL_MATERIALIZE_DATALESS_FILES_OFF)
    return _state["done"]


def allow_materialize() -> bool:
    """Process-wide opposite of never_materialize(): only for the cloudfetch helper, which downloads on purpose."""
    return sys.platform == "darwin" and _set_policy(_IOPOL_MATERIALIZE_DATALESS_FILES_ON)


def _set_policy(value: int) -> bool:
    try:
        import ctypes
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        return lib.setiopolicy_np(_IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, _IOPOL_SCOPE_PROCESS, value) == 0
    except Exception:  # noqa: BLE001
        return False


def materialization_off() -> bool | None:
    """Current process policy (None if unknown) – for tests and the sandbox self-check."""
    if sys.platform != "darwin":
        return None
    try:
        import ctypes
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        v = lib.getiopolicy_np(_IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, _IOPOL_SCOPE_PROCESS)
        return None if v < 0 else (v & 3) == _IOPOL_MATERIALIZE_DATALESS_FILES_OFF
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------------ which cloud-only files Mega fetches

# 0 = code that runs by itself, 1 = containers that usually carry it, 2 = documents with active content.
# Photos, videos, music and plain documents stay in the cloud: on their own they cannot run anything.
_RANK_EXT = {
    0: (".command", ".tool", ".sh", ".bash", ".zsh", ".csh", ".ksh", ".fish", ".py", ".pyc", ".pyw", ".pl", ".rb",
        ".php", ".js", ".mjs", ".cjs", ".jse", ".vbs", ".vbe", ".wsf", ".ps1", ".psm1", ".bat", ".cmd", ".applescript",
        ".scpt", ".jxa", ".jar", ".class", ".pkg", ".mpkg", ".dylib", ".so", ".kext", ".exe", ".dll", ".scr", ".msi",
        ".com", ".lnk", ".hta", ".terminal", ".mobileconfig", ".appimage", ".deb", ".rpm", ".apk", ".xpi", ".crx",
        ".vsix", ".whl", ".gem"),
    1: (".dmg", ".iso", ".img", ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".tbz", ".tbz2", ".xz", ".txz",
        ".zst", ".lz", ".lzma", ".cab", ".xar", ".cpio", ".cpgz", ".sit", ".sitx", ".pax"),
    2: (".pdf", ".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".xlsb", ".xlam", ".xlm", ".ppt", ".pptm", ".potm",
        ".ppam", ".ppsm", ".rtf", ".one", ".chm", ".html", ".htm", ".xhtml", ".shtml", ".svg", ".mht", ".mhtml",
        ".iqy", ".slk", ".url", ".webloc", ".inetloc", ".desktop", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
        ".ipynb", ".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib"),
}
_EXT_RANK = {e: r for r, exts in _RANK_EXT.items() for e in exts}
# copies from FAT/NTFS drives carry the execute bit on everything – ignore it on plain media and text
_DATA_EXT = {".txt", ".md", ".jpg", ".jpeg", ".png", ".heic", ".gif", ".tif", ".tiff", ".bmp", ".webp", ".dng", ".cr2",
             ".nef", ".arw", ".mov", ".mp4", ".m4v", ".avi", ".mkv", ".mp3", ".m4a", ".aac", ".wav", ".flac", ".csv",
             ".json", ".xml", ".log", ".pages", ".numbers", ".key", ".psd", ".srt"}


def cloud_rank(path: str, mode: int) -> int | None:
    """How urgently a cloud-only file is worth downloading for a scan (lower = sooner), None = leave it."""
    name = path.rsplit("/", 1)[-1].lower()
    dot = name.rfind(".")
    if dot > 0 and name[dot:] in _EXT_RANK:
        return _EXT_RANK[name[dot:]]
    if "/contents/macos/" in path.lower() or (mode & 0o111 and (dot <= 0 or name[dot:] not in _DATA_EXT)):
        return 0                                  # an app's main binary or anything marked executable
    return None

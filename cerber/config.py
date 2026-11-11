"""Filesystem layout. Everything lives next to the project unless CERBER_HOME is set."""
from __future__ import annotations

import os
import shutil

# realpath: Cerber.app imports the package through .venv/cerber-path/cerber (a symlink), see cerber/integrity.py
ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
HOME = os.environ.get("CERBER_HOME", ROOT)

DB = os.path.join(HOME, "db")
CLAMAV_RAW = os.path.join(DB, "clamav")                 # freshclam output (.cvd)
COMPILED = os.path.join(DB, "compiled")
CLAMAV_COMPILED = os.path.join(COMPILED, "clamav")
HASHDB = os.path.join(COMPILED, "hashes.sqlite")
IOCDB = os.path.join(COMPILED, "ioc.sqlite")
YARA_BIN = os.path.join(COMPILED, "yara.bin")
YARA_META = os.path.join(COMPILED, "yara.json")
FP_CALIBRATION = os.path.join(COMPILED, "fp_disabled.json")
YARA_SOURCES = os.path.join(DB, "yara")                 # downloaded rule sets
FEEDS = os.path.join(DB, "feeds")                       # raw downloads
CUSTOM_RULES = os.path.join(ROOT, "rules", "custom")              # validated packs (custom tier)
EXPERIMENTAL_RULES = os.path.join(ROOT, "rules", "experimental")  # unvalidated packs (community tier)
QUARANTINE = os.path.join(HOME, "quarantine")
REPORTS = os.path.join(HOME, "reports")
# "already scanned and clean" memory (cerber/scancache.py): HMAC key + rows. Never inside db/compiled (sealed into
# Cerber.app) – it changes after every scan
SCAN_CACHE_DIR = os.path.join(HOME, "scancache")

USER_AGENT = "Cerber-AV/1.0 (+local defensive scanner)"


def tools() -> dict[str, str]:
    """External helpers. CERBER_DISABLE_TOOLS (comma list) hides some, e.g. hdiutil inside the sandbox."""
    disabled = {t.strip() for t in os.environ.get("CERBER_DISABLE_TOOLS", "").split(",") if t.strip()}
    found = {}
    for name, cands in {"upx": ["upx"], "7z": ["7zz", "7z"], "hdiutil": ["hdiutil"], "codesign": ["codesign"],
                        "spctl": ["spctl"], "xattr": ["xattr"], "freshclam": ["freshclam"],
                        "mdls": ["mdls"]}.items():
        if name in disabled:
            continue
        for c in cands:
            p = shutil.which(c) or (f"/opt/homebrew/bin/{c}" if os.path.exists(f"/opt/homebrew/bin/{c}") else None)
            if p:
                found[name] = p
                break
    return found


PRIVATE_DIRS = ("QUARANTINE", "REPORTS", "SCAN_CACHE_DIR")   # malware copies, scan results, scan memory: owner only


def ensure_dirs() -> None:
    for d in (DB, CLAMAV_RAW, COMPILED, YARA_SOURCES, FEEDS, QUARANTINE, REPORTS):
        os.makedirs(d, exist_ok=True)
    for name in PRIVATE_DIRS:
        private_dir(globals()[name])


def private_dir(path: str) -> str:
    """Create `path` as a real directory readable only by the owner; refuse a symlink in its place."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    st = os.lstat(path)
    import stat as _stat
    if not _stat.S_ISDIR(st.st_mode):
        raise OSError(f"{path} nie jest katalogiem (dowiązanie?) – odmowa użycia")
    if st.st_uid == os.getuid() and st.st_mode & 0o077:
        try:
            os.chmod(path, 0o700)
        except OSError:                 # e.g. inside a sandbox, where the project folder is read-only
            pass
    return path


ABUSECH_KEY_FILE = os.path.join(HOME, "abusech.key")      # local only (git-ignored), mode 0600


def abusech_key() -> str | None:
    """The free abuse.ch Auth-Key (https://auth.abuse.ch): $CERBER_ABUSECH_KEY or the abusech.key file. Since
    2026-10 MalwareBazaar / ThreatFox / URLhaus exports need it; it is a secret – never logged or reported."""
    import re as _re
    key = (os.environ.get("CERBER_ABUSECH_KEY") or "").strip()
    if not key:
        try:
            with open(ABUSECH_KEY_FILE, encoding="utf-8") as fh:
                key = fh.read(256).strip()
        except OSError:
            return None
    return key if _re.fullmatch(r"[A-Za-z0-9_-]{16,128}", key) else None

"""Filesystem layout. Everything lives next to the project unless CERBER_HOME is set."""
from __future__ import annotations

import os
import shutil

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
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


def ensure_dirs() -> None:
    for d in (DB, CLAMAV_RAW, COMPILED, YARA_SOURCES, FEEDS, QUARANTINE, REPORTS):
        os.makedirs(d, exist_ok=True)

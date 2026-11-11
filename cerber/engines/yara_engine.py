"""YARA engine: robust multi-source compilation + matching with confidence tiers.

Sources are directories of .yar/.yara files, each with a *tier*:
    xprotect   Apple's own rules                                   -> CERTAIN
    custom     Cerber rule packs (meta.score decides)              -> score-based
    core       YARA-Forge core (high precision)                    -> CERTAIN when score >= 70
    community  YARA-Forge extended/full, signature-base, Elastic…  -> HIGH at most (heuristic)
Rules that fail to compile (unknown module, syntax, duplicates) are cut out
one by one; the rest of the file survives. Rules listed in the FP
calibration file (fired on clean Apple system files) are never reported.
"""
from __future__ import annotations

import json
import os
import re
import time
import warnings
from collections import Counter

import yara

from ..core import Confidence, Detection, ScanContext, ScanObject
from ..pipeline import Engine

warnings.filterwarnings("ignore", message="too many matches", category=RuntimeWarning)

EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
_RULE_START = re.compile(r"^\s*((?:private|global)\s+)*rule\s+([A-Za-z0-9_]+)", re.M)
_ERR_LINE = re.compile(r"\((\d+)\):")

UNCOMPRESSED_CONTAINERS = {"tar", "cpio", "ar", "iso"}

# rules about Windows/script payloads (PowerShell, batch, VBS…) say nothing about Mach-O binaries and
# disk-image blobs: their strings are scattered over megabytes of unrelated files there
SCRIPT_RULE_TAGS = {"POWERSHELL", "BATCH", "BAT", "CMD", "VBS", "VBSCRIPT", "VBA", "WSH", "HTA", "LNK",
                    "DOWNLOAD", "DOWNLOADER", "RUNDLL32", "LOLBAS", "MSHTA", "WMI"}
NON_SCRIPT_FTYPES = {"macho", "macho_fat", "dmg"}


def _is_fs_image(data: bytes) -> bool:
    """Raw HFS+/APFS volume or a whole raw disk (GPT / Apple partition map) – what a .dmg unpacks to."""
    if len(data) <= 0x600:
        return False
    if data[1024:1026] in (b"H+", b"HX") or data[32:36] == b"NXSB":
        return True
    if data[512:520] == b"EFI PART" or data[4096:4104] == b"EFI PART":       # GPT (512 / 4096-byte sectors)
        return True
    return data[:2] == b"ER" and data[512:514] == b"PM"                      # Apple partition map


# hunting/"catch-all" rules that are meant for triage, not detection
NOISY_RULES = {"GODMODERULES_IDDQD_God_Mode_Rule",
               "RUSSIANPANDA_Win_Sus_Internetshortcutfile",   # fires on Electron Framework builds
               # flags any obfuscator.io output; legitimate Electron apps ship obfuscated code, and the
               # script analyzers already score obfuscation together with what the code does
               "SIGNATURE_BASE_SUSP_Obfuscated_JS_Obfuscatorio",
               # "a (dirty) hack to display UTF-8 on Windows command prompt" (`chcp 65001`): electron-updater and
               # countless build scripts run it; it says nothing about intent
               "TELEKOM_SECURITY_Cn_Utf8_Windows_Terminal"}

PUA_HINTS = ("HKTL", "HACKTOOL", "HACKTOOL", "PUA", "ADWARE", "GRAYWARE", "RISKWARE", "PENTEST",
             "OFFENSIVE", "_TOOL_", "REDTEAM")
SUSP_HINTS = ("SUSP", "HUNT", "INDICATOR", "INFO_", "_INFO", "VULN", "GEN_", "_GEN", "ANOMALY",
              "CAPABILITY", "DEBUG", "EXPERIMENTAL", "OBFUS", "PACKER", "PACKED", "LOLBAS", "TOOLKIT",
              "SIGNED_", "CERT", "EMBEDDED", "HIGH_ENTROPY", "HEURISTIC", "GENERIC", "_LOW_",
              # build-tool identification: how a program was packaged, not what it does
              "PYINSTALLER")


_REGEX_CTX = re.compile(r"(?:=|\bmatches|\()\s*$")


def _skip_regex(src: str, i: int, n: int) -> int:
    """Skip a YARA regex literal body starting after the opening '/', return index after it."""
    in_class = False
    while i < n:
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if c == "\n":
            return i  # regexes never span lines; bail out safely
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "/":
            return i + 1
        i += 1
    return i


def split_rules(src: str) -> list[tuple[str, int, int]]:
    """Return (rule_name, start_offset, end_offset) for every rule, using brace matching."""
    out = []
    for m in _RULE_START.finditer(src):
        start = m.start()
        brace = src.find("{", m.end())
        if brace < 0:
            continue
        depth, i, n = 0, brace, len(src)
        in_str = in_re = False
        while i < n:
            c = src[i]
            if in_str:
                if c == "\\":
                    i += 2
                    continue
                if c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "/" and i + 1 < n and src[i + 1] == "/":
                j = src.find("\n", i)
                i = n if j < 0 else j
                continue
            elif c == "/" and i + 1 < n and src[i + 1] == "*":
                j = src.find("*/", i + 2)
                i = n if j < 0 else j + 2
                continue
            elif c == "/" and _REGEX_CTX.search(src, max(brace, i - 40), i):
                i = _skip_regex(src, i + 1, n)
                continue
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    out.append((m.group(2), start, i + 1))
                    break
            i += 1
    return out


_IMPORT = re.compile(r'^\s*import\s+"(\w+)"\s*$', re.M)
_PRIVATE = re.compile(r"^\s*(?:global\s+)?private\s+rule\b")


def _compiles(text: str) -> bool:
    try:
        yara.compile(source=text, externals=EXTERNALS)
        return True
    except yara.Error:
        return False


def _bisect(prefix: str, items: list[tuple[str, str]], removed: list[str], depth: int = 0) -> list[tuple[str, str]]:
    """Return the subset of rules that compile together with `prefix` (divide and conquer)."""
    if not items:
        return []
    if _compiles(prefix + "\n".join(t for _, t in items)):
        return items
    if len(items) == 1:
        removed.append(items[0][0])
        return []
    mid = len(items) // 2
    return _bisect(prefix, items[:mid], removed, depth + 1) + _bisect(prefix, items[mid:], removed, depth + 1)


def sanitize_source(src: str, log=None) -> tuple[str, list[str]]:
    """Make a rule file compile: drop unavailable-module imports and every rule that
    fails (unknown module functions, syntax, duplicates, missing references)."""
    if _compiles(src):
        return src, []
    removed: list[str] = []
    avail = set(yara.modules)
    mods = list(dict.fromkeys(_IMPORT.findall(src)))
    bad_mods = [m for m in mods if m not in avail]
    removed.extend(f"import {m}" for m in bad_mods)
    header = "".join(f'import "{m}"\n' for m in mods if m in avail)
    seen: set[str] = set()
    privates: list[tuple[str, str]] = []
    publics: list[tuple[str, str]] = []
    for name, s, e in split_rules(src):
        text = src[s:e]
        if name in seen:
            removed.append(name)
            continue
        seen.add(name)
        if bad_mods and any(re.search(rf"\b{m}\.", text) for m in bad_mods):
            removed.append(name)
            continue
        (privates if _PRIVATE.match(text) else publics).append((name, text))
    privates = _bisect(header, privates, removed)
    prefix = header + "\n".join(t for _, t in privates) + "\n"
    publics = _bisect(prefix, publics, removed)
    clean = prefix + "\n\n".join(t for _, t in publics)
    if not _compiles(clean):  # cross-rule references broken by removals: last resort per-rule
        publics = [r for r in publics if _compiles(prefix + r[1]) or removed.append(r[0])]
        clean = prefix + "\n\n".join(t for _, t in publics)
    return clean, removed


def _line_offset(src: str, line: int) -> int:
    off = 0
    for _ in range(line - 1):
        j = src.find("\n", off)
        if j < 0:
            return len(src)
        off = j + 1
    return off


def build_rules(sources: list[tuple[str, str]], out_bin: str, out_meta: str, log=print) -> dict:
    """sources: [(tier, directory)]. Compiles everything into one rules file."""
    namespaces: dict[str, str] = {}
    tiers: dict[str, str] = {}
    stats: Counter = Counter()
    removed_all: dict[str, list[str]] = {}
    for tier, directory in sources:
        if not os.path.isdir(directory):
            continue
        files = []
        for dp, _dn, fn in os.walk(directory):
            for f in fn:
                if f.lower().endswith((".yar", ".yara", ".yr")):
                    files.append(os.path.join(dp, f))
        for path in sorted(files):
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    src = fh.read()
            except OSError:
                continue
            if "include " in src and re.search(r'^\s*include\s+"', src, re.M):
                src = re.sub(r'^\s*include\s+"[^"]*"', "// include removed", src, flags=re.M)
            clean, removed = sanitize_source(src)
            n = len(split_rules(clean)) if clean else 0
            stats[f"{tier}:rules"] += n
            stats[f"{tier}:removed"] += len(removed)
            if removed:
                removed_all[os.path.relpath(path, directory)] = removed[:50]
            if n:
                ns = f"{tier}:{os.path.relpath(path, directory)}"
                namespaces[ns] = clean
                tiers[ns] = tier
    log(f"  compiling {len(namespaces)} rule files ...")
    t0 = time.time()
    rules = yara.compile(sources=namespaces, externals=EXTERNALS)
    rules.save(out_bin)
    total = sum(1 for _ in rules)
    meta = {"built": time.strftime("%Y-%m-%d %H:%M:%S"), "rules": total, "files": len(namespaces),
            "stats": dict(stats), "compile_seconds": round(time.time() - t0, 1), "tiers": tiers,
            "removed": removed_all}
    with open(out_meta, "w") as fh:
        json.dump(meta, fh, indent=1)
    return meta


def _meta_int(meta: dict, key: str, default: int | None = None) -> int | None:
    v = meta.get(key)
    if v is None:
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def classify(rule: str, namespace: str, meta: dict, tier: str) -> tuple[Confidence, int, bool]:
    up = rule.upper()
    pua = bool(meta.get("pua")) or any(h in up for h in PUA_HINTS)
    susp = any(h in up for h in SUSP_HINTS)
    score = _meta_int(meta, "score")
    sev = str(meta.get("severity", "")).lower()
    if score is None:
        score = {"critical": 95, "high": 80, "medium": 55, "low": 30}.get(sev, 70)
    if tier == "xprotect":
        return Confidence.CERTAIN, 100, pua
    if tier in ("custom", "core"):
        if score >= 75 and not susp:
            return Confidence.CERTAIN, 100, pua
        if susp:  # "suspicious"/hunting rules: a strong hint, not proof
            return Confidence.MEDIUM, min(score, 45), pua
        return (Confidence.HIGH if score >= 55 else Confidence.MEDIUM), min(score, 70), pua
    # community tier: never a verdict on its own
    if susp:
        return Confidence.MEDIUM, min(score, 30), pua
    return (Confidence.HIGH if score >= 70 else Confidence.MEDIUM), min(score, 60), pua


class YaraEngine(Engine):
    name = "yara"

    def __init__(self, compiled: str, meta_path: str, fp_path: str | None = None, timeout: int = 120):
        self.rules = yara.load(compiled)
        with open(meta_path) as fh:
            self.meta = json.load(fh)
        self.tiers = self.meta.get("tiers", {})
        self.disabled: set[str] = set(NOISY_RULES)
        if fp_path and os.path.exists(fp_path):
            with open(fp_path) as fh:
                self.disabled |= set(json.load(fh).get("disabled", []))
        self.timeout = timeout

    @property
    def rule_count(self) -> int:
        return int(self.meta.get("rules", 0))

    def match_raw(self, data: bytes, name: str = "", path: str = "", ftype: str = ""):
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        return self.rules.match(data=data, externals={"filename": name, "filepath": path, "extension": ext,
                                                      "filetype": ftype, "owner": ""},
                                timeout=self.timeout)

    def scan(self, obj: ScanObject, ctx: ScanContext) -> None:
        if not obj.data:
            return
        # uncompressed multi-file containers: their members are extracted and scanned one by one;
        # scanning the concatenated blob lets rules combine strings from unrelated files
        if obj.ftype in UNCOMPRESSED_CONTAINERS or (obj.data[:4] == b"\x04\x00\x00\x00"
                                                    and obj.data[16:25] == b'{"files":'):
            obj.meta["yara_container_skipped"] = True
            return
        try:
            matches = self.match_raw(obj.data, obj.name, obj.real_path or obj.display_path, obj.ftype)
        except yara.TimeoutError:
            obj.errors.append("yara: timeout")
            return
        except yara.Error as exc:
            obj.errors.append(f"yara: {exc}")
            return
        no_scripts = obj.ftype in NON_SCRIPT_FTYPES or _is_fs_image(obj.data)
        for m in matches:
            key = f"{m.namespace}::{m.rule}"
            if key in self.disabled or m.rule in self.disabled:
                continue
            if no_scripts and SCRIPT_RULE_TAGS & {str(t).upper() for t in m.tags}:
                continue
            tier = self.tiers.get(m.namespace, m.namespace.split(":", 1)[0])
            conf, score, pua = classify(m.rule, m.namespace, m.meta, tier)
            ev = []
            for s in m.strings[:6]:
                for inst in s.instances[:2]:
                    ev.append(f"{s.identifier}@{inst.offset}: {bytes(inst.matched_data[:60])!r}")
            desc = str(m.meta.get("description", ""))[:200]
            label = {"xprotect": "XProtect", "custom": "Cerber", "core": "YARA", "community": "YARA-ext"}.get(tier, "YARA")
            ctx.detect(obj, Detection(f"{label}:{m.rule}", "yara", conf, score, desc, ev, pua=pua))

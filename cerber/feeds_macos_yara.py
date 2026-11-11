"""Publiczne reguły YARA dla macOS pobierane w czasie aktualizacji (db/yara/macfeeds).

Każde źródło to repozytorium GitHub; pobieramy archiwum (lub pliki z drzewa), z każdego pliku .yar/.yara
wybieramy tylko reguły dotyczące macOS (Mach-O, osascript, LaunchAgent …), usuwamy duplikaty względem
reguł już obecnych w Cerberze i zapisujemy jedną skompilowalną paczkę na źródło. Reguły nie są nigdzie
przepisywane ręcznie — repo zawiera tylko listę źródeł i filtr.

Tier w kompilacji: "community" (nigdy sam werdykt). Opt-out: CERBER_MACYARA_SKIP=tag1,tag2.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from . import config
from .engines.yara_engine import sanitize_source, split_rules

Log = Callable[[str], None]

DIR_NAME = "macfeeds"
MAX_FILE = 3 << 20
CODELOAD = "https://codeload.github.com/{repo}/tar.gz/refs/heads/{branch}"
TREE = "https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"
RAW = "https://raw.githubusercontent.com/{repo}/{branch}/{path}"

# tag, repo, branch, licencja (wg GitHub), tryb, filtr ścieżek (None = wszystkie pliki), tylko_macos_w_ścieżce
# reguły "hunting"/informacyjne (odpalają na czystych plikach systemowych)
HUNT = r"(?i)^(SUSP|INFO|Logger|HUNT|Hunting|lang|file_macho|head_macho|macho|sign)_|(^|_)(Ref|LOObin|LowLevel|AntiDebug|ExternalLibary|StackString)(_|$)"

SOURCES = [
    {"tag": "ba", "repo": "airbnb/binaryalert", "branch": "master", "license": "Apache-2.0"},
    # SentineLabs/macos-ttps-yara pominięte: reguły "capability" odpalają na ~100% systemowych narzędzi
    {"tag": "slx", "repo": "SentineLabs/XProtect-Malware-Families", "branch": "main", "license": "brak"},
    {"tag": "d100", "repo": "100DaysofYARA/2022", "branch": "main", "license": "MIT/brak", "deny_re": HUNT},
    {"tag": "d101", "repo": "100DaysofYARA/2023", "branch": "main", "license": "brak", "deny_re": HUNT},
    {"tag": "d102", "repo": "100DaysofYARA/2024", "branch": "main", "license": "MIT", "deny_re": HUNT},
    {"tag": "d103", "repo": "100DaysofYARA/2025", "branch": "main", "license": "MIT", "deny_re": HUNT},
    {"tag": "d104", "repo": "100DaysofYARA/2026", "branch": "main", "license": "MIT", "deny_re": HUNT},
    {"tag": "sek", "repo": "SEKOIA-IO/Community", "branch": "main", "license": "CC BY-SA/inna"},
    {"tag": "yr", "repo": "Yara-Rules/rules", "branch": "master", "license": "GPL-2.0"},
    {"tag": "vol", "repo": "volexity/threat-intel", "branch": "main", "license": "inna (Volexity)"},
    {"tag": "jp", "repo": "JPCERTCC/jpcert-yara", "branch": "main", "license": "inna (JPCERT/CC)"},
    {"tag": "eset", "repo": "eset/malware-ioc", "branch": "master", "license": "BSD-2-Clause"},
    {"tag": "goog", "repo": "google/threat-team", "branch": "main", "license": "Apache-2.0"},
    {"tag": "hunt", "repo": "huntresslabs/threat-intel", "branch": "main", "license": "MIT"},
    {"tag": "bart", "repo": "bartblaze/Yara-rules", "branch": "master", "license": "MIT"},
    {"tag": "scar", "repo": "scarlet-shark/Detection-Rules", "branch": "main", "license": "CC0-1.0"},
    {"tag": "rasp", "repo": "Raspirus/yara-rules", "branch": "main", "license": "GPL-3.0"},
    {"tag": "mik", "repo": "mikesxrs/Open-Source-YARA-rules", "branch": "master", "license": "brak (agregat)"},
    # qqbgxi/MalwareDetectionTool pominięte: kopia reguł z innych repozytoriów (po deduplikacji 1 reguła)
    {"tag": "cape", "repo": "CAPESandbox/community", "branch": "master", "license": "brak/GPL (CAPE)",
     "path_re": r"(^|/)(data/)?yara/"},
    # Chainguard malcontent: tylko reguły rodzin malware, frameworków C2 i znanych ataków na łańcuch dostaw
    # (npm/PyPI); reguły „capability” z reszty repo są zbyt ogólne (każdy program coś pobiera, coś szyfruje)
    {"tag": "mc", "repo": "chainguard-dev/malcontent", "branch": "main", "license": "Apache-2.0",
     "mode": "tree", "path_re": r"/rules/malware/(family|framework)/"},
    {"tag": "mcs", "repo": "chainguard-dev/malcontent", "branch": "main", "license": "Apache-2.0",
     "mode": "tree", "path_re": r"/rules/malware/supplychain/", "all_rules": True,
     "deny_re": HUNT},
    # ~1000 reguł macOS wyciągniętych z sygnatur Defendera; repo bez licencji — wyłączalne przez CERBER_MACYARA_SKIP=dy
    {"tag": "dy", "repo": "roadwy/DefenderYara", "branch": "main", "license": "brak (pochodne sygnatur MS Defender)",
     "mode": "tree", "path_re": r"/MacOS/", "all_rules": True},
]

# reguły odrzucone po teście na czystym macOS (klucz "tag:oryginalna_nazwa")
FP_DENY: set[str] = {"d101:mal_macos_cointicker", "d101:macos_bundle_findersync_appex",
                     "d102:head_macho",
                     "mik:embedded_macho"}          # any Mach-O inside another file: every app with helpers

_NAME_MAC = re.compile(r"(?<![a-z])(macos|osx|darwin|macho|mach_?o|mac)(?![a-z])", re.I)
_TEXT_MAC = re.compile(
    r'import\s+"macho"|\bmacho\.|0x(?:feedfac[ef]|cefaedfe|cffaedfe)|\bosascript\b|LaunchAgents|LaunchDaemons|'
    r"\blaunchctl\b|objc_msgSend|\bNSTask\b|com\.apple\.|Mach-?O\b|\bmac ?OS\b|\bOS X\b|\bDarwin\b|"
    r"~/Library|/Library/(?:Application|Launch|Preferences|Keychains)|\.app/Contents|"
    r"security find-generic-password|\bdscl\b|\bsw_vers\b|\bspctl\b", re.I)
_IMPORT = re.compile(r'^\s*import\s+"(\w+)"\s*$', re.M)
_COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
_DECL = re.compile(r"^(\s*(?:(?:private|global)\s+)*rule\s+)([A-Za-z0-9_]+)", re.M)
_COND = re.compile(r"^\s*condition\s*:", re.M)
_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def is_macos_rule(name: str, text: str) -> bool:
    return bool(_NAME_MAC.search(name) or _TEXT_MAC.search(text))


def normalize_body(text: str) -> str:
    """Treść reguły bez nazwy, komentarzy i białych znaków (do wykrywania duplikatów)."""
    t = _COMMENTS.sub("", text)
    t = _DECL.sub(r"\1", t, count=1)
    return re.sub(r"\s+", "", t).lower()


def body_hash(text: str) -> str:
    return hashlib.sha1(normalize_body(text).encode("utf-8", "replace")).hexdigest()


def existing_hashes() -> set[str]:
    """Skróty treści reguł już kompilowanych z innych źródeł (Forge, XProtect, Elastic, custom)."""
    out: set[str] = set()
    dirs = [os.path.join(config.YARA_SOURCES, d) for d in ("core", "community", "xprotect", "elastic")]
    dirs += [config.CUSTOM_RULES, config.EXPERIMENTAL_RULES]
    for d in dirs:
        for dp, _dn, fn in os.walk(d):
            for f in fn:
                if f.lower().endswith((".yar", ".yara", ".yr")):
                    try:
                        with open(os.path.join(dp, f), encoding="utf-8", errors="replace") as fh:
                            src = fh.read()
                    except OSError:
                        continue
                    for _n, s, e in split_rules(src):
                        out.add(body_hash(src[s:e]))
    return out


def select_rules(files: list[tuple[str, str]], tag: str, seen: set[str], all_rules: bool = False, deny_re: str | None = None) -> tuple[str, dict]:
    """files: [(ścieżka, treść)]. Zwraca (tekst .yar, statystyki). `seen` jest uzupełniany o przyjęte skróty."""
    stats = {"total": 0, "mac": 0, "dup": 0, "denied": 0}
    chosen: list[tuple[str, str]] = []     # (oryginalna nazwa, tekst)
    imports: set[str] = set()
    for _path, src in files:
        if re.search(r'^\s*include\s+"', src, re.M):
            src = re.sub(r'^\s*include\s+"[^"]*"', "", src, flags=re.M)
        rules = [(n, src[s:e]) for n, s, e in split_rules(src)]
        stats["total"] += len(rules)
        by_name = dict(rules)
        picked: dict[str, str] = {}
        for n, t in rules:
            if all_rules or is_macos_rule(n, t):
                picked[n] = t
        # zależności (reguły prywatne / pomocnicze używane w warunku)
        changed = True
        while changed:
            changed = False
            for n, t in list(picked.items()):
                ms = list(_COND.finditer(t))
                cond = t[ms[-1].start():] if ms else ""
                for ident in set(_ID.findall(cond)):
                    if ident in by_name and ident not in picked and ident != n:
                        picked[ident] = by_name[ident]
                        changed = True
        for n, t in picked.items():
            imports.update(_IMPORT.findall(src))
            h = body_hash(t)
            if f"{tag}:{n}" in FP_DENY or (deny_re and re.search(deny_re, n)) or re.search(r"\bconsole\.", t):
                stats["denied"] += 1
                continue
            if h in seen:
                stats["dup"] += 1
                continue
            seen.add(h)
            stats["mac"] += 1
            chosen.append((n, t))
    if not chosen:
        return "", stats
    # unikalne nazwy z prefiksem źródła
    names: dict[str, str] = {}
    used: set[str] = set()
    renamed: list[tuple[str, str, str]] = []
    for n, t in chosen:
        new, k = f"MF_{tag}_{n}", 1
        while new in used:
            k += 1
            new = f"MF_{tag}_{n}_{k}"
        used.add(new)
        names.setdefault(n, new)
        renamed.append((n, new, t))
    out = []
    for n, new, t in renamed:
        ms = list(_COND.finditer(t))
        head, cond = (t[:ms[-1].start()], t[ms[-1].start():]) if ms else (t, "")
        head = _DECL.sub(lambda m: m.group(1) + new, head, count=1)
        if cond:
            cond = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b",
                          lambda m: names[m.group(0)] if m.group(0) in names and m.group(0) != n else m.group(0), cond)
        out.append((new, head + cond))
    mods = sorted(m for m in imports if re.search(rf"\b{m}\.", "".join(t for _, t in out)))
    text = "".join(f'import "{m}"\n' for m in mods) + "\n" + "\n\n".join(t for _, t in out) + "\n"
    return text, stats


MAX_DOWNLOAD = 1 << 30


def _http(url: str, timeout: int = 120) -> bytes:
    if not url.lower().startswith("https://"):           # urlopen would also accept file:// or ftp://
        raise ValueError(f"odrzucono adres spoza https: {url[:120]}")
    req = urllib.request.Request(url, headers={"User-Agent": config.USER_AGENT, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError(f"plik większy niż {MAX_DOWNLOAD >> 20} MB: {url[:120]}")
    return data


def _is_rule_file(path: str) -> bool:
    return path.lower().endswith((".yar", ".yara", ".yr"))


def fetch_files(src: dict) -> list[tuple[str, str]]:
    """Pobiera pliki reguł źródła (archiwum tar.gz albo pojedyncze pliki z drzewa)."""
    path_re = re.compile(src["path_re"]) if src.get("path_re") else None
    out: list[tuple[str, str]] = []
    if src.get("mode") == "tree":
        tree = json.loads(_http(TREE.format(repo=src["repo"], branch=src["branch"])))
        paths = [t["path"] for t in tree.get("tree", [])
                 if t.get("type") == "blob" and _is_rule_file(t["path"]) and (not path_re or path_re.search("/" + t["path"]))
                 and t.get("size", 0) < MAX_FILE]

        def one(p: str):
            for _ in range(3):
                try:
                    return p, _http(RAW.format(repo=src["repo"], branch=src["branch"], path=urllib.request.quote(p)), 60).decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    continue
            return p, None
        with ThreadPoolExecutor(8) as ex:
            for p, t in ex.map(one, paths):
                if t:
                    out.append((p, t))
        return out
    data = _http(CODELOAD.format(repo=src["repo"], branch=src["branch"]), 300)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf:
            if not m.isfile() or m.size > MAX_FILE or not _is_rule_file(m.name):
                continue
            rel = m.name.split("/", 1)[-1]
            if path_re and not path_re.search("/" + rel):
                continue
            fh = tf.extractfile(m)
            if fh:
                out.append((rel, fh.read().decode("utf-8", "replace")))
    return out


def update_macos_yara(log: Log, offline: bool = False, sources: list[dict] | None = None) -> str | None:
    """Pobiera i filtruje reguły macOS do db/yara/macfeeds (przy błędzie źródła zostaje jego poprzednia wersja)."""
    d = os.path.join(config.YARA_SOURCES, DIR_NAME)
    if offline:
        return d if os.path.isdir(d) else None
    os.makedirs(d, exist_ok=True)
    skip = {s.strip() for s in os.environ.get("CERBER_MACYARA_SKIP", "").split(",") if s.strip()}
    seen = existing_hashes()
    stats: dict[str, dict] = {}
    log("  reguły YARA macOS z publicznych repozytoriów: pobieranie …")
    for src in (SOURCES if sources is None else sources):
        tag = src["tag"]
        if tag in skip:
            continue
        out_path = os.path.join(d, f"{tag}.yar")
        try:
            files = fetch_files(src)
            text, st = select_rules(files, tag, seen, src.get("all_rules", False), src.get("deny_re"))
            st["files"] = len(files)
            if text:
                clean, removed = sanitize_source(text)
                st["uncompilable"] = len(removed)
                st["kept"] = len(split_rules(clean))
                header = f"// źródło: https://github.com/{src['repo']} (licencja: {src['license']})\n"
                tmp = out_path + ".new"
                with open(tmp, "w", encoding="utf-8") as fh:
                    fh.write(header + clean)
                os.replace(tmp, out_path)
            else:
                st["kept"] = 0
                if os.path.exists(out_path):
                    os.remove(out_path)
            st.update(repo=src["repo"], license=src["license"])
            stats[tag] = st
            log(f"    {src['repo']}: {st['total']} reguł, macOS {st['mac']}, duplikaty {st['dup']}, zapisano {st['kept']}")
        except Exception as exc:  # noqa: BLE001
            log(f"    {src['repo']} niedostępne ({exc}); zostaje poprzednia wersja")
            if os.path.exists(out_path):
                stats[tag] = {"repo": src["repo"], "license": src["license"], "kept": "poprzednia"}
    with open(os.path.join(d, "SOURCES.json"), "w", encoding="utf-8") as fh:
        json.dump(stats, fh, indent=1, ensure_ascii=False)
    return d

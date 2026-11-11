"""Fair benchmark: the same thresholds on both sides, the full product, and clean files nobody tuned on.

Why the older numbers flattered Cerber (tests/static_measure/measure.py):
  * the clean set (clean_files.json) is the set the heuristics were tuned against until it showed 0 false
    alarms – measuring on it again says little about files Cerber has never seen;
  * it ran only YARA + heuristics, not ClamAV / hashes / TLSH / IOC, i.e. not what a user's scan runs;
  * /System files were skipped silently by the sealed-volume shortcut and still counted as "clean";
  * the detection samples (tests/samples) were written next to the rules that catch them – they show the
    rules work, not how much real malware is caught.

What this does instead:
  * `build`: a HELD-OUT clean set from places the tuning set never sampled (app frameworks and helpers,
    Homebrew Cellar, Python libraries, your documents and installers, Application Support, node_modules),
    every file not in clean_files.json, deterministic sampling. The list stays local (gitignored).
  * `run`: the full deep scan engine (all signature engines + heuristics + macOS checks, nothing skipped)
    over held-out clean + tuning clean + the test samples, then ONE table: for each threshold
    (INFO+, SUSPICIOUS+, MALICIOUS) the detection rate and the false-alarm rate side by side.

Nothing is executed; files are only read. Results (paths only, no contents) go to tests/benchmark/results/.

    .venv/bin/python tests/benchmark/fair_bench.py build
    .venv/bin/python tests/benchmark/fair_bench.py run --label 20261103
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import importlib.util
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, ROOT)

HOME = os.path.expanduser("~")
HELDOUT = os.path.join(HERE, "heldout_files.json")
RESULTS = os.path.join(HERE, "results")
TUNING = os.path.join(ROOT, "tests", "static_measure", "clean_files.json")
ORDER = ["CLEAN", "INFO", "SUSPICIOUS", "PUA", "MALICIOUS"]
LEVELS = (("INFO+", "INFO"), ("SUSPICIOUS+", "SUSPICIOUS"), ("MALICIOUS", "MALICIOUS"))
MACHO_MAGIC = {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf", b"\xbe\xba\xfe\xca"}
SCRIPT_EXT = {"sh", "bash", "zsh", "command", "py", "rb", "pl", "js", "mjs", "cjs", "applescript", "scpt", "php"}
DOC_EXT = {"pdf", "docx", "doc", "xlsx", "xls", "pptx", "rtf", "pages", "numbers", "key", "odt"}
INSTALLER_EXT = {"dmg", "pkg", "zip", "7z", "rar", "tgz", "gz", "xip", "iso"}
SKIP_DIRS = {".git", "__pycache__", "Caches", "Cache", "CachedData", "GPUCache", "Code Cache", ".Trash"}
WALK_LIMIT = 250_000
MAX_SIZE = 64 << 20


def _measure():
    spec = importlib.util.spec_from_file_location("measure", os.path.join(ROOT, "tests", "static_measure",
                                                                         "measure.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _stable(p: str) -> str:
    return hashlib.sha1(p.encode("utf-8", "replace")).hexdigest()


def _ext(p: str) -> str:
    b = os.path.basename(p).lower()
    return b.rsplit(".", 1)[-1] if "." in b else ""


def _regular(p: str) -> bool:
    try:
        st = os.lstat(p)
    except OSError:
        return False
    import stat
    return stat.S_ISREG(st.st_mode) and 0 < st.st_size <= MAX_SIZE


def _macho(p: str) -> bool:
    try:
        with open(p, "rb") as fh:
            return fh.read(4) in MACHO_MAGIC
    except OSError:
        return False


def _walk(roots: list[str], want, exclude: set[str]) -> list[str]:
    out, n = [], 0
    cerber = os.path.realpath(ROOT) + "/"
    for root in roots:
        for dp, dn, fn in os.walk(root):
            dn[:] = sorted(d for d in dn if d not in SKIP_DIRS)
            if os.path.realpath(dp).startswith(cerber):
                dn[:] = []
                continue
            for f in fn:
                n += 1
                p = os.path.join(dp, f)
                if p in exclude or not _regular(p):
                    continue
                try:
                    if want(p):
                        out.append(p)
                except OSError:
                    pass
            if n > WALK_LIMIT:
                return out
    return out


def build_heldout() -> list[tuple[str, str]]:
    with open(TUNING) as fh:
        tuned = {p for _c, p in json.load(fh)["files"]}
    apps = sorted(glob.glob("/Applications/*.app") + glob.glob("/Applications/*/*.app"))
    docs_roots = [os.path.join(HOME, d) for d in ("Documents", "Desktop", "Downloads")]
    pools = [
        ("app_frameworks_macho", 800,
         [os.path.join(a, "Contents", sub) for a in apps for sub in ("Frameworks", "Helpers", "Library", "PlugIns",
                                                                     "XPCServices")],
         _macho),
        ("app_resources_scripts", 500, [os.path.join(a, "Contents", "Resources") for a in apps],
         lambda p: _ext(p) in SCRIPT_EXT),
        ("homebrew_cellar", 800, ["/opt/homebrew/Cellar", "/usr/local/Cellar"],
         lambda p: _macho(p) or _ext(p) in SCRIPT_EXT),
        ("python_libs", 400, glob.glob("/opt/homebrew/lib/python3*/site-packages"),
         lambda p: _ext(p) == "py"),
        ("user_documents", 600, docs_roots, lambda p: _ext(p) in DOC_EXT),
        ("installers_archives", 120, [os.path.join(HOME, "Downloads"), os.path.join(HOME, "Desktop")],
         lambda p: _ext(p) in INSTALLER_EXT),
        ("app_support", 500, [os.path.join(HOME, "Library", "Application Support"), "/Library/Application Support"],
         lambda p: _macho(p) or _ext(p) in SCRIPT_EXT),
        ("project_deps", 400, [os.path.join(HOME, "Documents")],
         lambda p: ("/node_modules/" in p or "/site-packages/" in p) and _ext(p) in SCRIPT_EXT),
    ]
    out, seen = [], set(tuned)
    for cat, cap, roots, want in pools:
        roots = [r for r in roots if os.path.isdir(r)]
        cands = [p for p in _walk(roots, want, seen) if p not in seen]
        pick = sorted(set(cands), key=_stable)[:cap]
        seen.update(pick)
        out += [(cat, p) for p in pick]
        print(f"  {cat:24} {len(pick):5} (z {len(set(cands))} kandydatów)", flush=True)
    return out


def cmd_build(_a) -> None:
    items = build_heldout()
    with open(HELDOUT, "w") as fh:
        json.dump({"built": time.strftime("%Y-%m-%d %H:%M:%S"), "files": items}, fh, indent=0, ensure_ascii=False)
    print(f"{len(items)} plików → {HELDOUT}")


# ------------------------------------------------------------------ scanning with the full engine

def scan_full(paths: list[str]) -> dict[str, dict]:
    """path → {verdict, score, dets}; everything not reported is CLEAN (scan_paths reports non-clean files)."""
    from cerber.scanner import ScanOptions, load_engines, scan_paths
    opts = ScanOptions(deep=True, level="deep", quarantine=False, skip_sealed_system=False, macos_checks=True,
                       file_timeout=300)
    bundle = load_engines(opts, lambda m: None)
    out: dict[str, dict] = {}
    step = 400
    t0 = time.time()
    for i in range(0, len(paths), step):
        part = paths[i:i + step]
        rep = scan_paths(part, opts, log=lambda m: None, engines_bundle=bundle, progress=False)
        for r in rep.get("results", []):
            top = r["path"].split(">>", 1)[0]
            prev = out.get(top)
            if prev is None or ORDER.index(r["verdict"]) > ORDER.index(prev["verdict"]):
                out[top] = {"verdict": r["verdict"], "score": r.get("score", 0),
                            "dets": [f"{d.get('name')}:{d.get('score')}" for d in (r.get("detections") or [])
                                     if (d.get("score") or 0) > 0][:12]}
        print(f"  {min(i + step, len(paths))}/{len(paths)}  {time.time() - t0:.0f}s", flush=True)
    return out


def _at_least(v: str, lvl: str) -> bool:
    return ORDER.index(v) >= ORDER.index(lvl)


def cmd_run(a) -> None:
    os.makedirs(RESULTS, exist_ok=True)
    with open(HELDOUT) as fh:
        held = [tuple(x) for x in json.load(fh)["files"] if os.path.exists(x[1])]
    with open(TUNING) as fh:
        tuned = [tuple(x) for x in json.load(fh)["files"] if os.path.exists(x[1])]
    fixtures = _measure()._fixture_items()
    pos = [p for c, p in fixtures if c.startswith("malicious")]
    neg_fx = [p for c, p in fixtures if c.startswith("clean")]
    sets = {"held-out clean (nigdy nie strojone)": [p for _c, p in held],
            "clean użyty do strojenia": [p for _c, p in tuned],
            "czyste próbki testowe": neg_fx}
    allp = list(dict.fromkeys(pos + [p for v in sets.values() for p in v]))
    print(f"pełny silnik (wszystkie bazy + heurystyki): {len(allp)} plików")
    res = scan_full(allp)
    verdict = {p: (res.get(p) or {"verdict": "CLEAN"})["verdict"] for p in allp}

    table = []
    for name, lvl in LEVELS:
        row = {"próg": name, "wykrywanie (próbki testowe)": f"{sum(_at_least(verdict[p], lvl) for p in pos)}/{len(pos)}"}
        for sname, ps in sets.items():
            fp = sum(_at_least(verdict[p], lvl) for p in ps)
            row[f"fałszywe alarmy: {sname}"] = f"{fp}/{len(ps)} ({100 * fp / max(1, len(ps)):.2f}%)"
        table.append(row)

    cats = {}
    for c, p in held:
        s = cats.setdefault(c, {"n": 0, "INFO+": 0, "SUSPICIOUS+": 0, "MALICIOUS": 0})
        s["n"] += 1
        for name, lvl in LEVELS:
            s[name] += _at_least(verdict[p], lvl)
    fps = [{"cat": c, "path": p, **res[p]} for c, p in held if p in res and _at_least(res[p]["verdict"], "SUSPICIOUS")]
    names: dict[str, int] = {}
    for f in fps:
        for d in f["dets"]:
            k = d.rsplit(":", 1)[0]
            names[k] = names.get(k, 0) + 1
    out = {"label": a.label, "when": time.strftime("%Y-%m-%d %H:%M:%S"), "table": table, "heldout_by_category": cats,
           "heldout_false_alarms": fps, "false_alarm_detections": dict(sorted(names.items(), key=lambda x: -x[1])),
           "records": {p: res.get(p) or {"verdict": "CLEAN"} for p in allp}}
    jp = os.path.join(RESULTS, f"fair-{a.label}.json")
    with open(jp, "w") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False)
    print()
    for row in table:
        print(" | ".join(f"{k}: {v}" for k, v in row.items()))
    print("\nheld-out wg kategorii:", json.dumps(cats, ensure_ascii=False))
    print(f"\nfałszywe alarmy (SUSPICIOUS+) na held-out: {len(fps)}")
    for f in fps[:40]:
        print(f"  {f['verdict']:10} {f['score']:4} [{f['cat']}] {f['path']}\n      {f['dets']}")
    print(f"→ {jp}")


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build").set_defaults(fn=cmd_build)
    p = sub.add_parser("run")
    p.add_argument("--label", required=True)
    p.set_defaults(fn=cmd_run)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()

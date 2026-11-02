"""Static-heuristics measurement: fixture verdicts + false positives on real clean files of this Mac.

    .venv/bin/python tests/static_measure/measure.py list                       # (re)build clean_files.json
    .venv/bin/python tests/static_measure/measure.py fixtures --label before
    .venv/bin/python tests/static_measure/measure.py clean --label before [--workers 8]
    .venv/bin/python tests/static_measure/measure.py compare before after

Everything is read-only: files are only read (the macOS trust analyzer runs `codesign -dv` / `codesign --verify`
on top-level Mach-O files, exactly like a normal scan); nothing that is scanned is ever executed.

Engines: heuristics (all analyzers) + YARA. YARA uses the compiled database in db/compiled/yara.bin, but the
rule files Cerber owns (rules/custom/*.yar, rules/experimental/*.yar) are compiled fresh from the working tree
and their stale copies in the database are ignored, so rule edits show up without rebuilding db/.
ClamAV / hash / TLSH / IOC engines are not loaded (signature engines, not what this measures).

Results (JSON, no file contents) go to tests/static_measure/results/.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import multiprocessing as mp
import os
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, ROOT)

RESULTS = os.path.join(HERE, "results")
FILE_LIST = os.path.join(HERE, "clean_files.json")
HOME = os.path.expanduser("~")

SCRIPT_EXT = {"sh", "bash", "zsh", "command", "tool", "py", "applescript", "scpt", "rb", "pl", "js", "mjs", "cjs",
              "plist"}
PRIORITY_EXT = {"sh", "bash", "zsh", "command", "tool", "applescript", "scpt", "plist", "py", "rb", "pl"}
DEP_DIRS = ("/node_modules/", "/site-packages/", "/.venv/", "/venv/", "/vendor/", "/dist/", "/build/",
            "/.next/", "/Pods/", "/.build/")
# Cerber itself (malware fixtures) plus folders listed in exclude.local.txt, one per line – private data and
# offensive-security playgrounds are not "clean" ground truth; the list is personal, so it is never committed
EXCLUDE_FILE = os.path.join(HERE, "exclude.local.txt")
DOC_EXCLUDE = {"antywirus"} | ({ln.strip() for ln in open(EXCLUDE_FILE, encoding="utf-8") if ln.strip()}
                              if os.path.isfile(EXCLUDE_FILE) else set())
PER_APP_MACOS = 4
PER_APP_SCRIPTS = 15
PER_APP_HELPERS = 4
PER_PROJECT_OWN = 50
PER_PROJECT_DEPS = 30
WALK_LIMIT = 150_000


def _stable(p: str) -> str:
    return hashlib.sha1(p.encode("utf-8", "surrogateescape")).hexdigest()


def _is_file(p: str) -> bool:
    try:
        return os.path.isfile(p) and not os.path.islink(p)
    except OSError:
        return False


def _has_shebang(p: str) -> bool:
    try:
        with open(p, "rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


def _ext(p: str) -> str:
    b = os.path.basename(p).lower()
    return b.rsplit(".", 1)[-1] if "." in b else ""


# ------------------------------------------------------------------ file list
def _app_files(app: str, cat: str, out: list) -> None:
    contents = os.path.join(app, "Contents")
    macos = os.path.join(contents, "MacOS")
    try:
        for f in sorted(os.listdir(macos))[:PER_APP_MACOS]:
            p = os.path.join(macos, f)
            if _is_file(p):
                out.append((cat + "_main", p))
    except OSError:
        pass
    info = os.path.join(contents, "Info.plist")
    if _is_file(info):
        out.append((cat + "_plist", info))
    if cat != "apps":
        return
    helpers, scripts = [], []
    n = 0
    for dp, dn, fn in os.walk(contents):
        dn[:] = sorted(d for d in dn if d not in ("_CodeSignature",) and not d.endswith(".lproj"))
        for f in sorted(fn):
            n += 1
            if n > 20000:
                break
            p = os.path.join(dp, f)
            if dp == macos or p == info:
                continue
            if "/MacOS/" in p + "/" and dp.endswith("/MacOS") and _is_file(p):
                helpers.append(p)
            elif (_ext(p) in SCRIPT_EXT - {"js", "mjs", "cjs", "plist"} or
                  ("." not in f and "/Resources/" in p and _has_shebang(p))) and _is_file(p):
                scripts.append(p)
        if n > 20000:
            break
    out.extend((cat + "_helper", p) for p in sorted(helpers, key=_stable)[:PER_APP_HELPERS])
    out.extend((cat + "_script", p) for p in sorted(scripts, key=_stable)[:PER_APP_SCRIPTS])


def build_list() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    apps = sorted(set(glob.glob("/Applications/*.app") + glob.glob("/Applications/*/*.app")))
    for a in apps:
        _app_files(a, "apps", out)
    for a in sorted(glob.glob("/System/Applications/*.app") + glob.glob("/System/Applications/Utilities/*.app")):
        _app_files(a, "sysapps", out)
    seen = set()
    for f in sorted(os.listdir("/opt/homebrew/bin")) if os.path.isdir("/opt/homebrew/bin") else []:
        rp = os.path.realpath(os.path.join("/opt/homebrew/bin", f))
        if rp not in seen and os.path.isfile(rp):
            seen.add(rp)
            out.append(("homebrew_bin", rp))
    for f in sorted(os.listdir("/usr/bin")):
        p = os.path.join("/usr/bin", f)
        if _is_file(p) and _has_shebang(p):
            out.append(("usr_bin_script", p))
    for d, cap in (("/Library/LaunchAgents", 200), ("/Library/LaunchDaemons", 200),
                   (os.path.join(HOME, "Library/LaunchAgents"), 200),
                   ("/System/Library/LaunchAgents", 60), ("/System/Library/LaunchDaemons", 60)):
        try:
            names = sorted(os.listdir(d), key=lambda x: _stable(x))[:cap]
        except OSError:
            continue
        for f in names:
            p = os.path.join(d, f)
            if _is_file(p) and f.endswith(".plist"):
                out.append(("launchd_plist", p))
    # more real-world scripts: Homebrew's own code, Xcode / CLT tools, Application Support (installers,
    # updaters, browser extensions) – the places a full scan walks through
    for d, cap, exts in (("/opt/homebrew/Library/Homebrew", 150, {"sh", "bash", "zsh", "rb", "py"}),
                         ("/Applications/Xcode.app/Contents/Developer/usr/bin", 80, None),
                         ("/Library/Developer/CommandLineTools/usr/bin", 80, None),
                         ("/Library/Application Support", 150, SCRIPT_EXT - {"plist"}),
                         (os.path.join(HOME, "Library/Application Support"), 250, SCRIPT_EXT - {"plist"}),
                         ("/usr/libexec", 60, None), ("/usr/sbin", 40, None)):
        cands = []
        n = 0
        for dp, dn, fn in os.walk(d):
            dn[:] = sorted(x for x in dn if x not in (".git", "__pycache__", "Caches", "Cache", "CachedData"))
            for f in fn:
                n += 1
                p = os.path.join(dp, f)
                ok = (_ext(p) in exts) if exts else _has_shebang(p)
                if ok and _is_file(p):
                    try:
                        if os.path.getsize(p) <= (8 << 20):
                            cands.append(p)
                    except OSError:
                        pass
            if n > WALK_LIMIT:
                break
        out.extend(("extra_script", p) for p in sorted(cands, key=_stable)[:cap])
    docs = os.path.join(HOME, "Documents")
    for proj in sorted(os.listdir(docs)):
        pd = os.path.join(docs, proj)
        if proj in DOC_EXCLUDE or not os.path.isdir(pd) or os.path.islink(pd):
            continue
        own, deps = [], []
        n = 0
        for dp, dn, fn in os.walk(pd):
            dn[:] = sorted(d for d in dn if d not in (".git", "__pycache__", ".cache"))
            for f in fn:
                n += 1
                p = os.path.join(dp, f)
                e = _ext(p)
                if e not in SCRIPT_EXT or not _is_file(p):
                    continue
                try:
                    if os.path.getsize(p) > (8 << 20):
                        continue
                except OSError:
                    continue
                (deps if any(x in p for x in DEP_DIRS) else own).append(p)
            if n > WALK_LIMIT:
                break

        def pick(lst: list[str], k: int) -> list[str]:
            """Up to 2/3 shell/plist/AppleScript/Python files, the rest JavaScript; top up from either."""
            pri = sorted((p for p in lst if _ext(p) in PRIORITY_EXT), key=_stable)
            rest = sorted((p for p in lst if _ext(p) not in PRIORITY_EXT), key=_stable)
            first = pri[: (k * 2) // 3]
            sel = first + rest[: k - len(first)]
            return sel + pri[len(first): len(first) + k - len(sel)]
        out.extend(("docs_own", p) for p in pick(own, PER_PROJECT_OWN))
        out.extend(("docs_deps", p) for p in pick(deps, PER_PROJECT_DEPS))
    # de-duplicate by path, keep first category
    seen_p: set[str] = set()
    res = []
    for cat, p in out:
        if p not in seen_p:
            seen_p.add(p)
            res.append((cat, p))
    return res


# ------------------------------------------------------------------ engines
class _CombinedRules:
    """yara.bin minus Cerber's own namespaces + Cerber's rule files compiled from the working tree."""

    def __init__(self, bin_rules, own_rules, own_ns: set[str]):
        self.bin, self.own, self.own_ns = bin_rules, own_rules, own_ns

    def match(self, **kw):
        res = [m for m in self.bin.match(**kw) if m.namespace not in self.own_ns]
        if self.own is not None:
            res += list(self.own.match(**kw))
        return res


def make_yara():
    import yara
    from cerber import config
    from cerber.engines.yara_engine import EXTERNALS, YaraEngine, sanitize_source
    eng = YaraEngine(config.YARA_BIN, config.YARA_META, config.FP_CALIBRATION)
    sources, own_ns = {}, set()
    for tier, d in (("custom", "rules/custom"), ("community", "rules/experimental")):
        for p in sorted(glob.glob(os.path.join(ROOT, d, "*.yar"))):
            ns = f"{tier}:{os.path.basename(p)}"
            with open(p, encoding="utf-8", errors="replace") as fh:
                src, _removed = sanitize_source(fh.read())
            sources[ns] = src
            eng.tiers[ns] = tier
            own_ns.add(ns)
    own = yara.compile(sources=sources, externals=EXTERNALS) if sources else None
    eng.rules = _CombinedRules(eng.rules, own, own_ns)
    return eng


_PIPE = None


class _Timeout(Exception):
    pass


def _alarm(*_a):
    raise _Timeout()


def _init(engines_kind: str, macos: bool) -> None:
    global _PIPE
    from cerber.pipeline import Pipeline
    engines = [make_yara()] if engines_kind == "yara" else []
    _PIPE = Pipeline(engines=engines, options={"deep": True, "macos": macos})
    signal.signal(signal.SIGALRM, _alarm)
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _scan(item: tuple[str, str]) -> dict:
    cat, path = item
    t0 = time.time()
    rec = {"cat": cat, "path": path}
    try:
        signal.alarm(120)
        try:
            root = _PIPE.scan_file(path)
        finally:
            signal.alarm(0)
    except _Timeout:
        rec.update(verdict="TIMEOUT", score=0, dets=[], seconds=round(time.time() - t0, 1))
        return rec
    except Exception as exc:  # noqa: BLE001
        rec.update(verdict="ERROR", score=0, dets=[], error=repr(exc)[:200], seconds=round(time.time() - t0, 1))
        return rec
    dets = []
    for o in root.iter_tree():
        for d in o.detections:
            if d.score <= 0 and d.confidence.name not in ("CERTAIN",):
                continue
            dets.append([d.name, d.score, d.confidence.name, o.display_path.rsplit(">>", 1)[-1][-80:]])
    rec.update(verdict=root.meta["verdict"].name, score=root.meta.get("score", 0), primary=root.meta.get("primary"),
               ftype=root.ftype, trusted=root.meta.get("trusted_signer"), dets=dets,
               seconds=round(time.time() - t0, 2))
    return rec


def _run(items: list[tuple[str, str]], engines_kind: str, macos: bool, workers: int) -> list[dict]:
    out = []
    ctx = mp.get_context("fork")
    t0 = time.time()
    with ctx.Pool(workers, initializer=_init, initargs=(engines_kind, macos)) as pool:
        for i, r in enumerate(pool.imap_unordered(_scan, items, chunksize=2), 1):
            out.append(r)
            if i % 100 == 0 or i == len(items):
                print(f"  {i}/{len(items)}  {time.time() - t0:.0f}s", flush=True)
    out.sort(key=lambda r: r["path"])
    return out


# ------------------------------------------------------------------ modes
FLAG = ("SUSPICIOUS", "PUA", "MALICIOUS")


def _summary(recs: list[dict]) -> dict:
    by: dict = {}
    for r in recs:
        c = by.setdefault(r["cat"], {})
        c[r["verdict"]] = c.get(r["verdict"], 0) + 1
    return {"files": len(recs), "by_category": by,
            "flagged": sum(r["verdict"] in FLAG for r in recs), "info": sum(r["verdict"] == "INFO" for r in recs),
            "seconds_total": round(sum(r.get("seconds", 0) for r in recs), 1)}


def cmd_list(_a) -> None:
    items = build_list()
    with open(FILE_LIST, "w") as fh:
        json.dump({"built": time.strftime("%Y-%m-%d %H:%M:%S"), "files": items}, fh, indent=0, ensure_ascii=False)
    cats: dict = {}
    for c, _ in items:
        cats[c] = cats.get(c, 0) + 1
    print(f"{len(items)} files -> {FILE_LIST}\n{json.dumps(cats, indent=1)}")


def cmd_clean(a) -> None:
    with open(FILE_LIST) as fh:
        items = [tuple(x) for x in json.load(fh)["files"]]
    items = [x for x in items if os.path.exists(x[1])]
    print(f"scanning {len(items)} clean files (engines: {a.engines}, macos checks: {not a.no_macos})")
    recs = _run(items, a.engines, not a.no_macos, a.workers)
    summ = _summary(recs)
    fps = [{"path": r["path"], "verdict": r["verdict"], "score": r["score"],
            "dets": [d for d in r["dets"] if d[1] > 0][:12]} for r in recs if r["verdict"] in FLAG]
    infos = [{"path": r["path"], "score": r["score"], "dets": [d[0] for d in r["dets"] if d[1] > 0][:8]}
             for r in recs if r["verdict"] == "INFO"]
    res = {"label": a.label, "when": time.strftime("%Y-%m-%d %H:%M:%S"), "summary": summ, "false_positives": fps,
           "info": infos, "records": recs}
    p = os.path.join(RESULTS, f"clean-{a.label}.json")
    with open(p, "w") as fh:
        json.dump(res, fh, indent=1, ensure_ascii=False)
    print(json.dumps(summ, indent=1))
    for f in fps:
        print(f"  FP {f['verdict']:10} {f['score']:4}  {f['path']}\n       {[d[0] + ':' + str(d[1]) for d in f['dets']]}")
    print(f"-> {p}")


def _fixture_items() -> list[tuple[str, str]]:
    base = os.path.join(ROOT, "tests", "samples")
    items = []
    for dp, dn, fn in os.walk(base):
        dn.sort()
        for f in sorted(fn):
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, base)
            if f.startswith(".") or f.startswith("bomb_") or f in ("many60k.zip", "expected.json", "hello.c"):
                continue
            top = rel.split(os.sep)[0]
            if top == "archives":
                exp = "neutral"
            elif top == "executables" or f.startswith("clean") or rel == "hello.txt":
                exp = "clean"
            else:
                exp = "malicious"
            items.append((f"{exp}:{os.path.dirname(rel)}", p))
    return items


def cmd_fixtures(a) -> None:
    items = _fixture_items()
    res = {"label": a.label, "when": time.strftime("%Y-%m-%d %H:%M:%S"), "modes": {}}
    for mode in ("heur", "yara"):
        print(f"fixtures, engines={mode}: {len(items)} files")
        recs = _run(items, mode, False, a.workers)
        pos = [r for r in recs if r["cat"].startswith("malicious")]
        neg = [r for r in recs if r["cat"].startswith("clean")]
        order = ["CLEAN", "INFO", "SUSPICIOUS", "PUA", "MALICIOUS"]

        def rate(rs, lvl):
            return sum(1 for r in rs if r["verdict"] in order and order.index(r["verdict"]) >= order.index(lvl))
        groups: dict = {}
        for r in pos:
            g = r["cat"].split(":", 1)[1].split(os.sep)
            g = os.sep.join(g[:2]) if g[0] == "yara" else g[0]
            s = groups.setdefault(g, {"n": 0, "info+": 0, "suspicious+": 0, "malicious": 0})
            s["n"] += 1
            s["info+"] += rate([r], "INFO")
            s["suspicious+"] += rate([r], "SUSPICIOUS")
            s["malicious"] += r["verdict"] == "MALICIOUS"
        summ = {"positives": len(pos), "pos_info_plus": rate(pos, "INFO"), "pos_suspicious_plus": rate(pos, "SUSPICIOUS"),
                "pos_malicious": sum(r["verdict"] == "MALICIOUS" for r in pos),
                "negatives": len(neg), "neg_flagged": [r["path"] for r in neg if r["verdict"] in FLAG],
                "by_group": groups}
        res["modes"][mode] = {"summary": summ,
                              "records": [{k: r.get(k) for k in ("cat", "path", "verdict", "score", "primary")}
                                          | {"dets": [d[0] + ":" + str(d[1]) for d in r["dets"]][:15]} for r in recs]}
        print(json.dumps({k: v for k, v in summ.items() if k != "by_group"}, indent=1))
        for g, s in sorted(groups.items()):
            print(f"   {g:28} n={s['n']:3}  info+={s['info+']:3}  susp+={s['suspicious+']:3}  mal={s['malicious']:3}")
    p = os.path.join(RESULTS, f"fixtures-{a.label}.json")
    with open(p, "w") as fh:
        json.dump(res, fh, indent=1, ensure_ascii=False)
    print(f"-> {p}")


def cmd_compare(a) -> None:
    def load(kind, label):
        p = os.path.join(RESULTS, f"{kind}-{label}.json")
        return json.load(open(p)) if os.path.exists(p) else None
    for kind in ("fixtures", "clean"):
        b, c = load(kind, a.before), load(kind, a.after)
        if not b or not c:
            continue
        print(f"== {kind}: {a.before} -> {a.after}")
        if kind == "clean":
            print(f"   flagged {b['summary']['flagged']} -> {c['summary']['flagged']}, "
                  f"info {b['summary']['info']} -> {c['summary']['info']}")
            bm = {r["path"]: r for r in b["records"]}
            for r in c["records"]:
                o = bm.get(r["path"])
                if o and o["verdict"] != r["verdict"]:
                    print(f"   {o['verdict']:10} -> {r['verdict']:10} {r['path']}")
        else:
            for mode in c["modes"]:
                sb, sc = b["modes"][mode]["summary"], c["modes"][mode]["summary"]
                print(f"   [{mode}] positives {sc['positives']}: info+ {sb['pos_info_plus']} -> {sc['pos_info_plus']}, "
                      f"suspicious+ {sb['pos_suspicious_plus']} -> {sc['pos_suspicious_plus']}, "
                      f"malicious {sb['pos_malicious']} -> {sc['pos_malicious']}; "
                      f"clean fixtures flagged {len(sb['neg_flagged'])} -> {len(sc['neg_flagged'])}")


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    for name in ("clean", "fixtures"):
        p = sub.add_parser(name)
        p.add_argument("--label", required=True)
        p.add_argument("--workers", type=int, default=max(1, min(8, (os.cpu_count() or 2) - 1)))
        if name == "clean":
            p.add_argument("--engines", choices=("yara", "heur"), default="yara")
            p.add_argument("--no-macos", action="store_true")
    p = sub.add_parser("compare")
    p.add_argument("before")
    p.add_argument("after")
    a = ap.parse_args()
    os.makedirs(RESULTS, exist_ok=True)
    {"list": cmd_list, "clean": cmd_clean, "fixtures": cmd_fixtures, "compare": cmd_compare}[a.cmd](a)


if __name__ == "__main__":
    main()

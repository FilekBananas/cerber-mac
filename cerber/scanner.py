"""Scan orchestration: load engines once, fork workers, walk paths, aggregate results."""
from __future__ import annotations

import fnmatch
import gc
import json
import multiprocessing as mp
import os
import signal
import stat
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from . import config
from .dataless import NOT_MATERIALIZED, cloud_rank, is_dataless, never_materialize
from .core import Confidence, Limits, ScanObject, Verdict
from .pipeline import Pipeline

SKIP_DIRS = {"/dev", "/proc", "/System/Volumes", "/private/var/vm", "/Volumes/com.apple.TimeMachine.localsnapshots",
             "/private/var/db/uuidtext", "/private/var/db/diagnostics", "/.Spotlight-V100", "/.fseventsd",
             "/.DocumentRevisions-V100", "/private/var/folders/zz"}
SKIP_NAMES = {".Spotlight-V100", ".fseventsd", ".DocumentRevisions-V100", ".Trashes"}
# "patterns only" levels: engines + the analyzers that unpack containers or match indicator lists
PATTERN_ANALYZERS = {"archives", "email_extract", "asar", "exe_unpack", "ioc"}
LEVELS = ("quick", "patterns", "deep", "mega")


@dataclass
class ScanOptions:
    deep: bool = True
    workers: int = 0                     # 0 = auto
    max_file_size: int = 1024 << 20
    follow_symlinks: bool = False
    one_filesystem: bool = True
    exclude: list[str] = field(default_factory=list)
    macos_checks: bool = True
    ai: bool = False
    ai_all: bool = False
    quarantine: bool = False
    file_timeout: int = 600
    skip_sealed_system: bool = True      # /System is on the signed, read-only system volume
    level: str = "deep"                  # quick/patterns = signatures only, deep/mega = everything
    defer_ai: bool = False               # build AI context but let the caller run the model
    collect_cloud: bool = False          # Mega: list risky cloud-only files so the caller can fetch them
    cache: bool = False                  # skip files remembered as clean (cerber/scancache.py; quick/patterns only)
    cache_fp: str = ""                   # context fingerprint (hex) computed by the trusted parent
    cache_record: str = ""               # side file for the identities of files found CLEAN (merged by the parent)

    @property
    def patterns_only(self) -> bool:
        return self.level in ("quick", "patterns")


# ------------------------------------------------------------------ engines

# Signatures confirmed to misfire on legitimate software that the clean-corpus calibration
# (Apple system files + notarized apps in /Applications) never sees. Kept across database updates.
KNOWN_FP_SIGNATURES = {
    # an old Java applet exploit pattern; matches the Bun-compiled Claude Code CLI (Mach-O, signed by Anthropic)
    "PUA.Java.Exploit.CVE_2012_0501-1",
}


def load_engines(opts: ScanOptions, log: Callable[[str], None] = print) -> tuple[list, Any, dict]:
    from .engines.clamav import ClamAVEngine
    from .engines.hashdb import HashDB, HashEngine
    from .engines.ioc_fuzzy import FuzzyEngine, IocService
    from .engines.yara_engine import YaraEngine

    engines: list = []
    info: dict = {"missing": []}
    t0 = time.time()
    calib = {}
    if os.path.exists(config.FP_CALIBRATION):
        try:
            with open(config.FP_CALIBRATION) as fh:
                calib = json.load(fh)
        except (OSError, ValueError):
            calib = {}
    disabled = set(calib.get("disabled", [])) | set(KNOWN_FP_SIGNATURES)
    hdb = None
    if os.path.exists(config.HASHDB):
        hdb = HashDB(config.HASHDB)
        engines.append(HashEngine(hdb, set(calib.get("fp_sha256", []))))
        info["hashes"] = hdb.counts()
    else:
        info["missing"].append("hash")
    if os.path.exists(os.path.join(config.CLAMAV_COMPILED, "meta.json")):
        eng = ClamAVEngine(config.CLAMAV_COMPILED, disabled=disabled)
        eng.preload(skip_targets=(PE_TARGET,))      # built in scan_paths, only when Windows files can turn up
        engines.append(eng)
        info["clamav_signatures"] = eng.signature_count
        info["clamav_patterns"] = len(eng.pat_spec)
    else:
        info["missing"].append("clamav")
    if os.path.exists(config.YARA_BIN):
        y = YaraEngine(config.YARA_BIN, config.YARA_META, config.FP_CALIBRATION)
        engines.append(y)
        info["yara_rules"] = y.rule_count
        info["yara_disabled_fp"] = len(y.disabled)
    else:
        info["missing"].append("yara")
    if opts.deep and hdb is not None and info.get("hashes", {}).get("tlsh"):
        engines.append(FuzzyEngine(hdb))
    services = type("Services", (), {})()
    services.ioc = IocService(config.IOCDB) if os.path.exists(config.IOCDB) else None
    if services.ioc:
        info["ioc_indicators"] = services.ioc.count()
    info["load_seconds"] = round(time.time() - t0, 1)
    return engines, services, info


PE_TARGET = 1
# first bytes of Windows executables and of every container a Windows executable can be unpacked from
PE_HOLDER_MAGIC = (b"MZ", b"PK", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!", b"\xfd7zXZ", b"BZh", b"xar!",
                   b"\xd0\xcf\x11\xe0", b"MSCF", b"ISc(", b"\x78\xda", b"\x78\x9c", b"%PDF", b"\x28\xb5\x2f\xfd",
                   b"LZIP", b"\x5d\x00\x00", b"\xed\xab\xee\xdb", b"070707", b"0707", b"!<arch>", b"\x04\x22\x4d\x18",
                   b"\x1f\x9d")
PE_HOLDER_EXT = (".exe", ".dll", ".scr", ".sys", ".msi", ".cab", ".com", ".cpl", ".ocx", ".dmg", ".iso", ".img",
                 ".tar", ".eml", ".mbox", ".msg", ".asar", ".jar", ".apk", ".vhd", ".vhdx", ".wim", ".sparseimage",
                 ".sparsebundle", ".pkg", ".mpkg", ".zip", ".lnk", ".one", ".chm", ".hta", ".udf", ".nupkg", ".z", ".b64")
PE_PRECHECK_MAX = 40_000        # above this many files the 25 s build is small next to the scan anyway


def may_hold_windows_exe(files: list[str]) -> bool:
    """Can any of these files be – or contain – a Windows (PE) executable? Reads at most 8 bytes per file.
    A False here only defers the PE signatures: a worker still builds them the moment a PE object appears
    (e.g. one decoded out of a script), so this decides speed, never what is detected."""
    if len(files) > PE_PRECHECK_MAX:
        return True
    for f in files:
        if f.lower().endswith(PE_HOLDER_EXT):
            return True
        try:
            with open(f, "rb") as fh:
                head = fh.read(8)
        except OSError:
            continue
        if head.startswith(PE_HOLDER_MAGIC):
            return True
    return False


def total_patterns(info: dict) -> int:
    h = info.get("hashes", {})
    return (h.get("file", 0) + h.get("section", 0) + info.get("clamav_signatures", 0) + info.get("yara_rules", 0)
            + info.get("ioc_indicators", 0))


# ------------------------------------------------------------------ result conversion

def _jsonable(v: Any, depth: int = 0) -> Any:
    if depth > 6:
        return str(v)[:200]
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v if not isinstance(v, str) else v[:2000]
    if isinstance(v, bytes):
        return v[:200].decode("latin-1")
    if isinstance(v, dict):
        return {str(k): _jsonable(x, depth + 1) for k, x in list(v.items())[:200] if not str(k).startswith("_")}
    if isinstance(v, (list, tuple, set, frozenset)):
        return [_jsonable(x, depth + 1) for x in list(v)[:200]]
    if hasattr(v, "name") and hasattr(v, "value"):
        return v.name
    return str(v)[:200]


def result_dict(root: ScanObject, want_ai_context: bool) -> dict:
    dets = []
    for o in root.iter_tree():
        for d in o.detections:
            x = d.to_dict()
            x["object"] = o.display_path
            dets.append(x)
    verdict: Verdict = root.meta.get("verdict", Verdict.CLEAN)
    res = {
        "path": root.real_path or root.display_path,
        "verdict": verdict.name,
        "score": root.meta.get("score", 0),
        "primary": root.meta.get("primary"),
        "size": root.size,
        "ftype": root.ftype,
        "sha256": root.sha256,
        "objects": root.meta.get("objects", 1),
        "seconds": root.meta.get("scan_seconds"),
        "detections": dets,
        "errors": [f"{o.display_path.rsplit('>>', 1)[-1]}: {e}" for o in root.iter_tree() for e in o.errors][:30],
    }
    if verdict >= Verdict.INFO:
        res["meta"] = _jsonable({k: v for k, v in root.meta.items()
                                 if k not in ("verdict", "score", "primary", "objects", "scan_seconds")})
        res["tree"] = [{"path": o.display_path, "type": o.ftype, "size": o.size, "sha256": o.sha256,
                        "kind": o.kind, "detections": len(o.detections)}
                       for o in root.iter_tree() if o.detections or o is root][:100]
    res["ai_context"] = None
    if want_ai_context and verdict in (Verdict.INFO, Verdict.SUSPICIOUS, Verdict.MALICIOUS, Verdict.PUA):
        from .engines.ai import build_ai_context
        try:
            res["ai_context"] = build_ai_context(root)
        except Exception as exc:  # noqa: BLE001
            res["errors"].append(f"ai_context: {exc!r}")
    return res


# ------------------------------------------------------------------ workers

_PIPE: Pipeline | None = None
_WANT_AI = False
_RECORD_IDS = False             # take each file's identity before scanning it (scan memory, see scancache)


class _FileTimeout(Exception):
    pass


def _alarm(_sig, _frm):
    raise _FileTimeout()


def _init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGALRM, _alarm)


def _identity(path: str) -> list[int] | None:
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns] if stat.S_ISREG(st.st_mode) else None


def _scan_one(args: tuple[str, int]) -> dict:
    path, timeout = args
    t0 = time.time()
    try:
        ident = _identity(path) if _RECORD_IDS else None      # before reading: a later change bumps ctime
        signal.alarm(timeout)
        try:
            root = _PIPE.scan_file(path)
        finally:
            signal.alarm(0)
        res = result_dict(root, _WANT_AI)
        if ident is not None:
            res["_id"] = ident
        return res
    except _FileTimeout:
        return {"path": path, "verdict": "CLEAN", "score": 0, "detections": [], "size": 0, "objects": 0,
                "errors": [f"timeout po {timeout}s – plik przeskanowany częściowo"], "ai_context": None,
                "seconds": round(time.time() - t0, 1), "timeout": True}
    except (OSError, MemoryError) as exc:
        msg = ("plik tylko w chmurze (iCloud itp.) – nie pobrano" if getattr(exc, "errno", None) in NOT_MATERIALIZED
               else f"nie można odczytać: {exc}")
        return {"path": path, "verdict": "CLEAN", "score": 0, "detections": [], "size": 0, "objects": 0,
                "errors": [msg], "ai_context": None, "unreadable": True}
    except Exception as exc:  # noqa: BLE001
        return {"path": path, "verdict": "CLEAN", "score": 0, "detections": [], "size": 0, "objects": 0,
                "errors": [f"błąd skanera: {exc!r}"], "ai_context": None}


# ------------------------------------------------------------------ walking

CLOUD_LIST_MAX = 20000          # risky cloud-only files / unlisted cloud folders remembered for Mega's fetch step

def iter_files(paths: list[str], opts: ScanOptions, skipped: list[str],
               stats: dict | None = None, on_dir: Callable[[str], None] | None = None,
               skip: Callable[[str, os.stat_result], bool] | None = None) -> Iterator[str]:
    """Regular files under `paths`. Cloud-only placeholders (iCloud Drive etc.) are counted in
    stats["cloud_only"] and never listed or opened – that would download them. With opts.collect_cloud the
    risky ones go to stats["cloud_files"] ([path, size, rank]) and unlisted folders to stats["cloud_dirs"].
    `skip(path, stat)`: True leaves the file out (scan memory hit; the walk's own stat, no extra syscall)."""
    never_materialize()
    if stats is None:
        stats = {}
    stats.setdefault("cloud_only", 0)
    cloud_files = stats.setdefault("cloud_files", [])
    cloud_dirs = stats.setdefault("cloud_dirs", [])

    def cloud(p: str, st) -> None:
        stats["cloud_only"] += 1
        if not opts.collect_cloud:
            return
        if stat.S_ISDIR(st.st_mode):
            if len(cloud_dirs) < CLOUD_LIST_MAX:
                cloud_dirs.append(p)
        elif stat.S_ISREG(st.st_mode) and len(cloud_files) < CLOUD_LIST_MAX:
            rank = cloud_rank(p, st.st_mode)
            if rank is not None:
                cloud_files.append([p, st.st_size, rank])
    seen_inodes: set[tuple[int, int]] = set()
    for top in paths:
        top = os.path.abspath(os.path.expanduser(top))
        try:
            st = os.stat(top) if opts.follow_symlinks else os.lstat(top)
        except OSError as exc:
            skipped.append(f"{top}: {exc}")
            continue
        if is_dataless(st):
            cloud(top, st)
            continue
        if stat.S_ISREG(st.st_mode):
            if skip is None or not skip(top, st):
                yield top
            continue
        if not stat.S_ISDIR(st.st_mode):
            continue
        dev0 = st.st_dev
        stack = [top]
        while stack:
            d = stack.pop()
            if d in SKIP_DIRS or (opts.skip_sealed_system and d == "/System" and top != "/System"):
                continue
            if any(fnmatch.fnmatch(d, pat) for pat in opts.exclude):
                continue
            if on_dir:
                on_dir(d)
            try:
                it = os.scandir(d)
            except OSError as exc:
                if exc.errno in NOT_MATERIALIZED:
                    stats["cloud_only"] += 1
                    if opts.collect_cloud and len(cloud_dirs) < CLOUD_LIST_MAX:
                        cloud_dirs.append(d)
                    continue
                skipped.append(f"{d}: {exc.strerror or exc}")
                continue
            subdirs = []
            with it:
                for e in it:
                    if e.name in SKIP_NAMES:
                        continue
                    p = e.path
                    try:
                        if e.is_symlink() and not opts.follow_symlinks:
                            continue
                        est = e.stat(follow_symlinks=opts.follow_symlinks)
                    except OSError:
                        continue
                    if is_dataless(est):
                        cloud(p, est)
                        continue
                    if stat.S_ISDIR(est.st_mode):
                        if opts.one_filesystem and est.st_dev != dev0:
                            continue
                        key = (est.st_dev, est.st_ino)
                        if key in seen_inodes:
                            continue
                        seen_inodes.add(key)
                        subdirs.append(p)
                    elif stat.S_ISREG(est.st_mode):
                        if opts.exclude and any(fnmatch.fnmatch(p, pat) for pat in opts.exclude):
                            continue
                        if est.st_size == 0:
                            continue
                        if skip is not None and skip(p, est):
                            continue
                        yield p
            stack.extend(reversed(subdirs))


# ------------------------------------------------------------------ main entry

class Progress:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled and sys.stderr.isatty()
        self.last = 0.0

    def update(self, done: int, total: int | None, nbytes: int, t0: float, flagged: int, current: str = "") -> None:
        if not self.enabled:
            return
        now = time.time()
        if now - self.last < 0.25 and total != done:
            return
        self.last = now
        el = max(0.001, now - t0)
        tot = f"/{total}" if total else ""
        cur = current[-60:]
        sys.stderr.write(f"\r\033[K  {done}{tot} plików · {nbytes / 1e6:,.0f} MB · {nbytes / 1e6 / el:,.1f} MB/s · "
                         f"wykryte: {flagged} · {cur}")
        sys.stderr.flush()

    def done(self) -> None:
        if self.enabled:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()


def scan_paths(paths: list[str], opts: ScanOptions, log: Callable[[str], None] = print,
               engines_bundle: tuple | None = None, progress: bool = True,
               on_result: Callable[[dict], None] | None = None,
               on_progress: Callable[[dict], None] | None = None) -> dict:
    global _PIPE, _WANT_AI, _RECORD_IDS
    from .analyzers import load_all

    started = time.strftime("%Y-%m-%d %H:%M:%S")
    t0 = time.time()
    if engines_bundle is None:
        log("Ładowanie baz sygnatur …")
        engines_bundle = load_engines(opts, log)
    engines, services, info = engines_bundle
    if info.get("missing"):
        log(f"UWAGA: brak baz: {', '.join(info['missing'])} – uruchom `cerber update`")
    analyzers = load_all()
    deep, macos = opts.deep, opts.macos_checks
    if opts.patterns_only:
        analyzers = [a for a in analyzers if a.name in PATTERN_ANALYZERS]
        engines = [e for e in engines if e.name != "fuzzy"]
        deep = macos = False
    limits = Limits(max_file_size=opts.max_file_size)
    _PIPE = Pipeline(engines=engines, analyzers=analyzers, limits=limits, services=services,
                     options={"deep": deep, "macos": macos, "tools": config.tools()})
    _WANT_AI = opts.ai or opts.ai_all or opts.defer_ai
    log(f"Silniki: {', '.join(e.name for e in engines)} · analizatory: {len(analyzers)} · "
        f"wzorce/sygnatury: {total_patterns(info):,}")

    skipped: list[str] = []
    walk_stats: dict = {}
    files = []
    last_dir = [0.0]
    # scan memory (cerber/scancache.py): only the signature levels; the child reads, the parent writes
    use_cache = opts.cache and opts.patterns_only
    lookup = recorder = None
    if use_cache:
        from . import scancache
        try:
            fp = bytes.fromhex(opts.cache_fp) if opts.cache_fp else scancache.context_fingerprint(opts)
            lookup = scancache.Lookup(fp) if len(fp) == 16 else None
        except (OSError, ValueError) as exc:
            log(f"Pamięć skanów niedostępna: {exc}")
        if opts.cache_record and not info.get("missing"):
            try:
                recorder = scancache.Recorder(opts.cache_record)
            except OSError as exc:
                log(f"Pamięć skanów: nie można zapisać listy sprawdzonych plików: {exc}")

    def on_dir(d: str) -> None:
        now = time.time()
        if on_progress and now - last_dir[0] > 0.5:
            last_dir[0] = now
            on_progress({"stage": "enumerate", "found": len(files), "current": d})

    for f in iter_files(paths, opts, skipped, walk_stats, on_dir, skip=lookup.hit if lookup else None):
        files.append(f)
    cache_hits = lookup.hits if lookup else 0
    if lookup is not None and lookup.bad:
        log(f"Pamięć skanów: odrzucono {lookup.bad:,} wpisów z nieprawidłowym podpisem (HMAC) – pliki skanuję")
    lookup = None                           # free the rows before the workers fork
    total_bytes = 0
    if cache_hits:
        log(f"Pominięto {cache_hits:,} niezmienionych plików (już sprawdzone, pamięć skanów)")
    log(f"Do przeskanowania: {len(files):,} plików")
    if walk_stats["cloud_only"]:
        log(f"Pominięto {walk_stats['cloud_only']:,} elementów tylko w chmurze (iCloud itp.) – nie ma ich na dysku")

    workers = opts.workers or max(1, min(8, (os.cpu_count() or 4) - 1))
    results_flagged: list[dict] = []
    counts = {v.name: 0 for v in Verdict}
    errors: list[str] = []
    timeouts = 0
    objects = 0
    prog = Progress(progress)
    done = 0
    last_cb = 0.0

    def handle(r: dict) -> None:
        nonlocal total_bytes, objects, done, timeouts, last_cb
        ident = r.pop("_id", None)
        if recorder is not None and ident is not None and scancache.result_cacheable(r):
            recorder.add(r["path"], ident)
        done += 1
        total_bytes += r.get("size", 0) or 0
        objects += r.get("objects", 0) or 0
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        if r.get("timeout"):
            timeouts += 1
        if r.get("errors") and len(errors) < 500:
            errors.extend(f"{r['path']}: {e}" for e in r["errors"][:3])
        if r["verdict"] != "CLEAN":
            results_flagged.append(r)
            if on_result:
                on_result(r)
        prog.update(done, len(files), total_bytes, t0, len(results_flagged), r["path"])
        now = time.time()
        if on_progress and (now - last_cb > 0.2 or done == len(files)):
            last_cb = now
            el = max(0.001, now - t0)
            on_progress({"stage": "scan", "done": done, "total": len(files), "bytes": total_bytes,
                         "rate_mbs": round(total_bytes / 1e6 / el, 1), "flagged": len(results_flagged),
                         "current": r["path"], "eta_s": int(el / done * (len(files) - done)) if done > 20 else None})

    jobs = [(f, opts.file_timeout) for f in files]
    _RECORD_IDS = recorder is not None
    try:
        _run_jobs(jobs, files, workers, engines, info, handle, prog, log)
    finally:
        _RECORD_IDS = False
        if recorder is not None:
            recorder.close()                # flushed even when the scan is interrupted
    prog.done()

    counts["CLEAN"] = counts.get("CLEAN", 0) + cache_hits
    report = {
        "started": started,
        "finished": time.strftime("%Y-%m-%d %H:%M:%S"),
        "seconds": round(time.time() - t0, 1),
        "paths": paths,
        "options": {k: v for k, v in opts.__dict__.items()},
        "databases": info,
        "patterns_total": total_patterns(info),
        "files": done + cache_hits,
        "cache_hits": cache_hits,
        "cancelled": done < len(files),
        "bytes": total_bytes,
        "objects": objects,
        "counts": counts,
        "timeouts": timeouts,
        "skipped": skipped[:200],
        "skipped_count": len(skipped),
        "cloud_only": walk_stats["cloud_only"],
        **({"cloud_candidates": walk_stats["cloud_files"], "cloud_dirs": walk_stats["cloud_dirs"]}
           if opts.collect_cloud else {}),
        "errors": errors[:200],
        "results": sorted(results_flagged, key=lambda r: (["CLEAN", "INFO", "SUSPICIOUS", "PUA", "MALICIOUS"]
                                                          .index(r["verdict"]), r.get("score", 0)), reverse=True),
    }
    if (opts.ai or opts.ai_all) and not opts.defer_ai:
        run_ai(report, opts, log)
        report["counts"] = {v.name: 0 for v in Verdict}
        report["counts"]["CLEAN"] = report["files"] - len(report["results"])
        for r in report["results"]:
            report["counts"][r["verdict"]] += 1
    if not opts.defer_ai:
        for r in report["results"]:
            r.pop("ai_context", None)
    if opts.quarantine:
        from .quarantine import quarantine_file
        from .verdict import ml_decisive
        for r in report["results"]:
            if r["verdict"] == "MALICIOUS" and not ml_decisive(r) and os.path.isfile(r["path"]):
                try:
                    r["quarantined"] = quarantine_file(r["path"], r)
                except OSError as exc:
                    r["quarantine_error"] = str(exc)
    return report


def _run_jobs(jobs: list, files: list[str], workers: int, engines: list, info: dict,
              handle: Callable[[dict], None], prog: Progress, log: Callable[[str], None]) -> None:
    if workers <= 1 or len(files) < 4:
        _init_worker_main()
        for j in jobs:
            handle(_scan_one(j))
    else:
        clam = next((e for e in engines if getattr(e, "name", "") == "clamav"), None)
        if clam is not None and PE_TARGET in clam.pending_targets() and may_hold_windows_exe(files):
            t1 = time.time()
            log("Ładowanie sygnatur plików Windows (.exe) …")
            clam.preload()                 # before the fork: one shared copy instead of one per worker
            info["load_seconds"] = round(info.get("load_seconds", 0) + time.time() - t1, 1)
        gc.collect()
        gc.freeze()  # keep the huge signature structures shared (copy-on-write friendly)
        ctx = mp.get_context("fork")
        with ctx.Pool(workers, initializer=_init_worker) as pool:
            try:
                for r in pool.imap_unordered(_scan_one, jobs, chunksize=2):
                    handle(r)
            except KeyboardInterrupt:
                pool.terminate()
                prog.done()
                log("Przerwano – raport zawiera wyniki częściowe.")
        gc.unfreeze()


def merge_reports(base: dict, extra: dict) -> dict:
    """Add a follow-up scan (same options) to a finished report, in place."""
    seen = {r["path"] for r in base.get("results", [])}
    for r in extra.get("results", []):
        if r["path"] not in seen:
            base.setdefault("results", []).append(r)
            seen.add(r["path"])
    for k in ("files", "bytes", "objects", "timeouts", "skipped_count", "cloud_only", "cache_hits"):
        base[k] = (base.get(k) or 0) + (extra.get(k) or 0)
    counts = {v.name: 0 for v in Verdict}            # recount: a program may have been in the main scan already
    for r in base.get("results", []):
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    counts["CLEAN"] = max(0, base["files"] - sum(n for k, n in counts.items() if k != "CLEAN"))
    base["counts"] = counts
    base["errors"] = (base.get("errors") or []) + (extra.get("errors") or [])[:50]
    return base


def _init_worker_main():
    try:
        signal.signal(signal.SIGALRM, _alarm)
    except ValueError:
        pass


def run_ai(report: dict, opts: ScanOptions, log: Callable[[str], None]) -> None:
    from .engines.ai import AIAnalyst, apply_ai, wants_ai
    todo = [r for r in report["results"] if wants_ai(r, opts.ai_all)]
    if not todo:
        log("AI: brak plików w szarej strefie do analizy")
        return
    log(f"AI: analiza {len(todo)} plików lokalnym modelem …")
    try:
        analyst = AIAnalyst(log=log)
    except Exception as exc:  # noqa: BLE001
        log(f"AI niedostępne: {exc}")
        report["ai_error"] = str(exc)
        return
    try:
        for i, r in enumerate(todo, 1):
            try:
                ai = analyst.verify(r)
                if ai is None:
                    continue
                apply_ai(r, ai)
                accs = ai.get("accusations") or []
                tally = ", ".join(f"{sum(1 for x in accs if x['verdict'] == v)} {pl}" for v, pl in
                                  (("confirmed", "trafne"), ("refuted", "chybione"), ("unsure", "niepewne")))
                log(f"  [{i}/{len(todo)}] {os.path.basename(r['path'])}: AI – zarzuty: {tally}; "
                    f"rodzina: {ai.get('family') or ai.get('family_match')} ({ai.get('confidence', 0):.2f}"
                    f"{'' if ai.get('agree') else ', niezgodne odpowiedzi'}) → {ai.get('points', 0):+d} pkt "
                    f"{ai.get('summary_pl', '')[:120]}")
            except Exception as exc:  # noqa: BLE001
                r.setdefault("errors", []).append(f"AI: {exc!r}")
    finally:
        analyst.stop()


def save_json(report: dict, path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(report, fh, indent=1, ensure_ascii=False, default=str)
    return path

"""Cerber command line interface."""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import time

from . import config

BANNER = r"""
   ____          _
  / ___|___ _ __| |__   ___ _ __   ciężki skaner antywirusowy dla macOS
 | |   / _ \ '__| '_ \ / _ \ '__|  sygnatury ClamAV · MalwareBazaar · YARA · XProtect
 | |__|  __/ |  | |_) |  __/ |     heurystyki · deobfuskacja · środowisko · AI (lokalnie)
  \____\___|_|  |_.__/ \___|_|
"""

DEFAULT_FULL_PATHS = ["~/Downloads", "~/Desktop", "~/Documents", "~/Library/LaunchAgents",
                      "~/Library/Application Support", "/Library/LaunchAgents", "/Library/LaunchDaemons",
                      "/Library/Application Support", "/Applications", "/Users/Shared", "/tmp", "/private/var/tmp",
                      "/usr/local", "/opt/homebrew/bin"]


def _log(msg: str) -> None:
    print(msg, flush=True)


def _stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _opts_from_args(a) -> "ScanOptions":
    from .scanner import ScanOptions
    o = ScanOptions()
    o.deep = not getattr(a, "fast", False)
    o.workers = getattr(a, "workers", 0) or 0
    o.ai = getattr(a, "ai", False)
    o.ai_all = getattr(a, "ai_all", False)
    o.quarantine = getattr(a, "quarantine", False)
    o.exclude = getattr(a, "exclude", None) or []
    o.macos_checks = not getattr(a, "no_macos", False)
    if getattr(a, "max_size", None):
        o.max_file_size = int(a.max_size) << 20
    if getattr(a, "timeout", None):
        o.file_timeout = int(a.timeout)
    o.follow_symlinks = getattr(a, "follow_symlinks", False)
    o.skip_sealed_system = not getattr(a, "include_system", False)
    return o


def _write_reports(report: dict, a, env: dict | None, prefix: str) -> None:
    from .report import print_console, write_html
    from .scanner import save_json
    if env is not None:
        report["environment"] = env
    print_console(report, show_info=getattr(a, "show_info", False), env=env)
    base = os.path.join(config.REPORTS, f"{prefix}-{_stamp()}")
    jp = save_json(report, getattr(a, "json", None) or base + ".json")
    hp = write_html(report, getattr(a, "html", None) or base + ".html", env)
    print(f" Raporty: {jp}\n          {hp}")


def _env_to_dict(rep) -> dict:
    def fd(f):
        d = f.detection
        return {"category": f.category, "title": f.title, "location": f.location, "name": d.name,
                "engine": d.engine, "confidence": d.confidence.name, "score": d.score,
                "description": d.description, "pua": d.pua,
                "details": json.loads(json.dumps(f.details, default=str)) if f.details else {}}
    return {"findings": [fd(f) for f in rep.findings], "targets": list(rep.targets),
            "posture": json.loads(json.dumps(rep.posture, default=str)),
            "inventory": json.loads(json.dumps(rep.inventory, default=str)),
            "limitations": list(rep.limitations)}


def cmd_scan(a) -> int:
    from .scanner import scan_paths
    print(BANNER)
    opts = _opts_from_args(a)
    report = scan_paths(a.paths, opts, log=_log)
    _write_reports(report, a, None, "scan")
    return 2 if report["counts"].get("MALICIOUS") else (1 if report["counts"].get("SUSPICIOUS") else 0)


def run_env(a, log=_log) -> dict | None:
    try:
        from .envscan import scan_environment
    except ImportError as exc:
        log(f"Skaner środowiska niedostępny: {exc}")
        return None
    log("Skanowanie środowiska (autostart, procesy, sieć, rozszerzenia, ustawienia bezpieczeństwa) …")
    t0 = time.time()
    rep = scan_environment({"deep": not getattr(a, "fast", False)}, progress=lambda m: log(f"  · {m}"))
    env = _env_to_dict(rep)
    env["seconds"] = round(time.time() - t0, 1)
    log(f"Środowisko: {len(env['findings'])} znalezisk, {len(env['targets'])} plików do głębokiego skanu "
        f"({env['seconds']} s)")
    return env


def cmd_env(a) -> int:
    from .scanner import scan_paths
    print(BANNER)
    env = run_env(a)
    if env is None:
        return 3
    opts = _opts_from_args(a)
    targets = [] if a.no_files else env["targets"]
    report = scan_paths(targets, opts, log=_log) if targets else _empty_report()
    _write_reports(report, a, env, "env")
    bad = any(f["score"] >= 50 for f in env["findings"])
    return 2 if report["counts"].get("MALICIOUS") or bad else 0


def cmd_full(a) -> int:
    from .scanner import scan_paths
    print(BANNER)
    env = run_env(a)
    paths = [os.path.expanduser(p) for p in (a.paths or DEFAULT_FULL_PATHS)]
    paths = [p for p in paths if os.path.exists(p)]
    if env:
        paths += [t for t in env["targets"] if not any(t.startswith(p + "/") for p in paths)]
    opts = _opts_from_args(a)
    report = scan_paths(paths, opts, log=_log)
    _write_reports(report, a, env, "full")
    return 2 if report["counts"].get("MALICIOUS") else 0


def _empty_report() -> dict:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    return {"started": now, "finished": now, "seconds": 0, "files": 0, "bytes": 0, "objects": 0,
            "counts": {k: 0 for k in ("CLEAN", "INFO", "SUSPICIOUS", "PUA", "MALICIOUS")}, "results": [],
            "patterns_total": 0, "databases": {}}


def cmd_update(a) -> int:
    from .updater import calibrate, update_all
    print(BANNER)
    if a.calibrate_only:
        calibrate(_log, max_files=a.calibrate_files)
        return 0
    if a.yara_offline:          # recompile local YARA rules only (after editing rules/custom), no downloads
        from .updater import update_yara
        update_yara(_log, offline=True)
        return cmd_info(a)
    if a.only_mac_hashes:       # add macOS hashes to the existing hashes.sqlite without the full update
        from .feeds_macos import refresh_only
        refresh_only(_log)
        return cmd_info(a)
    if a.only_ios:              # rebuild only the iPhone indicator DB (ios_ioc.sqlite)
        from .feeds_ios import format_table, update_ios_indicators
        st = update_ios_indicators(_log)
        if st.get("total"):
            print(format_table(st))
        return 0 if st.get("total") else 1
    update_all(_log, clamav=not a.no_clamav, bazaar=not a.no_bazaar, sigbase=not a.no_sigbase,
               yara_rules=not a.no_yara, ioc=not a.no_ioc, calib=not a.no_calibrate,
               machashes=not a.no_machashes, ios=not a.no_ios)
    return cmd_info(a)


def cmd_info(a) -> int:
    from .scanner import ScanOptions, load_engines, total_patterns
    _, _, info = load_engines(ScanOptions(deep=True), _log)
    h = info.get("hashes", {})
    print("Bazy Cerbera:")
    print(f"  ClamAV sygnatury bajtowe/logiczne : {info.get('clamav_signatures', 0):>12,}  "
          f"(wzorców: {info.get('clamav_patterns', 0):,})")
    print(f"  hashe plików (ClamAV+Bazaar+IOC)  : {h.get('file', 0):>12,}")
    print(f"  hashe sekcji PE (ClamAV .mdb)     : {h.get('section', 0):>12,}")
    print(f"  TLSH (podobieństwo, MalwareBazaar) : {h.get('tlsh', 0):>12,}")
    print(f"  biała lista (fałszywe alarmy)     : {h.get('fp', 0):>12,}")
    print(f"  reguły YARA (Forge+XProtect+Cerber): {info.get('yara_rules', 0):>12,}  "
          f"(wyłączone po kalibracji: {info.get('yara_disabled_fp', 0)})")
    print(f"  wskaźniki IOC (URL/domeny/IP)     : {info.get('ioc_indicators', 0):>12,}")
    print(f"  RAZEM wzorców/sygnatur            : {total_patterns(info):>12,}")
    if info.get("missing"):
        print(f"  brakujące bazy: {', '.join(info['missing'])} → uruchom: ./cerber update")
    try:
        from .llm import find_default_model
        m = find_default_model()
        print(f"  model AI: {m or 'brak (ustaw CERBER_LLM_MODEL)'}")
    except Exception as exc:  # noqa: BLE001
        print(f"  model AI: niedostępny ({exc})")
    print(f"  czas ładowania baz: {info.get('load_seconds')} s")
    return 0


def cmd_quarantine(a) -> int:
    from . import quarantine as q
    if a.action == "list":
        items = q.list_quarantine()
        if not items:
            print("Kwarantanna jest pusta.")
        for m in items:
            print(f"{m['id']}  {m['quarantined']}  {m.get('primary') or '-'}  {m['original_path']}")
    elif a.action == "restore":
        print("Przywrócono do:", q.restore(a.id, a.to))
    elif a.action == "delete":
        q.delete(a.id)
        print("Usunięto", a.id)
    return 0


def cmd_selftest(a) -> int:
    """EICAR + bundled inert samples: verifies that every engine is wired up."""
    import tempfile
    from .scanner import ScanOptions, scan_paths
    d = tempfile.mkdtemp(prefix="cerber-selftest-")
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with open(os.path.join(d, "eicar.com"), "wb") as fh:
        fh.write(eicar)
    import zipfile
    with zipfile.ZipFile(os.path.join(d, "eicar_in_zip.zip"), "w") as z:
        z.writestr("folder/inner.txt", eicar)
    with open(os.path.join(d, "clean.txt"), "w") as fh:
        fh.write("zwykły plik tekstowy\n")
    samples = os.path.join(config.ROOT, "tests", "samples")
    paths = [d] + ([samples] if a.samples and os.path.isdir(samples) else [])
    rep = scan_paths(paths, ScanOptions(deep=True, workers=a.workers or 0), log=_log)
    from .report import print_console
    print_console(rep)
    ok = sum(1 for r in rep["results"] if "eicar" in r["path"] and r["verdict"] == "MALICIOUS")
    print(f"EICAR wykryty w {ok}/2 plikach testowych → {'OK' if ok == 2 else 'BŁĄD'}")
    return 0 if ok == 2 else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cerber", description="Cerber – ciężki skaner antywirusowy dla macOS")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def scan_flags(p, paths=True):
        if paths:
            p.add_argument("paths", nargs="*" if p.prog.endswith("full") else "+", help="pliki / katalogi")
        p.add_argument("--fast", action="store_true", help="bez TLSH i najcięższych analiz")
        p.add_argument("--ai", action="store_true", help="analiza szarej strefy lokalnym modelem AI")
        p.add_argument("--ai-all", action="store_true", help="AI dla każdego pliku z jakimkolwiek znaleziskiem")
        p.add_argument("--workers", type=int, default=0, help="liczba procesów (domyślnie: rdzenie-1, max 8)")
        p.add_argument("--quarantine", action="store_true", help="przenieś ZŁOŚLIWE pliki do kwarantanny")
        p.add_argument("--exclude", action="append", help="wzorzec glob do pominięcia (wielokrotnie)")
        p.add_argument("--max-size", type=int, help="maks. rozmiar pliku w MB (domyślnie 1024)")
        p.add_argument("--timeout", type=int, help="limit czasu na plik w sekundach (domyślnie 600)")
        p.add_argument("--follow-symlinks", action="store_true")
        p.add_argument("--include-system", action="store_true", help="skanuj też zapieczętowany wolumin /System")
        p.add_argument("--no-macos", action="store_true", help="bez codesign/spctl/xattr")
        p.add_argument("--show-info", action="store_true", help="pokaż też znaleziska informacyjne")
        p.add_argument("--json", help="ścieżka raportu JSON")
        p.add_argument("--html", help="ścieżka raportu HTML")

    p = sub.add_parser("scan", help="skanuj pliki/katalogi")
    scan_flags(p)
    p.set_defaults(fn=cmd_scan)
    p = sub.add_parser("env", help="skanuj środowisko systemu (autostart, procesy, sieć, rozszerzenia …)")
    scan_flags(p, paths=False)
    p.add_argument("--no-files", action="store_true", help="bez głębokiego skanu plików znalezionych w środowisku")
    p.set_defaults(fn=cmd_env)
    p = sub.add_parser("full", help="środowisko + katalogi użytkownika i aplikacje")
    scan_flags(p)
    p.set_defaults(fn=cmd_full)
    p = sub.add_parser("update", help="pobierz i zbuduj bazy sygnatur")
    for flag in ("clamav", "bazaar", "sigbase", "yara", "ioc", "calibrate"):
        p.add_argument(f"--no-{flag}", action="store_true")
    p.add_argument("--calibrate-only", action="store_true")
    p.add_argument("--no-machashes", action="store_true", help="bez hashy macOS (ThreatFox osx.*, ESET, CIRCL, OTX)")
    p.add_argument("--only-mac-hashes", action="store_true", help="tylko dodaj hashe macOS do istniejącej bazy")
    p.add_argument("--no-ios", action="store_true",
                   help="bez wskaźników szpiegostwa iPhone (MVT, Amnesty, Echap, Citizen Lab)")
    p.add_argument("--only-ios", action="store_true", help="tylko przebuduj bazę wskaźników iPhone (ios_ioc.sqlite)")
    p.add_argument("--yara-offline", action="store_true", help="tylko przebuduj reguły YARA z plików lokalnych")
    p.add_argument("--calibrate-files", type=int, default=25000)
    p.set_defaults(fn=cmd_update)
    p = sub.add_parser("info", help="statystyki baz")
    p.set_defaults(fn=cmd_info)
    p = sub.add_parser("quarantine", help="zarządzanie kwarantanną")
    p.add_argument("action", choices=["list", "restore", "delete"])
    p.add_argument("id", nargs="?")
    p.add_argument("--to", help="restore: ścieżka docelowa")
    p.set_defaults(fn=cmd_quarantine)
    p = sub.add_parser("selftest", help="test działania (EICAR)")
    p.add_argument("--samples", action="store_true", help="skanuj też próbki testowe z tests/samples")
    p.add_argument("--workers", type=int, default=0)
    p.set_defaults(fn=cmd_selftest)
    from .watch import add_parser as watch_parser
    watch_parser(sub)

    a = ap.parse_args(argv)
    config.ensure_dirs()
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())

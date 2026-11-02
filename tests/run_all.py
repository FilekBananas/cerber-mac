"""Run every Cerber regression test in one go.

    .venv/bin/python tests/run_all.py [--quick]

Checks: analyzer loading, script/archive/network-audit (+ deep audit) unit tests, document/script sample
verdicts, YARA packs (compile + positive coverage), ClamAV signature
round-trip, EICAR selftest through the full engine stack.
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PY = sys.executable


def run(name: str, args: list[str], ok_marker: str | None = None, timeout: int = 3600) -> bool:
    t0 = time.time()
    p = subprocess.run([PY, *args], cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    out = p.stdout + p.stderr
    ok = p.returncode == 0 and (ok_marker is None or ok_marker in out)
    tail = "\n      ".join(out.strip().splitlines()[-3:])
    print(f"[{'OK ' if ok else 'FAIL'}] {name} ({time.time() - t0:.0f}s)\n      {tail}")
    return ok


def sample_verdicts() -> bool:
    """Malicious document/script samples must be flagged, clean.* must stay clean."""
    sys.path.insert(0, ROOT)
    from cerber.pipeline import Pipeline
    pipe = Pipeline(options={"deep": True, "macos": False})
    bad = []
    n = 0
    for area in ("documents", "scripts"):
        d = os.path.join(ROOT, "tests", "samples", area)
        for fn in sorted(os.listdir(d)):
            p = os.path.join(d, fn)
            if not os.path.isfile(p) or fn.startswith("."):
                continue
            n += 1
            v = pipe.scan_file(p).meta["verdict"].name
            clean_expected = fn.startswith("clean")
            if clean_expected and v not in ("CLEAN", "INFO"):
                bad.append(f"{area}/{fn}: expected clean, got {v}")
            if not clean_expected and v in ("CLEAN",):
                bad.append(f"{area}/{fn}: expected detection, got {v}")
    print(f"[{'OK ' if not bad else 'FAIL'}] sample verdicts ({n} files)")
    for b in bad:
        print("      " + b)
    return not bad


def main() -> int:
    quick = "--quick" in sys.argv
    results = [
        run("analyzers load", ["-c", "from cerber.analyzers import load_all; print(len(load_all()), 'analyzers')"]),
        run("script analyzers", ["-m", "unittest", "tests.test_scripts"]),
        run("static heuristics (capability chains, configs, JXA, keychain FP gating)",
            ["-m", "unittest", "tests.test_static_heuristics"]),
        run("archive extraction", ["-m", "unittest", "tests.test_archives"]),
        run("model/ML analyzers", ["-m", "unittest", "tests.test_models_ml"]),
        run("network & remote-access audit", ["-m", "unittest", "tests.test_netaudit"]),
        run("deep audit (system log, LAN, trusted certificates)", ["-m", "unittest", "tests.test_netaudit_deep"]),
        run("known-malware artefacts (envscan, fake file system)", ["-m", "unittest", "tests.test_artifacts"]),
        run("file walker (iCloud placeholders never downloaded)", ["-m", "unittest", "tests.test_walk"]),
        run("Mega: risky cloud-only files fetched, scanned, given back", ["-m", "unittest", "tests.test_cloudfetch"]),
        run("script detonation (sandboxed behavioural analysis)", ["-m", "unittest", "tests.test_detonate"]),
        run("macOS hash feed importers (offline)", ["-m", "unittest", "tests.test_mac_hashes"]),
        run("macOS YARA feed filter (offline)", ["-m", "unittest", "tests.test_mac_yara_feeds"]),
        run("iOS indicator feeds (STIX2/Echap parsers, offline)", ["-m", "unittest", "tests.test_ios_feeds"]),
        run("iPhone check (fake backup, encrypted backup, no device, sandboxed flow)",
            ["-m", "unittest", "tests.test_iphone"]),
        run("live network & behaviour watch (Mega)", ["-m", "unittest", "tests.test_netwatch"]),
        run("AI accusation verifier (confirm/refute per accusation, ±15 points, never final)", ["-m", "unittest", "tests.test_ai_policy"]),
        run("quarantine is the user's choice (button for high risk, auto off)",
            ["-m", "unittest", "tests.test_quarantine_offer"]),
        run("network & remote-access guard (watch --net) + report quarantine links",
            ["-m", "unittest", "tests.test_netguard"]),
        run("provenance, names, correlation (process + network + autostart + files)",
            ["-m", "unittest", "tests.test_correlate"]),
        run("live attacks (remote shells, secret stores held open, stealer staging)", ["-m", "unittest", "tests.test_live"]),
        run("local HTTP API (auth, queue, streams; mock + real info)", ["-m", "unittest", "tests.test_api_server"]),
        run("self-hardening (integrity seal, escaping, API, quarantine, sandboxes)", ["-m", "unittest", "tests.test_hardening"]),
        run("false-positive gating (Windows-script YARA rules vs disk images / Mach-O)",
            ["-m", "unittest", "tests.test_fp_gating"]),
        sample_verdicts(),
    ]
    for pack in ("scripts_web", "macos"):
        rules = f"rules/custom/{pack}.yar"
        if os.path.exists(os.path.join(ROOT, rules)):
            results.append(run(f"YARA {pack} (compile + positives, small clean corpus)",
                               ["-m", "cerber.tools.yaracheck", rules, "--positive", f"tests/samples/yara/{pack}",
                                "--corpus", "/usr/bin", "--max-files", "2000"], "no false positives"))
    gen = sorted(glob.glob(os.path.join(ROOT, "rules", "experimental", "gen_*.yar")))
    if gen:
        results.append(run(f"YARA own rules gen_* ({len(gen)} packs, compile + positives, small clean corpus)",
                           ["-m", "cerber.tools.yaracheck", *gen, "--positive", "tests/samples/yara/gen",
                            "--corpus", "/usr/bin", "--max-files", "2000"], "no false positives"))
    results.append(run("ClamAV signature round-trip", ["tests/test_clamav_roundtrip.py", "--n",
                                                         "300" if quick else "1500"]))
    results.append(run("EICAR selftest (all engines)", ["-m", "cerber", "selftest", "--workers", "2"], "OK"))
    passed = sum(bool(r) for r in results)
    print(f"\n{passed}/{len(results)} test groups passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())

"""Quick manual check of the live-environment scanner.

    python -m cerber.envscan [--all] [--json FILE] [--only launchd,processes] [--skip browser] [--days 60]
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from . import COLLECTORS, scan_environment

SEV_LABEL = {"malicious": "MALICIOUS", "pua": "PUA", "suspicious": "SUSPICIOUS", "low": "LOW", "info": "info"}


def _posture_line(p: dict) -> str:
    xp = p.get("xprotect") or {}
    newest = max((v for k, v in xp.items() if k.startswith("XProtect (")), key=lambda v: v.get("date") or "",
                 default=None)
    xpr = xp.get("XProtect Remediator") or {}
    parts = [f"SIP {p.get('sip', '?')}", f"Gatekeeper {p.get('gatekeeper', '?')}", f"FileVault {p.get('filevault', '?')}",
             f"Firewall {p.get('firewall', '?')}" + (" +stealth" if p.get("firewall_stealth") else ""),
             f"XProtect {newest.get('version')} ({newest.get('date')})" if newest else "XProtect ?",
             f"XProtectRemediator {xpr.get('version', '?')}",
             f"auto-update check {'on' if p.get('auto_update_check') else 'off' if p.get('auto_update_check') is False else '?'}",
             f"Full Disk Access {'yes' if p.get('full_disk_access') else 'no'}",
             f"root {'yes' if p.get('running_as_root') else 'no'}"]
    return " | ".join(parts)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Cerber live-environment scan (read-only)")
    ap.add_argument("--all", action="store_true", help="also print info-level findings")
    ap.add_argument("--json", metavar="FILE", help="write the full report as JSON ('-' for stdout)")
    ap.add_argument("--only", help="comma separated collectors: " + ",".join(c[0] for c in COLLECTORS))
    ap.add_argument("--skip", help="comma separated collectors to skip")
    ap.add_argument("--days", type=int, default=60, help="recent-download window (days)")
    ap.add_argument("--no-codesign", action="store_true")
    ap.add_argument("--targets", type=int, default=15, help="how many targets to print")
    ap.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    args = ap.parse_args(argv)
    opts = {"recent_days": args.days, "codesign": not args.no_codesign}
    if args.only:
        opts["categories"] = [x.strip() for x in args.only.split(",") if x.strip()]
    if args.skip:
        opts["skip"] = [x.strip() for x in args.skip.split(",") if x.strip()]
    t0 = time.monotonic()

    def prog(msg: str) -> None:
        if not args.quiet:
            print(f"  [{time.monotonic() - t0:6.1f}s] {msg}", file=sys.stderr, flush=True)

    rep = scan_environment(opts, progress=prog)
    if args.json:
        data = json.dumps(rep.to_dict(), indent=1, ensure_ascii=False)
        if args.json == "-":
            print(data)
            return 0
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(data)
    inv = rep.inventory
    os_info = rep.posture.get("os") or {}
    print(f"\n=== Cerber environment scan: macOS {os_info.get('version')} ({os_info.get('build')}), "
          f"users {', '.join(inv.get('scanned_users', []))}, {inv.get('runtime_seconds')} s ===")
    print("Posture:  " + _posture_line(rep.posture))
    if rep.posture.get("pending_updates"):
        print("Pending updates: " + "; ".join(rep.posture["pending_updates"][:5]))
    if rep.posture.get("sharing_services"):
        print("Sharing services: " + ", ".join(rep.posture["sharing_services"]))
    counts = inv.get("counts", {})
    print("Inventory: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()) if v))
    print("Timing:   " + ", ".join(f"{k} {v}s" for k, v in inv.get("timing", {}).items()))
    sev = inv.get("findings_by_severity", {})
    print("Findings: " + ", ".join(f"{k} {sev.get(k, 0)}" for k in ("malicious", "pua", "suspicious", "low", "info"))
          + "   by category: " + ", ".join(f"{k} {v}" for k, v in sorted(inv.get("findings_by_category", {}).items())))
    print()
    shown = 0
    for f in rep.findings:
        if f.severity == "info" and not args.all:
            continue
        shown += 1
        d = f.detection
        print(f"[{SEV_LABEL[f.severity]:>10} {d.score:3d} {d.confidence.name:<6}] {f.category:<11} {f.title}")
        print(f"{'':25}{d.name}: {d.description}")
        print(f"{'':25}@ {f.location}")
        for e in d.evidence[:4]:
            print(f"{'':27}- {e[:170]}")
    hidden = sum(1 for f in rep.findings if f.severity == "info")
    if not args.all and hidden:
        print(f"({hidden} info-level findings hidden; use --all)")
    if not shown and (args.all is False):
        print("No findings above info level.")
    print(f"\nTargets for deep file scan: {len(rep.targets)}")
    for t in rep.inventory.get("targets_detail", [])[:args.targets]:
        print(f"   p{t['priority']} {t['path']}  ({t['reason']})")
    if len(rep.targets) > args.targets:
        print(f"   ... {len(rep.targets) - args.targets} more")
    if rep.limitations:
        print("\nLimitations:")
        for l in rep.limitations:
            print(f"   - {l}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

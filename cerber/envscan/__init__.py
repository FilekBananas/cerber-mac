"""Live-environment ("środowisko") scanner for macOS.

    from cerber.envscan import scan_environment
    report = scan_environment({"recent_days": 60}, progress=print)
    report.findings   # list[EnvFinding] (detection.engine == "env"), sorted by severity/score
    report.targets    # existing files/dirs the file scanner should deep-scan next
    report.inventory  # everything enumerated + inventory["counts"]
    report.posture    # SIP, Gatekeeper, FileVault, firewall, XProtect, updates, sharing ...
    report.limitations

Read-only by design: only reads files and runs query commands (codesign -dv,
csrutil status, netstat -anv, ...) with timeouts and without a shell. Works
without root/Full Disk Access and lists what it could not check.

options:
    categories        list of collector names to run (default: all, see COLLECTORS)
    skip              list of collector names to skip
    codesign          bool, run codesign (default True)
    verify_signatures bool, `codesign --verify` persistence binaries (default True)
    recent_days       int, window for recent downloads (default 60)
    extension_targets bool, add every browser extension folder to targets (default True)
    timeout           float, default per-command timeout (default 20 s)
    max_seconds       float, overall budget; remaining collectors are skipped (default 600)
    homes_override    list[envscan.util.UserHome], scan these home folders instead (tests/forensics)

Per finding, `EnvFinding.severity` maps the calibrated Detection onto
malicious / pua / suspicious / low / info with the thresholds of cerber.verdict.
"""
from __future__ import annotations

import os
import time
from typing import Callable

from .model import SEVERITY_ORDER, EnvFinding, EnvReport, Signal, combine, severity_of

__all__ = ["EnvFinding", "EnvReport", "Signal", "scan_environment", "COLLECTORS", "combine", "severity_of"]

# name -> (module, function); order matters (posture feeds network, launchd feeds plugins, profiles feed browser)
COLLECTORS: list[tuple[str, str, str]] = [
    ("posture", "system", "collect_posture"),
    ("launchd", "persistence", "collect_launchd"),
    ("login_items", "persistence", "collect_login_items"),
    ("cron", "persistence", "collect_cron_and_rc"),
    ("plugins", "persistence", "collect_plugins"),
    ("shell", "shell", "collect_shell"),
    ("processes", "processes", "collect_processes"),
    # attacks in progress: remote shells, browser/keychain/wallet stores held open by a program that does not own
    # them (runs after "processes": reuses its process snapshot and provenance)
    ("live", "live", "collect_live"),
    ("hosts", "network", "collect_hosts"),
    ("dns", "network", "collect_dns_proxy"),
    ("network", "network", "collect_network"),
    ("ssh", "accounts", "collect_ssh"),
    ("kext", "system", "collect_extensions"),
    ("profiles", "system", "collect_profiles"),
    ("tcc", "system", "collect_tcc"),
    ("browser", "browser", "collect_browsers"),
    ("downloads", "files", "collect_downloads"),
    ("staging", "files", "collect_staging"),
    # exact paths/labels/bundle ids/process names of known macOS malware families (runs after "processes")
    ("artifacts", "artifacts", "collect_artifacts"),
    ("apps", "system", "collect_gatekeeper_bypassed_apps"),
    # network & remote-access audit (Mega level; runs after "network"/"ssh"/"profiles" to reuse their results)
    ("netaudit_traffic", "netaudit", "collect_traffic"),
    ("netaudit_remote", "netaudit", "collect_remote"),
    # deep audit: unified-log history, local network (ARP / Wi-Fi) and trusted root certificates (netaudit_deep)
    ("netaudit_syslog", "netaudit_deep", "collect_syslog"),
    ("netaudit_lan", "netaudit_deep", "collect_lan"),
    ("netaudit_certs", "netaudit_deep", "collect_certs"),
]


def _sharing_posture(ctx) -> None:
    from ..core import Confidence
    services = ctx.posture.get("sharing_services") or []
    if services:
        ctx.add_finding("posture", "Włączone usługi zdalnego dostępu / udostępniania", "System Settings > Sharing",
                        [Signal("Heur:Env.Posture.SharingEnabled", 5, Confidence.LOW,
                                "usługi sieciowe przyjmują połączenia przychodzące", list(services))],
                        {"services": services})


def _finalize_targets(ctx) -> list[str]:
    items = [t for t in ctx.targets.values() if os.path.exists(t["path"])]
    items.sort(key=lambda t: (-t["priority"], t["path"]))
    dirs = sorted({t["path"] for t in items if os.path.isdir(t["path"])}, key=len)
    out, info = [], []
    for t in items:
        p = t["path"]
        parent_dir = next((d for d in dirs if d != p and p.startswith(d.rstrip("/") + "/")), None)
        if parent_dir is not None:
            continue  # scanned as part of the enclosing bundle / extension folder
        out.append(p)
        info.append(t)
    ctx.inventory["targets_detail"] = info
    return out


def scan_environment(options: dict | None = None, progress: Callable[[str], None] | None = None,
                     on_module: Callable[[str], None] | None = None) -> EnvReport:
    from importlib import import_module

    from .util import EnvContext

    t0 = time.monotonic()
    ctx = EnvContext(options, progress)
    opts = ctx.options
    wanted = set(opts.get("categories") or [c[0] for c in COLLECTORS])
    skip = set(opts.get("skip") or [])
    budget = float(opts.get("max_seconds", 600))
    if not ctx.is_root:
        ctx.limit("brak uprawnień roota: nie sprawdzono systemowych tablic cron, sudoers, bazy Background Task Management, "
                  "profili konfiguracji na poziomie komputera ani wierszy poleceń procesów roota")
    for name, mod, func in COLLECTORS:
        if name not in wanted or name in skip:
            continue
        if time.monotonic() - t0 > budget:
            ctx.limit(f"wyczerpano limit czasu {budget:.0f} s: pominięto moduł '{name}'")
            continue
        if on_module:
            on_module(name)
        t1 = time.monotonic()
        try:
            getattr(import_module(f"{__name__}.{mod}"), func)(ctx)
        except Exception as exc:  # noqa: BLE001 - a broken collector must not kill the scan
            import traceback
            tb = traceback.format_exc(limit=4).strip().splitlines()
            ctx.limit(f"błąd wewnętrzny modułu '{name}': {exc!r} ({tb[-2].strip() if len(tb) > 1 else ''})")
        ctx.timing[name] = round(time.monotonic() - t1, 2)
        if name == "network":
            _sharing_posture(ctx)
    ctx.progress("finalizowanie raportu")
    findings = sorted(ctx.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], -f.detection.score, f.category, f.title))
    targets = _finalize_targets(ctx)
    inv = ctx.inventory
    inv.pop("_known_programs", None)
    counts = {}
    for k, v in list(inv.items()):
        if isinstance(v, list) and k != "targets_detail":
            counts[k] = len(v)
    if isinstance(inv.get("launchd_system"), dict):
        counts["launchd_system"] = inv["launchd_system"].get("count", 0)
    if isinstance(inv.get("process_summary"), dict):
        counts["processes"] = inv["process_summary"].get("total", counts.get("processes", 0))
    counts["targets"] = len(targets)
    by_cat: dict[str, int] = {}
    by_sev: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
        by_sev[f.severity] += 1
    inv["counts"] = counts
    inv["findings_by_category"] = by_cat
    inv["findings_by_severity"] = by_sev
    inv["timing"] = dict(ctx.timing)
    inv["codesign"] = {"calls": ctx.codesign.calls, "timeouts": ctx.codesign.timeouts}
    inv["runtime_seconds"] = round(time.monotonic() - t0, 2)
    inv["scanned_users"] = [h.name for h in ctx.homes]
    ctx.posture.setdefault("running_as_root", ctx.is_root)
    ctx.posture.setdefault("full_disk_access", ctx.fda)
    return EnvReport(findings=findings, targets=targets, inventory=inv, posture=ctx.posture,
                     limitations=list(ctx.limitations))

"""Persistence collectors: launchd jobs, login items / BTM, cron, periodic, rc files, emond,
loginwindow hooks, plugins (authorization, directory services, Spotlight, QuickLook, ...),
privileged helper tools and Folder Actions."""
from __future__ import annotations

import glob
import os
import plistlib
import re
from urllib.parse import unquote

from ..core import Confidence
from .launchd_rules import analyze_job, analyze_plist
from .model import Signal
from .patterns import classify_path, command_signals, expand, is_apple_path, path_signals, redact
from .util import (EnvContext, SignInfo, file_kind, load_plist, lstat_info, mtime_days, read_text, run,
                   safe_listdir, world_writable)

E = "Heur:Env"
SCOPE_TITLE = {"user_agent": "LaunchAgent użytkownika", "global_agent": "LaunchAgent", "global_daemon": "LaunchDaemon",
               "system": "Systemowe zadanie launchd", "app_bundle": "Zadanie launchd wbudowane w aplikację",
               "submitted": "Załadowane zadanie launchd", "file": "Zadanie launchd"}


# --------------------------------------------------------------------------- shared executable checks

def check_executable(ctx: EnvContext, exe: str, prefix: str, what: str, scope: str = "",
                     verify: bool = False) -> tuple[list[Signal], SignInfo | None, dict]:
    """Live checks for an executable referenced by persistence: existence, signature, permissions, script body."""
    sigs: list[Signal] = []
    details: dict = {}
    if not exe or not exe.startswith("/"):
        return sigs, None, details
    kind = file_kind(exe)
    details["kind"] = kind
    if kind == "missing":
        sigs.append(Signal(f"{prefix}.MissingBinary", 5, Confidence.LOW, f"{what}: nie istnieje (nieaktualny wpis?)", [exe]))
        return sigs, None, details
    st = lstat_info(exe)
    if st:
        details["file"] = {k: st[k] for k in ("owner", "mode", "mtime", "size") if k in st}
    sinfo: SignInfo | None = None
    if kind in ("macho", "bundle"):
        sinfo = ctx.sign(exe)
        details["signature"] = sinfo.to_dict()
        sigs.extend(ctx.signing_signals(exe, prefix, what, info=sinfo))
        if verify and sinfo.trusted and not sinfo.is_apple and ctx.options.get("verify_signatures", True):
            ok, msg = ctx.codesign.verify(exe)
            sinfo.verified, sinfo.verify_error = ok, msg
            details["signature"] = sinfo.to_dict()
            if ok is False:
                sigs.append(Signal(f"{prefix}.BrokenSignature", 30, Confidence.MEDIUM,
                                   f"{what}: podpis nie przechodzi weryfikacji (zmieniony po podpisaniu?)", [msg]))
    elif kind == "script":
        body = read_text(exe, 512 << 10) or ""
        sigs.extend(command_signals(body, f"{prefix}.Script", f"{what} (skrypt)"))
        details["script_lines"] = body.count("\n") + 1
    if not is_apple_path(exe):
        if world_writable(exe):
            sigs.append(Signal(f"{prefix}.WritableBinary", 25, Confidence.MEDIUM,
                               f"{what}: zapisywalny dla wszystkich (każdy może go podmienić)", [exe]))
        if scope == "global_daemon" and st and st.get("uid", 0) != 0 and "app_bundle" not in classify_path(exe).tags:
            sigs.append(Signal(f"{prefix}.UserOwnedRootBinary", 10, Confidence.LOW,
                               f"{what}: działa jako root, ale należy do '{st.get('owner')}' (ryzyko eskalacji uprawnień)", [exe]))
    return sigs, sinfo, details


def _finalize_signals(sigs: list[Signal], sinfo: SignInfo | None, program: str | None = None) -> list[Signal]:
    """Dampen location signals of a trusted-signed program; an Apple-signed program is no masquerade."""
    out = EnvContext.dampen_trusted(sigs, sinfo, only_path=program)
    if sinfo and sinfo.is_apple:
        out = [s for s in out if not s.name.endswith((".AppleMasquerade", ".Argv0Spoof"))]
    return out


# --------------------------------------------------------------------------- launchd

def _launch_dirs(ctx: EnvContext) -> list[tuple[str, str]]:
    dirs = []
    for h in ctx.homes:
        dirs.append(("user_agent", os.path.join(h.home, "Library/LaunchAgents")))
    dirs += [("global_agent", "/Library/LaunchAgents"), ("global_daemon", "/Library/LaunchDaemons"),
             ("system", "/System/Library/LaunchAgents"), ("system", "/System/Library/LaunchDaemons"),
             ("system", "/Library/Apple/System/Library/LaunchAgents"),
             ("system", "/Library/Apple/System/Library/LaunchDaemons")]
    return dirs


def eval_job(ctx: EnvContext, plist_path: str, d: dict, scope: str, home: str, known_programs: set,
             bundle_root: str | None = None) -> dict:
    ja = analyze_job(d, plist_path, scope, home, bundle_root)
    job = ja.job
    sigs = list(ja.signals)
    details: dict = {"plist": plist_path, "scope": scope, "job": job.to_dict()}
    pst = lstat_info(plist_path)
    if pst:
        details["plist_file"] = {k: pst[k] for k in ("owner", "mode", "mtime") if k in pst}
    entry = {"plist": plist_path, "scope": scope, "label": job.label, "program": ja.program,
             "run_at_load": job.run_at_load, "disabled": job.disabled}
    if ja.program:
        known_programs.add(ja.program)
    sinfo = None
    if scope != "system":
        verify = scope in ("user_agent", "global_agent", "global_daemon", "submitted")
        if ja.program and ja.program.startswith("/"):
            s2, sinfo, ed = check_executable(ctx, ja.program, f"{E}.Launchd", "program", scope, verify)
            sigs += s2
            details["program"] = ed
            if sinfo:
                entry["signer"] = sinfo.signer
            if ed.get("kind") != "missing":
                ctx.add_target(ja.program, f"{SCOPE_TITLE.get(scope, scope)} {job.label or ''} program".strip(), 1)
        if ja.script:
            s3, _, sd = check_executable(ctx, ja.script, f"{E}.Launchd", "script", scope)
            sigs += s3
            details["script"] = sd
            if sd.get("kind") != "missing":
                ctx.add_target(ja.script, f"script run by launchd job {job.label or ''}".strip(), 1)
        for p in ja.paths:
            if p not in (ja.program, ja.script) and os.path.exists(p) and not is_apple_path(p):
                ctx.add_target(p, f"path referenced by launchd job {job.label or ''}".strip(), 1)
        if world_writable(plist_path):
            sigs.append(Signal(f"{E}.Launchd.WritablePlist", 20, Confidence.MEDIUM,
                               "plik plist launchd jest zapisywalny dla wszystkich", [plist_path]))
        if scope in ("global_agent", "global_daemon") and pst and pst.get("uid", 0) != 0:
            sigs.append(Signal(f"{E}.Launchd.NonRootPlist", 15, Confidence.MEDIUM,
                               f"ogólnosystemowy plik plist launchd należy do '{pst.get('owner')}' zamiast do roota", [plist_path]))
        age = mtime_days(plist_path)
        if age is not None and age < 7:
            details["recently_modified"] = True
    sigs = _finalize_signals(sigs, sinfo, ja.program)
    f = ctx.add_finding("persistence", f"{SCOPE_TITLE.get(scope, 'Zadanie launchd')} '{job.label or os.path.basename(plist_path)}'",
                        plist_path, sigs, details)
    entry["score"] = f.score if f else 0
    return entry


def collect_launchd(ctx: EnvContext) -> None:
    ctx.progress("agenty i demony launchd")
    known_programs: set[str] = set()
    known_labels: set[str] = set()
    jobs: list[dict] = ctx.inv("launchd")
    system_count = 0
    system_odd: list[str] = []
    other_files: list[str] = []
    for scope, d in _launch_dirs(ctx):
        names, err = safe_listdir(d)
        if err == "denied":
            ctx.limit(f"{d} jest nieczytelny (wymaga roota)")
            continue
        home = next((h.home for h in ctx.homes if d.startswith(h.home + "/")), ctx.homes[0].home if ctx.homes else None)
        for n in names:
            p = os.path.join(d, n)
            if n in (".DS_Store", ".localized") or os.path.isdir(p):
                continue
            if not n.endswith(".plist"):
                other_files.append(p)
                continue
            data, perr = load_plist(p)
            if perr:
                if scope != "system":
                    if perr == "unreadable" or perr.startswith("unreadable"):
                        ctx.limit(f"{p} jest nieczytelny")
                    elif perr != "empty file":
                        ctx.add_finding("persistence", f"Nieczytelny plik plist launchd {n}", p,
                                        [Signal(f"{E}.Launchd.Unparseable", 5, Confidence.LOW,
                                                f"nie udało się sparsować pliku plist launchd ({perr})", [p])], {"error": perr})
                    jobs.append({"plist": p, "scope": scope, "error": perr})
                continue
            if not isinstance(data, dict) or not (data.get("Program") or data.get("ProgramArguments")
                                                   or data.get("BundleProgram")):
                if scope != "system":
                    jobs.append({"plist": p, "scope": scope, "label": (data or {}).get("Label") if isinstance(data, dict) else None,
                                 "note": "empty or no program (inactive)"})
                continue
            if isinstance(data.get("Label"), str):
                known_labels.add(data["Label"])
            if scope == "system":
                system_count += 1
                e = eval_job(ctx, p, data, scope, home or "", known_programs)
                if e.get("score"):
                    system_odd.append(p)
                continue
            jobs.append(eval_job(ctx, p, data, scope, home or "", known_programs))
    ctx.inventory["launchd_system"] = {"count": system_count, "anomalies": system_odd}
    if other_files:
        ctx.inventory["launchd_non_plist_files"] = other_files

    # app-embedded launchd plists (SMAppService) and helper login items
    app_roots = ["/Applications"] + [os.path.join(h.home, "Applications") for h in ctx.homes]
    apps: list[str] = []
    for r in app_roots:
        apps += glob.glob(os.path.join(glob.escape(r), "*.app")) + glob.glob(os.path.join(glob.escape(r), "*", "*.app")) \
            + glob.glob(os.path.join(glob.escape(r), "*", "*", "*", "*.app"))
    bundled = ctx.inv("launchd_app_bundled")
    login_helpers = ctx.inv("login_item_helpers")
    for app in sorted(set(apps)):
        for sub in ("LaunchAgents", "LaunchDaemons"):
            for p in glob.glob(os.path.join(glob.escape(app), "Contents", "Library", sub, "*.plist")):
                data, perr = load_plist(p)
                if not isinstance(data, dict) or not (data.get("Program") or data.get("ProgramArguments")
                                                       or data.get("BundleProgram")):
                    continue
                if isinstance(data.get("Label"), str):
                    known_labels.add(data["Label"])
                bundled.append(eval_job(ctx, p, data, "app_bundle", ctx.homes[0].home if ctx.homes else "",
                                        known_programs, bundle_root=app))
        for helper in glob.glob(os.path.join(glob.escape(app), "Contents", "Library", "LoginItems", "*.app")):
            si = ctx.sign(helper)
            sigs = ctx.signing_signals(helper, f"{E}.LoginItem", "pomocnik elementu logowania", info=si)
            login_helpers.append({"app": app, "helper": helper, "signer": si.signer})
            f = ctx.add_finding("persistence", f"Pomocnik elementu logowania {os.path.basename(helper)}", helper, sigs,
                                {"app": app, "signature": si.to_dict()})
            if f or not si.trusted:
                ctx.add_target(helper, "pomocnik elementu logowania", 1 if not f else 2)
    ctx.inventory["_known_programs"] = sorted(known_programs)

    # jobs loaded in the user's launchd domain without a plist on disk (launchctl submit, SMAppService...)
    if ctx.is_root:
        return
    r = run(["/bin/launchctl", "list"], timeout=ctx.timeout)
    if not r.ok:
        ctx.limit("launchctl list nie powiodło się; załadowane zadania bez pliku plist nie zostały wyliczone")
        return
    loaded = ctx.inv("launchd_loaded_without_plist")
    candidates = []
    for line in r.out.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        label = parts[2].strip()
        if not label or label.startswith(("com.apple.", "application.", "[0x")) or label in known_labels:
            continue
        candidates.append((label, parts[0].strip()))
    for label, pid in candidates[:40]:
        pr = run(["/bin/launchctl", "print", f"gui/{ctx.uid}/{label}"], timeout=5)
        prog = None
        plist = None
        if pr.ok:
            m = re.search(r"^\s*program = (.+)$", pr.out, re.M)
            prog = m.group(1).strip() if m else None
            m = re.search(r"^\s*path = (.+)$", pr.out, re.M)
            plist = m.group(1).strip() if m else None
        if plist and plist in {j.get("plist") for j in ctx.inventory.get("launchd", [])}:
            continue
        entry = {"label": label, "pid": None if pid == "-" else pid, "program": prog, "plist": plist}
        loaded.append(entry)
        if not prog or not prog.startswith("/"):
            continue
        sigs = path_signals(prog, f"{E}.Launchd", "program", ctx.homes[0].home if ctx.homes else None)
        s2, sinfo, ed = check_executable(ctx, prog, f"{E}.Launchd", "program", "submitted")
        sigs = _finalize_signals(sigs + [s for s in s2 if not s.name.endswith("MissingBinary")], sinfo)
        entry["signer"] = sinfo.signer if sinfo else None
        if ed.get("kind") not in (None, "missing"):
            ctx.add_target(prog, f"loaded launchd job {label}", 1)
        ctx.add_finding("persistence", f"Załadowane zadanie launchd '{label}' (brak pliku plist na dysku)", f"launchd:{label}", sigs,
                        {"label": label, "program": prog, "program_info": ed})


# --------------------------------------------------------------------------- login items / BTM

def _parse_dumpbtm(text: str) -> list[dict]:
    items: list[dict] = []
    cur: dict | None = None
    for line in text.splitlines():
        if re.match(r"^\s*#\d+:\s*$", line):
            cur = {}
            items.append(cur)
            continue
        m = re.match(r"^\s*([A-Za-z][A-Za-z ]+?):\s(.*)$", line)
        if m and cur is not None:
            cur.setdefault(m.group(1).strip(), m.group(2).strip())
    return items


def collect_login_items(ctx: EnvContext) -> None:
    ctx.progress("elementy logowania / zadania w tle")
    inv = ctx.inv("login_items")
    home = ctx.homes[0].home if ctx.homes else None
    if ctx.is_root:
        r = run(["/usr/bin/sfltool", "dumpbtm"], timeout=60)
        if r.ok and r.out:
            for it in _parse_dumpbtm(r.out):
                url = it.get("URL", "")
                exe = it.get("Executable Path") or (unquote(url[7:]) if url.startswith("file://") else "")
                exe = exe.rstrip("/") if exe else ""
                entry = {"name": it.get("Name"), "type": it.get("Type"), "developer": it.get("Developer Name"),
                         "team_id": it.get("Team Identifier"), "disposition": it.get("Disposition"),
                         "identifier": it.get("Identifier"), "path": exe}
                inv.append(entry)
                if not exe.startswith("/") or is_apple_path(exe):
                    continue
                sigs = path_signals(exe, f"{E}.LoginItem", "element logowania", home)
                s2, sinfo, ed = check_executable(ctx, exe, f"{E}.LoginItem", "element logowania")
                sigs = _finalize_signals(sigs + [s for s in s2 if not s.name.endswith("MissingBinary")], sinfo)
                if ed.get("kind") not in (None, "missing"):
                    ctx.add_target(exe, f"BTM item {entry['name']}", 1)
                ctx.add_finding("persistence", f"Element logowania/tła '{entry['name']}'", exe, sigs, entry)
            ctx.inventory["btm_source"] = "sfltool dumpbtm"
            return
        ctx.limit("sfltool dumpbtm nie powiodło się; baza Background Task Management nie została sprawdzona")
    else:
        ctx.limit("baza elementów logowania / Background Task Management wymaga roota (sfltool dumpbtm); "
                  "zamiast niej wyliczono elementy logowania wbudowane w aplikacje i starsze listy elementów logowania")
    for h in ctx.homes:
        # legacy SharedFileList-based and loginwindow-based lists
        legacy = os.path.join(h.home, "Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm")
        if os.path.exists(legacy):
            data, err = load_plist(legacy)
            urls: list[str] = []

            def walk(o, depth=0):
                if depth > 20 or len(urls) > 200:
                    return
                if isinstance(o, str) and o.startswith("file://"):
                    urls.append(o)
                elif isinstance(o, dict):
                    for v in o.values():
                        walk(v, depth + 1)
                elif isinstance(o, list):
                    for v in o:
                        walk(v, depth + 1)
            walk(data)
            for u in urls:
                p = unquote(u[7:]).rstrip("/")
                inv.append({"source": "backgrounditems.btm", "path": p})
                sigs = path_signals(p, f"{E}.LoginItem", "element logowania", h.home)
                if sigs:
                    ctx.add_finding("persistence", f"Element logowania {os.path.basename(p)}", p, sigs, {"source": legacy})
        lw = os.path.join(h.home, "Library/Preferences/com.apple.loginitems.plist")
        if os.path.exists(lw):
            data, err = load_plist(lw)
            names = []
            try:
                for it in data["SessionItems"]["CustomListItems"]:
                    names.append(it.get("Name"))
            except Exception:  # noqa: BLE001
                pass
            inv.extend({"source": "com.apple.loginitems.plist", "name": n} for n in names if n)
        # apps re-opened at login
        for f in glob.glob(os.path.join(glob.escape(h.home), "Library/Preferences/ByHost/com.apple.loginwindow.*.plist")):
            data, err = load_plist(f)
            if isinstance(data, dict):
                tal = data.get("TALAppsToRelaunchAtLogin") or []
                apps = [a.get("Path") or a.get("BundleID") for a in tal if isinstance(a, dict)]
                ctx.inventory["relaunch_at_login"] = [a for a in apps if a][:100]
                for a in apps:
                    if isinstance(a, str) and a.startswith("/"):
                        sigs = [s for s in path_signals(a, f"{E}.Relaunch", "aplikacja otwierana ponownie", h.home)
                                if s.score >= 25]
                        ctx.add_finding("persistence", f"Aplikacja otwierana ponownie przy logowaniu: {os.path.basename(a)}", a, sigs,
                                        {"source": f})


# --------------------------------------------------------------------------- cron / periodic / rc / emond / hooks

_CRON_LINE = re.compile(r"^\s*(@\w+|(?:\S+\s+){5})(.+)$")


def _cron_job(ctx: EnvContext, line: str, source: str) -> None:
    m = _CRON_LINE.match(line)
    if not m:
        return
    sched, cmd = m.group(1).strip(), m.group(2).strip()
    ctx.inv("cron").append({"source": source, "schedule": sched, "command": redact(cmd, 200)})
    sigs = [Signal(f"{E}.Cron.Job", 10, Confidence.LOW, "zadanie cron (rzadko używane w macOS; klasyczna persystencja)",
                   [redact(line, 200)])]
    sigs += command_signals(cmd, f"{E}.Cron", "polecenie cron")
    first = cmd.split()[0] if cmd.split() else ""
    home = ctx.homes[0].home if ctx.homes else None
    if first.startswith(("/", "~")):
        exe = expand(first, home)
        s2, sinfo, ed = check_executable(ctx, exe, f"{E}.Cron", "program cron")
        sigs = _finalize_signals(sigs + s2 + path_signals(exe, f"{E}.Cron", "program cron", home), sinfo)
        if ed.get("kind") not in (None, "missing"):
            ctx.add_target(exe, "cron job program", 1)
    ctx.add_finding("persistence", f"Zadanie cron ({source})", source, sigs, {"schedule": sched, "command": redact(cmd, 300)})


def collect_cron_and_rc(ctx: EnvContext) -> None:
    ctx.progress("cron, periodic, pliki rc, emond, login hooks")
    # --- cron
    r = run(["/usr/bin/crontab", "-l"], timeout=10)
    if r.ok:
        for line in r.out.splitlines():
            if line.strip() and not line.lstrip().startswith("#") and not re.match(r"^\s*\w+\s*=", line):
                _cron_job(ctx, line, f"crontab użytkownika {ctx.homes[0].name if ctx.homes else 'bieżącego'}")
    for tabs in ("/usr/lib/cron/tabs", "/private/var/at/tabs"):
        names, err = safe_listdir(tabs)
        if err == "denied":
            ctx.limit(f"systemowe tablice cron ({tabs}) wymagają roota")
        for n in names:
            if ctx.is_root:
                txt = read_text(os.path.join(tabs, n)) or ""
                for line in txt.splitlines():
                    if line.strip() and not line.lstrip().startswith("#") and not re.match(r"^\s*\w+\s*=", line):
                        _cron_job(ctx, line, f"crontab użytkownika {n}")
    if os.path.exists("/etc/crontab"):
        for line in (read_text("/etc/crontab") or "").splitlines():
            if line.strip() and not line.lstrip().startswith("#") and not re.match(r"^\s*\w+\s*=", line):
                m = re.match(r"^\s*((?:\S+\s+){5})(\S+)\s+(.+)$", line)
                if m:
                    _cron_job(ctx, m.group(1) + m.group(3), "/etc/crontab")
    jobs, err = safe_listdir("/usr/lib/cron/jobs")
    if err == "denied":
        ctx.limit("kolejka zadań at(1) wymaga roota")
    elif jobs:
        ctx.inventory["at_jobs"] = [j for j in jobs if not j.startswith(".")]

    # --- periodic
    for base in ("/etc/periodic", "/usr/local/etc/periodic"):
        for sub in ("daily", "weekly", "monthly"):
            d = os.path.join(base, sub)
            names, _ = safe_listdir(d)
            for n in names:
                p = os.path.join(d, n)
                st = lstat_info(p)
                ctx.inv("periodic").append({"path": p, "owner": st.get("owner")})
                sigs: list[Signal] = []
                if base.startswith("/usr/local"):
                    sigs.append(Signal(f"{E}.Periodic.LocalScript", 15, Confidence.LOW,
                                       "własny skrypt periodic (uruchamiany jako root codziennie/co tydzień/co miesiąc)", [p]))
                if st.get("uid", 0) != 0:
                    sigs.append(Signal(f"{E}.Periodic.NonRootOwned", 20, Confidence.MEDIUM,
                                       f"skrypt periodic należy do '{st.get('owner')}'", [p]))
                sigs += command_signals(read_text(p, 256 << 10) or "", f"{E}.Periodic", "skrypt periodic")
                if sigs:
                    ctx.add_target(p, "skrypt periodic", 1)
                ctx.add_finding("persistence", f"Skrypt periodic {n}", p, sigs, {"file": st})

    # --- legacy rc / launchd.conf
    for p in ("/etc/rc.local", "/etc/rc.shutdown.local", "/etc/launchd.conf", "/etc/launchd-user.conf",
              *[os.path.join(h.home, ".launchd.conf") for h in ctx.homes]):
        if os.path.exists(p):
            body = read_text(p, 256 << 10) or ""
            sigs = [Signal(f"{E}.Persistence.LegacyStartupFile", 20, Confidence.MEDIUM,
                           "obecny przestarzały plik startowy (ignorowany przez nowoczesny macOS; często zostawiany przez malware)", [p])]
            sigs += command_signals(body, f"{E}.RC", os.path.basename(p))
            ctx.add_target(p, "legacy startup file", 2)
            ctx.add_finding("persistence", f"Przestarzały plik startowy {p}", p, sigs, {"file": lstat_info(p)})
    if os.path.exists("/etc/rc.common"):
        body = read_text("/etc/rc.common", 256 << 10) or ""
        sigs = command_signals(body, f"{E}.RC", "/etc/rc.common")
        ctx.add_finding("persistence", "Zmodyfikowany /etc/rc.common", "/etc/rc.common", sigs, {"file": lstat_info("/etc/rc.common")})

    # --- emond
    rules, err = safe_listdir("/etc/emond.d/rules")
    for n in rules:
        p = os.path.join("/etc/emond.d/rules", n)
        data, perr = load_plist(p)
        pa = analyze_plist(data, p) if data is not None else None
        ctx.inv("emond_rules").append({"path": p, "commands": (pa.meta.get("emond_commands") if pa else None)})
        if pa and pa.signals:
            ctx.add_target(p, "emond rule", 2)
            ctx.add_finding("persistence", f"Reguła emond {n}", p, pa.signals, pa.meta)
    clients, err = safe_listdir("/private/var/db/emondClients")
    if clients:
        ctx.add_finding("persistence", "Zarejestrowani klienci emond", "/private/var/db/emondClients",
                        [Signal(f"{E}.Emond.Clients", 15, Confidence.LOW, "emond ma zarejestrowanych klientów (normalnie nieużywany)",
                                clients[:5])], {"clients": clients})
    elif err == "denied":
        ctx.limit("/private/var/db/emondClients jest nieczytelny (wymaga roota)")

    # --- loginwindow hooks & legacy auto-launched apps
    lw_files = ["/Library/Preferences/com.apple.loginwindow.plist",
                "/private/var/root/Library/Preferences/com.apple.loginwindow.plist"] + \
               [os.path.join(h.home, "Library/Preferences/com.apple.loginwindow.plist") for h in ctx.homes]
    for p in lw_files:
        if not os.path.exists(p):
            continue
        data, perr = load_plist(p)
        if perr:
            if "unreadable" in perr and "/var/root/" in p:
                ctx.limit("preferencje loginwindow roota (LoginHook) wymagają roota")
            continue
        pa = analyze_plist(data, p, home=ctx.homes[0].home if ctx.homes else None)
        if pa.meta.get("auto_launched"):
            ctx.inventory.setdefault("loginwindow_auto_launched", []).extend(pa.meta["auto_launched"])
        if not pa.signals:
            continue
        sigs = list(pa.signals)
        for hook in (pa.meta.get("hooks") or {}).values():
            hp = expand(hook, ctx.homes[0].home if ctx.homes else None)
            s2, sinfo, ed = check_executable(ctx, hp, f"{E}.LoginHook", "login hook")
            sigs += s2
            if ed.get("kind") not in (None, "missing"):
                ctx.add_target(hp, "loginwindow hook", 2)
        ctx.add_finding("persistence", "Hook loginwindow / element uruchamiany automatycznie", p, sigs, pa.meta)


# --------------------------------------------------------------------------- plugins & helpers

PLUGIN_LOCATIONS: tuple[tuple[str, str, tuple[str, ...], int], ...] = (
    # (kind, category, dirs, base score for a non-Apple item)
    ("authorization plugin", "persistence", ("/Library/Security/SecurityAgentPlugins",), 10),
    ("directory services plugin", "persistence", ("/Library/DirectoryServices/PlugIns",), 10),
    ("Spotlight importer", "persistence", ("/Library/Spotlight", "~/Library/Spotlight"), 0),
    ("QuickLook generator", "persistence", ("/Library/QuickLook", "~/Library/QuickLook"), 0),
    ("preference pane", "persistence", ("/Library/PreferencePanes", "~/Library/PreferencePanes"), 0),
    ("screen saver", "persistence", ("/Library/Screen Savers", "~/Library/Screen Savers"), 0),
    ("input method", "persistence", ("/Library/Input Methods", "~/Library/Input Methods"), 0),
    ("audio HAL plug-in", "persistence", ("/Library/Audio/Plug-Ins/HAL",), 0),
    ("color picker", "persistence", ("/Library/ColorPickers", "~/Library/ColorPickers"), 0),
    ("internet plug-in", "persistence", ("/Library/Internet Plug-Ins", "~/Library/Internet Plug-Ins"), 0),
    ("Mail bundle", "persistence", ("/Library/Mail/Bundles", "~/Library/Mail/Bundles"), 5),
    ("contextual menu item", "persistence", ("/Library/Contextual Menu Items", "~/Library/Contextual Menu Items"), 0),
)


# Polish display names of the plugin kinds above (the English kind stays the key in inventories/details)
PLUGIN_KIND_PL = {"authorization plugin": "wtyczka autoryzacji", "directory services plugin": "wtyczka Directory Services",
                  "Spotlight importer": "importer Spotlight", "QuickLook generator": "generator QuickLook",
                  "preference pane": "panel preferencji", "screen saver": "wygaszacz ekranu",
                  "input method": "metoda wprowadzania", "audio HAL plug-in": "wtyczka audio HAL",
                  "color picker": "próbnik kolorów", "internet plug-in": "wtyczka internetowa",
                  "Mail bundle": "pakiet Mail", "contextual menu item": "element menu kontekstowego"}


def _check_bundle(ctx: EnvContext, kind: str, path: str, base: int, home: str | None) -> dict:
    si = ctx.sign(path)
    entry = {"kind": kind, "path": path, "signer": si.signer}
    if si.is_apple:
        return entry
    kp = PLUGIN_KIND_PL.get(kind, kind)
    sigs: list[Signal] = []
    if base:
        sigs.append(Signal(f"{E}.Plugin.ThirdParty", base, Confidence.LOW,
                           f"{kp}: od zewnętrznego producenta (ładowany do procesu uprzywilejowanego/systemowego)", [path]))
    sev = 1.5 if kind in ("authorization plugin", "directory services plugin") else 1.0
    sigs += ctx.signing_signals(path, f"{E}.Plugin", kp, sev=sev, info=si)
    sigs += path_signals(path, f"{E}.Plugin", kp, home)
    if os.path.basename(path).startswith(".") and not any(s.name.endswith("HiddenFile") for s in sigs):
        sigs.append(Signal(f"{E}.Plugin.HiddenFile", 30, Confidence.MEDIUM, f"{kp}: plik ukryty", [path]))
    sigs = EnvContext.dampen_trusted(sigs, si)
    ctx.add_target(path, kind, 1)
    f = ctx.add_finding("persistence", f"{kp[0].upper() + kp[1:]} {os.path.basename(path)}", path, sigs,
                        {"kind": kind, "signature": si.to_dict()})
    entry["score"] = f.score if f else 0
    return entry


def collect_plugins(ctx: EnvContext) -> None:
    ctx.progress("wtyczki, uprzywilejowane pomocniki, Folder Actions")
    inv = ctx.inv("plugins")
    home = ctx.homes[0].home if ctx.homes else None
    for kind, _cat, dirs, base in PLUGIN_LOCATIONS:
        for d in dirs:
            targets_dirs = [d] if not d.startswith("~") else [os.path.join(h.home, d[2:]) for h in ctx.homes]
            for dd in targets_dirs:
                names, err = safe_listdir(dd)
                if err == "denied":
                    ctx.limit(f"{dd} jest nieczytelny")
                for n in names:
                    if n in (".DS_Store", ".localized", "ExtensionsCache") or n.startswith("._"):
                        continue
                    inv.append(_check_bundle(ctx, kind, os.path.join(dd, n), base, home))

    # authorization database: third-party mechanisms in the login right
    apple_plugins = {os.path.splitext(n)[0] for n in safe_listdir("/System/Library/CoreServices/SecurityAgentPlugins")[0]}
    apple_plugins |= {"builtin", "loginwindow", "HomeDirMechanism", "MCXMechanism", "CryptoTokenKit",
                      "PKINITMechanism", "KerberosAgent", "DiskUnlock", "TimeMachineAuthentication", "FDESupport",
                      "PasswordPolicy", "RestartAuthorization", "SecurityAgent"}
    third = {os.path.splitext(n)[0] for n in safe_listdir("/Library/Security/SecurityAgentPlugins")[0]}
    mech_inv = ctx.inv("authorization_mechanisms")
    for right in ("system.login.console", "authenticate"):
        r = run(["/usr/bin/security", "authorizationdb", "read", right], timeout=10)
        if not r.ok or not r.out.strip():
            continue
        try:
            d = plistlib.loads(r.out.encode())
        except Exception:  # noqa: BLE001
            continue
        mechs = [m for m in (d.get("mechanisms") or []) if isinstance(m, str)]
        for m in mechs:
            plugin = m.split(":", 1)[0]
            if plugin in apple_plugins:
                continue
            mech_inv.append({"right": right, "mechanism": m, "plugin_installed": plugin in third})
            sig = Signal(f"{E}.AuthDB.ThirdPartyMechanism", 10, Confidence.LOW,
                         f"uprawnienie autoryzacji '{right}' uruchamia zewnętrzny mechanizm {m}", [m])
            sigs = [sig]
            if plugin not in third:
                sigs.append(Signal(f"{E}.AuthDB.MissingPlugin", 10, Confidence.LOW,
                                   "mechanizm odwołuje się do niezainstalowanej wtyczki", [plugin]))
            ctx.add_finding("persistence", f"Mechanizm autoryzacji {m}", f"authorizationdb:{right}", sigs,
                            {"right": right, "mechanism": m})

    # StartupItems (legacy)
    names, _ = safe_listdir("/Library/StartupItems")
    for n in names:
        if n.startswith("."):
            continue
        p = os.path.join("/Library/StartupItems", n)
        ctx.add_target(p, "StartupItem", 2)
        ctx.add_finding("persistence", f"StartupItem {n}", p,
                        [Signal(f"{E}.Persistence.StartupItem", 20, Confidence.MEDIUM,
                                "obecny przestarzały StartupItem (niewykonywany przez nowoczesny macOS; często pozostałość lub malware)", [p])],
                        {"file": lstat_info(p)})

    # privileged helper tools (root, launched on demand by launchd)
    known = set(ctx.inventory.get("_known_programs", []))
    helpers = ctx.inv("privileged_helpers")
    names, err = safe_listdir("/Library/PrivilegedHelperTools")
    for n in names:
        if n in (".DS_Store",):
            continue
        p = os.path.join("/Library/PrivilegedHelperTools", n)
        si = ctx.sign(p)
        referenced = p in known
        helpers.append({"path": p, "signer": si.signer, "referenced_by_launchd": referenced})
        sigs = ctx.signing_signals(p, f"{E}.Helper", "uprzywilejowany pomocnik", sev=1.3, info=si)
        if n.startswith("."):
            sigs.append(Signal(f"{E}.Helper.HiddenFile", 35, Confidence.MEDIUM, "ukryty uprzywilejowany pomocnik", [p]))
        if not referenced:
            sigs.append(Signal(f"{E}.Helper.Orphan", 0, Confidence.INFO,
                               "nie jest używany przez żaden LaunchDaemon (pozostałość po odinstalowanej aplikacji?)", [p]))
        ctx.add_target(p, "privileged helper tool", 1)
        ctx.add_finding("persistence", f"Uprzywilejowany pomocnik {n}", p, sigs, {"signature": si.to_dict()})

    # Folder Actions
    for h in ctx.homes:
        fa = os.path.join(h.home, "Library/Preferences/com.apple.FolderActionsDispatcher.plist")
        data, err = load_plist(fa)
        enabled = isinstance(data, dict) and bool(data.get("folderActionsEnabled"))
        user_scripts_dir = os.path.join(h.home, "Library/Scripts/Folder Action Scripts")
        scripts, _ = safe_listdir(user_scripts_dir)
        scripts = [s for s in scripts if not s.startswith(".")]
        ctx.inventory["folder_actions"] = {"enabled": enabled, "user_scripts": scripts}
        for s in scripts:
            ctx.add_target(os.path.join(user_scripts_dir, s), "Folder Action script", 1)
        if enabled:
            ctx.add_finding("persistence", "Folder Actions włączone", fa,
                            [Signal(f"{E}.FolderActions.Enabled", 10, Confidence.LOW,
                                    "Folder Actions są włączone (skrypty uruchamiają się, gdy pliki trafiają do obserwowanych folderów)",
                                    scripts[:5])], {"user_scripts": scripts})
        # iTerm2 AutoLaunch scripts run at every iTerm2 start
        auto = os.path.join(h.home, "Library/Application Support/iTerm2/Scripts/AutoLaunch")
        names, _ = safe_listdir(auto)
        for n in names:
            if n.startswith("."):
                continue
            p = os.path.join(auto, n)
            ctx.inv("iterm_autolaunch").append(p)
            ctx.add_target(p, "iTerm2 AutoLaunch script", 1)
    sys_fa, _ = safe_listdir("/Library/Scripts/Folder Action Scripts")
    custom = [n for n in sys_fa if lstat_info(os.path.join("/Library/Scripts/Folder Action Scripts", n)).get("uid", 0) != 0]
    for n in custom:
        ctx.add_target(os.path.join("/Library/Scripts/Folder Action Scripts", n), "non-default Folder Action script", 1)

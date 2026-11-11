"""Security posture, kernel/system extensions, configuration profiles, managed preferences, TCC."""
from __future__ import annotations

import datetime as dt
import glob
import os
import platform
import re
import sqlite3
import time

from ..core import Confidence
from .model import Signal
from .patterns import classify_path, path_signals
from .util import EnvContext, load_plist, run

S = "Heur:Env.Posture"

XPROTECT_PATHS = {
    "XProtect (system)": "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
    "XProtect (cloud updates)": "/var/protected/xprotect/XProtect.bundle",
    "XProtect Remediator": "/Library/Apple/System/Library/CoreServices/XProtect.app",
    "MRT": "/Library/Apple/System/Library/CoreServices/MRT.app",
}
TCC_SERVICES = {
    "kTCCServiceAccessibility": "Dostępność (sterowanie komputerem)",
    "kTCCServiceScreenCapture": "Nagrywanie ekranu",
    "kTCCServiceListenEvent": "Monitorowanie wprowadzania (klawisze)",
    "kTCCServicePostEvent": "Syntetyczne zdarzenia wejścia",
    "kTCCServiceSystemPolicyAllFiles": "Pełny dostęp do dysku",
    "kTCCServiceEndpointSecurityClient": "Klient Endpoint Security",
    "kTCCServiceDeveloperTool": "Narzędzia deweloperskie",
    "kTCCServiceSystemPolicySysAdminFiles": "Administrowanie plikami systemu",
}
BROWSER_POLICY_DOMAINS = ("com.google.Chrome", "com.microsoft.Edge", "com.brave.Browser", "org.chromium.Chromium",
                          "com.vivaldi.Vivaldi", "com.operasoftware.Opera", "org.mozilla.firefox", "com.apple.Safari")
BROWSER_POLICY_KEYS = ("ExtensionInstallForcelist", "ExtensionSettings", "HomepageLocation", "NewTabPageLocation",
                       "DefaultSearchProviderSearchURL", "DefaultSearchProviderEnabled", "RestoreOnStartupURLs",
                       "ProxySettings", "ProxyServer", "ProxyPacUrl", "ProxyMode", "Extensions", "Homepage",
                       "SearchEngines", "HomePage", "NewTabBehavior")


def _bundle_version(path: str) -> tuple[str | None, str | None]:
    for f in ("Contents/version.plist", "Contents/Info.plist"):
        p = os.path.join(path, f)
        d, err = load_plist(p, 1 << 20)
        if isinstance(d, dict):
            v = d.get("CFBundleShortVersionString") or d.get("CFBundleVersion")
            ts = time.strftime("%Y-%m-%d", time.localtime(os.stat(p).st_mtime))
            return (str(v) if v is not None else None), ts
    return None, None


def collect_posture(ctx: EnvContext) -> None:
    ctx.progress("stan zabezpieczeń")
    post = ctx.posture
    sigs_by: list[tuple[str, str, list[Signal]]] = []
    mac_ver = platform.mac_ver()[0]
    r = run(["/usr/bin/sw_vers"], timeout=5)
    build = re.search(r"BuildVersion:\s*(\S+)", r.out)
    post["os"] = {"version": mac_ver, "build": build.group(1) if build else None, "arch": platform.machine()}
    post["running_as_root"] = ctx.is_root

    # SIP
    r = run(["/usr/bin/csrutil", "status"], timeout=10)
    txt = r.out.strip()
    post["sip"] = "enabled" if "status: enabled" in txt else "disabled" if "status: disabled" in txt \
        else ("custom" if "Custom Configuration" in txt else ("unknown" if not txt else txt[:120]))
    if post["sip"] == "disabled":
        sigs_by.append(("System Integrity Protection (SIP) wyłączony", "csrutil",
                        [Signal(f"{S}.SIPDisabled", 25, Confidence.MEDIUM,
                                "SIP jest wyłączony (rootkity mogą modyfikować system)", [txt])]))
    elif post["sip"] == "custom":
        sigs_by.append(("System Integrity Protection (SIP) częściowo wyłączony", "csrutil",
                        [Signal(f"{S}.SIPCustom", 15, Confidence.MEDIUM,
                                "SIP działa w konfiguracji niestandardowej (osłabionej)", [txt[:200]])]))
    # Signed System Volume: with "authenticated root" off the system volume no longer has to match Apple's seal,
    # which is what a rootkit modifying /System needs (CIS macOS benchmark, Wazuh SCA)
    r = run(["/usr/bin/csrutil", "authenticated-root", "status"], timeout=10)
    ar = r.out.strip()
    post["authenticated_root"] = "enabled" if "status: enabled" in ar else "disabled" if "status: disabled" in ar \
        else "unknown"
    if post["authenticated_root"] == "disabled":
        sigs_by.append(("Pieczęć woluminu systemowego (SSV) wyłączona", "csrutil authenticated-root",
                        [Signal(f"{S}.SSVDisabled", 25, Confidence.MEDIUM,
                                "„Authenticated Root” jest wyłączone: pliki systemu macOS nie muszą zgadzać się z pieczęcią "
                                "Apple (można je podmienić)", [ar])]))
    # Gatekeeper
    r = run(["/usr/sbin/spctl", "--status"], timeout=10)
    gk = r.out.strip() or r.err.strip()
    post["gatekeeper"] = "enabled" if "assessments enabled" in gk else "disabled" if "disabled" in gk else gk[:80]
    if post["gatekeeper"] == "disabled":
        sigs_by.append(("Gatekeeper wyłączony", "spctl",
                        [Signal(f"{S}.GatekeeperDisabled", 25, Confidence.MEDIUM,
                                "Gatekeeper jest wyłączony (niepodpisane aplikacje uruchamiają się bez ostrzeżenia)", [gk])]))
    # FileVault
    r = run(["/usr/bin/fdesetup", "status"], timeout=10)
    fv = r.out.strip()
    post["filevault"] = "on" if "FileVault is On" in fv else "off" if "FileVault is Off" in fv else (fv[:80] or "unknown")
    if post["filevault"] == "off":
        sigs_by.append(("Szyfrowanie dysku FileVault jest wyłączone", "fdesetup",
                        [Signal(f"{S}.FileVaultOff", 10, Confidence.LOW, "Szyfrowanie dysku FileVault jest wyłączone", [fv])]))
    # Application firewall
    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    r = run([fw, "--getglobalstate"], timeout=10)
    m = re.search(r"State = (\d)", r.out)
    state = int(m.group(1)) if m else (1 if "enabled" in r.out.lower() else 0 if "disabled" in r.out.lower() else None)
    post["firewall_state"] = state
    post["firewall"] = {0: "off", 1: "on", 2: "on (block all incoming)"}.get(state, "unknown") if state is not None else "unknown"
    r = run([fw, "--getstealthmode"], timeout=10)
    post["firewall_stealth"] = "on" in r.out.lower() and "off" not in r.out.lower()
    if state == 0:
        sigs_by.append(("Zapora aplikacji jest wyłączona", "socketfilterfw",
                        [Signal(f"{S}.FirewallOff", 5, Confidence.LOW, "zapora aplikacji jest wyłączona", [])]))
    # XProtect & friends
    xp = {}
    newest = None
    for name, path in XPROTECT_PATHS.items():
        if os.path.exists(path):
            v, ts = _bundle_version(path)
            xp[name] = {"version": v, "date": ts, "path": path}
            if name.startswith("XProtect (") and ts and (newest is None or ts > newest):
                newest = ts
    post["xprotect"] = xp
    if not any(k.startswith("XProtect (") for k in xp):
        sigs_by.append(("Brak XProtect", "XProtect.bundle",
                        [Signal(f"{S}.XProtectMissing", 30, Confidence.MEDIUM, "nie znaleziono pakietu sygnatur XProtect", [])]))
    elif newest:
        age = (dt.date.today() - dt.date.fromisoformat(newest)).days
        post["xprotect_age_days"] = age
        if age > 60:
            sigs_by.append(("Sygnatury XProtect są nieaktualne", "XProtect.bundle",
                            [Signal(f"{S}.XProtectStale", 15, Confidence.LOW,
                                    f"sygnatury XProtect ostatnio zaktualizowano {age} dni temu", [newest])]))
    # Software update settings
    r = run(["/usr/sbin/softwareupdate", "--schedule"], timeout=20)
    sched = (r.out + r.err).strip()
    post["auto_update_check"] = True if "turned on" in sched else False if "turned off" in sched else None
    su, _ = load_plist("/Library/Preferences/com.apple.SoftwareUpdate.plist")
    su = su if isinstance(su, dict) else {}
    post["software_update"] = {k: su.get(k) for k in ("AutomaticDownload", "AutomaticallyInstallMacOSUpdates",
                                                      "CriticalUpdateInstall", "ConfigDataInstall", "LastSuccessfulDate")
                               if k in su}
    pending = [u.get("Display Name") + (f" {u.get('Display Version')}" if u.get("Display Version") and
                                        u.get("Display Version") not in u.get("Display Name", "") else "")
               for u in (su.get("RecommendedUpdates") or []) if isinstance(u, dict) and u.get("Display Name")]
    post["pending_updates"] = pending
    if post["auto_update_check"] is False:
        sigs_by.append(("Automatyczne sprawdzanie aktualizacji jest wyłączone", "softwareupdate",
                        [Signal(f"{S}.AutoUpdateOff", 10, Confidence.LOW, "automatyczne sprawdzanie aktualizacji oprogramowania jest wyłączone", [])]))
    if su.get("CriticalUpdateInstall") is False or su.get("ConfigDataInstall") is False:
        sigs_by.append(("Aktualizacje danych bezpieczeństwa są wyłączone", "com.apple.SoftwareUpdate",
                        [Signal(f"{S}.SecurityUpdatesOff", 20, Confidence.MEDIUM,
                                "automatyczna instalacja poprawek bezpieczeństwa / danych XProtect jest wyłączona",
                                [f"CriticalUpdateInstall={su.get('CriticalUpdateInstall')}",
                                 f"ConfigDataInstall={su.get('ConfigDataInstall')}"])]))
    os_updates = [p for p in pending if re.search(r"(?i)macos|security|safari", p)]
    if os_updates:
        sigs_by.append(("Oczekują aktualizacje systemu operacyjnego", "softwareupdate",
                        [Signal(f"{S}.UpdatesPending", 5, Confidence.LOW, "dostępne aktualizacje macOS/bezpieczeństwa nie są zainstalowane",
                                os_updates[:5])]))
    # Quarantine / Gatekeeper tweaks
    for h in ctx.homes:
        for f in (os.path.join(h.home, "Library/Preferences/com.apple.LaunchServices.plist"),
                  os.path.join(h.home, "Library/Preferences/com.apple.LaunchServices/com.apple.LaunchServices.plist")):
            d, _ = load_plist(f)
            if isinstance(d, dict) and d.get("LSQuarantine") is False:
                post["quarantine_disabled"] = True
                sigs_by.append(("Kwarantanna pobranych plików wyłączona", f,
                                [Signal(f"{S}.QuarantineDisabled", 30, Confidence.MEDIUM,
                                        "LSQuarantine jest wyłączone: pobrane pliki nie trafiają na kwarantannę (obejście Gatekeepera)", [f])]))
    d, _ = load_plist("/Library/Preferences/com.apple.security.plist")
    if isinstance(d, dict) and d.get("GKAutoRearm") is False:
        sigs_by.append(("Automatyczne ponowne włączanie Gatekeepera wyłączone", "/Library/Preferences/com.apple.security.plist",
                        [Signal(f"{S}.GKNoRearm", 10, Confidence.LOW, "Gatekeeper nie włączy się ponownie automatycznie", [])]))
    # boot-args weakening code signing
    r = run(["/usr/sbin/nvram", "boot-args"], timeout=10)
    if r.ok and r.out.strip():
        ba = r.out.strip().split("\t", 1)[-1]
        post["boot_args"] = ba
        if re.search(r"amfi_get_out_of_my_way|cs_enforcement_disable|amfi=0x|amfi_allow_any_signature|"
                     r"cs_debug|-arm64e_preview_abi|amfi_unrestrict", ba):
            sigs_by.append(("Egzekwowanie podpisów kodu osłabione przez boot-args", "nvram boot-args",
                            [Signal(f"{S}.AMFIDisabled", 40, Confidence.HIGH,
                                    "boot-args wyłączają/osłabiają egzekwowanie podpisów kodu AMFI", [ba])]))
    # login window
    d, _ = load_plist("/Library/Preferences/com.apple.loginwindow.plist")
    if isinstance(d, dict):
        post["guest_account"] = bool(d.get("GuestEnabled"))
        if d.get("autoLoginUser"):
            post["auto_login_user"] = d.get("autoLoginUser")
            sigs_by.append(("Automatyczne logowanie jest włączone", "com.apple.loginwindow",
                            [Signal(f"{S}.AutoLogin", 10, Confidence.LOW, "automatyczne logowanie jest włączone", [str(d.get("autoLoginUser"))])]))
    post["kcpassword_present"] = os.path.exists("/etc/kcpassword")
    for title, loc, sigs in sigs_by:
        ctx.add_finding("posture", title, loc, sigs, {})


def collect_extensions(ctx: EnvContext) -> None:
    ctx.progress("rozszerzenia jądra i systemu")
    # loaded kexts
    r = run(["/usr/bin/kmutil", "showloaded", "--list-only"], timeout=60)
    if not r.ok:
        r = run(["/usr/sbin/kextstat", "-l"], timeout=60)
    loaded = []
    if r.ok:
        for line in r.out.splitlines():
            m = re.search(r"\s([A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+)\s+\(([^)]*)\)", line)
            if m and not m.group(1).startswith("com.apple."):
                loaded.append({"bundle_id": m.group(1), "version": m.group(2)})
    else:
        ctx.limit("nie udało się wylistować załadowanych rozszerzeń jądra (kmutil/kextstat zawiodły)")
    installed = []
    for base in ("/Library/Extensions", "/Library/StagedExtensions/Library/Extensions"):
        for k in glob.glob(os.path.join(base, "*.kext")):
            si = ctx.sign(k)
            d, _ = load_plist(os.path.join(k, "Contents/Info.plist"))
            bid = d.get("CFBundleIdentifier") if isinstance(d, dict) else None
            installed.append({"path": k, "bundle_id": bid, "signer": si.signer, "team_id": si.team_id or None})
            sigs = ctx.signing_signals(k, "Heur:Env.Kext", "rozszerzenie jądra", sev=1.2, info=si)
            if any(l["bundle_id"] == bid for l in loaded):
                sigs.append(Signal("Heur:Env.Kext.ThirdPartyLoaded", 5, Confidence.LOW,
                                   "załadowane rozszerzenie jądra firmy trzeciej", [bid or k]))
                ctx.add_target(k, "loaded third-party kernel extension", 1)
            ctx.add_finding("kext", f"Rozszerzenie jądra {os.path.basename(k)}", k, sigs, installed[-1])
    ctx.inventory["kexts"] = {"loaded_third_party": loaded, "installed": installed}
    for l in loaded:
        if not any(i["bundle_id"] == l["bundle_id"] for i in installed):
            ctx.add_finding("kext", f"Załadowane rozszerzenie jądra {l['bundle_id']}", l["bundle_id"],
                            [Signal("Heur:Env.Kext.ThirdPartyLoaded", 5, Confidence.LOW,
                                    "załadowane rozszerzenie jądra firmy trzeciej (nie znaleziono pakietu w /Library/Extensions)",
                                    [l["bundle_id"]])], l)
    # system extensions
    r = run(["/usr/bin/systemextensionsctl", "list"], timeout=30)
    sx = []
    if r.ok:
        category = None
        for line in r.out.splitlines():
            if line.startswith("---"):
                category = line.strip("- ").strip()
                continue
            parts = line.split("\t")
            if len(parts) >= 6 and parts[0] in ("*", "", " ") and "(" in parts[3]:
                bid, _, ver = parts[3].partition(" (")
                sx.append({"category": category, "enabled": parts[0] == "*", "active": parts[1] == "*",
                           "team_id": parts[2].strip(), "bundle_id": bid.strip(), "version": ver.rstrip(")"),
                           "name": parts[4].strip(), "state": parts[5].strip()})
    else:
        ctx.limit("systemextensionsctl list nie powiodło się; rozszerzenia systemu nie zostały wyliczone")
    ctx.inventory["system_extensions"] = sx
    for e in sx:
        if e["bundle_id"].startswith("com.apple."):
            continue
        sigs = [Signal("Heur:Env.SysExt.ThirdParty", 0, Confidence.INFO,
                       f"rozszerzenie systemu firmy trzeciej ({e.get('category') or 'nieznany typ'})", [e["bundle_id"]])]
        if not e["team_id"] or e["team_id"] in ("-", "(null)"):
            sigs.append(Signal("Heur:Env.SysExt.NoTeam", 25, Confidence.MEDIUM, "rozszerzenie systemu bez identyfikatora zespołu",
                               [e["bundle_id"]]))
        if "endpoint_security" in (e.get("category") or "") and e["active"]:
            sigs.append(Signal("Heur:Env.SysExt.EndpointSecurity", 5, Confidence.LOW,
                               "aktywne rozszerzenie Endpoint Security (widzi wszystkie zdarzenia procesów/plików)", [e["bundle_id"]]))
        ctx.add_finding("kext", f"Rozszerzenie systemu {e['name'] or e['bundle_id']}", e["bundle_id"], sigs, e, allow_zero=True)


def _parse_profiles(text: str) -> list[dict]:
    out = []
    for m in re.finditer(r"attribute:\s*profileIdentifier:\s*(\S+)", text):
        out.append({"identifier": m.group(1)})
    names = re.findall(r"attribute:\s*name:\s*(.+)", text)
    for i, n in enumerate(names):
        if i < len(out):
            out[i]["name"] = n.strip()
    return out


def collect_profiles(ctx: EnvContext) -> None:
    ctx.progress("profile konfiguracji i zarządzane preferencje")
    r = run(["/usr/bin/profiles", "status", "-type", "enrollment"], timeout=20)
    mdm = "MDM enrollment: Yes" in r.out
    dep = "Enrolled via DEP: Yes" in r.out
    ctx.posture["mdm_enrolled"] = mdm
    ctx.posture["dep_enrolled"] = dep
    profiles: list[dict] = []
    if ctx.is_root:
        r = run(["/usr/bin/profiles", "list", "-all"], timeout=30)
        profiles = _parse_profiles(r.out)
    else:
        r = run(["/usr/bin/profiles", "list"], timeout=30)
        profiles = _parse_profiles(r.out)
        ctx.limit("profile konfiguracji na poziomie komputera wymagają roota (`profiles list -all`); "
                  "sprawdzono tylko profile użytkownika i /Library/Managed Preferences")
    ctx.inventory["profiles"] = profiles
    for p in profiles:
        sig = Signal("Heur:Env.Profile.Installed", 5 if mdm else 10, Confidence.LOW,
                     "zainstalowany profil konfiguracji" + (" (urządzenie zarządzane przez MDM)" if mdm else
                                                          " na Macu bez MDM (profile bywają wektorem adware/przejęcia)"),
                     [p.get("identifier", "?")])
        ctx.add_finding("profile", f"Profil konfiguracji {p.get('name') or p.get('identifier')}",
                        p.get("identifier", "?"), [sig], p)
    # managed preferences written by profiles: browser hijack policies
    mp_root = "/Library/Managed Preferences"
    files = glob.glob(os.path.join(glob.escape(mp_root), "*.plist")) + \
        glob.glob(os.path.join(glob.escape(mp_root), "*", "*.plist"))
    domains = sorted({os.path.basename(f)[:-6] for f in files})
    ctx.inventory["managed_preference_domains"] = domains
    for f in files:
        dom = os.path.basename(f)[:-6]
        if dom not in BROWSER_POLICY_DOMAINS:
            continue
        d, err = load_plist(f)
        if not isinstance(d, dict):
            continue
        keys = [k for k in d if k in BROWSER_POLICY_KEYS]
        if not keys:
            continue
        ev = []
        for k in keys:
            v = d[k]
            ev.append(f"{k}={str(v)[:160]}")
        ctx.add_finding("profile", f"Zarządzana polityka przeglądarki dla {dom}", f,
                        [Signal("Heur:Env.Profile.BrowserPolicy", 10 if mdm else 35,
                                Confidence.LOW if mdm else Confidence.MEDIUM,
                                "profil konfiguracji wymusza rozszerzenia/stronę startową/wyszukiwarkę/proxy przeglądarki"
                                + (" (Mac zarządzany przez MDM)" if mdm else " na Macu bez MDM (technika porywacza przeglądarki)"),
                                ev[:6], pua=not mdm)], {"domain": dom, "keys": keys})


def collect_tcc(ctx: EnvContext) -> None:
    ctx.progress("uprawnienia prywatności (TCC)")
    dbs = [(h.name, os.path.join(h.home, "Library/Application Support/com.apple.TCC/TCC.db")) for h in ctx.homes]
    dbs.append(("system", "/Library/Application Support/com.apple.TCC/TCC.db"))
    grants: list[dict] = []
    readable_any = False
    for owner, db in dbs:
        if not os.path.exists(db):
            continue
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
            rows = con.execute("SELECT service, client, client_type, auth_value FROM access").fetchall()
            con.close()
            readable_any = True
        except sqlite3.Error:
            continue
        for service, client, ctype, auth in rows:
            if service not in TCC_SERVICES or auth != 2:
                continue
            client = str(client)
            if client.startswith("com.apple.") or (ctype == 1 and classify_path(client).has("apple")):
                continue
            grants.append({"db": owner, "service": service, "permission": TCC_SERVICES[service], "client": client,
                           "client_type": "path" if ctype == 1 else "bundle_id"})
    ctx.fda = readable_any
    ctx.posture["full_disk_access"] = readable_any
    if not readable_any:
        ctx.limit("TCC.db jest nieczytelny: nadaj terminalowi/skanerowi Pełny dostęp do dysku, aby sprawdzić uprawnienia prywatności "
                  "(Dostępność, Nagrywanie ekranu, Monitorowanie wprowadzania, Pełny dostęp do dysku)")
        return
    if not os.access("/Library/Application Support/com.apple.TCC/TCC.db", os.R_OK) or not ctx.is_root:
        ctx.limit("systemowy TCC.db (uprawnienia Dostępność / Nagrywanie ekranu / Pełny dostęp do dysku) może wymagać roota + Pełnego dostępu do dysku")
    ctx.inventory["tcc_grants"] = grants
    by_client: dict[str, list[dict]] = {}
    for g in grants:
        by_client.setdefault(g["client"], []).append(g)
    for client, gs in by_client.items():
        perms = sorted({g["permission"] for g in gs})
        sigs = [Signal("Heur:Env.TCC.SensitiveGrant", 0, Confidence.INFO,
                       "klient spoza Apple ma wrażliwe uprawnienia prywatności", perms)]
        if gs[0]["client_type"] == "path":
            if not os.path.exists(client):
                sigs.append(Signal("Heur:Env.TCC.MissingClient", 5, Confidence.LOW, "program z nadanymi uprawnieniami już nie istnieje", [client]))
            else:
                sigs += [s.scaled(1.0) for s in path_signals(client, "Heur:Env.TCC", "uprzywilejowany klient")]
                si = ctx.sign(client)
                sigs += ctx.signing_signals(client, "Heur:Env.TCC", "uprzywilejowany klient", sev=1.2, info=si)
                ctx.add_target(client, "binary with sensitive TCC permissions", 1)
        ctx.add_finding("tcc", f"{client} ma: {', '.join(perms)}", client, sigs, {"grants": gs}, allow_zero=True)


def collect_gatekeeper_bypassed_apps(ctx: EnvContext) -> None:
    """Apps that run without a Developer ID/App Store signature => the user overrode Gatekeeper
    (or quarantine was stripped)."""
    ctx.progress("aplikacje bez zaufanego podpisu")
    roots = ["/Applications"] + [os.path.join(h.home, "Applications") for h in ctx.homes]
    apps = []
    for r in roots:
        apps += glob.glob(os.path.join(glob.escape(r), "*.app")) + glob.glob(os.path.join(glob.escape(r), "*", "*.app"))
    ctx.codesign.prefetch(apps)
    weak = []
    for a in sorted(set(apps)):
        si = ctx.sign(a)
        if si.trusted or si.status in ("notcode", "missing", "error"):
            continue
        weak.append({"app": a, "signer": si.signer})
        ctx.add_target(a, "application without a trusted signature", 1)
    ctx.inventory["apps_total"] = len(set(apps))
    ctx.inventory["apps_without_trusted_signature"] = weak
    if weak:
        ctx.add_finding("posture", f"{len(weak)} aplikacji działa bez podpisu Developer ID / App Store",
                        "/Applications",
                        [Signal("Heur:Env.Posture.UntrustedApps", 5, Confidence.LOW,
                                "aplikacje niepodpisane lub podpisane ad-hoc (Gatekeeper został ominięty lub "
                                "zbudowano je lokalnie)", [w["app"] for w in weak[:10]])], {"apps": weak})

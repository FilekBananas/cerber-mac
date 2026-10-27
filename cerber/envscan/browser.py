"""Browser extensions (Chromium family, Firefox family, Safari) and native messaging hosts."""
from __future__ import annotations

import glob
import json
import os
import re
from collections import deque

from ..core import Confidence
from .launchd_rules import ADWARE_NAME_RX
from .model import Signal
from .patterns import path_signals, redact
from .util import EnvContext, read_text, run, safe_listdir
from .persistence import check_executable

B = "Heur:Env.Browser"
CHROMIUM_ROOTS = {
    "Chrome": "Library/Application Support/Google/Chrome",
    "Chrome Beta": "Library/Application Support/Google/Chrome Beta",
    "Chrome Dev": "Library/Application Support/Google/Chrome Dev",
    "Chrome Canary": "Library/Application Support/Google/Chrome Canary",
    "Chromium": "Library/Application Support/Chromium",
    "Brave": "Library/Application Support/BraveSoftware/Brave-Browser",
    "Edge": "Library/Application Support/Microsoft Edge",
    "Arc": "Library/Application Support/Arc/User Data",
    "Dia": "Library/Application Support/Dia/User Data",
    "Opera": "Library/Application Support/com.operasoftware.Opera",
    "Opera GX": "Library/Application Support/com.operasoftware.OperaGX",
    "Vivaldi": "Library/Application Support/Vivaldi",
    "Yandex": "Library/Application Support/Yandex/YandexBrowser",
    "Comet": "Library/Application Support/Comet",
    "Thorium": "Library/Application Support/Thorium",
    "ChatGPT Atlas": "Library/Application Support/com.openai.atlas/browser-data",
}
FIREFOX_ROOTS = {
    "Firefox": "Library/Application Support/Firefox/Profiles",
    "LibreWolf": "Library/Application Support/librewolf/Profiles",
    "Waterfox": "Library/Application Support/Waterfox/Profiles",
    "Zen": "Library/Application Support/zen/Profiles",
    "Floorp": "Library/Application Support/Floorp/Profiles",
}
NMH_SYSTEM_DIRS = ("/Library/Google/Chrome/NativeMessagingHosts", "/Library/Application Support/Chromium/NativeMessagingHosts",
                   "/Library/Microsoft/Edge/NativeMessagingHosts", "/Library/Application Support/Mozilla/NativeMessagingHosts",
                   "/Library/BraveSoftware/Brave-Browser/NativeMessagingHosts", "/Library/Vivaldi/NativeMessagingHosts")
STORE_UPDATE_HOSTS = ("clients2.google.com", "edge.microsoft.com", "extension-updates.opera.com",
                      "update.googleapis.com", "chrome.google.com")
BROAD_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "http://*/", "https://*/"}
HIGH_RISK = {"debugger", "proxy", "management", "nativeMessaging", "clipboardRead", "webRequestBlocking",
             "desktopCapture", "tabCapture", "privacy", "contentSettings", "browsingData", "cookies", "webRequest",
             "declarativeNetRequestWithHostAccess", "scripting", "history", "downloads", "tabs", "webNavigation"}
# permissions that matter on their own (the rest only in combination with broad host access)
CRITICAL = {"debugger", "proxy", "management", "nativeMessaging", "clipboardRead"}
LOCATION_NAMES = {1: "internal", 2: "external_pref", 3: "external_registry", 4: "unpacked", 5: "component",
                  6: "external_pref_download", 7: "external_policy_download", 8: "command_line", 9: "external_policy",
                  10: "external_component"}
SKIP_DIRS = {"Extensions", "Cache", "Code Cache", "GPUCache", "Service Worker", "IndexedDB", "Local Storage",
             "Session Storage", "blob_storage", "Crashpad", "component_crx_cache", "extensions_crx_cache",
             "Safe Browsing", "optimization_guide_model_store", "GrShaderCache", "GraphiteDawnCache", "ShaderCache",
             "WidevineCdm", "Local Extension Settings", "Sync Extension Settings", "File System", "WebStorage",
             "OnDeviceHeadSuggestModel", "OptGuideOnDeviceModel", "Snapshots", "Crash Reports", "databases"}


def _load_json(path: str, limit: int = 32 << 20) -> dict | None:
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as fh:
            return json.loads(fh.read().decode("utf-8-sig", "replace"))
    except (OSError, ValueError):
        return None


def _find_profiles(root: str, max_depth: int = 3, max_dirs: int = 400) -> list[str]:
    out: list[str] = []
    q = deque([(root, 0)])
    seen = 0
    while q and seen < max_dirs:
        d, depth = q.popleft()
        seen += 1
        names, err = safe_listdir(d)
        if err:
            continue
        s = set(names)
        if "Preferences" in s and ("Extensions" in s or "Secure Preferences" in s):
            out.append(d)
            continue
        if depth >= max_depth:
            continue
        for n in names:
            if n in SKIP_DIRS or n.startswith("."):
                continue
            p = os.path.join(d, n)
            if os.path.isdir(p) and not os.path.islink(p):
                q.append((p, depth + 1))
    return out


def _resolve_msg(name: str, ext_dir: str, manifest: dict) -> str:
    if not isinstance(name, str) or not name.startswith("__MSG_"):
        return name if isinstance(name, str) else ""
    key = name[6:].rstrip("_").lower()
    loc = manifest.get("default_locale") or "en"
    for cand in (loc, "en", "en_US"):
        msgs = _load_json(os.path.join(ext_dir, "_locales", cand, "messages.json"), 4 << 20)
        if isinstance(msgs, dict):
            for k, v in msgs.items():
                if k.lower() == key and isinstance(v, dict):
                    return str(v.get("message", name))
    return name


def _permissions(manifest: dict) -> tuple[set, set]:
    perms, hosts = set(), set()
    for key in ("permissions", "optional_permissions", "host_permissions", "optional_host_permissions"):
        for p in manifest.get(key) or []:
            if isinstance(p, str):
                if "://" in p or p == "<all_urls>":
                    hosts.add(p)
                else:
                    perms.add(p)
    for cs in manifest.get("content_scripts") or []:
        if isinstance(cs, dict):
            for m in cs.get("matches") or []:
                if isinstance(m, str):
                    hosts.add(m)
    return perms, hosts


def _newest_version_dir(ext_root: str) -> str | None:
    names, _ = safe_listdir(ext_root)
    dirs = [os.path.join(ext_root, n) for n in names if os.path.isfile(os.path.join(ext_root, n, "manifest.json"))]
    if not dirs:
        return None
    return max(dirs, key=lambda p: os.stat(p).st_mtime)


def _chromium(ctx: EnvContext, browser: str, root: str, home: str, inv: list, mdm: bool) -> None:
    for prof in _find_profiles(root):
        settings: dict = {}
        for f in ("Preferences", "Secure Preferences"):
            d = _load_json(os.path.join(prof, f))
            if isinstance(d, dict):
                s = (d.get("extensions") or {}).get("settings") or {}
                if isinstance(s, dict):
                    for k, v in s.items():
                        if isinstance(v, dict):
                            settings.setdefault(k, {}).update(v)
        ext_root = os.path.join(prof, "Extensions")
        ids = set(settings) | {n for n in safe_listdir(ext_root)[0] if re.fullmatch(r"[a-p]{32}", n)}
        pname = re.sub(r"[A-Za-z0-9_-]{20,}", lambda m: m.group(0)[:6] + "…", os.path.relpath(prof, root))
        for eid in sorted(ids):
            st = settings.get(eid, {})
            loc = st.get("location")
            if loc in (5, 10):
                continue  # browser components
            path = st.get("path")
            if isinstance(path, str) and path and not os.path.isabs(path):
                vdir = os.path.join(ext_root, path)
            elif isinstance(path, str) and os.path.isabs(path):
                vdir = path
            else:
                vdir = _newest_version_dir(os.path.join(ext_root, eid)) if os.path.isdir(os.path.join(ext_root, eid)) else None
            manifest = _load_json(os.path.join(vdir, "manifest.json"), 4 << 20) if vdir else None
            if not isinstance(manifest, dict):
                manifest = st.get("manifest") if isinstance(st.get("manifest"), dict) else None
            if not isinstance(manifest, dict):
                continue
            name = _resolve_msg(manifest.get("name", ""), vdir or "", manifest)
            update_url = manifest.get("update_url") or ""
            from_store = bool(st.get("from_webstore")) or any(h in update_url for h in STORE_UPDATE_HOSTS)
            perms, hosts = _permissions(manifest)
            broad = bool(hosts & BROAD_HOSTS) or any(re.match(r"^\*?://\*/|^https?://\*/", h) for h in hosts)
            risky = sorted(perms & CRITICAL) + (sorted(perms & HIGH_RISK - CRITICAL) if broad else [])
            if broad:
                risky.append("<all hosts>")
            enabled = not (st.get("state") == 0 or st.get("disable_reasons") not in (None, [], 0))
            rec = {"browser": browser, "profile": pname, "id": eid, "name": redact(name, 80),
                   "version": manifest.get("version"), "manifest_version": manifest.get("manifest_version"),
                   "location": LOCATION_NAMES.get(loc, loc), "from_store": from_store, "enabled": enabled,
                   "update_url": update_url or None, "risky_permissions": risky, "path": vdir}
            inv.append(rec)
            sigs: list[Signal] = []
            if loc == 4:
                sigs.append(Signal(f"{B}.UnpackedExtension", 15, Confidence.LOW,
                                   "rozszerzenie niespakowane, wczytane w trybie deweloperskim", [vdir or eid]))
                if vdir:
                    sigs += [s.scaled(0.8) for s in path_signals(vdir, f"{B}.Extension", "folder rozszerzenia", home)
                             if not s.name.endswith("UserDocsPath")]
            elif loc == 8:
                sigs.append(Signal(f"{B}.CommandLineExtension", 30, Confidence.MEDIUM,
                                   "rozszerzenie wczytane przez --load-extension (styl ChromeLoader)", [vdir or eid]))
            elif loc in (2, 3, 6) and not from_store:
                sigs.append(Signal(f"{B}.ExternalInstall", 25, Confidence.MEDIUM,
                                   "rozszerzenie wymuszone przez zewnętrzne oprogramowanie, spoza sklepu", [update_url or eid]))
            elif loc in (7, 9):
                sigs.append(Signal(f"{B}.PolicyInstalled", 5 if mdm else 20, Confidence.LOW if mdm else Confidence.MEDIUM,
                                   "rozszerzenie zainstalowane wymuszonie przez politykę" + ("" if mdm else " na Macu bez MDM"),
                                   [eid], pua=not mdm))
            elif not from_store and loc in (1, None):
                sigs.append(Signal(f"{B}.OffStoreExtension", 25, Confidence.MEDIUM,
                                   "rozszerzenie nie pochodzi z oficjalnego sklepu", [update_url or "no update_url"]))
            if risky:
                if from_store and loc not in (4, 8):
                    sigs.append(Signal(f"{B}.PowerfulExtension", 0, Confidence.INFO,
                                       "rozszerzenie ze sklepu z rozległymi uprawnieniami", risky[:8]))
                else:
                    sigs.append(Signal(f"{B}.DangerousPermissions", 20 if len(risky) >= 2 else 10, Confidence.MEDIUM,
                                       "rozszerzenie spoza sklepu z groźnymi uprawnieniami", risky[:8]))
            if ADWARE_NAME_RX.search(name or ""):
                sigs.append(Signal(f"{B}.AdwareName", 30, Confidence.MEDIUM, "nazwa rozszerzenia pasuje do znanego adware",
                                   [name], pua=True))
            if not enabled:
                sigs = [s.scaled(0.5, "wyłączone") if s.score else s for s in sigs]
            show_info = bool(risky) and ("debugger" in risky or "proxy" in risky or "management" in risky
                                         or ("<all hosts>" in risky and ({"cookies", "webRequestBlocking"} & set(risky))))
            f = ctx.add_finding("browser", f"Rozszerzenie {browser} '{rec['name']}' ({pname})", f"{browser}:{pname}:{eid}",
                                sigs, rec, allow_zero=show_info)
            if vdir and os.path.isdir(vdir) and ctx.options.get("extension_targets", True):
                ctx.add_target(vdir, f"{browser} extension {eid}", 2 if f and f.score >= 10 else 0)
    # native messaging hosts of this browser
    _nmh_dir(ctx, os.path.join(root, "NativeMessagingHosts"), browser, home)


def _nmh_dir(ctx: EnvContext, d: str, browser: str, home: str) -> None:
    for n in safe_listdir(d)[0]:
        if not n.endswith(".json"):
            continue
        p = os.path.join(d, n)
        m = _load_json(p, 1 << 20)
        if not isinstance(m, dict):
            continue
        exe = m.get("path") if isinstance(m.get("path"), str) else ""
        if exe and not os.path.isabs(exe):
            exe = os.path.normpath(os.path.join(d, exe))
        origins = [o for o in (m.get("allowed_origins") or m.get("allowed_extensions") or []) if isinstance(o, str)]
        rec = {"browser": browser, "manifest": p, "name": m.get("name"), "path": exe, "allowed_origins": origins[:10]}
        ctx.inv("native_messaging_hosts").append(rec)
        if not exe:
            continue
        sigs = path_signals(exe, f"{B}.NativeHost", "host native messaging", home)
        s2, sinfo, ed = check_executable(ctx, exe, f"{B}.NativeHost", "host native messaging")
        sigs = EnvContext.dampen_trusted(sigs + s2, sinfo)
        rec["signer"] = sinfo.signer if sinfo else ed.get("kind")
        if ed.get("kind") not in (None, "missing"):
            ctx.add_target(exe, f"{browser} native messaging host {m.get('name')}", 1)
        ctx.add_finding("browser", f"Host native messaging {browser}: {m.get('name')}", p, sigs, rec)


def _firefox(ctx: EnvContext, browser: str, root: str, home: str, inv: list) -> None:
    for prof in glob.glob(os.path.join(glob.escape(root), "*")):
        ej = _load_json(os.path.join(prof, "extensions.json"))
        if isinstance(ej, dict):
            for a in ej.get("addons") or []:
                if not isinstance(a, dict) or a.get("type") not in ("extension", "webextension", None):
                    continue
                loc = a.get("location") or ""
                if loc in ("app-builtin", "app-system-defaults", "app-system-addons"):
                    continue
                name = ((a.get("defaultLocale") or {}).get("name")) or a.get("id")
                up = a.get("userPermissions") or {}
                perms = set(p for p in (up.get("permissions") or []) if isinstance(p, str))
                origins = set(o for o in (up.get("origins") or []) if isinstance(o, str))
                broad = bool(origins & BROAD_HOSTS)
                risky = sorted(perms & CRITICAL) + (sorted(perms & HIGH_RISK - CRITICAL) if broad else []) + \
                    (["<all hosts>"] if broad else [])
                src = a.get("sourceURI") or ""
                amo = bool(re.match(r"^https://(?:addons\.mozilla\.org|addons\.cdn\.mozilla\.net)/", src))
                signed = a.get("signedState")
                rec = {"browser": browser, "profile": os.path.basename(prof), "id": a.get("id"), "name": redact(str(name), 80),
                       "version": a.get("version"), "location": loc, "from_store": amo, "signed_state": signed,
                       "enabled": bool(a.get("active")), "risky_permissions": risky, "path": a.get("path")}
                inv.append(rec)
                sigs: list[Signal] = []
                if isinstance(signed, int) and signed <= 0:
                    sigs.append(Signal(f"{B}.UnsignedAddon", 30, Confidence.MEDIUM, "dodatek nie jest podpisany przez Mozillę",
                                       [str(a.get("id"))]))
                if loc == "app-temporary":
                    sigs.append(Signal(f"{B}.TemporaryAddon", 5, Confidence.LOW, "dodatek tymczasowy (debug)", []))
                elif loc not in ("app-profile", "") :
                    sigs.append(Signal(f"{B}.SideloadedAddon", 20, Confidence.MEDIUM,
                                       f"dodatek zainstalowany poza profilem ({loc})", [str(a.get("path"))]))
                if src and not amo and loc == "app-profile":
                    sigs.append(Signal(f"{B}.OffStoreExtension", 10, Confidence.LOW, "dodatek nie pochodzi z AMO",
                                       [redact(src, 120)]))
                if risky and not amo:
                    sigs.append(Signal(f"{B}.DangerousPermissions", 15, Confidence.MEDIUM,
                                       "dodatek spoza sklepu z groźnymi uprawnieniami", risky[:8]))
                if ADWARE_NAME_RX.search(str(name)):
                    sigs.append(Signal(f"{B}.AdwareName", 30, Confidence.MEDIUM, "nazwa dodatku pasuje do znanego adware",
                                       [str(name)], pua=True))
                f = ctx.add_finding("browser", f"Dodatek {browser} '{rec['name']}'", f"{browser}:{rec['profile']}:{a.get('id')}",
                                    sigs, rec)
                pth = a.get("path")
                if isinstance(pth, str) and os.path.exists(pth) and ctx.options.get("extension_targets", True):
                    ctx.add_target(pth, f"{browser} add-on {a.get('id')}", 2 if f and f.score >= 10 else 0)
        # proxy auto-config hijack via prefs
        for pf in ("user.js", "prefs.js"):
            body = read_text(os.path.join(prof, pf), 4 << 20) or ""
            m = re.search(r'user_pref\("network\.proxy\.autoconfig_url",\s*"([^"]+)"\)', body)
            t = re.search(r'user_pref\("network\.proxy\.type",\s*(\d+)\)', body)
            if m and t and t.group(1) == "2":
                ctx.add_finding("browser", f"{browser} używa adresu automatycznej konfiguracji proxy (PAC)", os.path.join(prof, pf),
                                [Signal(f"{B}.FirefoxPAC", 20, Confidence.MEDIUM, "ruch przeglądarki kierowany plikiem PAC",
                                        [redact(m.group(1))])], {"profile": os.path.basename(prof)})


def _safari(ctx: EnvContext, inv: list) -> None:
    for sdk in ("com.apple.Safari.web-extension", "com.apple.Safari.extension", "com.apple.Safari.content-blocker"):
        r = run(["/usr/bin/pluginkit", "-mAvvv", "-p", sdk], timeout=20)
        if not r.ok:
            continue
        cur: dict | None = None
        for line in r.out.splitlines():
            m = re.match(r"^\s*[+\-=!?]?\s*([\w.\-]+)\(([^)]*)\)\s*$", line)
            if m:
                cur = {"browser": "Safari", "id": m.group(1), "version": m.group(2), "type": sdk.rsplit(".", 1)[-1]}
                inv.append(cur)
                continue
            m = re.match(r"^\s*(Path|Parent Bundle|Display Name)\s*=\s*(.+)$", line)
            if m and cur is not None:
                cur[m.group(1).lower().replace(" ", "_")] = m.group(2).strip()
    for rec in [r for r in inv if r.get("browser") == "Safari"]:
        p = rec.get("path")
        if not p or rec["id"].startswith("com.apple."):
            continue
        si = ctx.sign(p)
        rec["signer"] = si.signer
        sigs = ctx.signing_signals(p, f"{B}.Safari", "rozszerzenie Safari", info=si)
        sigs += path_signals(p, f"{B}.Safari", "rozszerzenie Safari")
        if ADWARE_NAME_RX.search(" ".join(str(v) for v in rec.values())):
            sigs.append(Signal(f"{B}.AdwareName", 30, Confidence.MEDIUM, "rozszerzenie Safari pasuje do znanego adware",
                               [rec["id"]], pua=True))
        sigs = EnvContext.dampen_trusted(sigs, si)
        f = ctx.add_finding("browser", f"Rozszerzenie Safari {rec.get('display_name') or rec['id']}", p, sigs, rec)
        ctx.add_target(rec.get("parent_bundle") or p, "rozszerzenie Safari", 2 if f and f.score >= 10 else 0)
    for h in ctx.homes:
        legacy = os.path.join(h.home, "Library/Safari/Extensions")
        for n in safe_listdir(legacy)[0]:
            if n.endswith(".safariextz"):
                p = os.path.join(legacy, n)
                inv.append({"browser": "Safari", "legacy": p})
                ctx.add_target(p, "legacy Safari extension", 2)
                ctx.add_finding("browser", f"Stare rozszerzenie Safari {n}", p,
                                [Signal(f"{B}.LegacySafariExtension", 20, Confidence.MEDIUM,
                                        "stare rozszerzenie .safariextz (nieobsługiwane; typowa pozostałość po adware)", [n])], {})


def collect_browsers(ctx: EnvContext) -> None:
    ctx.progress("rozszerzenia przeglądarek")
    inv = ctx.inv("browser_extensions")
    mdm = bool(ctx.posture.get("mdm_enrolled"))
    found = []
    for h in ctx.homes:
        for browser, rel in CHROMIUM_ROOTS.items():
            root = os.path.join(h.home, rel)
            if os.path.isdir(root):
                found.append(browser)
                _chromium(ctx, browser, root, h.home, inv, mdm)
        for browser, rel in FIREFOX_ROOTS.items():
            root = os.path.join(h.home, rel)
            if os.path.isdir(root):
                found.append(browser)
                _firefox(ctx, browser, root, h.home, inv)
        _nmh_dir(ctx, os.path.join(h.home, "Library/Application Support/Mozilla/NativeMessagingHosts"), "Firefox", h.home)
    for d in NMH_SYSTEM_DIRS:
        _nmh_dir(ctx, d, "system-wide", ctx.homes[0].home if ctx.homes else "")
    # Firefox enterprise policies shipped inside the app bundle (adware uses them to force add-ons)
    for app in glob.glob("/Applications/Firefox*.app"):
        pol = _load_json(os.path.join(app, "Contents/Resources/distribution/policies.json"))
        if isinstance(pol, dict):
            p = (pol.get("policies") or {})
            keys = [k for k in ("ExtensionSettings", "Extensions", "Proxy", "Homepage", "SearchEngines") if k in p]
            if keys:
                ctx.add_finding("browser", "Zainstalowano polityki korporacyjne Firefoksa", app,
                                [Signal(f"{B}.FirefoxPolicy", 25, Confidence.MEDIUM,
                                        "policies.json Firefoksa wymusza rozszerzenia/proxy/stronę startową/wyszukiwarkę", keys)],
                                {"keys": keys})
    _safari(ctx, inv)
    ctx.inventory["browsers_found"] = sorted(set(found))

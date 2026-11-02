"""Recently downloaded executables/installers, stealer staging artefacts and hidden payload folders."""
from __future__ import annotations

import os
import re
import time
import zipfile

from ..core import Confidence
from .model import Signal
from .patterns import KNOWN_DOT_DIRS, command_signals, looks_random
from .util import EnvContext, MACHO_MAGICS, quarantine_info, read_bytes, read_text, safe_listdir

F = "Heur:Env.Download"
ST = "Heur:Env.Stealer"
EXEC_EXT = {"command", "tool", "sh", "zsh", "bash", "csh", "scpt", "scptd", "applescript", "jxa", "jar", "terminal",
            "workflow", "action", "webloc", "inetloc", "fileloc"}
INSTALLER_EXT = {"pkg", "mpkg", "dmg", "iso", "img", "sparseimage", "app"}
ARCHIVE_EXT = {"zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "zst", "cpio", "xip"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam"}
SCRIPT_EXT = {"py", "js", "rb", "pl", "php", "ps1", "vbs"}
SKIP_WALK = {"node_modules", ".git", "__pycache__", ".venv", "venv", "site-packages", "Pods", "DerivedData",
             ".build", "build", "dist", "target", ".next", ".gradle"}
STEALER_NAMES = {"login.keychain-db", "login.keychain", "login data", "cookies", "web data", "key4.db", "logins.json",
                 "cookies.sqlite", "passwords.txt", "password.txt", "pwd.txt", "sysinfo.txt", "filegrabber",
                 "autofills", "creditcards", "wallet.dat", "exodus.wallet", "keychain.txt", "cookies.txt",
                 "login data for account", "browsers", "wallets", "cards.txt", "history.txt", "user.txt"}
STRONG_STEALER = {"login.keychain-db", "login.keychain", "key4.db", "logins.json", "wallet.dat", "exodus.wallet",
                  "filegrabber", "sysinfo.txt", "passwords.txt"}
WIN_EXEC_EXT = {"exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "lnk", "msi",
                "ps1", "cpl", "dll", "iso", "img", "vhd", "vhdx", "jar", "reg", "url", "library-ms", "chm"}
MAC_SCRIPT_EXT = {"command", "tool", "sh", "scpt", "applescript", "terminal"}
DOUBLE_EXT_RX = re.compile(r"(?i)\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|zip|rar|mp[34]|mov|csv|html?)"
                           r"\s*\.(?:exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|lnk|app|command|jar|msi|ps1|scpt)$")
STAGING_ARCHIVE_NAMES = {"out.zip", "log.zip", "data.zip", "info.zip", "result.zip", "stolen.zip"}


def _kind(path: str, is_dir: bool) -> str | None:
    n = os.path.basename(path)
    ext = n.rsplit(".", 1)[-1].lower() if "." in n else ""
    if is_dir:
        if ext in ("app", "pkg", "mpkg", "scptd", "workflow"):
            return "app" if ext == "app" else "installer" if ext in ("pkg", "mpkg") else "script"
        return None
    if ext in INSTALLER_EXT:
        return "installer"
    if ext in EXEC_EXT:
        return "script"
    if ext in ARCHIVE_EXT:
        return "archive"
    if ext in MACRO_EXT:
        return "macro_document"
    if ext in SCRIPT_EXT:
        return "source_script"
    head = read_bytes(path, 4) or b""
    if head[:4] in MACHO_MAGICS:
        return "macho"
    if head[:2] == b"#!":
        return "script"
    return None


def _walk(root: str, max_depth: int, max_entries: int):
    """Yield (path, is_dir) without descending into bundles or dev folders."""
    count = 0
    stack = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        try:
            it = list(os.scandir(d))
        except OSError:
            continue
        for e in it:
            count += 1
            if count > max_entries:
                return
            try:
                is_dir = e.is_dir(follow_symlinks=False)
            except OSError:
                continue
            yield e.path, is_dir
            if is_dir and depth + 1 < max_depth and e.name not in SKIP_WALK and \
                    not e.name.endswith((".app", ".pkg", ".mpkg", ".bundle", ".framework", ".photoslibrary",
                                         ".xcodeproj", ".xcworkspace", ".scptd", ".workflow", ".lproj")):
                stack.append((e.path, depth + 1))


def collect_downloads(ctx: EnvContext) -> None:
    days = int(ctx.options.get("recent_days", 60))
    ctx.progress(f"ostatnie pobrania (ostatnie {days} dni)")
    cutoff = time.time() - days * 86400
    inv = ctx.inv("recent_downloads")
    for h in ctx.homes:
        for sub in ("Downloads", "Desktop"):
            root = os.path.join(h.home, sub)
            if not os.path.isdir(root):
                continue
            try:
                os.listdir(root)
            except PermissionError:
                ctx.limit(f"~/{sub} jest nieczytelny (ochrona prywatności macOS: nadaj Pełny dostęp do dysku lub dostęp do plików i folderów)")
                continue
            for path, is_dir in _walk(root, 3, 20000):
                kind = _kind(path, is_dir)
                if not kind:
                    continue
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                q = quarantine_info(path)
                t = max(st.st_mtime, getattr(st, "st_birthtime", 0), (q or {}).get("epoch", 0))
                if t < cutoff:
                    continue
                if kind in ("source_script",) and not q:
                    continue  # the user's own code
                rel = os.path.relpath(path, h.home)
                rec = {"path": path, "kind": kind, "size": st.st_size if not is_dir else None,
                       "date": time.strftime("%Y-%m-%d", time.localtime(t)),
                       "quarantine": {k: q.get(k) for k in ("agent", "time", "user_approved") if k in q} if q else None}
                sigs: list[Signal] = []
                if kind in ("macho", "app"):
                    si = ctx.sign(path)
                    rec["signer"] = si.signer
                    if not si.trusted and si.status not in ("notcode", "missing", "error"):
                        if q:
                            sigs.append(Signal(f"{F}.UntrustedApp", 20, Confidence.MEDIUM,
                                               "pobrany program nie jest podpisany przez zidentyfikowanego dewelopera",
                                               [rel, si.signer]))
                        else:
                            local = "linker-signed" in (si.flags or "")
                            sigs.append(Signal(f"{F}.NoQuarantineExec", 5 if local else 15, Confidence.LOW,
                                               "niepodpisany/ad-hoc program bez flagi kwarantanny "
                                               "(pobrany przez curl/Terminal lub kwarantanna usunięta)"
                                               + (" - wygląda na skompilowany lokalnie" if local else ""), [rel, si.signer]))
                elif kind == "archive" and path.lower().endswith(".zip") and st.st_size < (300 << 20):
                    try:
                        with zipfile.ZipFile(path) as z:
                            members = [i.filename for i in z.infolist()[:20000] if not i.is_dir()]
                    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError):
                        members = []
                    exts = [(m, m.rsplit(".", 1)[-1].lower() if "." in os.path.basename(m) else "") for m in members]
                    # .js/.sh/.jar/.dll are ordinary in source/project archives: only count them in tiny archives
                    common = {"js", "sh", "jar", "dll", "url", "reg", "cmd", "bat", "ps1"}
                    risky = [m for m, e in exts if (e in WIN_EXEC_EXT or e in MAC_SCRIPT_EXT)
                             and (e not in common or len(members) <= 5)]
                    double = [m for m in members if DOUBLE_EXT_RX.search(os.path.basename(m))]
                    rec["members"] = len(members)
                    if double:
                        sigs.append(Signal(f"{F}.DoubleExtension", 35, Confidence.MEDIUM,
                                           "pobrane archiwum zawiera plik z zwodniczym podwójnym rozszerzeniem",
                                           [os.path.basename(m) for m in double[:5]]))
                    if risky:
                        sigs.append(Signal(f"{F}.ArchiveWithExecutable", 10, Confidence.LOW,
                                           "pobrane archiwum zawiera pliki wykonywalne/skrypty",
                                           [os.path.basename(m) for m in risky[:5]]))
                        if len(members) <= 3 and q:
                            sigs.append(Signal(f"{F}.SmallDropperArchive", 10, Confidence.LOW,
                                               "małe archiwum zawierające głównie program/skrypt (wzorzec dropper)",
                                               [os.path.basename(m) for m in risky[:3]]))
                elif kind == "script" and not is_dir:
                    body = read_text(path, 512 << 10) or ""
                    sigs += command_signals(body, f"{F}.Script", "pobrany skrypt")
                    if q and path.endswith((".command", ".tool", ".terminal")):
                        sigs.append(Signal(f"{F}.DoubleClickScript", 10, Confidence.LOW,
                                           "pobrany skrypt Terminala uruchamiany dwukliknięciem", [rel]))
                inv.append(rec)
                ctx.add_target(path, f"recent download ({kind})", 2 if sigs else 1)
                ctx.add_finding("files", f"Ostatnie pobranie {os.path.basename(path)}", path, sigs, rec)


PROFILE_MARKERS = {"preferences", "secure preferences", "prefs.js", "current session", "last session",
                   "network persistent state", "times.json", "compatibility.ini", "user.js"}
ARCHIVE_ROOTS = ("/tmp", "/private/tmp", "/private/var/tmp", "/Users/Shared")


def _strict_ok(low: set[str]) -> bool:
    """$TMPDIR is busy (automation browser profiles, importers): only an unmistakable haul counts there."""
    return (len(low) >= 3 and bool(low & STRONG_STEALER)) or \
        (bool(low & {"login.keychain-db", "login.keychain"}) and len(low) >= 2)


def stealer_artifacts(root: str, depth: int, label: str, home_lib: str | None = None, group_by_root: bool = False,
                      max_entries: int = 5000, zips: bool | None = None, strict: bool = False) -> list[dict]:
    """Browser/keychain/wallet artefacts below `root`, grouped by top-level folder, plus stealer archives.

    → [{"kind": "staging"|"archive"|"archive_name", "path", "signals": [Signal], "artefacts": [names]}]
    Real (automation) browser profiles also contain Cookies/Login Data, so any folder that carries profile
    bookkeeping files (Preferences, prefs.js, ...) is ignored. `strict` ($TMPDIR): see _strict_ok, no name-only
    archive hints. Shared by the environment scan and the live watch (netwatch)."""
    zips = root.startswith(ARCHIVE_ROOTS) or strict if zips is None else zips
    out: list[dict] = []
    hits: dict[str, list[str]] = {}
    profile_dirs: set[str] = set()
    for path, is_dir in _walk(root, depth, max_entries):
        n = os.path.basename(path).lower()
        parent = os.path.dirname(path)
        if n in PROFILE_MARKERS:
            profile_dirs.add(parent)
        if n in STEALER_NAMES and not (home_lib and path.startswith(home_lib)):
            rel = os.path.relpath(path, root)
            group = root if (group_by_root or os.sep not in rel) else os.path.join(root, rel.split(os.sep, 1)[0])
            hits.setdefault(group, []).append(path)
        if not is_dir and n.endswith(".zip") and zips:
            out += stealer_archive(path, strict)
    for group, paths in hits.items():
        paths = [p for p in paths if os.path.dirname(p) not in profile_dirs]
        if not paths:
            continue
        low = {os.path.basename(p).lower() for p in paths}
        strong = low & STRONG_STEALER
        if (len(low) >= 2 or strong) and (not strict or _strict_ok(low)):
            score = 60 if (len(low) >= 3 or ("login.keychain-db" in low and len(low) >= 2)) else 45
            rels = sorted({os.path.relpath(p, group) for p in paths})[:8]
            sig = Signal(f"{ST}.Staging", score, Confidence.HIGH,
                         f"kopie danych przeglądarki/pęku kluczy/portfeli w {label} (folder przygotowawczy stealera)", rels)
            out.append({"kind": "staging", "path": group, "signals": [sig], "artefacts": rels,
                        "names": sorted(low)})
    return out


def stealer_archive(path: str, strict: bool = False) -> list[dict]:
    """A zip in a temp folder carrying copied browser/keychain/wallet stores (see stealer_artifacts)."""
    n = os.path.basename(path).lower()
    names: list[str] = []
    try:
        if os.path.getsize(path) < (300 << 20):
            with zipfile.ZipFile(path) as z:
                names = [os.path.basename(i.filename.rstrip("/")).lower() for i in z.infolist()[:20000]]
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError):
        names = []
    found = sorted(set(names) & STEALER_NAMES)
    has_profile = bool(set(names) & PROFILE_MARKERS)
    if not has_profile and (len(found) >= 2 or set(found) & STRONG_STEALER) and (not strict or _strict_ok(set(found))):
        return [{"kind": "archive", "path": path, "artefacts": found[:8], "names": found,
                 "signals": [Signal(f"{ST}.Archive", 60, Confidence.HIGH,
                                    "archiwum w folderze tymczasowym zawiera dane przeglądarki/pęku kluczy/portfeli "
                                    "(pakiet exfiltracji stealera)", found[:8])]}]
    if n in STAGING_ARCHIVE_NAMES and not strict:
        return [{"kind": "archive_name", "path": path, "artefacts": [], "names": [],
                 "signals": [Signal(f"{ST}.ArchiveName", 10, Confidence.LOW,
                                    "nazwa archiwum używana przez stealery macOS do exfiltracji", [path])]}]
    return []


def _stealer_scan_dir(ctx: EnvContext, root: str, depth: int, label: str, group_by_root: bool = False,
                      strict: bool = False) -> None:
    home_lib = (ctx.homes[0].home + "/Library/") if ctx.homes else None
    for hit in stealer_artifacts(root, depth, label, home_lib, group_by_root, strict=strict):
        path = hit["path"]
        if hit["kind"] == "staging":
            ctx.add_target(path, "possible stealer staging folder", 2)
            ctx.add_finding("files", f"Możliwy folder przygotowawczy stealera {path}", path, hit["signals"],
                            {"artefacts": hit["artefacts"]})
        else:
            ctx.add_target(path, "possible stealer archive", 2)
            ctx.add_finding("files", f"Możliwe archiwum stealera {os.path.basename(path)}", path, hit["signals"],
                            {"members": hit["artefacts"]})


def collect_staging(ctx: EnvContext) -> None:
    ctx.progress("foldery stealerów i ukrytych ładunków")
    for root, label in (("/private/tmp", "/tmp"), ("/private/var/tmp", "/var/tmp"), ("/Users/Shared", "/Users/Shared")):
        if os.path.isdir(root):
            _stealer_scan_dir(ctx, root, 3, label)
    from .live import user_temp_dir
    tmpdir = user_temp_dir()
    if tmpdir:                                  # mktemp -d / tempfile / os.MkdirTemp land here on macOS
        _stealer_scan_dir(ctx, tmpdir, 3, "folderze tymczasowym użytkownika ($TMPDIR)", strict=True)
    hidden_inv = ctx.inv("hidden_home_dirs")
    for h in ctx.homes:
        names, _ = safe_listdir(h.home)
        for n in names:
            if not n.startswith(".") or n in KNOWN_DOT_DIRS or n in (".Trash", ".DS_Store", ".CFUserTextEncoding"):
                continue
            p = os.path.join(h.home, n)
            if not os.path.isdir(p) or os.path.islink(p):
                continue
            _stealer_scan_dir(ctx, p, 3, f"~/{n}", group_by_root=True)
            execs = []
            for path, is_dir in _walk(p, 2, 400):
                if is_dir:
                    continue
                head = read_bytes(path, 4) or b""
                if head[:4] in MACHO_MAGICS or head[:2] == b"#!" or path.endswith((".py", ".js", ".sh", ".command")):
                    execs.append(path)
            rand = looks_random(n)
            hidden_inv.append({"dir": p, "random_name": rand, "executables": len(execs)})
            if execs:
                for e in execs[:20]:
                    ctx.add_target(e, f"executable in hidden folder ~/{n}", 1)
            if execs and rand:
                ctx.add_finding("files", f"Programy w ukrytym folderze o losowej nazwie ~/{n}", p,
                                [Signal("Heur:Env.Files.HiddenPayloadDir", 30, Confidence.MEDIUM,
                                        "ukryty folder o losowej nazwie w katalogu domowym zawiera programy",
                                        [os.path.relpath(x, h.home) for x in execs[:5]])],
                                {"executables": [os.path.relpath(x, h.home) for x in execs[:20]]})
        # executables sitting directly in ~ as hidden files (e.g. ~/.helper, ~/.agent)
        for n in names:
            p = os.path.join(h.home, n)
            if n.startswith(".") and os.path.isfile(p) and not os.path.islink(p):
                head = read_bytes(p, 4) or b""
                if head[:4] in MACHO_MAGICS:
                    si = ctx.sign(p)
                    ctx.add_target(p, "hidden executable in home directory", 2)
                    sigs = [Signal("Heur:Env.Files.HiddenExecutable", 40, Confidence.HIGH if not si.trusted else Confidence.MEDIUM,
                                   "ukryty program Mach-O bezpośrednio w katalogu domowym", [p, si.signer])]
                    if n in (".helper", ".agent"):
                        sigs.append(Signal("Heur:Env.Files.IOC.AtomicStealer", 40, Confidence.HIGH,
                                           "nazwa pliku używana przez backdoora Atomic Stealer (AMOS)", [p]))
                    ctx.add_finding("files", f"Ukryty program ~/{n}", p, sigs, {"signature": si.to_dict()})
                elif head[:2] == b"#!" and re.fullmatch(r"\.(helper|agent)", n):
                    ctx.add_target(p, "hidden script in home directory", 2)
                    ctx.add_finding("files", f"Ukryty skrypt ~/{n}", p,
                                    [Signal("Heur:Env.Files.IOC.AtomicStealer", 40, Confidence.HIGH,
                                            "nazwa pliku używana przez backdoora Atomic Stealer (AMOS)", [p])], {})

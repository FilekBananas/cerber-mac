import AppKit
import CryptoKit
import Foundation
import MachO

// MARK: - Events

enum BackendEvent: Sendable {
    case info(DBInfo)
    case stage(id: String, title: String)
    case log(String)
    case progress(ProgressEvent)
    case finding(ScanResult)
    case done(Summary)
    case error(message: String, fatal: Bool)
    case quarantined(path: String, id: String)
    case history([HistoryItem])
    case aiInstalled(model: String, path: String?, llamaServer: String?)
    case apiReady(url: String, token: String?, docs: String?)
    case sandboxViolation([String])
    case watch(WatchEvent)
    case netStatus(NetMonitorStatus)
    case netEvent(NetEvent)
    /// `iphone` command events (`iphone_devices`, `iphone_finding`, `iphone_done`) – decoded by IPhoneModel.
    case iphone(name: String, data: JSONValue)
    case unknown(String)

    var name: String {
        switch self {
        case .info: return "info"
        case .stage: return "stage"
        case .log: return "log"
        case .progress: return "progress"
        case .finding: return "finding"
        case .done: return "done"
        case .error: return "error"
        case .quarantined: return "quarantined"
        case .history: return "history"
        case .aiInstalled: return "ai_installed"
        case .apiReady: return "api_ready"
        case .sandboxViolation: return "sandbox_violation"
        case .watch(let w): return w.ev
        case .netStatus: return "net_status"
        case .netEvent: return "net_event"
        case .iphone(let n, _): return n
        case .unknown(let ev): return "unknown(\(ev))"
        }
    }
}

enum DecodedLine: Sendable {
    case event(BackendEvent)
    case invalid(String)
    case blank
}

/// The one decoder used by the app, the snapshot generator and `--selftest-parse`.
enum EventDecoder {
    static func decode(line raw: String) -> DecodedLine {
        let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if line.isEmpty { return .blank }
        guard let j = JSONValue.parse(line), j.object != nil, let ev = j["ev"].text else {
            return .invalid(line)
        }
        return .event(decode(ev: ev, j))
    }

    static func decode(ev: String, _ j: JSONValue) -> BackendEvent {
        switch ev {
        case "info":
            return .info(DBInfo(j))
        case "stage":
            let id = j["id"].text ?? "?"
            return .stage(id: id, title: j["title"].text ?? Stage.defaultTitle(id))
        case "log":
            return .log(j["msg"].string ?? "")
        case "progress":
            return .progress(ProgressEvent(j))
        case "finding":
            return .finding(ScanResult(j["item"]))
        case "done":
            return .done(Summary(j["summary"]))
        case "error":
            return .error(message: j["msg"].text ?? "Nieznany błąd skanera.", fatal: j["fatal"].bool ?? false)
        case "quarantined":
            return .quarantined(path: j["path"].text ?? "", id: j["id"].text ?? "")
        case "history":
            return .history(j["items"].array.enumerated().map { HistoryItem($0.element, index: $0.offset) })
        case "ai_installed":
            var server = j["llama_server"].text
            if case .bool(let b) = j["llama_server"] { server = b ? "llama-server" : nil }
            return .aiInstalled(model: j["model"].text ?? "", path: j["path"].text, llamaServer: server)
        case "watch_ready", "watch_new", "watch_scanning", "watch_worker", "watch_sandbox", "watch_result",
             "watch_notice", "watch_alert", "watch_net", "watch_net_status", "watch_defense":
            return .watch(WatchEvent(ev: ev, j))
        case "sandbox_violation":
            let problems = j["problems"].stringArray
            return .sandboxViolation(problems.isEmpty ? ["Sandbox nie przeszedł samosprawdzenia."] : problems)
        case "api_ready":
            return .apiReady(url: j["url"].text ?? "", token: j["token"].text, docs: j["docs"].text)
        case "net_status":
            return .netStatus(NetMonitorStatus(j))
        case "net_event":
            return .netEvent(NetEvent(j["item"]))
        case "iphone_devices", "iphone_finding", "iphone_done":
            return .iphone(name: ev, data: j)
        default:
            return .unknown(ev)
        }
    }
}

// MARK: - Configuration

struct BackendConfig: Sendable {
    let root: URL
    let mock: Bool

    static func detect(forceMock: Bool = false) -> BackendConfig {
        let env = ProcessInfo.processInfo.environment
        let mock = forceMock || env["CERBER_MOCK"] == "1" || CommandLine.arguments.contains("--mock")
        BackendIntegrity.shared.prefetch()
        return BackendConfig(root: detectRoot(), mock: mock)
    }

    static func detectRoot() -> URL {
        let fm = FileManager.default
        let env = ProcessInfo.processInfo.environment
        var candidates: [String] = []
        // A sealed build runs only the backend it was sealed for: CERBER_ROOT (which any program can pass with
        // `open --env`) is honoured only by unsealed developer builds.
        if let r = BackendIntegrity.shared.sealedRoot { candidates.append(r) }
        if let r = env["CERBER_ROOT"], !BackendIntegrity.shared.isSealed { candidates.append(r) }
        if let r = Bundle.main.object(forInfoDictionaryKey: "CerberRoot") as? String { candidates.append(r) }
        candidates.append(Bundle.main.bundleURL.deletingLastPathComponent().path)
        let exe = URL(fileURLWithPath: CommandLine.arguments.first ?? "").resolvingSymlinksInPath()
        candidates.append(exe.deletingLastPathComponent().deletingLastPathComponent().path)
        candidates.append(fm.currentDirectoryPath)
        for c in candidates {
            let url = URL(fileURLWithPath: (c as NSString).expandingTildeInPath)
            if fm.fileExists(atPath: url.appendingPathComponent("cerber").path)
                || fm.fileExists(atPath: url.appendingPathComponent("app/mock_backend.py").path) {
                // the sealed root verbatim (standardizing would turn /private/tmp into /tmp)
                return c == BackendIntegrity.shared.sealedRoot ? url : url.standardizedFileURL
            }
        }
        return URL(fileURLWithPath: candidates.first ?? fm.currentDirectoryPath)
    }

    var venvPython: URL { root.appendingPathComponent(".venv/bin/python") }
    var mockScript: URL { root.appendingPathComponent("app/mock_backend.py") }

    /// Executable + arguments for one backend command. When the integrity seal is broken this is a harmless
    /// `/usr/bin/false` (callers that spawn processes themselves – self-test, snapshots – get it too).
    func launchSpec(_ args: [String]) -> (URL, [String]) {
        if let problem = BackendIntegrity.shared.gate(root: root) {
            _ = problem
            return (URL(fileURLWithPath: "/usr/bin/false"), [])
        }
        return uncheckedLaunchSpec(args)
    }

    fileprivate func uncheckedLaunchSpec(_ args: [String]) -> (URL, [String]) {
        let fm = FileManager.default
        if mock {
            let py = fm.isExecutableFile(atPath: venvPython.path) ? venvPython : URL(fileURLWithPath: "/usr/bin/python3")
            return (py, [mockScript.path] + args)
        }
        return (venvPython, ["-m", "cerber.gui_backend"] + args)
    }

    /// The child's environment is built from scratch, never copied: everything the app inherits can be set by
    /// another program (`launchctl setenv`, `open --env`) – DYLD_INSERT_LIBRARIES, PYTHONPATH, PYTHONSTARTUP,
    /// CERBER_LLAMA_SERVER, CERBER_API_BACKEND … would each hand Cerber's Full Disk Access to that program.
    var environment: [String: String] {
        let src = ProcessInfo.processInfo.environment
        var env: [String: String] = [:]
        if let pw = getpwuid(getuid()) {
            env["HOME"] = String(cString: pw.pointee.pw_dir)
            env["USER"] = String(cString: pw.pointee.pw_name)
            env["LOGNAME"] = env["USER"]
        }
        var tmp = [CChar](repeating: 0, count: Int(PATH_MAX))
        if confstr(_CS_DARWIN_USER_TEMP_DIR, &tmp, tmp.count) > 0 { env["TMPDIR"] = String(cString: tmp) }
        for key in ["LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "__CF_USER_TEXT_ENCODING"] {
            if let v = src[key], v.count < 64, !v.contains("/") { env[key] = v }
        }
        // inert test knobs (read only by app/mock_backend.py and the self-test's fake API server)
        for (k, v) in src where k.hasPrefix("CERBER_MOCK_") || k.hasPrefix("FAKE_API_") { env[k] = v }
        env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"
        env["SHELL"] = "/bin/zsh"
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONNOUSERSITE"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["LANG"] = env["LANG"] ?? "pl_PL.UTF-8"
        if let seal = BackendIntegrity.shared.importPaths {
            // the project root is never on sys.path (a stray json.py next to cerber/ could shadow a module);
            // .pyc come only from the sealed tree inside Cerber.app, never from writable __pycache__ folders
            env["PYTHONSAFEPATH"] = "1"
            env["PYTHONPATH"] = seal.pypath
            env["CERBER_PYPATH"] = seal.pypath
            if let c = seal.pycache { env["PYTHONPYCACHEPREFIX"] = c }
        }
        return env
    }
}

// MARK: - Code integrity seal (cerber/integrity.py, app/build.sh)

/// Cerber.app has Full Disk Access and so does every process it starts. Before the first backend process the
/// app recomputes the manifest written by app/build.sh (cerber/, .venv, the interpreter, Homebrew libraries and
/// tools, pickle/YARA databases) and compares it with the SHA-256 linked into this executable (__TEXT,
/// __cerber_seal, covered by the code signature). Any difference blocks the backend until the user rebuilds the
/// app or deliberately approves the current state (root-owned file, administrator password).
/// The text rules must stay identical to `entries()` in cerber/integrity.py.
final class BackendIntegrity: @unchecked Sendable {
    static let shared = BackendIntegrity()

    struct ImportPaths: Sendable {
        let pypath: String
        let pycache: String?
    }

    struct Failure: Sendable, Equatable {
        let problems: [String]
        let resealable: Bool
        /// Manifest of the files as they are now (only when `resealable`).
        let liveText: String?
        let summary: String
    }

    static let resealDir = "/Library/Application Support/Cerber"
    static let resealFile = resealDir + "/backend.seal"

    private let lock = NSLock()
    private let done = DispatchSemaphore(value: 0)
    private var started = false
    private var finished = false
    private var failure: Failure?
    private var verifiedSpec: Spec?
    private var snapshot: [Snapshot] = []
    private var lastFastCheck = Date.distantPast
    private var lastFullVerify = Date.distantPast
    private var alertShownFor: [String] = []
    private var unsealedWarned = false

    /// SHA-256 of the build manifest, linked into the executable; nil for unsealed (developer) builds.
    let embedded: String?
    /// The bundle's manifest when it matches `embedded` (header parsed up front for the root / import paths).
    private let bundleText: String?
    private let bundleSpec: Spec?

    private init() {
        embedded = Self.readEmbeddedSeal()
        if let embedded, let url = Bundle.main.url(forResource: "backend", withExtension: "manifest"),
           let data = try? Data(contentsOf: url), Self.hex(SHA256.hash(data: data)) == embedded,
           let text = String(data: data, encoding: .ascii), let parsed = Spec.parse(text) {
            bundleText = text
            bundleSpec = parsed.0
        } else {
            bundleText = nil
            bundleSpec = nil
        }
    }

    var isSealed: Bool { embedded != nil }

    var sealedRoot: String? { bundleSpec.map { String(decoding: $0.root, as: UTF8.self) } }

    var importPaths: ImportPaths? {
        guard let s = bundleSpec, let p = s.pypath else { return nil }
        return ImportPaths(pypath: String(decoding: p, as: UTF8.self), pycache: s.pycache.map { String(decoding: $0, as: UTF8.self) })
    }

    /// Starts the first full verification in the background (app launch).
    func prefetch() {
        lock.lock()
        let go = isSealed && !started
        if go { started = true }
        lock.unlock()
        guard go else { return }
        DispatchQueue.global(qos: .userInitiated).async { self.fullVerify() }
    }

    /// nil = the backend may run; otherwise a Polish explanation (and the warning window is shown once).
    func gate(root: URL) -> String? {
        guard isSealed else {
            lock.lock()
            let warn = !unsealedWarned
            unsealedWarned = true
            lock.unlock()
            if warn { FileHandle.standardError.write(Data("Cerber: kompilacja bez pieczęci integralności (app/build.sh ją tworzy) – backend nie jest sprawdzany.\n".utf8)) }
            return nil
        }
        if let expected = sealedRoot {
            let (real, err) = FSBytes.realpathErrno(Array(root.path.utf8))
            if real == nil {
                // the folder could not be resolved at all: almost always macOS privacy protection (the engine lives
                // in ~/Documents and every rebuild of an ad-hoc signed app loses its Full Disk Access)
                if err == EPERM || err == EACCES {
                    return "macOS nie pozwala Cerberowi czytać folderu z silnikiem (\(expected)). Nadaj mu Pełny dostęp do dysku: Ustawienia systemowe → Prywatność i ochrona → Pełny dostęp do dysku (usuń Cerbera „–” i dodaj ponownie „+”), potem uruchom Cerbera jeszcze raz."
                }
                return "Nie można otworzyć folderu z silnikiem Cerbera (\(expected)): \(String(cString: strerror(err))). Sprawdź, czy folder nadal istnieje."
            }
            if real != Array(expected.utf8) {
                return "Ta kopia Cerber.app została zbudowana dla katalogu \(expected), a silnik jest teraz w \(String(decoding: real!, as: UTF8.self)). Przebuduj aplikację (app/build.sh)."
            }
        }
        prefetch()
        done.wait()
        done.signal()
        lock.lock()
        var current = failure
        let fresh = Date().timeIntervalSince(lastFastCheck) < 1.0
        let retry = current != nil && Date().timeIntervalSince(lastFullVerify) > 10
        lock.unlock()
        if retry {                                   // the files may have been restored (or the app rebuilt)
            fullVerify()
            lock.lock()
            current = failure
            lock.unlock()
        } else if current == nil && !fresh {
            if snapshotIntact() {
                lock.lock()
                lastFastCheck = Date()
                lock.unlock()
            } else {
                fullVerify()
                lock.lock()
                current = failure
                lock.unlock()
            }
        }
        guard let f = current else { return nil }
        presentAlert(f)
        return f.summary
    }

    // MARK: verification

    private func fullVerify() {
        let result = verifyNow()
        lock.lock()
        lastFullVerify = Date()
        switch result {
        case .success(let (spec, snap)):
            failure = nil
            verifiedSpec = spec
            snapshot = snap
            lastFastCheck = Date()
        case .failure(let f):
            failure = f
            verifiedSpec = nil
            snapshot = []
        }
        let first = !finished
        finished = true
        lock.unlock()
        if first { done.signal() }
    }

    private enum VerifyResult {
        case success((Spec, [Snapshot]))
        case failure(Failure)
    }

    private func verifyNow() -> VerifyResult {
        guard let embedded else { return .failure(Failure(problems: [], resealable: false, liveText: nil, summary: "")) }
        guard let bundleText, let bundleSpec else {
            return .failure(Self.fail(["brak albo uszkodzony manifest w Cerber.app (Contents/Resources/backend.manifest)"],
                                      resealable: false, live: nil))
        }
        var candidates: [(Spec, Set<String>)] = []
        if let reseal = resealedText(embedded: embedded), let parsed = Spec.parse(reseal) {
            candidates.append((parsed.0, Set(parsed.1)))
        }
        if let parsed = Spec.parse(bundleText) { candidates.append((bundleSpec, Set(parsed.1))) }
        var best: (problems: [String], live: LiveScan, spec: Spec)?
        var scans: [String: LiveScan] = [:]          // a re-seal keeps the build's header: scan the disk once
        for (spec, recorded) in candidates {
            let live = scans[spec.headerText] ?? LiveScan.run(spec)
            scans[spec.headerText] = live
            if live.entries == recorded {
                return .success((spec, live.snapshot))
            }
            let problems = Self.describe(recorded: recorded, live: live.entries)
            if best == nil || problems.count < best!.problems.count { best = (problems, live, spec) }
        }
        guard let best else {
            return .failure(Self.fail(["manifest nieczytelny"], resealable: false, live: nil))
        }
        let resealable = !best.live.entries.contains { $0.hasPrefix("?") }
        let text = resealable ? best.spec.headerText + "--\n" + best.live.sortedEntries.joined(separator: "\n") + "\n" : nil
        return .failure(Self.fail(best.problems, resealable: resealable, live: text))
    }

    private static func fail(_ problems: [String], resealable: Bool, live: String?) -> Failure {
        let head = problems.prefix(3).joined(separator: "; ")
        let more = problems.count > 3 ? " (i \(problems.count - 3) więcej)" : ""
        return Failure(problems: problems, resealable: resealable, liveText: live,
                       summary: "Cerber zablokował uruchomienie silnika: pliki backendu różnią się od zatwierdzonej wersji – \(head)\(more). Szczegóły i dalsze kroki są w oknie ostrzeżenia.")
    }

    private func snapshotIntact() -> Bool {
        lock.lock()
        let snap = snapshot
        lock.unlock()
        return Snapshot.allIntact(snap)
    }

    /// The approved re-seal: digest in a root-owned file bound to this build, manifest in Application Support.
    private func resealedText(embedded: String) -> String? {
        guard let seal = Self.rootOwnedFile(Self.resealFile),
              let line = String(data: seal, encoding: .ascii)?.split(separator: "\n").first else { return nil }
        let parts = line.split(separator: " ").map(String.init)
        guard parts.count == 4, parts[0] == "cerber-reseal", parts[1] == "1", parts[2] == embedded,
              Self.isHex64(parts[3]),
              let data = try? Data(contentsOf: Self.userManifestURL), Self.hex(SHA256.hash(data: data)) == parts[3] else { return nil }
        return String(data: data, encoding: .ascii)
    }

    static var userManifestURL: URL {
        let home = getpwuid(getuid()).map { String(cString: $0.pointee.pw_dir) } ?? NSHomeDirectory()
        return URL(fileURLWithPath: home).appendingPathComponent("Library/Application Support/Cerber/backend.manifest")
    }

    /// Contents of `path` only if it and its folder belong to root and nobody else may write them.
    static func rootOwnedFile(_ path: String) -> Data? {
        var st = stat()
        var dst = stat()
        guard lstat(path, &st) == 0, lstat((path as NSString).deletingLastPathComponent, &dst) == 0,
              (st.st_mode & S_IFMT) == S_IFREG, (dst.st_mode & S_IFMT) == S_IFDIR,
              st.st_uid == 0, dst.st_uid == 0, st.st_mode & 0o022 == 0, dst.st_mode & 0o022 == 0,
              st.st_size < 4096 else { return nil }
        return FileManager.default.contents(atPath: path)
    }

    static func describe(recorded: Set<String>, live: Set<String>) -> [String] {
        func byPath(_ lines: Set<String>) -> [String: String] {
            var out: [String: String] = [:]
            for l in lines {
                let parts = l.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
                if parts.count >= 2 { out[String(parts[1])] = l }
            }
            return out
        }
        let a = byPath(recorded), b = byPath(live)
        var msgs: [String] = []
        for p in Set(a.keys).union(b.keys).sorted() where a[p] != b[p] {
            let path = String(decoding: SealText.unesc(p), as: UTF8.self)
            if b[p] == nil { msgs.append("brak: \(path)") }
            else if a[p] == nil { msgs.append("nowy plik: \(path)") }
            else if b[p]!.hasPrefix("?") { msgs.append("niepoprawny: \(path)") }
            else { msgs.append("zmieniony: \(path)") }
        }
        return msgs
    }

    // MARK: warning window + deliberate re-seal

    private func presentAlert(_ f: Failure) {
        lock.lock()
        let shown = alertShownFor == f.problems
        alertShownFor = f.problems
        lock.unlock()
        guard !shown else { return }
        DispatchQueue.main.async { MainActor.assumeIsolated {
            guard let app = NSApp, app.isRunning else { return }
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "Cerber zablokował uruchomienie swojego silnika"
            let data = f.problems.filter { $0.contains("/db/compiled/") }.count
            let list = f.problems.prefix(12).map { "• " + Fmt.tilde($0) }.joined(separator: "\n")
                + (f.problems.count > 12 ? "\n• … i \(f.problems.count - 12) więcej" : "")
            var text = "Pliki, z których korzysta silnik Cerbera (kod w Pythonie, interpreter, biblioteki, narzędzia albo bazy sygnatur), różnią się od wersji zatwierdzonej przy budowaniu aplikacji. Cerber ma pełny dostęp do dysku – podmieniony plik dałby ten dostęp także temu, kto go podmienił. Dlatego silnik nie zostanie uruchomiony.\n\nZmiany (\(f.problems.count)\(data > 0 ? ", w tym bazy sygnatur: \(data)" : "")):\n\(list)\n\n"
            if f.resealable {
                text += "Jeśli to Ty zaktualizowałeś Cerbera (./cerber.sh update, edycja kodu, pip install), możesz zatwierdzić obecny stan – macOS poprosi o hasło administratora. Jeśli niczego nie zmieniałeś, NIE zatwierdzaj: przeskanuj komputer i przebuduj aplikację (app/build.sh)."
                alert.addButton(withTitle: "Nie zatwierdzaj")
                alert.addButton(withTitle: "Zatwierdź obecny stan…")
            } else {
                text += "Tej zmiany nie da się zatwierdzić w aplikacji (brakuje plików albo zmieniła się wersja Pythona lub bibliotek Homebrew). Przebuduj aplikację poleceniem app/build.sh."
                alert.addButton(withTitle: "OK")
            }
            alert.informativeText = text
            if alert.runModal() == .alertSecondButtonReturn, f.resealable, let live = f.liveText {
                self.reseal(live)
            }
        } }
    }

    /// Writes the current manifest to Application Support and its digest (bound to this build) to a root-owned
    /// file – the administrator password is the user's deliberate confirmation; malware running as the user
    /// cannot forge it.
    @MainActor
    private func reseal(_ text: String) {
        guard let embedded else { return }
        let digest = Self.hex(SHA256.hash(data: Data(text.utf8)))
        do {
            let url = Self.userManifestURL
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(text.utf8).write(to: url, options: .atomic)
        } catch {
            Self.info("Nie udało się zapisać manifestu: \(error.localizedDescription)", critical: true)
            return
        }
        let line = "cerber-reseal 1 \(embedded) \(digest)"
        guard Self.isHex64(embedded), Self.isHex64(digest) else { return }
        let dir = Self.resealDir, file = Self.resealFile
        let shell = "/bin/mkdir -p '\(dir)' && /bin/chmod 755 '\(dir)' && /usr/sbin/chown root:wheel '\(dir)' && " +
            "/bin/echo \" & quoted form of (item 1 of argv) & \" > '\(file).tmp' && /bin/chmod 644 '\(file).tmp' && " +
            "/usr/sbin/chown root:wheel '\(file).tmp' && /bin/mv -f '\(file).tmp' '\(file)'"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", "on run argv",
                       "-e", "do shell script \"\(shell)\" with prompt \"Cerber: zatwierdzenie zmienionych plików silnika\" with administrator privileges",
                       "-e", "end run", line]
        p.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch {
            Self.info("Nie udało się uruchomić okna autoryzacji: \(error.localizedDescription)", critical: true)
            return
        }
        p.waitUntilExit()
        lock.lock()
        alertShownFor = []
        lock.unlock()
        DispatchQueue.global(qos: .userInitiated).async {
            self.fullVerify()
            self.lock.lock()
            let ok = self.failure == nil
            self.lock.unlock()
            let status = p.terminationStatus
            DispatchQueue.main.async { MainActor.assumeIsolated {
                if ok {
                    Self.info("Zatwierdzono obecny stan plików silnika. Możesz ponowić operację.", critical: false)
                } else if status != 0 {
                    Self.info("Nie zatwierdzono (anulowano albo brak uprawnień administratora).", critical: true)
                } else {
                    Self.info("Pliki zmieniły się ponownie w trakcie zatwierdzania – nic nie zostało odblokowane.", critical: true)
                }
            } }
        }
    }

    @MainActor
    private static func info(_ text: String, critical: Bool) {
        let a = NSAlert()
        a.alertStyle = critical ? .critical : .informational
        a.messageText = "Cerber"
        a.informativeText = text
        a.addButton(withTitle: "OK")
        a.runModal()
    }

    // MARK: helpers

    static func readEmbeddedSeal() -> String? {
        var size: UInt = 0
        let header = #dsohandle.assumingMemoryBound(to: mach_header_64.self)
        guard let p = getsectiondata(header, "__TEXT", "__cerber_seal", &size), size > 0, size < 4096 else { return nil }
        let text = String(decoding: UnsafeBufferPointer(start: p, count: Int(size)), as: UTF8.self)
        let lines = text.split(separator: "\n").map(String.init)
        guard lines.count >= 2, lines[0] == "cerber-seal 1", isHex64(lines[1]) else { return nil }
        return lines[1]
    }

    static func isHex64(_ s: String) -> Bool {
        s.utf8.count == 64 && s.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        let chars = Array("0123456789abcdef".utf8)
        var out = [UInt8]()
        for b in digest { out.append(chars[Int(b >> 4)]); out.append(chars[Int(b & 0xF)]) }
        return String(decoding: out, as: UTF8.self)
    }
}

/// Percent-escaping of manifest paths (cerber/integrity.py `esc`).
enum SealText {
    static func esc(_ raw: [UInt8]) -> String {
        let hexd = Array("0123456789ABCDEF".utf8)
        var out = [UInt8]()
        out.reserveCapacity(raw.count)
        for b in raw {
            if b >= 0x21 && b <= 0x7E && b != 0x25 { out.append(b) } else {
                out.append(0x25); out.append(hexd[Int(b >> 4)]); out.append(hexd[Int(b & 0xF)])
            }
        }
        return String(decoding: out, as: UTF8.self)
    }

    static func unesc(_ s: String) -> [UInt8] {
        let u = Array(s.utf8)
        var out = [UInt8]()
        var i = 0
        func val(_ c: UInt8) -> UInt8? {
            switch c {
            case 0x30...0x39: return c - 0x30
            case 0x41...0x46: return c - 0x41 + 10
            case 0x61...0x66: return c - 0x61 + 10
            default: return nil
            }
        }
        while i < u.count {
            if u[i] == 0x25, i + 2 < u.count, let h = val(u[i + 1]), let l = val(u[i + 2]) {
                out.append(h << 4 | l)
                i += 3
            } else {
                out.append(u[i])
                i += 1
            }
        }
        return out
    }
}

/// Header of a manifest: what to walk, hash and check.
struct Spec: Sendable {
    var root: [UInt8] = []
    var pycache: [UInt8]?
    var pypath: [UInt8]?
    var excludes: Set<[UInt8]> = []
    var skip: Set<[UInt8]> = []
    var trees: [[UInt8]] = []
    var files: [[UInt8]] = []
    var links: [[UInt8]] = []
    var absent: [[UInt8]] = []
    var headerText = ""

    static func parse(_ text: String) -> (Spec, [String])? {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard lines.first == "cerber-manifest 1" else { return nil }
        var s = Spec()
        var i = 1
        while i < lines.count, lines[i] != "--" {
            let line = lines[i]
            guard line.count > 2, line.dropFirst().first == " " else { return nil }
            let v = SealText.unesc(String(line.dropFirst(2)))
            switch line.first {
            case "R": s.root = v
            case "C": s.pycache = v
            case "Y": s.pypath = v
            case "X": s.excludes.insert(v)
            case "P": s.skip.insert(v)
            case "T": s.trees.append(v)
            case "F": s.files.append(v)
            case "L": s.links.append(v)
            case "N": s.absent.append(v)
            default: return nil
            }
            i += 1
        }
        guard i < lines.count else { return nil }
        s.headerText = lines[0..<i].joined(separator: "\n") + "\n"
        let entries = lines[(i + 1)...].filter { !$0.isEmpty }
        return (s, entries)
    }
}

/// lstat fingerprint used for the fast re-check between full verifications. The ctime cannot be set back by an
/// unprivileged process, so any write, rename, chmod or new directory entry changes it.
struct Snapshot: Equatable, Sendable {
    let path: [UInt8]
    let exists: Bool
    let dev: Int32
    let ino: UInt64
    let mode: UInt16
    let size: Int64
    let mtime: Int
    let mtimeNs: Int
    let ctime: Int
    let ctimeNs: Int

    init(path: [UInt8], st: stat?) {
        self.path = path
        exists = st != nil
        dev = st?.st_dev ?? 0
        ino = st?.st_ino ?? 0
        mode = st?.st_mode ?? 0
        size = st?.st_size ?? 0
        mtime = st?.st_mtimespec.tv_sec ?? 0
        mtimeNs = st?.st_mtimespec.tv_nsec ?? 0
        ctime = st?.st_ctimespec.tv_sec ?? 0
        ctimeNs = st?.st_ctimespec.tv_nsec ?? 0
    }

    static func take(_ path: [UInt8]) -> Snapshot { Snapshot(path: path, st: FSBytes.lstat(path)) }

    /// Parallel lstat sweep (a few thousand paths); false on the first difference.
    static func allIntact(_ snap: [Snapshot]) -> Bool {
        guard !snap.isEmpty else { return false }
        let lanes = 8
        var bad = [Bool](repeating: false, count: lanes)
        bad.withUnsafeMutableBufferPointer { out in
            let base = out.baseAddress!
            DispatchQueue.concurrentPerform(iterations: lanes) { lane in
                var i = lane
                while i < snap.count {
                    if Snapshot.take(snap[i].path) != snap[i] { base[lane] = true; return }
                    i += lanes
                }
            }
        }
        return !bad.contains(true)
    }
}

/// POSIX calls on raw byte paths (file names are bytes; no Unicode normalisation on the way).
enum FSBytes {
    static func withC<T>(_ p: [UInt8], _ body: (UnsafePointer<CChar>) -> T) -> T {
        (p + [0]).withUnsafeBufferPointer { buf in
            buf.baseAddress!.withMemoryRebound(to: CChar.self, capacity: buf.count) { body($0) }
        }
    }

    static func lstat(_ p: [UInt8]) -> stat? {
        var st = stat()
        return withC(p) { Darwin.lstat($0, &st) } == 0 ? st : nil
    }

    /// 0 when the path exists (without following a final symlink), otherwise errno.
    static func lstatError(_ p: [UInt8]) -> Int32 {
        var st = stat()
        return withC(p) { Darwin.lstat($0, &st) == 0 ? 0 : errno }
    }

    static func realpath(_ p: [UInt8]) -> [UInt8]? {
        withC(p) { c -> [UInt8]? in
            guard let r = Darwin.realpath(c, nil) else { return nil }
            defer { free(r) }
            return Array(UnsafeBufferPointer(start: UnsafeRawPointer(r).assumingMemoryBound(to: UInt8.self), count: strlen(r)))
        }
    }

    /// realpath plus the errno when it fails (EPERM/EACCES = privacy protection, ENOENT = gone).
    static func realpathErrno(_ p: [UInt8]) -> ([UInt8]?, Int32) {
        withC(p) { c -> ([UInt8]?, Int32) in
            errno = 0
            guard let r = Darwin.realpath(c, nil) else { return (nil, errno) }    // errno read right at the failure
            defer { free(r) }
            return (Array(UnsafeBufferPointer(start: UnsafeRawPointer(r).assumingMemoryBound(to: UInt8.self), count: strlen(r))), 0)
        }
    }

    static func readlink(_ p: [UInt8]) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: Int(PATH_MAX) + 1)
        let n = withC(p) { c in buf.withUnsafeMutableBufferPointer { Darwin.readlink(c, UnsafeMutableRawPointer($0.baseAddress!).assumingMemoryBound(to: CChar.self), $0.count - 1) } }
        return n >= 0 ? Array(buf[0..<n]) : nil
    }

    static func listdir(_ p: [UInt8]) -> [[UInt8]]? {
        guard let d = withC(p, { opendir($0) }) else { return nil }
        defer { closedir(d) }
        var out: [[UInt8]] = []
        while let ent = readdir(d) {
            let len = Int(ent.pointee.d_namlen)
            let name = withUnsafeBytes(of: ent.pointee.d_name) { Array($0.prefix(len)) }
            if name == [0x2E] || name == [0x2E, 0x2E] { continue }
            out.append(name)
        }
        return out
    }

    /// SHA-256 (hex) of a regular file opened without following a symlink, with its fstat.
    static func sha256(_ p: [UInt8]) -> (String, stat)? {
        let fd = withC(p) { open($0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) }
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return nil }
        var h = SHA256()
        let cap = 1 << 20
        let buf = UnsafeMutableRawPointer.allocate(byteCount: cap, alignment: 16)
        defer { buf.deallocate() }
        while true {
            let n = read(fd, buf, cap)
            if n < 0 { return nil }
            if n == 0 { break }
            h.update(bufferPointer: UnsafeRawBufferPointer(start: buf, count: n))
        }
        return (BackendIntegrity.hex(h.finalize()), st)
    }
}

/// The manifest records of the files as they are now (cerber/integrity.py `entries`) plus their fingerprints.
struct LiveScan {
    var entries: Set<String> = []
    var snapshot: [Snapshot] = []

    var sortedEntries: [String] { entries.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) } }

    static func run(_ spec: Spec) -> LiveScan {
        var scan = LiveScan()
        var toHash: [[UInt8]] = []
        func canonical(_ p: [UInt8]) -> Bool { FSBytes.realpath(p) == p }
        func parent(_ p: [UInt8]) -> [UInt8] {
            guard let i = p.lastIndex(of: 0x2F) else { return p }
            return i == 0 ? [0x2F] : Array(p[..<i])
        }
        func isType(_ st: stat, _ t: mode_t) -> Bool { (st.st_mode & S_IFMT) == t }
        func bad(_ p: [UInt8], _ why: String) { scan.entries.insert("? \(SealText.esc(p)) \(why)") }

        for root in spec.trees {
            guard canonical(root) else { bad(root, "not-canonical"); continue }
            guard let st = FSBytes.lstat(root), isType(st, S_IFDIR) else { bad(root, "missing"); continue }
            var stack = [root]
            while let d = stack.popLast() {
                scan.snapshot.append(Snapshot.take(d))
                guard let names = FSBytes.listdir(d) else { bad(d, "unreadable"); continue }
                for name in names where !spec.excludes.contains(name) {
                    let p = d + [0x2F] + name
                    if spec.skip.contains(p) { continue }
                    guard let st = FSBytes.lstat(p) else { bad(p, "vanished"); continue }
                    if isType(st, S_IFDIR) {
                        stack.append(p)
                    } else if isType(st, S_IFLNK) {
                        scan.entries.insert("l \(SealText.esc(p)) \(SealText.esc(FSBytes.readlink(p) ?? []))")
                        scan.snapshot.append(Snapshot(path: p, st: st))
                    } else if isType(st, S_IFREG) {
                        toHash.append(p)
                    } else {
                        scan.entries.insert("o \(SealText.esc(p))")
                        scan.snapshot.append(Snapshot(path: p, st: st))
                    }
                }
            }
        }
        for p in spec.files {
            guard let st = FSBytes.lstat(p) else { bad(p, "missing"); continue }
            if !isType(st, S_IFREG) || !canonical(p) { bad(p, "not-a-plain-file") } else { toHash.append(p) }
        }
        for p in spec.links {
            guard let st = FSBytes.lstat(p) else { bad(p, "missing"); continue }
            if !isType(st, S_IFLNK) || !canonical(parent(p)) { bad(p, "not-a-plain-symlink"); continue }
            scan.entries.insert("l \(SealText.esc(p)) \(SealText.esc(FSBytes.readlink(p) ?? []))")
            scan.snapshot.append(Snapshot(path: p, st: st))
            scan.snapshot.append(Snapshot.take(parent(p)))
        }
        for p in spec.absent {
            let err = FSBytes.lstatError(p)
            if err == ENOENT || err == ENOTDIR {
                scan.entries.insert("n \(SealText.esc(p))")
                scan.snapshot.append(Snapshot(path: p, st: nil))
                scan.snapshot.append(Snapshot.take(parent(p)))
            } else {
                bad(p, "exists")
            }
        }
        // hash in parallel (several hundred MB: interpreter, libraries, databases)
        let unique = Array(Set(toHash))
        var results: [(String, stat)?] = Array(repeating: nil, count: unique.count)
        results.withUnsafeMutableBufferPointer { out in
            let base = out.baseAddress!
            DispatchQueue.concurrentPerform(iterations: unique.count) { i in
                base[i] = FSBytes.sha256(unique[i])
            }
        }
        for (i, p) in unique.enumerated() {
            guard let (digest, st) = results[i] else { bad(p, "unreadable"); continue }
            scan.entries.insert("f \(SealText.esc(p)) \(st.st_mode & 0o111 != 0 ? "x" : "-") \(digest)")
            scan.snapshot.append(Snapshot(path: p, st: st))
        }
        return scan
    }
}

struct BackendLaunchError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

// MARK: - Process

/// Runs one backend command and streams its JSON-Lines events to the main queue.
/// All callbacks are delivered on the main queue, in order; `onExit` always comes last.
final class BackendProcess: @unchecked Sendable {
    var onEvents: (([BackendEvent]) -> Void)?
    var onInvalid: ((String) -> Void)?
    var onStderr: (([String]) -> Void)?
    var onExit: ((Int32) -> Void)?

    private let config: BackendConfig
    private let arguments: [String]
    /// Explicit executable + arguments (e.g. the API server) instead of `config.launchSpec`.
    private let explicitCommand: (URL, [String])?
    private let process = Process()
    private let outPipe = Pipe()
    /// When set, the child gets a pipe as stdin that stays open while this object lives
    /// (the background watcher exits by itself when its stdin closes, e.g. if the app dies).
    var keepStdinOpen = false
    private var stdinPipe: Pipe?
    private let errPipe = Pipe()
    private let queue = DispatchQueue(label: "pl.cerber.backend.io")
    private var outBuffer = Data()
    private var errBuffer = Data()
    private var stdoutClosed = false
    private var stderrClosed = false
    private var exited = false
    private var forceFinalize = false
    private var finalized = false

    init(config: BackendConfig, arguments: [String]) {
        self.config = config
        self.arguments = arguments
        self.explicitCommand = nil
    }

    init(config: BackendConfig, executable: URL, arguments: [String]) {
        self.config = config
        self.arguments = arguments
        self.explicitCommand = (executable, arguments)
    }

    /// Extra variables for the child only (e.g. secrets that must not appear in `ps` output).
    var extraEnvironment: [String: String] = [:]

    private var spec: (URL, [String]) { explicitCommand ?? config.launchSpec(arguments) }

    var commandLine: String {
        let (exe, args) = spec
        return ([exe.path] + args).map { $0.contains(" ") ? "\"\($0)\"" : $0 }.joined(separator: " ")
    }

    var isRunning: Bool { process.isRunning }
    var pid: Int32 { process.processIdentifier }

    func start() throws {
        let fm = FileManager.default
        if let problem = BackendIntegrity.shared.gate(root: config.root) {
            throw BackendLaunchError(message: problem)
        }
        let (exe, args) = explicitCommand ?? config.uncheckedLaunchSpec(arguments)
        if BackendIntegrity.shared.isSealed,
           ![config.venvPython.path, "/usr/bin/python3"].contains(exe.path) {
            throw BackendLaunchError(message: "Odmowa: Cerber uruchamia tylko własny, sprawdzony interpreter (\(config.venvPython.path)), a nie \(exe.path).")
        }
        guard fm.isExecutableFile(atPath: exe.path) else {
            throw BackendLaunchError(message: config.mock
                ? "Nie znaleziono interpretera Pythona (\(exe.path))."
                : "Nie znaleziono środowiska Pythona Cerbera: \(exe.path). Uruchom najpierw instalację (./cerber.sh update).")
        }
        if config.mock, explicitCommand == nil, !fm.fileExists(atPath: config.mockScript.path) {
            throw BackendLaunchError(message: "Brak pliku \(config.mockScript.path).")
        }
        process.executableURL = exe
        process.arguments = args
        process.currentDirectoryURL = config.root
        process.environment = config.environment.merging(extraEnvironment) { _, new in new }
        process.standardOutput = outPipe
        process.standardError = errPipe
        if keepStdinOpen {
            let p = Pipe()
            stdinPipe = p
            process.standardInput = p
        } else {
            process.standardInput = FileHandle.nullDevice
        }

        outPipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            let data = h.availableData
            guard let self else { return }
            if data.isEmpty {
                h.readabilityHandler = nil
                self.queue.async { self.flushStdout(final: true); self.stdoutClosed = true; self.checkFinished() }
            } else {
                self.queue.async { self.outBuffer.append(data); self.flushStdout(final: false) }
            }
        }
        errPipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            let data = h.availableData
            guard let self else { return }
            if data.isEmpty {
                h.readabilityHandler = nil
                self.queue.async { self.flushStderr(final: true); self.stderrClosed = true; self.checkFinished() }
            } else {
                self.queue.async { self.errBuffer.append(data); self.flushStderr(final: false) }
            }
        }
        process.terminationHandler = { [weak self] _ in
            guard let self else { return }
            self.queue.async {
                self.exited = true
                self.checkFinished()
                // A grandchild may keep the pipes open; do not wait for EOF forever.
                self.queue.asyncAfter(deadline: .now() + 2.5) {
                    self.forceFinalize = true
                    self.checkFinished()
                }
            }
        }
        do {
            try process.run()
        } catch {
            outPipe.fileHandleForReading.readabilityHandler = nil
            errPipe.fileHandleForReading.readabilityHandler = nil
            throw BackendLaunchError(message: "Nie udało się uruchomić skanera: \(error.localizedDescription)")
        }
    }

    /// SIGINT – the backend stops and still emits `done` with partial results.
    func interrupt() {
        if process.isRunning { process.interrupt() }
    }

    /// SIGTERM – last resort when no `done` arrived.
    func terminate() {
        if process.isRunning { process.terminate() }
    }

    /// Closes the child's stdin pipe (the watcher treats EOF as "stop").
    func closeStdin() {
        try? stdinPipe?.fileHandleForWriting.close()
        stdinPipe = nil
    }

    // MARK: private (on `queue`)

    private static func splitLines(_ buffer: inout Data, final: Bool) -> [String] {
        var lines: [String] = []
        while let nl = buffer.firstIndex(of: 0x0A) {
            let chunk = buffer.subdata(in: buffer.startIndex..<nl)
            buffer.removeSubrange(buffer.startIndex...nl)
            lines.append(String(decoding: chunk, as: UTF8.self))
        }
        if final, !buffer.isEmpty {
            lines.append(String(decoding: buffer, as: UTF8.self))
            buffer.removeAll()
        }
        return lines
    }

    private func flushStdout(final: Bool) {
        let lines = Self.splitLines(&outBuffer, final: final)
        guard !lines.isEmpty else { return }
        var events: [BackendEvent] = []
        var invalid: [String] = []
        for line in lines {
            switch EventDecoder.decode(line: line) {
            case .event(let e): events.append(e)
            case .invalid(let s): invalid.append(s)
            case .blank: break
            }
        }
        let onEvents = self.onEvents
        let onInvalid = self.onInvalid
        DispatchQueue.main.async {
            for s in invalid { onInvalid?(s) }
            if !events.isEmpty { onEvents?(events) }
        }
    }

    private func flushStderr(final: Bool) {
        let lines = Self.splitLines(&errBuffer, final: final).filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        guard !lines.isEmpty else { return }
        let onStderr = self.onStderr
        DispatchQueue.main.async { onStderr?(lines) }
    }

    private func checkFinished() {
        guard !finalized, exited, (stdoutClosed && stderrClosed) || forceFinalize else { return }
        finalized = true
        flushStdout(final: true)
        flushStderr(final: true)
        outPipe.fileHandleForReading.readabilityHandler = nil
        errPipe.fileHandleForReading.readabilityHandler = nil
        let status = process.terminationStatus
        let reason = process.terminationReason
        let code: Int32 = reason == .uncaughtSignal ? 128 + status : status
        let onExit = self.onExit
        DispatchQueue.main.async {
            onExit?(code)
        }
    }
}

// MARK: - One-shot commands

struct BackendRunResult: Sendable {
    var events: [BackendEvent]
    var stderr: [String]
    var invalid: [String]
    var exitCode: Int32
    var launchError: String?

    var firstError: String? {
        for e in events { if case .error(let m, _) = e { return m } }
        return launchError
    }

    /// A short, user-presentable description of why the command failed.
    var failureDescription: String {
        if let e = firstError { return e }
        let tail = stderr.suffix(3).joined(separator: "\n")
        return tail.isEmpty ? "Skaner zakończył się kodem \(exitCode)." : tail
    }
}

extension BackendProcess {
    /// Runs a short command (info, history, quarantine) to completion.
    @MainActor
    static func run(config: BackendConfig, arguments: [String]) async -> BackendRunResult {
        await withCheckedContinuation { (cont: CheckedContinuation<BackendRunResult, Never>) in
            let p = BackendProcess(config: config, arguments: arguments)
            var result = BackendRunResult(events: [], stderr: [], invalid: [], exitCode: 0, launchError: nil)
            p.onEvents = { result.events.append(contentsOf: $0) }
            p.onInvalid = { result.invalid.append($0) }
            p.onStderr = { result.stderr.append(contentsOf: $0) }
            p.onExit = { code in
                result.exitCode = code
                cont.resume(returning: result)
                _ = p  // keep the process object alive until it finished
            }
            do {
                try p.start()
            } catch {
                result.launchError = error.localizedDescription
                result.exitCode = -1
                cont.resume(returning: result)
            }
        }
    }
}

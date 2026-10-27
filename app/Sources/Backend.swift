import Foundation

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
             "watch_notice", "watch_alert", "watch_net", "watch_net_status":
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
        return BackendConfig(root: detectRoot(), mock: mock)
    }

    static func detectRoot() -> URL {
        let fm = FileManager.default
        let env = ProcessInfo.processInfo.environment
        var candidates: [String] = []
        if let r = env["CERBER_ROOT"] { candidates.append(r) }
        if let r = Bundle.main.object(forInfoDictionaryKey: "CerberRoot") as? String { candidates.append(r) }
        candidates.append(Bundle.main.bundleURL.deletingLastPathComponent().path)
        let exe = URL(fileURLWithPath: CommandLine.arguments.first ?? "").resolvingSymlinksInPath()
        candidates.append(exe.deletingLastPathComponent().deletingLastPathComponent().path)
        candidates.append(fm.currentDirectoryPath)
        for c in candidates {
            let url = URL(fileURLWithPath: (c as NSString).expandingTildeInPath)
            if fm.fileExists(atPath: url.appendingPathComponent("cerber").path)
                || fm.fileExists(atPath: url.appendingPathComponent("app/mock_backend.py").path) {
                return url.standardizedFileURL
            }
        }
        return URL(fileURLWithPath: candidates.first ?? fm.currentDirectoryPath)
    }

    var venvPython: URL { root.appendingPathComponent(".venv/bin/python") }
    var mockScript: URL { root.appendingPathComponent("app/mock_backend.py") }

    /// Executable + arguments for one backend command.
    func launchSpec(_ args: [String]) -> (URL, [String]) {
        let fm = FileManager.default
        if mock {
            let py = fm.isExecutableFile(atPath: venvPython.path) ? venvPython : URL(fileURLWithPath: "/usr/bin/python3")
            return (py, [mockScript.path] + args)
        }
        return (venvPython, ["-m", "cerber.gui_backend"] + args)
    }

    var environment: [String: String] {
        var env = ProcessInfo.processInfo.environment
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["LANG"] = env["LANG"] ?? "pl_PL.UTF-8"
        let extra = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        let current = (env["PATH"] ?? "").split(separator: ":").map(String.init)
        env["PATH"] = (current + extra.filter { !current.contains($0) }).joined(separator: ":")
        return env
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
        let (exe, args) = spec
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

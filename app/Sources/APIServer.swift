import AppKit
import Foundation
import Observation
import Security

/// Optional localhost API: runs `python -m cerber.api_server --port 8765` (token via CERBER_API_TOKEN) while the app is open
/// (never at login). The token is generated here, kept in the Keychain and passed on the command line,
/// so it stays the same across restarts.
@Observable
final class APIServer {
    enum State: Equatable {
        case off
        case starting
        case running(url: String, docs: String?)
        case failed(String)
    }

    static let port = 8765
    static let preferenceKey = "localAPIEnabled"

    var state: State = .off
    /// The user's choice (UserDefaults) – when on, the server starts with the app.
    var enabled: Bool = UserDefaults.standard.bool(forKey: APIServer.preferenceKey)
    /// Loaded lazily from the Keychain (only when the API page is shown or the server starts).
    var token: String?
    var stderrTail: [String] = []
    let config: BackendConfig

    @ObservationIgnored private var process: BackendProcess?
    @ObservationIgnored private var stopRequested = false
    @ObservationIgnored private var startTimeout: DispatchWorkItem?
    @ObservationIgnored private var killWork: DispatchWorkItem?

    init(config: BackendConfig) {
        self.config = config
    }

    var isRunning: Bool {
        if case .running = state { return true }
        return false
    }

    var baseURL: String {
        if case .running(let url, _) = state { return url }
        return "http://127.0.0.1:\(Self.port)"
    }

    var docsURL: String {
        if case .running(let url, let docs) = state { return docs ?? url + "/" }
        return baseURL + "/"
    }

    var curlExample: String {
        "curl -H \"Authorization: Bearer \(token ?? "<token>")\" \(baseURL)/api/info"
    }

    // MARK: token

    func loadToken() {
        guard token == nil else { return }
        if let t = Keychain.read() {
            token = t
        } else {
            let t = Self.generateToken()
            Keychain.save(t)
            token = t
        }
    }

    static func generateToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        if SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) != errSecSuccess {
            for i in bytes.indices { bytes[i] = UInt8.random(in: 0...255) }
        }
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    func regenerateToken() {
        let t = Self.generateToken()
        Keychain.save(t)
        token = t
        if process != nil || state == .starting || isRunning {
            restart()
        }
    }

    // MARK: lifecycle

    func setEnabled(_ on: Bool) {
        enabled = on
        UserDefaults.standard.set(on, forKey: Self.preferenceKey)
        if on { start() } else { stop() }
    }

    /// App launch: start only if the user left it on last time.
    func startIfPreferred() {
        if enabled, process == nil { start() }
    }

    func restart() {
        if let p = process {
            stopRequested = true
            let old = p
            old.onExit = { [weak self] _ in
                self?.process = nil
                self?.start()
            }
            stopProcess(old)
        } else {
            start()
        }
    }

    func start() {
        guard process == nil else { return }
        loadToken()
        guard let token else { return }
        stopRequested = false
        stderrTail = []
        state = .starting
        let exe = config.venvPython
        // the token goes through the environment, not argv (command lines are visible to every user in `ps`)
        let args = ["-m", "cerber.api_server", "--port", String(Self.port)]
        let p = BackendProcess(config: config, executable: exe, arguments: args)
        p.extraEnvironment = ["CERBER_API_TOKEN": token]
        p.onEvents = { [weak self] events in
            guard let self else { return }
            for e in events {
                if case .apiReady(let url, _, let docs) = e {
                    self.startTimeout?.cancel()
                    self.state = .running(url: url.isEmpty ? self.baseURL : url, docs: docs)
                }
            }
        }
        p.onStderr = { [weak self] lines in
            guard let self else { return }
            self.stderrTail.append(contentsOf: lines)
            if self.stderrTail.count > 40 { self.stderrTail.removeFirst(self.stderrTail.count - 40) }
        }
        p.onExit = { [weak self] code in
            guard let self else { return }
            self.process = nil
            self.startTimeout?.cancel()
            self.killWork?.cancel()
            if self.stopRequested {
                self.state = .off
            } else {
                let tail = self.stderrTail.suffix(3).joined(separator: "\n")
                self.state = .failed("Serwer API zakończył działanie (kod \(code))." + (tail.isEmpty ? "" : "\n" + tail))
            }
        }
        do {
            try p.start()
            process = p
            let timeout = DispatchWorkItem { [weak self, weak p] in
                guard let self, let p, self.state == .starting else { return }
                self.stderrTail.append("Brak odpowiedzi api_ready po 30 s")
                self.stopRequested = false
                p.terminate()
            }
            startTimeout = timeout
            DispatchQueue.main.asyncAfter(deadline: .now() + 30, execute: timeout)
        } catch {
            state = .failed(FileManager.default.isExecutableFile(atPath: exe.path)
                            ? error.localizedDescription
                            : "Nie znaleziono środowiska Pythona Cerbera: \(exe.path)")
        }
    }

    func stop() {
        startTimeout?.cancel()
        guard let p = process else {
            state = .off
            return
        }
        stopRequested = true
        stopProcess(p)
    }

    /// SIGINT, then SIGTERM after 5 s.
    private func stopProcess(_ p: BackendProcess) {
        p.interrupt()
        let work = DispatchWorkItem { [weak p] in
            if let p, p.isRunning { p.terminate() }
        }
        killWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 5, execute: work)
    }

    /// App quit: blocking stop (SIGINT, SIGTERM after 5 s).
    func shutdown() {
        guard let p = process, p.isRunning else { return }
        stopRequested = true
        p.interrupt()
        let deadline = Date().addingTimeInterval(5)
        while p.isRunning && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
        p.terminate()
    }
}

// MARK: - Keychain (login keychain, generic password)

enum Keychain {
    static let service = "pl.cerber.app.api"
    static let account = "api-token"

    private static var baseQuery: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    static func read() -> String? {
        var q = baseQuery
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func save(_ token: String) {
        let data = Data(token.utf8)
        let status = SecItemUpdate(baseQuery as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var add = baseQuery
            add[kSecValueData as String] = data
            add[kSecAttrLabel as String] = "Cerber – token lokalnego API"
            SecItemAdd(add as CFDictionary, nil)
        }
    }
}

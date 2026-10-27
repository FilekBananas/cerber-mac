import AppKit
import Foundation
import Observation
import SwiftUI

// MARK: - Navigation

enum SidebarItem: String, Hashable, CaseIterable, Identifiable {
    case session, laptop, file, location, sandbox, github, huggingface, link, iphone, protection, history, api
    var id: String { rawValue }

    static let scanScreens: [SidebarItem] = [.laptop, .file, .location, .sandbox, .github, .huggingface, .link, .iphone]

    var title: String {
        switch self {
        case .session: return "Skanowanie"
        case .laptop: return "Przeskanuj laptop"
        case .file: return "Plik lub folder"
        case .location: return "Lokalizacja"
        case .sandbox: return "Archiwum w sandboksie"
        case .github: return "Repozytorium GitHub"
        case .huggingface: return "Hugging Face"
        case .link: return "Sprawdź link"
        case .iphone: return "iPhone (kabel)"
        case .protection: return "Ochrona w tle"
        case .history: return "Historia"
        case .api: return "API (localhost)"
        }
    }

    var icon: String {
        switch self {
        case .session: return "shield.lefthalf.filled"
        case .laptop: return "laptopcomputer"
        case .file: return "doc.viewfinder"
        case .location: return "folder"
        case .sandbox: return "archivebox"
        case .github: return "chevron.left.forwardslash.chevron.right"
        case .huggingface: return "brain"
        case .link: return "link.badge.plus"
        case .iphone: return "iphone"
        case .protection: return "shield.lefthalf.filled.badge.checkmark"
        case .history: return "clock.arrow.circlepath"
        case .api: return "network.badge.shield.half.filled"
        }
    }
}

// MARK: - Stages

enum Stage {
    static func defaultTitle(_ id: String) -> String {
        switch id {
        case "check": return "Sprawdzanie adresu…"
        case "sandbox": return "Uruchamianie izolowanego sandboksa…"
        case "load": return "Ładowanie baz sygnatur…"
        case "enumerate": return "Wyszukiwanie plików…"
        case "download": return "Pobieranie…"
        case "extract": return "Rozpakowywanie w sandboksie…"
        case "env": return "Skanowanie środowiska…"
        case "network": return "Audyt sieci…"
        case "scan": return "Skanowanie plików…"
        case "behavior": return "Analiza zachowania…"
        case "cloud": return "Pliki z chmury…"
        case "ai": return "Analiza AI…"
        case "report": return "Zapisywanie raportu…"
        default: return id
        }
    }

    static func shortTitle(_ id: String) -> String {
        switch id {
        case "check": return "Adres"
        case "sandbox": return "Sandbox"
        case "load": return "Bazy"
        case "enumerate": return "Wyszukiwanie"
        case "download": return "Pobieranie"
        case "extract": return "Rozpakowanie"
        case "env": return "Środowisko"
        case "network": return "Sieć"
        case "scan": return "Skanowanie"
        case "behavior": return "Zachowanie"
        case "cloud": return "Chmura"
        case "ai": return "Analiza AI"
        case "report": return "Raport"
        default: return id.capitalized
        }
    }

    static func icon(_ id: String) -> String {
        switch id {
        case "check": return "link"
        case "sandbox": return "lock.shield"
        case "load": return "cylinder.split.1x2"
        case "enumerate": return "magnifyingglass"
        case "download": return "arrow.down.circle"
        case "extract": return "shippingbox"
        case "env": return "gearshape.2"
        case "network": return "network"
        case "scan": return "doc.viewfinder"
        case "behavior": return "testtube.2"
        case "cloud": return "icloud.and.arrow.down"
        case "ai": return "sparkles"
        case "report": return "doc.richtext"
        default: return "circle.dashed"
        }
    }
}

// MARK: - Requests

struct ScanRequest: Sendable {
    var mode: ScanMode
    var arguments: [String]
    var title: String
    var level: ScanLevel
    var ai: Bool
    var origin: SidebarItem

    /// The order the stepper starts with; real `stage` events reorder it as they arrive.
    /// Every mode runs in a sandbox (read-only for `scan`/`laptop`), so "sandbox" precedes "load".
    /// "behavior" (suspicious scripts run in a sealed sandbox, after "scan") is never listed: it happens only
    /// when there is something to run, and its `stage` event inserts it after the stages already visited.
    /// The same goes for "cloud" (Mega only: risky files kept only in iCloud are downloaded and scanned).
    var expectedStages: [String] {
        let ai = self.ai ? ["ai"] : []
        let files = ["sandbox", "load", "enumerate", "scan"]
        switch mode {
        case .scan:
            return files + ai + ["report"]
        case .sandbox:
            return ["sandbox", "extract", "load", "scan"] + ai + ["report"]
        case .github, .huggingface:
            return ["download", "sandbox", "extract", "load", "scan"] + ai + ["report"]
        case .url:
            return ["check", "download", "sandbox", "extract", "load", "scan"] + ai + ["report"]
        case .laptop:
            switch level {
            case .quick, .patterns: return files + ai + ["report"]
            case .deep: return ["env"] + files + ai + ["report"]
            case .mega: return ["env", "network"] + files + ai + ["report"]
            }
        }
    }

    var modeLabel: String {
        switch mode {
        case .laptop: return "Laptop · poziom \(level.label)"
        case .scan: return origin == .location ? "Lokalizacja · skan dokładny" : "Plik lub folder · skan dokładny"
        case .sandbox: return "Archiwum w sandboksie"
        case .github: return "Repozytorium GitHub"
        case .huggingface: return "Hugging Face"
        case .url: return "Sprawdź link"
        }
    }
}

struct LogLine: Identifiable, Sendable {
    let id: Int
    let text: String
    let isStderr: Bool
}

// MARK: - Session

@Observable
final class ScanSession: Identifiable {
    enum Phase: Equatable {
        case running
        case cancelling
        case finished
        case failed(cancelled: Bool)
    }

    let id = UUID()
    let request: ScanRequest
    var phase: Phase = .running
    var stageOrder: [String]
    var stageTitles: [String: String] = [:]
    var visited: [String] = []
    var currentStage: String?
    var progress: [String: ProgressEvent] = [:]
    var findings: [ScanResult] = []
    var log: [LogLine] = []
    var summary: Summary?
    var warnings: [String] = []
    /// Problems reported by `sandbox_violation` – the scan is aborted for safety.
    var sandboxViolation: [String]?
    /// Mega: latest `net_status` of the live network monitor (nil until the start audit is done).
    var netStatus: NetMonitorStatus?
    /// Live monitor events, newest first, capped at `netEventCap`.
    var netEvents: [NetEvent] = []
    static let netEventCap = 300
    var fatalMessage: String?
    var exitCode: Int32?
    var startedAt = Date()
    var finishedAt: Date?
    var cancelRequestedAt: Date?
    var commandLine: String = ""
    @ObservationIgnored private var logCounter = 0

    init(request: ScanRequest) {
        self.request = request
        self.stageOrder = request.expectedStages
    }

    var isActive: Bool { phase == .running || phase == .cancelling }

    var currentProgress: ProgressEvent? {
        guard let s = currentStage else { return nil }
        return progress[s]
    }

    var scanProgress: ProgressEvent? { progress["scan"] }

    var flaggedCount: Int {
        max(findings.count, progress["scan"]?.flagged ?? 0)
    }

    var worstFinding: Verdict {
        findings.map(\.verdict).max() ?? .clean
    }

    func stageState(_ id: String) -> StageState {
        if id == currentStage {
            switch phase {
            case .running, .cancelling: return .active
            case .finished: return .done
            case .failed: return .failed
            }
        }
        if visited.contains(id) { return .done }
        if phase == .finished { return .skipped }
        return .pending
    }

    func appendLog(_ text: String, stderr: Bool) {
        logCounter += 1
        log.append(LogLine(id: logCounter, text: text, isStderr: stderr))
        if log.count > 3000 { log.removeFirst(log.count - 3000) }
    }

    func apply(_ event: BackendEvent) {
        switch event {
        case .stage(let id, let title):
            stageTitles[id] = title
            if !visited.contains(id) { visited.append(id) }
            currentStage = id
            stageOrder = visited + stageOrder.filter { !visited.contains($0) }
            appendLog("▸ " + title, stderr: false)
        case .log(let msg):
            appendLog(msg, stderr: false)
        case .progress(let p):
            progress[p.stage] = p
            if currentStage == nil {
                currentStage = p.stage
                if !visited.contains(p.stage) { visited.append(p.stage) }
            }
        case .finding(let r):
            if let i = findings.firstIndex(where: { $0.id == r.id }) {
                findings[i] = r
            } else {
                findings.append(r)
            }
        case .done(let s):
            summary = s
            phase = .finished
            finishedAt = Date()
            netStatus?.active = false
        case .error(let msg, let fatal):
            appendLog((fatal ? "BŁĄD: " : "Uwaga: ") + msg, stderr: false)
            if fatal {
                fatalMessage = msg
            } else if !warnings.contains(msg) {
                warnings.append(msg)
            }
        case .quarantined(let path, let qid):
            markQuarantined(path: path, id: qid)
        case .sandboxViolation(let problems):
            sandboxViolation = problems
            appendLog("NARUSZENIE SANDBOKSA: " + problems.joined(separator: "; "), stderr: false)
        case .netStatus(let st):
            // Arrives during enumerate/scan/ai – never touches the stepper.
            netStatus = st
        case .netEvent(let e):
            if let i = netEvents.firstIndex(where: { $0.id == e.id }) {
                netEvents[i] = e
            } else {
                netEvents.insert(e, at: 0)
                if netEvents.count > Self.netEventCap { netEvents.removeLast(netEvents.count - Self.netEventCap) }
                if e.isAlert { appendLog("Sieć na żywo: " + e.title, stderr: false) }
            }
        case .info, .history, .aiInstalled, .apiReady, .watch, .iphone, .unknown:
            break
        }
    }

    func markQuarantined(path: String, id qid: String) {
        for i in findings.indices where findings[i].path == path { findings[i].quarantined = qid }
        if var s = summary {
            for i in s.results.indices where s.results[i].path == path { s.results[i].quarantined = qid }
            summary = s
        }
    }

    func processExited(code: Int32) {
        exitCode = code
        finishedAt = finishedAt ?? Date()
        netStatus?.active = false
        if summary != nil {
            phase = .finished
            return
        }
        let cancelled = code == 130 || code == 143 || code == 128 + 15 || cancelRequestedAt != nil
        phase = .failed(cancelled: cancelled)
        if fatalMessage == nil && !cancelled {
            let tail = log.filter(\.isStderr).suffix(4).map(\.text).joined(separator: "\n")
            fatalMessage = "Skaner zakończył pracę bez wyników (kod \(code))." + (tail.isEmpty ? "" : "\n\n" + tail)
        }
    }
}

enum StageState {
    case pending, active, done, skipped, failed
}

// MARK: - App model

struct AppAlert: Identifiable {
    let id = UUID()
    var title: String
    var message: String
}

struct PresentationHints {
    var resultsTab: ResultsTab? = nil
    var expandLog = false
    var expandFirstResult = false
    /// Also expand the results whose path contains this text.
    var expandResultMatching: String? = nil
}

enum LoadState: Equatable {
    case idle, loading, loaded
    case failed(String)
}

/// Download of the local AI model (`ai-install`) – started only by the user's click, independent from scans.
enum AIInstallState: Equatable {
    case idle
    case downloading(bytes: Int, total: Int?)
    case failed(String)
    case installed

    var isDownloading: Bool {
        if case .downloading = self { return true }
        return false
    }

    var failureMessage: String? {
        if case .failed(let m) = self { return m }
        return nil
    }

    var fraction: Double? {
        guard case .downloading(let b, let t) = self, let t, t > 0 else { return nil }
        return min(1, max(0, Double(b) / Double(t)))
    }
}

@Observable
final class AppModel {
    var selection: SidebarItem? = .laptop
    var info: DBInfo?
    var infoState: LoadState = .idle
    var history: [HistoryItem] = []
    var historyState: LoadState = .idle
    var session: ScanSession?
    var level: ScanLevel = .deep
    /// The user's AI choice for the target screens (UserDefaults; never touched → off).
    var aiPreference: Bool = AppModel.storedAIPreference()
    var aiInstall: AIInstallState = .idle
    var githubText = ""
    var hfText = ""
    var linkText = ""
    var alert: AppAlert?
    var pendingQuarantine: ScanResult?
    var quarantining: Set<String> = []
    /// Initial presentation choices (used by `--snapshot`).
    var presentation = PresentationHints()
    let config: BackendConfig
    /// Optional localhost API server (lives only while the app runs).
    let api: APIServer
    /// "Ochrona w tle" – background watcher of downloads/installs.
    let protection: BackgroundProtection
    /// "iPhone (kabel)" – device list and iPhone/backup checks (own backend runs, see IPhoneScreen.swift).
    let iphone: IPhoneModel

    @ObservationIgnored private var process: BackendProcess?
    @ObservationIgnored private var killWork: DispatchWorkItem?
    @ObservationIgnored private var aiProcess: BackendProcess?
    @ObservationIgnored private var shuttingDown = false
    static let aiPreferenceKey = "aiAnalysisEnabled"

    /// `live` = the real app (notifications allowed); false for --snapshot / --selftest-parse.
    init(config: BackendConfig, live: Bool = false) {
        self.config = config
        self.api = APIServer(config: config)
        self.protection = BackgroundProtection(config: config)
        self.protection.notificationsEnabled = live
        self.iphone = IPhoneModel(config: config)
        ReportViewer.config = config
    }

    var isScanning: Bool { session?.isActive ?? false }

    /// Model present and the llama-server engine not reported missing.
    var aiAvailable: Bool {
        guard let info else { return false }
        return info.aiModel != nil && info.llamaServer != false
    }

    /// What the toggle shows and what scans use: the user's choice, only when AI can actually run.
    var aiEnabled: Bool {
        get { aiPreference && aiAvailable }
        set {
            aiPreference = newValue
            UserDefaults.standard.set(newValue, forKey: Self.aiPreferenceKey)
        }
    }

    static func storedAIPreference() -> Bool {
        UserDefaults.standard.object(forKey: aiPreferenceKey) as? Bool ?? false
    }

    /// One-line explanation of the AI state for toggles and the Mega level.
    var aiStatusNote: String? {
        if aiAvailable { return nil }
        if let info, info.aiModel != nil, info.llamaServer == false {
            return "Brak silnika llama-server – zainstaluj go: brew install llama.cpp."
        }
        switch aiInstall {
        case .downloading:
            let pct = aiInstall.fraction.map { " (\(Fmt.percent($0)))" } ?? ""
            return "Analiza AI będzie dostępna po pobraniu modelu\(pct). Skanować możesz już teraz – bez AI."
        case .failed:
            return "Nie udało się pobrać modelu AI – ponów pobieranie w lewym dolnym rogu okna."
        default:
            if info == nil { return "Sprawdzanie dostępności modelu AI…" }
            guard info?.aiInstallable == true else { return "Model AI nie jest zainstalowany." }
            let size = info?.aiModelSize.map { " (\(Fmt.bytes($0)))" } ?? ""
            return "Model AI nie jest pobrany – kliknij „Pobierz model AI\(size)” w lewym dolnym rogu okna."
        }
    }

    // MARK: scanning

    func start(_ request: ScanRequest) {
        guard !isScanning else {
            alert = AppAlert(title: "Trwa już skanowanie",
                             message: "Cerber wykonuje jedno skanowanie naraz. Poczekaj na jego koniec albo je anuluj.")
            return
        }
        let s = ScanSession(request: request)
        let p = BackendProcess(config: config, arguments: request.arguments)
        s.commandLine = p.commandLine
        s.appendLog("$ " + p.commandLine + (config.mock ? "   (tryb demonstracyjny – mock)" : ""), stderr: true)
        p.onEvents = { [weak self, weak s] events in
            guard let s else { return }
            withAnimation(.spring(response: 0.45, dampingFraction: 0.85)) {
                for e in events { s.apply(e) }
            }
            for e in events {
                if case .sandboxViolation(let problems) = e {
                    self?.alert = AppAlert(title: "Samosprawdzenie sandboksa nie powiodło się – skan przerwany dla bezpieczeństwa",
                                           message: problems.map { "• " + $0 }.joined(separator: "\n"))
                }
            }
            if s.summary != nil { self?.scanFinished() }
        }
        p.onInvalid = { [weak s] line in s?.appendLog("[stdout] " + line, stderr: true) }
        p.onStderr = { [weak s] lines in for l in lines { s?.appendLog(l, stderr: true) } }
        p.onExit = { [weak self, weak s] code in
            guard let s else { return }
            withAnimation(.easeInOut(duration: 0.3)) { s.processExited(code: code) }
            if let self, self.session === s {
                self.process = nil
                self.killWork?.cancel()
                self.killWork = nil
                self.loadHistory()
            }
        }
        session = s
        process = p
        withAnimation(.easeInOut(duration: 0.25)) { selection = .session }
        do {
            try p.start()
        } catch {
            s.fatalMessage = error.localizedDescription
            s.phase = .failed(cancelled: false)
            process = nil
        }
    }

    private func scanFinished() {
        NSApp?.requestUserAttention(.informationalRequest)
    }

    func cancel() {
        guard let s = session, s.isActive, let p = process else { return }
        if s.phase == .cancelling {
            // Second press: stop immediately.
            p.terminate()
            return
        }
        s.phase = .cancelling
        s.cancelRequestedAt = Date()
        s.appendLog("Wysłano SIGINT – czekam na częściowe wyniki…", stderr: true)
        p.interrupt()
        let work = DispatchWorkItem { [weak self, weak s, weak p] in
            guard let s, let p, s.summary == nil, p.isRunning else { return }
            s.appendLog("Brak odpowiedzi po 10 s – wysyłam SIGTERM", stderr: true)
            p.terminate()
            _ = self
        }
        killWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 10, execute: work)
    }

    func newScan() {
        guard let s = session, !s.isActive else { return }
        let origin = s.request.origin
        withAnimation(.easeInOut(duration: 0.25)) {
            selection = origin
            session = nil
        }
    }

    func retry() {
        guard let s = session, !s.isActive else { return }
        let r = s.request
        session = nil
        start(r)
    }

    /// App quit: interrupt the scan and the AI download (the download resumes on the next launch).
    func shutdown() {
        api.shutdown()
        protection.shutdown()
        iphone.shutdown()
        shuttingDown = true
        let running = [process, aiProcess].compactMap { $0 }.filter(\.isRunning)
        guard !running.isEmpty else { return }
        running.forEach { $0.interrupt() }
        let deadline = Date().addingTimeInterval(3)
        while running.contains(where: \.isRunning) && Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        running.forEach { $0.terminate() }
    }

    // MARK: request builders

    private func flags(ai: Bool) -> [String] { ai ? ["--ai"] : [] }

    func scanPaths(_ urls: [URL], origin: SidebarItem) {
        let paths = urls.map { $0.standardizedFileURL.path }
        guard !paths.isEmpty else { return }
        let first = (paths[0] as NSString).lastPathComponent
        let title = paths.count == 1 ? first : "\(first) i \(Fmt.count(paths.count - 1, "inny", "inne", "innych"))"
        start(ScanRequest(mode: .scan, arguments: ["scan"] + paths + flags(ai: aiEnabled), title: title,
                          level: .deep, ai: aiEnabled, origin: origin))
    }

    func scanSandbox(_ url: URL) {
        start(ScanRequest(mode: .sandbox, arguments: ["sandbox", url.standardizedFileURL.path] + flags(ai: aiEnabled),
                          title: url.lastPathComponent, level: .deep, ai: aiEnabled, origin: .sandbox))
    }

    func scanGitHub(_ ref: RepoRef) {
        start(ScanRequest(mode: .github, arguments: ["github", ref.url] + flags(ai: aiEnabled),
                          title: ref.display, level: .deep, ai: aiEnabled, origin: .github))
    }

    func scanHuggingFace(_ ref: RepoRef) {
        start(ScanRequest(mode: .huggingface, arguments: ["huggingface", ref.url] + flags(ai: aiEnabled),
                          title: ref.display, level: .deep, ai: aiEnabled, origin: .huggingface))
    }

    func scanURL(_ link: LinkRef) {
        start(ScanRequest(mode: .url, arguments: ["url", link.url] + flags(ai: aiEnabled),
                          title: link.title, level: .deep, ai: aiEnabled, origin: .link))
    }

    func scanLaptop() {
        // Mega always includes AI when the model can run; it is passed explicitly.
        let ai = level.includesAI && aiAvailable
        start(ScanRequest(mode: .laptop, arguments: ["laptop", "--level", level.rawValue] + flags(ai: ai),
                          title: "Laptop – \(level.label)", level: level, ai: ai, origin: .laptop))
    }

    // MARK: open panels

    func chooseAndScan(origin: SidebarItem = .file) {
        guard !isScanning else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Przeskanuj"
        panel.message = "Wybierz pliki lub foldery do przeskanowania"
        if panel.runModal() == .OK, !panel.urls.isEmpty {
            scanPaths(panel.urls, origin: origin)
        }
    }

    func chooseLocation() {
        guard !isScanning else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Przeskanuj"
        panel.message = "Wybierz folder lub dysk do przeskanowania"
        if panel.runModal() == .OK, let url = panel.url {
            scanPaths([url], origin: .location)
        }
    }

    func chooseArchive() {
        guard !isScanning else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Rozpakuj i przeskanuj"
        panel.message = "Wybierz archiwum – zostanie rozpakowane w izolowanym sandboksie"
        if panel.runModal() == .OK, let url = panel.url {
            scanSandbox(url)
        }
    }

    // MARK: one-shot commands

    func loadInfo() {
        guard infoState != .loading else { return }
        infoState = .loading
        Task { @MainActor in
            let r = await BackendProcess.run(config: config, arguments: ["info"])
            for e in r.events { if case .info(let i) = e { self.info = i } }
            self.infoState = self.info != nil ? .loaded : .failed(r.failureDescription)
        }
    }

    // MARK: AI model download

    /// The user clicked "Pobierz model AI" (size shown on the button). Nothing is ever downloaded without
    /// that click – owner's rule: nothing runs in the background without asking.
    func downloadAIModel() {
        guard let info, info.aiInstallable, aiProcess == nil, !shuttingDown else { return }
        if info.aiModel != nil && !info.aiUpgradeAvailable { return }
        aiInstall = .idle
        startAIInstall()
    }

    func retryAIInstall() {
        guard aiProcess == nil else { return }
        aiInstall = .idle
        startAIInstall()
    }

    private func startAIInstall() {
        let p = BackendProcess(config: config, arguments: ["ai-install"])
        var installed = false
        var lastError: String?
        aiInstall = .downloading(bytes: info?.aiDownloadPartial ?? 0, total: info?.aiModelSize)
        p.onEvents = { [weak self] events in
            guard let self else { return }
            for e in events {
                switch e {
                case .progress(let pr) where pr.stage == "download":
                    self.aiInstall = .downloading(bytes: pr.bytes ?? 0, total: pr.total ?? self.info?.aiModelSize)
                case .aiInstalled:
                    installed = true
                    self.aiInstall = .installed
                case .error(let msg, _):
                    lastError = msg
                default:
                    break
                }
            }
        }
        p.onExit = { [weak self] code in
            guard let self else { return }
            self.aiProcess = nil
            if installed {
                self.aiInstall = .installed
                self.loadInfo()
            } else if self.shuttingDown || code == 130 || code == 143 {
                self.aiInstall = .idle
            } else {
                self.aiInstall = .failed(lastError ?? "Instalacja modelu AI nie powiodła się (kod \(code)).")
            }
        }
        do {
            try p.start()
            aiProcess = p
        } catch {
            aiInstall = .failed(error.localizedDescription)
        }
    }

    func loadHistory() {
        guard historyState != .loading else { return }
        historyState = .loading
        Task { @MainActor in
            let r = await BackendProcess.run(config: config, arguments: ["history"])
            var got = false
            for e in r.events { if case .history(let items) = e { self.history = items; got = true } }
            self.historyState = got ? .loaded : .failed(r.failureDescription)
        }
    }

    func quarantine(_ result: ScanResult) {
        let path = result.path
        guard !quarantining.contains(path) else { return }
        quarantining.insert(path)
        Task { @MainActor in
            let r = await BackendProcess.run(config: config, arguments: ["quarantine", path])
            self.quarantining.remove(path)
            var ok = false
            for e in r.events {
                if case .quarantined(let p, let qid) = e {
                    ok = true
                    withAnimation { self.session?.markQuarantined(path: p.isEmpty ? path : p, id: qid) }
                }
            }
            if !ok {
                self.alert = AppAlert(title: "Nie udało się przenieść pliku do kwarantanny",
                                      message: r.failureDescription)
            }
        }
    }
}

// MARK: - Labels

extension ScanLevel {
    /// Levels that use the local AI model whenever it is available (only Mega).
    var includesAI: Bool { self == .mega }

    var label: String {
        switch self {
        case .quick: return "Szybki"
        case .patterns: return "Średni"
        case .deep: return "Dokładny"
        case .mega: return "Mega"
        }
    }
}

extension ScanMode {
    var label: String {
        switch self {
        case .scan: return "Plik lub folder"
        case .sandbox: return "Archiwum w sandboksie"
        case .github: return "GitHub"
        case .huggingface: return "Hugging Face"
        case .url: return "Link"
        case .laptop: return "Laptop"
        }
    }

    var icon: String {
        switch self {
        case .scan: return "doc.viewfinder"
        case .sandbox: return "archivebox"
        case .github: return "chevron.left.forwardslash.chevron.right"
        case .huggingface: return "brain"
        case .url: return "link"
        case .laptop: return "laptopcomputer"
        }
    }
}

// MARK: - Link parsing ("Sprawdź link")

struct LinkRef: Equatable {
    var url: String
    var host: String
    var isEncrypted: Bool

    /// "host/…/file.zip" style short title.
    var title: String {
        guard let u = URL(string: url) else { return host }
        let last = u.lastPathComponent
        return last.isEmpty || last == "/" ? host : "\(host) · \(last)"
    }

    /// http/https only; a missing scheme becomes https://.
    static func parse(_ input: String) -> LinkRef? {
        var s = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty, !s.contains(" ") else { return nil }
        if !s.contains("://") { s = "https://" + s }
        guard let u = URL(string: s), let scheme = u.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = u.host, !host.isEmpty, host.contains(".") || host == "localhost" else { return nil }
        return LinkRef(url: s, host: host.lowercased(), isEncrypted: scheme == "https")
    }
}

// MARK: - Repository URL parsing

struct RepoRef: Equatable {
    enum Kind: String { case repo, model, dataset, space }
    var kind: Kind
    var owner: String
    var name: String
    var ref: String?
    var url: String

    var display: String {
        switch kind {
        case .repo: return "github.com/\(owner)/\(name)"
        case .model: return "huggingface.co/\(owner)/\(name)"
        case .dataset: return "huggingface.co/datasets/\(owner)/\(name)"
        case .space: return "huggingface.co/spaces/\(owner)/\(name)"
        }
    }

    private static func match(_ pattern: String, _ s: String) -> [String?]? {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
        let ns = s as NSString
        guard let m = re.firstMatch(in: s, range: NSRange(location: 0, length: ns.length)) else { return nil }
        return (0..<m.numberOfRanges).map { i in
            let r = m.range(at: i)
            return r.location == NSNotFound ? nil : ns.substring(with: r)
        }
    }

    static func github(_ input: String) -> RepoRef? {
        let s = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        let full = #"^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]+?)(?:\.git)?(?:/tree/([^\s?#]+?))?/?(?:[?#].*)?$"#
        let short = #"^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]+?)(?:\.git)?$"#
        if let g = match(full, s) ?? match(short, s), let owner = g[1], let name = g[2] {
            let ref = g.count > 3 ? g[3] : nil
            var url = "https://github.com/\(owner)/\(name)"
            if let ref { url += "/tree/\(ref)" }
            return RepoRef(kind: .repo, owner: owner, name: name, ref: ref, url: url)
        }
        return nil
    }

    static func huggingFace(_ input: String) -> RepoRef? {
        let s = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        let full = #"^(?:https?://)?(?:www\.)?(?:huggingface\.co|hf\.co)/(?:(datasets|spaces)/)?([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)(?:/(?:tree|blob|resolve)/([^/\s?#]+)[^\s]*)?/?(?:[?#].*)?$"#
        let short = #"^(?:(datasets|spaces)/)?([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)$"#
        if let g = match(full, s) ?? match(short, s), let owner = g[2], let name = g[3] {
            let kind: Kind = g[1]?.lowercased() == "datasets" ? .dataset : (g[1]?.lowercased() == "spaces" ? .space : .model)
            let prefix = kind == .dataset ? "datasets/" : (kind == .space ? "spaces/" : "")
            let ref = g.count > 4 ? g[4] : nil
            var url = "https://huggingface.co/\(prefix)\(owner)/\(name)"
            if let ref { url += "/tree/\(ref)" }
            return RepoRef(kind: kind, owner: owner, name: name, ref: ref, url: url)
        }
        return nil
    }
}

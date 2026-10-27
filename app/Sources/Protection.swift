import AppKit
import Foundation
import Observation
import ServiceManagement
import UserNotifications

// MARK: - Watch events (`python -m cerber watch run --app`)

struct WatchSpot: Identifiable, Sendable, Equatable {
    var id: String { kind + "|" + path }
    var kind: String
    var kindPL: String
    var path: String
    var ok: Bool
    var error: String?

    init(_ j: JSONValue) {
        kind = j["kind"].text ?? ""
        kindPL = j["kind_pl"].text ?? kind
        path = j["path"].text ?? ""
        ok = j["ok"].bool ?? true
        error = j["error"].text
    }

    /// TCC (Full Disk Access / Files & Folders) not granted yet.
    var isPermissionError: Bool {
        let e = (error ?? "").lowercased()
        return e.contains("not permitted") || e.contains("permission") || e.contains("brak uprawnie")
    }
}

struct WatchFlagged: Identifiable, Sendable, Equatable {
    var id: String { path }
    /// Same rule as the backend's `high_risk`: MALICIOUS, or SUSPICIOUS/PUA from 60 points up.
    var highRisk: Bool { verdict == .malicious || ((verdict == .suspicious || verdict == .pua) && (score ?? 0) >= 60) }
    var path: String
    var verdict: Verdict
    var primary: String?
    var score: Double?
    var quarantined: String?
    var quarantineError: String?

    init(_ j: JSONValue) {
        path = j["path"].text ?? ""
        verdict = Verdict(raw: j["verdict"].text)
        primary = j["primary"].text
        score = j["score"].double
        quarantined = j["quarantined"].text
        quarantineError = j["quarantine_error"].text
    }
}

/// `watch_net_status` – the network & remote-access guard (sent every ~30 s; `active: false` when it stops).
struct NetGuardStatus: Sendable, Equatable {
    var active: Bool
    var since: String?
    var polls: Int
    var intervalS: Double?
    var stats: NetMonitorStats
    var logChecked: String?
    var permissions: Bool
    var limitations: [String]
    var error: String?

    init(_ j: JSONValue) {
        active = j["active"].bool ?? true
        since = j["since"].text
        polls = j["polls"].int ?? 0
        intervalS = j["interval_s"].double
        stats = NetMonitorStats(j)
        logChecked = j["log_checked"].text
        permissions = j["permissions"].bool ?? false
        limitations = j["limitations"].stringArray
        error = j["error"].text
    }
}

struct WatchEvent: Sendable, Equatable {
    var ev: String
    var kind: String?
    var kindPL: String?
    var path: String?
    var name: String?
    var note: String?
    // ready
    var level: String?
    var quarantine: Bool?
    var net: Bool?
    var netReport: String?
    var spots: [WatchSpot] = []
    // network guard
    var netItem: NetEvent?
    var netStatus: NetGuardStatus?
    // worker
    var state: String?
    var patterns: Int?
    // sandbox
    var verified: [String] = []
    // result
    var verdict: Verdict?
    var files: Int?
    var scanned: Int?
    var seconds: Double?
    var flagged: [WatchFlagged] = []
    var report: String?
    var time: String?
    // notice / alert
    var title: String?
    var subtitle: String?
    var msg: String?
    var noticeLevel: String?

    init(ev: String, _ j: JSONValue) {
        self.ev = ev
        kind = j["kind"].text
        kindPL = j["kind_pl"].text
        path = j["path"].text
        name = j["name"].text
        note = j["note"].text
        level = j["level"].text
        quarantine = j["quarantine"].bool
        net = j["net"].bool
        netReport = j["net_report"].text
        spots = j["spots"].array.map(WatchSpot.init)
        if ev == "watch_net" { netItem = NetEvent(j["item"]) }
        if ev == "watch_net_status" { netStatus = NetGuardStatus(j) }
        state = j["state"].text?.lowercased()
        patterns = j["patterns"].int
        verified = j["verified"].stringArray
        verdict = j["verdict"].text.map { Verdict(raw: $0) }
        files = j["files"].int
        scanned = j["scanned"].int
        seconds = j["seconds"].double
        flagged = j["flagged"].array.map(WatchFlagged.init)
        report = j["report"].text
        time = j["time"].text
        title = j["title"].text
        subtitle = j["subtitle"].text
        msg = j["msg"].text
        noticeLevel = (ev == "watch_notice") ? j["level"].text?.lowercased() : nil
    }
}

/// One line of the "Aktywność" feed (merged by path: new → scanning → result).
struct ActivityItem: Identifiable, Sendable, Equatable {
    enum Phase: Equatable { case waiting, scanning, done }
    let id: UUID
    var kind: String
    var kindPL: String
    var path: String
    var name: String
    var note: String?
    var phase: Phase
    var verdict: Verdict?
    var files: Int?
    var seconds: Double?
    var flagged: [WatchFlagged] = []
    var report: String?
    var time: Date

    var quarantinedCount: Int { flagged.filter { $0.quarantined != nil }.count }
    /// High-risk finds still on disk – the row offers "Do kwarantanny" (auto-quarantine is off by default).
    var quarantinable: [WatchFlagged] { flagged.filter { $0.highRisk && $0.quarantined == nil } }
}

// MARK: - Controller

@Observable
final class BackgroundProtection {
    enum Status: Equatable {
        case off
        case starting
        case running
        case failed(String)
    }

    static let enabledKey = "backgroundProtectionEnabled"
    static let quarantineKey = "backgroundProtectionQuarantine"
    static let levelKey = "backgroundProtectionLevel"
    static let networkKey = "backgroundProtectionNetwork"
    static let maxActivity = 500
    static let maxNetEvents = 300

    /// The user's choices (UserDefaults). Nothing is ever switched on by the app itself.
    var enabled: Bool = UserDefaults.standard.bool(forKey: BackgroundProtection.enabledKey)
    /// Off unless the user turns it on: detections are reported, the user decides about quarantine.
    var autoQuarantine: Bool = UserDefaults.standard.object(forKey: BackgroundProtection.quarantineKey) as? Bool ?? false
    var level: ScanLevel = ScanLevel(rawValue: UserDefaults.standard.string(forKey: BackgroundProtection.levelKey) ?? "") == .deep ? .deep : .quick
    /// Off unless the user turns it on: network & remote-access guard (`--net`).
    var netGuard: Bool = UserDefaults.standard.bool(forKey: BackgroundProtection.networkKey)
    /// Mirrors SMAppService.mainApp.status (refreshed on demand).
    var loginItemEnabled = false
    var loginItemNote: String?

    var status: Status = .off
    var spots: [WatchSpot] = []
    var workerState: String = "stopped"
    var workerPatterns: Int?
    var verified: [String] = []
    var activity: [ActivityItem] = []
    /// Network guard: newest first (this session); the daily report keeps the whole day.
    var netEvents: [NetEvent] = []
    var netStatus: NetGuardStatus?
    var netReport: String?
    var lastAlert: WatchEvent?
    var stderrTail: [String] = []
    let config: BackendConfig
    /// Real notifications only in the running app (never in --snapshot / --selftest-parse).
    var notificationsEnabled = false

    @ObservationIgnored private var process: BackendProcess?
    @ObservationIgnored private var stopRequested = false
    @ObservationIgnored private var killWork: DispatchWorkItem?
    @ObservationIgnored private var pendingNotices: [DispatchWorkItem] = []

    init(config: BackendConfig) {
        self.config = config
    }

    var isRunning: Bool { status == .running || status == .starting }

    var lastResult: ActivityItem? { activity.first { $0.phase == .done } }

    var lastWasMalicious: Bool { lastResult?.verdict == .malicious }

    var recentResults: [ActivityItem] { Array(activity.filter { $0.phase == .done }.prefix(5)) }

    var statusLine: String {
        switch status {
        case .off: return "Ochrona w tle wyłączona"
        case .starting: return "Uruchamianie ochrony w tle…"
        case .failed(let m): return "Błąd ochrony w tle: \(m)"
        case .running:
            let ok = spots.filter(\.ok).count
            if let r = lastResult, let v = r.verdict {
                return "Chroni \(ok) \(Fmt.plural(ok, "miejsce", "miejsca", "miejsc")) · ostatnio: \(r.name) – \(v.badge.lowercased())"
            }
            return "Chroni \(ok) \(Fmt.plural(ok, "miejsce", "miejsca", "miejsc")) · nic nowego"
        }
    }

    var workerLabel: String {
        switch workerState {
        case "loading": return "ładowanie silnika"
        case "ready": return "gotowy"
        default: return "uśpiony"
        }
    }

    // MARK: settings

    func setEnabled(_ on: Bool) {
        enabled = on
        UserDefaults.standard.set(on, forKey: Self.enabledKey)
        if on {
            requestNotificationPermission()
            start()
        } else {
            stop()
        }
    }

    func setAutoQuarantine(_ on: Bool) {
        autoQuarantine = on
        UserDefaults.standard.set(on, forKey: Self.quarantineKey)
        if isRunning { restart() }
    }

    func setNetGuard(_ on: Bool) {
        netGuard = on
        UserDefaults.standard.set(on, forKey: Self.networkKey)
        if !on { netStatus = nil }
        if isRunning { restart() }
    }

    /// Alarms of the network guard in this session (low and up).
    var netAlerts: Int { netEvents.filter(\.isAlert).count }

    func setLevel(_ l: ScanLevel) {
        level = l
        UserDefaults.standard.set(l.rawValue, forKey: Self.levelKey)
        if isRunning { restart() }
    }

    func refreshLoginItem() {
        let s = SMAppService.mainApp.status
        loginItemEnabled = s == .enabled
        loginItemNote = s == .requiresApproval
            ? "Wymaga zatwierdzenia w Ustawieniach systemowych → Ogólne → Rzeczy otwierane podczas logowania." : nil
    }

    func setLoginItem(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            loginItemNote = "Nie udało się \(on ? "dodać" : "usunąć") Cerbera z rzeczy otwieranych przy logowaniu: \(error.localizedDescription)"
        }
        refreshLoginItem()
    }

    // MARK: process

    var arguments: [String] {
        ["watch", "run", "--app", "--level", level == .deep ? "deep" : "quick"] + (autoQuarantine ? ["--quarantine"] : [])
            + (netGuard ? ["--net"] : [])
    }

    private var launchCommand: (URL, [String]) {
        if config.mock {
            let (exe, args) = config.launchSpec(arguments)
            return (exe, args)
        }
        return (config.venvPython, ["-m", "cerber"] + arguments)
    }

    func startIfPreferred() {
        if enabled, process == nil { start() }
    }

    func restart() {
        guard let p = process else { start(); return }
        stopRequested = true
        p.onExit = { [weak self] _ in
            self?.process = nil
            self?.start()
        }
        stopProcess(p)
    }

    func start() {
        guard process == nil else { return }
        stopRequested = false
        stderrTail = []
        status = .starting
        let (exe, args) = launchCommand
        let p = BackendProcess(config: config, executable: exe, arguments: args)
        p.keepStdinOpen = true
        p.onEvents = { [weak self] events in
            guard let self else { return }
            for e in events { if case .watch(let w) = e { self.apply(w) } }
        }
        p.onStderr = { [weak self] lines in
            guard let self else { return }
            self.stderrTail.append(contentsOf: lines)
            if self.stderrTail.count > 40 { self.stderrTail.removeFirst(self.stderrTail.count - 40) }
        }
        p.onExit = { [weak self] code in
            guard let self else { return }
            self.process = nil
            self.killWork?.cancel()
            self.workerState = "stopped"
            self.netStatus?.active = false
            if self.stopRequested {
                self.status = .off
            } else {
                let tail = self.stderrTail.suffix(3).joined(separator: "\n")
                self.status = .failed("proces zakończył się (kod \(code))" + (tail.isEmpty ? "" : "\n" + tail))
            }
        }
        do {
            try p.start()
            process = p
        } catch {
            status = .failed(error.localizedDescription)
        }
    }

    func stop() {
        guard let p = process else {
            status = .off
            return
        }
        stopRequested = true
        stopProcess(p)
    }

    /// SIGINT (and close stdin), SIGTERM after 5 s.
    private func stopProcess(_ p: BackendProcess) {
        p.interrupt()
        p.closeStdin()
        let work = DispatchWorkItem { [weak p] in
            if let p, p.isRunning { p.terminate() }
        }
        killWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 5, execute: work)
    }

    /// App quit: blocking stop.
    func shutdown() {
        guard let p = process, p.isRunning else { return }
        stopRequested = true
        p.interrupt()
        p.closeStdin()
        let deadline = Date().addingTimeInterval(5)
        while p.isRunning && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
        p.terminate()
    }

    // MARK: events

    func apply(_ w: WatchEvent) {
        switch w.ev {
        case "watch_ready":
            status = .running
            spots = w.spots
            if let r = w.netReport { netReport = r }
        case "watch_net":
            if let e = w.netItem {
                var e = e
                if netEvents.contains(where: { $0.id == e.id }) { e.id += "#\(netEvents.count)" }
                netEvents.insert(e, at: 0)
                if netEvents.count > Self.maxNetEvents { netEvents.removeLast(netEvents.count - Self.maxNetEvents) }
            }
            if let r = w.report { netReport = r }
        case "watch_net_status":
            netStatus = w.netStatus
            if let r = w.report { netReport = r }
        case "watch_worker":
            workerState = w.state ?? workerState
            if let p = w.patterns { workerPatterns = p }
        case "watch_sandbox":
            verified = w.verified
        case "watch_new":
            upsert(w, phase: .waiting)
        case "watch_scanning":
            upsert(w, phase: .scanning)
        case "watch_result":
            upsert(w, phase: .done)
            pendingNotices.forEach { $0.cancel() }      // a quick result makes "Sprawdzam…" pointless
            pendingNotices.removeAll()
        case "watch_notice":
            notify(notice: w)
        case "watch_alert":
            lastAlert = w
            notify(alert: w)
        default:
            break
        }
    }

    private func upsert(_ w: WatchEvent, phase: ActivityItem.Phase) {
        let path = w.path ?? w.name ?? ""
        if let i = activity.firstIndex(where: { $0.path == path && $0.phase != .done }) {
            var item = activity.remove(at: i)
            item.phase = phase
            item.note = w.note ?? item.note
            if phase == .done { fill(&item, w) }
            activity.insert(item, at: 0)
        } else {
            var item = ActivityItem(id: UUID(), kind: w.kind ?? "", kindPL: w.kindPL ?? w.kind ?? "", path: path,
                                    name: w.name ?? (path as NSString).lastPathComponent, note: w.note, phase: phase,
                                    time: Fmt.parseDate(w.time) ?? Date())
            if phase == .done { fill(&item, w) }
            activity.insert(item, at: 0)
        }
        if activity.count > Self.maxActivity { activity.removeLast(activity.count - Self.maxActivity) }
    }

    /// Paths being moved right now (spinner on the button).
    var quarantining: Set<String> = []

    /// The user's click on "Do kwarantanny" in the activity feed: same backend command as in scan results.
    func quarantine(itemID: UUID, path: String) {
        guard !quarantining.contains(path) else { return }
        quarantining.insert(path)
        Task { @MainActor in
            let r = await BackendProcess.run(config: config, arguments: ["quarantine", path])
            self.quarantining.remove(path)
            var qid: String?
            for e in r.events { if case .quarantined(_, let id) = e { qid = id } }
            guard let i = self.activity.firstIndex(where: { $0.id == itemID }),
                  let j = self.activity[i].flagged.firstIndex(where: { $0.path == path }) else { return }
            if let qid { self.activity[i].flagged[j].quarantined = qid }
            else { self.activity[i].flagged[j].quarantineError = r.failureDescription }
        }
    }

    private func fill(_ item: inout ActivityItem, _ w: WatchEvent) {
        item.verdict = w.verdict ?? .clean
        item.files = w.files ?? w.scanned
        item.seconds = w.seconds
        item.flagged = w.flagged
        item.report = w.report
        item.time = Fmt.parseDate(w.time) ?? Date()
    }

    // MARK: notifications

    static var notificationsSupported: Bool { Bundle.main.bundleIdentifier != nil }

    func requestNotificationPermission() {
        guard notificationsEnabled, Self.notificationsSupported else { return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }

    private func notify(notice w: WatchEvent) {
        guard notificationsEnabled, Self.notificationsSupported else { return }
        let content = UNMutableNotificationContent()
        content.title = w.title ?? "Cerber"
        if let s = w.subtitle { content.subtitle = s }
        content.body = w.msg ?? ""
        if w.noticeLevel == "error" { content.sound = .default }
        let isProgress = (w.noticeLevel ?? "info") == "info"
            && ((w.title ?? "") + (w.subtitle ?? "") + (w.msg ?? "")).lowercased().contains("sprawdzam")
        if isProgress {
            // Deliver only if the result does not arrive within 3 s.
            let work = DispatchWorkItem { Self.post(content) }
            pendingNotices.append(work)
            DispatchQueue.main.asyncAfter(deadline: .now() + 3, execute: work)
        } else {
            Self.post(content)
        }
    }

    private func notify(alert w: WatchEvent) {
        guard notificationsEnabled, Self.notificationsSupported else { return }
        let content = UNMutableNotificationContent()
        content.title = w.title ?? "Cerber: wykryto zagrożenie"
        content.body = w.msg ?? ""
        content.sound = .default
        content.categoryIdentifier = NotificationRouter.alertCategory
        if let r = w.report { content.userInfo = ["report": r] }
        if #available(macOS 12.0, *) { content.interruptionLevel = .timeSensitive }
        Self.post(content)
    }

    private static func post(_ content: UNMutableNotificationContent) {
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req) { _ in }
    }
}

/// Handles the "Pokaż raport" action of malware alerts.
final class NotificationRouter: NSObject, UNUserNotificationCenterDelegate {
    static let alertCategory = "CERBER_ALERT"
    static let showReportAction = "SHOW_REPORT"
    static let shared = NotificationRouter()

    func install() {
        guard BackgroundProtection.notificationsSupported else { return }
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let show = UNNotificationAction(identifier: Self.showReportAction, title: "Pokaż raport", options: [.foreground])
        center.setNotificationCategories([UNNotificationCategory(identifier: Self.alertCategory, actions: [show],
                                                                 intentIdentifiers: [], options: [])])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        if let report = response.notification.request.content.userInfo["report"] as? String {
            DispatchQueue.main.async { ReportViewer.open(report) }
        } else {
            DispatchQueue.main.async { NSApp.activate(ignoringOtherApps: true) }
        }
        completionHandler()
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound, .list])
    }
}

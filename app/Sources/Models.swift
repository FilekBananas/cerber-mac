import Foundation

// MARK: - Enums

enum Verdict: String, CaseIterable, Comparable, Sendable {
    case clean = "CLEAN"
    case info = "INFO"
    case suspicious = "SUSPICIOUS"
    case pua = "PUA"
    case malicious = "MALICIOUS"

    init(raw: String?) {
        guard let raw, !raw.isEmpty else { self = .clean; return }
        self = Verdict(rawValue: raw.uppercased()) ?? .info
    }

    var rank: Int {
        switch self {
        case .clean: return 0
        case .info: return 1
        case .suspicious: return 2
        case .pua: return 3
        case .malicious: return 4
        }
    }

    static func < (a: Verdict, b: Verdict) -> Bool { a.rank < b.rank }

    /// Flagged verdicts, worst first.
    static let flagged: [Verdict] = [.malicious, .pua, .suspicious, .info]
}

enum ScanLevel: String, CaseIterable, Identifiable, Sendable {
    case quick, patterns, deep, mega
    var id: String { rawValue }

    init(raw: String?) { self = ScanLevel(rawValue: (raw ?? "").lowercased()) ?? .deep }
}

enum ScanMode: String, Sendable {
    case scan, sandbox, github, huggingface, url, laptop

    init(raw: String?) { self = ScanMode(rawValue: (raw ?? "").lowercased()) ?? .scan }
}

enum Severity: String, CaseIterable, Sendable {
    case malicious, pua, suspicious, low, info

    init(raw: String?) { self = Severity(rawValue: (raw ?? "").lowercased()) ?? .info }

    var rank: Int {
        switch self {
        case .malicious: return 4
        case .pua: return 3
        case .suspicious: return 2
        case .low: return 1
        case .info: return 0
        }
    }

    var verdict: Verdict {
        switch self {
        case .malicious: return .malicious
        case .pua: return .pua
        case .suspicious: return .suspicious
        case .low, .info: return .info
        }
    }
}

// MARK: - Database info

struct DBInfo: Sendable, Equatable {
    var patternsTotal: Int?
    var clamavSignatures: Int?
    var yaraRules: Int?
    var fileHashes: Int?
    var sectionHashes: Int?
    var iocIndicators: Int?
    var dbBuilt: String?
    var aiModel: String?
    var missing: [String]
    /// The backend can download the model itself (`ai-install`).
    var aiInstallable: Bool
    var aiModelSize: Int?
    var aiDownloadPartial: Int?
    /// nil = the backend did not say (older backend).
    var llamaServer: Bool?
    /// An older model is installed; the recommended one (`ai_model_recommended`) can be downloaded on request.
    var aiUpgradeAvailable: Bool
    var aiModelRecommended: String?

    init(_ j: JSONValue) {
        patternsTotal = j["patterns_total"].int
        clamavSignatures = j["clamav_signatures"].int
        yaraRules = j["yara_rules"].int
        fileHashes = j["file_hashes"].int
        sectionHashes = j["section_hashes"].int
        iocIndicators = j["ioc_indicators"].int
        dbBuilt = j["db_built"].text
        aiModel = j["ai_model"].text
        missing = j["missing"].stringArray
        aiInstallable = j["ai_installable"].bool ?? false
        aiModelSize = j["ai_model_size"].int
        aiDownloadPartial = j["ai_download_partial"].int
        llamaServer = j["llama_server"].bool
        aiUpgradeAvailable = j["ai_upgrade_available"].bool ?? false
        aiModelRecommended = j["ai_model_recommended"].text
    }
}

// MARK: - Results

struct Detection: Identifiable, Sendable, Equatable {
    let id: Int
    var name: String
    var engine: String
    var confidence: String
    var score: Double?
    var description: String?
    var object: String?
    var pua: Bool

    init(_ j: JSONValue, index: Int) {
        id = index
        name = j["name"].text ?? "—"
        engine = (j["engine"].text ?? "").lowercased()
        confidence = (j["confidence"].text ?? "").uppercased()
        score = j["score"].double
        description = j["description"].text
        object = j["object"].text
        pua = j["pua"].bool ?? false
    }
}

/// One engine finding ("accusation") as judged by the AI verifier.
struct AIAccusation: Identifiable, Sendable, Equatable {
    enum Assessment: String, Sendable { case confirmed, refuted, unsure }
    let id: String
    var name: String
    var assessment: Assessment
    var confidence: Double?
    var reason: String?
    var quote: String?
    /// Points the AI added (+) or took away (−) for this accusation.
    var points: Int
    var agree: Bool
    var grounded: Bool

    init(_ j: JSONValue, index: Int) {
        id = (j["id"].text ?? "A") + "#\(index)"
        name = j["name"].text ?? "—"
        assessment = Assessment(rawValue: (j["verdict"].text ?? "").lowercased()) ?? .unsure
        confidence = j["confidence"].double
        reason = j["reason_pl"].text
        quote = j["quote"].text.flatMap { $0.isEmpty ? nil : $0 }
        points = Int(j["points"].double ?? 0)
        agree = j["agree"].bool ?? true
        grounded = j["grounded"].bool ?? true
    }

    var label: String {
        switch assessment {
        case .confirmed: return "trafny"
        case .refuted: return "chybiony"
        case .unsure: return "niepewne"
        }
    }
}

/// The AI verifier's answer: each accusation confirmed / refuted / unsure, plus whether the file is the
/// suspected family (same / similar / different / benign). It moves the score by at most ±`cap` points and
/// never decides on its own. Older reports (family classifier) have no accusations.
struct AIReview: Sendable, Equatable {
    var verdict: Verdict?
    var confidence: Double?
    var summary: String?
    var choice: String?
    var family: String?
    var familyMatch: String?
    var agree: Bool?
    var options: [String]
    var accusations: [AIAccusation]
    var points: Int?
    var pointsRaw: Int?
    var cap: Int
    var model: String?

    init?(_ j: JSONValue) {
        guard j.object != nil else { return nil }
        verdict = j["verdict"].text.map { Verdict(raw: $0) }
        confidence = j["confidence"].double
        summary = j["summary_pl"].text ?? j["summary"].text
        choice = j["choice"].text
        family = j["family"].text
        familyMatch = j["family_match"].text
        agree = j["agree"].bool
        options = j["options"].array.compactMap { $0["name"].text }
        accusations = j["accusations"].array.enumerated().map { AIAccusation($1, index: $0) }
        points = j["points"].double.map { Int($0) }
        pointsRaw = j["points_raw"].double.map { Int($0) }
        cap = Int(j["cap"].double ?? 15)
        model = j["model"].text
    }

    /// Small print under the AI panel: what it chose from (old reports), disagreement, cap.
    var footnote: String {
        var parts: [String] = []
        if accusations.isEmpty && !options.isEmpty {
            parts.append("Wybierało spośród: \(options.joined(separator: ", ")).")
        }
        if agree == false { parts.append("Dwie odpowiedzi modelu się różniły – pewność obniżona.") }
        if let raw = pointsRaw, let p = points, raw != p {
            parts.append("Łącznie \(raw) pkt, ograniczone do \(p).")
        }
        parts.append("AI nie decyduje: zmienia wynik najwyżej o \(cap) punktów i nigdy nie podważa sygnatur.")
        return parts.joined(separator: " ")
    }

    /// "to ta rodzina Atomic macOS Stealer (AMOS)" / "wygląda na legalne oprogramowanie" / …
    var familyText: String? {
        switch familyMatch {
        case "same": return family.map { "To rodzina \($0)" } ?? "Szkodliwe, nieznana rodzina"
        case "similar": return family.map { "Podobne do rodziny \($0)" } ?? "Szkodliwe, nieznana rodzina"
        case "different": return "Szkodliwe, ale żadna z podejrzewanych rodzin"
        case "benign": return "Wygląda na legalne oprogramowanie"
        default:
            if let family { return "Rodzina: \(family)" }
            if choice == "benign" { return "Wygląda na legalne oprogramowanie" }
            if choice == "other" { return "Szkodliwe, ale żadna ze znanych rodzin" }
            return nil
        }
    }
}

// MARK: - Detonation ("Analiza zachowania")

/// One behaviour the script showed in the sealed sandbox.
struct DetonationBehavior: Identifiable, Sendable, Equatable {
    enum Level: Int, Sendable, Comparable {
        case info, low, medium, high, critical
        static func < (a: Level, b: Level) -> Bool { a.rawValue < b.rawValue }
    }

    let id: String
    var title: String
    var detail: String?
    var score: Double?
    /// Backend scale: critical / high / medium / low / info (verdict words are accepted too).
    var level: Level
    var evidence: [String]

    init(_ j: JSONValue, index: Int) {
        id = (j["id"].text ?? "b") + "#\(index)"
        title = j["title"].text ?? "—"
        detail = j["detail"].text
        score = j["score"].double
        switch (j["severity"].text ?? "").lowercased() {
        case "critical", "malicious": level = .critical
        case "high", "suspicious", "pua": level = .high
        case "medium": level = .medium
        case "low": level = .low
        default: level = .info
        }
        evidence = j["evidence"].stringArray
    }
}

/// An address the script tried to reach (blocked – the sandbox has no network).
struct DetonationTarget: Identifiable, Sendable, Equatable {
    let id: Int
    var target: String
    var kind: String?
    var url: String?
    var port: Int?
    var ioc: String?

    init(_ j: JSONValue, index: Int) {
        id = index
        target = j["target"].text ?? "?"
        kind = j["kind"].text?.lowercased()
        url = j["url"].text
        port = j["port"].int
        ioc = j["ioc"].text
    }

    /// The URL when known, otherwise "host:port".
    var display: String { url ?? (target + (port.map { ":\($0)" } ?? "")) }
}

/// A hidden stage decoded while the script ran (e.g. a base64 payload), re-scanned statically.
struct DetonationStage: Identifiable, Sendable, Equatable {
    let id: Int
    var sourcePreview: String?
    var detections: [String]

    init(_ j: JSONValue, index: Int) {
        id = index
        sourcePreview = j["source_preview"].string.flatMap { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0 }
        detections = j["detections"].stringArray
    }
}

/// `result.detonation`: what a suspicious script tried to do when run for a few seconds in a sealed sandbox
/// (no network, a fake home folder with bait files). Null when the script was not run.
struct Detonation: Sendable, Equatable {
    var ran: Bool
    var kind: String?
    var seconds: Double?
    var timedOut: Bool
    var verdict: Verdict?
    var score: Double?
    var behaviors: [DetonationBehavior]
    var commands: [String]
    var network: [DetonationTarget]
    var filesRead: [String]
    var filesWritten: [String]
    var stages: [DetonationStage]
    var limitations: [String]

    init?(_ j: JSONValue) {
        guard j.object != nil else { return nil }
        ran = j["ran"].bool ?? true
        kind = j["kind"].text
        seconds = j["seconds"].double
        timedOut = j["timed_out"].bool ?? false
        verdict = j["verdict"].text.map { Verdict(raw: $0) }
        score = j["score"].double
        behaviors = j["behaviors"].array.enumerated().map { DetonationBehavior($0.element, index: $0.offset) }
            .sorted { ($0.level, $0.score ?? 0) > ($1.level, $1.score ?? 0) }
        commands = j["commands"].stringArray
        var seen = Set<String>()
        network = j["network"].array.enumerated().map { DetonationTarget($0.element, index: $0.offset) }
            .filter { seen.insert($0.display).inserted }
        filesRead = j["files_read"].stringArray
        // device nodes (/dev/tty, /dev/null) are not attempts to change anything
        filesWritten = j["files_written"].stringArray.filter { !$0.hasPrefix("/dev/") }
        stages = j["stages"].array.enumerated().map { DetonationStage($0.element, index: $0.offset) }
            .filter { $0.sourcePreview != nil || !$0.detections.isEmpty }
        limitations = j["limitations"].stringArray
    }
}

struct ScanResult: Identifiable, Sendable, Equatable {
    var id: String
    var path: String
    var displayPath: String
    var verdict: Verdict
    var score: Double?
    var primary: String?
    var size: Int?
    var ftype: String?
    var sha256: String?
    var worstObject: String?
    var canQuarantine: Bool
    /// Why there is no quarantine button (low risk, sandbox copy, file gone …).
    var quarantineNote: String?
    var quarantined: String?
    var ai: AIReview?
    var detections: [Detection]
    /// Set when the script was run in the sealed behaviour sandbox.
    var detonation: Detonation?

    init(_ j: JSONValue) {
        path = j["path"].text ?? ""
        displayPath = j["display_path"].text ?? path
        verdict = Verdict(raw: j["verdict"].text)
        score = j["score"].double
        primary = j["primary"].text
        size = j["size"].int
        ftype = j["ftype"].text
        sha256 = j["sha256"].text
        worstObject = j["worst_object"].text
        canQuarantine = j["can_quarantine"].bool ?? false
        quarantineNote = j["quarantine_note"].text
        quarantined = j["quarantined"].text
        ai = AIReview(j["ai"])
        detections = j["detections"].array.enumerated().map { Detection($0.element, index: $0.offset) }
        detonation = Detonation(j["detonation"])
        id = path + "|" + (worstObject ?? "")
    }

    var fileName: String {
        let name = (displayPath as NSString).lastPathComponent
        return name.isEmpty ? displayPath : name
    }

    var folder: String {
        let dir = (displayPath as NSString).deletingLastPathComponent
        return dir
    }
}

// MARK: - Sandbox / repo

struct TreeEntry: Sendable, Equatable {
    var path: String
    var size: Int?
    var verdict: Verdict

    init(_ j: JSONValue) {
        path = j["path"].text ?? ""
        size = j["size"].int
        verdict = Verdict(raw: j["verdict"].text)
    }
}

/// Mega: risky files kept only in iCloud (or another cloud drive) that were downloaded, scanned and given back.
struct CloudFetchInfo: Sendable, Equatable {
    var candidates: Int
    var fetched: Int
    var bytes: Int
    var evicted: Int
    var kept: Int
    var notFetched: Int
    var stalled: Bool

    init?(_ j: JSONValue) {
        guard j.object != nil else { return nil }
        candidates = j["candidates"].int ?? 0
        fetched = j["fetched"].int ?? 0
        bytes = j["bytes"].int ?? 0
        evicted = j["evicted"].int ?? 0
        kept = j["kept"].int ?? 0
        notFetched = (j["over_limit"].int ?? 0) + (j["too_big"].int ?? 0) + (j["failed"].int ?? 0)
        stalled = j["stalled"].bool ?? false
    }
}

struct SandboxInfo: Sendable, Equatable {
    var extractedFiles: Int?
    var extractedBytes: Int?
    var depth: Int?
    var tree: [TreeEntry]
    var limitsHit: [String]
    var isolation: [String]
    /// Self-checks the sandbox performed against itself before the scan (e.g. "zapis poza sandboksem zablokowany").
    var verified: [String]
    /// "readonly" for `scan` / `laptop` (files are scanned in place inside a read-only sandbox).
    var mode: String?

    /// True when the sandbox unpacked something (archive, repository) – otherwise only the isolation list.
    var hasExtraction: Bool { extractedFiles != nil || extractedBytes != nil || !tree.isEmpty }

    init?(_ j: JSONValue) {
        guard j.object != nil else { return nil }
        mode = j["mode"].text?.lowercased()
        extractedFiles = j["extracted_files"].int
        extractedBytes = j["extracted_bytes"].int
        depth = j["depth"].int
        tree = j["tree"].array.map(TreeEntry.init)
        limitsHit = j["limits_hit"].stringArray
        isolation = j["isolation"].stringArray
        verified = j["verified"].stringArray
    }
}

struct SkippedFile: Identifiable, Sendable, Equatable {
    let id: Int
    var path: String
    var size: Int?
    var reason: String

    init(_ j: JSONValue, index: Int) {
        id = index
        path = j["path"].text ?? "—"
        size = j["size"].int
        reason = j["reason"].text ?? ""
    }
}

struct RepoInfo: Sendable, Equatable {
    var source: String
    var owner: String?
    var name: String?
    var kind: String
    var ref: String?
    var url: String?
    var description: String?
    var stars: Int?
    var archiveBytes: Int?
    var filesTotal: Int?
    var filesDownloaded: Int?
    var skipped: [SkippedFile]

    init?(_ j: JSONValue) {
        guard j.object != nil else { return nil }
        source = (j["source"].text ?? "github").lowercased()
        owner = j["owner"].text
        name = j["name"].text
        kind = (j["kind"].text ?? "repo").lowercased()
        ref = j["ref"].text
        url = j["url"].text
        description = j["description"].text
        stars = j["stars"].int
        archiveBytes = j["archive_bytes"].int
        filesTotal = j["files_total"].int
        filesDownloaded = j["files_downloaded"].int
        skipped = j["skipped"].array.enumerated().map { SkippedFile($0.element, index: $0.offset) }
    }

    var fullName: String {
        [owner, name].compactMap { $0 }.joined(separator: "/")
    }
}

// MARK: - Environment

struct EnvFinding: Identifiable, Sendable, Equatable {
    let id: Int
    var category: String
    var title: String
    var location: String?
    var severity: Severity
    var score: Double?
    var description: String?
    var evidence: [String]

    init(_ j: JSONValue, index: Int) {
        id = index
        category = (j["category"].text ?? "").lowercased()
        title = j["title"].text ?? "—"
        location = j["location"].text
        severity = Severity(raw: j["severity"].text)
        score = j["score"].double
        description = j["description"].text
        evidence = j["evidence"].stringArray
    }
}

struct Posture: Sendable, Equatable {
    var sip: Bool?
    var gatekeeper: Bool?
    var filevault: Bool?
    var firewall: String?
    var xprotect: String?
    var raw: [String: JSONValue]

    init(_ j: JSONValue) {
        raw = j.object ?? [:]
        sip = j["sip"].bool
        gatekeeper = j["gatekeeper"].bool
        filevault = j["filevault"].bool
        if case .bool(let b) = j["firewall"] {
            firewall = b ? "on" : "off"
        } else {
            firewall = j["firewall"].text?.lowercased()
        }
        xprotect = j["xprotect_version"].text ?? j["xprotect"].text
    }
}

struct EnvironmentInfo: Sendable, Equatable {
    var findings: [EnvFinding]
    var posture: Posture
    var limitations: [String]

    init?(_ j: JSONValue) {
        guard j.object != nil else { return nil }
        findings = j["findings"].array.enumerated().map { EnvFinding($0.element, index: $0.offset) }
        posture = Posture(j["posture"])
        limitations = j["limitations"].stringArray
    }

    var worstSeverity: Severity? {
        findings.map(\.severity).max { $0.rank < $1.rank }
    }
}

// MARK: - Network

struct NetSummary: Sendable, Equatable {
    var listeningAll: Int?
    var publicConnections: Int?
    var processesOnline: Int?
    var remoteTools: Int?
    var iocHits: Int?
    var uploadedBytes: Int?

    init(_ j: JSONValue) {
        listeningAll = j["listening_all_interfaces"].int
        publicConnections = j["public_connections"].int
        processesOnline = j["processes_online"].int
        remoteTools = j["remote_tools"].int
        iocHits = j["ioc_hits"].int
        uploadedBytes = j["uploaded_bytes_since_boot"].int
    }
}

struct Listener: Identifiable, Sendable, Equatable {
    let id: Int
    var proto: String
    var address: String
    var port: Int?
    var exposure: String
    var process: String
    var pid: Int?
    var exe: String?
    var signer: String?
    var service: String?

    init(_ j: JSONValue, index: Int) {
        id = index
        proto = j["proto"].text ?? ""
        address = j["address"].text ?? "*"
        port = j["port"].int
        exposure = (j["exposure"].text ?? "specific").lowercased()
        process = j["process"].text ?? "?"
        pid = j["pid"].int
        exe = j["exe"].text
        signer = j["signer"].text
        service = j["service"].text
    }
}

struct Connection: Identifiable, Sendable, Equatable {
    let id: Int
    var process: String
    var pid: Int?
    var exe: String?
    var remote: String
    var port: Int?
    var host: String?
    var state: String?
    var isPublic: Bool
    var ioc: String?

    init(_ j: JSONValue, index: Int) {
        id = index
        process = j["process"].text ?? "?"
        pid = j["pid"].int
        exe = j["exe"].text
        remote = j["remote"].text ?? "?"
        port = j["port"].int
        host = j["host"].text
        state = j["state"].text
        isPublic = j["public"].bool ?? false
        ioc = j["ioc"].text
    }
}

struct TrafficItem: Identifiable, Sendable, Equatable {
    let id: Int
    var process: String
    var pid: Int?
    var exe: String?
    var bytesOut: Int
    var bytesIn: Int
    var signer: String?
    var firstSeen: String?
    var lastSeen: String?

    init(_ j: JSONValue, index: Int) {
        id = index
        process = j["process"].text ?? "?"
        pid = j["pid"].int
        exe = j["exe"].text
        bytesOut = j["bytes_out"].int ?? 0
        bytesIn = j["bytes_in"].int ?? 0
        signer = j["signer"].text
        firstSeen = j["first_seen"].text
        lastSeen = j["last_seen"].text
    }
}

struct TrafficHistory: Sendable, Equatable {
    var available: Bool
    var reason: String?
    var items: [TrafficItem]

    init?(_ j: JSONValue) {
        guard j.object != nil else { return nil }
        items = j["items"].array.enumerated().map { TrafficItem($0.element, index: $0.offset) }
        available = j["available"].bool ?? !items.isEmpty
        reason = j["reason"].text
    }
}

struct RemoteAccessItem: Identifiable, Sendable, Equatable {
    let id: Int
    var name: String
    var kind: String
    var status: String
    var detail: String?
    var risk: String

    init(_ j: JSONValue, index: Int) {
        id = index
        name = j["name"].text ?? "—"
        kind = (j["kind"].text ?? "").lowercased()
        status = (j["status"].text ?? "").lowercased()
        detail = j["detail"].text
        risk = (j["risk"].text ?? "info").lowercased()
    }

    var riskRank: Int {
        switch risk {
        case "malicious": return 3
        case "suspicious": return 2
        case "low": return 1
        default: return 0
        }
    }
}

struct SessionItem: Identifiable, Sendable, Equatable {
    let id: Int
    var user: String
    var tty: String
    var from: String?
    var since: String?

    init(_ j: JSONValue, index: Int) {
        id = index
        user = j["user"].text ?? "?"
        tty = j["tty"].text ?? ""
        from = j["from"].text
        since = j["since"].text
    }
}

struct LoginItem: Identifiable, Sendable, Equatable {
    let id: Int
    var user: String
    var tty: String
    var from: String?
    var when: String?
    var remote: Bool

    init(_ j: JSONValue, index: Int) {
        id = index
        user = j["user"].text ?? "?"
        tty = j["tty"].text ?? ""
        from = j["from"].text
        when = j["when"].text
        remote = j["remote"].bool ?? (from != nil)
    }
}

struct NetworkInfo: Sendable, Equatable {
    var bootTime: String?
    var summary: NetSummary
    var listening: [Listener]
    var connections: [Connection]
    var traffic: [TrafficItem]
    var trafficHistory: TrafficHistory?
    var remoteAccess: [RemoteAccessItem]
    var sessions: [SessionItem]
    var logins: [LoginItem]
    /// Mega: what the live monitor saw during the rest of the scan (absent in older reports).
    var monitor: NetMonitor?
    /// Mega start audit, deep part (each absent in older reports): system log history, local network, trusted certificates.
    var syslog: SyslogInfo?
    var lan: LanInfo?
    /// nil = not checked (older report); empty = no manually trusted certificates.
    var certificates: [TrustedCert]?
    /// False when the start audit failed and `network` carries only `monitor`.
    var hasAudit: Bool

    init?(_ j: JSONValue) {
        guard j.object != nil else { return nil }
        bootTime = j["boot_time"].text
        summary = NetSummary(j["summary"])
        listening = j["listening"].array.enumerated().map { Listener($0.element, index: $0.offset) }
        connections = j["connections"].array.enumerated().map { Connection($0.element, index: $0.offset) }
        traffic = j["traffic"].array.enumerated().map { TrafficItem($0.element, index: $0.offset) }
        trafficHistory = TrafficHistory(j["traffic_history"])
        remoteAccess = j["remote_access"].array.enumerated().map { RemoteAccessItem($0.element, index: $0.offset) }
        sessions = j["sessions"].array.enumerated().map { SessionItem($0.element, index: $0.offset) }
        logins = j["logins"].array.enumerated().map { LoginItem($0.element, index: $0.offset) }
        monitor = NetMonitor(j["monitor"])
        syslog = SyslogInfo(j["syslog"])
        lan = LanInfo(j["lan"])
        if case .array(let certs) = j["certificates"] {
            certificates = certs.enumerated().map { TrustedCert($0.element, index: $0.offset) }
        }
        hasAudit = ["summary", "listening", "connections", "traffic", "remote_access", "sessions", "logins",
                    "syslog", "lan", "certificates"].contains { !j[$0].isNull }
    }

    var iocConnections: [Connection] { connections.filter { $0.ioc != nil } }
}

// MARK: - System log history, local network, trusted certificates (Mega start audit)

struct SyslogEvent: Identifiable, Sendable, Equatable {
    let id: Int
    var time: String?
    var category: String
    var title: String
    var detail: String?
    var severity: Severity
    var process: String?

    init(_ j: JSONValue, index: Int) {
        id = index
        time = j["time"].text
        category = (j["category"].text ?? "").lowercased()
        title = j["title"].text ?? "—"
        detail = j["detail"].text
        severity = Severity(raw: j["severity"].text)
        process = j["process"].text
    }
}

/// `network.syslog`: what macOS logged about XProtect, Gatekeeper, logins and background items.
struct SyslogInfo: Sendable, Equatable {
    var available: Bool
    var reason: String?
    var from: String?
    var to: String?
    var securityDays: Double?
    var privacyDays: Double?
    /// Oldest detailed ("persist") log file – the real reach of the history.
    var persistSince: String?
    var specialSince: String?
    var counts: [String: Int]
    /// Worst first (as sent).
    var events: [SyslogEvent]

    init?(_ j: JSONValue) {
        guard j.object != nil else { return nil }
        events = j["events"].array.enumerated().map { SyslogEvent($0.element, index: $0.offset) }
        available = j["available"].bool ?? !events.isEmpty
        reason = j["reason"].text
        let w = j["window"]
        from = w["from"].text
        to = w["to"].text
        securityDays = w["days"]["security"].double
        privacyDays = w["days"]["privacy"].double
        persistSince = w["persist_since"].text
        specialSince = w["special_since"].text
        var c: [String: Int] = [:]
        for (k, v) in j["counts"].object ?? [:] { if let n = v.int { c[k] = n } }
        counts = c
    }

    func count(_ key: String) -> Int? { counts[key] }

    /// True when the detailed log does not reach back to the start of the query window.
    var historyShorter: Bool {
        guard let p = persistSince, let f = from else { return false }
        return p > f
    }
}

struct ArpItem: Identifiable, Sendable, Equatable {
    let id: Int
    var mac: String
    var ips: [String]
    var reason: String?
    var interface: String?

    init(_ j: JSONValue, index: Int) {
        id = index
        mac = j["mac"].text ?? "?"
        ips = j["ips"].stringArray
        reason = j["reason"].text
        interface = j["interface"].text
    }
}

/// `network.lan`: gateway, Wi‑Fi security, DHCP and ARP/IPv6 neighbours.
struct LanInfo: Sendable, Equatable {
    var gatewayIP: String?
    var gatewayMAC: String?
    var gatewayInterface: String?
    var macRandomized: Bool?
    var wifiConnected: Bool
    var wifiInterface: String?
    var wifiSecurity: String?
    /// open | wep | wpa | wpa2 | wpa3 | enterprise | owe | unknown
    var securityLevel: String
    var securityLabel: String?
    var ssid: String?
    var dhcpServer: String?
    var router: String?
    var dns: [String]
    var domain: String?
    var routerARPVerified: Bool?
    var arpEntries: Int?
    var arpSuspicious: [ArpItem]
    var arpMultiIP: [ArpItem]
    var ipv6Routers: Int

    init?(_ j: JSONValue) {
        guard j.object != nil else { return nil }
        let g = j["gateway"], w = j["wifi"], d = j["dhcp"]
        gatewayIP = g["ip"].text
        gatewayMAC = g["mac"].text
        gatewayInterface = g["interface"].text
        macRandomized = g["mac_randomized"].bool
        wifiConnected = w["connected"].bool ?? false
        wifiInterface = w["interface"].text
        wifiSecurity = w["security"].text
        securityLevel = (w["security_level"].text ?? "unknown").lowercased()
        securityLabel = w["security_label"].text
        ssid = w["ssid"].text
        dhcpServer = d["dhcp_server"].text
        router = d["router"].text
        if case .array = d["dns"] { dns = d["dns"].stringArray } else { dns = d["dns"].text.map { [$0] } ?? [] }
        domain = d["domain"].text
        routerARPVerified = d["router_arp_verified"].bool
        arpEntries = j["arp_entries"].int
        arpSuspicious = j["arp_suspicious"].array.enumerated().map { ArpItem($0.element, index: $0.offset) }
        arpMultiIP = j["arp_multi_ip"].array.enumerated().map { ArpItem($0.element, index: $0.offset) }
        ipv6Routers = j["ipv6_routers"].array.count
    }
}

/// A certificate someone marked as trusted by hand (user or admin trust settings).
struct TrustedCert: Identifiable, Sendable, Equatable {
    let id: Int
    var name: String
    var domain: String?
    var trust: String?
    var policies: [String]
    var subject: String?
    var issuer: String?
    var notBefore: String?
    var notAfter: String?
    var expired: Bool
    var isCA: Bool
    var selfSigned: Bool
    var sha256: String?
    var kind: String
    var tool: String?
    var risk: String
    var explanation: String?

    init(_ j: JSONValue, index: Int) {
        id = index
        name = j["name"].text ?? j["subject"].text ?? "—"
        domain = j["domain"].text?.lowercased()
        trust = j["trust"].text?.lowercased()
        policies = j["policies"].stringArray
        subject = j["subject"].text
        issuer = j["issuer"].text
        notBefore = j["not_before"].text
        notAfter = j["not_after"].text
        expired = j["expired"].bool ?? false
        isCA = j["is_ca"].bool ?? false
        selfSigned = j["self_signed"].bool ?? false
        sha256 = j["sha256"].text
        kind = (j["kind"].text ?? "unknown").lowercased()
        tool = j["tool"].text
        risk = (j["risk"].text ?? "info").lowercased()
        explanation = j["explanation"].text
    }

    var riskRank: Int {
        switch risk {
        case "malicious": return 3
        case "suspicious": return 2
        case "low": return 1
        default: return 0
        }
    }
}

// MARK: - Live network monitor (Mega)

/// Counts of what is new since the monitor started (flat in `net_status`, under `stats` in the summary).
struct NetMonitorStats: Sendable, Equatable {
    var connectionsNew: Int
    var publicNew: Int
    var listeningNew: Int
    var inbound: Int
    var sessionsNew: Int
    var processesRemote: Int
    var uploadedBytes: Int
    var alerts: Int

    init(_ j: JSONValue) {
        connectionsNew = j["connections_new"].int ?? 0
        publicNew = j["public_new"].int ?? 0
        listeningNew = j["listening_new"].int ?? 0
        inbound = j["inbound"].int ?? 0
        sessionsNew = j["sessions_new"].int ?? 0
        processesRemote = j["processes_remote"].int ?? 0
        uploadedBytes = j["uploaded_bytes"].int ?? 0
        alerts = j["alerts"].int ?? 0
    }
}

/// `net_status` – sent after every poll; the last one has `active: false`.
struct NetMonitorStatus: Sendable, Equatable {
    var active: Bool
    var since: String?
    var polls: Int
    var intervalS: Double?
    var stats: NetMonitorStats

    init(_ j: JSONValue) {
        active = j["active"].bool ?? true
        since = j["since"].text
        polls = j["polls"].int ?? 0
        intervalS = j["interval_s"].double
        stats = NetMonitorStats(j)
    }
}

/// One notable change seen by the monitor (`net_event.item`, `monitor.events[]`).
struct NetEvent: Identifiable, Sendable, Equatable {
    var id: String
    var time: String?
    var kind: String
    var severity: Severity
    var title: String
    var detail: String?
    var process: String?
    var pid: Int?
    var exe: String?
    var remote: String?
    var host: String?
    var signer: String?
    // runtime detection (optional – older events and reports lack them)
    var confidence: String?          // high | medium | low
    var attack: String?              // remote_shell, credential_theft, c2, …
    var evidence: [String]           // short Polish lines, strongest first
    var signals: [String]
    var targetPath: String?          // the file to quarantine (an untrusted program or the script an interpreter runs)
    var trust: String?
    var ioc: Bool                    // the remote address is on a threat list

    init(_ j: JSONValue) {
        time = j["time"].text
        kind = (j["kind"].text ?? "").lowercased()
        severity = Severity(raw: j["severity"].text)
        title = j["title"].text ?? "—"
        detail = j["detail"].text
        process = j["process"].text
        pid = j["pid"].int
        exe = j["exe"].text
        remote = j["remote"].text
        host = j["host"].text
        signer = j["signer"].text
        confidence = j["confidence"].text?.lowercased()
        attack = j["attack"].text
        evidence = Array(j["evidence"].stringArray.prefix(8))
        signals = Array(j["signals"].stringArray.prefix(12))
        targetPath = j["target"].text
        trust = j["trust"].text
        ioc = j["ioc"].bool ?? false
        id = j["id"].text ?? "ne|\(time ?? "")|\(title)"
    }

    /// Counted as an alert (also reported as a `network_live` environment finding).
    var isAlert: Bool { severity.rank >= Severity.low.rank }

    /// "Pewność: wysoka" – only for alerts (every harmless event would otherwise say "niska").
    var confidenceLabel: String? {
        guard isAlert else { return nil }
        switch confidence {
        case "high": return "Pewność: wysoka"
        case "medium": return "Pewność: średnia"
        case "low": return "Pewność: niska"
        default: return nil
        }
    }
}

/// A public connection that did not exist when the monitor started.
struct NetNewPublic: Identifiable, Sendable, Equatable {
    let id: Int
    var time: String?
    var process: String
    var pid: Int?
    var exe: String?
    var remote: String
    var port: Int?
    var host: String?
    var signer: String?

    init(_ j: JSONValue, index: Int) {
        id = index
        time = j["time"].text
        process = j["process"].text ?? "?"
        pid = j["pid"].int
        exe = j["exe"].text
        remote = j["remote"].text ?? "?"
        port = j["port"].int
        host = j["host"].text
        signer = j["signer"].text
    }
}

/// `summary.network.monitor`.
struct NetMonitor: Sendable, Equatable {
    var started: String?
    var ended: String?
    var seconds: Double?
    var polls: Int?
    var intervalS: Double?
    var stats: NetMonitorStats
    var events: [NetEvent]
    var newPublic: [NetNewPublic]
    var uploads: [TrafficItem]
    var limitations: [String]

    init?(_ j: JSONValue) {
        guard j.object != nil else { return nil }
        started = j["started"].text
        ended = j["ended"].text
        seconds = j["seconds"].double
        polls = j["polls"].int
        intervalS = j["interval_s"].double
        stats = NetMonitorStats(j["stats"])
        var seen = Set<String>()
        var evs: [NetEvent] = []
        for (i, item) in j["events"].array.enumerated() {
            var e = NetEvent(item)
            if seen.contains(e.id) { e.id += "#\(i)" }
            seen.insert(e.id)
            evs.append(e)
        }
        events = evs
        newPublic = j["new_public"].array.enumerated().map { NetNewPublic($0.element, index: $0.offset) }
        uploads = j["uploads"].array.enumerated().map { TrafficItem($0.element, index: $0.offset) }
        limitations = j["limitations"].stringArray
    }

    var alertCount: Int { max(stats.alerts, events.filter(\.isAlert).count) }
    var worstSeverity: Severity? { events.map(\.severity).max { $0.rank < $1.rank } }
}

// MARK: - Link ("Sprawdź link")

struct TLSInfo: Sendable, Equatable {
    var issuer: String?
    var subject: String?
    var expires: String?
    var version: String?

    init?(_ j: JSONValue) {
        guard j.object != nil else { return nil }
        issuer = j["issuer"].text
        subject = j["subject"].text
        expires = j["expires"].text
        version = j["version"].text
    }
}

struct LinkedFile: Identifiable, Sendable, Equatable {
    let id: Int
    var name: String
    var url: String?
    var size: Int?
    var contentType: String?
    var sha256: String?

    init(_ j: JSONValue, index: Int) {
        id = index
        url = j["url"].text
        name = j["name"].text ?? (url.map { ($0 as NSString).lastPathComponent } ?? "—")
        size = j["size"].int
        contentType = j["content_type"].text
        sha256 = j["sha256"].text
    }
}

struct SkippedLink: Identifiable, Sendable, Equatable {
    let id: Int
    var url: String
    var reason: String

    init(_ j: JSONValue, index: Int) {
        id = index
        url = j["url"].text ?? "—"
        reason = j["reason"].text ?? ""
    }
}

struct URLInfo: Sendable, Equatable {
    var input: String
    var finalURL: String?
    var redirects: [String]
    var status: Int?
    var contentType: String?
    var server: String?
    var domain: String?
    var ip: String?
    var tls: TLSInfo?
    var ioc: [String]
    var pageTitle: String?
    var linksFound: Int?
    var hasPage: Bool
    var files: [LinkedFile]
    var skipped: [SkippedLink]
    var notes: [String]

    init?(_ j: JSONValue) {
        guard j.object != nil else { return nil }
        input = j["input"].text ?? ""
        finalURL = j["final_url"].text
        redirects = j["redirects"].stringArray
        status = j["status"].int
        contentType = j["content_type"].text
        server = j["server"].text
        domain = j["domain"].text
        ip = j["ip"].text
        tls = TLSInfo(j["tls"])
        ioc = j["ioc"].stringArray
        hasPage = j["page"].object != nil
        pageTitle = j["page"]["title"].text
        linksFound = j["page"]["links_found"].int
        files = j["files"].array.enumerated().map { LinkedFile($0.element, index: $0.offset) }
        skipped = j["skipped"].array.enumerated().map { SkippedLink($0.element, index: $0.offset) }
        notes = j["notes"].stringArray
    }

    var isEncrypted: Bool { (finalURL ?? input).lowercased().hasPrefix("https://") }
}

// MARK: - Summary

struct Summary: Sendable, Equatable {
    var mode: ScanMode
    var level: ScanLevel
    var title: String
    var started: String?
    var finished: String?
    var seconds: Double?
    var cancelled: Bool
    var verdict: Verdict
    var files: Int?
    var bytes: Int?
    var objects: Int?
    var patternsTotal: Int?
    var counts: [Verdict: Int]
    var results: [ScanResult]
    var skipped: Int?
    /// iCloud/File Provider placeholders that were not downloaded (not on disk, so nothing to run).
    var cloudOnly: Int
    var cloudFetch: CloudFetchInfo?
    var errors: [String]
    var reportHTML: String?
    var reportJSON: String?
    var sandbox: SandboxInfo?
    var repo: RepoInfo?
    var environment: EnvironmentInfo?
    var network: NetworkInfo?
    var url: URLInfo?

    init(_ j: JSONValue) {
        mode = ScanMode(raw: j["mode"].text)
        level = ScanLevel(raw: j["level"].text)
        title = j["title"].text ?? ""
        started = j["started"].text
        finished = j["finished"].text
        seconds = j["seconds"].double
        cancelled = j["cancelled"].bool ?? false
        verdict = Verdict(raw: j["verdict"].text)
        files = j["files"].int
        bytes = j["bytes"].int
        objects = j["objects"].int
        patternsTotal = j["patterns_total"].int
        var c: [Verdict: Int] = [:]
        for (k, v) in j["counts"].object ?? [:] {
            if let n = v.int { c[Verdict(raw: k)] = n }
        }
        counts = c
        var seen = Set<String>()
        var rs: [ScanResult] = []
        for (i, item) in j["results"].array.enumerated() {
            var r = ScanResult(item)
            if seen.contains(r.id) { r.id += "#\(i)" }
            seen.insert(r.id)
            rs.append(r)
        }
        results = rs
        skipped = j["skipped"].int
        cloudOnly = j["cloud_only"].int ?? 0
        cloudFetch = CloudFetchInfo(j["cloud_fetch"])
        errors = j["errors"].stringArray
        reportHTML = j["report_html"].text
        reportJSON = j["report_json"].text
        sandbox = SandboxInfo(j["sandbox"])
        repo = RepoInfo(j["repo"])
        environment = EnvironmentInfo(j["environment"])
        network = NetworkInfo(j["network"])
        url = URLInfo(j["url"])
    }

    func count(_ v: Verdict) -> Int {
        counts[v] ?? results.filter { $0.verdict == v }.count
    }
}

// MARK: - History

struct HistoryItem: Identifiable, Sendable, Equatable {
    var id: String
    var mode: ScanMode
    var title: String
    var verdict: Verdict
    var started: String?
    var files: Int?
    var reportHTML: String?
    var reportJSON: String?

    init(_ j: JSONValue, index: Int) {
        id = j["id"].text ?? "item-\(index)"
        mode = ScanMode(raw: j["mode"].text)
        title = j["title"].text ?? "—"
        verdict = Verdict(raw: j["verdict"].text)
        started = j["started"].text
        files = j["files"].int
        reportHTML = j["report_html"].text
        reportJSON = j["report_json"].text
    }
}

// MARK: - Progress

struct ProgressEvent: Sendable, Equatable {
    var stage: String
    var found: Int?
    var bytes: Int?
    var total: Int?
    var files: Int?
    var done: Int?
    var rateMBs: Double?
    var flagged: Int?
    var current: String?
    var etaSeconds: Double?
    /// `url` downloads: how many of the linked files are done.
    var filesTotal: Int?

    init(_ j: JSONValue) {
        stage = j["stage"].text ?? ""
        found = j["found"].int
        bytes = j["bytes"].int
        total = j["total"].int
        files = j["files"].int
        done = j["done"].int
        rateMBs = j["rate_mbs"].double
        flagged = j["flagged"].int
        current = j["current"].text
        etaSeconds = j["eta_s"].double
        filesTotal = j["files_total"].int
    }

    /// Determinate fraction when the stage knows its total.
    var fraction: Double? {
        switch stage {
        case "scan":
            guard let total, total > 0, let done else { return nil }
            return min(1, max(0, Double(done) / Double(total)))
        case "behavior":
            // `done` = scripts finished; 0 means the first one is still running → indeterminate
            guard let total, total > 0, let done, done > 0 else { return nil }
            return min(1, max(0, Double(done) / Double(total)))
        case "download":
            if let total, total > 0, let bytes { return min(1, max(0, Double(bytes) / Double(total))) }
            if let filesTotal, filesTotal > 0, let files { return min(1, max(0, Double(files) / Double(filesTotal))) }
            return nil
        default:
            return nil
        }
    }
}

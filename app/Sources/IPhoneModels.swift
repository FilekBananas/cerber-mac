import Foundation

// MARK: - iPhone (kabel): data decoded from `iphone_devices` / `iphone_finding` / `iphone_done`

struct IPhoneBackup: Identifiable, Sendable, Equatable {
    var id: String { path }
    var path: String
    var udid: String?
    var deviceName: String?
    var model: String?
    var ios: String?
    var date: String?
    var encrypted: Bool
    var complete: Bool
    var source: String?

    init?(_ j: JSONValue) {
        guard j.object != nil, let p = j["path"].text else { return nil }
        path = p
        udid = j["udid"].text
        deviceName = j["device_name"].text
        model = j["model"].text
        ios = j["ios"].text
        date = j["date"].text
        encrypted = j["encrypted"].bool ?? false
        complete = j["complete"].bool ?? true
        source = j["source"].text
    }

    var title: String { deviceName ?? model ?? (path as NSString).lastPathComponent }

    var sourceLabel: String {
        switch source {
        case "cerber": return "kopia Cerbera"
        case "finder": return "kopia z Findera"
        default: return "kopia zapasowa"
        }
    }
}

struct IPhoneDevice: Identifiable, Sendable, Equatable {
    var id: String { udid }
    var udid: String
    var name: String?
    var model: String?
    var productType: String?
    var ios: String?
    /// usb | wifi | offline
    var state: String
    var trusted: Bool?
    var lastSeen: String?
    var sources: [String]
    var backup: IPhoneBackup?

    init(_ j: JSONValue) {
        udid = j["udid"].text ?? "?"
        name = j["name"].text
        model = j["model"].text
        productType = j["product_type"].text
        ios = j["ios"].text
        state = j["state"].text ?? "offline"
        trusted = j["trusted"].bool
        lastSeen = j["last_seen"].text
        sources = j["sources"].stringArray
        backup = IPhoneBackup(j["backup"])
    }

    var title: String { name ?? model ?? "iPhone" }
    var connected: Bool { state == "usb" || state == "wifi" }
    /// Real UDID (not the placeholder for a phone seen only on USB without its serial).
    var readable: Bool { connected && !udid.hasPrefix("usb-") && trusted != false }

    var stateLabel: String {
        if state == "usb" && trusted == false { return "Wymaga „Zaufaj”" }
        switch state {
        case "usb": return "Podłączony kablem"
        case "wifi": return "Połączony przez Wi‑Fi"
        default: return "Niepodłączony"
        }
    }
}

struct IPhoneSource: Identifiable, Sendable, Equatable {
    var id: String { name }
    var name: String
    var license: String?
    var url: String?
}

struct IPhoneDevicesInfo: Sendable, Equatable {
    var devices: [IPhoneDevice]
    var backups: [IPhoneBackup]
    var notes: [String]
    /// "idevicebackup2" | "apple" | nil
    var canBackup: String?
    var backupDir: String?
    var backupFree: Int?
    /// ok | denied | missing
    var mobilesync: String
    var libimobiledevice: Bool
    var devicectl: Bool
    var indicatorsTotal: Int
    var indicatorsBuilt: String?
    var sources: [IPhoneSource]

    init(_ j: JSONValue) {
        devices = j["devices"].array.map(IPhoneDevice.init)
        backups = j["backups"].array.compactMap(IPhoneBackup.init)
        notes = j["notes"].stringArray
        canBackup = j["can_backup"].text
        backupDir = j["backup_target"]["dir"].text
        backupFree = j["backup_target"]["free_bytes"].int
        mobilesync = j["access"]["mobilesync"].text ?? "missing"
        libimobiledevice = j["tools"]["libimobiledevice"].bool ?? false
        devicectl = j["tools"]["devicectl"].bool ?? false
        indicatorsTotal = j["indicators"]["total"].int ?? 0
        indicatorsBuilt = j["indicators"]["built"].text
        sources = j["indicators"]["sources"].array.compactMap { s in
            s["name"].text.map { IPhoneSource(name: $0, license: s["license"].text, url: s["url"].text) }
        }
    }
}

struct IPhoneFinding: Identifiable, Sendable, Equatable {
    var id: String
    var category: String
    var title: String
    var location: String?
    var severity: Severity
    var score: Int
    var description: String?
    var evidence: [String]
    var evidenceTotal: Int
    var advice: [String]
    var threat: String?

    init(_ j: JSONValue, index: Int) {
        id = j["id"].text ?? "f\(index)"
        category = j["category"].text ?? ""
        title = j["title"].text ?? "—"
        location = j["location"].text
        severity = Severity(raw: j["severity"].text)
        score = j["score"].int ?? 0
        description = j["description"].text
        evidence = j["evidence"].stringArray
        evidenceTotal = j["evidence_total"].int ?? evidence.count
        advice = j["advice"].stringArray
        threat = j["threat"].text
    }

    var icon: String {
        switch category {
        case "spyware": return "eye.trianglebadge.exclamationmark"
        case "stalkerware": return "location.viewfinder"
        case "profile": return "gearshape.2"
        case "jailbreak": return "lock.open.trianglebadge.exclamationmark"
        case "app": return "app.badge"
        case "phishing": return "link.badge.plus"
        case "posture": return "shield.lefthalf.filled"
        default: return "exclamationmark.circle"
        }
    }
}

struct IPhoneCheck: Identifiable, Sendable, Equatable {
    var id: String
    var title: String
    /// ok | found | missing | skipped | error
    var status: String
    var detail: String?

    init(_ j: JSONValue, index: Int) {
        id = (j["id"].text ?? "c") + "-\(index)"
        title = j["title"].text ?? "—"
        status = j["status"].text ?? "ok"
        detail = j["detail"].text
    }

    var statusLabel: String {
        switch status {
        case "ok": return "sprawdzono"
        case "found": return "znaleziono"
        case "missing": return "brak danych"
        case "skipped": return "pominięto"
        case "error": return "błąd"
        default: return status
        }
    }
}

struct IPhoneSummary: Sendable, Equatable {
    var title: String
    var started: String?
    var seconds: Double?
    var cancelled: Bool
    var verdict: Verdict
    var deviceName: String?
    var deviceModel: String?
    var ios: String?
    var backup: IPhoneBackup?
    var findings: [IPhoneFinding]
    var checks: [IPhoneCheck]
    var limitations: [String]
    var advice: [String]
    var lockdownMode: Bool?
    var passcodeSet: Bool?
    var mdm: Bool?
    var appsTotal: Int?
    var backupFiles: Int?
    var indicatorsTotal: Int?
    var sandboxVerified: [String]
    var reportHTML: String?
    var reportJSON: String?
    /// full (unencrypted backup analysed) | partial (encrypted backup or device data only) | none
    var coverage: String

    init(_ j: JSONValue) {
        coverage = j["coverage"].text ?? "full"
        title = j["title"].text ?? "iPhone"
        started = j["started"].text
        seconds = j["seconds"].double
        cancelled = j["cancelled"].bool ?? false
        verdict = Verdict(raw: j["verdict"].text)
        deviceName = j["device"]["name"].text
        deviceModel = j["device"]["model"].text ?? j["device"]["product_type"].text
        ios = j["device"]["ios"].text ?? j["posture"]["ios"].text
        backup = IPhoneBackup(j["backup"])
        findings = j["findings"].array.enumerated().map { IPhoneFinding($0.element, index: $0.offset) }
        checks = j["checks"].array.enumerated().map { IPhoneCheck($0.element, index: $0.offset) }
        limitations = j["limitations"].stringArray
        advice = j["advice"].stringArray
        lockdownMode = j["posture"]["lockdown_mode"].bool
        passcodeSet = j["posture"]["passcode_set"].bool
        mdm = j["posture"]["mdm"].bool
        appsTotal = j["apps_total"].int ?? j["posture"]["apps_total"].int
        backupFiles = j["stats"]["backup_files"].int
        indicatorsTotal = j["indicators"]["total"].int
        sandboxVerified = j["sandbox"]["verified"].stringArray
        reportHTML = j["report_html"].text
        reportJSON = j["report_json"].text
    }

    var serious: [IPhoneFinding] { findings.filter { $0.severity.rank >= Severity.suspicious.rank } }
}

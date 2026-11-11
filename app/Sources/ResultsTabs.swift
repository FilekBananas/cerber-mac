import AppKit
import SwiftUI

// MARK: - Environment

struct EnvironmentTab: View {
    var env: EnvironmentInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PostureRow(posture: env.posture)
            if env.findings.isEmpty {
                EmptyState(icon: "checkmark.shield.fill", title: "Środowisko wygląda dobrze",
                           message: "Nie znaleziono podejrzanych elementów autostartu, procesów, rozszerzeń ani ustawień.")
            }
            ForEach(Severity.allCases, id: \.self) { sev in
                let group = env.findings.filter { $0.severity == sev }
                if !group.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 8) {
                            Dot(color: sev.color, size: 9)
                            Text(sev.label).font(.system(size: 13, weight: .semibold))
                            Text("\(group.count)").font(.system(size: 12)).foregroundStyle(.secondary)
                        }
                        .padding(.leading, 4)
                        ForEach(group) { f in EnvFindingCard(finding: f) }
                    }
                }
            }
            if !env.limitations.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Ograniczenia tego skanu", systemImage: "info.circle")
                        .font(.system(size: 12.5, weight: .semibold))
                    ForEach(env.limitations, id: \.self) { l in
                        Text("• " + l).font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(14)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Palette.subtle))
            }
        }
    }
}

private struct PostureRow: View {
    var posture: Posture

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle(title: "Zabezpieczenia systemu", icon: "lock.shield")
            HStack(spacing: 10) {
                chip("SIP", "Ochrona systemu", posture.sip.map { $0 ? .ok("włączona") : .bad("wyłączona") } ?? .unknown)
                chip("Gatekeeper", "Kontrola aplikacji", posture.gatekeeper.map { $0 ? .ok("włączony") : .bad("wyłączony") } ?? .unknown)
                chip("FileVault", "Szyfrowanie dysku", posture.filevault.map { $0 ? .ok("włączony") : .warn("wyłączony") } ?? .unknown)
                chip("Zapora", "Zapora sieciowa", firewallState)
                chip("XProtect", "Sygnatury Apple", posture.xprotect.map { .ok("wersja \($0)") } ?? .unknown)
            }
        }
    }

    private var firewallState: ChipState {
        switch posture.firewall {
        case "on", "enabled", "true": return .ok("włączona")
        case "block_all": return .ok("blokuje wszystko")
        case "off", "disabled", "false": return .warn("wyłączona")
        case nil: return .unknown
        case let s?: return .warn(s)
        }
    }

    enum ChipState {
        case ok(String), warn(String), bad(String), unknown
    }

    private func chip(_ name: String, _ caption: String, _ state: ChipState) -> some View {
        let (icon, color, text): (String, Color, String) = {
            switch state {
            case .ok(let t): return ("checkmark.circle.fill", Palette.green, t)
            case .warn(let t): return ("exclamationmark.triangle.fill", Palette.orange, t)
            case .bad(let t): return ("xmark.octagon.fill", Palette.red, t)
            case .unknown: return ("questionmark.circle", Palette.gray, "nieznany")
            }
        }()
        return HStack(spacing: 10) {
            Image(systemName: icon).font(.system(size: 18, weight: .semibold)).foregroundStyle(color)
            VStack(alignment: .leading, spacing: 1) {
                Text(name).font(.system(size: 13, weight: .semibold))
                Text(text).font(.system(size: 11.5, weight: .medium)).foregroundStyle(color)
                Text(caption).font(.system(size: 10.5)).foregroundStyle(.tertiary).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity)
        .card(padding: 12, radius: 14)
    }
}

private struct EnvFindingCard: View {
    var finding: EnvFinding

    private var categoryIcon: String {
        switch finding.category {
        case "persistence": return "arrow.triangle.2.circlepath"
        case "correlation": return "point.3.connected.trianglepath.dotted"
        case "artifacts": return "ladybug"
        case "process": return "cpu"
        case "network": return "network"
        case "network_live": return "dot.radiowaves.left.and.right"
        case "syslog": return "doc.text.magnifyingglass"
        case "lan": return "wifi.router"
        case "certs": return "checkmark.seal"
        case "remote_access": return "display.2"
        case "posture": return "lock.shield"
        case "browser": return "globe"
        case "ssh": return "key.horizontal"
        case "profile": return "person.crop.circle.badge.checkmark"
        case "keyboard": return "keyboard"
        default: return "exclamationmark.circle"
        }
    }

    private var categoryLabel: String {
        switch finding.category {
        case "persistence": return "Autostart"
        case "correlation": return "Powiązania: proces + sieć + pliki"
        case "artifacts": return "Znane ślady malware"
        case "process": return "Proces"
        case "network": return "Sieć"
        case "network_live": return "Sieć na żywo"
        case "syslog": return "Logi systemowe"
        case "lan": return "Sieć lokalna"
        case "certs": return "Certyfikaty"
        case "remote_access": return "Zdalny dostęp"
        case "posture": return "Ustawienia"
        case "browser": return "Przeglądarka"
        case "ssh": return "SSH"
        case "profile": return "Profil"
        case "keyboard": return "Klawiatura"
        case "": return "Inne"
        default: return finding.category.capitalized
        }
    }

    private var revealPath: String? {
        guard let loc = finding.location, loc.hasPrefix("/") || loc.hasPrefix("~") else { return nil }
        var p = (loc as NSString).expandingTildeInPath
        if let r = p.range(of: " (pid") { p = String(p[..<r.lowerBound]) }
        if let r = p.range(of: " → ") { p = String(p[..<r.lowerBound]) }
        return FileManager.default.fileExists(atPath: p) ? p : nil
    }

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            SoftIcon(systemName: categoryIcon, color: finding.severity.color, size: 38)
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Text(finding.title).font(.system(size: 14, weight: .semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 8)
                    Pill(text: categoryLabel, color: Palette.gray)
                    Pill(text: finding.severity.label, color: finding.severity.color, filled: finding.severity.rank >= 2)
                }
                if let loc = finding.location {
                    Text(Fmt.tilde(loc))
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                if let d = finding.description {
                    Text(d).font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true)
                }
                if !finding.evidence.isEmpty {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(finding.evidence, id: \.self) { e in
                            HStack(alignment: .firstTextBaseline, spacing: 6) {
                                Text("›").foregroundStyle(finding.severity.color)
                                Text(Fmt.tilde(e)).textSelection(.enabled)
                            }
                            .font(.system(size: 11.5, design: .monospaced))
                            .foregroundStyle(.secondary)
                        }
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Palette.subtle.opacity(0.8)))
                }
                if let p = revealPath {
                    Button {
                        FinderActions.reveal(p)
                    } label: {
                        Label("Pokaż w Finderze", systemImage: "folder")
                    }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                }
            }
        }
        .card(padding: 16, radius: 16)
        .overlay(alignment: .leading) {
            UnevenRoundedRectangle(topLeadingRadius: 16, bottomLeadingRadius: 16, style: .continuous)
                .fill(finding.severity.color)
                .frame(width: 4)
        }
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

// MARK: - Network

struct NetworkTab: View {
    var net: NetworkInfo
    @Environment(\.snapshotMode) private var snapshot

    /// Monitor first when it raised alarms (or when it is all there is), otherwise after the start-audit summary.
    private var monitorFirst: Bool {
        guard let m = net.monitor else { return false }
        return m.alertCount > 0 || !net.hasAudit
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            if !net.hasAudit {
                Banner(icon: "exclamationmark.triangle", title: "Audyt sieci na starcie skanu się nie powiódł",
                       message: "Poniżej jest tylko to, co monitor na żywo zauważył w trakcie skanu.", color: Palette.gray)
            }
            if monitorFirst, let m = net.monitor {
                NetMonitorSection(monitor: m)
            }
            if net.hasAudit {
                audit
            }
        }
    }

    @ViewBuilder
    private var audit: some View {
        if net.monitor != nil {
            SectionTitle(title: "Audyt na starcie skanu", subtitle: "Stan sieci w chwili rozpoczęcia skanu", icon: "network")
                .padding(.top, monitorFirst ? 6 : 0)
        }
        summaryTiles
        ForEach(net.iocConnections) { c in
            Banner(icon: "bolt.trianglebadge.exclamationmark.fill",
                   title: "\(c.process) łączy się z adresem z listy zagrożeń",
                   message: "\(c.host ?? c.remote):\(c.port.map(String.init) ?? "?") – \(c.ioc ?? "")",
                   color: Palette.red)
        }
        if !monitorFirst, let m = net.monitor {
            NetMonitorSection(monitor: m)
        }
        remoteAccess
        deepAudit
        tables
        HStack(alignment: .top, spacing: 16) {
            NetSection(title: "Sesje", subtitle: "Kto jest teraz zalogowany", icon: "person.2", count: net.sessions.count) {
                SessionsTable(rows: net.sessions)
            }
            NetSection(title: "Ostatnie logowania", subtitle: "Zdalne logowania są wyróżnione", icon: "person.badge.clock",
                       count: net.logins.count) {
                LoginsTable(rows: net.logins)
            }
        }
    }

    /// Local network + trusted certificates side by side, then the system log history (Mega, newer reports).
    @ViewBuilder
    private var deepAudit: some View {
        if net.lan != nil || net.certificates != nil {
            HStack(alignment: .top, spacing: 16) {
                if let lan = net.lan { LanCard(lan: lan) }
                if let certs = net.certificates { CertificatesCard(certs: certs) }
            }
            .fixedSize(horizontal: false, vertical: true)     // both cards as tall as the taller one
        }
        if let sl = net.syslog { SyslogCard(syslog: sl) }
    }

    @ViewBuilder
    private var tables: some View {
        NetSection(title: "Porty nasłuchujące", subtitle: "Usługi, z którymi można się połączyć z sieci", icon: "dot.radiowaves.left.and.right",
                   count: net.listening.count) {
            ListeningTable(rows: sortedListening)
        }
        NetSection(title: "Aktywne połączenia", subtitle: "Dokąd łączą się programy na tym Macu", icon: "arrow.left.arrow.right",
                   count: net.connections.count) {
            ConnectionsTable(rows: sortedConnections)
        }
        NetSection(title: "Ruch sieciowy według procesu", subtitle: trafficSubtitle, icon: "chart.bar.xaxis",
                   count: net.traffic.count) {
            TrafficTable(rows: net.traffic.sorted { $0.bytesOut + $0.bytesIn > $1.bytesOut + $1.bytesIn })
        }
        trafficHistory
    }

    private var trafficSubtitle: String {
        if let b = net.bootTime { return "Od uruchomienia systemu (\(Fmt.dateTime(b)))" }
        return "Od uruchomienia systemu"
    }

    private var sortedListening: [Listener] {
        let order = ["all": 0, "specific": 1, "localhost": 2]
        return net.listening.sorted { (order[$0.exposure] ?? 3, $0.port ?? 0) < (order[$1.exposure] ?? 3, $1.port ?? 0) }
    }

    private var sortedConnections: [Connection] {
        net.connections.sorted { ($0.ioc != nil ? 0 : 1, $0.isPublic ? 0 : 1) < ($1.ioc != nil ? 0 : 1, $1.isPublic ? 0 : 1) }
    }

    private var summaryTiles: some View {
        let s = net.summary
        let cols = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]
        return LazyVGrid(columns: cols, spacing: 12) {
            StatTile(icon: "dot.radiowaves.left.and.right", label: "Nasłuchuje na wszystkich interfejsach",
                     value: Fmt.int(s.listeningAll ?? net.listening.filter { $0.exposure == "all" }.count),
                     tint: (s.listeningAll ?? 0) > 0 ? Palette.orange : Palette.green, emphasize: (s.listeningAll ?? 0) > 0)
            StatTile(icon: "globe.europe.africa", label: "Połączenia z internetem", value: Fmt.int(s.publicConnections))
            StatTile(icon: "app.connected.to.app.below.fill", label: "Procesy w sieci", value: Fmt.int(s.processesOnline))
            StatTile(icon: "display.2", label: "Aktywne narzędzia zdalne", value: Fmt.int(s.remoteTools),
                     tint: (s.remoteTools ?? 0) > 0 ? Palette.orange : Palette.green, emphasize: (s.remoteTools ?? 0) > 0)
            StatTile(icon: (s.iocHits ?? 0) > 0 ? "bolt.trianglebadge.exclamationmark.fill" : "checkmark.shield.fill",
                     label: "Trafienia IOC (ThreatFox, URLhaus)", value: Fmt.int(s.iocHits ?? net.iocConnections.count),
                     tint: (s.iocHits ?? 0) > 0 ? Palette.red : Palette.green, emphasize: (s.iocHits ?? 0) > 0)
            StatTile(icon: "arrow.up.circle", label: "Wysłano od uruchomienia", value: Fmt.bytes(s.uploadedBytes))
        }
    }

    @ViewBuilder
    private var remoteAccess: some View {
        if !net.remoteAccess.isEmpty {
            VStack(alignment: .leading, spacing: 12) {
                SectionTitle(title: "Zdalny dostęp", subtitle: "Usługi, aplikacje i tunele, przez które ktoś może sterować tym Macem",
                             icon: "display.2")
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
                    ForEach(net.remoteAccess.sorted { $0.riskRank > $1.riskRank }) { item in
                        RemoteAccessCard(item: item)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var trafficHistory: some View {
        if let h = net.trafficHistory {
            if h.available, !h.items.isEmpty {
                NetSection(title: "Historia ruchu", subtitle: "Dłuższy okres – z dzienników systemu", icon: "clock.arrow.circlepath",
                           count: h.items.count) {
                    TrafficTable(rows: h.items, showSeen: true)
                }
            } else {
                Banner(icon: "clock.badge.questionmark", title: "Historia ruchu niedostępna",
                       message: (h.reason.map { $0.prefix(1).uppercased() + $0.dropFirst() } ?? "Brak danych") + ". Pokazano tylko ruch od uruchomienia systemu.",
                       color: Palette.gray)
            }
        }
    }
}

private struct NetSection<Content: View>: View {
    var title: String
    var subtitle: String
    var icon: String
    var count: Int
    var emptyText = "Brak pozycji"
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitle(title: title, subtitle: subtitle, icon: icon,
                         trailing: AnyView(Text("\(count)").font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)))
            if count == 0 {
                Text(emptyText).font(.system(size: 12)).foregroundStyle(.secondary)
            } else {
                content
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card(padding: 16, radius: 18)
    }
}

private struct RemoteAccessCard: View {
    var item: RemoteAccessItem

    private var icon: String {
        switch item.kind {
        case "macos_service": return "macwindow"
        case "app": return "app.badge"
        case "tunnel": return "point.3.connected.trianglepath.dotted"
        case "mdm": return "building.columns"
        case "ssh_keys": return "key.horizontal"
        case "session": return "person.wave.2"
        default: return "display.2"
        }
    }

    private var status: (String, Color) {
        switch item.status {
        case "enabled": return ("włączone", Palette.orange)
        case "running": return ("działa", Palette.red)
        case "installed": return ("zainstalowane", Palette.gray)
        case "disabled": return ("wyłączone", Palette.green)
        case "present": return ("obecne", Palette.gray)
        default: return (item.status, Palette.gray)
        }
    }

    var body: some View {
        let color = RiskStyle.color(item.risk)
        HStack(alignment: .top, spacing: 12) {
            SoftIcon(systemName: icon, color: color, size: 36)
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 6) {
                    Text(item.name).font(.system(size: 13.5, weight: .semibold)).lineLimit(1)
                    Spacer(minLength: 4)
                    Pill(text: status.0, color: status.1, icon: item.status == "running" ? "circle.fill" : nil)
                }
                if let d = item.detail {
                    Text(Fmt.tilde(d)).font(.system(size: 12)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Pill(text: RiskStyle.label(item.risk), color: color, filled: item.riskRank >= 2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(color.opacity(item.riskRank >= 2 ? 0.08 : 0.04)))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(color.opacity(item.riskRank >= 2 ? 0.4 : 0.15), lineWidth: 1))
    }
}

// MARK: System logs, local network, certificates

private struct SyslogCard: View {
    var syslog: SyslogInfo
    @State private var showAll = false
    @Environment(\.snapshotMode) private var snapshot

    private var title: String {
        guard let d = syslog.securityDays, d > 0 else { return "Logi systemowe" }
        let n = Int(d.rounded())
        return "Logi systemowe (ostatnie \(Fmt.count(n, "dzień", "dni", "dni")))"
    }

    private var windowNote: String? {
        if syslog.historyShorter, let p = syslog.persistSince {
            return "macOS trzyma szczegółowe wpisy dopiero od \(Fmt.shortDateTime(p)) – starsze logowania, autoryzacje i nowe elementy w tle zostały już nadpisane."
        }
        if let f = syslog.from, let t = syslog.to { return "Przejrzano wpisy od \(Fmt.shortDateTime(f)) do \(Fmt.shortDateTime(t))." }
        return nil
    }

    private func c(_ k: String) -> Int { syslog.count(k) ?? 0 }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitle(title: title, subtitle: "Co macOS zapisał o XProtect, Gatekeeperze, logowaniach i autostarcie",
                         icon: "doc.text.magnifyingglass",
                         trailing: syslog.available ? AnyView(Text("\(syslog.events.count)").font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)) : nil)
            if !syslog.available {
                Label(syslog.reason.map { "Historia dziennika niedostępna: " + $0 } ?? "Historia dziennika niedostępna.", systemImage: "info.circle")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                tiles
                events
                if let n = windowNote {
                    Label(n, systemImage: "clock.arrow.circlepath")
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let r = syslog.reason {
                    Text(r).font(.system(size: 11.5)).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card(padding: 16, radius: 18)
    }

    private var tiles: some View {
        let cols = Array(repeating: GridItem(.flexible(), spacing: 10, alignment: .top), count: 4)
        return LazyVGrid(columns: cols, spacing: 10) {
            pair("shield.lefthalf.filled", c("xprotect_scans"), c("xprotect_detections") + c("xprotect_blocks"),
                 "XProtect: skanów / wykryć", bad: Palette.red)
            pair("hand.raised", c("gatekeeper_blocks"), c("gatekeeper_overrides"), "Gatekeeper: blokad / obejść", bad: Palette.orange)
            pair("terminal", c("ssh_accepted"), c("ssh_failed"), "SSH: udane / nieudane", bad: Palette.orange)
            pair("display.2", c("screen_sharing_ok"), c("screen_sharing_failed"), "Udostępnianie ekranu: udane / nieudane",
                 bad: Palette.orange, firstIsBad: c("screen_sharing_ok") > 0)
            single("key.slash", c("auth_failures"), "Nieudane hasła", warn: c("auth_failures") >= 10)
            single("arrow.triangle.2.circlepath", c("new_login_items"), "Nowe elementy w tle", warn: false)
            single("lock.open", c("privileged_authorizations"), "Autoryzacje administratora", warn: false)
            single("hand.raised.square", c("privacy_prompts"),
                   "Prośby o uprawnienia" + (syslog.privacyDays.map { $0 < 1 ? " (\(Int(($0 * 24).rounded())) h)" : "" } ?? ""),
                   warn: false)
        }
    }

    private func pair(_ icon: String, _ a: Int, _ b: Int, _ label: String, bad: Color, firstIsBad: Bool = false) -> some View {
        let alarm = b > 0 || firstIsBad
        return NetMetric(icon: icon, value: "\(Fmt.int(a)) / \(Fmt.int(b))", label: label,
                         tint: alarm ? bad : Palette.brand, emphasize: alarm)
    }

    private func single(_ icon: String, _ n: Int, _ label: String, warn: Bool) -> some View {
        NetMetric(icon: icon, value: Fmt.int(n), label: label, tint: warn ? Palette.orange : Palette.brand, emphasize: warn)
    }

    @ViewBuilder
    private var events: some View {
        if syslog.events.isEmpty {
            HStack(spacing: 8) {
                Image(systemName: "checkmark.shield.fill").foregroundStyle(Palette.green)
                Text("Nic niepokojącego w dzienniku systemowym.").foregroundStyle(.secondary)
            }
            .font(.system(size: 12.5))
        } else {
            let limit = showAll || snapshot ? (snapshot ? 8 : syslog.events.count) : 6
            VStack(spacing: 6) {
                ForEach(syslog.events.prefix(limit)) { e in SyslogRow(event: e) }
            }
            if syslog.events.count > 6, !snapshot {
                Button(showAll ? "Pokaż mniej" : "Pokaż wszystkie (\(syslog.events.count))") {
                    withAnimation(.easeInOut(duration: 0.2)) { showAll.toggle() }
                }
                .buttonStyle(SecondaryButtonStyle(compact: true))
            }
        }
    }
}

private struct SyslogRow: View {
    var event: SyslogEvent

    private var categoryLabel: String {
        switch event.category {
        case "xprotect": return "XProtect"
        case "gatekeeper": return "Gatekeeper"
        case "remote_login": return "Zdalne logowanie"
        case "screen_sharing": return "Udostępnianie ekranu"
        case "login_failure": return "Nieudane logowanie"
        case "authorization": return "Autoryzacja"
        case "persistence": return "Elementy w tle"
        case "privacy": return "Prywatność"
        case "": return "System"
        default: return event.category.capitalized
        }
    }

    var body: some View {
        let color = event.severity.netColor
        let alert = event.severity.rank >= Severity.low.rank
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Dot(color: color, size: 8)
                .alignmentGuide(.firstTextBaseline) { $0[VerticalAlignment.center] + 4 }
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(event.title).font(.system(size: 12.5, weight: alert ? .semibold : .medium))
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 8)
                    Text(Fmt.shortDateTime(event.time)).font(.system(size: 11)).foregroundStyle(.secondary).monospacedDigit()
                    Pill(text: categoryLabel, color: Palette.gray)
                    if alert {
                        Pill(text: event.severity.label, color: color, filled: event.severity.rank >= Severity.suspicious.rank)
                    }
                }
                if let d = event.detail {
                    Text(Fmt.tilde(d)).font(.system(size: 11.5)).foregroundStyle(.secondary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let p = event.process {
                    Text(p).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(.tertiary)
                }
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(alert ? color.opacity(0.07) : Palette.subtle.opacity(0.6)))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(alert ? color.opacity(0.22) : Color.clear, lineWidth: 1))
    }
}

private struct LanCard: View {
    var lan: LanInfo

    private var wifi: (String, Color, String) {
        let label = lan.securityLabel ?? lan.securityLevel.uppercased()
        switch lan.securityLevel {
        case "open": return ("Otwarta – bez hasła", Palette.red, "wifi.exclamationmark")
        case "wep": return ("\(label) – przestarzałe, łatwe do złamania", Palette.red, "wifi.exclamationmark")
        case "wpa": return ("\(label) – przestarzałe", Palette.orange, "wifi.exclamationmark")
        case "wpa2", "wpa3", "enterprise", "owe": return (label, Palette.green, "lock.fill")
        default: return (lan.securityLabel ?? "nieznane", Palette.gray, "questionmark")
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitle(title: "Sieć lokalna", subtitle: "Wi‑Fi, router i sąsiedzi w sieci", icon: "wifi.router")
            HStack(spacing: 8) {
                Image(systemName: "wifi").font(.system(size: 13, weight: .semibold)).foregroundStyle(lan.wifiConnected ? wifi.1 : Palette.gray)
                if lan.wifiConnected {
                    Text(lan.ssid ?? "Wi‑Fi").font(.system(size: 13, weight: .semibold)).lineLimit(1)
                    Pill(text: wifi.0, color: wifi.1, icon: wifi.2, filled: wifi.1 == Palette.red)
                } else {
                    Text("Brak połączenia Wi‑Fi").font(.system(size: 13)).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            VStack(alignment: .leading, spacing: 5) {
                row("Router", lan.gatewayIP.map { ip in ip + (lan.gatewayInterface.map { " (\($0))" } ?? "") })
                row("MAC routera", lan.gatewayMAC.map { $0 + (lan.macRandomized == true ? " · losowy (prywatny)" : "") })
                if !lan.dns.isEmpty { row("DNS", lan.dns.prefix(3).joined(separator: ", ")) }
                row("Wpisy ARP", lan.arpEntries.map { Fmt.int($0) })
                row("Routery IPv6", lan.ipv6Routers > 0 ? Fmt.int(lan.ipv6Routers) : "brak")
                if lan.routerARPVerified == false {
                    row("Router z DHCP", "inny niż w tablicy ARP", warn: true)
                }
            }
            if lan.arpSuspicious.isEmpty {
                Label("Brak oznak podszywania się pod router (ARP spoofing)", systemImage: "checkmark.shield.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(Palette.green)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(lan.arpSuspicious) { a in
                    VStack(alignment: .leading, spacing: 2) {
                        Label(a.reason ?? "Podejrzany wpis ARP", systemImage: "exclamationmark.triangle.fill")
                            .font(.system(size: 12, weight: .semibold)).foregroundStyle(Palette.orange)
                            .fixedSize(horizontal: false, vertical: true)
                        Text("\(a.mac) → \(a.ips.joined(separator: ", "))").font(.system(size: 11.5, design: .monospaced))
                            .foregroundStyle(.secondary).lineLimit(2)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Palette.orange.opacity(0.08)))
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .card(padding: 16, radius: 18)
    }

    private func row(_ k: String, _ v: String?, warn: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(k).font(.system(size: 12)).foregroundStyle(.secondary).frame(width: 104, alignment: .leading)
            Text(v ?? "—").font(.system(size: 12, design: .monospaced))
                .foregroundStyle(warn ? Palette.orange : Color.primary)
                .lineLimit(1).truncationMode(.middle)
                .textSelection(.enabled)
        }
    }
}

private struct CertificatesCard: View {
    var certs: [TrustedCert]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitle(title: "Certyfikaty zaufane ręcznie",
                         subtitle: "Dodane przez użytkownika lub administratora – mogą pozwolić podsłuchiwać HTTPS",
                         icon: "checkmark.seal",
                         trailing: AnyView(Text("\(certs.count)").font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)))
            if certs.isEmpty {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: "checkmark.seal.fill").foregroundStyle(Palette.green)
                    Text("Brak ręcznie zaufanych certyfikatów – nikt nie dodał certyfikatu do podsłuchu HTTPS")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .font(.system(size: 12.5))
            } else {
                ForEach(certs.sorted { $0.riskRank > $1.riskRank }) { c in CertRow(cert: c) }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .card(padding: 16, radius: 18)
    }
}

private struct CertRow: View {
    var cert: TrustedCert

    private var kindLabel: String {
        switch cert.kind {
        case "interception_tool": return "Podsłuch HTTPS"
        case "adware": return "Adware"
        case "impersonation": return "Podszywa się"
        case "enterprise": return "Firmowy"
        case "antivirus_filter": return "Filtr antywirusa"
        case "dev": return "Deweloperski"
        case "system_duplicate": return "Kopia systemowego"
        case "distrusted": return "Zablokowany"
        default: return "Nieznany"
        }
    }

    private var trustLabel: String? {
        switch cert.trust {
        case "all": return "zaufany do wszystkiego"
        case "ssl": return "zaufany dla HTTPS (SSL)"
        case "other": return "zaufany do innych zastosowań"
        case "deny": return "oznaczony jako niezaufany"
        case "unspecified": return "zaufanie nieokreślone"
        default: return nil
        }
    }

    var body: some View {
        let color = RiskStyle.color(cert.risk)
        VStack(alignment: .leading, spacing: 5) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(cert.tool ?? cert.name).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                Pill(text: kindLabel, color: Palette.gray)
                Spacer(minLength: 4)
                Pill(text: RiskStyle.label(cert.risk), color: color, filled: cert.riskRank >= 2)
            }
            if cert.tool != nil {
                Text(cert.name).font(.system(size: 11.5)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            if let e = cert.explanation {
                Text(e).font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
            }
            let meta = [trustLabel,
                        cert.domain == "admin" ? "dla wszystkich użytkowników" : (cert.domain == "user" ? "tylko to konto" : nil),
                        cert.notAfter.map { (cert.expired ? "wygasł " : "ważny do ") + Fmt.shortDate($0) },
                        cert.isCA ? "urząd certyfikacji (CA)" : nil,
                        cert.selfSigned ? "samopodpisany" : nil].compactMap { $0 }
            if !meta.isEmpty {
                Text(meta.joined(separator: " · ")).font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(color.opacity(cert.riskRank >= 1 ? 0.07 : 0.04)))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(color.opacity(cert.riskRank >= 1 ? 0.25 : 0.12), lineWidth: 1))
        .help(cert.subject ?? cert.name)
    }
}

// MARK: Live monitor ("W trakcie skanu")

extension NetEvent {
    var kindIcon: String {
        switch kind {
        case "connection": return "arrow.up.right.circle"
        case "listen": return "dot.radiowaves.right"
        case "inbound": return "arrow.down.left.circle"
        case "session": return "person.badge.clock"
        case "process": return "display.2"
        case "traffic": return "arrow.up.circle"
        case "log": return "doc.text.magnifyingglass"
        case "permission": return "hand.raised"
        case "autostart": return "arrow.triangle.2.circlepath"
        case "file": return "doc.badge.plus"
        case "gateway": return "wifi.router"
        case "correlation": return "point.3.connected.trianglepath.dotted"
        default: return "network"
        }
    }

    var kindLabel: String {
        switch kind {
        case "connection": return "Połączenie"
        case "listen": return "Nowy port"
        case "inbound": return "Przychodzące"
        case "session": return "Logowanie"
        case "process": return "Zdalny dostęp"
        case "traffic": return "Wysyłanie"
        case "log": return "Dziennik"
        case "permission": return "Uprawnienia"
        case "autostart": return "Autostart"
        case "file": return "Nowy plik"
        case "gateway": return "Router"
        case "correlation": return "Powiązania"
        default: return "Sieć"
        }
    }
}

private struct NetMonitorSection: View {
    var monitor: NetMonitor
    @State private var showPublic = false
    @Environment(\.snapshotMode) private var snapshot

    private var alertColor: Color {
        monitor.events.contains { $0.severity == .malicious } ? Palette.red : Palette.orange
    }

    /// "7 paź, 12:00 – 16:41 · 4 h 39 min · 3354 sprawdzenia co 5 s"
    private var subtitle: String {
        var parts: [String] = []
        if let st = monitor.started {
            parts.append(monitor.ended.map { "\(Fmt.shortDateTime(st)) – \(Fmt.time($0))" } ?? "od \(Fmt.shortDateTime(st))")
        }
        if let sec = monitor.seconds { parts.append(Fmt.duration(sec)) }
        if let p = monitor.polls {
            parts.append(Fmt.count(p, "sprawdzenie", "sprawdzenia", "sprawdzeń")
                         + (monitor.intervalS.map { " co \(Fmt.interval($0))" } ?? ""))
        }
        return parts.isEmpty ? "Co się zmieniło w sieci od startu skanu" : parts.joined(separator: " · ")
    }

    /// Alarms first (worst first), then the rest in the order they happened.
    private var sortedEvents: [NetEvent] {
        monitor.events.enumerated()
            .sorted { ($0.element.severity.rank, -$0.offset) > ($1.element.severity.rank, -$1.offset) }
            .map(\.element)
    }

    var body: some View {
        let alerts = monitor.alertCount
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center, spacing: 12) {
                SoftIcon(systemName: "dot.radiowaves.left.and.right", color: alerts > 0 ? alertColor : Palette.green, size: 38)
                VStack(alignment: .leading, spacing: 2) {
                    Text("W trakcie skanu (monitor na żywo)").font(.system(size: 17, weight: .semibold))
                    Text(subtitle).font(.system(size: 12)).foregroundStyle(.secondary).monospacedDigit()
                }
                Spacer(minLength: 8)
                if alerts > 0 {
                    Pill(text: Fmt.count(alerts, "alarm", "alarmy", "alarmów"), color: alertColor,
                         icon: "exclamationmark.triangle.fill", filled: true)
                } else {
                    Pill(text: "bez alarmów", color: Palette.green, icon: "checkmark")
                }
            }
            stats
            eventsList
            publicList
            if !monitor.uploads.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    subheader("Wysyłanie w trakcie skanu", icon: "arrow.up.circle", count: monitor.uploads.count,
                              note: "Procesy, które wysłały najwięcej danych od startu monitora")
                    TrafficTable(rows: monitor.uploads.sorted { $0.bytesOut > $1.bytesOut }, maxRows: 15)
                }
            }
            if !monitor.limitations.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Ograniczenia monitora", systemImage: "info.circle")
                        .font(.system(size: 12.5, weight: .semibold))
                    ForEach(monitor.limitations, id: \.self) { l in
                        Text("• " + l).font(.system(size: 12)).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Palette.subtle))
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card(padding: 18, radius: 18)
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous)
            .strokeBorder(alerts > 0 ? alertColor.opacity(0.35) : Color.clear, lineWidth: 1.5))
    }

    private var stats: some View {
        let s = monitor.stats
        let alerts = monitor.alertCount
        let cols = Array(repeating: GridItem(.flexible(), spacing: 10, alignment: .top), count: 4)
        return LazyVGrid(columns: cols, spacing: 10) {
            NetMetric(icon: alerts > 0 ? "exclamationmark.triangle.fill" : "checkmark.shield.fill", value: Fmt.int(alerts),
                      label: "Alarmy", tint: alerts > 0 ? alertColor : Palette.green, emphasize: alerts > 0)
            NetMetric(icon: "globe.europe.africa", value: Fmt.int(s.publicNew), label: "Nowe połączenia z Internetem")
            NetMetric(icon: "arrow.left.arrow.right", value: Fmt.int(s.connectionsNew), label: "Wszystkie nowe połączenia")
            NetMetric(icon: "arrow.up.circle", value: Fmt.bytes(s.uploadedBytes), label: "Wysłano w trakcie skanu")
            NetMetric(icon: "dot.radiowaves.right", value: Fmt.int(s.listeningNew), label: "Nowe otwarte porty")
            NetMetric(icon: "arrow.down.left.circle", value: Fmt.int(s.inbound), label: "Połączenia przychodzące")
            NetMetric(icon: "person.badge.clock", value: Fmt.int(s.sessionsNew), label: "Nowe logowania")
            NetMetric(icon: "display.2", value: Fmt.int(s.processesRemote), label: "Nowe narzędzia zdalne i tunele",
                      tint: s.processesRemote > 0 ? Palette.orange : Palette.brand, emphasize: s.processesRemote > 0)
        }
    }

    @ViewBuilder
    private var eventsList: some View {
        let events = sortedEvents
        VStack(alignment: .leading, spacing: 8) {
            subheader("Zdarzenia", icon: "list.bullet.rectangle", count: events.count,
                      note: events.isEmpty ? nil : "Alarmy na górze, potem wszystko w kolejności wystąpienia")
            if events.isEmpty {
                HStack(spacing: 10) {
                    Image(systemName: "checkmark.shield.fill").foregroundStyle(Palette.green)
                    Text("Nic nowego w trakcie skanu – nikt się nie łączył, nic nowego nie nasłuchiwało.").foregroundStyle(.secondary)
                }
                .font(.system(size: 12.5))
            } else {
                VStack(spacing: 6) {
                    ForEach(snapshot ? Array(events.prefix(12)) : events) { e in NetEventRow(event: e) }
                }
            }
        }
    }

    @ViewBuilder
    private var publicList: some View {
        if !monitor.newPublic.isEmpty {
            let open = showPublic || snapshot
            VStack(alignment: .leading, spacing: 8) {
                Button {
                    withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) { showPublic.toggle() }
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: "chevron.right")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundStyle(.secondary)
                            .rotationEffect(.degrees(open ? 90 : 0))
                            .frame(width: 12)
                        subheader("Nowe połączenia z Internetem", icon: "globe.europe.africa", count: monitor.newPublic.count,
                                  note: "Proces → dokąd, kiedy i czym podpisany")
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                if open {
                    NewPublicTable(rows: monitor.newPublic)
                        .transition(.opacity.combined(with: .move(edge: .top)))
                }
            }
        }
    }

    private func subheader(_ title: String, icon: String, count: Int, note: String?) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 7) {
            Image(systemName: icon).font(.system(size: 12, weight: .semibold)).foregroundStyle(Palette.brand)
            Text(title).font(.system(size: 13.5, weight: .semibold))
            Text("\(count)").font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)
            if let note {
                Text(note).font(.system(size: 11.5)).foregroundStyle(.tertiary).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
    }
}

struct NetEventRow: View {
    var event: NetEvent

    private var target: String? {
        switch (event.host, event.remote) {
        case let (h?, r?): return "\(h) · \(r)"
        case let (h?, nil): return h
        case let (nil, r?): return r
        default: return nil
        }
    }

    var body: some View {
        let color = event.severity.netColor
        HStack(alignment: .top, spacing: 12) {
            SoftIcon(systemName: event.kindIcon, color: color, size: 30)
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(event.title)
                        .font(.system(size: 13, weight: .semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 8)
                    if let t = event.time {
                        Text(Fmt.time(t, seconds: true)).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(.secondary)
                    }
                    Pill(text: event.kindLabel, color: Palette.gray)
                    Pill(text: event.severity.label, color: color, filled: event.severity.rank >= Severity.suspicious.rank)
                }
                if let d = event.detail {
                    Text(Fmt.tilde(d)).font(.system(size: 12)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
                if !event.evidence.isEmpty || event.confidenceLabel != nil || event.ioc {
                    VStack(alignment: .leading, spacing: 3) {
                        let head = [event.confidenceLabel, event.ioc ? "adres z listy zagrożeń" : nil].compactMap { $0 }
                        if !head.isEmpty {
                            Text(head.joined(separator: " · "))
                                .font(.system(size: 11, weight: .semibold)).foregroundStyle(color)
                        }
                        ForEach(Array(event.evidence.prefix(5).enumerated()), id: \.offset) { _, e in
                            HStack(alignment: .firstTextBaseline, spacing: 6) {
                                Text("›").foregroundStyle(color)
                                Text(Fmt.tilde(e)).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                            }
                            .font(.system(size: 11.5))
                            .foregroundStyle(.secondary)
                        }
                    }
                }
                if event.process != nil || target != nil || event.signer != nil {
                    HStack(spacing: 14) {
                        if let p = event.process { NetCells.process(p, pid: event.pid, exe: event.exe) }
                        if let t = target {
                            HStack(spacing: 4) {
                                Image(systemName: "arrow.right").font(.system(size: 9.5, weight: .bold)).foregroundStyle(.tertiary)
                                Text(t).font(.system(size: 11.5, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                                    .textSelection(.enabled)
                            }
                        }
                        if let sg = event.signer { NetCells.signer(sg) }
                        Spacer(minLength: 0)
                    }
                }
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous)
            .fill(event.isAlert ? color.opacity(0.06) : Palette.subtle.opacity(0.6)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous)
            .strokeBorder(event.isAlert ? color.opacity(0.25) : Color.clear, lineWidth: 1))
    }
}

private struct NewPublicTable: View {
    var rows: [NetNewPublic]
    @Environment(\.snapshotMode) private var snapshot

    var body: some View {
        if snapshot {
            SnapshotGrid(rows: rows, columns: [
                GridColumn(title: "Kiedy", width: 64) { r in AnyView(time(r)) },
                GridColumn(title: "Proces", width: 190) { r in AnyView(NetCells.process(r.process, pid: r.pid, exe: r.exe)) },
                GridColumn(title: "Dokąd", width: nil) { r in AnyView(target(r)) },
                GridColumn(title: "Podpis", width: 190) { r in AnyView(NetCells.signer(r.signer)) },
            ], maxRows: 8)
        } else {
            Table(rows) {
                TableColumn("Kiedy") { r in time(r) }.width(min: 56, ideal: 64)
                TableColumn("Proces") { r in NetCells.process(r.process, pid: r.pid, exe: r.exe) }.width(min: 120, ideal: 190)
                TableColumn("Dokąd") { r in target(r) }.width(min: 160, ideal: 280)
                TableColumn("Podpis") { r in NetCells.signer(r.signer) }.width(min: 100, ideal: 190)
            }
            .modifier(TableHeightModifier(rows: rows.count, maxRows: 12))
        }
    }

    private func time(_ r: NetNewPublic) -> some View {
        Text(r.time.map { Fmt.time($0, seconds: true) } ?? "—").font(.system(size: 11.5, design: .monospaced)).foregroundStyle(.secondary)
    }

    private func target(_ r: NetNewPublic) -> some View {
        let addr = r.remote + (r.port.map { ":\($0)" } ?? "")
        return VStack(alignment: .leading, spacing: 0) {
            Text(r.host ?? addr).font(.system(size: 12)).lineLimit(1).truncationMode(.middle)
            if r.host != nil {
                Text(addr).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(.tertiary)
            }
        }
    }
}

// MARK: Network tables (SwiftUI Table live, grid offscreen)

enum NetCells {
    static func exposure(_ e: String) -> some View {
        switch e {
        case "all": return Pill(text: "wszystkie interfejsy", color: Palette.orange, icon: "globe")
        case "localhost": return Pill(text: "tylko lokalnie", color: Palette.green, icon: "house")
        default: return Pill(text: "wybrany interfejs", color: Palette.blue, icon: "point.topleft.down.to.point.bottomright.curvepath")
        }
    }

    static func process(_ name: String, pid: Int?, exe: String? = nil) -> some View {
        HStack(spacing: 5) {
            Text(name).font(.system(size: 12, weight: .medium)).lineLimit(1)
            if let pid { Text("\(pid)").font(.system(size: 10.5, design: .monospaced)).foregroundStyle(.tertiary) }
        }
        .help(exe ?? name)
    }

    static func signer(_ s: String?) -> some View {
        Group {
            if let s {
                HStack(spacing: 4) {
                    Image(systemName: s == "Apple" ? "apple.logo" : (s == "ad-hoc" ? "seal" : "checkmark.seal.fill"))
                        .font(.system(size: 10))
                        .foregroundStyle(s == "ad-hoc" ? Palette.orange : Palette.green)
                    Text(s.replacingOccurrences(of: "Developer ID: ", with: "")).lineLimit(1).truncationMode(.tail)
                }
            } else {
                HStack(spacing: 4) {
                    Image(systemName: "xmark.seal.fill").font(.system(size: 10)).foregroundStyle(Palette.red)
                    Text("bez podpisu").foregroundStyle(Palette.red)
                }
            }
        }
        .font(.system(size: 11.5))
    }

    static func bytesBar(_ value: Int, max: Int, color: Color) -> some View {
        HStack(spacing: 8) {
            LinearBar(fraction: max > 0 ? Double(value) / Double(max) : 0, color: color, height: 6)
                .frame(width: 90)
            Text(Fmt.bytes(value)).font(.system(size: 11.5)).monospacedDigit().lineLimit(1)
        }
    }
}

private struct TableHeightModifier: ViewModifier {
    var rows: Int
    var maxRows: Int = 10
    func body(content: Content) -> some View {
        content
            .frame(height: CGFloat(min(rows, maxRows)) * 26 + 34)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Palette.cardBorder, lineWidth: 1))
    }
}

private struct ListeningTable: View {
    var rows: [Listener]
    @Environment(\.snapshotMode) private var snapshot

    var body: some View {
        if snapshot {
            SnapshotGrid(rows: rows, columns: [
                GridColumn(title: "Port", width: 80) { r in AnyView(port(r)) },
                GridColumn(title: "Adres", width: 100) { r in AnyView(Text(r.address).font(.system(size: 12, design: .monospaced))) },
                GridColumn(title: "Ekspozycja", width: 160) { r in AnyView(NetCells.exposure(r.exposure)) },
                GridColumn(title: "Proces", width: nil) { r in AnyView(NetCells.process(r.process, pid: r.pid, exe: r.exe)) },
                GridColumn(title: "Usługa", width: 170) { r in AnyView(Text(r.service ?? "—").lineLimit(1)) },
                GridColumn(title: "Podpis", width: 150) { r in AnyView(NetCells.signer(r.signer)) },
            ])
        } else {
            Table(rows) {
                TableColumn("Port") { r in port(r) }.width(min: 70, ideal: 80)
                TableColumn("Adres") { r in Text(r.address).font(.system(size: 12, design: .monospaced)) }.width(min: 70, ideal: 100)
                TableColumn("Ekspozycja") { r in NetCells.exposure(r.exposure) }.width(min: 140, ideal: 160)
                TableColumn("Proces") { r in NetCells.process(r.process, pid: r.pid, exe: r.exe) }.width(min: 100, ideal: 150)
                TableColumn("Usługa") { r in Text(r.service ?? "—").lineLimit(1) }.width(min: 90, ideal: 160)
                TableColumn("Podpis") { r in NetCells.signer(r.signer) }.width(min: 90, ideal: 150)
            }
            .modifier(TableHeightModifier(rows: rows.count))
        }
    }

    private func port(_ r: Listener) -> some View {
        HStack(spacing: 4) {
            Text(r.port.map(String.init) ?? "?").font(.system(size: 12, weight: .semibold, design: .monospaced))
            Text(r.proto).font(.system(size: 10)).foregroundStyle(.tertiary)
        }
    }
}

private struct ConnectionsTable: View {
    var rows: [Connection]
    @Environment(\.snapshotMode) private var snapshot

    var body: some View {
        if snapshot {
            SnapshotGrid(rows: rows, columns: [
                GridColumn(title: "Proces", width: 190) { r in AnyView(NetCells.process(r.process, pid: r.pid, exe: r.exe)) },
                GridColumn(title: "Zdalny adres", width: nil) { r in AnyView(remote(r)) },
                GridColumn(title: "Port", width: 50) { r in AnyView(Text(r.port.map(String.init) ?? "?").font(.system(size: 12, design: .monospaced))) },
                GridColumn(title: "Sieć", width: 90) { r in AnyView(scope(r)) },
                GridColumn(title: "Zagrożenie", width: 230) { r in AnyView(ioc(r)) },
            ], maxRows: 9)
        } else {
            Table(rows) {
                TableColumn("Proces") { r in NetCells.process(r.process, pid: r.pid, exe: r.exe) }.width(min: 120, ideal: 180)
                TableColumn("Zdalny adres") { r in remote(r) }.width(min: 160, ideal: 260)
                TableColumn("Port") { r in Text(r.port.map(String.init) ?? "?").font(.system(size: 12, design: .monospaced)) }.width(50)
                TableColumn("Sieć") { r in scope(r) }.width(min: 70, ideal: 90)
                TableColumn("Zagrożenie") { r in ioc(r) }.width(min: 120, ideal: 240)
            }
            .modifier(TableHeightModifier(rows: rows.count, maxRows: 12))
        }
    }

    private func remote(_ r: Connection) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(r.host ?? r.remote).font(.system(size: 12, weight: r.ioc != nil ? .semibold : .regular))
                .foregroundStyle(r.ioc != nil ? Palette.red : Color.primary).lineLimit(1).truncationMode(.middle)
            if r.host != nil {
                Text(r.remote).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(.tertiary)
            }
        }
    }

    private func scope(_ r: Connection) -> some View {
        Text(r.isPublic ? "internet" : "lokalna").font(.system(size: 11.5)).foregroundStyle(r.isPublic ? Color.primary : Color.secondary)
    }

    @ViewBuilder
    private func ioc(_ r: Connection) -> some View {
        if let ioc = r.ioc {
            HStack(spacing: 4) {
                Image(systemName: "bolt.fill").font(.system(size: 9.5, weight: .bold))
                Text(ioc).font(.system(size: 11, weight: .semibold)).lineLimit(1).truncationMode(.tail)
            }
            .foregroundStyle(.white)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Capsule().fill(Palette.red))
            .help(ioc)
        } else {
            Text("—").foregroundStyle(.tertiary)
        }
    }
}

private struct TrafficTable: View {
    var rows: [TrafficItem]
    var showSeen = false
    var maxRows = 12
    @Environment(\.snapshotMode) private var snapshot

    var body: some View {
        let maxV = rows.map { max($0.bytesOut, $0.bytesIn) }.max() ?? 1
        if snapshot {
            SnapshotGrid(rows: rows, columns: [
                GridColumn(title: "Proces", width: nil) { r in AnyView(NetCells.process(r.process, pid: r.pid, exe: r.exe)) },
                GridColumn(title: "Wysłane", width: 180) { r in AnyView(NetCells.bytesBar(r.bytesOut, max: maxV, color: Palette.orange)) },
                GridColumn(title: "Odebrane", width: 180) { r in AnyView(NetCells.bytesBar(r.bytesIn, max: maxV, color: Palette.blue)) },
                GridColumn(title: showSeen ? "Ostatnio" : "Podpis", width: 190) { r in
                    AnyView(Group { if showSeen { Text(Fmt.shortDateTime(r.lastSeen)) } else { NetCells.signer(r.signer) } })
                },
            ], maxRows: 9)
        } else {
            Table(rows) {
                TableColumn("Proces") { r in NetCells.process(r.process, pid: r.pid, exe: r.exe) }.width(min: 120, ideal: 200)
                TableColumn("Wysłane") { r in NetCells.bytesBar(r.bytesOut, max: maxV, color: Palette.orange) }.width(min: 150, ideal: 180)
                TableColumn("Odebrane") { r in NetCells.bytesBar(r.bytesIn, max: maxV, color: Palette.blue) }.width(min: 150, ideal: 180)
                TableColumn(showSeen ? "Ostatnio" : "Podpis") { r in
                    if showSeen { Text(Fmt.shortDateTime(r.lastSeen)) } else { NetCells.signer(r.signer) }
                }.width(min: 100, ideal: 190)
            }
            .modifier(TableHeightModifier(rows: rows.count, maxRows: maxRows))
        }
    }
}

private struct SessionsTable: View {
    var rows: [SessionItem]
    @Environment(\.snapshotMode) private var snapshot

    var body: some View {
        if snapshot {
            SnapshotGrid(rows: rows, columns: [
                GridColumn(title: "Użytkownik", width: nil) { r in AnyView(Text(r.user).fontWeight(.medium)) },
                GridColumn(title: "Terminal", width: 70) { r in AnyView(Text(r.tty).font(.system(size: 11.5, design: .monospaced))) },
                GridColumn(title: "Skąd", width: 95) { r in AnyView(from(r.from)) },
                GridColumn(title: "Od", width: 90) { r in AnyView(Text(Fmt.shortDateTime(r.since))) },
            ])
        } else {
            Table(rows) {
                TableColumn("Użytkownik") { r in Text(r.user).fontWeight(.medium) }
                TableColumn("Terminal") { r in Text(r.tty).font(.system(size: 11.5, design: .monospaced)) }.width(min: 60, ideal: 70)
                TableColumn("Skąd") { r in from(r.from) }.width(min: 80, ideal: 100)
                TableColumn("Od") { r in Text(Fmt.shortDateTime(r.since)) }.width(min: 80, ideal: 100)
            }
            .modifier(TableHeightModifier(rows: rows.count, maxRows: 8))
        }
    }

    @ViewBuilder
    private func from(_ f: String?) -> some View {
        if let f {
            Text(f).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Palette.orange)
        } else {
            Text("lokalnie").foregroundStyle(.secondary)
        }
    }
}

private struct LoginsTable: View {
    var rows: [LoginItem]
    @Environment(\.snapshotMode) private var snapshot

    var body: some View {
        if snapshot {
            SnapshotGrid(rows: rows, columns: [
                GridColumn(title: "Użytkownik", width: nil) { r in AnyView(user(r)) },
                GridColumn(title: "Terminal", width: 64) { r in AnyView(Text(r.tty).font(.system(size: 11.5, design: .monospaced))) },
                GridColumn(title: "Skąd", width: 95) { r in AnyView(from(r)) },
                GridColumn(title: "Kiedy", width: 90) { r in AnyView(Text(Fmt.shortDateTime(r.when))) },
            ])
        } else {
            Table(rows) {
                TableColumn("Użytkownik") { r in user(r) }
                TableColumn("Terminal") { r in Text(r.tty).font(.system(size: 11.5, design: .monospaced)) }.width(min: 56, ideal: 64)
                TableColumn("Skąd") { r in from(r) }.width(min: 80, ideal: 100)
                TableColumn("Kiedy") { r in Text(Fmt.shortDateTime(r.when)) }.width(min: 80, ideal: 100)
            }
            .modifier(TableHeightModifier(rows: rows.count, maxRows: 8))
        }
    }

    private func user(_ r: LoginItem) -> some View {
        HStack(spacing: 5) {
            if r.remote {
                Image(systemName: "globe").font(.system(size: 10)).foregroundStyle(Palette.orange)
            }
            Text(r.user).fontWeight(.medium).lineLimit(1)
        }
    }

    @ViewBuilder
    private func from(_ r: LoginItem) -> some View {
        if let f = r.from {
            Text(f).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(r.remote ? Palette.orange : Color.primary)
        } else {
            Text("lokalnie").foregroundStyle(.secondary)
        }
    }
}

// MARK: - Repository

struct RepoTab: View {
    var repo: RepoInfo

    private var kindLabel: String {
        switch repo.kind {
        case "model": return "model"
        case "dataset": return "zbiór danych"
        case "space": return "Space"
        default: return "repozytorium"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 16) {
                IconTile(systemName: repo.source == "huggingface" ? "brain" : "chevron.left.forwardslash.chevron.right",
                         colors: repo.source == "huggingface" ? [Color(hex: 0xF59E0B), Color(hex: 0xEF4444)] : [Color(hex: 0x24292F), Color(hex: 0x57606A)],
                         size: 56)
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 8) {
                        Text(repo.fullName.isEmpty ? "—" : repo.fullName).font(.system(size: 20, weight: .bold, design: .rounded))
                        Pill(text: kindLabel, color: Palette.brand)
                        Pill(text: repo.source == "huggingface" ? "Hugging Face" : "GitHub", color: Palette.gray)
                    }
                    if let d = repo.description {
                        Text(d).font(.system(size: 13)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                    HStack(spacing: 14) {
                        if let s = repo.stars {
                            Label(Fmt.int(s), systemImage: repo.source == "huggingface" ? "heart.fill" : "star.fill")
                                .foregroundStyle(Palette.yellow)
                        }
                        if let r = repo.ref { Label(r, systemImage: "arrow.triangle.branch") }
                        if let a = repo.archiveBytes { Label("pobrano \(Fmt.bytes(a))", systemImage: "arrow.down.circle") }
                        if let u = repo.url, let url = URL(string: u) {
                            Button {
                                NSWorkspace.shared.open(url)
                            } label: {
                                Label(u.replacingOccurrences(of: "https://", with: ""), systemImage: "link")
                                    .lineLimit(1).truncationMode(.middle)
                                    .foregroundStyle(Palette.brand)
                            }
                            .buttonStyle(.plain)
                            .help("Otwórz w przeglądarce")
                        }
                    }
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .card(padding: 20, radius: 20)

            if let total = repo.filesTotal {
                let got = repo.filesDownloaded ?? total
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("Pobrane pliki").font(.system(size: 14, weight: .semibold))
                        Spacer()
                        Text("\(Fmt.int(got)) z \(Fmt.filesGenitive(total))").font(.system(size: 13, weight: .medium)).monospacedDigit()
                    }
                    LinearBar(fraction: total > 0 ? Double(got) / Double(total) : 1, gradient: [Palette.brandA, Palette.brandB], height: 8)
                    Text(repo.skipped.isEmpty
                         ? "Pobrano i sprawdzono wszystkie pliki."
                         : "Pominięte pliki nie mogą wykonać kodu albo są za duże – szczegóły poniżej.")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
                .card(padding: 18, radius: 18)
            }

            if !repo.skipped.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    SectionTitle(title: "Pominięte pliki", subtitle: "Nie pobrano ich w całości", icon: "arrow.uturn.forward.circle",
                                 trailing: AnyView(Text("\(repo.skipped.count)").font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)))
                    VStack(spacing: 0) {
                        ForEach(repo.skipped) { s in
                            HStack(spacing: 12) {
                                Image(systemName: skipIcon(s.reason)).foregroundStyle(skipColor(s.reason)).frame(width: 18)
                                Text(s.path).font(.system(size: 12, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                                Spacer(minLength: 8)
                                Text(s.reason).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                                Text(Fmt.bytes(s.size)).font(.system(size: 12)).monospacedDigit().frame(width: 70, alignment: .trailing)
                            }
                            .padding(.vertical, 8)
                            .padding(.horizontal, 10)
                            if s.id != repo.skipped.last?.id { Divider() }
                        }
                    }
                    .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Palette.subtle.opacity(0.6)))
                }
                .card(padding: 16, radius: 18)
            }
        }
    }

    private func skipIcon(_ r: String) -> String {
        let l = r.lowercased()
        if l.contains("bezpieczny") || l.contains("nagłów") { return "checkmark.seal.fill" }
        if l.contains("limit") || l.contains("za duż") { return "scalemass" }
        return "arrow.uturn.forward"
    }

    private func skipColor(_ r: String) -> Color {
        let l = r.lowercased()
        if l.contains("bezpieczny") || l.contains("nagłów") { return Palette.green }
        if l.contains("limit") || l.contains("za duż") { return Palette.orange }
        return Palette.gray
    }
}

// MARK: - Sandbox

struct SandboxTab: View {
    var sandbox: SandboxInfo

    private var readOnly: Bool { sandbox.mode == "readonly" || !sandbox.hasExtraction }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 16) {
                isolationCard
                if !sandbox.verified.isEmpty {
                    verifiedCard
                }
            }
            if sandbox.hasExtraction {
                HStack(spacing: 12) {
                    StatTile(icon: "doc.on.doc", label: "Rozpakowane pliki", value: Fmt.int(sandbox.extractedFiles))
                    StatTile(icon: "internaldrive", label: "Po rozpakowaniu", value: Fmt.bytes(sandbox.extractedBytes))
                    StatTile(icon: "square.3.layers.3d.down.right", label: "Głębokość zagnieżdżenia", value: Fmt.int(sandbox.depth))
                }
            }
            if !sandbox.limitsHit.isEmpty {
                Banner(icon: "scalemass.fill", title: "Osiągnięto limity",
                       message: sandbox.limitsHit.joined(separator: "\n"), color: Palette.orange)
            }
            if !sandbox.tree.isEmpty {
                SandboxTreeView(entries: sandbox.tree)
            }
        }
    }

    private var isolationCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                SectionTitle(title: "Izolacja",
                             subtitle: readOnly ? "Skaner działał w sandboksie macOS z dostępem tylko do odczytu"
                                                : "Jak było chronione rozpakowywanie",
                             icon: "lock.shield")
                if readOnly {
                    Pill(text: "tylko do odczytu", color: Palette.green, icon: "lock.fill")
                }
            }
            ForEach(sandbox.isolation.isEmpty ? defaultIsolation : sandbox.isolation, id: \.self) { i in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(Palette.green)
                    Text(i.prefix(1).uppercased() + i.dropFirst()).font(.system(size: 12.5))
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if readOnly {
                Text("Pliki były sprawdzane na miejscu – proces skanera nie mógł niczego zmienić, usunąć ani wysłać do sieci.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card(padding: 16, radius: 18)
    }

    private var verifiedCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle(title: "Zweryfikowano przed skanem",
                         subtitle: "Sandbox sprawdził sam siebie, zanim dostał pliki", icon: "checkmark.seal")
            ForEach(sandbox.verified, id: \.self) { v in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: "checkmark.shield.fill").foregroundStyle(Palette.green)
                    Text(v.prefix(1).uppercased() + v.dropFirst()).font(.system(size: 12.5))
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card(padding: 16, radius: 18)
    }

    private var defaultIsolation: [String] {
        readOnly ? ["brak dostępu do sieci", "system plików tylko do odczytu"]
                 : ["brak sieci", "zapis tylko do katalogu roboczego", "katalog roboczy usunięty"]
    }
}

final class TreeNode: Identifiable {
    let id: String
    let name: String
    var size: Int?
    var ownVerdict: Verdict?
    var children: [TreeNode] = []
    var childIndex: [String: TreeNode] = [:]
    var insideArchive: Bool
    var worst: Verdict = .clean

    init(id: String, name: String, insideArchive: Bool) {
        self.id = id
        self.name = name
        self.insideArchive = insideArchive
    }

    func child(_ name: String, insideArchive: Bool) -> TreeNode {
        if let c = childIndex[name] { return c }
        let c = TreeNode(id: id + "/" + name, name: name, insideArchive: insideArchive)
        childIndex[name] = c
        children.append(c)
        return c
    }

    @discardableResult
    func computeWorst() -> Verdict {
        var w = ownVerdict ?? .clean
        for c in children { w = max(w, c.computeWorst()) }
        worst = w
        return w
    }

    func sortChildren() {
        children.sort { a, b in
            if a.children.isEmpty != b.children.isEmpty { return !a.children.isEmpty }
            return a.name.localizedStandardCompare(b.name) == .orderedAscending
        }
        children.forEach { $0.sortChildren() }
    }

    static func build(_ entries: [TreeEntry]) -> TreeNode {
        let root = TreeNode(id: "", name: "", insideArchive: false)
        for e in entries {
            var node = root
            let archiveParts = e.path.components(separatedBy: ">>")
            for (ai, part) in archiveParts.enumerated() {
                for comp in part.split(separator: "/") {
                    node = node.child(String(comp), insideArchive: ai > 0)
                }
            }
            node.size = e.size
            node.ownVerdict = e.verdict
        }
        root.computeWorst()
        root.sortChildren()
        return root
    }
}

private struct SandboxTreeView: View {
    var entries: [TreeEntry]
    @State private var root: TreeNode
    @State private var expanded: Set<String>
    @Environment(\.snapshotMode) private var snapshot

    init(entries: [TreeEntry]) {
        self.entries = entries
        let tree = TreeNode.build(entries)
        _root = State(initialValue: tree)
        _expanded = State(initialValue: Self.initialExpanded(tree, count: entries.count))
    }

    private struct Row: Identifiable {
        let node: TreeNode
        let depth: Int
        var id: String { node.id }
    }

    private func rows(_ root: TreeNode) -> [Row] {
        var out: [Row] = []
        func walk(_ n: TreeNode, _ d: Int) {
            for c in n.children {
                out.append(Row(node: c, depth: d))
                if !c.children.isEmpty, expanded.contains(c.id) { walk(c, d + 1) }
            }
        }
        walk(root, 0)
        return out
    }

    var body: some View {
        let tree = root
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle(title: "Zawartość archiwum", subtitle: "Rozpakowane drzewo z werdyktem każdego pliku", icon: "list.bullet.indent",
                         trailing: AnyView(HStack(spacing: 6) {
                             Button("Rozwiń wszystko") { expanded = allDirs(tree) }
                                 .buttonStyle(SecondaryButtonStyle(compact: true))
                             Button("Zwiń") { expanded = [] }
                                 .buttonStyle(SecondaryButtonStyle(compact: true))
                         }))
            if entries.isEmpty {
                Text("Brak listy plików.").font(.system(size: 12)).foregroundStyle(.secondary)
            } else {
                let visible = rows(tree)
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array((snapshot ? Array(visible.prefix(22)) : visible).enumerated()), id: \.element.id) { idx, row in
                        treeRow(row, odd: idx % 2 == 1)
                    }
                }
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Palette.subtle.opacity(0.35)))
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                if entries.count >= 2000 {
                    Text("Pokazano pierwsze 2000 pozycji – pełna lista jest w raporcie HTML.")
                        .font(.system(size: 11.5)).foregroundStyle(.secondary)
                }
            }
        }
        .card(padding: 16, radius: 18)
    }

    private static func allDirs(_ n: TreeNode) -> Set<String> {
        var s = Set<String>()
        func walk(_ n: TreeNode) { for c in n.children where !c.children.isEmpty { s.insert(c.id); walk(c) } }
        walk(n)
        return s
    }

    private func allDirs(_ n: TreeNode) -> Set<String> { Self.allDirs(n) }

    private static func initialExpanded(_ n: TreeNode, count: Int) -> Set<String> {
        if count <= 60 { return allDirs(n) }
        var s = Set<String>()
        func walk(_ n: TreeNode, _ d: Int) {
            for c in n.children where !c.children.isEmpty {
                if d == 0 || c.worst > .clean { s.insert(c.id); walk(c, d + 1) }
            }
        }
        walk(n, 0)
        return s
    }

    private func treeRow(_ row: Row, odd: Bool) -> some View {
        let n = row.node
        let isDir = !n.children.isEmpty
        let isArchive = isDir && n.ownVerdict != nil
        return Button {
            guard isDir else { return }
            withAnimation(.easeInOut(duration: 0.18)) {
                if expanded.contains(n.id) { expanded.remove(n.id) } else { expanded.insert(n.id) }
            }
        } label: {
            HStack(spacing: 6) {
                Color.clear.frame(width: CGFloat(row.depth) * 18, height: 1)
                Image(systemName: "chevron.right")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(.secondary)
                    .rotationEffect(.degrees(expanded.contains(n.id) ? 90 : 0))
                    .opacity(isDir ? 1 : 0)
                    .frame(width: 12)
                Image(systemName: isArchive ? "archivebox.fill" : (isDir ? "folder.fill" : fileIcon(n.name)))
                    .font(.system(size: 12))
                    .foregroundStyle(isArchive ? Palette.orange : (isDir ? Palette.blue : Color.secondary))
                    .frame(width: 18)
                Text(n.name)
                    .font(.system(size: 12, weight: n.worst >= .suspicious ? .semibold : .regular))
                    .foregroundStyle(n.ownVerdict.map { $0 >= .suspicious } == true ? n.worst.color : Color.primary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if n.insideArchive {
                    Text("w archiwum").font(.system(size: 9.5, weight: .medium)).foregroundStyle(.tertiary)
                }
                Spacer(minLength: 8)
                if let s = n.size {
                    Text(Fmt.bytes(s)).font(.system(size: 11)).foregroundStyle(.secondary).monospacedDigit()
                }
                if n.worst > .clean {
                    HStack(spacing: 4) {
                        Dot(color: n.worst.color, size: 7)
                        Text(isDir && n.ownVerdict == nil ? "zawiera: " + n.worst.badge.lowercased() : n.worst.badge)
                            .font(.system(size: 10.5, weight: .semibold))
                            .foregroundStyle(n.worst.color)
                    }
                    .frame(width: 128, alignment: .trailing)
                } else {
                    HStack(spacing: 4) {
                        Dot(color: Palette.green.opacity(0.7), size: 6)
                    }
                    .frame(width: 128, alignment: .trailing)
                }
            }
            .padding(.vertical, 5)
            .padding(.horizontal, 10)
            .background(odd ? Palette.subtle.opacity(0.55) : Color.clear)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func fileIcon(_ name: String) -> String {
        let ext = (name as NSString).pathExtension.lowercased()
        switch ext {
        case "png", "jpg", "jpeg", "gif", "icns", "svg", "heic": return "photo"
        case "sh", "py", "js", "rb", "pl", "php", "ps1", "command": return "terminal"
        case "pdf": return "doc.richtext"
        case "txt", "md", "rtf": return "doc.text"
        case "json", "plist", "yml", "yaml", "xml": return "curlybraces"
        case "aiff", "mp3", "wav", "m4a": return "waveform"
        case "otf", "ttf": return "textformat"
        default: return "doc"
        }
    }
}

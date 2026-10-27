import AppKit
import Observation
import SwiftUI

// MARK: - Model ("iPhone (kabel)")

/// Device list and one iPhone/backup check at a time (`gui_backend iphone …`). Independent from the main scan
/// session; nothing starts by itself – the list is read when the screen opens, a check only after a click.
@Observable
final class IPhoneModel {
    enum Phase: Equatable {
        case idle, running, cancelling, finished
        case failed(String)
    }

    let config: BackendConfig
    var listState: LoadState = .idle
    var info: IPhoneDevicesInfo?
    var phase: Phase = .idle
    var scanTitle = ""
    var makingBackup = false
    var stage: String?
    var stageTitles: [String: String] = [:]
    var visited: [String] = []
    var progress: [String: ProgressEvent] = [:]
    var liveFindings: [IPhoneFinding] = []
    var summary: IPhoneSummary?
    var log: [String] = []
    var startedAt: Date?
    /// Confirmation dialog before a new backup (size/time warning).
    var pendingBackup: IPhoneDevice?

    @ObservationIgnored private var listProcess: BackendProcess?
    @ObservationIgnored private var scanProcess: BackendProcess?

    init(config: BackendConfig) {
        self.config = config
    }

    var isRunning: Bool { phase == .running || phase == .cancelling }

    var expectedStages: [String] {
        (scanTitle.isEmpty ? [] : ["device"]) + (makingBackup ? ["backup"] : []) + ["sandbox", "analyze", "report"]
    }

    // MARK: device list

    func refresh() {
        guard listProcess == nil else { return }
        listState = .loading
        let p = BackendProcess(config: config, arguments: ["iphone", "devices"])
        var got = false
        p.onEvents = { [weak self] events in
            for e in events { if self?.apply(e) == true { got = true } }
        }
        p.onExit = { [weak self] code in
            guard let self else { return }
            self.listProcess = nil
            if !got { self.listState = .failed("Nie udało się odczytać listy urządzeń (kod \(code)).") }
        }
        do {
            try p.start()
            listProcess = p
        } catch {
            listState = .failed(error.localizedDescription)
        }
    }

    // MARK: checks

    func scanDevice(_ d: IPhoneDevice, makeBackup: Bool) {
        if d.readable {
            start(["iphone", "scan", d.udid] + (makeBackup ? ["--make-backup"] : []), title: d.title, backup: makeBackup)
        } else if let b = d.backup {
            scanBackup(b.path, title: d.title)
        }
    }

    func scanBackup(_ path: String, title: String? = nil) {
        start(["iphone", "backup", path], title: title ?? (path as NSString).lastPathComponent, backup: false,
              device: false)
    }

    func chooseBackup() {
        guard !isRunning else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Sprawdź kopię"
        panel.message = "Wskaż folder kopii zapasowej iPhone'a (ten z plikami Manifest.plist i Info.plist)"
        let ms = (NSHomeDirectory() as NSString).appendingPathComponent("Library/Application Support/MobileSync/Backup")
        if FileManager.default.fileExists(atPath: ms) { panel.directoryURL = URL(fileURLWithPath: ms) }
        if panel.runModal() == .OK, let url = panel.url {
            scanBackup(url.path)
        }
    }

    private func start(_ args: [String], title: String, backup: Bool, device: Bool = true) {
        guard !isRunning else { return }
        scanTitle = device ? title : ""
        makingBackup = backup
        stage = nil
        stageTitles = [:]
        visited = []
        progress = [:]
        liveFindings = []
        summary = nil
        log = []
        startedAt = Date()
        phase = .running
        if !device { scanTitle = "" }
        let p = BackendProcess(config: config, arguments: args)
        p.onEvents = { [weak self] events in
            withAnimation(.spring(response: 0.45, dampingFraction: 0.85)) {
                for e in events { _ = self?.apply(e) }
            }
        }
        p.onStderr = { [weak self] lines in self?.appendLog(lines) }
        p.onExit = { [weak self] code in
            guard let self else { return }
            self.scanProcess = nil
            if self.summary != nil {
                self.phase = .finished
                NSApp?.requestUserAttention(.informationalRequest)
            } else if case .failed = self.phase {
            } else if code == 130 || self.phase == .cancelling {
                self.phase = .failed("Sprawdzanie przerwane.")
            } else {
                self.phase = .failed("Sprawdzanie zakończyło się bez wyników (kod \(code)).")
            }
            self.refresh()
        }
        do {
            try p.start()
            scanProcess = p
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    private func appendLog(_ lines: [String]) {
        log.append(contentsOf: lines)
        if log.count > 600 { log.removeFirst(log.count - 600) }
    }

    func cancel() {
        guard let p = scanProcess, isRunning else { return }
        if phase == .cancelling { p.terminate(); return }
        phase = .cancelling
        p.interrupt()
        DispatchQueue.main.asyncAfter(deadline: .now() + 25) { [weak p] in
            if let p, p.isRunning { p.terminate() }
        }
    }

    func reset() {
        guard !isRunning else { return }
        withAnimation(.easeInOut(duration: 0.25)) {
            phase = .idle
            summary = nil
        }
    }

    /// App quit: stop the running check (a backup being made by the system tool is interrupted too).
    func shutdown() {
        let running = [scanProcess, listProcess].compactMap { $0 }.filter(\.isRunning)
        running.forEach { $0.interrupt() }
        let deadline = Date().addingTimeInterval(3)
        while running.contains(where: \.isRunning) && Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        running.forEach { $0.terminate() }
    }

    /// Applies one backend event; true when it was the device list. Used by the app, snapshots and the self-test.
    @discardableResult
    func apply(_ e: BackendEvent) -> Bool {
        switch e {
        case .iphone(let name, let j):
            switch name {
            case "iphone_devices":
                info = IPhoneDevicesInfo(j)
                listState = .loaded
                return true
            case "iphone_finding":
                let f = IPhoneFinding(j["item"], index: liveFindings.count)
                if let i = liveFindings.firstIndex(where: { $0.id == f.id }) { liveFindings[i] = f } else { liveFindings.append(f) }
            case "iphone_done":
                summary = IPhoneSummary(j["summary"])
                phase = .finished
            default: break
            }
        case .stage(let id, let title):
            stageTitles[id] = title
            if !visited.contains(id) { visited.append(id) }
            stage = id
            log.append("▸ " + title)
        case .progress(let p):
            progress[p.stage] = p
        case .log(let m):
            log.append(m)
        case .error(let msg, let fatal):
            log.append((fatal ? "BŁĄD: " : "Uwaga: ") + msg)
            if fatal { phase = .failed(msg) }
        default:
            break
        }
        return false
    }

    func fraction(_ stage: String) -> Double? {
        guard let p = progress[stage], let t = p.total, t > 0, let d = p.done else { return nil }
        return min(1, max(0, Double(d) / Double(t)))
    }
}

// MARK: - Screen

struct IPhoneScreen: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let ip = model.iphone
        Group {
            switch ip.phase {
            case .running, .cancelling:
                IPhoneProgressView(ip: ip)
            case .finished:
                if let s = ip.summary { IPhoneResultsView(ip: ip, summary: s) } else { IPhoneHomeView(ip: ip) }
            case .failed(let msg):
                IPhoneFailureView(ip: ip, message: msg)
            case .idle:
                IPhoneHomeView(ip: ip)
            }
        }
        .animation(.easeInOut(duration: 0.3), value: ip.phase)
        .task { if ip.listState == .idle { ip.refresh() } }
    }
}

private struct IPhoneHomeView: View {
    @Environment(AppModel.self) private var model
    var ip: IPhoneModel
    @State private var makeBackup = false

    var body: some View {
        ScreenScaffold(item: .iphone,
                       subtitle: "Sprawdź iPhone'a podłączonego kablem pod kątem oprogramowania szpiegującego (Pegasus, Predator…) i aplikacji śledzących. Analiza działa lokalnie, w sandboksie – nic nie trafia do sieci, telefon nie jest zmieniany.") {
            if let info = ip.info {
                devicesSection(info)
                ForEach(info.notes, id: \.self) { n in
                    Banner(icon: n.contains("Pełny dostęp") ? "lock.shield" : "info.circle.fill",
                           title: n.contains("Pełny dostęp") ? "Potrzebny „Pełny dostęp do dysku”" :
                               n.hasPrefix("Brak narzędzi") ? "Brak narzędzi do odczytu telefonu" :
                               n.hasPrefix("Nie znaleziono kopii") ? "Brak kopii zapasowej" :
                               n.hasPrefix("Odblokuj") ? "Zaufaj temu Macowi" : "Wskazówka",
                           message: n, color: n.contains("Pełny dostęp") || n.hasPrefix("Odblokuj") ? Palette.orange : Palette.blue)
                }
                backupsSection(info)
                howItWorks(info)
            } else if case .failed(let msg) = ip.listState {
                Banner(icon: "exclamationmark.triangle.fill", title: "Nie udało się odczytać urządzeń", message: msg,
                       color: Palette.red, action: ("Spróbuj ponownie", { ip.refresh() }))
            } else {
                HStack(spacing: 10) {
                    Spinner(size: 16)
                    Text("Szukam podłączonych iPhone'ów i kopii zapasowych…").foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 120)
                .card()
            }
        }
        .alert("Utworzyć nową kopię zapasową?", isPresented: Binding(
            get: { ip.pendingBackup != nil }, set: { if !$0 { ip.pendingBackup = nil } }
        ), presenting: ip.pendingBackup) { d in
            Button("Utwórz kopię i sprawdź") { ip.scanDevice(d, makeBackup: true) }
            Button("Anuluj", role: .cancel) {}
        } message: { _ in
            Text(backupWarning)
        }
    }

    private var backupWarning: String {
        let free = ip.info?.backupFree.map { " Wolne miejsce na dysku: \(Fmt.bytes($0))." } ?? ""
        let whereTo = ip.info?.canBackup == "idevicebackup2"
            ? "Kopia trafi do folderu Cerbera (\(Fmt.tilde(ip.info?.backupDir ?? "iphone_backups"))) – możesz ją potem usunąć."
            : "Kopia trafi tam, gdzie robi ją Finder (MobileSync)."
        return "Pełna kopia iPhone'a może zająć dziesiątki GB i potrwać od kilku minut do ponad godziny.\(free) " +
            "\(whereTo) Na telefonie może pojawić się prośba o kod blokady – nie odłączaj kabla. Jeśli w Finderze włączone jest szyfrowanie kopii, " +
            "nowa kopia też będzie zaszyfrowana i Cerber sprawdzi tylko listę aplikacji."
    }

    @ViewBuilder
    private func devicesSection(_ info: IPhoneDevicesInfo) -> some View {
        SectionTitle(title: "Urządzenia", subtitle: info.devices.isEmpty ? nil : "Telefony podłączone teraz lub sparowane z tym Makiem",
                     icon: "iphone",
                     trailing: AnyView(Button { ip.refresh() } label: { Label("Odśwież", systemImage: "arrow.clockwise") }
                        .buttonStyle(SecondaryButtonStyle(compact: true)).disabled(ip.listState == .loading)))
        if info.devices.isEmpty {
            EmptyState(icon: "iphone.slash", title: "Nie wykryto iPhone'a",
                       message: "Podłącz iPhone'a kablem USB, odblokuj go i stuknij „Zaufaj”, a potem kliknij „Odśwież”. Możesz też sprawdzić istniejącą kopię zapasową poniżej.",
                       color: Palette.gray)
        } else {
            ForEach(info.devices) { d in deviceCard(d, info) }
        }
    }

    private func deviceCard(_ d: IPhoneDevice, _ info: IPhoneDevicesInfo) -> some View {
        let canScan = d.readable || d.backup != nil
        let stateColor = d.connected ? (d.trusted == false ? Palette.orange : Palette.green) : Palette.gray
        return VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 14) {
                IconTile(systemName: "iphone", colors: [Color(hex: 0x0EA5E9), Color(hex: 0x6366F1)], size: 50)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(d.title).font(.system(size: 17, weight: .semibold))
                        Pill(text: d.stateLabel, color: stateColor, icon: d.connected ? "cable.connector" : "moon.zzz")
                    }
                    Text([d.model, d.ios.map { "iOS \($0)" }].compactMap { $0 }.joined(separator: " · "))
                        .font(.system(size: 12.5)).foregroundStyle(.secondary)
                    if let b = d.backup {
                        HStack(spacing: 6) {
                            Image(systemName: "externaldrive.badge.checkmark").font(.system(size: 11))
                            Text("Ostatnia kopia: \(Fmt.dateTime(b.date)) · \(b.sourceLabel)")
                            if b.encrypted { Pill(text: "zaszyfrowana", color: Palette.orange, icon: "lock.fill") }
                        }
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                    } else {
                        Text("Brak kopii zapasowej tego telefonu na Macu").font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 0)
            }
            if backupAllowed(d, info) {
                Toggle(isOn: $makeBackup) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Najpierw zrób nową kopię zapasową").font(.system(size: 13, weight: .semibold))
                        Text("Najdokładniej: wiadomości, Safari, profile i statystyki sieci są tylko w kopii. Może zająć dziesiątki GB i do godziny.")
                            .font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
                .toggleStyle(SwitchToggleStyle())
            }
            HStack(spacing: 12) {
                Text(scanNote(d)).font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                Button {
                    if makeBackup && backupAllowed(d, info) { ip.pendingBackup = d } else { ip.scanDevice(d, makeBackup: false) }
                } label: {
                    Label("Przeskanuj iPhone'a", systemImage: "checkmark.shield").padding(.horizontal, 6)
                }
                .buttonStyle(PrimaryButtonStyle(large: true, colors: [Color(hex: 0x0EA5E9), Color(hex: 0x6366F1)]))
                .disabled(!canScan || ip.isRunning)
            }
        }
        .card(padding: 18, radius: 18)
    }

    /// A new backup only when a tool exists and Cerber could read the result (Finder's folder needs Full Disk Access).
    private func backupAllowed(_ d: IPhoneDevice, _ info: IPhoneDevicesInfo) -> Bool {
        d.readable && info.canBackup != nil && !(info.canBackup == "apple" && info.mobilesync == "denied")
    }

    private func scanNote(_ d: IPhoneDevice) -> String {
        if d.readable {
            return d.backup != nil || makeBackup
                ? "Cerber odczyta dane z telefonu (aplikacje, raporty awarii) i przeanalizuje \(makeBackup ? "nową" : "ostatnią") kopię zapasową."
                : "Cerber odczyta dane z telefonu (aplikacje, raporty awarii). Bez kopii zapasowej analiza będzie niepełna."
        }
        if d.backup != nil { return "Telefon nie jest teraz podłączony – sprawdzę jego ostatnią kopię zapasową." }
        return "Podłącz telefon kablem i stuknij na nim „Zaufaj”, aby go sprawdzić."
    }

    @ViewBuilder
    private func backupsSection(_ info: IPhoneDevicesInfo) -> some View {
        SectionTitle(title: "Kopie zapasowe na tym Macu", subtitle: "Sprawdź istniejącą kopię – bez podłączania telefonu",
                     icon: "externaldrive",
                     trailing: AnyView(Button { ip.chooseBackup() } label: { Label("Wybierz kopię…", systemImage: "folder") }
                        .buttonStyle(SecondaryButtonStyle(compact: true)).disabled(ip.isRunning)))
        if info.backups.isEmpty {
            Text(info.mobilesync == "denied"
                 ? "Kopie z Findera są niewidoczne bez „Pełnego dostępu do dysku”. Możesz wskazać folder kopii przyciskiem „Wybierz kopię…”."
                 : "Brak kopii. Zrób ją w Finderze (iPhone → „Utwórz kopię zapasową teraz”), najlepiej bez szyfrowania.")
                .font(.system(size: 12.5)).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .card(padding: 16, radius: 14)
        } else {
            VStack(spacing: 0) {
                ForEach(Array(info.backups.enumerated()), id: \.element.id) { i, b in
                    if i > 0 { Divider() }
                    HStack(spacing: 12) {
                        SoftIcon(systemName: b.encrypted ? "lock.doc" : "doc.on.doc", color: b.encrypted ? Palette.orange : Palette.brand, size: 34)
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Text(b.title).font(.system(size: 13.5, weight: .semibold))
                                if b.encrypted { Pill(text: "zaszyfrowana – tylko lista aplikacji", color: Palette.orange, icon: "lock.fill") }
                                if !b.complete { Pill(text: "niedokończona", color: Palette.orange) }
                            }
                            Text([Fmt.dateTime(b.date), b.model, b.ios.map { "iOS \($0)" }, b.sourceLabel].compactMap { $0 }.joined(separator: " · "))
                                .font(.system(size: 11.5)).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Sprawdź tę kopię") { ip.scanBackup(b.path, title: b.title) }
                            .buttonStyle(SecondaryButtonStyle(compact: true))
                            .disabled(ip.isRunning)
                    }
                    .padding(.vertical, 10)
                }
            }
            .card(padding: 14, radius: 16)
        }
    }

    private func howItWorks(_ info: IPhoneDevicesInfo) -> some View {
        HStack(alignment: .top, spacing: 14) {
            FeatureTile(icon: "externaldrive.badge.checkmark", title: "Analiza kopii jak MVT",
                        text: "SMS/iMessage, Safari, WhatsApp, statystyki sieci procesów, konta iMessage, uprawnienia, profile MDM.")
            FeatureTile(icon: "eye.trianglebadge.exclamationmark",
                        title: "\(Fmt.int(info.indicatorsTotal)) wskaźników iOS",
                        text: info.sources.isEmpty ? "Baza wskaźników nie jest zbudowana – uruchom ./cerber.sh update --only-ios."
                            : "Pegasus, Predator, Triangulation, stalkerware – " + info.sources.map(\.name).joined(separator: ", ") + ".")
            FeatureTile(icon: "lock.shield", title: "Bezpiecznie",
                        text: "Dane z telefonu analizowane w sandboksie, bez sieci. Kopia i telefon nie są zmieniane.")
        }
    }
}

// MARK: - Progress

private struct IPhoneProgressView: View {
    var ip: IPhoneModel

    private var stages: [String] { ip.visited + ip.expectedStages.filter { !ip.visited.contains($0) } }

    private func title(_ id: String) -> String {
        switch id {
        case "device": return "Odczyt z telefonu"
        case "backup": return "Kopia zapasowa"
        case "sandbox": return "Sandbox"
        case "analyze": return "Analiza"
        case "report": return "Raport"
        default: return Stage.shortTitle(id)
        }
    }

    private var currentFraction: Double? {
        guard let s = ip.stage else { return nil }
        return ip.fraction(s)
    }

    var body: some View {
        AdaptiveScroll {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 26) {
                    ZStack {
                        ProgressRing(fraction: currentFraction, colors: [Color(hex: 0x0EA5E9), Color(hex: 0x6366F1)])
                        VStack(spacing: 2) {
                            Image(systemName: "iphone").font(.system(size: 30, weight: .semibold)).foregroundStyle(Palette.brand)
                            if let f = currentFraction {
                                Text(Fmt.percent(f)).font(.system(size: 15, weight: .semibold, design: .rounded)).monospacedDigit()
                            }
                        }
                    }
                    .frame(width: 150, height: 150)
                    VStack(alignment: .leading, spacing: 6) {
                        Text(ip.phase == .cancelling ? "Przerywanie…" : (ip.stage.flatMap { ip.stageTitles[$0] } ?? "Przygotowanie…"))
                            .font(.system(size: 22, weight: .bold, design: .rounded))
                        if let s = ip.stage, let cur = ip.progress[s]?.current {
                            Text(cur).font(.system(size: 13)).foregroundStyle(.secondary).lineLimit(2)
                        }
                        if ip.stage == "backup", let p = ip.progress["backup"] {
                            Text("Skopiowano \(Fmt.bytes(p.bytes ?? 0)) · nie odłączaj kabla i nie blokuj telefonu w trakcie")
                                .font(.system(size: 12)).foregroundStyle(.secondary)
                        }
                        if let t = ip.startedAt {
                            Text("Czas: \(Fmt.duration(Date().timeIntervalSince(t)))").font(.system(size: 12)).foregroundStyle(.tertiary)
                        }
                        HStack(spacing: 10) {
                            Button(ip.phase == .cancelling ? "Zatrzymaj natychmiast" : "Przerwij") { ip.cancel() }
                                .buttonStyle(SecondaryButtonStyle(tint: Palette.red))
                                .keyboardShortcut(".", modifiers: .command)
                            SandboxBadge()
                        }
                        .padding(.top, 4)
                    }
                    Spacer(minLength: 0)
                }
                .card(padding: 22, radius: 22)
                HStack(spacing: 8) {
                    ForEach(stages, id: \.self) { s in
                        let done = ip.visited.contains(s) && s != ip.stage
                        let active = s == ip.stage
                        HStack(spacing: 6) {
                            Image(systemName: done ? "checkmark.circle.fill" : active ? "circle.dotted.circle" : "circle")
                                .foregroundStyle(done ? Palette.green : active ? Palette.brand : Color.secondary)
                            Text(title(s)).font(.system(size: 12, weight: active ? .semibold : .regular))
                        }
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .background(Capsule().fill(active ? Palette.brand.opacity(0.12) : Palette.subtle))
                    }
                }
                if !ip.liveFindings.isEmpty {
                    SectionTitle(title: "Znalezione do tej pory", subtitle: Fmt.count(ip.liveFindings.count, "znalezisko", "znaleziska", "znalezisk"),
                                 icon: "exclamationmark.triangle")
                    ForEach(ip.liveFindings) { f in IPhoneFindingRow(finding: f, expanded: false) }
                }
                if !ip.log.isEmpty {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(Array(ip.log.suffix(8).enumerated()), id: \.offset) { _, l in
                            Text(l).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .card(padding: 14, radius: 14)
                }
            }
            .padding(.horizontal, 36).padding(.vertical, 30)
            .frame(maxWidth: 1080).frame(maxWidth: .infinity)
        }
        .background(Palette.canvas)
    }
}

// MARK: - Results

private struct IPhoneResultsView: View {
    var ip: IPhoneModel
    var summary: IPhoneSummary

    private var headline: String {
        let serious = summary.serious.count
        if summary.coverage == "none" && serious == 0 {
            return "Za mało danych do oceny: nie było kopii zapasowej, a telefon nie udostępnił listy aplikacji. Zrób kopię (bez szyfrowania) i sprawdź ponownie."
        }
        if summary.coverage == "partial" && summary.findings.isEmpty {
            return "Nic nie znaleziono w dostępnych danych – sprawdzenie było niepełne (zobacz ograniczenia poniżej)."
        }
        if summary.findings.isEmpty { return "Nie znaleziono śladów oprogramowania szpiegującego ani aplikacji śledzących." }
        if serious == 0 { return "Brak poważnych zagrożeń – \(Fmt.count(summary.findings.count, "drobna uwaga", "drobne uwagi", "drobnych uwag"))." }
        return "\(Fmt.count(serious, "poważne znalezisko", "poważne znaleziska", "poważnych znalezisk")) – przeczytaj, co zrobić."
    }

    var body: some View {
        AdaptiveScroll {
            VStack(alignment: .leading, spacing: 18) {
                hero
                if summary.cancelled {
                    Banner(icon: "stop.circle.fill", title: "Sprawdzanie zostało przerwane", message: "To wyniki częściowe.", color: Palette.orange)
                }
                ForEach(summary.limitations, id: \.self) { l in
                    Banner(icon: l.contains("zaszyfrowana") ? "lock.doc" : "info.circle", title: l.contains("zaszyfrowana") ? "Kopia zaszyfrowana" : "Ograniczenie",
                           message: l, color: l.contains("zaszyfrowana") ? Palette.orange : Palette.blue)
                }
                HStack(spacing: 12) {
                    StatTile(icon: "iphone", label: "Urządzenie", value: summary.deviceModel ?? summary.deviceName ?? "—")
                    StatTile(icon: "gearshape", label: "iOS", value: summary.ios ?? "—")
                    StatTile(icon: "externaldrive", label: "Kopia z", value: summary.backup.map { Fmt.shortDate($0.date) } ?? "brak")
                    StatTile(icon: "square.grid.3x3", label: "Aplikacje", value: Fmt.int(summary.appsTotal))
                    StatTile(icon: summary.lockdownMode == true ? "lock.fill" : "lock.open", label: "Tryb blokady",
                             value: summary.lockdownMode.map { $0 ? "włączony" : "wyłączony" } ?? "—",
                             tint: summary.lockdownMode == true ? Palette.green : Palette.brand)
                }
                if !summary.advice.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionTitle(title: "Co zrobić", icon: "list.number")
                        ForEach(Array(summary.advice.enumerated()), id: \.offset) { i, a in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text("\(i + 1).").font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Palette.brand)
                                Text(a).font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    .card(padding: 18, radius: 18)
                }
                SectionTitle(title: "Znaleziska", subtitle: summary.findings.isEmpty ? "Brak" : Fmt.count(summary.findings.count, "pozycja", "pozycje", "pozycji"),
                             icon: "exclamationmark.triangle")
                if summary.findings.isEmpty {
                    EmptyState(icon: "checkmark.shield.fill", title: "Czysto",
                               message: "Żaden z \(Fmt.int(summary.indicatorsTotal)) wskaźników iOS nie pasuje do danych z telefonu i kopii, heurystyki też niczego nie wskazały.")
                } else {
                    ForEach(Array(summary.findings.enumerated()), id: \.element.id) { i, f in
                        IPhoneFindingRow(finding: f, expanded: i == 0 && f.severity.rank >= Severity.suspicious.rank)
                    }
                }
                SectionTitle(title: "Co sprawdzono", icon: "checklist")
                VStack(spacing: 0) {
                    ForEach(Array(summary.checks.enumerated()), id: \.element.id) { i, c in
                        if i > 0 { Divider() }
                        HStack(spacing: 10) {
                            Image(systemName: checkIcon(c.status)).foregroundStyle(checkColor(c.status)).frame(width: 18)
                            Text(c.title).font(.system(size: 12.5, weight: .medium))
                            Spacer()
                            Text(c.detail ?? c.statusLabel).font(.system(size: 11.5)).foregroundStyle(.secondary).lineLimit(1)
                        }
                        .padding(.vertical, 7)
                    }
                }
                .card(padding: 14, radius: 16)
            }
            .padding(.horizontal, 32).padding(.vertical, 26)
            .frame(maxWidth: 1180).frame(maxWidth: .infinity)
        }
        .background(Palette.canvas)
    }

    private var hero: some View {
        let v = summary.coverage == "none" && summary.serious.isEmpty ? Verdict.info : summary.verdict
        return HStack(spacing: 20) {
            Image(systemName: v.heroIcon).font(.system(size: 46, weight: .semibold)).foregroundStyle(.white)
            VStack(alignment: .leading, spacing: 6) {
                Label(summary.title.isEmpty ? "iPhone" : summary.title, systemImage: "iphone")
                    .font(.system(size: 13, weight: .semibold)).foregroundStyle(.white.opacity(0.85))
                Text(summary.coverage == "none" && summary.serious.isEmpty ? "Niewiele do sprawdzenia" : v.heroTitle)
                    .font(.system(size: 30, weight: .bold, design: .rounded)).foregroundStyle(.white)
                Text(headline).font(.system(size: 14)).foregroundStyle(.white.opacity(0.92))
                HStack(spacing: 10) {
                    if let html = summary.reportHTML {
                        Button { ReportViewer.open(html) } label: { Label("Otwórz raport", systemImage: "doc.richtext") }
                            .buttonStyle(HeroButtonStyle())
                    }
                    if let b = summary.backup, FinderActions.exists(b.path) {
                        Button { FinderActions.reveal(b.path) } label: { Label("Pokaż kopię w Finderze", systemImage: "folder") }
                            .buttonStyle(HeroButtonStyle())
                    }
                    Button { ip.reset() } label: { Label("Nowe sprawdzenie", systemImage: "arrow.counterclockwise") }
                        .buttonStyle(HeroButtonStyle())
                    SandboxBadge(onColor: true)
                }
                .padding(.top, 4)
            }
            Spacer(minLength: 0)
        }
        .padding(26)
        .background(RoundedRectangle(cornerRadius: 24, style: .continuous)
            .fill(LinearGradient(colors: v.heroColors, startPoint: .topLeading, endPoint: .bottomTrailing))
            .shadow(color: v.heroColors[0].opacity(0.35), radius: 20, y: 8))
    }

    private func checkIcon(_ s: String) -> String {
        switch s {
        case "ok": return "checkmark.circle.fill"
        case "found": return "exclamationmark.circle.fill"
        case "error": return "xmark.octagon.fill"
        case "skipped": return "lock.circle"
        default: return "minus.circle"
        }
    }

    private func checkColor(_ s: String) -> Color {
        switch s {
        case "ok": return Palette.green
        case "found", "skipped": return Palette.orange
        case "error": return Palette.red
        default: return Palette.gray
        }
    }
}

struct IPhoneFindingRow: View {
    var finding: IPhoneFinding
    @State private var open: Bool

    init(finding: IPhoneFinding, expanded: Bool) {
        self.finding = finding
        _open = State(initialValue: expanded)
    }

    var body: some View {
        let f = finding
        VStack(alignment: .leading, spacing: 10) {
            Button {
                withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) { open.toggle() }
            } label: {
                HStack(alignment: .top, spacing: 12) {
                    SoftIcon(systemName: f.icon, color: f.severity.color, size: 34)
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 8) {
                            Pill(text: f.severity.label, color: f.severity.color, filled: f.severity.rank >= Severity.suspicious.rank)
                            Text("\(f.score) pkt").font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        Text(f.title).font(.system(size: 14, weight: .semibold)).multilineTextAlignment(.leading)
                        if let loc = f.location {
                            Text(loc).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                    Spacer()
                    Image(systemName: "chevron.right").font(.system(size: 11, weight: .bold)).foregroundStyle(.secondary)
                        .rotationEffect(.degrees(open ? 90 : 0))
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if open {
                VStack(alignment: .leading, spacing: 10) {
                    if let d = f.description {
                        Text(d).font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true)
                    }
                    if !f.evidence.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Dowody").font(.system(size: 11.5, weight: .semibold)).foregroundStyle(.secondary)
                            ForEach(Array(f.evidence.prefix(12).enumerated()), id: \.offset) { _, e in
                                Text(e).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            if f.evidenceTotal > 12 {
                                Text("… i \(f.evidenceTotal - 12) więcej (pełna lista w raporcie)").font(.system(size: 11)).foregroundStyle(.secondary)
                            }
                        }
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Palette.subtle))
                    }
                    if !f.advice.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Co zrobić").font(.system(size: 11.5, weight: .semibold)).foregroundStyle(.secondary)
                            ForEach(f.advice, id: \.self) { a in
                                HStack(alignment: .firstTextBaseline, spacing: 6) {
                                    Image(systemName: "arrow.right.circle.fill").font(.system(size: 10)).foregroundStyle(Palette.brand)
                                    Text(a).font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
                                }
                            }
                        }
                    }
                }
                .padding(.leading, 46)
                .transition(.opacity)
            }
        }
        .card(padding: 16, radius: 16)
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous)
            .strokeBorder(f.severity.rank >= Severity.suspicious.rank ? f.severity.color.opacity(0.35) : Color.clear, lineWidth: 1))
    }
}

private struct IPhoneFailureView: View {
    var ip: IPhoneModel
    var message: String

    var body: some View {
        AdaptiveScroll {
            VStack(alignment: .leading, spacing: 18) {
                Banner(icon: "exclamationmark.octagon.fill", title: "Nie udało się sprawdzić iPhone'a", message: message,
                       color: Palette.red, action: ("Wróć", { ip.reset() }))
                if !ip.log.isEmpty {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(Array(ip.log.suffix(20).enumerated()), id: \.offset) { _, l in
                            Text(l).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .card(padding: 14, radius: 14)
                }
            }
            .padding(.horizontal, 36).padding(.vertical, 30)
            .frame(maxWidth: 1080).frame(maxWidth: .infinity)
        }
        .background(Palette.canvas)
    }
}

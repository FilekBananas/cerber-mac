import AppKit
import SwiftUI

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            Sidebar()
                .navigationSplitViewColumnWidth(min: 220, ideal: 240, max: 300)
        } detail: {
            DetailView()
                .navigationTitle(model.selection?.title ?? "Cerber")
                .navigationSubtitle(model.config.mock ? "tryb demonstracyjny" : "")
        }
        .frame(minWidth: 1000, minHeight: 680)
        .alert(item: $model.alert) { a in
            Alert(title: Text(a.title), message: Text(a.message), dismissButton: .default(Text("OK")))
        }
        .task {
            model.loadInfo()
            model.loadHistory()
            model.api.startIfPreferred()
            model.protection.startIfPreferred()
            DemoRun.start(model: model)
        }
        .onChange(of: model.selection) { _, new in
            if new == .history { model.loadHistory() }
            if new == .session && model.session == nil { model.selection = .laptop }
        }
    }
}

struct DetailView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            switch model.selection ?? .laptop {
            case .session:
                if let s = model.session {
                    SessionScreen(session: s)
                } else {
                    LaptopScreen()
                }
            case .laptop: LaptopScreen()
            case .file: FileScreen()
            case .location: LocationScreen()
            case .sandbox: SandboxScreen()
            case .github: GitHubScreen()
            case .huggingface: HuggingFaceScreen()
            case .link: LinkScreen()
            case .iphone: IPhoneScreen()
            case .protection: ProtectionScreen()
            case .history: HistoryScreen()
            case .api: APIScreen()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Palette.canvas)
    }
}

struct SessionScreen: View {
    @Environment(AppModel.self) private var model
    var session: ScanSession

    var body: some View {
        Group {
            switch session.phase {
            case .running, .cancelling:
                ProgressScreen(session: session, expandLog: model.presentation.expandLog)
                    .transition(.opacity)
            case .finished:
                if let summary = session.summary {
                    ResultsScreen(session: session, summary: summary, initialTab: model.presentation.resultsTab,
                                  expandFirst: model.presentation.expandFirstResult,
                                  expandMatching: model.presentation.expandResultMatching)
                        .transition(.asymmetric(insertion: .opacity.combined(with: .scale(scale: 0.98)), removal: .opacity))
                } else {
                    FailureScreen(session: session)
                }
            case .failed:
                FailureScreen(session: session)
                    .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.35), value: session.phase)
    }
}

// MARK: - Sidebar (live)

struct Sidebar: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        List(selection: $model.selection) {
            if let s = model.session {
                Section("Bieżące") {
                    SessionSidebarRow(session: s, selected: model.selection == .session)
                        .tag(SidebarItem.session)
                }
            }
            Section("Skanowanie") {
                ForEach(SidebarItem.scanScreens) { item in
                    Label(item.title, systemImage: item.icon)
                        .tag(item)
                }
            }
            Section("Ochrona") {
                Label(SidebarItem.protection.title, systemImage: SidebarItem.protection.icon)
                    .tag(SidebarItem.protection)
            }
            Section("Raporty") {
                Label(SidebarItem.history.title, systemImage: SidebarItem.history.icon)
                    .tag(SidebarItem.history)
            }
            Section("Integracje") {
                Label(SidebarItem.api.title, systemImage: SidebarItem.api.icon)
                    .tag(SidebarItem.api)
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .top, spacing: 0) {
            BrandHeader().padding(.horizontal, 16).padding(.top, 6).padding(.bottom, 10)
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            DatabaseFooter().padding(12)
        }
    }
}

struct BrandHeader: View {
    var body: some View {
        HStack(spacing: 10) {
            Image(nsImage: IconCache.small)
                .resizable()
                .interpolation(.high)
                .frame(width: 38, height: 38)
            VStack(alignment: .leading, spacing: 0) {
                Text("Cerber").font(.system(size: 17, weight: .bold, design: .rounded))
                Text("skaner antywirusowy").font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
    }
}

struct SessionSidebarRow: View {
    var session: ScanSession
    var selected = false

    var body: some View {
        HStack(spacing: 8) {
            switch session.phase {
            case .running, .cancelling:
                Spinner(size: 13, lineWidth: 2, color: selected ? .white : Palette.brand)
                    .frame(width: 18)
            case .finished:
                Image(systemName: session.summary?.verdict.icon ?? "checkmark.circle.fill")
                    .symbolRenderingMode(.palette)
                    .foregroundStyle(selected ? Color.white : (session.summary?.verdict.color ?? Palette.green),
                                     selected ? (session.summary?.verdict.color ?? Palette.green) : Color.white)
                    .frame(width: 18)
            case .failed:
                Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(selected ? Color.white : Palette.red).frame(width: 18)
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(rowTitle).lineLimit(1)
                Text(rowSubtitle).font(.system(size: 11)).foregroundStyle(selected ? AnyShapeStyle(Color.white.opacity(0.8)) : AnyShapeStyle(.secondary)).lineLimit(1)
            }
            Spacer(minLength: 0)
            if session.isActive,
               let f = session.currentStage == "behavior" ? session.currentProgress?.fraction : session.scanProgress?.fraction {
                Text(Fmt.percent(f)).font(.system(size: 11, weight: .semibold)).monospacedDigit()
                    .foregroundStyle(selected ? AnyShapeStyle(Color.white.opacity(0.85)) : AnyShapeStyle(.secondary))
            }
        }
    }

    private var rowTitle: String {
        switch session.phase {
        case .running: return "Skanowanie w toku"
        case .cancelling: return "Przerywanie…"
        case .finished: return "Wyniki skanowania"
        case .failed(let c): return c ? "Przerwano" : "Błąd skanowania"
        }
    }

    private var rowSubtitle: String { session.request.title }
}

struct DatabaseFooter: View {
    @Environment(AppModel.self) private var model

    /// Exact count, so every added pattern shows ("7,2 mln" hid additions of a few thousand).
    static func label(_ info: DBInfo) -> String {
        "\(Fmt.int(info.patternsTotal)) wzorców · bazy z \(Fmt.shortDate(info.dbBuilt))"
    }

    static func breakdown(_ info: DBInfo) -> String {
        [("sygnatury ClamAV", info.clamavSignatures), ("reguły YARA", info.yaraRules),
         ("odciski plików (MalwareBazaar, ClamAV, Mac)", info.fileHashes), ("odciski sekcji programów", info.sectionHashes),
         ("adresy z list zagrożeń (ThreatFox, URLhaus)", info.iocIndicators)]
            .compactMap { name, n in n.map { "\(name): \(Fmt.int($0))" } }
            .joined(separator: "\n")
            + "\nData: ostatnia pełna aktualizacja (./cerber.sh update)"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let info = model.info {
                HStack(spacing: 6) {
                    Image(systemName: "cylinder.split.1x2.fill").foregroundStyle(Palette.brand)
                    Text(Self.label(info))
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                }
                .font(.system(size: 11, weight: .medium))
                .help(Self.breakdown(info))
                AIFooterStatus(info: info)
                if !info.missing.isEmpty {
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Palette.orange)
                        Text("Brakuje baz: \(info.missing.joined(separator: ", ")). Uruchom ./cerber.sh update.")
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .font(.system(size: 11))
                    .help(info.missing.joined(separator: "\n"))
                }
            } else {
                switch model.infoState {
                case .failed(let msg):
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Palette.orange)
                        Text("Nie udało się odczytać baz").font(.system(size: 11, weight: .medium))
                    }
                    .help(msg)
                default:
                    HStack(spacing: 6) {
                        Spinner(size: 10, lineWidth: 1.5)
                        Text("Odczytywanie baz…").font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                }
            }
            if model.config.mock || model.api.isRunning || model.protection.isRunning {
                FlowLayout(spacing: 6) {
                    if model.protection.isRunning {
                        Pill(text: "Ochrona w tle", color: model.protection.lastWasMalicious ? Palette.red : Palette.green,
                             icon: "shield.lefthalf.filled")
                            .help(model.protection.statusLine)
                    }
                    if model.api.isRunning {
                        Pill(text: "API :\(APIServer.port)", color: Palette.green, icon: "network")
                            .help("Lokalne API działa na \(model.api.baseURL)")
                    }
                    if model.config.mock {
                        Pill(text: model.api.isRunning ? "mock" : "tryb demonstracyjny (mock)", color: Palette.orange, icon: "theatermasks.fill")
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Palette.card.opacity(0.7)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Palette.cardBorder, lineWidth: 1))
    }

}

/// AI line of the sidebar footer: model, download progress, error with retry, missing engine.
struct AIFooterStatus: View {
    @Environment(AppModel.self) private var model
    var info: DBInfo

    var body: some View {
        Group {
            if let ai = info.aiModel, !model.aiInstall.isDownloading, model.aiInstall.failureMessage == nil {
                if info.llamaServer == false {
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Palette.orange)
                        Text("AI: brak silnika llama-server (brew install llama.cpp)")
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                    }
                    .help("Model \(ai) jest pobrany, ale do jego uruchomienia potrzebny jest llama-server z pakietu llama.cpp.")
                } else {
                    VStack(alignment: .leading, spacing: 5) {
                        HStack(spacing: 6) {
                            Image(systemName: "sparkles").foregroundStyle(Palette.brand)
                            Text("AI: \(Self.shortName(ai))").lineLimit(1).truncationMode(.middle)
                        }
                        .foregroundStyle(.secondary)
                        .help(ai)
                        if info.aiUpgradeAvailable, info.aiInstallable {
                            Button {
                                model.downloadAIModel()
                            } label: {
                                Label("Pobierz lepszy model AI\(Self.sizeSuffix(info))", systemImage: "arrow.down.circle")
                            }
                            .buttonStyle(SecondaryButtonStyle(tint: Palette.brand, compact: true))
                            .help("Nowy model \(Self.shortName(info.aiModelRecommended ?? "")) lepiej ocenia zarzuty wobec plików. "
                                  + "Pobieranie startuje dopiero po kliknięciu; obecny model zostaje na dysku.")
                        }
                    }
                }
            } else {
                switch model.aiInstall {
                case .downloading(let bytes, let total):
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Image(systemName: "arrow.down.circle.fill").foregroundStyle(Palette.brand)
                            Text(Self.progressText(bytes: bytes, total: total))
                                .lineLimit(1)
                                .minimumScaleFactor(0.8)
                                .monospacedDigit()
                        }
                        .foregroundStyle(.secondary)
                        LinearBar(fraction: model.aiInstall.fraction ?? 0, gradient: [Palette.brandA, Palette.brandB], height: 3)
                    }
                    .help("Model AI się pobiera (uruchomione przez Ciebie) – zamknięcie aplikacji je przerywa, kliknięcie „Pobierz” je wznowi.")
                case .failed(let msg):
                    VStack(alignment: .leading, spacing: 5) {
                        HStack(alignment: .top, spacing: 6) {
                            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Palette.red)
                            Text(msg).lineLimit(3).fixedSize(horizontal: false, vertical: true)
                        }
                        Button {
                            model.retryAIInstall()
                        } label: {
                            Label("Spróbuj ponownie", systemImage: "arrow.clockwise")
                        }
                        .buttonStyle(SecondaryButtonStyle(tint: Palette.brand, compact: true))
                    }
                    .help(msg)
                case .installed, .idle:
                    VStack(alignment: .leading, spacing: 5) {
                        HStack(spacing: 6) {
                            Image(systemName: "sparkles").foregroundStyle(Color.secondary)
                            Text("AI: model niepobrany").lineLimit(1)
                        }
                        .foregroundStyle(.secondary)
                        if info.aiInstallable {
                            Button {
                                model.downloadAIModel()
                            } label: {
                                Label(((info.aiDownloadPartial ?? 0) > 0 ? "Wznów pobieranie modelu AI" : "Pobierz model AI")
                                      + Self.sizeSuffix(info), systemImage: "arrow.down.circle")
                            }
                            .buttonStyle(SecondaryButtonStyle(tint: Palette.brand, compact: true))
                            .help("Lokalny model AI do oceny zarzutów wobec plików z szarej strefy. Pobieranie startuje "
                                  + "dopiero po kliknięciu; skanować można też bez niego.")
                        }
                    }
                }
            }
        }
        .font(.system(size: 11))
    }

    static func shortName(_ s: String) -> String {
        let l = s.lowercased()
        if l.contains("foundation-sec") { return "Foundation-Sec 8B (lokalnie)" }
        if l.contains("granite") { return "Granite 4.0 H Tiny (lokalnie)" }
        return s
    }

    /// " (4,9 GB)" for the download buttons.
    static func sizeSuffix(_ info: DBInfo) -> String {
        guard let size = info.aiModelSize, size > 0 else { return "" }
        return " (\(Fmt.decimal(Double(size) / 1e9, fixed: true)) GB)"
    }

    /// "AI: pobieranie modelu 37% · 1,6 / 4,2 GB"
    static func progressText(bytes: Int, total: Int?) -> String {
        guard let total, total > 0 else { return "AI: pobieranie modelu · \(Fmt.bytes(bytes))" }
        let pct = Fmt.percent(Double(bytes) / Double(total))
        let pair: String
        if total >= 1_000_000_000 {
            pair = "\(Fmt.decimal(Double(bytes) / 1e9, fixed: true)) / \(Fmt.decimal(Double(total) / 1e9, fixed: true)) GB"
        } else {
            pair = "\(Fmt.bytes(bytes)) / \(Fmt.bytes(total))"
        }
        return "AI: pobieranie modelu \(pct) · \(pair)"
    }
}

// MARK: - Sidebar look-alike for offscreen snapshots

struct SnapshotSidebar: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 7) {
                ForEach([Color(hex: 0xFF5F57), Color(hex: 0xFEBC2E), Color(hex: 0x28C840)], id: \.self) { c in
                    Circle().fill(c).frame(width: 12, height: 12)
                }
            }
            .padding(.leading, 18)
            .padding(.top, 16)
            .padding(.bottom, 14)
            BrandHeader().padding(.horizontal, 16).padding(.bottom, 14)
            VStack(alignment: .leading, spacing: 2) {
                if let s = model.session {
                    header("Bieżące")
                    row(selected: model.selection == .session) { SessionSidebarRow(session: s, selected: model.selection == .session) }
                }
                header("Skanowanie")
                ForEach(SidebarItem.scanScreens) { item in
                    row(selected: model.selection == item) { Label(item.title, systemImage: item.icon) }
                }
                header("Ochrona")
                row(selected: model.selection == .protection) {
                    Label(SidebarItem.protection.title, systemImage: SidebarItem.protection.icon)
                }
                header("Raporty")
                row(selected: model.selection == .history) {
                    Label(SidebarItem.history.title, systemImage: SidebarItem.history.icon)
                }
                header("Integracje")
                row(selected: model.selection == .api) {
                    Label(SidebarItem.api.title, systemImage: SidebarItem.api.icon)
                }
            }
            .padding(.horizontal, 10)
            Spacer()
            DatabaseFooter().padding(12)
        }
        .font(.system(size: 13))
        .frame(width: 250)
        .frame(maxHeight: .infinity)
        .background(Palette.sidebar)
    }

    private func header(_ t: String) -> some View {
        Text(t)
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 10)
            .padding(.top, 12)
            .padding(.bottom, 4)
    }

    private func row<V: View>(selected: Bool, @ViewBuilder _ content: () -> V) -> some View {
        content()
            .labelStyle(SidebarLabelStyle(selected: selected))
            .foregroundStyle(selected ? Color.white : Color.primary)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(selected ? AnyShapeStyle(Palette.brandGradient) : AnyShapeStyle(Color.clear))
            )
    }
}

private struct SidebarLabelStyle: LabelStyle {
    var selected: Bool
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 9) {
            configuration.icon
                .foregroundStyle(selected ? Color.white : Palette.brand)
                .frame(width: 20)
            configuration.title
        }
    }
}

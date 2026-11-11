import AppKit
import SwiftUI

enum ResultsTab: String, CaseIterable, Identifiable {
    case link, files, environment, network, repo, sandbox
    var id: String { rawValue }

    var title: String {
        switch self {
        case .link: return "Link"
        case .files: return "Pliki"
        case .environment: return "Środowisko"
        case .network: return "Sieć i zdalny dostęp"
        case .repo: return "Repozytorium"
        case .sandbox: return "Sandbox"
        }
    }

    var icon: String {
        switch self {
        case .link: return "link"
        case .files: return "doc.on.doc"
        case .environment: return "gearshape.2"
        case .network: return "network"
        case .repo: return "shippingbox"
        case .sandbox: return "lock.shield"
        }
    }
}

struct ResultsScreen: View {
    @Environment(AppModel.self) private var model
    var session: ScanSession
    var summary: Summary
    var expandFirst: Bool
    var expandMatching: String?
    @State private var tab: ResultsTab

    init(session: ScanSession, summary: Summary, initialTab: ResultsTab? = nil, expandFirst: Bool = false,
         expandMatching: String? = nil) {
        self.session = session
        self.summary = summary
        self.expandFirst = expandFirst
        self.expandMatching = expandMatching
        _tab = State(initialValue: initialTab ?? (summary.url != nil ? .link : .files))
    }

    private var tabs: [ResultsTab] {
        var t: [ResultsTab] = summary.url != nil ? [.link, .files] : [.files]
        if summary.environment != nil { t.append(.environment) }
        if summary.network != nil { t.append(.network) }
        if summary.repo != nil { t.append(.repo) }
        if summary.sandbox != nil { t.append(.sandbox) }
        return t
    }

    var body: some View {
        AdaptiveScroll {
            VStack(alignment: .leading, spacing: 18) {
                if let v = session.sandboxViolation { SandboxViolationBanner(problems: v) }
                VerdictHero(summary: summary, request: session.request)
                if !session.defenseLog.isEmpty {
                    VStack(alignment: .leading, spacing: 10) {
                        SectionTitle(title: "Aktywna obrona",
                                     subtitle: "Co Cerber zrobił sam w trakcie tego skanu",
                                     icon: "shield.lefthalf.filled")
                        ForEach(session.defenseLog) { d in DefenseRow(action: d, protection: model.protection) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .card(padding: 16, radius: 18)
                }
                if summary.cancelled {
                    Banner(icon: "stop.circle.fill", title: "Skanowanie zostało przerwane",
                           message: "To wyniki częściowe – sprawdzono \(Fmt.files(summary.files ?? 0)). Uruchom skan ponownie, aby sprawdzić resztę.",
                           color: Palette.orange, action: ("Skanuj ponownie", { model.retry() }))
                }
                ForEach(session.warnings, id: \.self) { w in
                    Banner(icon: "exclamationmark.triangle.fill", title: "Ostrzeżenie", message: w, color: Palette.orange)
                }
                if !summary.errors.isEmpty || (summary.skipped ?? 0) > 0 {
                    ErrorsBanner(summary: summary)
                }
                if let cf = summary.cloudFetch, cf.candidates > 0 {
                    Banner(icon: "icloud.and.arrow.down", title: "Sprawdzono \(Fmt.count(cf.fetched, "ryzykowny plik", "ryzykowne pliki", "ryzykownych plików")) z chmury (\(Fmt.bytes(cf.bytes)))",
                           message: cloudFetchMessage(cf), color: Palette.blue)
                }
                if summary.cloudOnly > 0 {
                    Banner(icon: "icloud", title: "\(summary.cloudFetch == nil ? "Pominięto" : "W chmurze zostało") \(Fmt.count(summary.cloudOnly, "element", "elementy", "elementów")) trzymanych tylko w chmurze",
                           message: summary.cloudFetch == nil
                               ? "To pliki i foldery z iCloud Drive (lub innej chmury), których nie ma na tym Macu – są tylko w chmurze, więc nic z nich nie może się uruchomić. Cerber ich nie pobiera, żeby nie ściągać całej chmury na dysk. Skan Mega pobiera i sprawdza te ryzykowne (programy, skrypty, instalatory, archiwa)."
                               : "Zdjęcia, filmy, muzyka i zwykłe dokumenty – same niczego nie uruchomią, więc zostały w chmurze.",
                           color: Palette.blue)
                }
                StatsRow(summary: summary)
                if tabs.count > 1 {
                    TabBar(tabs: tabs, selection: $tab, badges: badges)
                        .padding(.top, 4)
                }
                Group {
                    switch tab {
                    case .files: FilesTab(session: session, results: summary.results, expandFirst: expandFirst,
                                          expandMatching: expandMatching)
                    case .environment:
                        if let e = summary.environment { EnvironmentTab(env: e) }
                    case .network:
                        if let n = summary.network { NetworkTab(net: n) }
                    case .repo:
                        if let r = summary.repo { RepoTab(repo: r) }
                    case .sandbox:
                        if let s = summary.sandbox { SandboxTab(sandbox: s) }
                    case .link:
                        if let u = summary.url { LinkTab(info: u, verdict: summary.verdict, tree: summary.sandbox?.tree ?? []) }
                    }
                }
                .id(tab)
                .transition(.opacity)
            }
            .padding(.horizontal, 32)
            .padding(.vertical, 26)
            .frame(maxWidth: 1180)
            .frame(maxWidth: .infinity)
        }
        .background(Palette.canvas)
        .alert("Przenieść plik do kwarantanny?", isPresented: Binding(
            get: { model.pendingQuarantine != nil },
            set: { if !$0 { model.pendingQuarantine = nil } }
        ), presenting: model.pendingQuarantine) { r in
            Button("Przenieś do kwarantanny", role: .destructive) { model.quarantine(r) }
            Button("Anuluj", role: .cancel) {}
        } message: { r in
            Text("„\(r.fileName)” zostanie przeniesiony do zaszyfrowanej kwarantanny Cerbera i nie będzie mógł się uruchomić. Możesz go później przywrócić poleceniem ./cerber.sh quarantine restore.")
        }
    }

    private var badges: [ResultsTab: (Int, Color)] {
        var b: [ResultsTab: (Int, Color)] = [:]
        if let u = summary.url, !u.ioc.isEmpty {
            b[.link] = (u.ioc.count, Palette.red)
        }
        let flagged = summary.results.filter { $0.verdict != .clean }
        if !flagged.isEmpty {
            b[.files] = (flagged.count, flagged.map(\.verdict).max()?.color ?? Palette.gray)
        }
        if let e = summary.environment, !e.findings.isEmpty {
            b[.environment] = (e.findings.count, e.worstSeverity?.color ?? Palette.gray)
        }
        if let n = summary.network {
            let live = n.monitor?.events.filter { $0.severity.rank >= Severity.suspicious.rank } ?? []
            let logs = n.syslog?.events.filter { $0.severity.rank >= Severity.suspicious.rank } ?? []
            let certs = n.certificates?.filter { $0.riskRank >= 2 } ?? []
            let risky = n.remoteAccess.filter { $0.riskRank >= 2 }.count + n.iocConnections.count + live.count
                + logs.count + certs.count + (n.lan?.arpSuspicious.count ?? 0)
            let red = !n.iocConnections.isEmpty || live.contains { $0.severity == .malicious }
                || logs.contains { $0.severity == .malicious } || certs.contains { $0.risk == "malicious" }
            if risky > 0 { b[.network] = (risky, red ? Palette.red : Palette.orange) }
        }
        return b
    }

    private func cloudFetchMessage(_ cf: CloudFetchInfo) -> String {
        var parts = ["Programy, skrypty, instalatory, archiwa i dokumenty z aktywną treścią trzymane tylko w iCloud (lub innej chmurze) zostały pobrane i przeskanowane w sandboksie."]
        if cf.evicted > 0 { parts.append("\(Fmt.count(cf.evicted, "plik wrócił", "pliki wróciły", "plików wróciło")) z powrotem tylko do chmury.") }
        if cf.kept > 0 { parts.append("\(Fmt.count(cf.kept, "plik", "pliki", "plików")) z wykryciem zostaje na dysku, żeby można go było przenieść do kwarantanny.") }
        if cf.fetched - cf.evicted - cf.kept > 0 { parts.append("Część pobranych plików została na dysku – w Finderze: prawy klik → „Usuń pobrany plik”.") }
        if cf.notFetched > 0 { parts.append("\(Fmt.count(cf.notFetched, "pliku", "plików", "plików")) nie pobrano (limit 1500 plików / 3 GB / 30 min, za duże albo błąd chmury).") }
        if cf.stalled { parts.append("Chmura przestała odpowiadać.") }
        return parts.joined(separator: " ")
    }
}

// MARK: - Hero

struct VerdictHero: View {
    @Environment(AppModel.self) private var model
    var summary: Summary
    var request: ScanRequest

    var body: some View {
        let v = summary.verdict
        HStack(alignment: .center, spacing: 20) {
            ZStack {
                Circle().fill(.white.opacity(0.18)).frame(width: 92, height: 92)
                Circle().strokeBorder(.white.opacity(0.35), lineWidth: 1.5).frame(width: 92, height: 92)
                Image(systemName: v.heroIcon)
                    .font(.system(size: 42, weight: .semibold))
                    .foregroundStyle(.white)
                    .shadow(color: .black.opacity(0.18), radius: 4, y: 2)
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(summary.cancelled ? "Wyniki częściowe" : "Wynik skanowania")
                    .font(.system(size: 12, weight: .bold))
                    .kerning(0.8)
                    .textCase(.uppercase)
                    .foregroundStyle(.white.opacity(0.8))
                Text(v.heroTitle)
                    .font(.system(size: 32, weight: .heavy, design: .rounded))
                    .foregroundStyle(.white)
                Text(headline)
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(.white.opacity(0.92))
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 10) {
                    Label(summary.title.isEmpty ? request.title : summary.title, systemImage: summary.mode.icon)
                    Text("·")
                    Text(levelText)
                    if let f = summary.finished ?? summary.started {
                        Text("·")
                        Text(Fmt.dateTime(f))
                    }
                    if summary.sandbox != nil {
                        SandboxBadge(onColor: true)
                    }
                }
                .font(.system(size: 12))
                .foregroundStyle(.white.opacity(0.78))
                .lineLimit(1)
            }
            Spacer(minLength: 16)
            VStack(alignment: .trailing, spacing: 10) {
                Button {
                    if let p = summary.reportHTML, !ReportViewer.open(p) {
                        model.alert = AppAlert(title: "Nie znaleziono raportu", message: "Plik \(p) nie istnieje.")
                    }
                } label: {
                    Label("Otwórz raport", systemImage: "doc.richtext")
                }
                .buttonStyle(HeroButtonStyle(filled: true, accent: v.heroColors[0]))
                .disabled(summary.reportHTML == nil)
                Button {
                    model.newScan()
                } label: {
                    Label("Nowe skanowanie", systemImage: "arrow.counterclockwise")
                }
                .buttonStyle(HeroButtonStyle(filled: false))
            }
        }
        .padding(24)
        .background(
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .fill(LinearGradient(colors: v.heroColors, startPoint: .topLeading, endPoint: .bottomTrailing))
                .overlay(alignment: .trailing) {
                    Image(systemName: "shield.fill")
                        .font(.system(size: 210, weight: .black))
                        .foregroundStyle(.white.opacity(0.08))
                        .rotationEffect(.degrees(-12))
                        .offset(x: 40, y: 34)
                }
                .overlay(alignment: .topLeading) {
                    Circle()
                        .fill(RadialGradient(colors: [.white.opacity(0.22), .clear], center: .center, startRadius: 0, endRadius: 160))
                        .frame(width: 320, height: 320)
                        .offset(x: -110, y: -150)
                }
                .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
                .shadow(color: v.heroColors[0].opacity(0.35), radius: 20, y: 8)
        )
    }

    private var levelText: String {
        switch summary.mode {
        case .laptop: return "poziom \(summary.level.label)"
        case .scan: return "skan dokładny"
        case .sandbox: return "sandbox"
        case .github: return "GitHub"
        case .huggingface: return "Hugging Face"
        case .url: return "link"
        }
    }

    private var headline: String {
        let files = summary.files ?? 0
        var parts: [String] = []
        for v in Verdict.flagged {
            let n = summary.count(v)
            if n > 0 { parts.append(v.countPhrase(n)) }
        }
        var s: String
        if parts.isEmpty {
            s = "Nie znaleziono nic niepokojącego w \(Fmt.count(files, "pliku", "plikach", "plikach"))."
        } else {
            s = "Pliki: " + parts.joined(separator: ", ") + " (spośród \(Fmt.int(files)))."
        }
        if let e = summary.environment {
            let serious = e.findings.filter { $0.severity.rank >= Severity.suspicious.rank }.count
            if serious > 0 {
                s += " Środowisko: \(Fmt.count(serious, "problem", "problemy", "problemów"))."
            }
        }
        if let n = summary.network, !n.iocConnections.isEmpty {
            s += " Sieć: \(Fmt.count(n.iocConnections.count, "połączenie", "połączenia", "połączeń")) z adresem złośliwym."
        }
        if let u = summary.url, !u.ioc.isEmpty {
            s += " Link: adres jest na \(u.ioc.count == 1 ? "liście" : "listach") zagrożeń – nie pobieraj z niego niczego."
        }
        return s
    }
}

// MARK: - Stats

private struct StatsRow: View {
    var summary: Summary

    var body: some View {
        HStack(spacing: 12) {
            StatTile(icon: "doc.on.doc", label: "Pliki", value: Fmt.int(summary.files))
            StatTile(icon: "square.stack.3d.up", label: "Obiekty", value: Fmt.int(summary.objects))
            StatTile(icon: "internaldrive", label: "Rozmiar", value: Fmt.bytes(summary.bytes))
            StatTile(icon: "stopwatch", label: "Czas", value: Fmt.duration(summary.seconds))
            StatTile(icon: "cylinder.split.1x2", label: "Wzorce", value: Fmt.int(summary.patternsTotal))
        }
    }
}

private struct ErrorsBanner: View {
    var summary: Summary
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                withAnimation(.spring(response: 0.3)) { expanded.toggle() }
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: "exclamationmark.bubble.fill").foregroundStyle(Palette.yellow)
                    Text(title).font(.system(size: 13, weight: .semibold))
                    Spacer()
                    if !summary.errors.isEmpty {
                        Image(systemName: "chevron.down").font(.system(size: 11, weight: .bold)).foregroundStyle(.secondary)
                            .rotationEffect(.degrees(expanded ? 180 : 0))
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if expanded {
                ForEach(summary.errors, id: \.self) { e in
                    Text("• " + e).font(.system(size: 12)).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Palette.yellow.opacity(0.09)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Palette.yellow.opacity(0.3), lineWidth: 1))
    }

    private var title: String {
        var parts: [String] = []
        if let s = summary.skipped, s > 0 { parts.append("pominięto \(Fmt.files(s))") }
        if !summary.errors.isEmpty {
            parts.append(Fmt.count(summary.errors.count, "błąd odczytu", "błędy odczytu", "błędów odczytu"))
        }
        return "Nie wszystko udało się sprawdzić: " + parts.joined(separator: ", ")
    }
}

// MARK: - Tab bar

struct TabBar: View {
    var tabs: [ResultsTab]
    @Binding var selection: ResultsTab
    var badges: [ResultsTab: (Int, Color)]
    @Namespace private var ns

    var body: some View {
        HStack(spacing: 4) {
            ForEach(tabs) { t in
                Button {
                    withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) { selection = t }
                } label: {
                    HStack(spacing: 7) {
                        Image(systemName: t.icon).font(.system(size: 12, weight: .semibold))
                        Text(t.title).font(.system(size: 13, weight: selection == t ? .semibold : .medium))
                        if let b = badges[t] {
                            Text("\(b.0)")
                                .font(.system(size: 10.5, weight: .bold))
                                .foregroundStyle(.white)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 1.5)
                                .background(Capsule().fill(b.1))
                        }
                    }
                    .foregroundStyle(selection == t ? Color.primary : Color.secondary)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .background {
                        if selection == t {
                            Capsule(style: .continuous)
                                .fill(Palette.cardRaised)
                                .shadow(color: Palette.shadow, radius: 4, y: 1)
                                .matchedGeometryEffect(id: "tab", in: ns)
                        }
                    }
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(4)
        .background(Capsule(style: .continuous).fill(Palette.subtleStrong.opacity(0.7)))
    }
}

// MARK: - Files tab

struct FilesTab: View {
    @Environment(AppModel.self) private var model
    var session: ScanSession
    var results: [ScanResult]
    @State private var query = ""
    @State private var filter: Verdict? = nil
    @State private var expanded: Set<String>

    init(session: ScanSession, results: [ScanResult], expandFirst: Bool = false, expandMatching: String? = nil) {
        self.session = session
        self.results = results
        var open = expandFirst ? Set(results.prefix(1).map(\.id)) : []
        if let m = expandMatching { open.formUnion(results.filter { $0.path.contains(m) }.map(\.id)) }
        _expanded = State(initialValue: open)
    }

    private var filtered: [ScanResult] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        return results.filter { r in
            (filter == nil || r.verdict == filter) &&
            (q.isEmpty || r.displayPath.lowercased().contains(q) || (r.primary ?? "").lowercased().contains(q)
             || r.detections.contains { $0.name.lowercased().contains(q) })
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if results.isEmpty {
                EmptyState(icon: "checkmark.shield.fill", title: "Nie znaleziono podejrzanych plików",
                           message: "Żaden plik nie pasuje do wzorców zagrożeń ani heurystyk Cerbera.")
            } else {
                HStack(spacing: 10) {
                    SearchField(text: $query, placeholder: "Szukaj w wynikach")
                        .frame(maxWidth: 300)
                    Spacer()
                    filterChip(nil, label: "Wszystkie", count: results.count, color: Palette.brand)
                    ForEach(Verdict.flagged, id: \.self) { v in
                        let n = results.filter { $0.verdict == v }.count
                        if n > 0 { filterChip(v, label: v.groupTitle, count: n, color: v.color) }
                    }
                }
                let list = filtered
                if list.isEmpty {
                    Text("Brak wyników dla „\(query)”.").foregroundStyle(.secondary).padding(.vertical, 20)
                        .frame(maxWidth: .infinity)
                }
                ForEach(Verdict.flagged, id: \.self) { v in
                    let group = list.filter { $0.verdict == v }
                    if !group.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(spacing: 8) {
                                Dot(color: v.color, size: 9)
                                Text(v.groupTitle).font(.system(size: 13, weight: .semibold))
                                Text("\(group.count)").font(.system(size: 12, weight: .medium)).foregroundStyle(.secondary)
                            }
                            .padding(.leading, 4)
                            ForEach(group) { r in
                                ResultRow(result: r, expanded: expanded.contains(r.id)) {
                                    withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) {
                                        if expanded.contains(r.id) { expanded.remove(r.id) } else { expanded.insert(r.id) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private func filterChip(_ v: Verdict?, label: String, count: Int, color: Color) -> some View {
        let on = filter == v
        return Button {
            withAnimation(.easeInOut(duration: 0.2)) { filter = v }
        } label: {
            HStack(spacing: 5) {
                Text(label)
                Text("\(count)").foregroundStyle(on ? Color.white.opacity(0.85) : Color.secondary)
            }
            .font(.system(size: 12, weight: .medium))
            .foregroundStyle(on ? Color.white : Color.primary)
            .padding(.horizontal, 11)
            .padding(.vertical, 5)
            .background(Capsule().fill(on ? AnyShapeStyle(color) : AnyShapeStyle(Palette.subtle)))
            .overlay(Capsule().strokeBorder(on ? Color.clear : Palette.cardBorder, lineWidth: 1))
        }
        .buttonStyle(.plain)
    }
}

struct ResultRow: View {
    @Environment(AppModel.self) private var model
    var result: ScanResult
    var expanded: Bool
    var toggle: () -> Void
    @State private var hovering = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button(action: toggle) {
                HStack(spacing: 12) {
                    Image(systemName: result.verdict.icon)
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(result.verdict.color)
                        .frame(width: 36, height: 36)
                        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(result.verdict.color.opacity(0.13)))
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 8) {
                            Text(result.fileName).font(.system(size: 14, weight: .semibold)).lineLimit(1)
                            if result.quarantined != nil {
                                Pill(text: "W kwarantannie", color: Palette.green, icon: "lock.fill")
                            }
                            if result.ai != nil {
                                Pill(text: "AI", color: Palette.brand, icon: "sparkles")
                            }
                            if result.detonation != nil {
                                Pill(text: "Zachowanie", color: Palette.cyan, icon: "testtube.2")
                                    .help("Skrypt został uruchomiony w zamkniętym sandboksie – szczegóły po rozwinięciu")
                            }
                        }
                        Text(Fmt.tilde(result.folder.isEmpty ? result.displayPath : result.folder))
                            .font(.system(size: 11.5, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Spacer(minLength: 10)
                    if let p = result.primary {
                        Text(p)
                            .font(.system(size: 11.5, weight: .medium, design: .monospaced))
                            .foregroundStyle(result.verdict.color)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .padding(.horizontal, 9)
                            .padding(.vertical, 4)
                            .background(Capsule().fill(result.verdict.color.opacity(0.10)))
                            .frame(maxWidth: 300, alignment: .trailing)
                    }
                    if let s = result.score {
                        ScoreBadge(score: s, color: result.verdict.color)
                    }
                    Image(systemName: "chevron.down")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(expanded ? 180 : 0))
                }
                .padding(12)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if expanded {
                ResultDetails(result: result)
                    .padding(.horizontal, 14)
                    .padding(.bottom, 14)
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(Palette.card)
                .shadow(color: Palette.shadow, radius: expanded ? 12 : 6, y: 2)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .strokeBorder(expanded || hovering ? result.verdict.color.opacity(0.35) : Palette.cardBorder, lineWidth: 1)
        )
        .overlay(alignment: .leading) {
            UnevenRoundedRectangle(topLeadingRadius: 14, bottomLeadingRadius: 14, style: .continuous)
                .fill(result.verdict.color)
                .frame(width: 4)
        }
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .onHover { h in withAnimation(.easeOut(duration: 0.12)) { hovering = h } }
    }
}

struct ScoreBadge: View {
    var score: Double
    var color: Color

    var body: some View {
        VStack(spacing: 0) {
            Text("\(Int(score.rounded()))").font(.system(size: 13, weight: .bold, design: .rounded)).monospacedDigit()
            Text("pkt").font(.system(size: 9, weight: .medium)).foregroundStyle(.secondary)
        }
        .foregroundStyle(color)
        .frame(width: 40)
    }
}

private struct ResultDetails: View {
    @Environment(AppModel.self) private var model
    var result: ScanResult

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Divider()
            let wideEngine = result.detections.contains { EngineStyle.label($0.engine).count > 11 }
            VStack(spacing: 8) {
                ForEach(result.detections) { d in DetectionRow(detection: d, engineWidth: wideEngine ? 134 : 84) }
            }
            if let det = result.detonation {
                DetonationSection(detonation: det)
            }
            if let ai = result.ai {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "sparkles").foregroundStyle(Palette.brand).font(.system(size: 15, weight: .semibold))
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            Text(ai.accusations.isEmpty ? "Klasyfikacja AI" : "Ocena zarzutów przez AI")
                                .font(.system(size: 12.5, weight: .semibold))
                            if ai.accusations.isEmpty, let v = ai.verdict { VerdictBadge(verdict: v) }
                            if let c = ai.confidence {
                                Text("pewność \(Int((c * 100).rounded()))%").font(.system(size: 11.5)).foregroundStyle(.secondary)
                            }
                            if let p = ai.points, p != 0 {
                                Pill(text: "\(p > 0 ? "+" : "−")\(abs(p)) pkt", color: p > 0 ? Palette.orange : Palette.green)
                            }
                        }
                        if let f = ai.familyText {
                            Text(f).font(.system(size: 12.5, weight: .semibold))
                        }
                        if let s = ai.summary {
                            Text(s).font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true)
                        }
                        if !ai.accusations.isEmpty {
                            VStack(alignment: .leading, spacing: 6) {
                                ForEach(ai.accusations) { a in AIAccusationRow(accusation: a) }
                            }
                            .padding(.vertical, 2)
                        }
                        Text(ai.footnote)
                            .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Palette.brand.opacity(0.07)))
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Palette.brand.opacity(0.2), lineWidth: 1))
            }
            HStack(alignment: .center, spacing: 16) {
                meta("Rozmiar", Fmt.bytes(result.size))
                if let t = result.ftype { meta("Typ", t) }
                if let w = result.worstObject { meta("Najgorszy obiekt", w, mono: true) }
                if let sha = result.sha256 {
                    meta("SHA-256", String(sha.prefix(16)) + "…", mono: true)
                        .help(sha)
                        .onTapGesture { FinderActions.copy(sha) }
                }
                Spacer(minLength: 0)
            }
            HStack(spacing: 8) {
                Button {
                    FinderActions.reveal(result.path)
                } label: {
                    Label("Pokaż w Finderze", systemImage: "folder")
                }
                .buttonStyle(SecondaryButtonStyle())
                .disabled(!result.canQuarantine && !FinderActions.exists(result.path))
                Button {
                    if let sha = result.sha256 { FinderActions.copy(sha) }
                } label: {
                    Label("Kopiuj SHA-256", systemImage: "number")
                }
                .buttonStyle(SecondaryButtonStyle())
                .disabled(result.sha256 == nil)
                Spacer()
                if let q = result.quarantined {
                    Label("Przeniesiono do kwarantanny (ID \(q))", systemImage: "lock.shield.fill")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(Palette.green)
                } else if result.canQuarantine {
                    Button {
                        model.pendingQuarantine = result
                    } label: {
                        HStack(spacing: 6) {
                            if model.quarantining.contains(result.path) {
                                Spinner(size: 11, lineWidth: 1.5, color: .white)
                            } else {
                                Image(systemName: "lock.shield")
                            }
                            Text("Przenieś do kwarantanny")
                        }
                    }
                    .buttonStyle(PrimaryButtonStyle(colors: [Color(hex: 0xE5383B), Color(hex: 0xC2185B)]))
                    .disabled(model.quarantining.contains(result.path))
                } else {
                    Text(result.quarantineNote ?? "Kopia z sandboksu – katalog roboczy został już usunięty")
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func meta(_ label: String, _ value: String, mono: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.system(size: 10.5, weight: .medium)).foregroundStyle(.secondary)
            Text(value).font(.system(size: 12, design: mono ? .monospaced : .default)).lineLimit(1).truncationMode(.middle)
                .textSelection(.enabled)
        }
    }
}

struct DetectionRow: View {
    var detection: Detection
    /// Width of the engine column (wider when a long label such as "Sandbox (zachowanie)" is in the list).
    var engineWidth: CGFloat = 84

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(EngineStyle.label(detection.engine))
                .font(.system(size: 10.5, weight: .bold))
                .foregroundStyle(.white)
                .padding(.horizontal, 7)
                .padding(.vertical, 3)
                .background(Capsule().fill(EngineStyle.color(detection.engine)))
                .lineLimit(1)
                .fixedSize()
                .frame(width: engineWidth, alignment: .leading)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(detection.name).font(.system(size: 12.5, weight: .semibold, design: .monospaced))
                        .lineLimit(1).truncationMode(.middle)
                    ConfidenceMeter(level: EngineStyle.confidenceLevel(detection.confidence))
                    Text(EngineStyle.confidence(detection.confidence)).font(.system(size: 11)).foregroundStyle(.secondary)
                    if detection.pua { Pill(text: "PUA", color: Palette.purple) }
                }
                if let d = detection.description {
                    Text(d).font(.system(size: 12)).foregroundStyle(.primary.opacity(0.85))
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let o = detection.object {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.turn.down.right").font(.system(size: 9.5))
                        Text(o).font(.system(size: 11, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                    }
                    .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 8)
            if let s = detection.score {
                Text(s < 0 ? "−\(Int((-s).rounded()))" : "+\(Int(s.rounded()))")
                    .font(.system(size: 12, weight: .semibold, design: .rounded))
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Palette.subtle.opacity(0.7)))
    }
}

struct ConfidenceMeter: View {
    var level: Int
    var body: some View {
        HStack(spacing: 2) {
            ForEach(0..<4, id: \.self) { i in
                RoundedRectangle(cornerRadius: 1.5)
                    .fill(i < level ? Palette.brand : Palette.subtleStrong)
                    .frame(width: 5, height: 9)
            }
        }
    }
}

// MARK: - Behaviour in the sealed sandbox ("detonation")

extension DetonationBehavior.Level {
    var color: Color {
        switch self {
        case .critical: return Palette.red
        case .high: return Palette.orange
        case .medium: return Palette.yellow
        case .low: return Palette.blue
        case .info: return Palette.gray
        }
    }

    var label: String {
        switch self {
        case .critical: return "Krytyczne"
        case .high: return "Wysokie ryzyko"
        case .medium: return "Średnie ryzyko"
        case .low: return "Niskie ryzyko"
        case .info: return "Informacja"
        }
    }
}

struct DetonationSection: View {
    var detonation: Detonation
    @State private var allCommands = false

    private var d: Detonation { detonation }

    private var explanation: String {
        let base = "Skrypt został uruchomiony na kilka sekund bez dostępu do internetu i Twoich plików"
        if !d.ran { return "Skryptu nie udało się uruchomić w zamkniętym sandboksie – ocena opiera się tylko na analizie statycznej." }
        if d.behaviors.isEmpty && d.network.isEmpty && d.filesRead.isEmpty && d.filesWritten.isEmpty {
            return base + " – nie próbował niczego podejrzanego."
        }
        return base + " – oto, co próbował zrobić."
    }

    private var timeNote: String? {
        guard d.ran else { return nil }
        if d.timedOut { return "przerwany po \(Fmt.duration(d.seconds)) (limit czasu)" }
        return d.seconds.map { "działał \(Fmt.duration($0))" }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center, spacing: 8) {
                Image(systemName: "testtube.2").font(.system(size: 14, weight: .semibold)).foregroundStyle(Palette.cyan)
                Text("Zachowanie w zamkniętym sandboksie").font(.system(size: 13.5, weight: .semibold))
                if let k = d.kind { Pill(text: k, color: Palette.gray) }
                if let v = d.verdict, v > .clean { VerdictBadge(verdict: v) }
                Spacer(minLength: 8)
                if let t = timeNote {
                    Label(t, systemImage: d.timedOut ? "timer" : "stopwatch")
                        .font(.system(size: 11.5))
                        .foregroundStyle(d.timedOut ? Palette.orange : Color.secondary)
                }
            }
            Text(explanation)
                .font(.system(size: 12.5))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if !d.behaviors.isEmpty {
                VStack(spacing: 6) {
                    ForEach(d.behaviors) { b in BehaviorRow(behavior: b) }
                }
            }
            let small = smallBlocks
            if !small.isEmpty {
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 12, alignment: .top), GridItem(.flexible(), spacing: 12, alignment: .top)],
                          alignment: .leading, spacing: 12) {
                    ForEach(small.indices, id: \.self) { small[$0] }
                }
            }
            if !d.commands.isEmpty { commands }
            if !d.stages.isEmpty { stages }
            if !d.limitations.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(d.limitations, id: \.self) { l in
                        Text("• " + l).font(.system(size: 11.5)).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Palette.cyan.opacity(0.05)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Palette.cyan.opacity(0.25), lineWidth: 1))
    }

    /// Addresses, bait files and write attempts – two per row.
    private var smallBlocks: [AnyView] {
        var out: [AnyView] = []
        if !d.network.isEmpty {
            out.append(AnyView(block("Adresy, z którymi próbował się łączyć", icon: "network",
                                     note: "zablokowane – sandbox nie ma internetu") {
                ForEach(d.network) { t in
                    VStack(alignment: .leading, spacing: 1) {
                        HStack(spacing: 6) {
                            Text(t.display).font(.system(size: 11.5, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                                .foregroundStyle(t.ioc != nil ? Palette.red : Color.primary)
                                .textSelection(.enabled)
                            if t.ioc != nil {
                                HStack(spacing: 3) {
                                    Image(systemName: "bolt.fill").font(.system(size: 8.5, weight: .bold))
                                    Text("IOC").font(.system(size: 10, weight: .bold))
                                }
                                .foregroundStyle(.white)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Capsule().fill(Palette.red))
                                .fixedSize()
                            }
                        }
                        if let ioc = t.ioc {
                            Text(ioc).font(.system(size: 11)).foregroundStyle(Palette.red)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .help(t.ioc ?? t.display)
                }
            }))
        }
        if !d.filesRead.isEmpty {
            out.append(AnyView(block("Pliki-przynęty, po które sięgnął", icon: "key.viewfinder",
                                     note: "fałszywe kopie – prawdziwe były niewidoczne") {
                ForEach(d.filesRead, id: \.self) { f in
                    Text(Fmt.tilde(f)).font(.system(size: 11.5, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                        .help(f)
                }
            }))
        }
        if !d.filesWritten.isEmpty {
            out.append(AnyView(block("Próby zapisu plików", icon: "square.and.pencil", note: nil) {
                ForEach(d.filesWritten, id: \.self) { f in
                    Text(Fmt.tilde(f)).font(.system(size: 11.5, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                        .help(f)
                }
            }))
        }
        return out
    }

    private var commands: some View {
        let shown = allCommands ? d.commands : Array(d.commands.prefix(10))
        return block("Polecenia", icon: "terminal", note: "w kolejności uruchamiania – \(d.commands.count)") {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(Array(shown.enumerated()), id: \.offset) { _, c in
                    Text(Fmt.tilde(c)).font(.system(size: 11, design: .monospaced)).lineLimit(2).truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .help(c)
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Palette.subtle.opacity(0.9)))
            .textSelection(.enabled)
            if d.commands.count > 10 {
                Button(allCommands ? "Pokaż mniej" : "Pokaż wszystkie (\(d.commands.count))") {
                    withAnimation(.easeInOut(duration: 0.2)) { allCommands.toggle() }
                }
                .buttonStyle(SecondaryButtonStyle(compact: true))
            }
        }
    }

    private var stages: some View {
        block("Odkodowane ukryte etapy", icon: "doc.text.magnifyingglass", note: "zaciemniony kod odkryty w trakcie działania") {
            ForEach(d.stages) { st in
                VStack(alignment: .leading, spacing: 6) {
                    if let src = st.sourcePreview {
                        Text(Fmt.tilde(src))
                            .font(.system(size: 11, design: .monospaced))
                            .lineLimit(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                            .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Palette.subtle.opacity(0.9)))
                            .textSelection(.enabled)
                    }
                    if !st.detections.isEmpty {
                        FlowLayout(spacing: 5) {
                            ForEach(st.detections, id: \.self) { n in
                                Text(n).font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                                    .foregroundStyle(Palette.orange)
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 2)
                                    .background(Capsule().fill(Palette.orange.opacity(0.12)))
                            }
                        }
                    }
                }
            }
        }
    }

    private func block<C: View>(_ title: String, icon: String, note: String?, @ViewBuilder content: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Image(systemName: icon).font(.system(size: 11, weight: .semibold)).foregroundStyle(Palette.cyan)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).font(.system(size: 12, weight: .semibold))
                    if let note {
                        Text(note).font(.system(size: 11)).foregroundStyle(.tertiary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            content()
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }
}

private struct BehaviorRow: View {
    var behavior: DetonationBehavior

    var body: some View {
        let color = behavior.level.color
        VStack(alignment: .leading, spacing: 3) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(behavior.title).font(.system(size: 12.5, weight: .semibold))
                    .fixedSize(horizontal: false, vertical: true)
                Pill(text: behavior.level.label, color: color, filled: behavior.level >= .high)
                Spacer(minLength: 8)
                if let s = behavior.score {
                    Text("+\(Int(s.rounded()))")
                        .font(.system(size: 11.5, weight: .semibold, design: .rounded))
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
            }
            if let detail = behavior.detail {
                Text(detail).font(.system(size: 12)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !behavior.evidence.isEmpty {
                VStack(alignment: .leading, spacing: 1) {
                    ForEach(Array(behavior.evidence.prefix(3).enumerated()), id: \.offset) { _, e in
                        HStack(alignment: .firstTextBaseline, spacing: 5) {
                            Text("›").foregroundStyle(color)
                            Text(Fmt.tilde(e)).lineLimit(1).truncationMode(.middle).help(e)
                        }
                    }
                    if behavior.evidence.count > 3 {
                        Text("+ \(behavior.evidence.count - 3) więcej")
                            .font(.system(size: 10.5)).foregroundStyle(.tertiary).padding(.leading, 11)
                    }
                }
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
                .padding(.top, 1)
            }
        }
        .padding(.vertical, 8)
        .padding(.leading, 13)
        .padding(.trailing, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(Palette.card))
        .overlay(alignment: .leading) {
            UnevenRoundedRectangle(topLeadingRadius: 9, bottomLeadingRadius: 9, style: .continuous)
                .fill(color)
                .frame(width: 3)
        }
        .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
    }
}

/// One accusation in the "Ocena zarzutów przez AI" panel: name → trafny / chybiony / niepewne, confidence,
/// the model's reason (with its quote from the file) and the points it moved.
struct AIAccusationRow: View {
    let accusation: AIAccusation

    private var tint: Color {
        switch accusation.assessment {
        case .confirmed: return Palette.red
        case .refuted: return Palette.green
        case .unsure: return Color.secondary
        }
    }

    var body: some View {
        let a = accusation
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text(a.name).font(.system(size: 11.5, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                Pill(text: a.label, color: tint)
                if let c = a.confidence {
                    Text("\(Int((c * 100).rounded()))%").font(.system(size: 11)).foregroundStyle(.secondary).monospacedDigit()
                }
                if a.points != 0 {
                    Text("\(a.points > 0 ? "+" : "−")\(abs(a.points)) pkt").font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(a.points > 0 ? Palette.orange : Palette.green)
                }
                if !a.agree || !a.grounded {
                    Image(systemName: "exclamationmark.circle").font(.system(size: 10.5)).foregroundStyle(.secondary)
                        .help((!a.agree ? "Dwie odpowiedzi modelu się różniły. " : "") + (!a.grounded ? "Cytat nie występuje w pliku." : ""))
                }
            }
            if let r = a.reason, !r.isEmpty {
                Text(r).font(.system(size: 11.5)).fixedSize(horizontal: false, vertical: true)
            }
            if let q = a.quote {
                Text(q).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(.secondary).lineLimit(2).textSelection(.enabled)
            }
        }
    }
}

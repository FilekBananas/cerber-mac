import AppKit
import SwiftUI

/// "Ochrona w tle": automatic scanning of everything that is downloaded or installed.
struct ProtectionScreen: View {
    @Environment(AppModel.self) private var model
    @Environment(\.snapshotMode) private var snapshot

    private var p: BackgroundProtection { model.protection }

    var body: some View {
        ScreenScaffold(item: .protection,
                       subtitle: "Nowe pliki, aplikacje i elementy autostartu są sprawdzane od razu po pojawieniu się – w sandboksie, jak skan Szybki.") {
            mainToggle
            if let a = p.lastAlert, p.enabled {
                Banner(icon: "xmark.shield.fill", title: a.title ?? "Wykryto złośliwy plik", message: a.msg, color: Palette.red,
                       action: a.report.map { r in ("Pokaż raport", { ReportViewer.open(r) }) })
            }
            HStack(alignment: .top, spacing: 16) {
                optionsCard
                statusCard.frame(width: 360)
            }
            if p.netGuard && (p.enabled || !p.netEvents.isEmpty) { netCard }
            if p.enabled || !p.spots.isEmpty { spotsCard }
            if !p.verified.isEmpty { verifiedCard }
            activityCard
        }
        .onAppear { if !snapshot { p.refreshLoginItem() } }
    }

    // MARK: main toggle

    private var mainToggle: some View {
        Toggle(isOn: Binding(get: { p.enabled }, set: { p.setEnabled($0) })) {
            HStack(spacing: 14) {
                IconTile(systemName: "shield.lefthalf.filled.badge.checkmark",
                         colors: [Color(hex: 0x10B981), Color(hex: 0x6366F1)], size: 50)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Skanuj automatycznie wszystko, co pobierasz i instalujesz")
                        .font(.system(size: 16, weight: .semibold))
                    Text("Pobrane pliki, nowe aplikacje i instalacje .pkg, autostart (LaunchAgents/Daemons), narzędzia uprzywilejowane, programy Homebrew i rozszerzenia przeglądarek. Gdy ochrona jest włączona, Cerber działa w pasku menu także po zamknięciu okna.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .toggleStyle(SwitchToggleStyle(tint: Palette.green))
        .card(padding: 18, radius: 18)
    }

    // MARK: options

    private var optionsCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            SectionTitle(title: "Ustawienia", icon: "slider.horizontal.3")
            Toggle(isOn: Binding(get: { p.autoQuarantine }, set: { p.setAutoQuarantine($0) })) {
                optionLabel("Automatyczna kwarantanna złośliwych plików",
                            "Potwierdzone złośliwe pliki trafiają od razu do zaszyfrowanej kwarantanny (można je przywrócić).")
            }
            .toggleStyle(SwitchToggleStyle())
            Toggle(isOn: Binding(get: { p.netGuard }, set: { p.setNetGuard($0) })) {
                optionLabel("Nadzór sieci i zdalnego dostępu",
                            "Sprawdza, czy nikt nie steruje Makiem zdalnie. Co 10 s: połączenia z Internetem, otwarte porty, logowania przez SSH i udostępnianie ekranu, programy do zdalnego sterowania i tunele, nowe uprawnienia do nagrywania ekranu i sterowania komputerem. Co 5 min przegląda dziennik systemowy. Nic nie jest wysyłane do sieci.")
            }
            .toggleStyle(SwitchToggleStyle())
            VStack(alignment: .leading, spacing: 8) {
                optionLabel("Głębokość", "Szybki wystarcza dla nowych plików; Dokładny dokłada heurystyki i podpisy kodu.")
                HStack(spacing: 4) {
                    levelChoice(.quick, "Szybki (zalecane)")
                    levelChoice(.deep, "Dokładny")
                }
                .padding(3)
                .background(Capsule().fill(Palette.subtleStrong.opacity(0.7)))
            }
            Divider()
            Toggle(isOn: Binding(get: { p.loginItemEnabled }, set: { p.setLoginItem($0) })) {
                optionLabel("Uruchamiaj Cerbera przy logowaniu",
                            "Cerber pojawi się w Ustawieniach systemowych → Ogólne → Rzeczy otwierane podczas logowania. Bez tego ochrona działa tylko wtedy, gdy Cerber jest uruchomiony.")
            }
            .toggleStyle(SwitchToggleStyle())
            if let note = p.loginItemNote {
                Label(note, systemImage: "info.circle").font(.system(size: 11.5)).foregroundStyle(Palette.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card(padding: 18, radius: 18)
    }

    private func optionLabel(_ title: String, _ caption: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.system(size: 13, weight: .semibold))
            Text(caption).font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func levelChoice(_ level: ScanLevel, _ title: String) -> some View {
        let on = p.level == level
        return Button {
            withAnimation(.easeInOut(duration: 0.2)) { p.setLevel(level) }
        } label: {
            Text(title)
                .font(.system(size: 12.5, weight: on ? .semibold : .medium))
                .foregroundStyle(on ? Color.primary : Color.secondary)
                .padding(.horizontal, 14)
                .padding(.vertical, 6)
                .background(Capsule().fill(on ? Palette.cardRaised : Color.clear).shadow(color: on ? Palette.shadow : .clear, radius: 3, y: 1))
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
    }

    // MARK: status

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                switch p.status {
                case .running:
                    SoftIcon(systemName: "checkmark.shield.fill", color: Palette.green, size: 36)
                case .starting:
                    ZStack {
                        RoundedRectangle(cornerRadius: 11, style: .continuous).fill(Palette.brand.opacity(0.13))
                        Spinner(size: 16, lineWidth: 2)
                    }
                    .frame(width: 36, height: 36)
                case .failed:
                    SoftIcon(systemName: "exclamationmark.octagon.fill", color: Palette.red, size: 36)
                case .off:
                    SoftIcon(systemName: "shield.slash", color: Palette.gray, size: 36)
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(statusTitle).font(.system(size: 14, weight: .semibold))
                    Text(p.status == .running ? "poziom \(p.level.label) · kwarantanna \(p.autoQuarantine ? "automatyczna" : "wyłączona")"
                         + (p.netGuard ? " · sieć nadzorowana" : "")
                         : "Włącz przełącznik powyżej")
                        .font(.system(size: 11.5)).foregroundStyle(.secondary)
                }
            }
            if case .failed(let m) = p.status {
                Text(m).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(.secondary)
                    .lineLimit(5).textSelection(.enabled)
                Button { p.start() } label: { Label("Spróbuj ponownie", systemImage: "arrow.clockwise") }
                    .buttonStyle(SecondaryButtonStyle(tint: Palette.brand, compact: true))
            }
            Divider()
            HStack(spacing: 8) {
                Image(systemName: "cpu").foregroundStyle(engineColor)
                Text("Silnik skanowania:").font(.system(size: 12)).foregroundStyle(.secondary)
                Text(p.workerLabel).font(.system(size: 12, weight: .semibold)).foregroundStyle(engineColor)
                if p.workerState == "loading" { Spinner(size: 10, lineWidth: 1.5) }
            }
            Text(p.workerState == "ready"
                 ? "\(Fmt.compact(p.workerPatterns ?? 7_215_172)) wzorców w pamięci – zostanie zwolniony po 10 min bezczynności."
                 : "Bazy (2,6 GB) są ładowane dopiero wtedy, gdy pojawi się coś nowego.")
                .font(.system(size: 11.5)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card(padding: 18, radius: 18)
    }

    private var statusTitle: String {
        switch p.status {
        case .off: return "Wyłączona"
        case .starting: return "Uruchamianie…"
        case .running: return "Ochrona działa"
        case .failed: return "Błąd ochrony w tle"
        }
    }

    private var engineColor: Color {
        switch p.workerState {
        case "ready": return Palette.green
        case "loading": return Palette.brand
        default: return Palette.gray
        }
    }

    // MARK: network & remote access

    private var netSubtitle: String {
        guard let st = p.netStatus else {
            return p.status == .running ? "Uruchamianie nadzoru…" : "Działa razem z ochroną w tle"
        }
        if !st.active { return st.error ?? "Zatrzymany" }
        var parts = ["co \(Fmt.interval(st.intervalS ?? 10))",
                     Fmt.count(st.polls, "sprawdzenie", "sprawdzenia", "sprawdzeń")]
        if let l = st.logChecked { parts.append("dziennik do \(Fmt.time(l))") }
        return parts.joined(separator: " · ")
    }

    private var netCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitle(title: "Sieć i zdalny dostęp", subtitle: netSubtitle, icon: "network.badge.shield.half.filled",
                         trailing: AnyView(
                            Button {
                                if let r = p.netReport, !ReportViewer.open(r) {
                                    model.alert = AppAlert(title: "Raport jeszcze nie powstał",
                                                           message: "Raport sieci zapisuje się po pierwszych minutach nadzoru.")
                                }
                            } label: { Label("Raport sieci", systemImage: "doc.richtext") }
                            .buttonStyle(SecondaryButtonStyle(tint: Palette.brand, compact: true))
                            .disabled(p.netReport == nil)))
            if let st = p.netStatus {
                FlowLayout(spacing: 6) {
                    Pill(text: "alarmy: \(p.netAlerts)", color: p.netAlerts > 0 ? Palette.orange : Palette.green,
                         icon: p.netAlerts > 0 ? "exclamationmark.triangle" : "checkmark")
                    Pill(text: "nowe połączenia z Internetem: \(Fmt.int(st.stats.publicNew))", color: Palette.gray)
                    Pill(text: "przychodzące: \(Fmt.int(st.stats.inbound))", color: Palette.gray)
                    Pill(text: "nowe porty: \(Fmt.int(st.stats.listeningNew))", color: Palette.gray)
                    Pill(text: "logowania: \(Fmt.int(st.stats.sessionsNew))", color: Palette.gray)
                    Pill(text: "wysłano: \(Fmt.bytes(st.stats.uploadedBytes))", color: Palette.gray)
                }
                if !st.permissions {
                    HStack(spacing: 8) {
                        Image(systemName: "hand.raised").foregroundStyle(Palette.orange)
                        Text("Bez Pełnego dostępu do dysku Cerber nie widzi nowych uprawnień (nagrywanie ekranu, Dostępność, odczyt klawiatury). Reszta nadzoru działa.")
                            .font(.system(size: 11.5)).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer(minLength: 8)
                        Button {
                            if let u = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
                                NSWorkspace.shared.open(u)
                            }
                        } label: { Label("Prywatność i ochrona", systemImage: "hand.raised") }
                        .buttonStyle(SecondaryButtonStyle(tint: Palette.orange, compact: true))
                    }
                }
            }
            if p.netEvents.isEmpty {
                HStack(spacing: 10) {
                    Image(systemName: "checkmark.shield").foregroundStyle(Palette.green)
                    Text("Nic nowego w sieci. Gdy ktoś połączy się z Twoim Makiem, uruchomi się program do zdalnego sterowania albo coś dostanie dostęp do ekranu, zobaczysz to tutaj.")
                        .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                .font(.system(size: 12.5))
            } else {
                let shown = Array(p.netEvents.prefix(snapshot ? 6 : 40))
                LazyVStack(spacing: 6) {
                    ForEach(shown) { e in NetEventRow(event: e) }
                }
                if p.netEvents.count > shown.count {
                    Text("… i \(p.netEvents.count - shown.count) starszych – wszystkie są w raporcie sieci.")
                        .font(.system(size: 11.5)).foregroundStyle(.secondary)
                }
            }
        }
        .card(padding: 16, radius: 18)
    }

    // MARK: watched places

    private var spotsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitle(title: "Obserwowane miejsca",
                         subtitle: p.spots.isEmpty ? "Lista pojawi się po uruchomieniu" : "\(p.spots.filter(\.ok).count) z \(p.spots.count) dostępnych",
                         icon: "eye")
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 8) {
                ForEach(p.spots) { s in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: s.ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(s.ok ? Palette.green : Palette.orange)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(s.kindPL.prefix(1).uppercased() + s.kindPL.dropFirst()).font(.system(size: 12.5, weight: .semibold))
                            Text(Fmt.tilde(s.path)).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                                .lineLimit(1).truncationMode(.middle)
                            if let e = s.error {
                                Text(s.isPermissionError ? "Brak dostępu – zezwól Cerberowi w Ustawieniach → Prywatność i ochrona" : e)
                                    .font(.system(size: 11)).foregroundStyle(Palette.orange)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(s.ok ? Palette.subtle.opacity(0.6) : Palette.orange.opacity(0.08)))
                }
            }
            if p.spots.contains(where: \.isPermissionError) {
                HStack(spacing: 8) {
                    Text("Cerber ponawia próbę co minutę – po nadaniu uprawnień miejsca zaczną być obserwowane same.")
                        .font(.system(size: 11.5)).foregroundStyle(.secondary)
                    Spacer()
                    Button {
                        if let u = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
                            NSWorkspace.shared.open(u)
                        }
                    } label: {
                        Label("Otwórz Prywatność i ochrona", systemImage: "hand.raised")
                    }
                    .buttonStyle(SecondaryButtonStyle(tint: Palette.orange, compact: true))
                }
            }
        }
        .card(padding: 16, radius: 18)
    }

    private var verifiedCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionTitle(title: "Sandbox zweryfikowany", subtitle: "Samosprawdzenie przed pierwszym skanem", icon: "checkmark.seal")
            FlowLayout(spacing: 6) {
                ForEach(p.verified, id: \.self) { v in
                    Pill(text: v, color: Palette.green, icon: "checkmark")
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card(padding: 16, radius: 18)
    }

    // MARK: activity

    private var activityCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle(title: "Aktywność", subtitle: "Najnowsze na górze · ostatnie \(BackgroundProtection.maxActivity) zdarzeń w tej sesji",
                         icon: "list.bullet.rectangle",
                         trailing: AnyView(Text("\(p.activity.count)").font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)))
            if p.activity.isEmpty {
                HStack(spacing: 10) {
                    Image(systemName: "tray").foregroundStyle(.secondary)
                    Text(p.enabled ? "Nic nowego – gdy coś pobierzesz lub zainstalujesz, pojawi się tutaj."
                         : "Ochrona w tle jest wyłączona.")
                        .foregroundStyle(.secondary)
                }
                .font(.system(size: 12.5))
                .padding(.vertical, 6)
            } else {
                LazyVStack(spacing: 6) {
                    ForEach(snapshot ? Array(p.activity.prefix(8)) : p.activity) { a in
                        ActivityRow(item: a, protection: p)
                    }
                }
            }
        }
        .card(padding: 16, radius: 18)
    }
}

private struct ActivityRow: View {
    var item: ActivityItem
    var protection: BackgroundProtection

    private var icon: String {
        switch item.kind {
        case "download": return "arrow.down.circle"
        case "desktop": return "menubar.dock.rectangle"
        case "app": return "app.badge"
        case "autostart": return "arrow.triangle.2.circlepath"
        case "pkg": return "shippingbox"
        case "extension": return "puzzlepiece.extension"
        case "bin": return "terminal"
        case "helper": return "lock.shield"
        case "network": return "network"
        default: return "doc"
        }
    }

    var body: some View {
        let color = item.verdict?.color ?? Palette.brand
        HStack(spacing: 12) {
            SoftIcon(systemName: icon, color: item.phase == .done ? color : Palette.brand, size: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name).font(.system(size: 13, weight: .semibold)).lineLimit(1).truncationMode(.middle)
                HStack(spacing: 6) {
                    Text(item.kindPL)
                    Text("·")
                    Text(Self.time(item.time))
                    if let n = item.note { Text("·"); Text(n).lineLimit(1) }
                }
                .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            switch item.phase {
            case .waiting:
                Label("czeka, aż plik przestanie się zmieniać", systemImage: "hourglass")
                    .font(.system(size: 11.5)).foregroundStyle(.secondary)
            case .scanning:
                HStack(spacing: 6) {
                    Spinner(size: 11, lineWidth: 1.5)
                    Text("sprawdzam…").font(.system(size: 11.5, weight: .medium)).foregroundStyle(Palette.brand)
                }
            case .done:
                if item.quarantinedCount > 0 {
                    Pill(text: "w kwarantannie", color: Palette.green, icon: "lock.fill")
                }
                if let f = item.quarantinable.first {
                    Button {
                        protection.quarantine(itemID: item.id, path: f.path)
                    } label: {
                        HStack(spacing: 5) {
                            if protection.quarantining.contains(f.path) {
                                Spinner(size: 10, lineWidth: 1.5, color: .white)
                            } else {
                                Image(systemName: "lock.shield")
                            }
                            Text(item.quarantinable.count > 1 ? "Do kwarantanny (1 z \(item.quarantinable.count))" : "Do kwarantanny")
                        }
                    }
                    .buttonStyle(PrimaryButtonStyle(colors: [Color(hex: 0xE5383B), Color(hex: 0xC2185B)]))
                    .disabled(protection.quarantining.contains(f.path))
                    .help(f.quarantineError ?? f.path)
                }
                if let f = item.flagged.first, item.verdict ?? .clean >= .suspicious, let pr = f.primary {
                    Text(pr).font(.system(size: 11, design: .monospaced)).foregroundStyle(color).lineLimit(1)
                        .frame(maxWidth: 220, alignment: .trailing)
                }
                if let s = item.seconds {
                    Text(Fmt.duration(s)).font(.system(size: 11)).foregroundStyle(.tertiary).monospacedDigit()
                }
                if let v = item.verdict { VerdictBadge(verdict: v) }
            }
            HStack(spacing: 4) {
                Button {
                    if let r = item.report { ReportViewer.open(r) }
                } label: { Image(systemName: "doc.richtext") }
                .buttonStyle(SecondaryButtonStyle(compact: true))
                .disabled(item.report == nil)
                .help("Otwórz raport")
                Button {
                    FinderActions.reveal(item.path)
                } label: { Image(systemName: "folder") }
                .buttonStyle(SecondaryButtonStyle(compact: true))
                .help("Pokaż w Finderze")
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous)
            .fill(item.phase == .done && (item.verdict ?? .clean) >= .suspicious ? color.opacity(0.07) : Palette.subtle.opacity(0.5)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous)
            .strokeBorder(item.phase == .done && (item.verdict ?? .clean) >= .suspicious ? color.opacity(0.3) : Color.clear, lineWidth: 1))
    }

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Fmt.locale
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    static func time(_ d: Date) -> String { timeFormatter.string(from: d) }
}

// MARK: - Menu bar

struct ProtectionMenu: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let p = model.protection
        Text(p.statusLine)
        Divider()
        if p.recentResults.isEmpty {
            Text("Brak nowych wyników")
        } else {
            ForEach(p.recentResults) { r in
                Button {
                    if let rep = r.report { ReportViewer.open(rep) } else { FinderActions.reveal(r.path) }
                } label: {
                    Label("\(r.name) – \(r.verdict?.badge.lowercased() ?? "?")", systemImage: r.verdict?.icon ?? "doc")
                }
            }
        }
        Divider()
        Button("Otwórz Cerbera") {
            NSApp.activate(ignoringOtherApps: true)
            openWindow(id: "main")
            model.selection = .protection
        }
        Button("Wstrzymaj ochronę w tle") { p.setEnabled(false) }
        Divider()
        Button("Zakończ") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }
}

enum MenuBarIcon {
    /// Template icon normally; red (non-template) after a malicious result.
    static func image(malicious: Bool) -> NSImage {
        let name = malicious ? "xmark.shield.fill" : "shield.lefthalf.filled"
        let base = NSImage(systemSymbolName: name, accessibilityDescription: "Cerber") ?? NSImage()
        if malicious {
            let cfg = NSImage.SymbolConfiguration(pointSize: 15, weight: .semibold)
                .applying(NSImage.SymbolConfiguration(paletteColors: [.systemRed]))
            let img = base.withSymbolConfiguration(cfg) ?? base
            img.isTemplate = false
            return img
        }
        let img = base.withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 15, weight: .semibold)) ?? base
        img.isTemplate = true
        return img
    }
}

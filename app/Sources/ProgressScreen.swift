import AppKit
import SwiftUI

struct ProgressScreen: View {
    @Environment(AppModel.self) private var model
    var session: ScanSession
    @State private var showLog: Bool

    init(session: ScanSession, expandLog: Bool = false) {
        self.session = session
        _showLog = State(initialValue: expandLog)
    }

    var body: some View {
        AdaptiveScroll {
            VStack(alignment: .leading, spacing: 18) {
                if let v = session.sandboxViolation { SandboxViolationBanner(problems: v) }
                header
                StageStepper(session: session)
                HStack(alignment: .top, spacing: 18) {
                    RingCard(session: session)
                        .frame(width: 300)
                    VStack(spacing: 12) {
                        StatsGrid(session: session)
                        CurrentFileCard(session: session)
                    }
                }
                if session.netStatus != nil || !session.netEvents.isEmpty {
                    NetLiveCard(session: session)
                }
                ForEach(session.warnings, id: \.self) { w in
                    Banner(icon: "exclamationmark.triangle.fill", title: "Ostrzeżenie", message: w, color: Palette.orange)
                }
                LiveFindingsCard(session: session)
                TechnicalLog(session: session, expanded: $showLog)
            }
            .padding(.horizontal, 32)
            .padding(.vertical, 26)
            .frame(maxWidth: 1080)
            .frame(maxWidth: .infinity)
        }
        .background(Palette.canvas)
    }

    private var header: some View {
        HStack(spacing: 16) {
            ZStack {
                Circle().fill(Palette.brandGradient).frame(width: 54, height: 54)
                    .shadow(color: Palette.brandA.opacity(0.4), radius: 10, y: 4)
                Image(systemName: session.request.mode.icon)
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(.white)
                PulseRing(active: session.phase == .running)
            }
            VStack(alignment: .leading, spacing: 3) {
                Text(session.phase == .cancelling ? "Przerywanie skanowania…" : "Skanowanie w toku")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(session.phase == .cancelling ? Palette.orange : Palette.brand)
                    .textCase(.uppercase)
                    .kerning(0.6)
                Text(session.request.title)
                    .font(.system(size: 24, weight: .bold, design: .rounded))
                    .lineLimit(1)
                    .truncationMode(.middle)
                HStack(spacing: 8) {
                    Text(session.request.modeLabel)
                    SandboxBadge()
                    if session.request.ai {
                        Pill(text: "AI", color: Palette.brand, icon: "sparkles")
                    }
                    if model.config.mock {
                        Pill(text: "mock", color: Palette.orange, icon: "theatermasks.fill")
                    }
                }
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
            }
            Spacer(minLength: 16)
            Button {
                model.cancel()
            } label: {
                Label(session.phase == .cancelling ? "Zakończ natychmiast" : "Anuluj",
                      systemImage: session.phase == .cancelling ? "stop.fill" : "xmark")
            }
            .buttonStyle(SecondaryButtonStyle(tint: Palette.red))
            .help("Przerwij skanowanie (⌘.) – wyniki częściowe zostaną zachowane")
        }
        .card(padding: 18, radius: 20)
    }
}

private struct PulseRing: View {
    var active: Bool
    @State private var animate = false
    @Environment(\.snapshotMode) private var snapshot

    var body: some View {
        Circle()
            .stroke(Palette.brandB.opacity(animate ? 0 : 0.6), lineWidth: 2)
            .frame(width: 54, height: 54)
            .scaleEffect(animate ? 1.45 : 1)
            .opacity(active && !snapshot ? 1 : 0)
            .animation(active && !snapshot ? .easeOut(duration: 1.6).repeatForever(autoreverses: false) : nil, value: animate)
            .onAppear { if !snapshot { animate = true } }
    }
}

// MARK: - Stage stepper

struct StageStepper: View {
    var session: ScanSession

    var body: some View {
        let stages = session.stageOrder
        VStack(spacing: 14) {
            HStack(alignment: .top, spacing: 0) {
                ForEach(Array(stages.enumerated()), id: \.element) { idx, id in
                    let state = session.stageState(id)
                    VStack(spacing: 7) {
                        HStack(spacing: 0) {
                            connector(visible: idx > 0, done: state == .done || state == .active)
                            StageDot(state: state, icon: Stage.icon(id))
                            connector(visible: idx < stages.count - 1,
                                      done: idx < stages.count - 1 && [.done, .active].contains(session.stageState(stages[idx + 1])))
                        }
                        Text(Stage.shortTitle(id))
                            .font(.system(size: 11.5, weight: state == .active ? .semibold : .regular))
                            .foregroundStyle(state == .pending || state == .skipped ? Color.secondary : Color.primary)
                            .lineLimit(1)
                            .minimumScaleFactor(0.8)
                    }
                    .frame(maxWidth: .infinity)
                }
            }
            .padding(.top, 4)
            if let cur = session.currentStage {
                HStack(spacing: 8) {
                    if session.phase == .cancelling {
                        Image(systemName: "stop.circle.fill").foregroundStyle(Palette.orange)
                        Text("Przerywanie – czekam na częściowe wyniki…")
                    } else {
                        Spinner(size: 12, lineWidth: 1.8)
                        Text(session.stageTitles[cur] ?? Stage.defaultTitle(cur))
                    }
                }
                .font(.system(size: 12.5, weight: .medium))
                .foregroundStyle(session.phase == .cancelling ? Palette.orange : Palette.brand)
                .padding(.horizontal, 12)
                .padding(.vertical, 5)
                .background(Capsule().fill((session.phase == .cancelling ? Palette.orange : Palette.brand).opacity(0.09)))
                .id(cur)
                .transition(.opacity)
            }
        }
        .card(padding: 16, radius: 18)
    }

    @ViewBuilder
    private func connector(visible: Bool, done: Bool) -> some View {
        Rectangle()
            .fill(visible ? (done ? AnyShapeStyle(Palette.brandGradient) : AnyShapeStyle(Palette.subtleStrong)) : AnyShapeStyle(Color.clear))
            .frame(height: 2.5)
            .frame(maxWidth: .infinity)
    }
}

private struct StageDot: View {
    var state: StageState
    var icon: String

    var body: some View {
        ZStack {
            switch state {
            case .done:
                Circle().fill(Palette.brandGradient)
                Image(systemName: "checkmark").font(.system(size: 12, weight: .heavy)).foregroundStyle(.white)
            case .active:
                Circle().fill(Palette.card)
                Circle().strokeBorder(Palette.brandGradient, lineWidth: 2.5)
                Image(systemName: icon).font(.system(size: 12, weight: .semibold)).foregroundStyle(Palette.brand)
                Spinner(size: 36, lineWidth: 2, color: Palette.brandB.opacity(0.8))
            case .failed:
                Circle().fill(Palette.red)
                Image(systemName: "xmark").font(.system(size: 12, weight: .heavy)).foregroundStyle(.white)
            case .pending, .skipped:
                Circle().fill(Palette.subtle)
                Circle().strokeBorder(Palette.subtleStrong, lineWidth: 1.5)
                Image(systemName: icon).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
                    .opacity(state == .skipped ? 0.4 : 0.9)
            }
        }
        .frame(width: 30, height: 30)
        .animation(.spring(response: 0.35, dampingFraction: 0.75), value: state)
    }
}

// MARK: - Ring

private struct RingCard: View {
    var session: ScanSession

    var body: some View {
        let p = session.currentProgress
        let scan = session.scanProgress
        let showScan = session.currentStage == "scan" || session.currentStage == "ai" || session.currentStage == "report"
        let fraction: Double? = showScan ? scan?.fraction : p?.fraction
        VStack(spacing: 14) {
            ZStack {
                ProgressRing(fraction: fraction, lineWidth: 15)
                    .frame(width: 190, height: 190)
                VStack(spacing: 2) {
                    if let fraction {
                        Text(Fmt.percent(fraction))
                            .font(.system(size: 40, weight: .bold, design: .rounded))
                            .monospacedDigit()
                            .contentTransition(.numericText())
                    } else {
                        Image(systemName: Stage.icon(session.currentStage ?? "load"))
                            .font(.system(size: 30, weight: .semibold))
                            .foregroundStyle(Palette.brandGradient)
                    }
                    Text(centerCaption(p: p, scan: scan, showScan: showScan))
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 140)
                }
            }
            .padding(.top, 6)
            Text(primaryCount(p: p, scan: scan, showScan: showScan))
                .font(.system(size: 13, weight: .semibold))
                .monospacedDigit()
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, minHeight: 262)
        .card(padding: 18, radius: 20)
    }

    private func centerCaption(p: ProgressEvent?, scan: ProgressEvent?, showScan: Bool) -> String {
        if showScan, scan != nil { return "przeskanowano" }
        switch session.currentStage {
        case "check": return "sprawdzanie adresu"
        case "sandbox": return "izolowanie"
        case "load": return "ładowanie baz"
        case "enumerate": return "szukanie plików"
        case "download": return p?.fraction != nil ? "pobrano" : "pobieranie"
        case "extract": return "rozpakowywanie"
        case "env": return "środowisko systemu"
        case "network": return "audyt sieci"
        case "behavior": return p?.fraction != nil ? "przeanalizowano" : "analiza zachowania"
        case "ai": return "analiza AI"
        case "report": return "zapis raportu"
        default: return "przygotowanie"
        }
    }

    private func primaryCount(p: ProgressEvent?, scan: ProgressEvent?, showScan: Bool) -> String {
        if showScan, let scan, let done = scan.done {
            if let total = scan.total { return "\(Fmt.int(done)) z \(Fmt.filesGenitive(total))" }
            return Fmt.files(done)
        }
        guard let p else { return session.stageTitles[session.currentStage ?? ""] ?? "Przygotowanie…" }
        switch p.stage {
        case "enumerate": return "Znaleziono \(Fmt.files(p.found ?? 0))"
        case "download":
            if let ft = p.filesTotal, ft > 0 {
                let f = p.files ?? 0
                return "Plik \(f < ft ? f + 1 : ft) z \(ft) · \(Fmt.bytes(p.bytes))"
            }
            if let t = p.total { return "\(Fmt.bytes(p.bytes)) z \(Fmt.bytes(t))" }
            return "Pobrano \(Fmt.bytes(p.bytes))"
        case "extract": return "\(Fmt.files(p.files ?? 0)) · \(Fmt.bytes(p.bytes))"
        case "behavior":
            guard let total = p.total, total > 0 else { return Stage.defaultTitle("behavior") }
            let done = p.done ?? 0
            return done < total ? "Skrypt \(done + 1) z \(total) w zamkniętym sandboksie"
                                : "Uruchomiono \(Fmt.count(total, "skrypt", "skrypty", "skryptów"))"
        default: return session.stageTitles[p.stage] ?? Stage.defaultTitle(p.stage)
        }
    }
}

// MARK: - Stats

private struct StatsGrid: View {
    var session: ScanSession
    @Environment(\.snapshotMode) private var snapshot

    var body: some View {
        let scan = session.scanProgress
        let flagged = session.flaggedCount
        let cols = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]
        LazyVGrid(columns: cols, spacing: 12) {
            StatTile(icon: "speedometer", label: "Szybkość", value: Fmt.rate(scan?.rateMBs))
            StatTile(icon: "hourglass", label: "Pozostało", value: Fmt.eta(scan?.etaSeconds))
            if snapshot {
                StatTile(icon: "stopwatch", label: "Czas trwania", value: Fmt.clock(Date().timeIntervalSince(session.startedAt)))
            } else {
                TimelineView(.periodic(from: .now, by: 1)) { ctx in
                    StatTile(icon: "stopwatch", label: "Czas trwania",
                             value: Fmt.clock((session.finishedAt ?? ctx.date).timeIntervalSince(session.startedAt)))
                }
            }
            StatTile(icon: "doc.on.doc",
                     label: scan?.total.map { "z \(Fmt.compact($0)) \(Fmt.plural($0, "pliku", "plików", "plików"))" } ?? "Pliki",
                     value: scan.map { Fmt.compact($0.done ?? 0) } ?? "—")
            StatTile(icon: "internaldrive", label: "Przeskanowano", value: Fmt.bytes(scan?.bytes))
            StatTile(icon: flagged > 0 ? "exclamationmark.triangle.fill" : "checkmark.shield.fill",
                     label: "Oznaczone", value: Fmt.int(flagged),
                     tint: flagged > 0 ? session.worstFinding.color : Palette.green, emphasize: flagged > 0)
        }
    }
}

private struct CurrentFileCard: View {
    var session: ScanSession

    var body: some View {
        // While scripts are being run, show the one in the sealed sandbox instead of the last scanned file.
        let behavior = session.currentStage == "behavior"
        let current = (behavior ? session.currentProgress?.current : nil)
            ?? session.scanProgress?.current ?? session.currentProgress?.current
        HStack(spacing: 12) {
            SoftIcon(systemName: behavior ? "testtube.2" : "doc.text.magnifyingglass", color: behavior ? Palette.cyan : Palette.brand, size: 34)
            VStack(alignment: .leading, spacing: 2) {
                Text(behavior ? "Teraz uruchamiam w zamkniętym sandboksie (bez internetu i Twoich plików)" : "Teraz sprawdzam")
                    .font(.system(size: 11.5)).foregroundStyle(.secondary)
                Text(current.map(Fmt.tilde) ?? (session.stageTitles[session.currentStage ?? ""] ?? "Przygotowanie…"))
                    .font(.system(size: 12.5, design: current == nil ? .default : .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .contentTransition(.opacity)
                    .help(current ?? "")
            }
            Spacer(minLength: 0)
        }
        .card(padding: 14, radius: 14)
    }
}

// MARK: - Live network monitor (Mega)

private struct NetLiveCard: View {
    var session: ScanSession

    private var status: NetMonitorStatus? { session.netStatus }
    private var stats: NetMonitorStats? { status?.stats }
    private var active: Bool { (status?.active ?? true) && session.isActive }

    private var alerts: Int {
        max(stats?.alerts ?? 0, session.netEvents.filter(\.isAlert).count)
    }

    private var indicatorColor: Color {
        if alerts > 0 {
            return session.netEvents.contains { $0.severity == .malicious } ? Palette.red : Palette.orange
        }
        return active ? Palette.green : Palette.gray
    }

    private var statusLine: String {
        var parts: [String] = [active ? "Monitor aktywny" : "Monitor zakończony"]
        if active, let i = status?.intervalS { parts.append("sprawdzam co \(Fmt.interval(i))") }
        if let n = status?.polls, n > 0 { parts.append(Fmt.count(n, "sprawdzenie", "sprawdzenia", "sprawdzeń")) }
        return parts.joined(separator: " · ")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .center, spacing: 12) {
                SoftIcon(systemName: "dot.radiowaves.left.and.right", color: indicatorColor, size: 34)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 10) {
                        Text("Sieć na żywo").font(.system(size: 15, weight: .semibold))
                        HStack(spacing: 6) {
                            LiveDot(color: indicatorColor, pulsing: active)
                            Text(statusLine)
                                .font(.system(size: 12, weight: .medium))
                                .foregroundStyle(active ? indicatorColor : Color.secondary)
                                .monospacedDigit()
                                .lineLimit(1)
                        }
                    }
                    Text("Pokazuję tylko to, co pojawiło się w sieci" + (status?.since.map { " od \(Fmt.time($0))" } ?? " od startu monitora")
                         + " – nowe połączenia, porty, logowania i narzędzia zdalne.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                if alerts > 0 {
                    Pill(text: Fmt.count(alerts, "alarm", "alarmy", "alarmów"), color: indicatorColor,
                         icon: "exclamationmark.triangle.fill", filled: true)
                }
            }
            metrics
            events
        }
        .card(padding: 18, radius: 18)
    }

    private var metrics: some View {
        let s = stats
        return HStack(spacing: 10) {
            NetMetric(icon: "globe.europe.africa", value: Fmt.int(s?.publicNew), label: "Nowe połączenia z Internetem")
                .help(s.map { "Wszystkich nowych połączeń: \(Fmt.int($0.connectionsNew))" } ?? "")
            NetMetric(icon: "dot.radiowaves.right", value: Fmt.int(s?.listeningNew), label: "Nowe otwarte porty")
            NetMetric(icon: "arrow.down.left.circle", value: Fmt.int(s?.inbound), label: "Połączenia przychodzące")
            NetMetric(icon: "person.badge.clock", value: Fmt.int(s?.sessionsNew), label: "Nowe logowania")
            NetMetric(icon: "arrow.up.circle", value: Fmt.bytes(s?.uploadedBytes), label: "Wysłano w trakcie skanu")
            NetMetric(icon: alerts > 0 ? "exclamationmark.triangle.fill" : "checkmark.shield.fill",
                      value: Fmt.int(alerts), label: "Alarmy",
                      tint: alerts > 0 ? indicatorColor : Palette.green, emphasize: alerts > 0)
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder
    private var events: some View {
        let all = session.netEvents
        if all.isEmpty {
            HStack(spacing: 10) {
                Image(systemName: "checkmark.shield.fill").foregroundStyle(Palette.green)
                Text("Na razie nic nowego – nikt się nie łączy, nic nowego nie nasłuchuje.").foregroundStyle(.secondary)
            }
            .font(.system(size: 13))
            .padding(.vertical, 2)
        } else {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(all.prefix(5)) { e in
                    NetLiveRow(event: e)
                        .transition(.asymmetric(insertion: .move(edge: .top).combined(with: .opacity), removal: .opacity))
                }
                if all.count > 5 {
                    Text("+ \(Fmt.count(all.count - 5, "wcześniejsze zdarzenie", "wcześniejsze zdarzenia", "wcześniejszych zdarzeń")) – pełna lista będzie w wynikach (zakładka „Sieć i zdalny dostęp”).")
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                        .padding(.leading, 4)
                }
            }
        }
    }
}

/// Compact metric used inside cards (live monitor on the progress screen and in the results).
struct NetMetric: View {
    var icon: String
    var value: String
    var label: String
    var tint: Color = Palette.brand
    var emphasize = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Image(systemName: icon).font(.system(size: 11.5, weight: .semibold)).foregroundStyle(tint)
                Text(value)
                    .font(.system(size: 16, weight: .semibold, design: .rounded))
                    .monospacedDigit()
                    .foregroundStyle(emphasize ? tint : Color.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                    .contentTransition(.numericText())
            }
            Text(label)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .lineLimit(3)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(emphasize ? tint.opacity(0.09) : Palette.subtle.opacity(0.8)))
    }
}

private struct NetLiveRow: View {
    var event: NetEvent

    var body: some View {
        let color = event.severity.netColor
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Dot(color: color, size: 8)
                .alignmentGuide(.firstTextBaseline) { $0[VerticalAlignment.center] + 4 }
            Text(event.time.map { Fmt.time($0, seconds: true) } ?? "—")
                .font(.system(size: 11.5, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 62, alignment: .leading)
            VStack(alignment: .leading, spacing: 1) {
                Text(event.title)
                    .font(.system(size: 12.5, weight: event.isAlert ? .semibold : .medium))
                    .lineLimit(1)
                    .truncationMode(.tail)
                if let d = event.detail {
                    Text(Fmt.tilde(d))
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
            }
            .help([event.title, event.detail].compactMap { $0 }.joined(separator: "\n"))
            Spacer(minLength: 8)
            if event.isAlert {
                Pill(text: event.severity.label, color: color, filled: event.severity.rank >= Severity.suspicious.rank)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous)
            .fill(event.isAlert ? color.opacity(0.07) : Palette.subtle.opacity(0.6)))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
            .strokeBorder(event.isAlert ? color.opacity(0.22) : Color.clear, lineWidth: 1))
    }
}

/// Small status dot; a ring pulses out of it while the monitor runs (static offscreen).
private struct LiveDot: View {
    var color: Color
    var pulsing: Bool
    @State private var animate = false
    @Environment(\.snapshotMode) private var snapshot

    var body: some View {
        ZStack {
            Circle()
                .stroke(color.opacity(animate ? 0 : 0.7), lineWidth: 1.5)
                .scaleEffect(animate ? 2.4 : 1)
                .opacity(pulsing && !snapshot ? 1 : 0)
                .animation(pulsing && !snapshot ? .easeOut(duration: 1.4).repeatForever(autoreverses: false) : nil, value: animate)
            Circle().fill(color)
        }
        .frame(width: 8, height: 8)
        .onAppear { if !snapshot { animate = true } }
    }
}

// MARK: - Live findings

private struct LiveFindingsCard: View {
    var session: ScanSession

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Text("Wykryte na bieżąco").font(.system(size: 15, weight: .semibold))
                if !session.findings.isEmpty {
                    Text("\(session.findings.count)")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(session.worstFinding.color))
                }
                Spacer()
            }
            if session.findings.isEmpty {
                HStack(spacing: 10) {
                    Image(systemName: "checkmark.shield.fill").foregroundStyle(Palette.green)
                    Text("Na razie nic podejrzanego.").foregroundStyle(.secondary)
                }
                .font(.system(size: 13))
                .padding(.vertical, 6)
            } else {
                VStack(spacing: 8) {
                    ForEach(session.findings.reversed()) { r in
                        LiveFindingRow(result: r)
                            .transition(.asymmetric(insertion: .move(edge: .top).combined(with: .opacity), removal: .opacity))
                    }
                }
            }
        }
        .card(padding: 18, radius: 18)
    }
}

private struct LiveFindingRow: View {
    var result: ScanResult

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: result.verdict.icon)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(result.verdict.color)
                .frame(width: 30, height: 30)
                .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(result.verdict.color.opacity(0.13)))
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(result.fileName).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                    if result.detonation != nil {
                        Pill(text: "Zachowanie", color: Palette.cyan, icon: "testtube.2")
                            .help("Skrypt został uruchomiony w zamkniętym sandboksie")
                    }
                }
                Text(Fmt.tilde(result.displayPath)).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 8)
            if let p = result.primary {
                Text(p).font(.system(size: 11.5, weight: .medium, design: .monospaced))
                    .foregroundStyle(result.verdict.color)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: 280, alignment: .trailing)
            }
            VerdictBadge(verdict: result.verdict)
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(result.verdict.color.opacity(0.05)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(result.verdict.color.opacity(0.18), lineWidth: 1))
    }
}

// MARK: - Technical log

struct TechnicalLog: View {
    var session: ScanSession
    @Binding var expanded: Bool
    @Environment(\.snapshotMode) private var snapshot

    var body: some View {
        DisclosureCard(title: "Szczegóły techniczne", icon: "terminal",
                       subtitle: "\(session.log.count) wpisów", expanded: $expanded) {
            VStack(alignment: .trailing, spacing: 8) {
                logBody
                    .frame(height: 200)
                    .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Palette.codeBG))
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                Button {
                    FinderActions.copy(session.log.map(\.text).joined(separator: "\n"))
                } label: {
                    Label("Kopiuj dziennik", systemImage: "doc.on.doc")
                }
                .buttonStyle(SecondaryButtonStyle(compact: true))
            }
        }
    }

    @ViewBuilder
    private var logBody: some View {
        if snapshot {
            VStack(alignment: .leading, spacing: 2) {
                Spacer(minLength: 0)
                ForEach(session.log.suffix(11)) { line in row(line) }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(session.log) { line in row(line).id(line.id) }
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                }
                .onChange(of: session.log.last?.id) { _, id in
                    if let id { proxy.scrollTo(id, anchor: .bottom) }
                }
                .onAppear { if let id = session.log.last?.id { proxy.scrollTo(id, anchor: .bottom) } }
            }
        }
    }

    private func row(_ line: LogLine) -> some View {
        Text(line.text)
            .font(.system(size: 11, design: .monospaced))
            .foregroundStyle(line.isStderr ? Color(hex: 0x8B93A7) : Color(hex: 0xD8DEE9))
            .frame(maxWidth: .infinity, alignment: .leading)
            .lineLimit(snapshot ? 1 : nil)
    }
}

// MARK: - Failure

struct FailureScreen: View {
    @Environment(AppModel.self) private var model
    var session: ScanSession
    @State private var showLog = true

    var body: some View {
        let cancelled: Bool = { if case .failed(let c) = session.phase { return c }; return false }()
        AdaptiveScroll {
            VStack(spacing: 18) {
                if let v = session.sandboxViolation { SandboxViolationBanner(problems: v) }
                VStack(spacing: 14) {
                    Image(systemName: cancelled ? "stop.circle.fill" : "exclamationmark.octagon.fill")
                        .font(.system(size: 54, weight: .semibold))
                        .foregroundStyle(cancelled ? Palette.orange : Palette.red)
                        .padding(20)
                        .background(Circle().fill((cancelled ? Palette.orange : Palette.red).opacity(0.12)))
                    Text(cancelled ? "Skanowanie przerwane" : "Skanowanie nie powiodło się")
                        .font(.system(size: 24, weight: .bold, design: .rounded))
                    Text(cancelled
                         ? "Skaner zakończył pracę, zanim przesłał wyniki. Nic nie zostało zmienione na dysku."
                         : (session.fatalMessage ?? "Nieznany błąd."))
                        .font(.system(size: 14))
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 560)
                        .textSelection(.enabled)
                    HStack(spacing: 10) {
                        Button {
                            model.retry()
                        } label: {
                            Label("Spróbuj ponownie", systemImage: "arrow.clockwise")
                        }
                        .buttonStyle(PrimaryButtonStyle())
                        Button {
                            model.newScan()
                        } label: {
                            Label("Wróć", systemImage: "chevron.left")
                        }
                        .buttonStyle(SecondaryButtonStyle())
                    }
                    .padding(.top, 4)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 30)
                .card(radius: 22)
                TechnicalLog(session: session, expanded: $showLog)
            }
            .padding(32)
            .frame(maxWidth: 900)
            .frame(maxWidth: .infinity)
        }
        .background(Palette.canvas)
    }
}

import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Scrolling that also works offscreen

/// A vertical ScrollView, replaced by a plain top-aligned container in snapshot mode
/// (ImageRenderer cannot draw NSScrollView content).
struct AdaptiveScroll<Content: View>: View {
    @Environment(\.snapshotMode) private var snapshot
    @ViewBuilder var content: Content

    var body: some View {
        if snapshot {
            VStack(spacing: 0) {
                content
            }
            .fixedSize(horizontal: false, vertical: true)
            .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity, alignment: .top)
            .clipped()
        } else {
            ScrollView(.vertical) {
                content
            }
            .scrollIndicators(.automatic)
        }
    }
}

// MARK: - Screen scaffold

struct ScreenHeader: View {
    var icon: String
    var title: String
    var subtitle: String

    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            IconTile(systemName: icon, size: 52)
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.system(size: 28, weight: .bold, design: .rounded))
                Text(subtitle)
                    .font(.system(size: 14))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
    }
}

struct ScreenScaffold<Content: View>: View {
    var item: SidebarItem
    var subtitle: String
    @ViewBuilder var content: Content

    var body: some View {
        AdaptiveScroll {
            VStack(alignment: .leading, spacing: 22) {
                ScreenHeader(icon: item.icon, title: item.title, subtitle: subtitle)
                content
            }
            .padding(.horizontal, 36)
            .padding(.top, 30)
            .padding(.bottom, 36)
            .frame(maxWidth: 1080)
            .frame(maxWidth: .infinity)
        }
        .background(Palette.canvas)
    }
}

// MARK: - "Scan busy" banner

struct BusyBanner: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let s = model.session, s.isActive {
            Banner(icon: "hourglass", title: "Trwa skanowanie: \(s.request.title)",
                   message: "Cerber wykonuje jedno skanowanie naraz – nowe możesz zacząć po jego zakończeniu.",
                   color: Palette.brand, action: ("Pokaż postęp", { model.selection = .session }))
        }
    }
}

// MARK: - AI toggle

struct AIToggleCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Toggle(isOn: $model.aiEnabled) {
            HStack(spacing: 12) {
                SoftIcon(systemName: "sparkles", color: Palette.brand, size: 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Analiza AI (lokalnie)").font(.system(size: 13.5, weight: .semibold))
                    Text(model.aiStatusNote
                         ?? "Model działa wyłącznie na tym Macu i sprawdza zarzuty silników wobec plików z „szarej strefy” – potwierdza je albo podważa. Nie decyduje sam: zmienia wynik najwyżej o 15 punktów. Wydłuża skanowanie.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if let f = model.aiInstall.fraction, !model.aiAvailable {
                        LinearBar(fraction: f, gradient: [Palette.brandA, Palette.brandB], height: 4)
                            .frame(maxWidth: 260)
                            .padding(.top, 3)
                    }
                }
            }
        }
        .toggleStyle(SwitchToggleStyle())
        .disabled(!model.aiAvailable)
        .card(padding: 16, radius: 16)
    }
}

/// "Aktywna obrona" for laptop / location / file scans – the same switch as in background protection.
struct DefenseToggleCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let p = model.protection
        Toggle(isOn: Binding(get: { p.activeDefense }, set: { p.setActiveDefense($0) })) {
            HStack(spacing: 12) {
                SoftIcon(systemName: "shield.lefthalf.filled", color: Palette.green, size: 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Aktywna obrona").font(.system(size: 13.5, weight: .semibold))
                    Text("Pewne zagrożenia znalezione w trakcie skanu od razu trafiają do kwarantanny, a uruchomione z nich procesy są zatrzymywane (zrywa to ich połączenia; w Mega także ataki wykryte na żywo). Nigdy nie rusza systemu macOS, aplikacji Apple, Cerbera ani programów znanych producentów. Każde działanie można cofnąć. Ten sam przełącznik co w Ochronie w tle.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .toggleStyle(SwitchToggleStyle())
        .card(padding: 16, radius: 16)
    }
}

// MARK: - Drop zone

struct DropZone: View {
    var icon: String
    var title: String
    var subtitle: String
    var buttonTitle: String
    var height: CGFloat = 270
    var onPick: () -> Void
    var onDrop: ([URL]) -> Void

    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.snapshotMode) private var snapshot
    @State private var targeted = false
    @State private var hovering = false

    private var active: Bool { targeted && isEnabled }

    var body: some View {
        VStack(spacing: 14) {
            ZStack {
                Circle()
                    .fill(Palette.brandGradient)
                    .opacity(active ? 0.22 : 0.12)
                    .frame(width: 92, height: 92)
                    .scaleEffect(active ? 1.12 : 1)
                Image(systemName: icon)
                    .font(.system(size: 36, weight: .semibold))
                    .foregroundStyle(Palette.brandGradient)
                    .offset(y: active ? 3 : 0)
            }
            VStack(spacing: 5) {
                Text(active ? "Upuść, aby przeskanować" : title)
                    .font(.system(size: 18, weight: .semibold))
                Text(subtitle)
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 440)
            }
            HStack(spacing: 10) {
                Rectangle().fill(Palette.cardBorder).frame(width: 40, height: 1)
                Text("albo").font(.system(size: 12)).foregroundStyle(.tertiary)
                Rectangle().fill(Palette.cardBorder).frame(width: 40, height: 1)
            }
            Button(action: onPick) {
                Label(buttonTitle, systemImage: "folder")
            }
            .buttonStyle(PrimaryButtonStyle())
        }
        .padding(28)
        .frame(maxWidth: .infinity, minHeight: height)
        .background(
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .fill(active ? AnyShapeStyle(Palette.brand.opacity(0.08)) : AnyShapeStyle(Palette.card))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .strokeBorder(style: StrokeStyle(lineWidth: active ? 2.5 : 2, dash: [9, 7]))
                .foregroundStyle(active ? AnyShapeStyle(Palette.brandGradient)
                                 : AnyShapeStyle(Color.secondary.opacity(hovering ? 0.55 : 0.32)))
        )
        .shadow(color: active ? Palette.brandA.opacity(0.25) : Palette.shadow, radius: active ? 18 : 10, y: 4)
        .scaleEffect(active ? 1.01 : 1)
        .animation(.spring(response: 0.35, dampingFraction: 0.7), value: active)
        .animation(.easeOut(duration: 0.15), value: hovering)
        .onHover { hovering = $0 }
        .modifier(DropTarget(enabled: !snapshot && isEnabled, targeted: $targeted, onDrop: onDrop))
        .opacity(isEnabled ? 1 : 0.6)
    }
}

/// File-URL drop target (skipped offscreen, where AppKit drop views cannot be drawn).
private struct DropTarget: ViewModifier {
    var enabled: Bool
    @Binding var targeted: Bool
    var onDrop: ([URL]) -> Void

    func body(content: Content) -> some View {
        if enabled {
            content.dropDestination(for: URL.self) { urls, _ in
                let files = urls.filter(\.isFileURL)
                guard !files.isEmpty else { return false }
                onDrop(files)
                return true
            } isTargeted: { targeted = $0 }
        } else {
            content
        }
    }
}

// MARK: - Progress shapes (custom so they render offscreen)

struct ProgressRing: View {
    var fraction: Double?
    var lineWidth: CGFloat = 14
    var colors: [Color] = [Palette.brandA, Palette.brandB]
    @State private var spin = false
    @Environment(\.snapshotMode) private var snapshot

    var body: some View {
        ZStack {
            Circle().stroke(Palette.subtleStrong, lineWidth: lineWidth)
            if let fraction {
                Circle()
                    .trim(from: 0, to: max(0.004, fraction))
                    .stroke(AngularGradient(colors: colors + [colors.first ?? .blue], center: .center),
                            style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                    .animation(.easeInOut(duration: 0.4), value: fraction)
            } else {
                Circle()
                    .trim(from: 0, to: 0.28)
                    .stroke(AngularGradient(colors: [colors.first!.opacity(0), colors.last!], center: .center,
                                            startAngle: .degrees(0), endAngle: .degrees(100)),
                            style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
                    .rotationEffect(.degrees(spin ? 360 : 0))
                    .animation(snapshot ? nil : .linear(duration: 1.1).repeatForever(autoreverses: false), value: spin)
                    .onAppear { if !snapshot { spin = true } }
            }
        }
    }
}

struct LinearBar: View {
    var fraction: Double
    var color: Color = Palette.brand
    var gradient: [Color]? = nil
    var height: CGFloat = 6

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(Palette.subtleStrong)
                Capsule()
                    .fill(gradient.map { AnyShapeStyle(LinearGradient(colors: $0, startPoint: .leading, endPoint: .trailing)) }
                          ?? AnyShapeStyle(color))
                    .frame(width: max(height, geo.size.width * min(1, max(0, fraction))))
            }
        }
        .frame(height: height)
    }
}

struct Spinner: View {
    var size: CGFloat = 14
    var lineWidth: CGFloat = 2
    var color: Color = Palette.brand
    @State private var spin = false
    @Environment(\.snapshotMode) private var snapshot

    var body: some View {
        Circle()
            .trim(from: 0.08, to: 0.78)
            .stroke(color, style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
            .frame(width: size, height: size)
            .rotationEffect(.degrees(spin ? 360 : 0))
            .animation(snapshot ? nil : .linear(duration: 0.9).repeatForever(autoreverses: false), value: spin)
            .onAppear { if !snapshot { spin = true } }
    }
}

// MARK: - Disclosure (custom)

struct DisclosureCard<Content: View>: View {
    var title: String
    var icon: String
    var subtitle: String? = nil
    @Binding var expanded: Bool
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) { expanded.toggle() }
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                    Image(systemName: icon).foregroundStyle(.secondary)
                    Text(title).font(.system(size: 13, weight: .semibold))
                    if let subtitle {
                        Text(subtitle).font(.system(size: 12)).foregroundStyle(.tertiary)
                    }
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if expanded {
                content
                    .padding(.top, 12)
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .card(padding: 14, radius: 14)
    }
}

// MARK: - Text input that renders offscreen

struct InputField: View {
    var placeholder: String
    @Binding var text: String
    var icon: String
    var state: FieldState = .neutral
    var onSubmit: () -> Void = {}
    @Environment(\.snapshotMode) private var snapshot
    @FocusState private var focused: Bool

    enum FieldState { case neutral, valid, invalid }

    private var borderColor: Color {
        switch state {
        case .neutral: return focused ? Palette.brand.opacity(0.7) : Palette.cardBorder
        case .valid: return Palette.green.opacity(0.7)
        case .invalid: return Palette.red.opacity(0.6)
        }
    }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(.secondary)
            Group {
                if snapshot {
                    Text(text.isEmpty ? placeholder : text)
                        .foregroundStyle(text.isEmpty ? Color.secondary.opacity(0.7) : Color.primary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    TextField(placeholder, text: $text)
                        .textFieldStyle(.plain)
                        .focused($focused)
                        .onSubmit(onSubmit)
                }
            }
            .font(.system(size: 15))
            .lineLimit(1)
            switch state {
            case .valid:
                Image(systemName: "checkmark.circle.fill").foregroundStyle(Palette.green)
                    .transition(.scale.combined(with: .opacity))
            case .invalid:
                Image(systemName: "exclamationmark.circle.fill").foregroundStyle(Palette.red)
                    .transition(.scale.combined(with: .opacity))
            case .neutral:
                EmptyView()
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Palette.card))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(borderColor, lineWidth: focused || state != .neutral ? 1.5 : 1))
        .shadow(color: Palette.shadow, radius: 8, y: 2)
        .animation(.easeOut(duration: 0.2), value: state)
    }
}

struct SearchField: View {
    @Binding var text: String
    var placeholder = "Szukaj"
    @Environment(\.snapshotMode) private var snapshot

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: "magnifyingglass").font(.system(size: 12, weight: .medium)).foregroundStyle(.secondary)
            if snapshot {
                Text(text.isEmpty ? placeholder : text)
                    .foregroundStyle(text.isEmpty ? Color.secondary.opacity(0.7) : Color.primary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                TextField(placeholder, text: $text).textFieldStyle(.plain)
            }
            if !text.isEmpty {
                Button { text = "" } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary)
                }
                .buttonStyle(.plain)
            }
        }
        .font(.system(size: 13))
        .padding(.horizontal, 11)
        .padding(.vertical, 7)
        .background(Capsule().fill(Palette.subtle))
        .overlay(Capsule().strokeBorder(Palette.cardBorder, lineWidth: 1))
    }
}

// MARK: - Empty state

struct EmptyState: View {
    var icon: String
    var title: String
    var message: String
    var color: Color = Palette.green

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 40, weight: .semibold))
                .foregroundStyle(color)
                .padding(18)
                .background(Circle().fill(color.opacity(0.12)))
            Text(title).font(.system(size: 16, weight: .semibold))
            Text(message).font(.system(size: 13)).foregroundStyle(.secondary)
                .multilineTextAlignment(.center).frame(maxWidth: 420)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 34)
        .card()
    }
}

// MARK: - Simple data grid (used offscreen instead of Table)

struct GridColumn<Row> {
    var title: String
    var width: CGFloat?          // nil = flexible
    var alignment: Alignment = .leading
    var cell: (Row) -> AnyView
}

struct SnapshotGrid<Row: Identifiable>: View {
    var rows: [Row]
    var columns: [GridColumn<Row>]
    var maxRows = 12

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                ForEach(columns.indices, id: \.self) { i in
                    cellFrame(Text(columns[i].title).font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary), i)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(Palette.subtle)
            ForEach(Array(rows.prefix(maxRows).enumerated()), id: \.element.id) { idx, row in
                HStack(spacing: 12) {
                    ForEach(columns.indices, id: \.self) { i in
                        cellFrame(columns[i].cell(row), i)
                    }
                }
                .font(.system(size: 12))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(idx % 2 == 1 ? Palette.subtle.opacity(0.5) : Color.clear)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    @ViewBuilder
    private func cellFrame<V: View>(_ v: V, _ i: Int) -> some View {
        if let w = columns[i].width {
            v.frame(width: w, alignment: columns[i].alignment)
        } else {
            v.frame(maxWidth: .infinity, alignment: columns[i].alignment)
        }
    }
}

// MARK: - Finder helpers

enum FinderActions {
    static func reveal(_ path: String) {
        let fm = FileManager.default
        var url = URL(fileURLWithPath: path)
        // Walk up until something exists (results may point into archives).
        while !fm.fileExists(atPath: url.path), url.path != "/" {
            url.deleteLastPathComponent()
        }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    static func open(_ path: String) -> Bool {
        guard FileManager.default.fileExists(atPath: path) else { return false }
        return NSWorkspace.shared.open(URL(fileURLWithPath: path))
    }

    static func exists(_ path: String?) -> Bool {
        guard let path, !path.isEmpty else { return false }
        return FileManager.default.fileExists(atPath: path)
    }

    static func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }
}

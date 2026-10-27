import AppKit
import SwiftUI

// MARK: - Colors

extension NSColor {
    convenience init(hex: UInt32, alpha: CGFloat = 1) {
        self.init(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                  blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
    }
}

extension Color {
    init(hex: UInt32, opacity: Double = 1) {
        self.init(.sRGB, red: Double((hex >> 16) & 0xFF) / 255, green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255, opacity: opacity)
    }

    /// Light/dark adaptive color.
    static func dyn(_ light: UInt32, _ dark: UInt32, lightAlpha: CGFloat = 1, darkAlpha: CGFloat = 1) -> Color {
        Color(nsColor: NSColor(name: nil) { ap in
            ap.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                ? NSColor(hex: dark, alpha: darkAlpha) : NSColor(hex: light, alpha: lightAlpha)
        })
    }
}

enum Palette {
    static let brandA = Color(hex: 0x4F46E5)
    static let brandB = Color(hex: 0x0EA5E9)
    static let brand = Color.dyn(0x4F46E5, 0x7C83FF)

    static let canvas = Color.dyn(0xF4F5F9, 0x15161B)
    static let card = Color.dyn(0xFFFFFF, 0x1F2027)
    static let cardRaised = Color.dyn(0xFFFFFF, 0x262731)
    static let cardBorder = Color.dyn(0x000000, 0xFFFFFF, lightAlpha: 0.07, darkAlpha: 0.08)
    static let subtle = Color.dyn(0xF1F2F6, 0x2A2B34)
    static let subtleStrong = Color.dyn(0xE6E8EF, 0x33343F)
    static let sidebar = Color.dyn(0xE9EAF0, 0x1A1B21)
    static let codeBG = Color.dyn(0x1B1D26, 0x0E0F13)
    static let shadow = Color.dyn(0x1A1D3A, 0x000000, lightAlpha: 0.08, darkAlpha: 0.35)

    static let green = Color.dyn(0x1E9E53, 0x34D17A)
    static let blue = Color.dyn(0x2F74F0, 0x4C9AFF)
    static let orange = Color.dyn(0xE87F00, 0xFFA23A)
    static let purple = Color.dyn(0x9446D8, 0xC17BF5)
    static let red = Color.dyn(0xE0383E, 0xFF5A52)
    static let yellow = Color.dyn(0xC99400, 0xFFD34D)
    static let gray = Color.dyn(0x6E717E, 0x9A9DAA)
    static let teal = Color.dyn(0x0E9488, 0x2DD4BF)
    static let pink = Color.dyn(0xC2307F, 0xF472B6)
    /// Behaviour analysis (scripts run in the sealed sandbox).
    static let cyan = Color.dyn(0x0E7490, 0x22A6C3)

    static var brandGradient: LinearGradient {
        LinearGradient(colors: [brandA, brandB], startPoint: .topLeading, endPoint: .bottomTrailing)
    }
}

// MARK: - Verdict / severity styling

extension Verdict {
    var color: Color {
        switch self {
        case .clean: return Palette.green
        case .info: return Palette.blue
        case .suspicious: return Palette.orange
        case .pua: return Palette.purple
        case .malicious: return Palette.red
        }
    }

    /// Two raw colors for the hero gradient (same in both appearances).
    var heroColors: [Color] {
        switch self {
        case .clean: return [Color(hex: 0x16A34A), Color(hex: 0x0D9488)]
        case .info: return [Color(hex: 0x2563EB), Color(hex: 0x0EA5E9)]
        case .suspicious: return [Color(hex: 0xEA7A0C), Color(hex: 0xE5A50A)]
        case .pua: return [Color(hex: 0x7E3AD9), Color(hex: 0xB33ACF)]
        case .malicious: return [Color(hex: 0xD92D3A), Color(hex: 0xB0154F)]
        }
    }

    var heroTitle: String {
        switch self {
        case .clean: return "Czysto"
        case .info: return "Brak zagrożeń"
        case .suspicious: return "Podejrzane"
        case .pua: return "Niechciane (PUA)"
        case .malicious: return "Wykryto zagrożenie"
        }
    }

    var heroIcon: String {
        switch self {
        case .clean: return "checkmark.shield.fill"
        case .info: return "info.circle.fill"
        case .suspicious: return "exclamationmark.triangle.fill"
        case .pua: return "hand.raised.fill"
        case .malicious: return "xmark.shield.fill"
        }
    }

    var icon: String {
        switch self {
        case .clean: return "checkmark.circle.fill"
        case .info: return "info.circle.fill"
        case .suspicious: return "exclamationmark.triangle.fill"
        case .pua: return "hand.raised.fill"
        case .malicious: return "xmark.octagon.fill"
        }
    }

    /// Short label for a single file.
    var badge: String {
        switch self {
        case .clean: return "Czysty"
        case .info: return "Info"
        case .suspicious: return "Podejrzany"
        case .pua: return "PUA"
        case .malicious: return "Złośliwy"
        }
    }

    /// Section heading for a group of files.
    var groupTitle: String {
        switch self {
        case .clean: return "Czyste"
        case .info: return "Informacyjne"
        case .suspicious: return "Podejrzane"
        case .pua: return "Niechciane (PUA)"
        case .malicious: return "Złośliwe"
        }
    }

    func countPhrase(_ n: Int) -> String {
        switch self {
        case .clean: return Fmt.count(n, "czysty", "czyste", "czystych")
        case .info: return Fmt.count(n, "informacyjny", "informacyjne", "informacyjnych")
        case .suspicious: return Fmt.count(n, "podejrzany", "podejrzane", "podejrzanych")
        case .pua: return Fmt.count(n, "niechciany", "niechciane", "niechcianych")
        case .malicious: return Fmt.count(n, "złośliwy", "złośliwe", "złośliwych")
        }
    }
}

extension Severity {
    var color: Color {
        switch self {
        case .malicious: return Palette.red
        case .pua: return Palette.purple
        case .suspicious: return Palette.orange
        case .low: return Palette.yellow
        case .info: return Palette.blue
        }
    }

    var label: String {
        switch self {
        case .malicious: return "Złośliwe"
        case .pua: return "Niechciane"
        case .suspicious: return "Podejrzane"
        case .low: return "Niskie ryzyko"
        case .info: return "Informacja"
        }
    }

    /// Live network monitor: harmless "info" changes stay neutral grey, PUA reads as suspicious.
    var netColor: Color {
        switch self {
        case .malicious: return Palette.red
        case .pua, .suspicious: return Palette.orange
        case .low: return Palette.yellow
        case .info: return Palette.gray
        }
    }
}

enum RiskStyle {
    static func color(_ risk: String) -> Color {
        switch risk {
        case "malicious": return Palette.red
        case "suspicious": return Palette.orange
        case "low": return Palette.yellow
        default: return Palette.blue
        }
    }

    static func label(_ risk: String) -> String {
        switch risk {
        case "malicious": return "Złośliwe"
        case "suspicious": return "Podejrzane"
        case "low": return "Niskie ryzyko"
        default: return "Informacja"
        }
    }
}

enum EngineStyle {
    static func label(_ e: String) -> String {
        switch e {
        case "clamav": return "ClamAV"
        case "yara": return "YARA"
        case "hash": return "Hash"
        case "heuristic": return "Heurystyka"
        case "ioc": return "IOC"
        case "fuzzy": return "TLSH"
        case "macos": return "macOS"
        case "ai": return "AI"
        case "env": return "Środowisko"
        case "detonate": return "Sandbox (zachowanie)"
        case "": return "—"
        default: return e.capitalized
        }
    }

    static func color(_ e: String) -> Color {
        switch e {
        case "clamav": return Palette.red
        case "yara": return Palette.purple
        case "hash": return Palette.blue
        case "heuristic": return Palette.orange
        case "ioc": return Palette.pink
        case "fuzzy": return Palette.teal
        case "macos": return Palette.gray
        case "ai": return Palette.brand
        case "detonate": return Palette.cyan
        default: return Palette.gray
        }
    }

    static func confidence(_ c: String) -> String {
        switch c {
        case "CERTAIN": return "pewne"
        case "HIGH": return "wysoka pewność"
        case "MEDIUM": return "średnia pewność"
        case "LOW": return "niska pewność"
        case "INFO": return "informacja"
        default: return c.lowercased()
        }
    }

    static func confidenceLevel(_ c: String) -> Int {
        switch c {
        case "CERTAIN": return 4
        case "HIGH": return 3
        case "MEDIUM": return 2
        case "LOW": return 1
        default: return 0
        }
    }
}

// MARK: - Snapshot environment

private struct SnapshotModeKey: EnvironmentKey {
    static let defaultValue = false
}

extension EnvironmentValues {
    /// True when rendered offscreen by `--snapshot` (no AppKit-backed controls available).
    var snapshotMode: Bool {
        get { self[SnapshotModeKey.self] }
        set { self[SnapshotModeKey.self] = newValue }
    }
}

// MARK: - Card

struct CardModifier: ViewModifier {
    var padding: CGFloat = 20
    var radius: CGFloat = 18
    var fill: Color = Palette.card

    func body(content: Content) -> some View {
        content
            .padding(padding)
            .background(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .fill(fill)
                    .shadow(color: Palette.shadow, radius: 12, x: 0, y: 4)
            )
            .overlay(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .strokeBorder(Palette.cardBorder, lineWidth: 1)
            )
    }
}

extension View {
    func card(padding: CGFloat = 20, radius: CGFloat = 18, fill: Color = Palette.card) -> some View {
        modifier(CardModifier(padding: padding, radius: radius, fill: fill))
    }
}

// MARK: - Buttons

struct PrimaryButtonStyle: ButtonStyle {
    var large = false
    var colors: [Color] = [Palette.brandA, Palette.brandB]
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: large ? 16 : 13, weight: .semibold))
            .foregroundStyle(.white)
            .padding(.horizontal, large ? 30 : 16)
            .padding(.vertical, large ? 14 : 8)
            .background(
                Capsule(style: .continuous)
                    .fill(LinearGradient(colors: isEnabled ? colors : [Color.gray.opacity(0.55), Color.gray.opacity(0.45)],
                                         startPoint: .topLeading, endPoint: .bottomTrailing))
                    .shadow(color: (isEnabled ? colors.first ?? .clear : .clear).opacity(0.35), radius: large ? 14 : 6, y: large ? 6 : 3)
            )
            .overlay(Capsule(style: .continuous).strokeBorder(.white.opacity(0.18), lineWidth: 1))
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .brightness(configuration.isPressed ? -0.05 : 0)
            .animation(.easeOut(duration: 0.15), value: configuration.isPressed)
            .contentShape(Capsule())
    }
}

struct SecondaryButtonStyle: ButtonStyle {
    var tint: Color? = nil
    var compact = false
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: compact ? 12 : 13, weight: .medium))
            .foregroundStyle(tint ?? Color.primary)
            .padding(.horizontal, compact ? 10 : 14)
            .padding(.vertical, compact ? 5 : 7)
            .background(
                Capsule(style: .continuous)
                    .fill((tint ?? Color.primary).opacity(configuration.isPressed ? 0.16 : 0.08))
            )
            .overlay(Capsule(style: .continuous).strokeBorder((tint ?? Color.primary).opacity(0.12), lineWidth: 1))
            .opacity(isEnabled ? 1 : 0.45)
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
            .contentShape(Capsule())
    }
}

/// White-on-color buttons for the verdict hero.
struct HeroButtonStyle: ButtonStyle {
    var filled = true
    var accent: Color = .black

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(filled ? accent : Color.white)
            .padding(.horizontal, 16)
            .padding(.vertical, 9)
            .background(Capsule().fill(filled ? Color.white : Color.white.opacity(0.18)))
            .overlay(Capsule().strokeBorder(Color.white.opacity(filled ? 0 : 0.35), lineWidth: 1))
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
            .contentShape(Capsule())
    }
}

/// Plain hover-highlight button used for rows / tiles.
struct TileButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.985 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

// MARK: - Switch toggle (custom so it renders offscreen too)

struct SwitchToggleStyle: ToggleStyle {
    var tint: Color? = nil
    @Environment(\.isEnabled) private var isEnabled

    private var tintColors: [Color] { tint.map { [$0, $0.opacity(0.8)] } ?? [Palette.brandA, Palette.brandB] }

    func makeBody(configuration: Configuration) -> some View {
        Button {
            withAnimation(.spring(response: 0.3, dampingFraction: 0.75)) { configuration.isOn.toggle() }
        } label: {
            HStack(spacing: 12) {
                configuration.label
                Spacer(minLength: 8)
                ZStack(alignment: configuration.isOn ? .trailing : .leading) {
                    Capsule()
                        .fill(configuration.isOn ? AnyShapeStyle(LinearGradient(colors: tintColors, startPoint: .leading, endPoint: .trailing))
                              : AnyShapeStyle(Palette.subtleStrong))
                        .frame(width: 42, height: 24)
                    Circle()
                        .fill(.white)
                        .shadow(color: .black.opacity(0.25), radius: 1.5, y: 1)
                        .frame(width: 20, height: 20)
                        .padding(2)
                }
                .opacity(isEnabled ? 1 : 0.45)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Small pieces

struct Pill: View {
    var text: String
    var color: Color
    var icon: String? = nil
    var filled = false

    var body: some View {
        HStack(spacing: 4) {
            if let icon { Image(systemName: icon).font(.system(size: 9.5, weight: .bold)) }
            Text(text).font(.system(size: 11, weight: .semibold)).lineLimit(1)
        }
        .foregroundStyle(filled ? Color.white : color)
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(Capsule().fill(filled ? AnyShapeStyle(color) : AnyShapeStyle(color.opacity(0.14))))
        .fixedSize()
    }
}

struct VerdictBadge: View {
    var verdict: Verdict
    var large = false

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: verdict.icon).font(.system(size: large ? 12 : 10, weight: .bold))
            Text(verdict.badge).font(.system(size: large ? 13 : 11, weight: .semibold))
        }
        .foregroundStyle(verdict.color)
        .padding(.horizontal, large ? 10 : 8)
        .padding(.vertical, large ? 5 : 3)
        .background(Capsule().fill(verdict.color.opacity(0.14)))
        .fixedSize()
    }
}

struct IconTile: View {
    var systemName: String
    var colors: [Color] = [Palette.brandA, Palette.brandB]
    var size: CGFloat = 44

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                .fill(LinearGradient(colors: colors, startPoint: .topLeading, endPoint: .bottomTrailing))
            RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                .strokeBorder(.white.opacity(0.22), lineWidth: 1)
            Image(systemName: systemName)
                .font(.system(size: size * 0.44, weight: .semibold))
                .foregroundStyle(.white)
                .shadow(color: .black.opacity(0.15), radius: 1, y: 1)
        }
        .frame(width: size, height: size)
        .shadow(color: (colors.first ?? .clear).opacity(0.3), radius: 6, y: 3)
    }
}

struct SoftIcon: View {
    var systemName: String
    var color: Color
    var size: CGFloat = 32

    var body: some View {
        Image(systemName: systemName)
            .font(.system(size: size * 0.46, weight: .semibold))
            .foregroundStyle(color)
            .frame(width: size, height: size)
            .background(RoundedRectangle(cornerRadius: size * 0.3, style: .continuous).fill(color.opacity(0.13)))
    }
}

struct SectionTitle: View {
    var title: String
    var subtitle: String? = nil
    var icon: String? = nil
    var trailing: AnyView? = nil

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            if let icon {
                Image(systemName: icon).font(.system(size: 14, weight: .semibold)).foregroundStyle(Palette.brand)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 17, weight: .semibold))
                if let subtitle {
                    Text(subtitle).font(.system(size: 12)).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if let trailing { trailing }
        }
    }
}

struct StatTile: View {
    var icon: String
    var label: String
    var value: String
    var tint: Color = Palette.brand
    var emphasize = false

    var body: some View {
        HStack(spacing: 12) {
            SoftIcon(systemName: icon, color: tint, size: 34)
            VStack(alignment: .leading, spacing: 2) {
                Text(value)
                    .font(.system(size: 17, weight: .semibold, design: .rounded))
                    .monospacedDigit()
                    .foregroundStyle(emphasize ? tint : Color.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                Text(label).font(.system(size: 11.5)).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .card(padding: 14, radius: 14)
    }
}

struct Banner: View {
    var icon: String
    var title: String
    var message: String? = nil
    var color: Color
    var action: (String, () -> Void)? = nil

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(color)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 13, weight: .semibold))
                if let message {
                    Text(message).font(.system(size: 12)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
            if let action {
                Button(action.0, action: action.1).buttonStyle(SecondaryButtonStyle(tint: color, compact: true))
            }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(color.opacity(0.10)))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(color.opacity(0.28), lineWidth: 1))
    }
}

/// Red alert shown when the sandbox self-check failed (`sandbox_violation`).
struct SandboxViolationBanner: View {
    var problems: [String]

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "lock.trianglebadge.exclamationmark.fill")
                .font(.system(size: 26, weight: .semibold))
                .foregroundStyle(Palette.red)
            VStack(alignment: .leading, spacing: 6) {
                Text("Samosprawdzenie sandboksa nie powiodło się – skan przerwany dla bezpieczeństwa")
                    .font(.system(size: 14, weight: .semibold))
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(problems, id: \.self) { p in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Image(systemName: "xmark.circle.fill").font(.system(size: 11)).foregroundStyle(Palette.red)
                        Text(p).font(.system(size: 12.5)).textSelection(.enabled)
                    }
                }
                Text("Żaden plik nie został przeskanowany poza izolacją. Zgłoś ten problem – sandbox nie zachowuje się zgodnie z oczekiwaniami.")
                    .font(.system(size: 11.5)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Palette.red.opacity(0.10)))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(Palette.red.opacity(0.45), lineWidth: 1.5))
    }
}

/// Small "Sandbox" lock badge: every scan runs isolated (read-only for in-place scans).
struct SandboxBadge: View {
    var onColor = false

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: "lock.fill").font(.system(size: 9, weight: .bold))
            Text("Sandbox").font(.system(size: 11, weight: .semibold))
        }
        .foregroundStyle(onColor ? Color.white : Palette.green)
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(Capsule().fill(onColor ? Color.white.opacity(0.2) : Palette.green.opacity(0.14)))
        .overlay(Capsule().strokeBorder(onColor ? Color.white.opacity(0.3) : Color.clear, lineWidth: 1))
        .fixedSize()
        .help("Skan działa w izolowanym sandboksie macOS: bez sieci, bez możliwości zmiany plików.")
    }
}

struct Dot: View {
    var color: Color
    var size: CGFloat = 8
    var body: some View {
        Circle().fill(color).frame(width: size, height: size)
    }
}

import AppKit
import SwiftUI

/// "API (localhost)": switch the local HTTP API on/off, show its status, token and an example call.
struct APIScreen: View {
    @Environment(AppModel.self) private var model
    @Environment(\.snapshotMode) private var snapshot
    @State private var copied: String?

    private var api: APIServer { model.api }

    var body: some View {
        ScreenScaffold(item: .api,
                       subtitle: "Wszystko, co potrafi aplikacja, możesz zlecić innym programom na tym Macu – przez HTTP na localhost.") {
            toggleCard
            statusCard
            HStack(alignment: .top, spacing: 16) {
                tokenCard
                securityCard.frame(width: 320)
            }
            exampleCard
        }
        .onAppear { if !snapshot { api.loadToken() } }
    }

    // MARK: toggle

    private var toggleCard: some View {
        Toggle(isOn: Binding(get: { api.enabled }, set: { api.setEnabled($0) })) {
            HStack(spacing: 14) {
                IconTile(systemName: "network.badge.shield.half.filled",
                         colors: [Color(hex: 0x10B981), Color(hex: 0x0EA5E9)], size: 46)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Włącz API na localhost").font(.system(size: 16, weight: .semibold))
                    Text("Serwer działa tylko wtedy, gdy Cerber jest otwarty – nigdy nie startuje przy logowaniu. Twój wybór zostanie zapamiętany.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .toggleStyle(SwitchToggleStyle(tint: Palette.green))
        .card(padding: 18, radius: 18)
    }

    // MARK: status

    private var statusCard: some View {
        HStack(alignment: .top, spacing: 12) {
            statusIcon
            VStack(alignment: .leading, spacing: 4) {
                Text(statusTitle).font(.system(size: 14, weight: .semibold))
                switch api.state {
                case .running:
                    Text("Każde wywołanie /api/* wymaga nagłówka Authorization: Bearer <token>.")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                case .failed(let msg):
                    Text(msg).font(.system(size: 12)).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    if !api.stderrTail.isEmpty {
                        Text(api.stderrTail.suffix(6).joined(separator: "\n"))
                            .font(.system(size: 10.5, design: .monospaced))
                            .foregroundStyle(Color(hex: 0xD8DEE9))
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Palette.codeBG))
                            .textSelection(.enabled)
                    }
                case .starting:
                    Text("Uruchamianie python -m cerber.api_server…").font(.system(size: 12)).foregroundStyle(.secondary)
                case .off:
                    Text("Włącz przełącznik powyżej, aby uruchomić serwer na porcie \(APIServer.port).")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 8)
            switch api.state {
            case .running:
                Button {
                    if let u = URL(string: api.docsURL) { NSWorkspace.shared.open(u) }
                } label: {
                    Label("Otwórz dokumentację", systemImage: "book")
                }
                .buttonStyle(PrimaryButtonStyle(colors: [Color(hex: 0x10B981), Color(hex: 0x0EA5E9)]))
            case .failed:
                Button {
                    api.start()
                } label: {
                    Label("Spróbuj ponownie", systemImage: "arrow.clockwise")
                }
                .buttonStyle(PrimaryButtonStyle())
            default:
                EmptyView()
            }
        }
        .card(padding: 18, radius: 18)
    }

    @ViewBuilder
    private var statusIcon: some View {
        switch api.state {
        case .off:
            SoftIcon(systemName: "power", color: Palette.gray, size: 36)
        case .starting:
            ZStack {
                RoundedRectangle(cornerRadius: 11, style: .continuous).fill(Palette.brand.opacity(0.13))
                Spinner(size: 16, lineWidth: 2)
            }
            .frame(width: 36, height: 36)
        case .running:
            SoftIcon(systemName: "checkmark.circle.fill", color: Palette.green, size: 36)
        case .failed:
            SoftIcon(systemName: "exclamationmark.octagon.fill", color: Palette.red, size: 36)
        }
    }

    private var statusTitle: String {
        switch api.state {
        case .off: return "Wyłączone"
        case .starting: return "Uruchamianie…"
        case .running(let url, _): return "Działa na \(url)"
        case .failed: return "Błąd"
        }
    }

    // MARK: token

    private var tokenCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitle(title: "Token dostępu", subtitle: "Przechowywany w pęku kluczy macOS", icon: "key.horizontal")
            Text(api.token ?? "••••••••••••••••••••••••••••••••••••••••••")
                .font(.system(size: 13, design: .monospaced))
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Palette.subtle))
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Palette.cardBorder, lineWidth: 1))
            HStack(spacing: 8) {
                Button {
                    if let t = api.token { copy(t, as: "token") }
                } label: {
                    Label(copied == "token" ? "Skopiowano" : "Kopiuj", systemImage: copied == "token" ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(SecondaryButtonStyle(tint: Palette.brand))
                .disabled(api.token == nil)
                Button {
                    api.regenerateToken()
                } label: {
                    Label("Wygeneruj nowy", systemImage: "arrow.triangle.2.circlepath")
                }
                .buttonStyle(SecondaryButtonStyle())
                .help("Nowy token unieważnia stary; działający serwer zostanie uruchomiony ponownie.")
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card(padding: 18, radius: 18)
    }

    // MARK: security

    private var securityCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                SoftIcon(systemName: "lock.shield.fill", color: Palette.green, size: 32)
                Text("Bezpieczeństwo").font(.system(size: 14, weight: .semibold))
            }
            ForEach([("desktopcomputer", "Dostępne tylko z tego Maca (127.0.0.1) – nie z sieci."),
                     ("key.fill", "Każde wywołanie wymaga tokenu."),
                     ("globe.badge.chevron.backward", "Chronione przed stronami WWW otwartymi w przeglądarce."),
                     ("power", "Działa tylko, gdy Cerber jest otwarty.")], id: \.1) { icon, text in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: icon).font(.system(size: 11, weight: .semibold)).foregroundStyle(Palette.green).frame(width: 16)
                    Text(text).font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card(padding: 18, radius: 18)
    }

    // MARK: example

    private var exampleCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle(title: "Przykład", subtitle: "Informacje o bazach przez API", icon: "terminal",
                         trailing: AnyView(
                            Button {
                                copy(api.curlExample, as: "curl")
                            } label: {
                                Label(copied == "curl" ? "Skopiowano" : "Kopiuj przykład curl",
                                      systemImage: copied == "curl" ? "checkmark" : "doc.on.doc")
                            }
                            .buttonStyle(SecondaryButtonStyle(tint: Palette.brand, compact: true))
                            .disabled(api.token == nil)
                         ))
            Text(api.curlExample)
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(Color(hex: 0xD8DEE9))
                .lineLimit(2)
                .truncationMode(.middle)
                .textSelection(.enabled)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Palette.codeBG))
            Text("Pełna lista wywołań (skanowanie, postęp, wyniki, kwarantanna, historia) jest w dokumentacji serwera.")
                .font(.system(size: 11.5)).foregroundStyle(.secondary)
        }
        .card(padding: 18, radius: 18)
    }

    private func copy(_ s: String, as key: String) {
        FinderActions.copy(s)
        withAnimation { copied = key }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            if copied == key { withAnimation { copied = nil } }
        }
    }
}

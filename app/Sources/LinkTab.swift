import AppKit
import SwiftUI

/// Results of "Sprawdź link": reconnaissance of the address and the files downloaded in the sandbox.
struct LinkTab: View {
    var info: URLInfo
    var verdict: Verdict
    var tree: [TreeEntry]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if !info.ioc.isEmpty { iocBanner }
            HStack(alignment: .top, spacing: 16) {
                addressCard
                VStack(spacing: 16) {
                    tlsCard
                    if info.hasPage { pageCard }
                }
                .frame(width: 330)
            }
            filesCard
            if !info.skipped.isEmpty { skippedCard }
            if !info.notes.isEmpty { notesCard }
        }
    }

    // MARK: IOC

    private var iocBanner: some View {
        let color = verdict >= .suspicious ? verdict.color : Palette.red
        return HStack(alignment: .top, spacing: 14) {
            Image(systemName: "bolt.trianglebadge.exclamationmark.fill")
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(color)
            VStack(alignment: .leading, spacing: 6) {
                Text("Ten adres jest na listach zagrożeń").font(.system(size: 15, weight: .semibold))
                Text("Nie pobieraj z niego niczego, nawet jeśli pobrane pliki wyglądają na czyste.")
                    .font(.system(size: 12.5)).foregroundStyle(.secondary)
                ForEach(info.ioc, id: \.self) { hit in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Image(systemName: "exclamationmark.circle.fill").font(.system(size: 11)).foregroundStyle(color)
                        Text(hit).font(.system(size: 12.5, weight: .medium)).textSelection(.enabled)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(color.opacity(0.10)))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(color.opacity(0.4), lineWidth: 1.5))
    }

    // MARK: address & redirects

    private var addressCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            SectionTitle(title: "Adres", subtitle: info.redirects.count > 1
                         ? "Łańcuch przekierowań: \(info.redirects.count - 1) \(Fmt.plural(info.redirects.count - 1, "skok", "skoki", "skoków"))"
                         : "Bez przekierowań", icon: "arrow.triangle.turn.up.right.diamond")
            VStack(alignment: .leading, spacing: 0) {
                let chain = info.redirects.isEmpty ? [info.input] : info.redirects
                ForEach(Array(chain.enumerated()), id: \.offset) { idx, hop in
                    HStack(alignment: .top, spacing: 10) {
                        ZStack {
                            Circle().fill(idx == chain.count - 1 ? AnyShapeStyle(Palette.brandGradient) : AnyShapeStyle(Palette.subtleStrong))
                            Text("\(idx + 1)").font(.system(size: 10.5, weight: .bold))
                                .foregroundStyle(idx == chain.count - 1 ? Color.white : Color.secondary)
                        }
                        .frame(width: 22, height: 22)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(hop).font(.system(size: 12, design: .monospaced))
                                .lineLimit(2).truncationMode(.middle).textSelection(.enabled)
                            Text(idx == 0 ? "wklejony adres" : (idx == chain.count - 1 ? "adres końcowy" : "przekierowanie"))
                                .font(.system(size: 10.5)).foregroundStyle(.tertiary)
                        }
                    }
                    if idx < chain.count - 1 {
                        Image(systemName: "arrow.down")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundStyle(.tertiary)
                            .frame(width: 22, height: 16)
                    }
                }
            }
            Divider()
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 7) {
                row("Domena", info.domain)
                row("Adres IP", info.ip, mono: true)
                row("Status HTTP", info.status.map { "\($0)\(Self.statusText($0))" })
                row("Typ treści", info.contentType, mono: true)
                row("Serwer", info.server)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card(padding: 18, radius: 18)
    }

    @ViewBuilder
    private func row(_ label: String, _ value: String?, mono: Bool = false) -> some View {
        GridRow {
            Text(label).font(.system(size: 12)).foregroundStyle(.secondary)
            Text(value ?? "—").font(.system(size: 12.5, weight: .medium, design: mono ? .monospaced : .default))
                .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
        }
    }

    private static func statusText(_ s: Int) -> String {
        switch s {
        case 200..<300: return " (OK)"
        case 300..<400: return " (przekierowanie)"
        case 404: return " (nie znaleziono)"
        case 400..<500: return " (błąd klienta)"
        case 500..<600: return " (błąd serwera)"
        default: return ""
        }
    }

    // MARK: TLS & page

    private var tlsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                SoftIcon(systemName: info.tls != nil ? "lock.fill" : "lock.open.fill",
                         color: info.tls != nil ? Palette.green : Palette.orange, size: 32)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Certyfikat TLS").font(.system(size: 14, weight: .semibold))
                    Text(info.tls != nil ? "Połączenie szyfrowane" : "Brak szyfrowania (http)")
                        .font(.system(size: 11.5)).foregroundStyle(info.tls != nil ? Palette.green : Palette.orange)
                }
            }
            if let t = info.tls {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                    tlsRow("Wystawca", t.issuer)
                    tlsRow("Dla", t.subject)
                    tlsRow("Ważny do", t.expires.map(Fmt.shortDate))
                    tlsRow("Protokół", t.version)
                }
            } else {
                Text("Treść mogła zostać podmieniona po drodze – pliki z takich adresów są szczególnie ryzykowne.")
                    .font(.system(size: 11.5)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card(padding: 16, radius: 18)
    }

    @ViewBuilder
    private func tlsRow(_ label: String, _ value: String?) -> some View {
        GridRow {
            Text(label).font(.system(size: 11.5)).foregroundStyle(.secondary)
            Text(value ?? "—").font(.system(size: 12, weight: .medium)).lineLimit(1).truncationMode(.middle)
        }
    }

    private var pageCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                SoftIcon(systemName: "doc.richtext", color: Palette.blue, size: 32)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Strona internetowa").font(.system(size: 14, weight: .semibold))
                    Text(info.linksFound.map { "znaleziono \(Fmt.count($0, "link", "linki", "linków"))" } ?? "link prowadził do strony")
                        .font(.system(size: 11.5)).foregroundStyle(.secondary)
                }
            }
            if let t = info.pageTitle {
                Text("„\(t)”").font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .card(padding: 16, radius: 18)
    }

    // MARK: files

    /// Worst verdict of the sandbox tree entries belonging to a downloaded file (incl. its unpacked content).
    private func verdict(for file: LinkedFile) -> Verdict? {
        let matches = tree.filter { e in
            let outer = e.path.components(separatedBy: ">>").first ?? e.path
            return (outer as NSString).lastPathComponent == file.name
        }
        return matches.isEmpty ? nil : matches.map(\.verdict).max()
    }

    private var filesCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitle(title: "Pobrane pliki", subtitle: "Pobrane i rozpakowane w sandboksie, potem usunięte",
                         icon: "arrow.down.doc",
                         trailing: AnyView(Text("\(info.files.count)").font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)))
            if info.files.isEmpty {
                Text("Nic nie zostało pobrane.").font(.system(size: 12)).foregroundStyle(.secondary)
            } else {
                VStack(spacing: 0) {
                    HStack(spacing: 12) {
                        Text("Plik").frame(maxWidth: .infinity, alignment: .leading)
                        Text("Rozmiar").frame(width: 80, alignment: .trailing)
                        Text("Typ").frame(width: 170, alignment: .leading)
                        Text("SHA-256").frame(width: 180, alignment: .leading)
                        Text("Werdykt").frame(width: 96, alignment: .trailing)
                    }
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(Palette.subtle)
                    ForEach(Array(info.files.enumerated()), id: \.element.id) { idx, f in
                        fileRow(f)
                            .background(idx % 2 == 1 ? Palette.subtle.opacity(0.5) : Color.clear)
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
        }
        .card(padding: 16, radius: 18)
    }

    private func fileRow(_ f: LinkedFile) -> some View {
        let v = verdict(for: f)
        return HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 1) {
                Text(f.name).font(.system(size: 12.5, weight: .semibold)).lineLimit(1).truncationMode(.middle)
                if let u = f.url {
                    Text(u).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(.tertiary)
                        .lineLimit(1).truncationMode(.middle)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Text(Fmt.bytes(f.size)).font(.system(size: 12)).monospacedDigit().frame(width: 80, alignment: .trailing)
            Text(f.contentType ?? "—").font(.system(size: 11.5, design: .monospaced)).foregroundStyle(.secondary)
                .lineLimit(1).truncationMode(.tail).frame(width: 170, alignment: .leading)
            HStack(spacing: 4) {
                Text(f.sha256.map { String($0.prefix(14)) + "…" } ?? "—")
                    .font(.system(size: 11.5, design: .monospaced)).lineLimit(1)
                if let sha = f.sha256 {
                    Button {
                        FinderActions.copy(sha)
                    } label: {
                        Image(systemName: "doc.on.doc").font(.system(size: 10.5))
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(Palette.brand)
                    .help("Kopiuj SHA-256: \(sha)")
                }
            }
            .frame(width: 180, alignment: .leading)
            HStack(spacing: 5) {
                if let v {
                    Dot(color: v.color, size: 8)
                    Text(v.badge).font(.system(size: 11.5, weight: .semibold)).foregroundStyle(v.color)
                } else {
                    Text("—").foregroundStyle(.tertiary)
                }
            }
            .frame(width: 96, alignment: .trailing)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    // MARK: skipped & notes

    private var skippedCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle(title: "Pominięte", subtitle: "Linki, których Cerber nie pobrał", icon: "arrow.uturn.forward.circle",
                         trailing: AnyView(Text("\(info.skipped.count)").font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)))
            ForEach(info.skipped) { s in
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Image(systemName: "arrow.uturn.forward").font(.system(size: 11)).foregroundStyle(.secondary)
                    Text(s.url).font(.system(size: 11.5, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 8)
                    Text(s.reason).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                }
            }
        }
        .card(padding: 16, radius: 18)
    }

    private var notesCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Uwagi", systemImage: "info.circle").font(.system(size: 12.5, weight: .semibold))
            ForEach(info.notes, id: \.self) { n in
                Text("• " + n).font(.system(size: 12)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Palette.subtle))
    }
}

import SwiftUI

extension ScanLevel {
    var icon: String {
        switch self {
        case .quick: return "hare.fill"
        case .patterns: return "gauge.with.dots.needle.50percent"
        case .deep: return "scope"
        case .mega: return "bolt.shield.fill"
        }
    }

    var tagline: String {
        switch self {
        case .quick: return "Lekko, na szybko"
        case .patterns: return "Cały laptop, tylko wzorce"
        case .deep: return "„Na poważnie”"
        case .mega: return "Najmocniejszy"
        }
    }

    var summary: String {
        switch self {
        case .quick: return "Tylko wzorce, najważniejsze miejsca – dobre na co dzień albo po pobraniu czegoś nowego."
        case .patterns: return "Wszystkie dane na komputerze, sprawdzane wyłącznie znanymi wzorcami zagrożeń."
        case .deep: return "Wszystkie heurystyki na całym dysku + przegląd środowiska, znane ślady groźnych rodzin malware i uruchamianie podejrzanych skryptów w zamkniętym sandboksie."
        case .mega: return "Wszystko z poziomu Dokładny + sieć, zdalny dostęp, logi systemowe i monitor na żywo przez cały skan + AI."
        }
    }

    var checks: [String] {
        switch self {
        case .quick:
            return ["Hashe, ClamAV, YARA, IOC (7 mln+ wzorców)",
                    "Pobrane, Biurko, /tmp, /Users/Shared, rozszerzenia Chrome",
                    "Autostart (LaunchAgents/Daemons) + pliki uruchomionych programów"]
        case .patterns:
            return ["Hashe, ClamAV, YARA, IOC",
                    "/Applications, /Users, /Library, /opt, /usr/local, /private",
                    "Archiwa rozpakowywane do ostatniej warstwy"]
        case .deep:
            return ["Heurystyki, deobfuskacja, podobieństwo TLSH",
                    "Podpisy kodu i notaryzacja aplikacji",
                    "Autostart, procesy, rozszerzenia, SIP/FileVault/zapora",
                    "Ślady topowych rodzin malware (AMOS, Banshee, Lazarus…)",
                    "Zachowanie podejrzanych skryptów w zamkniętym sandboksie"]
        case .mega:
            return ["Porty, połączenia, ruch per proces, trafienia IOC",
                    "Zdalny dostęp, tunele, MDM, logowania",
                    "Logi systemowe: XProtect, Gatekeeper, SSH, nieudane hasła",
                    "Sieć lokalna (ARP spoofing, Wi‑Fi) i certyfikaty do podsłuchu HTTPS",
                    "Monitor sieci i zachowania na żywo do końca skanu",
                    "Ryzykowne pliki z iCloud: pobierane, sprawdzane i oddawane do chmury",
                    "Analiza AI: ocena zarzutów wobec plików z szarej strefy"]
        }
    }

    var duration: String {
        switch self {
        case .quick: return "do godziny"
        case .patterns: return "kilka godzin"
        case .deep: return "do 10 godzin"
        case .mega: return "do 24 godzin"
        }
    }

    var colors: [Color] {
        switch self {
        case .quick: return [Color(hex: 0x10B981), Color(hex: 0x14B8A6)]
        case .patterns: return [Color(hex: 0x3B82F6), Color(hex: 0x06B6D4)]
        case .deep: return [Color(hex: 0x6366F1), Color(hex: 0x3B82F6)]
        case .mega: return [Color(hex: 0xA855F7), Color(hex: 0xEC4899)]
        }
    }
}

struct LaptopScreen: View {
    @Environment(AppModel.self) private var model

    private let columns = [GridItem(.flexible(), spacing: 16), GridItem(.flexible(), spacing: 16)]

    var body: some View {
        ScreenScaffold(item: .laptop,
                       subtitle: "Wybierz, jak dokładnie Cerber ma sprawdzić ten komputer. Skan działa lokalnie – nic nie jest wysyłane do sieci.") {
            BusyBanner()
            LazyVGrid(columns: columns, spacing: 16) {
                ForEach(ScanLevel.allCases) { level in
                    LevelCard(level: level, selected: model.level == level) {
                        withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) { model.level = level }
                    }
                }
            }
            StartBar()
        }
    }
}

private struct LevelCard: View {
    var level: ScanLevel
    var selected: Bool
    var action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 12) {
                    IconTile(systemName: level.icon, colors: level.colors, size: 46)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 8) {
                            Text(level.label).font(.system(size: 19, weight: .bold, design: .rounded))
                            if level.includesAI {
                                Pill(text: "+ AI", color: level.colors[0], icon: "sparkles")
                            }
                        }
                        Text(level.tagline).font(.system(size: 13, weight: .medium)).foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 4)
                    ZStack {
                        Circle()
                            .strokeBorder(selected ? Color.clear : Color.secondary.opacity(0.35), lineWidth: 1.5)
                            .background(Circle().fill(selected ? AnyShapeStyle(LinearGradient(colors: level.colors, startPoint: .topLeading, endPoint: .bottomTrailing)) : AnyShapeStyle(Color.clear)))
                        if selected {
                            Image(systemName: "checkmark").font(.system(size: 11, weight: .heavy)).foregroundStyle(.white)
                                .transition(.scale)
                        }
                    }
                    .frame(width: 22, height: 22)
                }
                Text(level.summary)
                    .font(.system(size: 12.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(level.checks, id: \.self) { c in
                        HStack(alignment: .firstTextBaseline, spacing: 7) {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.system(size: 11))
                                .foregroundStyle(level.colors[0])
                            Text(c).font(.system(size: 12)).foregroundStyle(.primary.opacity(0.85))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                Spacer(minLength: 0)
                HStack(spacing: 6) {
                    Image(systemName: "clock").font(.system(size: 11, weight: .semibold))
                    Text("Czas: \(level.duration)").font(.system(size: 12, weight: .semibold))
                }
                .foregroundStyle(level.colors[0])
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(Capsule().fill(level.colors[0].opacity(0.12)))
            }
            .padding(18)
            .frame(maxWidth: .infinity, minHeight: 262, alignment: .topLeading)
            .background(
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .fill(Palette.card)
                    .shadow(color: selected ? level.colors[0].opacity(0.28) : Palette.shadow, radius: selected ? 18 : 10, y: selected ? 6 : 3)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .strokeBorder(selected ? AnyShapeStyle(LinearGradient(colors: level.colors, startPoint: .topLeading, endPoint: .bottomTrailing))
                                  : AnyShapeStyle(hovering ? Color.secondary.opacity(0.3) : Palette.cardBorder),
                                  lineWidth: selected ? 2.5 : 1)
            )
            .scaleEffect(hovering && !selected ? 1.006 : 1)
            .contentShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
        }
        .buttonStyle(TileButtonStyle())
        .onHover { h in withAnimation(.easeOut(duration: 0.15)) { hovering = h } }
    }
}

private struct StartBar: View {
    @Environment(AppModel.self) private var model

    private var levelAINote: String {
        let name = model.level.label
        if model.aiInstall.isDownloading {
            let pct = model.aiInstall.fraction.map { " (\(Fmt.percent($0)))" } ?? ""
            return "Model AI jeszcze się pobiera\(pct) – skan uruchomiony teraz pominie analizę AI; po pobraniu poziom \(name) będzie ją zawierać."
        }
        return (model.aiStatusNote ?? "Model AI jest niedostępny.") + " Poziom \(name) pominie analizę AI."
    }

    var body: some View {
        HStack(spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text("Poziom:").foregroundStyle(.secondary)
                    Text(model.level.label).fontWeight(.semibold)
                    Text("·").foregroundStyle(.tertiary)
                    Text("potrwa \(model.level.duration)").foregroundStyle(.secondary)
                }
                .font(.system(size: 14))
                Text((model.level == .quick || model.level == .patterns
                     ? "W tym czasie możesz normalnie pracować. Skan można w każdej chwili przerwać (⌘.)."
                     : "Najlepiej uruchomić na zasilaczu. Skan można w każdej chwili przerwać (⌘.) – wyniki częściowe zostaną zachowane.")
                     + (model.level.includesAI && !model.aiAvailable ? " " + levelAINote : ""))
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            Button {
                model.scanLaptop()
            } label: {
                Label("Przeskanuj", systemImage: "shield.lefthalf.filled")
                    .padding(.horizontal, 8)
            }
            .buttonStyle(PrimaryButtonStyle(large: true, colors: model.level.colors))
            .keyboardShortcut(.defaultAction)
            .disabled(model.isScanning)
        }
        .card(padding: 18, radius: 20)
    }
}

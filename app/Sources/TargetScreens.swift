import AppKit
import SwiftUI

// MARK: - Plik lub folder

struct FileScreen: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScreenScaffold(item: .file,
                       subtitle: "Upuść pliki lub foldery. Cerber rozpakuje je do ostatniej warstwy i porówna każdą z milionami wzorców.") {
            BusyBanner()
            DropZone(icon: "arrow.down.doc.fill",
                     title: "Upuść pliki lub foldery tutaj",
                     subtitle: "Możesz upuścić kilka elementów naraz – także całe foldery, aplikacje, archiwa i obrazy dysków.",
                     buttonTitle: "Wybierz…",
                     onPick: { model.chooseAndScan(origin: .file) },
                     onDrop: { model.scanPaths($0, origin: .file) })
                .disabled(model.isScanning)
            AIToggleCard()
            HStack(spacing: 14) {
                FeatureTile(icon: "scope", title: "Zawsze dokładnie",
                            text: "Wszystkie heurystyki, deobfuskacja i sprawdzanie podpisów kodu.")
                FeatureTile(icon: "shippingbox", title: "~30 formatów archiwów",
                            text: "zip, 7z, rar, dmg, pkg, asar, iso i inne – z ochroną przed bombami.")
                FeatureTile(icon: "cylinder.split.1x2", title: "\(Fmt.int(model.info?.patternsTotal ?? 7_217_044)) wzorców",
                            text: "ClamAV, YARA, hashe MalwareBazaar, IOC z URLhaus i ThreatFox.")
            }
        }
    }
}

struct FeatureTile: View {
    var icon: String
    var title: String
    var text: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            SoftIcon(systemName: icon, color: Palette.brand, size: 32)
            Text(title).font(.system(size: 13, weight: .semibold))
            Text(text).font(.system(size: 12)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, minHeight: 112, alignment: .topLeading)
        .card(padding: 16, radius: 16)
    }
}

// MARK: - Lokalizacja

struct LocationTileInfo: Identifiable {
    var id: String { path }
    var title: String
    var path: String
    var icon: String
    var colors: [Color]
    var note: String
}

struct LocationScreen: View {
    @Environment(AppModel.self) private var model

    private var tiles: [LocationTileInfo] {
        let home = NSHomeDirectory()
        return [
            LocationTileInfo(title: "Pobrane", path: home + "/Downloads", icon: "arrow.down.circle.fill",
                             colors: [Color(hex: 0x3B82F6), Color(hex: 0x06B6D4)], note: "Najczęstsze źródło zagrożeń"),
            LocationTileInfo(title: "Biurko", path: home + "/Desktop", icon: "menubar.dock.rectangle",
                             colors: [Color(hex: 0x8B5CF6), Color(hex: 0x6366F1)], note: "Pliki na pulpicie"),
            LocationTileInfo(title: "Dokumenty", path: home + "/Documents", icon: "doc.text.fill",
                             colors: [Color(hex: 0xF59E0B), Color(hex: 0xF97316)], note: "Dokumenty, makra, PDF-y"),
            LocationTileInfo(title: "Aplikacje", path: "/Applications", icon: "square.grid.3x3.fill",
                             colors: [Color(hex: 0x10B981), Color(hex: 0x14B8A6)], note: "Programy i ich podpisy"),
            LocationTileInfo(title: "Katalog domowy", path: home, icon: "house.fill",
                             colors: [Color(hex: 0xEC4899), Color(hex: 0xF43F5E)], note: "Wszystko, co należy do Ciebie"),
        ]
    }

    private let columns = [GridItem(.flexible(), spacing: 16), GridItem(.flexible(), spacing: 16), GridItem(.flexible(), spacing: 16)]

    var body: some View {
        ScreenScaffold(item: .location,
                       subtitle: "Szybki wybór typowego miejsca do dokładnego skanu. Duże foldery mogą zająć sporo czasu.") {
            BusyBanner()
            LazyVGrid(columns: columns, spacing: 16) {
                ForEach(tiles) { t in
                    LocationTile(info: t) { model.scanPaths([URL(fileURLWithPath: t.path)], origin: .location) }
                }
                ChooseLocationTile { model.chooseLocation() }
            }
            .disabled(model.isScanning)
            AIToggleCard()
        }
    }
}

private struct LocationTile: View {
    var info: LocationTileInfo
    var action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    IconTile(systemName: info.icon, colors: info.colors, size: 44)
                    Spacer()
                    Image(systemName: "arrow.right.circle.fill")
                        .font(.system(size: 20))
                        .foregroundStyle(info.colors[0])
                        .opacity(hovering ? 1 : 0)
                        .offset(x: hovering ? 0 : -6)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text(info.title).font(.system(size: 16, weight: .semibold))
                    Text(info.note).font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Text(Fmt.tilde(info.path))
                    .font(.system(size: 11.5, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(Capsule().fill(Palette.subtle))
            }
            .frame(maxWidth: .infinity, minHeight: 150, alignment: .topLeading)
            .card(padding: 18, radius: 18)
            .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(info.colors[0].opacity(hovering ? 0.55 : 0), lineWidth: 1.5))
            .offset(y: hovering ? -2 : 0)
            .contentShape(Rectangle())
        }
        .buttonStyle(TileButtonStyle())
        .onHover { h in withAnimation(.easeOut(duration: 0.15)) { hovering = h } }
        .help("Przeskanuj \(info.path)")
    }
}

private struct ChooseLocationTile: View {
    var action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            VStack(spacing: 10) {
                Image(systemName: "folder.badge.plus")
                    .font(.system(size: 28, weight: .medium))
                    .foregroundStyle(Palette.brandGradient)
                Text("Wybierz lokalizację…").font(.system(size: 15, weight: .semibold))
                Text("Dowolny folder lub dysk zewnętrzny").font(.system(size: 12)).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, minHeight: 150)
            .padding(18)
            .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(hovering ? Palette.brand.opacity(0.06) : Color.clear))
            .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [7, 5]))
                .foregroundStyle(hovering ? Palette.brand.opacity(0.7) : Color.secondary.opacity(0.35)))
            .contentShape(Rectangle())
        }
        .buttonStyle(TileButtonStyle())
        .onHover { h in withAnimation(.easeOut(duration: 0.15)) { hovering = h } }
    }
}

// MARK: - Archiwum w sandboksie

struct SandboxScreen: View {
    @Environment(AppModel.self) private var model

    static let formats = ["zip", "7z", "rar", "tar.gz", "tar.xz", "tar.bz2", "dmg", "pkg", "iso", "jar", "apk",
                          "cab", "msi", "deb", "rpm", "cpio", "xar", "asar", "wim", "vhd"]

    var body: some View {
        ScreenScaffold(item: .sandbox,
                       subtitle: "Podejrzane archiwum rozpakujesz bez ryzyka: wszystko dzieje się w izolowanej piaskownicy macOS.") {
            BusyBanner()
            HStack(alignment: .top, spacing: 18) {
                DropZone(icon: "archivebox.fill",
                         title: "Upuść archiwum tutaj",
                         subtitle: "zip, 7z, rar, tar.*, dmg, pkg, iso i inne – także zagnieżdżone i zaszyfrowane hasłem „infected”.",
                         buttonTitle: "Wybierz archiwum…",
                         height: 330,
                         onPick: { model.chooseArchive() },
                         onDrop: { urls in if let u = urls.first { model.scanSandbox(u) } })
                    .disabled(model.isScanning)
                    .frame(maxWidth: .infinity)
                IsolationCard()
                    .frame(width: 330)
            }
            VStack(alignment: .leading, spacing: 10) {
                Text("Obsługiwane formaty").font(.system(size: 13, weight: .semibold))
                FlowLayout(spacing: 6) {
                    ForEach(Self.formats, id: \.self) { f in
                        Text(f)
                            .font(.system(size: 11.5, weight: .medium, design: .monospaced))
                            .padding(.horizontal, 9)
                            .padding(.vertical, 4)
                            .background(Capsule().fill(Palette.subtle))
                            .overlay(Capsule().strokeBorder(Palette.cardBorder, lineWidth: 1))
                    }
                    Text("…i ~10 innych").font(.system(size: 11.5)).foregroundStyle(.secondary).padding(.vertical, 4)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .card(padding: 16, radius: 16)
            AIToggleCard()
        }
    }
}

struct IsolationCard: View {
    private let items: [(String, String, String)] = [
        ("wifi.slash", "Bez sieci", "Rozpakowywanie działa w piaskownicy macOS bez dostępu do internetu."),
        ("lock.doc", "Zapis tylko do izolowanego katalogu", "Proces nie może zmienić niczego poza katalogiem roboczym."),
        ("gauge.with.dots.needle.67percent", "Limity rozmiaru i czasu", "Ochrona przed „bombami” dekompresyjnymi i zawieszeniem."),
        ("trash", "Katalog usuwany po skanie", "Po zakończeniu nie zostaje żaden rozpakowany plik."),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                SoftIcon(systemName: "lock.shield.fill", color: Palette.green, size: 34)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Pełna izolacja").font(.system(size: 15, weight: .semibold))
                    Text("Nic z archiwum nie jest uruchamiane").font(.system(size: 11.5)).foregroundStyle(.secondary)
                }
            }
            ForEach(items, id: \.1) { icon, title, text in
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: icon)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Palette.green)
                        .frame(width: 20)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(title).font(.system(size: 12.5, weight: .semibold))
                        Text(text).font(.system(size: 11.5)).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, minHeight: 330, alignment: .topLeading)
        .card(padding: 18, radius: 20)
    }
}

// MARK: - GitHub

struct GitHubScreen: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        let parsed = RepoRef.github(model.githubText)
        let state: InputField.FieldState = model.githubText.trimmingCharacters(in: .whitespaces).isEmpty ? .neutral : (parsed == nil ? .invalid : .valid)
        ScreenScaffold(item: .github,
                       subtitle: "Sprawdź publiczne repozytorium, zanim je sklonujesz lub zainstalujesz. Kod nigdy nie jest uruchamiany.") {
            BusyBanner()
            VStack(alignment: .leading, spacing: 12) {
                Text("Adres repozytorium").font(.system(size: 13, weight: .semibold))
                InputField(placeholder: "https://github.com/właściciel/repozytorium", text: $model.githubText,
                           icon: "link", state: state) {
                    if let parsed, !model.isScanning { model.scanGitHub(parsed) }
                }
                if state == .invalid {
                    Label("Podaj adres w postaci github.com/właściciel/repozytorium, właściciel/repozytorium albo …/tree/gałąź.",
                          systemImage: "exclamationmark.circle")
                        .font(.system(size: 12))
                        .foregroundStyle(Palette.red)
                        .transition(.opacity)
                }
                HStack(spacing: 8) {
                    Text("Przykłady:").font(.system(size: 12)).foregroundStyle(.secondary)
                    ForEach(["github.com/psf/requests", "psf/requests", "github.com/psf/requests/tree/v2.32.3"], id: \.self) { ex in
                        Button(ex) { model.githubText = ex }
                            .buttonStyle(SecondaryButtonStyle(compact: true))
                    }
                }
            }
            .card(padding: 18, radius: 18)

            RepoPreviewCard(ref: parsed, emptyText: "Wpisz adres, aby zobaczyć, co zostanie pobrane.",
                            sourceIcon: "chevron.left.forwardslash.chevron.right",
                            sourceColors: [Color(hex: 0x24292F), Color(hex: 0x57606A)]) {
                if let parsed { model.scanGitHub(parsed) }
            }

            HStack(spacing: 14) {
                FeatureTile(icon: "arrow.down.circle", title: "Pobranie jako archiwum",
                            text: "Bez git clone i bez hooków – tylko archiwum wskazanej gałęzi lub tagu.")
                FeatureTile(icon: "lock.shield", title: "Rozpakowanie w sandboksie",
                            text: "Bez sieci, zapis tylko do katalogu roboczego, który potem jest usuwany.")
                FeatureTile(icon: "curlybraces", title: "Skrypty i zależności",
                            text: "postinstall, setup.py, workflowy CI, zaciemniony JS, IOC w kodzie.")
            }
            AIToggleCard()
        }
    }
}

struct RepoPreviewCard: View {
    var ref: RepoRef?
    var emptyText: String
    var sourceIcon: String
    var sourceColors: [Color]
    var start: () -> Void
    @Environment(AppModel.self) private var model

    var body: some View {
        HStack(spacing: 16) {
            IconTile(systemName: sourceIcon, colors: ref == nil ? [Color.gray.opacity(0.5), Color.gray.opacity(0.35)] : sourceColors, size: 48)
            VStack(alignment: .leading, spacing: 4) {
                if let ref {
                    HStack(spacing: 8) {
                        Text("\(ref.owner)/\(ref.name)").font(.system(size: 17, weight: .semibold))
                        Pill(text: kindLabel(ref.kind), color: Palette.brand)
                        if let r = ref.ref {
                            Pill(text: r, color: Palette.gray, icon: "arrow.triangle.branch")
                        }
                    }
                    Text(ref.url).font(.system(size: 12, design: .monospaced)).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                } else {
                    Text("Nic jeszcze nie wybrano").font(.system(size: 15, weight: .semibold)).foregroundStyle(.secondary)
                    Text(emptyText).font(.system(size: 12)).foregroundStyle(.tertiary)
                }
            }
            Spacer(minLength: 12)
            Button(action: start) {
                Label("Pobierz i przeskanuj", systemImage: "arrow.down.to.line.compact")
            }
            .buttonStyle(PrimaryButtonStyle())
            .disabled(ref == nil || model.isScanning)
        }
        .card(padding: 18, radius: 18)
        .animation(.easeInOut(duration: 0.2), value: ref)
    }

    private func kindLabel(_ k: RepoRef.Kind) -> String {
        switch k {
        case .repo: return "repozytorium"
        case .model: return "model"
        case .dataset: return "zbiór danych"
        case .space: return "Space"
        }
    }
}

// MARK: - Hugging Face

struct HuggingFaceScreen: View {
    @Environment(AppModel.self) private var model

    private let checks: [(String, String, String)] = [
        ("shippingbox.fill", "Pickle (.bin, .pt, .pth, .ckpt, .pkl)", "Niebezpieczne importy i wywołania przy wczytaniu (torch.load)."),
        ("chevron.left.forwardslash.chevron.right", "Kod trust_remote_code", "Pliki modeling_*.py i configuration_*.py uruchamiane przez transformers."),
        ("text.bubble.fill", "Szablony czatu GGUF / Jinja", "Szablony z dostępem do atrybutów Pythona (SSTI)."),
        ("function", "Keras Lambda (.h5, .keras)", "Kod zapisany w warstwach Lambda modeli Keras."),
        ("checkmark.seal.fill", "Bezpieczne formaty – tylko nagłówki", "safetensors i GGUF: sprawdzane nagłówki, bez pobierania wag."),
    ]

    var body: some View {
        @Bindable var model = model
        let parsed = RepoRef.huggingFace(model.hfText)
        let state: InputField.FieldState = model.hfText.trimmingCharacters(in: .whitespaces).isEmpty ? .neutral : (parsed == nil ? .invalid : .valid)
        ScreenScaffold(item: .huggingface,
                       subtitle: "Sprawdź model, zbiór danych lub Space z Hugging Face, zanim wczytasz go w Pythonie.") {
            BusyBanner()
            VStack(alignment: .leading, spacing: 12) {
                Text("Adres na Hugging Face").font(.system(size: 13, weight: .semibold))
                InputField(placeholder: "https://huggingface.co/organizacja/model", text: $model.hfText,
                           icon: "link", state: state) {
                    if let parsed, !model.isScanning { model.scanHuggingFace(parsed) }
                }
                if state == .invalid {
                    Label("Obsługiwane adresy: huggingface.co/org/model, …/datasets/org/nazwa, …/spaces/org/nazwa.",
                          systemImage: "exclamationmark.circle")
                        .font(.system(size: 12))
                        .foregroundStyle(Palette.red)
                }
                HStack(spacing: 8) {
                    Text("Przykłady:").font(.system(size: 12)).foregroundStyle(.secondary)
                    ForEach(["huggingface.co/ibm-granite/granite-4.0-h-tiny", "huggingface.co/datasets/org/nazwa", "huggingface.co/spaces/org/demo"], id: \.self) { ex in
                        Button(ex) { model.hfText = ex }
                            .buttonStyle(SecondaryButtonStyle(compact: true))
                            .lineLimit(1)
                    }
                }
            }
            .card(padding: 18, radius: 18)

            RepoPreviewCard(ref: parsed, emptyText: "Wpisz adres modelu, zbioru danych albo Space’a.",
                            sourceIcon: "brain", sourceColors: [Color(hex: 0xF59E0B), Color(hex: 0xEF4444)]) {
                if let parsed { model.scanHuggingFace(parsed) }
            }

            VStack(alignment: .leading, spacing: 12) {
                SectionTitle(title: "Co sprawdza Cerber", subtitle: "Pobierane są tylko pliki, które mogą wykonać kod, oraz nagłówki bezpiecznych formatów.",
                             icon: "checklist")
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
                    ForEach(checks, id: \.1) { icon, title, text in
                        HStack(alignment: .top, spacing: 10) {
                            SoftIcon(systemName: icon, color: Palette.orange, size: 30)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(title).font(.system(size: 12.5, weight: .semibold))
                                Text(text).font(.system(size: 11.5)).foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer(minLength: 0)
                        }
                    }
                }
            }
            .card(padding: 18, radius: 18)
            AIToggleCard()
        }
    }
}

// MARK: - Flow layout

struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? 600
        var x: CGFloat = 0, y: CGFloat = 0, rowH: CGFloat = 0, maxX: CGFloat = 0
        for v in subviews {
            let s = v.sizeThatFits(.unspecified)
            if x + s.width > width, x > 0 {
                x = 0
                y += rowH + spacing
                rowH = 0
            }
            x += s.width + spacing
            maxX = max(maxX, x)
            rowH = max(rowH, s.height)
        }
        return CGSize(width: min(width, maxX), height: y + rowH)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowH: CGFloat = 0
        for v in subviews {
            let s = v.sizeThatFits(.unspecified)
            if x + s.width > bounds.maxX, x > bounds.minX {
                x = bounds.minX
                y += rowH + spacing
                rowH = 0
            }
            v.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(s))
            x += s.width + spacing
            rowH = max(rowH, s.height)
        }
    }
}

// MARK: - Sprawdź link

struct LinkScreen: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        let parsed = LinkRef.parse(model.linkText)
        let state: InputField.FieldState = model.linkText.trimmingCharacters(in: .whitespaces).isEmpty ? .neutral : (parsed == nil ? .invalid : .valid)
        ScreenScaffold(item: .link,
                       subtitle: "Wklej link, z którego chcesz coś pobrać – dowiesz się, czy jest bezpieczny, zanim pobierzesz go sam.") {
            BusyBanner()
            VStack(alignment: .leading, spacing: 12) {
                Text("Link do sprawdzenia").font(.system(size: 13, weight: .semibold))
                InputField(placeholder: "https://example.com/pobierz/instalator.zip", text: $model.linkText,
                           icon: "link", state: state) {
                    if let parsed, !model.isScanning { model.scanURL(parsed) }
                }
                if state == .invalid {
                    Label("Podaj adres strony lub pliku zaczynający się od http:// lub https://.",
                          systemImage: "exclamationmark.circle")
                        .font(.system(size: 12))
                        .foregroundStyle(Palette.red)
                }
                Text("Cerber pobierze plik(i) w izolowanym sandboksie – bez dostępu do Twoich plików i bez możliwości uruchomienia czegokolwiek – rozpakuje archiwa i sprawdzi każdy plik. Jeśli link prowadzi do strony z wieloma plikami do pobrania, sprawdzi wszystkie.")
                    .font(.system(size: 12.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .card(padding: 18, radius: 18)

            LinkPreviewCard(link: parsed) {
                if let parsed { model.scanURL(parsed) }
            }

            HStack(spacing: 14) {
                FeatureTile(icon: "magnifyingglass", title: "Rozpoznanie adresu",
                            text: "Przekierowania, domena i IP, certyfikat TLS, listy zagrożeń URLhaus i ThreatFox.")
                FeatureTile(icon: "lock.shield", title: "Pobranie w sandboksie",
                            text: "Bez dostępu do Twoich plików i przeglądarki, nic nie jest uruchamiane.")
                FeatureTile(icon: "shippingbox", title: "Archiwa i całe strony",
                            text: "Rozpakowuje archiwa; ze strony z wieloma plikami pobiera i sprawdza wszystkie.")
            }
            AIToggleCard()
        }
    }
}

private struct LinkPreviewCard: View {
    var link: LinkRef?
    var start: () -> Void
    @Environment(AppModel.self) private var model

    var body: some View {
        HStack(spacing: 16) {
            IconTile(systemName: "link", colors: link == nil ? [Color.gray.opacity(0.5), Color.gray.opacity(0.35)]
                     : [Color(hex: 0x0EA5E9), Color(hex: 0x6366F1)], size: 48)
            VStack(alignment: .leading, spacing: 4) {
                if let link {
                    HStack(spacing: 8) {
                        Text(link.host).font(.system(size: 17, weight: .semibold)).lineLimit(1)
                        if link.isEncrypted {
                            Pill(text: "https", color: Palette.green, icon: "lock.fill")
                        } else {
                            Pill(text: "http – bez szyfrowania", color: Palette.orange, icon: "lock.open.fill")
                        }
                    }
                    Text(link.url).font(.system(size: 12, design: .monospaced)).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                } else {
                    Text("Nic jeszcze nie wklejono").font(.system(size: 15, weight: .semibold)).foregroundStyle(.secondary)
                    Text("Wklej link do pliku albo strony z plikami do pobrania.").font(.system(size: 12)).foregroundStyle(.tertiary)
                }
            }
            Spacer(minLength: 12)
            Button(action: start) {
                Label("Sprawdź link", systemImage: "checkmark.shield")
            }
            .buttonStyle(PrimaryButtonStyle())
            .disabled(link == nil || model.isScanning)
        }
        .card(padding: 18, radius: 18)
        .animation(.easeInOut(duration: 0.2), value: link)
    }
}

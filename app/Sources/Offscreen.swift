import AppKit
import SwiftUI

/// Offscreen rendering: `--render-icon` and `--snapshot`. Never opens a window.
@MainActor
enum Offscreen {
    static func prepareApp() {
        _ = NSApplication.shared
        NSApp.setActivationPolicy(.prohibited)
    }

    @discardableResult
    static func renderPNG<V: View>(_ view: V, size: CGSize, scheme: ColorScheme, to url: URL, scale: CGFloat = 1) -> Bool {
        let appearance = NSAppearance(named: scheme == .dark ? .darkAqua : .aqua)!
        var ok = false
        appearance.performAsCurrentDrawingAppearance {
            let content = view
                .frame(width: size.width, height: size.height)
                .environment(\.colorScheme, scheme)
            let renderer = ImageRenderer(content: content)
            renderer.proposedSize = ProposedViewSize(size)
            renderer.scale = scale
            renderer.isOpaque = false
            guard let cg = renderer.cgImage else { return }
            let rep = NSBitmapImageRep(cgImage: cg)
            rep.size = size
            if let data = rep.representation(using: .png, properties: [:]) {
                ok = (try? data.write(to: url)) != nil
            }
        }
        return ok
    }

    static func renderIcon(to url: URL) -> Bool {
        prepareApp()
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let ok = renderPNG(CerberIconView(), size: CGSize(width: 1024, height: 1024), scheme: .dark, to: url)
        print(ok ? "Ikona zapisana: \(url.path)" : "Nie udało się wyrenderować ikony")
        return ok
    }

    // MARK: mock data

    static func mockEvents(_ config: BackendConfig, _ args: [String], env extra: [String: String] = [:]) -> [BackendEvent] {
        let (exe, a) = config.launchSpec(args)
        let p = Process()
        p.executableURL = exe
        p.arguments = a
        p.currentDirectoryURL = config.root
        var env = config.environment
        env["CERBER_MOCK_NOSLEEP"] = "1"
        env["CERBER_MOCK_SYNTHETIC"] = "1"
        for (k, v) in extra { env[k] = v }
        p.environment = env
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch {
            print("Nie udało się uruchomić mocka: \(error)")
            return []
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self).split(separator: "\n").compactMap {
            if case .event(let e) = EventDecoder.decode(line: String($0)) { return e }
            return nil
        }
    }

    static func session(_ config: BackendConfig, _ request: ScanRequest, env: [String: String] = [:],
                        startedAgo: TimeInterval = 0) -> ScanSession {
        let s = ScanSession(request: request)
        s.startedAt = Date().addingTimeInterval(-startedAgo)
        let events = mockEvents(config, request.arguments, env: env)
        for e in events { s.apply(e) }
        if s.summary == nil, s.fatalMessage != nil { s.processExited(code: 1) }
        return s
    }

    static func baseModel(_ config: BackendConfig) -> AppModel {
        let m = AppModel(config: config)
        m.aiPreference = false         // snapshots show the default (AI off), not this user's choice
        for e in mockEvents(config, ["info"]) { if case .info(let i) = e { m.info = i; m.infoState = .loaded } }
        for e in mockEvents(config, ["history"]) { if case .history(let h) = e { m.history = h; m.historyState = .loaded } }
        return m
    }

    // MARK: snapshots

    struct Page {
        var name: String
        var tall: Bool = false
        var make: () -> AppModel
    }

    static func snapshots(to dir: URL) -> Bool {
        prepareApp()
        let fm = FileManager.default
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let fullDir = dir.appendingPathComponent("full")
        try? fm.createDirectory(at: fullDir, withIntermediateDirectories: true)

        var config = BackendConfig.detect(forceMock: true)
        if !fm.fileExists(atPath: config.mockScript.path) {
            config = BackendConfig(root: URL(fileURLWithPath: fm.currentDirectoryPath), mock: true)
        }
        let home = NSHomeDirectory()

        func screen(_ item: SidebarItem, _ tweak: @escaping (AppModel) -> Void = { _ in }) -> () -> AppModel {
            {
                let m = baseModel(config)
                m.selection = item
                tweak(m)
                return m
            }
        }

        func scan(_ request: ScanRequest, env: [String: String] = [:], ago: TimeInterval = 754,
                  tab: ResultsTab? = nil) -> () -> AppModel {
            {
                let m = baseModel(config)
                m.session = session(config, request, env: env, startedAgo: ago)
                m.selection = .session
                m.presentation.resultsTab = tab
                m.presentation.expandFirstResult = true
                m.presentation.expandLog = true
                return m
            }
        }

        let scanReq = ScanRequest(mode: .scan, arguments: ["scan", home + "/Downloads"], title: "Downloads",
                                  level: .deep, ai: false, origin: .file)
        let scanAIReq = ScanRequest(mode: .scan, arguments: ["scan", home + "/Downloads", "--ai"], title: "Downloads",
                                    level: .deep, ai: true, origin: .file)
        let sbxReq = ScanRequest(mode: .sandbox, arguments: ["sandbox", home + "/Downloads/instalator_programu.zip"],
                                 title: "instalator_programu.zip", level: .deep, ai: false, origin: .sandbox)
        let ghReq = ScanRequest(mode: .github, arguments: ["github", "https://github.com/acme/http-lite"],
                                title: "github.com/acme/http-lite", level: .deep, ai: false, origin: .github)
        let hfReq = ScanRequest(mode: .huggingface, arguments: ["huggingface", "https://huggingface.co/acme-ai/llama-tiny-chat", "--ai"],
                                title: "huggingface.co/acme-ai/llama-tiny-chat", level: .deep, ai: true, origin: .huggingface)
        let quickReq = ScanRequest(mode: .laptop, arguments: ["laptop", "--level", "quick"], title: "Laptop – Szybki",
                                   level: .quick, ai: false, origin: .laptop)
        let megaReq = ScanRequest(mode: .laptop, arguments: ["laptop", "--level", "mega", "--ai"], title: "Laptop – Mega",
                                  level: .mega, ai: true, origin: .laptop)
        let badReq = ScanRequest(mode: .github, arguments: ["github", "https://github.com/nieistnieje/repo"],
                                 title: "github.com/nieistnieje/repo", level: .deep, ai: false, origin: .github)

        let linkBadReq = ScanRequest(mode: .url, arguments: ["url", "https://bit.ly/malware-faktura"],
                                     title: "bit.ly · malware-faktura", level: .deep, ai: false, origin: .link)
        let linkOkReq = ScanRequest(mode: .url, arguments: ["url", "https://example.com/narzedzie/pobierz", "--ai"],
                                    title: "example.com · pobierz", level: .deep, ai: true, origin: .link)
        func aiState(_ item: SidebarItem, level: ScanLevel = .deep, _ state: AIInstallState, llama: Bool? = true,
                     model: String? = nil) -> () -> AppModel {
            screen(item) { m in
                m.level = level
                m.info?.aiModel = model
                m.info?.llamaServer = llama
                m.aiInstall = state
            }
        }

        let pages: [Page] = [
            Page(name: "01-laptop", make: screen(.laptop)),
            Page(name: "02-plik-lub-folder", make: screen(.file)),
            Page(name: "03-lokalizacja", make: screen(.location)),
            Page(name: "04-sandbox", make: screen(.sandbox)),
            Page(name: "05-github", make: screen(.github) { $0.githubText = "https://github.com/psf/requests/tree/v2.32.3" }),
            Page(name: "06-huggingface", make: screen(.huggingface) { $0.hfText = "huggingface.co/acme-ai/llama-tiny-chat" }),
            Page(name: "07-sprawdz-link", make: screen(.link) { $0.linkText = "https://example.com/narzedzie/pobierz" }),
            Page(name: "08-historia", make: screen(.history)),
            Page(name: "09-postep-laptop-mega", tall: true, make: scan(megaReq, env: ["CERBER_MOCK_STOP_AT": "0.45"], ago: 4_312)),
            Page(name: "10-postep-plik", tall: true, make: scan(scanAIReq, env: ["CERBER_MOCK_STOP_AT": "0.62"], ago: 48)),
            Page(name: "11-postep-anulowanie", tall: true, make: {
                let m = scan(scanReq, env: ["CERBER_MOCK_STOP_AT": "0.3"], ago: 21)()
                m.session?.phase = .cancelling
                return m
            }),
            Page(name: "12-wyniki-plik", tall: true, make: scan(scanReq)),
            Page(name: "13-wyniki-plik-sandbox", tall: true, make: scan(scanReq, tab: .sandbox)),
            Page(name: "14-wyniki-czysto", tall: true, make: scan(scanReq, env: ["CERBER_MOCK_CLEAN": "1"])),
            Page(name: "15-wyniki-sandbox-pliki", tall: true, make: scan(sbxReq)),
            Page(name: "16-wyniki-sandbox-drzewo", tall: true, make: scan(sbxReq, tab: .sandbox)),
            Page(name: "17-wyniki-github-repo", tall: true, make: scan(ghReq, tab: .repo)),
            Page(name: "18-wyniki-github-pliki", tall: true, make: scan(ghReq)),
            Page(name: "19-wyniki-hf-repo", tall: true, make: scan(hfReq, tab: .repo)),
            Page(name: "20-wyniki-hf-pliki", tall: true, make: scan(hfReq)),
            Page(name: "21-wyniki-link-zlosliwy", tall: true, make: scan(linkBadReq)),
            Page(name: "22-wyniki-link-zlosliwy-pliki", tall: true, make: scan(linkBadReq, tab: .files)),
            Page(name: "23-wyniki-link-czysty", tall: true, make: scan(linkOkReq)),
            Page(name: "24-wyniki-laptop-szybki", tall: true, make: scan(quickReq)),
            Page(name: "25-wyniki-laptop-mega-pliki", tall: true, make: scan(megaReq)),
            Page(name: "26-wyniki-laptop-mega-srodowisko", tall: true, make: scan(megaReq, tab: .environment)),
            Page(name: "27-wyniki-laptop-mega-siec", tall: true, make: scan(megaReq, tab: .network)),
            Page(name: "28-blad", make: scan(badReq)),
            Page(name: "29-brak-baz", make: screen(.laptop) { m in
                m.level = .mega
                m.info?.missing = ["db/clamav/daily.cvd", "ioc_indicators"]
            }),
            Page(name: "30-ai-pobieranie", make: aiState(.file, .downloading(bytes: 1_610_612_736, total: 4_230_976_352))),
            Page(name: "31-ai-pobieranie-laptop", make: aiState(.laptop, level: .deep, .downloading(bytes: 1_610_612_736, total: 4_230_976_352))),
            Page(name: "32-ai-blad", make: aiState(.huggingface, .failed("Instalacja modelu AI: zerwane połączenie z huggingface.co (HTTP 503)"))),
            Page(name: "33-ai-brak-llama", make: aiState(.link, .installed, llama: false, model: "granite-4.0-h-tiny-Q4_K_M.gguf")),
            Page(name: "37-naruszenie-sandboksa", make: scan(scanReq, env: ["CERBER_MOCK_VIOLATION": "1"])),
            Page(name: "40-postep-zachowanie", tall: true, make: scan(scanReq, env: ["CERBER_MOCK_STOP_BEHAVIOR": "0"], ago: 96)),
            Page(name: "40b-postep-zachowanie-po-skrypcie", make: scan(scanReq, env: ["CERBER_MOCK_STOP_BEHAVIOR": "1"], ago: 108)),
            Page(name: "41-wyniki-zachowanie", tall: true, make: {
                let m = scan(scanReq)()
                m.presentation.expandFirstResult = false
                m.presentation.expandResultMatching = "install-helper.sh"
                return m
            }),
            Page(name: "42-iphone", tall: true, make: screen(.iphone) { m in
                for e in mockEvents(config, ["iphone", "devices"]) { m.iphone.apply(e) }
            }),
            Page(name: "43-iphone-brak", make: screen(.iphone) { m in
                for e in mockEvents(config, ["iphone", "devices"], env: ["CERBER_MOCK_IPHONE": "none"]) { m.iphone.apply(e) }
            }),
            Page(name: "44-iphone-postep", make: screen(.iphone) { m in
                m.iphone.scanTitle = "iPhone (Ania)"
                m.iphone.makingBackup = true
                m.iphone.phase = .running
                m.iphone.startedAt = Date().addingTimeInterval(-312)
                for e in mockEvents(config, ["iphone", "scan", "00008110-001A2B3C4D5E801E", "--make-backup"]) {
                    if case .iphone(let n, _) = e, n == "iphone_done" { break }
                    if case .stage(let id, _) = e, id == "sandbox" { break }
                    m.iphone.apply(e)
                    if case .progress(let p) = e, p.stage == "backup", (p.done ?? 0) >= 40 { break }
                }
            }),
            Page(name: "45-iphone-wyniki", tall: true, make: screen(.iphone) { m in
                for e in mockEvents(config, ["iphone", "scan", "00008110-001A2B3C4D5E801E"]) { m.iphone.apply(e) }
            }),
            Page(name: "38-ochrona-wylaczona", make: screen(.protection)),
            Page(name: "39-ochrona-dziala", tall: true, make: screen(.protection) { m in
                m.protection.enabled = true
                for e in mockEvents(config, ["watch", "run", "--app", "--level", "quick"]) {
                    if case .watch(let w) = e { m.protection.apply(w) }
                }
                m.protection.workerState = "ready"
                m.protection.workerPatterns = 7_215_172
                m.protection.netGuard = false
            }),
            Page(name: "39b-ochrona-siec", tall: true, make: screen(.protection) { m in
                m.protection.enabled = true
                m.protection.netGuard = true
                for e in mockEvents(config, ["watch", "run", "--app", "--level", "quick", "--net"]) {
                    if case .watch(let w) = e { m.protection.apply(w) }
                }
                m.protection.workerState = "ready"
                m.protection.workerPatterns = 7_215_172
            }),
            Page(name: "34-api-dziala", make: screen(.api) { m in
                m.api.enabled = true
                m.api.token = "q7Rk2vX9pL4mN8sT1wY6zB3cD5fG0hJ2kQeUaW_oI-E"
                m.api.state = .running(url: "http://127.0.0.1:8765", docs: "http://127.0.0.1:8765/")
            }),
            Page(name: "35-api-blad", make: screen(.api) { m in
                m.api.enabled = true
                m.api.token = "q7Rk2vX9pL4mN8sT1wY6zB3cD5fG0hJ2kQeUaW_oI-E"
                m.api.stderrTail = ["Traceback (most recent call last):", "  File \"cerber/api_server.py\", line 812, in serve",
                                    "OSError: [Errno 48] Address already in use"]
                m.api.state = .failed("Serwer API zakończył działanie (kod 1).\nOSError: [Errno 48] Address already in use")
            }),
            Page(name: "36-api-wylaczone", make: screen(.api) { m in
                m.api.token = "q7Rk2vX9pL4mN8sT1wY6zB3cD5fG0hJ2kQeUaW_oI-E"
            }),
        ]

        _ = IconCache.small
        let env = ProcessInfo.processInfo.environment
        let only = env["CERBER_SNAPSHOT_ONLY"]
        // full-page renders: CERBER_SNAPSHOT_FULL_HEIGHT=3200, CERBER_SNAPSHOT_FULL_DARK=1 (also a dark one)
        let fullHeight = env["CERBER_SNAPSHOT_FULL_HEIGHT"].flatMap(Double.init) ?? 2300
        let fullSchemes: [ColorScheme] = env["CERBER_SNAPSHOT_FULL_DARK"] == "1" ? [.light, .dark] : [.light]
        var okAll = true
        var written = 0
        for page in pages {
            if let only, !page.name.contains(only) { continue }
            let model = page.make()
            for scheme in [ColorScheme.light, .dark] {
                let suffix = scheme == .dark ? "dark" : "light"
                let url = dir.appendingPathComponent("\(page.name)-\(suffix).png")
                let ok = renderPNG(SnapshotWindow(model: model), size: CGSize(width: 1200, height: 800), scheme: scheme, to: url)
                okAll = okAll && ok
                written += ok ? 1 : 0
                if !ok { print("BŁĄD renderowania: \(url.lastPathComponent)") }
            }
            if page.tall {
                for scheme in fullSchemes {
                    let url = fullDir.appendingPathComponent("\(page.name)-full\(scheme == .dark ? "-dark" : "").png")
                    if renderPNG(SnapshotWindow(model: model), size: CGSize(width: 1200, height: fullHeight), scheme: scheme, to: url) {
                        written += 1
                    }
                }
            }
        }
        print("Zapisano \(written) zrzutów w \(dir.path)")
        return okAll
    }
}

struct SnapshotWindow: View {
    var model: AppModel

    var body: some View {
        HStack(spacing: 0) {
            SnapshotSidebar()
            Rectangle().fill(Palette.cardBorder).frame(width: 1)
            DetailView()
        }
        .background(Palette.canvas)
        .environment(model)
        .environment(\.snapshotMode, true)
    }
}

import AppKit
import SwiftUI

@main
enum Entry {
    static func main() {
        let args = CommandLine.arguments
        func value(after flag: String) -> String? {
            guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
            return args[i + 1]
        }
        if args.contains("--render-icon") {
            guard let out = value(after: "--render-icon") else { fail("Użycie: Cerber --render-icon PLIK.png") }
            exit(MainActor.assumeIsolated { Offscreen.renderIcon(to: URL(fileURLWithPath: out)) } ? 0 : 1)
        }
        if args.contains("--snapshot") {
            guard let dir = value(after: "--snapshot") else { fail("Użycie: Cerber --snapshot KATALOG") }
            exit(MainActor.assumeIsolated { Offscreen.snapshots(to: URL(fileURLWithPath: dir)) } ? 0 : 1)
        }
        if args.contains("--decode") {
            guard let f = value(after: "--decode") else { fail("Użycie: Cerber --decode PLIK.jsonl") }
            exit(MainActor.assumeIsolated { SelfTest.decodeFile(URL(fileURLWithPath: f)) } ? 0 : 1)
        }
        if args.contains("--selftest-parse") {
            exit(MainActor.assumeIsolated { SelfTest.run() } ? 0 : 1)
        }
        CerberApp.main()
    }

    static func fail(_ msg: String) -> Never {
        FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
        exit(2)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var model: AppModel?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NotificationRouter.shared.install()
        if DemoRun.isActive {
            DemoRun.log("didFinishLaunching, okna: \(NSApp.windows.count)")
            NSApp.activate(ignoringOtherApps: true)
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                if let model = self.model { DemoRun.start(model: model) }
                else { DemoRun.log("brak modelu po 3 s – okno się nie pojawiło") }
            }
        }
    }

    /// With background protection on, closing the window keeps Cerber running in the menu bar.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        !(model?.protection.enabled ?? false)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model, model.isScanning else { return .terminateNow }
        let alert = NSAlert()
        alert.messageText = "Trwa skanowanie"
        alert.informativeText = "Zamknięcie Cerbera przerwie bieżące skanowanie. Czy na pewno chcesz zakończyć?"
        alert.addButton(withTitle: "Zakończ")
        alert.addButton(withTitle: "Anuluj")
        alert.alertStyle = .warning
        return alert.runModal() == .alertFirstButtonReturn ? .terminateNow : .terminateCancel
    }

    func applicationWillTerminate(_ notification: Notification) {
        model?.shutdown()
    }
}

struct CerberApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var model = AppModel(config: .detect(), live: true)

    var body: some Scene {
        Window("Cerber", id: "main") {
            RootView()
                .environment(model)
                .onAppear { delegate.model = model }
        }
        .defaultSize(width: 1220, height: 820)
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Przeskanuj plik lub folder…") { model.chooseAndScan(origin: .file) }
                    .keyboardShortcut("o", modifiers: .command)
                    .disabled(model.isScanning)
                Button("Rozpakuj archiwum w sandboksie…") { model.chooseArchive() }
                    .keyboardShortcut("o", modifiers: [.command, .shift])
                    .disabled(model.isScanning)
            }
            CommandMenu("Skanowanie") {
                Button(model.session?.phase == .cancelling ? "Zakończ natychmiast" : "Anuluj skanowanie") { model.cancel() }
                    .keyboardShortcut(".", modifiers: .command)
                    .disabled(!model.isScanning)
                Button("Nowe skanowanie") { model.newScan() }
                    .keyboardShortcut("n", modifiers: .command)
                    .disabled(model.session == nil || model.isScanning)
                Divider()
                ForEach(Array(([SidebarItem.laptop, .file, .location, .sandbox, .github, .huggingface, .link, .protection, .history, .api]).enumerated()), id: \.element) { i, item in
                    if i < 9 {
                        Button(item.title) { model.selection = item }
                            .keyboardShortcut(KeyEquivalent(Character("\(i + 1)")), modifiers: .command)
                    } else {
                        Button(item.title) { model.selection = item }
                    }
                }
                Divider()
                Button("Odśwież informacje o bazach") { model.loadInfo() }
            }
        }
        MenuBarExtra(isInserted: Binding(get: { model.protection.enabled }, set: { _ in })) {
            ProtectionMenu()
                .environment(model)
        } label: {
            Image(nsImage: MenuBarIcon.image(malicious: model.protection.lastWasMalicious))
        }
    }
}

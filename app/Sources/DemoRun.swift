import AppKit
import SwiftUI

/// Hidden developer mode used to smoke-test the live UI (real NSWindow, Table, List, process streaming):
///   CERBER_DEMO_RUN=laptop-mega|scan|cancel|ai|ai-quit CERBER_CAPTURE_DIR=DIR Cerber --mock
/// starts the scan, logs the UI state at a few checkpoints into DIR/demo.log and quits by itself.
/// (Passed in the environment on purpose: AppKit parses "-key value" arguments as defaults and treats
/// leftover arguments as documents to open, which suppresses the main window.)
@MainActor
enum DemoRun {
    static var isActive: Bool { ProcessInfo.processInfo.environment["CERBER_DEMO_RUN"] != nil }

    private static var started = false

    static func log(_ msg: String) {
        let dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["CERBER_CAPTURE_DIR"] ?? NSTemporaryDirectory())
        let url = dir.appendingPathComponent("demo.log")
        let line = "\(Date()) \(msg)\n"
        FileHandle.standardError.write(line.data(using: .utf8)!)
        if let h = try? FileHandle(forWritingTo: url) {
            h.seekToEndOfFile()
            h.write(line.data(using: .utf8)!)
            try? h.close()
        } else {
            try? line.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    static func start(model: AppModel) {
        guard isActive, !started else { return }
        started = true
        let mode = ProcessInfo.processInfo.environment["CERBER_DEMO_RUN"] ?? "laptop-mega"
        let dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["CERBER_CAPTURE_DIR"] ?? NSTemporaryDirectory())
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        setenv("CERBER_MOCK_SPEED", "3", 1)
        setenv("CERBER_MOCK_SYNTHETIC", "1", 1)

        log("demo-run: start \(mode), okna: \(NSApp.windows.count)")
        if mode == "ai" || mode == "ai-quit" {
            Task { @MainActor in
                // The download starts by itself after `info` (CERBER_MOCK_AI=missing in the mock).
                for i in 0..<60 {
                    try? await Task.sleep(for: .seconds(1))
                    capture(dir, "ai \(i)s: \(model.aiInstall)", model: model)
                    if mode == "ai-quit", model.aiInstall.isDownloading, i >= 2 { break }
                    if model.aiInstall == .installed, model.info?.aiModel != nil { break }
                }
                log("demo-run: koniec, AI dostępne: \(model.aiAvailable), przełącznik: \(model.aiEnabled)")
                NSApp.terminate(nil)
            }
            return
        }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.5))
            capture(dir, "start", model: model)
            switch mode {
            case "scan": model.scanPaths([URL(fileURLWithPath: NSHomeDirectory() + "/Downloads")], origin: .file)
            case "cancel":
                model.scanPaths([URL(fileURLWithPath: NSHomeDirectory() + "/Downloads")], origin: .file)
            default:
                model.level = .mega
                model.scanLaptop()
            }
            try? await Task.sleep(for: .seconds(mode == "cancel" ? 1.5 : 3))
            capture(dir, "w trakcie", model: model)
            if mode == "cancel" { model.cancel() }
            var waited = 0.0
            while model.isScanning && waited < 60 {
                try? await Task.sleep(for: .seconds(0.5))
                waited += 0.5
            }
            try? await Task.sleep(for: .seconds(1.2))
            capture(dir, "koniec", model: model)
            if mode != "cancel" {
                model.presentation.resultsTab = .network
                let s = model.session
                model.session = nil
                try? await Task.sleep(for: .seconds(0.3))
                model.session = s
                model.selection = .session
                try? await Task.sleep(for: .seconds(1.2))
                capture(dir, "zakładka sieć", model: model)
            }
            log("demo-run: gotowe, sesja: \(String(describing: model.session?.phase)), wyniki: \(model.session?.summary?.results.count ?? -1)")
            NSApp.terminate(nil)
        }
    }

    /// Logs what the live UI state looks like at a checkpoint (window, selection, session).
    static func capture(_ dir: URL, _ name: String, model: AppModel) {
        let w = NSApp.windows.first { $0.isVisible }
        var parts = ["[\(name)] okno: \(w.map { "\(Int($0.frame.width))×\(Int($0.frame.height))" } ?? "brak")",
                     "ekran: \(model.selection?.rawValue ?? "nil")"]
        if let s = model.session {
            parts.append("faza: \(s.phase)")
            parts.append("etapy: \(s.visited.joined(separator: ">"))")
            parts.append("znaleziska: \(s.findings.count)")
            parts.append("log: \(s.log.count)")
            if let p = s.scanProgress?.fraction { parts.append("postęp: \(Fmt.percent(p))") }
            if let sum = s.summary {
                parts.append("werdykt: \(sum.verdict.rawValue), wyniki: \(sum.results.count), anulowano: \(sum.cancelled)")
                parts.append("sekcje: env=\(sum.environment != nil) net=\(sum.network != nil) sbx=\(sum.sandbox != nil) repo=\(sum.repo != nil)")
            }
            if let f = s.fatalMessage { parts.append("błąd: \(f)") }
        }
        if let i = model.info { parts.append("bazy: \(Fmt.compact(i.patternsTotal)), AI: \(i.aiModel ?? "brak")") }
        parts.append("historia: \(model.history.count)")
        log(parts.joined(separator: " | "))
    }
}

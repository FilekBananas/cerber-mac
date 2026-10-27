import AppKit
import Observation
import SwiftUI
import WebKit

// MARK: - Report window (HTML reports inside Cerber instead of the browser)

/// Opens Cerber's HTML reports in an app window. The page itself runs no JavaScript and loads nothing from the
/// network; links to web pages go to the default browser. Next to high-risk files the report carries
/// "Do kwarantanny" links (`cerber-report://quarantine/<n>`, hidden in the .html file, shown only here); a click
/// re-checks result n in the report's JSON twin and then moves the file with the same backend command as the
/// button in scan results – the user's click is the decision, nothing is moved otherwise.
enum ReportViewer {
    static var config: BackendConfig?
    private static var windows: [String: ReportWindowController] = [:]

    /// false when the file does not exist. Non-HTML files open in their default app.
    @discardableResult
    static func open(_ path: String) -> Bool {
        guard FileManager.default.fileExists(atPath: path) else { return false }
        guard path.lowercased().hasSuffix(".html") else { return FinderActions.open(path) }
        if let c = windows[path] {
            c.page.load()
            c.window?.makeKeyAndOrderFront(nil)
        } else {
            let c = ReportWindowController(page: ReportPage(path: path, config: config))
            windows[path] = c
            c.onClose = { windows[path] = nil }
            c.window?.center()
            c.showWindow(nil)
        }
        NSApp.activate(ignoringOtherApps: true)
        return true
    }
}

final class ReportWindowController: NSWindowController, NSWindowDelegate {
    let page: ReportPage
    var onClose: (() -> Void)?

    init(page: ReportPage) {
        self.page = page
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 780),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = page.title
        window.minSize = NSSize(width: 640, height: 420)
        window.isReleasedWhenClosed = false
        window.contentViewController = NSHostingController(rootView: ReportWindowView(page: page))
        super.init(window: window)
        window.delegate = self
        page.load()
    }

    required init?(coder: NSCoder) { nil }

    func windowWillClose(_ notification: Notification) {
        onClose?()
    }
}

/// The report file, its JSON twin and what was moved to quarantine from this window.
@Observable
final class ReportPage {
    let path: String
    let config: BackendConfig?
    var html: String = ""
    /// Bumped when the page must be loaded again (file changed, "Odśwież").
    var version = 0
    var message: String?
    var messageIsError = false
    var busy: Set<Int> = []
    var moved: [Int: String] = [:]
    @ObservationIgnored var results: [JSONValue] = []
    /// Set by the web view: patches the page in place (keeps the scroll position).
    @ObservationIgnored var patch: ((String) -> Void)?

    init(path: String, config: BackendConfig?) {
        self.path = path
        self.config = config
    }

    var title: String {
        let name = (path as NSString).lastPathComponent
        if name.hasPrefix("siec-") { return "Raport – sieć i zdalny dostęp" }
        if name.hasPrefix("watch-") { return "Raport – ochrona w tle" }
        return "Raport – \(name)"
    }

    var jsonPath: String { (path as NSString).deletingPathExtension + ".json" }

    var quarantinableCount: Int { results.indices.filter { check($0) == nil }.count }

    func load() {
        var text = (try? String(contentsOfFile: path, encoding: .utf8)) ?? "<p>Nie można odczytać raportu: \(path)</p>"
        if let data = FileManager.default.contents(atPath: jsonPath), let j = JSONValue.parse(data) {
            results = j["results"].array
        } else {
            results = []
        }
        // Buttons only where the JSON agrees and the file is still there; already moved ones show it.
        for i in results.indices {
            let link = "<a class=\"qbtn\" data-i=\"\(i)\" href=\"cerber-report://quarantine/\(i)\">Do kwarantanny</a>"
            guard text.contains(link) else { continue }
            if moved[i] != nil {
                text = text.replacingOccurrences(of: link, with: Self.doneHTML)
            } else if check(i) != nil {
                text = text.replacingOccurrences(of: link, with: "<span class=\"qnote\">\(Self.esc(check(i) ?? ""))</span>")
            }
        }
        text = text.replacingOccurrences(of: "</head>", with: "<style>.qbtn{display:inline-block}</style></head>")
        html = text
        version += 1
    }

    static let doneHTML = "<span class=\"qdone\">✓ przeniesiono do kwarantanny</span>"

    /// nil = may be moved; otherwise why not (shown instead of the button).
    func check(_ i: Int) -> String? {
        guard results.indices.contains(i) else { return "brak w raporcie" }
        let r = results[i]
        let path = r["path"].text ?? ""
        let verdict = (r["verdict"].text ?? "").uppercased()
        let score = r["score"].double ?? 0
        let high = verdict == "MALICIOUS" || ((verdict == "SUSPICIOUS" || verdict == "PUA") && score >= 60)
        guard high else { return "niskie ryzyko" }
        guard path.hasPrefix("/"), !path.contains(">>") else { return "plik w archiwum – przenieś całe archiwum" }
        if r["quarantined"].text != nil || moved[i] != nil { return "już w kwarantannie" }
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else { return "pliku już nie ma na dysku" }
        guard !isDir.boolValue else { return "to folder – przenieś pliki pojedynczo" }
        return nil
    }

    func quarantine(_ i: Int) {
        guard !busy.contains(i) else { return }
        if let why = check(i) {
            show("Nie przeniesiono: \(why).", error: true)
            return
        }
        guard let config else {
            show("Nie przeniesiono: brak połączenia z silnikiem Cerbera.", error: true)
            return
        }
        let path = results[i]["path"].text ?? ""
        busy.insert(i)
        patch?("var a=document.querySelector('a.qbtn[data-i=\"\(i)\"]');if(a){a.textContent='Przenoszę…';a.style.opacity='0.6';}")
        Task { @MainActor in
            let r = await BackendProcess.run(config: config, arguments: ["quarantine", path])
            self.busy.remove(i)
            var qid: String?
            for e in r.events { if case .quarantined(_, let id) = e { qid = id } }
            if let qid {
                self.moved[i] = qid
                self.patch?("var a=document.querySelector('a.qbtn[data-i=\"\(i)\"]');if(a){a.outerHTML='\(Self.doneHTML)';}")
                self.show("Przeniesiono do kwarantanny: \((path as NSString).lastPathComponent). Plik jest zaszyfrowany i można go przywrócić (./cerber.sh quarantine).", error: false)
            } else {
                self.patch?("var a=document.querySelector('a.qbtn[data-i=\"\(i)\"]');if(a){a.textContent='Do kwarantanny';a.style.opacity='1';}")
                self.show("Nie udało się przenieść \((path as NSString).lastPathComponent): \(r.failureDescription)", error: true)
            }
        }
    }

    private func show(_ text: String, error: Bool) {
        message = text
        messageIsError = error
    }

    static func esc(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
    }
}

struct ReportWindowView: View {
    var page: ReportPage

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "doc.richtext").foregroundStyle(Palette.brand)
                VStack(alignment: .leading, spacing: 1) {
                    Text(page.title).font(.system(size: 13, weight: .semibold))
                    Text(Fmt.tilde(page.path)).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                }
                Spacer(minLength: 8)
                if page.quarantinableCount > 0 {
                    Pill(text: "do kwarantanny: \(page.quarantinableCount)", color: Palette.red, icon: "lock.shield")
                }
                Button { page.load() } label: { Label("Odśwież", systemImage: "arrow.clockwise") }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                Button { _ = FinderActions.open(page.path) } label: { Label("W przeglądarce", systemImage: "safari") }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                Button { FinderActions.reveal(page.path) } label: { Image(systemName: "folder") }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .help("Pokaż w Finderze")
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            if let m = page.message {
                HStack(spacing: 8) {
                    Image(systemName: page.messageIsError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                    Text(m).font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                    Button { page.message = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain)
                }
                .foregroundStyle(page.messageIsError ? Palette.red : Palette.green)
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .background((page.messageIsError ? Palette.red : Palette.green).opacity(0.08))
            }
            Divider()
            ReportWebView(page: page)
        }
        .frame(minWidth: 640, minHeight: 420)
    }
}

/// WKWebView without page JavaScript, without network, without persistent storage.
struct ReportWebView: NSViewRepresentable {
    var page: ReportPage

    func makeCoordinator() -> Coordinator { Coordinator(page: page) }

    func makeNSView(context: Context) -> WKWebView {
        let cfg = WKWebViewConfiguration()
        cfg.defaultWebpagePreferences.allowsContentJavaScript = false
        cfg.websiteDataStore = .nonPersistent()
        let web = WKWebView(frame: .zero, configuration: cfg)
        web.navigationDelegate = context.coordinator
        page.patch = { [weak web] js in web?.evaluateJavaScript(js, completionHandler: nil) }
        return web
    }

    func updateNSView(_ web: WKWebView, context: Context) {
        let c = context.coordinator
        guard c.loaded != page.version else { return }
        c.loaded = page.version
        let dir = URL(fileURLWithPath: (page.path as NSString).deletingLastPathComponent, isDirectory: true)
        web.loadHTMLString(page.html, baseURL: dir)
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        let page: ReportPage
        var loaded = -1

        init(page: ReportPage) { self.page = page }

        func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let url = action.request.url else { decisionHandler(.cancel); return }
            if url.scheme == "cerber-report" {
                if url.host == "quarantine", let i = Int(url.lastPathComponent), action.navigationType == .linkActivated {
                    page.quarantine(i)
                }
                decisionHandler(.cancel)
                return
            }
            if action.navigationType == .linkActivated {
                if let s = url.scheme?.lowercased(), s == "http" || s == "https" { NSWorkspace.shared.open(url) }
                decisionHandler(url.isFileURL && url.fragment != nil ? .allow : .cancel)
                return
            }
            // The page itself (loadHTMLString with the report folder as base) – nothing else is loaded.
            decisionHandler(url.isFileURL || url.scheme == "about" ? .allow : .cancel)
        }
    }
}

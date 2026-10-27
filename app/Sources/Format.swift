import Foundation

/// Polish formatting helpers (numbers, bytes, durations, dates, plural forms).
enum Fmt {
    static let locale = Locale(identifier: "pl_PL")

    private static let intFormatter: NumberFormatter = {
        let f = NumberFormatter()
        f.locale = locale
        f.numberStyle = .decimal
        f.usesGroupingSeparator = true
        f.maximumFractionDigits = 0
        return f
    }()

    private static let oneDecimal: NumberFormatter = {
        let f = NumberFormatter()
        f.locale = locale
        f.numberStyle = .decimal
        f.usesGroupingSeparator = true
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 1
        return f
    }()

    private static let fixedOneDecimal: NumberFormatter = {
        let f = NumberFormatter()
        f.locale = locale
        f.numberStyle = .decimal
        f.usesGroupingSeparator = true
        f.minimumFractionDigits = 1
        f.maximumFractionDigits = 1
        return f
    }()

    /// 7215172 → "7 215 172" (Polish grouping with a non-breaking space; 4-digit numbers are not grouped)
    static func int(_ n: Int?) -> String {
        guard let n else { return "—" }
        return intFormatter.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    static func decimal(_ d: Double, fixed: Bool = false) -> String {
        (fixed ? fixedOneDecimal : oneDecimal).string(from: NSNumber(value: d)) ?? String(format: "%.1f", d)
    }

    /// 7215172 → "7,2 mln", 13356 → "13,4 tys."
    static func compact(_ n: Int?) -> String {
        guard let n else { return "—" }
        let d = Double(n)
        if d >= 1_000_000_000 { return decimal(d / 1_000_000_000) + " mld" }
        if d >= 1_000_000 { return decimal(d / 1_000_000) + " mln" }
        if d >= 10_000 { return decimal(d / 1_000) + " tys." }
        return int(n)
    }

    /// Decimal (Finder-style) byte units.
    static func bytes(_ n: Int?) -> String {
        guard let n else { return "—" }
        let d = Double(n)
        if d < 1000 { return "\(n) B" }
        let units = ["kB", "MB", "GB", "TB", "PB"]
        var value = d / 1000
        var i = 0
        while value >= 1000, i < units.count - 1 {
            value /= 1000
            i += 1
        }
        let s = value >= 100 ? int(Int(value.rounded())) : decimal(value)
        return "\(s) \(units[i])"
    }

    static func rate(_ mbs: Double?) -> String {
        guard let mbs, mbs > 0 else { return "—" }
        return (mbs >= 100 ? int(Int(mbs.rounded())) : decimal(mbs, fixed: true)) + " MB/s"
    }

    /// 12.3 → "12,3 s", 252 → "4 min 12 s", 14230 → "3 h 57 min"
    static func duration(_ seconds: Double?) -> String {
        guard let s = seconds, s.isFinite, s >= 0 else { return "—" }
        if s < 60 { return (s < 10 ? decimal(s, fixed: true) : int(Int(s.rounded()))) + " s" }
        let total = Int(s.rounded())
        let h = total / 3600, m = (total % 3600) / 60, sec = total % 60
        if h > 0 { return m > 0 ? "\(h) h \(m) min" : "\(h) h" }
        return sec > 0 ? "\(m) min \(sec) s" : "\(m) min"
    }

    /// Stopwatch style: "02:15" / "1:02:15"
    static func clock(_ seconds: Double) -> String {
        let t = max(0, Int(seconds))
        let h = t / 3600, m = (t % 3600) / 60, s = t % 60
        return h > 0 ? String(format: "%d:%02d:%02d", h, m, s) : String(format: "%02d:%02d", m, s)
    }

    static func eta(_ seconds: Double?) -> String {
        guard let s = seconds, s.isFinite, s >= 0 else { return "—" }
        if s < 60 { return "< 1 min" }
        if s < 3600 { return "ok. \(Int((s / 60).rounded())) min" }
        let h = Int(s / 3600), m = Int((s.truncatingRemainder(dividingBy: 3600) / 60).rounded())
        return m > 0 ? "ok. \(h) h \(m) min" : "ok. \(h) h"
    }

    static func percent(_ fraction: Double) -> String {
        let p = max(0, min(100, fraction * 100))
        if p > 0, p < 1 { return "<1%" }
        return "\(Int(p.rounded(.down)))%"
    }

    // MARK: dates

    private static let parsers: [DateFormatter] = {
        ["yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd'T'HH:mm:ssZ", "yyyy-MM-dd HH:mm",
         "yyyy-MM-dd'T'HH:mm:ss.SSSSSS", "yyyy-MM-dd"].map {
            let f = DateFormatter()
            f.locale = Locale(identifier: "en_US_POSIX")
            f.dateFormat = $0
            return f
        }
    }()

    static func parseDate(_ s: String?) -> Date? {
        guard let s, !s.isEmpty else { return nil }
        for p in parsers { if let d = p.date(from: s) { return d } }
        return ISO8601DateFormatter().date(from: s)
    }

    private static let dateTimeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = locale
        f.dateFormat = "d MMM yyyy, HH:mm"
        return f
    }()

    private static let shortDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = locale
        f.dateFormat = "dd.MM.yyyy"
        return f
    }()

    private static let shortDateTimeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = locale
        f.dateFormat = "d MMM, HH:mm"
        return f
    }()

    /// "2026-10-06 10:15:00" → "6 paź 2026, 10:15"
    static func dateTime(_ s: String?) -> String {
        guard let s else { return "—" }
        guard let d = parseDate(s) else { return s }
        return dateTimeFormatter.string(from: d)
    }

    /// "2026-10-06 10:15" → "6 paź, 10:15"
    static func shortDateTime(_ s: String?) -> String {
        guard let s else { return "—" }
        guard let d = parseDate(s) else { return s }
        return shortDateTimeFormatter.string(from: d)
    }

    /// "2026-09-29 14:16" → "29.09.2026"
    static func shortDate(_ s: String?) -> String {
        guard let s else { return "—" }
        guard let d = parseDate(s) else { return s }
        return shortDateFormatter.string(from: d)
    }

    static func dateTime(_ d: Date) -> String { dateTimeFormatter.string(from: d) }

    private static let timeFormatters: [DateFormatter] = ["HH:mm", "HH:mm:ss"].map {
        let f = DateFormatter()
        f.locale = locale
        f.dateFormat = $0
        return f
    }

    /// "2026-10-07 13:10:00" → "13:10" ("13:10:00" with `seconds`); a bare time like "12:03:44" is returned as is.
    static func time(_ s: String?, seconds: Bool = false) -> String {
        guard let s else { return "—" }
        guard let d = parseDate(s) else { return s }
        return timeFormatters[seconds ? 1 : 0].string(from: d)
    }

    /// Poll interval: 5 → "5 s", 2.5 → "2,5 s"
    static func interval(_ s: Double?) -> String {
        guard let s, s.isFinite, s > 0 else { return "—" }
        return (s == s.rounded() ? "\(Int(s))" : decimal(s)) + " s"
    }

    // MARK: words

    /// Polish plural: 1 plik, 2–4 pliki (but 12–14 plików), 5+ plików.
    static func plural(_ n: Int, _ one: String, _ few: String, _ many: String) -> String {
        if n == 1 { return one }
        let m10 = n % 10, m100 = n % 100
        if (2...4).contains(m10) && !(12...14).contains(m100) { return few }
        return many
    }

    static func count(_ n: Int, _ one: String, _ few: String, _ many: String) -> String {
        "\(int(n)) \(plural(n, one, few, many))"
    }

    static func files(_ n: Int) -> String { count(n, "plik", "pliki", "plików") }

    /// Genitive, as in "361 z 1204 plików" / "z 1 pliku".
    static func filesGenitive(_ n: Int) -> String { "\(int(n)) \(n == 1 ? "pliku" : "plików")" }

    static func tilde(_ path: String) -> String {
        let home = NSHomeDirectory()
        if path == home { return "~" }
        if path.hasPrefix(home + "/") { return "~" + path.dropFirst(home.count) }
        return path
    }
}

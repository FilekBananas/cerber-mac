import Foundation

/// A lenient JSON value. Every accessor returns nil / empty instead of throwing, so unknown fields,
/// missing fields and type mismatches in backend events never break the app (PROTOCOL.md: "Unknown
/// events/fields must be ignored").
enum JSONValue: Sendable, Equatable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    init(any: Any?) {
        switch any {
        case nil:
            self = .null
        case is NSNull:
            self = .null
        case let n as NSNumber:
            if CFGetTypeID(n) == CFBooleanGetTypeID() {
                self = .bool(n.boolValue)
            } else {
                self = .number(n.doubleValue)
            }
        case let s as String:
            self = .string(s)
        case let a as [Any]:
            self = .array(a.map { JSONValue(any: $0) })
        case let d as [String: Any]:
            self = .object(d.mapValues { JSONValue(any: $0) })
        default:
            self = .null
        }
    }

    static func parse(_ data: Data) -> JSONValue? {
        guard let obj = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) else {
            return nil
        }
        return JSONValue(any: obj)
    }

    static func parse(_ text: String) -> JSONValue? {
        parse(Data(text.utf8))
    }

    subscript(key: String) -> JSONValue {
        if case .object(let d) = self { return d[key] ?? .null }
        return .null
    }

    var isNull: Bool {
        if case .null = self { return true }
        return false
    }

    var string: String? {
        switch self {
        case .string(let s): return s
        case .number(let n):
            if n.isFinite, n == n.rounded(), abs(n) < 1e15 { return String(Int64(n)) }
            return String(n)
        case .bool(let b): return b ? "true" : "false"
        default: return nil
        }
    }

    /// Non-empty, trimmed string or nil.
    var text: String? {
        guard let s = string?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty else { return nil }
        return s
    }

    var double: Double? {
        switch self {
        case .number(let n): return n.isFinite ? n : nil
        case .string(let s): return Double(s.replacingOccurrences(of: ",", with: "."))
        default: return nil
        }
    }

    var int: Int? {
        guard let d = double, d.isFinite, abs(d) < 9.0e18 else { return nil }
        return Int(d)
    }

    var bool: Bool? {
        switch self {
        case .bool(let b): return b
        case .number(let n): return n != 0
        case .string(let s):
            switch s.lowercased() {
            case "true", "yes", "on", "1", "enabled": return true
            case "false", "no", "off", "0", "disabled": return false
            default: return nil
            }
        default: return nil
        }
    }

    var array: [JSONValue] {
        if case .array(let a) = self { return a }
        return []
    }

    var object: [String: JSONValue]? {
        if case .object(let d) = self { return d }
        return nil
    }

    var stringArray: [String] {
        array.compactMap { $0.text }
    }
}

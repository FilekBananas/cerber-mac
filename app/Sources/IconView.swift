import AppKit
import SwiftUI

/// Classic heater shield.
struct ShieldShape: Shape {
    func path(in r: CGRect) -> Path {
        let w = r.width, h = r.height, x = r.minX, y = r.minY
        func p(_ px: CGFloat, _ py: CGFloat) -> CGPoint { CGPoint(x: x + px * w, y: y + py * h) }
        var path = Path()
        path.move(to: p(0.5, 0))
        path.addCurve(to: p(1, 0.13), control1: p(0.64, 0.085), control2: p(0.83, 0.13))
        path.addLine(to: p(1, 0.46))
        path.addCurve(to: p(0.5, 1), control1: p(1, 0.76), control2: p(0.76, 0.92))
        path.addCurve(to: p(0, 0.46), control1: p(0.24, 0.92), control2: p(0, 0.76))
        path.addLine(to: p(0, 0.13))
        path.addCurve(to: p(0.5, 0), control1: p(0.17, 0.13), control2: p(0.36, 0.085))
        path.closeSubpath()
        return path
    }
}

/// Stylised, geometric guard-dog head (pointing down), unit box w × 1.15w.
struct HeadShape: Shape {
    func path(in r: CGRect) -> Path {
        let w = r.width, h = r.height, x = r.minX, y = r.minY
        func p(_ px: CGFloat, _ py: CGFloat) -> CGPoint { CGPoint(x: x + px * w, y: y + py / 1.15 * h) }
        var path = Path()
        path.move(to: p(0.07, 0.0))                 // left ear tip
        path.addLine(to: p(0.37, 0.27))             // left ear inner base
        path.addQuadCurve(to: p(0.63, 0.27), control: p(0.5, 0.21))
        path.addLine(to: p(0.93, 0.0))              // right ear tip
        path.addLine(to: p(0.9, 0.44))              // right temple
        path.addLine(to: p(1.0, 0.64))              // right cheek ruff
        path.addLine(to: p(0.66, 0.9))              // right muzzle
        path.addQuadCurve(to: p(0.34, 0.9), control: p(0.5, 1.24))  // snout
        path.addLine(to: p(0.0, 0.64))              // left cheek ruff
        path.addLine(to: p(0.1, 0.44))              // left temple
        path.closeSubpath()
        return path
    }
}

/// Inner ear triangles.
struct EarsShape: Shape {
    func path(in r: CGRect) -> Path {
        let w = r.width, h = r.height, x = r.minX, y = r.minY
        func p(_ px: CGFloat, _ py: CGFloat) -> CGPoint { CGPoint(x: x + px * w, y: y + py / 1.15 * h) }
        var path = Path()
        path.move(to: p(0.14, 0.09)); path.addLine(to: p(0.33, 0.27)); path.addLine(to: p(0.17, 0.34)); path.closeSubpath()
        path.move(to: p(0.86, 0.09)); path.addLine(to: p(0.67, 0.27)); path.addLine(to: p(0.83, 0.34)); path.closeSubpath()
        return path
    }
}

/// Slanted, angry eyes.
struct EyesShape: Shape {
    func path(in r: CGRect) -> Path {
        let w = r.width, h = r.height, x = r.minX, y = r.minY
        func p(_ px: CGFloat, _ py: CGFloat) -> CGPoint { CGPoint(x: x + px * w, y: y + py / 1.15 * h) }
        var path = Path()
        path.move(to: p(0.2, 0.5)); path.addLine(to: p(0.42, 0.6)); path.addLine(to: p(0.3, 0.63)); path.closeSubpath()
        path.move(to: p(0.8, 0.5)); path.addLine(to: p(0.58, 0.6)); path.addLine(to: p(0.7, 0.63)); path.closeSubpath()
        return path
    }
}

struct NoseShape: Shape {
    func path(in r: CGRect) -> Path {
        let w = r.width, h = r.height, x = r.minX, y = r.minY
        func p(_ px: CGFloat, _ py: CGFloat) -> CGPoint { CGPoint(x: x + px * w, y: y + py / 1.15 * h) }
        var path = Path()
        path.move(to: p(0.41, 0.94)); path.addLine(to: p(0.59, 0.94)); path.addLine(to: p(0.5, 1.04)); path.closeSubpath()
        return path
    }
}

struct GuardHead: View {
    var width: CGFloat
    var separator: Color

    var body: some View {
        let size = CGSize(width: width, height: width * 1.15)
        ZStack {
            HeadShape()
                .stroke(separator, style: StrokeStyle(lineWidth: width * 0.07, lineJoin: .round))
            HeadShape()
                .fill(LinearGradient(colors: [Color(hex: 0xF4F6FF), Color(hex: 0xA9B3D6)], startPoint: .top, endPoint: .bottom))
            HeadShape()
                .stroke(Color.white.opacity(0.6), style: StrokeStyle(lineWidth: width * 0.008, lineJoin: .round))
            EarsShape()
                .fill(LinearGradient(colors: [Color(hex: 0x6B74A8), Color(hex: 0x9AA4CF)], startPoint: .top, endPoint: .bottom))
            EyesShape()
                .fill(Color(hex: 0xFFB020))
                .shadow(color: Color(hex: 0xFF8A00), radius: width * 0.05)
                .shadow(color: Color(hex: 0xFF6A00).opacity(0.8), radius: width * 0.1)
            NoseShape()
                .fill(Color(hex: 0x1E2347))
        }
        .frame(width: size.width, height: size.height)
    }
}

/// The icon rendered once to a bitmap (used in the sidebar header).
@MainActor
enum IconCache {
    static let small: NSImage = {
        let r = ImageRenderer(content: CerberIconView())
        r.scale = 0.25
        return r.nsImage ?? NSImage(size: NSSize(width: 256, height: 256))
    }()
}

/// The app icon, drawn at 1024 × 1024 (macOS grid: 824 pt body with a soft shadow).
struct CerberIconView: View {
    var body: some View {
        let inner = Color(hex: 0x141938)
        ZStack {
            // Body
            RoundedRectangle(cornerRadius: 186, style: .continuous)
                .fill(LinearGradient(colors: [Color(hex: 0x252B5C), Color(hex: 0x0B0E22)], startPoint: .top, endPoint: .bottom))
                .overlay(
                    RadialGradient(colors: [Color(hex: 0x5B5BF0).opacity(0.55), .clear], center: UnitPoint(x: 0.5, y: 0.42),
                                   startRadius: 20, endRadius: 430)
                        .clipShape(RoundedRectangle(cornerRadius: 186, style: .continuous))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 186, style: .continuous)
                        .strokeBorder(LinearGradient(colors: [.white.opacity(0.28), .white.opacity(0.04)], startPoint: .top, endPoint: .bottom), lineWidth: 3)
                )
                .frame(width: 824, height: 824)
                .shadow(color: .black.opacity(0.45), radius: 24, y: 14)

            // Shield: glow, rim and inner field
            ShieldShape()
                .fill(Color(hex: 0x4F46E5).opacity(0.65))
                .frame(width: 560, height: 640)
                .blur(radius: 40)
                .offset(y: 18)
            ShieldShape()
                .fill(LinearGradient(colors: [Color(hex: 0x8B8CFF), Color(hex: 0x4F46E5), Color(hex: 0x0EA5E9)],
                                     startPoint: .topLeading, endPoint: .bottomTrailing))
                .frame(width: 540, height: 620)
                .offset(y: 18)
            ShieldShape()
                .fill(LinearGradient(colors: [Color(hex: 0x1E2452), inner], startPoint: .top, endPoint: .bottom))
                .frame(width: 486, height: 562)
                .offset(y: 24)
            ShieldShape()
                .stroke(Color.white.opacity(0.10), lineWidth: 2)
                .frame(width: 486, height: 562)
                .offset(y: 24)

            // Three heads
            GuardHead(width: 172, separator: inner)
                .rotationEffect(.degrees(-24))
                .offset(x: -122, y: 102)
            GuardHead(width: 172, separator: inner)
                .rotationEffect(.degrees(24))
                .offset(x: 122, y: 102)
            GuardHead(width: 230, separator: inner)
                .offset(x: 0, y: 32)

            // Shine
            ShieldShape()
                .trim(from: 0.0, to: 0.25)
                .stroke(Color.white.opacity(0.55), style: StrokeStyle(lineWidth: 4, lineCap: .round))
                .frame(width: 540, height: 620)
                .offset(y: 18)
                .blur(radius: 1)
        }
        .frame(width: 1024, height: 1024)
    }
}

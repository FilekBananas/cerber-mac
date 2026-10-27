import AppKit
import SwiftUI

struct HistoryScreen: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScreenScaffold(item: .history, subtitle: "Raporty zapisane przez poprzednie skanowania z tej aplikacji.") {
            HStack(spacing: 10) {
                if !model.history.isEmpty {
                    summaryChips
                }
                Spacer()
                if model.historyState == .loading {
                    Spinner(size: 14)
                }
                Button {
                    model.loadHistory()
                } label: {
                    Label("Odśwież", systemImage: "arrow.clockwise")
                }
                .buttonStyle(SecondaryButtonStyle())
            }
            if case .failed(let msg) = model.historyState, model.history.isEmpty {
                Banner(icon: "exclamationmark.triangle.fill", title: "Nie udało się wczytać historii", message: msg,
                       color: Palette.orange, action: ("Spróbuj ponownie", { model.loadHistory() }))
            } else if model.history.isEmpty && model.historyState != .loading {
                EmptyState(icon: "clock.arrow.circlepath", title: "Brak zapisanych raportów",
                           message: "Po pierwszym skanowaniu jego raport pojawi się tutaj.", color: Palette.brand)
            } else {
                VStack(spacing: 10) {
                    ForEach(model.history) { item in
                        HistoryRow(item: item)
                    }
                }
            }
        }
    }

    private var summaryChips: some View {
        let threats = model.history.filter { $0.verdict >= .suspicious }.count
        return HStack(spacing: 8) {
            Pill(text: Fmt.count(model.history.count, "raport", "raporty", "raportów"), color: Palette.brand, icon: "doc.richtext")
            if threats > 0 {
                Pill(text: "\(threats) z wykryciami", color: Palette.orange, icon: "exclamationmark.triangle.fill")
            }
        }
    }
}

private struct HistoryRow: View {
    var item: HistoryItem
    @State private var hovering = false
    @Environment(AppModel.self) private var model

    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(item.verdict.color.opacity(0.14))
                Image(systemName: item.verdict.heroIcon)
                    .font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(item.verdict.color)
            }
            .frame(width: 44, height: 44)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(item.title).font(.system(size: 14, weight: .semibold)).lineLimit(1).truncationMode(.middle)
                    VerdictBadge(verdict: item.verdict)
                }
                HStack(spacing: 12) {
                    Label(item.mode.label, systemImage: item.mode.icon)
                    Label(Fmt.dateTime(item.started), systemImage: "calendar")
                    if let f = item.files {
                        Label(Fmt.files(f), systemImage: "doc.on.doc")
                    }
                }
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .labelStyle(CompactLabelStyle())
            }
            Spacer(minLength: 12)
            Button {
                if let p = item.reportHTML, !ReportViewer.open(p) {
                    model.alert = AppAlert(title: "Nie znaleziono raportu", message: "Plik \(p) nie istnieje – mógł zostać usunięty.")
                }
            } label: {
                Label("Raport", systemImage: "doc.richtext")
            }
            .buttonStyle(SecondaryButtonStyle(tint: Palette.brand))
            .disabled(item.reportHTML == nil)
            Button {
                if let p = item.reportHTML ?? item.reportJSON { FinderActions.reveal(p) }
            } label: {
                Image(systemName: "folder")
            }
            .buttonStyle(SecondaryButtonStyle())
            .help("Pokaż w Finderze")
            .disabled(item.reportHTML == nil && item.reportJSON == nil)
        }
        .card(padding: 14, radius: 16)
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous)
            .strokeBorder(item.verdict.color.opacity(hovering ? 0.4 : 0), lineWidth: 1.5))
        .onHover { h in withAnimation(.easeOut(duration: 0.15)) { hovering = h } }
    }
}

struct CompactLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 4) {
            configuration.icon.font(.system(size: 10.5))
            configuration.title
        }
    }
}

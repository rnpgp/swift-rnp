//
//  PaperKeyRestoreView.swift
//  RnpMailUI
//
//  Minimal UI for the paper-key restore flow. The container app
//  presents this during onboarding or from Settings → Restore from
//  backup. Calls PaperKeyRestoreService to do the work.
//

import MailSecurityEngine
import SwiftUI

@MainActor
public final class PaperKeyRestoreViewModel: ObservableObject {
    @Published public var paperKeyText: String = ""
    @Published public var inFlight: Bool = false
    @Published public var errorMessage: String?
    @Published public var restoredFingerprints: [String] = []

    public let service: PaperKeyRestoreService?
    public let onComplete: (([String]) -> Void)?

    public init(service: PaperKeyRestoreService?, onComplete: (([String]) -> Void)? = nil) {
        self.service = service
        self.onComplete = onComplete
    }

    public var canAttempt: Bool {
        !paperKeyText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    public func restore() {
        guard let service else {
            errorMessage = "Restore service unavailable (no engine)."
            return
        }
        inFlight = true
        errorMessage = nil
        let text = paperKeyText
        Task {
            do {
                let infos = try service.restore(fromText: text)
                await MainActor.run {
                    self.inFlight = false
                    self.restoredFingerprints = infos.map(\.fingerprint)
                    self.onComplete?(self.restoredFingerprints)
                }
            } catch {
                await MainActor.run {
                    self.inFlight = false
                    self.errorMessage = error.localizedDescription
                }
            }
        }
    }
}

public struct PaperKeyRestoreView: View {
    @StateObject public var viewModel: PaperKeyRestoreViewModel
    @Environment(\.dismiss) private var dismiss

    public init(viewModel: PaperKeyRestoreViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Restore from paper backup")
                .font(.title2.bold())

            Text("Paste or type your paper-key backup. The parser is whitespace- and case-insensitive; comment lines starting with `#` are ignored.")
                .font(.body)
                .foregroundStyle(.secondary)

            TextEditor(text: $viewModel.paperKeyText)
                .font(.system(.caption, design: .monospaced))
                .frame(minHeight: 200)
                .border(Color.secondary.opacity(0.3))
                .accessibilityIdentifier("restore.paper-key-text")

            if let error = viewModel.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.caption)
            }

            if !viewModel.restoredFingerprints.isEmpty {
                Label("Restored \(viewModel.restoredFingerprints.count) key\(viewModel.restoredFingerprints.count == 1 ? "" : "s")", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
                    .font(.caption)
            }

            HStack {
                Button("Cancel", role: .cancel) { dismiss() }
                Spacer()
                Button {
                    viewModel.restore()
                } label: {
                    if viewModel.inFlight {
                        ProgressView()
                    } else {
                        Text("Restore")
                    }
                }
                .keyboardShortcut(.return)
                .disabled(!viewModel.canAttempt || viewModel.inFlight)
                .accessibilityIdentifier("restore.submit")
            }
        }
        .padding()
        .frame(minWidth: 560, minHeight: 460)
    }
}

#Preview {
    PaperKeyRestoreView(viewModel: PaperKeyRestoreViewModel(service: nil))
}

//
//  DeleteForeverConfirmation.swift
//  RnpMailUI
//
//  Confirmation sheet requiring the user to type the key's
//  fingerprint before destructive deletion. Used by the
//  KeyDetailView's "Delete forever" path to prevent orphaning all
//  mail encrypted to the deleted key.
//

import SwiftUI

@MainActor
public final class DeleteForeverConfirmationViewModel: ObservableObject {
    @Published public var typedFingerprint: String = ""
    @Published public var errorMessage: String?

    public let fingerprint: String
    public let primaryUserID: String

    public init(fingerprint: String, primaryUserID: String) {
        self.fingerprint = fingerprint
        self.primaryUserID = primaryUserID
    }

    /// Normalize both fingerprints for comparison: uppercase, strip
    /// spaces and colons.
    public var matches: Bool {
        let normalize: (String) -> String = {
            $0.uppercased()
                .replacingOccurrences(of: " ", with: "")
                .replacingOccurrences(of: ":", with: "")
        }
        return normalize(typedFingerprint) == normalize(fingerprint)
    }

    public var canConfirm: Bool { matches }
}

public struct DeleteForeverConfirmation: View {
    @StateObject public var viewModel: DeleteForeverConfirmationViewModel
    @Environment(\.dismiss) private var dismiss
    public let onConfirm: () -> Void

    public init(
        viewModel: DeleteForeverConfirmationViewModel,
        onConfirm: @escaping () -> Void
    ) {
        _viewModel = StateObject(wrappedValue: viewModel)
        self.onConfirm = onConfirm
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Delete key forever?")
                .font(.title2.bold())
                .foregroundStyle(.red)

            Text("All mail encrypted to this key will become permanently undecryptable. This cannot be undone.")
                .font(.body)

            VStack(alignment: .leading, spacing: 4) {
                Text("Key: \(viewModel.primaryUserID)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Fingerprint:")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(viewModel.fingerprint)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
            }
            .padding(8)
            .background(Color(nsColor: .textBackgroundColor))
            .cornerRadius(8)

            Text("Type or paste the full fingerprint to confirm:")
                .font(.caption)
                .foregroundStyle(.secondary)
            TextField("Fingerprint", text: $viewModel.typedFingerprint)
                .font(.system(.body, design: .monospaced))
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel("Type the full fingerprint to confirm deletion")

            HStack {
                Button("Cancel", role: .cancel) { dismiss() }
                Spacer()
                Button("Delete forever", role: .destructive) {
                    guard viewModel.canConfirm else { return }
                    onConfirm()
                    dismiss()
                }
                .disabled(!viewModel.canConfirm)
            }
        }
        .padding()
        .frame(minWidth: 520, minHeight: 400)
    }
}

#Preview {
    DeleteForeverConfirmation(
        viewModel: DeleteForeverConfirmationViewModel(
            fingerprint: "AAABBBCCC111222333",
            primaryUserID: "Alice <alice@example.org>"
        ),
        onConfirm: {}
    )
}

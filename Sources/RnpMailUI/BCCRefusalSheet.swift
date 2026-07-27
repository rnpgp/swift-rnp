//
//  BCCRefusalSheet.swift
//  RnpMailUI
//
//  Sheet shown when the encode pipeline refuses to send an encrypted
//  message because BCC recipients are present (RFC 3156 §6 leak). The
//  user picks one of three resolution paths via BccResolution.
//

import MailSecurityEngine
import SwiftUI

@MainActor
public final class BCCRefusalViewModel: ObservableObject {
    @Published public var inFlight: Bool = false
    @Published public var errorMessage: String?

    public let error: BccRequiresSpecialHandlingError
    private let onResolve: (BccResolution) -> Void

    public init(error: BccRequiresSpecialHandlingError, onResolve: @escaping (BccResolution) -> Void) {
        self.error = error
        self.onResolve = onResolve
    }

    public func resolve(_ resolution: BccResolution) {
        inFlight = true
        onResolve(resolution)
        inFlight = false
    }
}

public struct BCCRefusalSheet: View {
    @StateObject public var viewModel: BCCRefusalViewModel
    @Environment(\.dismiss) private var dismiss

    public init(viewModel: BCCRefusalViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("BCC + encryption needs a decision", systemImage: "exclamationmark.shield.fill")
                .font(.title3.bold())
                .foregroundStyle(.orange)

            Text(bodyText)
                .font(.body)
                .foregroundStyle(.secondary)

            GroupBox("Hidden recipients") {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(viewModel.error.bccAddresses, id: \.self) { addr in
                        Text(addr)
                            .font(.system(.body, design: .monospaced))
                    }
                }
                .padding(8)
            }

            if let error = viewModel.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.caption)
            }

            VStack(spacing: 8) {
                Button {
                    viewModel.resolve(.sendSeparately)
                    dismiss()
                } label: {
                    Label("Send separately", systemImage: "envelope.badge")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("bcc.resolve.send-separately")

                Button {
                    viewModel.resolve(.removeEncryption)
                    dismiss()
                } label: {
                    Label("Remove encryption", systemImage: "lock.open")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("bcc.resolve.remove-encryption")

                Button {
                    viewModel.resolve(.removeBcc(bccAddresses: viewModel.error.bccAddresses))
                    dismiss()
                } label: {
                    Label("Remove BCC recipients", systemImage: "person.crop.circle.badge.minus")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("bcc.resolve.remove-bcc")

                Button("Cancel", role: .cancel) {
                    viewModel.resolve(.cancel)
                    dismiss()
                }
                .accessibilityIdentifier("bcc.resolve.cancel")
            }
        }
        .padding()
        .frame(minWidth: 480, minHeight: 420)
    }

    private var bodyText: String {
        "PGP/MIME produces one ciphertext for all recipients. Any decrypting recipient can enumerate the recipient list — including BCC — by inspecting PKESK packets. Choose how to proceed."
    }
}

#Preview {
    BCCRefusalSheet(
        viewModel: BCCRefusalViewModel(
            error: BccRequiresSpecialHandlingError(
                bccAddresses: ["hidden@example.org", "secret@example.org"]
            ),
            onResolve: { _ in }
        )
    )
}

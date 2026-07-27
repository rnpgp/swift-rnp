//
//  RecoverySheetWizard.swift
//  RnpMailUI
//
//  Three-step recovery sheet. Replaces the placeholder stub in
//  RoadmapUIStubs.swift. Engine-layer hooks: KeyManager.exportKey for
//  the revocation cert, KeyManager.exportPaperKey for the paper-key
//  text. The iCloud Keychain sync toggle uses the existing
//  KeychainPassphraseStore (the sync-bit flip lives in a follow-up; for
//  now the wizard records the user's intent and surfaces a path to
//  Settings).
//

import KeyStateStore
import MailSecurityEngine
import SwiftUI

@MainActor
public final class RecoverySheetViewModel: ObservableObject {
    public enum Step: Int, CaseIterable {
        case printRevocation
        case printPaperKey
        case icloudSync
    }

    @Published public var step: Step = .printRevocation
    @Published public var inFlight: Bool = false
    @Published public var errorMessage: String?
    @Published public var revocationCertText: String?
    @Published public var paperKeyText: String?
    @Published public var icloudSyncChosen: Bool = false
    @Published public var didSkipPaperKey: Bool = false

    public let keyFingerprint: String
    public let keyManager: KeyManager

    public init(keyFingerprint: String, keyManager: KeyManager) {
        self.keyFingerprint = keyFingerprint
        self.keyManager = keyManager
    }

    public var stepNumber: Int { step.rawValue + 1 }
    public var stepCount: Int { Step.allCases.count }

    public func loadRevocationCert() {
        inFlight = true
        errorMessage = nil
        Task {
            do {
                let data = try keyManager.exportRevocationCertificate(fingerprint: keyFingerprint)
                let text = String(data: data, encoding: .utf8) ?? ""
                await MainActor.run {
                    self.revocationCertText = text
                    self.inFlight = false
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                    self.inFlight = false
                }
            }
        }
    }

    public func loadPaperKey() {
        inFlight = true
        errorMessage = nil
        Task {
            do {
                let text = try keyManager.exportPaperKey(fingerprint: keyFingerprint)
                await MainActor.run {
                    self.paperKeyText = text
                    self.inFlight = false
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                    self.inFlight = false
                }
            }
        }
    }

    public func advance() {
        if let next = Step(rawValue: step.rawValue + 1) {
            step = next
        }
    }

    public func dismissAfterSkip() {
        // The wizard is "sticky" — it re-appears on next launch until
        // the paper-key step is completed. The container app's
        // persistence layer records this; the view just signals intent.
        if step == .printPaperKey, paperKeyText == nil {
            didSkipPaperKey = true
        }
    }
}

public struct RecoverySheetWizard: View {
    @StateObject public var viewModel: RecoverySheetViewModel
    @Environment(\.dismiss) private var dismiss

    public init(viewModel: RecoverySheetViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Save your recovery materials")
                    .font(.title2.bold())
                Spacer()
                Text("Step \(viewModel.stepNumber) of \(viewModel.stepCount)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            ProgressView(value: Double(viewModel.stepNumber), total: Double(viewModel.stepCount))

            switch viewModel.step {
            case .printRevocation:
                revocationStep
            case .printPaperKey:
                paperKeyStep
            case .icloudSync:
                icloudStep
            }

            if let error = viewModel.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.caption)
            }

            HStack {
                Button("Cancel", role: .cancel) {
                    viewModel.dismissAfterSkip()
                    dismiss()
                }
                Spacer()
                if viewModel.step != .icloudSync {
                    Button("Next") { viewModel.advance() }
                        .keyboardShortcut(.return)
                } else {
                    Button("Done") {
                        viewModel.dismissAfterSkip()
                        dismiss()
                    }
                    .keyboardShortcut(.return)
                }
            }
        }
        .padding()
        .frame(minWidth: 560, minHeight: 480)
        .onAppear {
            if viewModel.step == .printRevocation && viewModel.revocationCertText == nil {
                viewModel.loadRevocationCert()
            }
        }
        .onChange(of: viewModel.step) { newStep in
            if newStep == .printPaperKey && viewModel.paperKeyText == nil {
                viewModel.loadPaperKey()
            }
        }
    }

    // MARK: - Steps

    @ViewBuilder
    private var revocationStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Print your revocation certificate")
                .font(.headline)
            Text("If your key is ever lost or compromised, this certificate tells the world to stop using it. Print it now and store it somewhere safe — without it, you cannot revoke your key.")
                .font(.body)
                .foregroundStyle(.secondary)
            if viewModel.inFlight {
                ProgressView()
            } else if let cert = viewModel.revocationCertText {
                ScrollView {
                    Text(cert)
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                .frame(maxHeight: 240)
                .padding(8)
                .background(Color(nsColor: .textBackgroundColor))
                .cornerRadius(8)

                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(cert, forType: .string)
                } label: {
                    Label("Copy to clipboard", systemImage: "doc.on.doc")
                }
            }
        }
    }

    @ViewBuilder
    private var paperKeyStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Print your paper-key backup")
                .font(.headline)
            Text("This lets you restore all your encrypted mail on a new Mac. Store it somewhere safe and offline. Anyone with this paper and your passphrase can read your mail.")
                .font(.body)
                .foregroundStyle(.secondary)
            if viewModel.inFlight {
                ProgressView()
            } else if let paperKey = viewModel.paperKeyText {
                ScrollView {
                    Text(paperKey)
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                .frame(maxHeight: 240)
                .padding(8)
                .background(Color(nsColor: .textBackgroundColor))
                .cornerRadius(8)
            }
        }
    }

    @ViewBuilder
    private var icloudStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("iCloud Keychain sync")
                .font(.headline)
            Text("If you turn this on, your keyring passphrase syncs to your iCloud Keychain. On a new Mac, you'll only need to restore the paper-key — the passphrase comes automatically. iCloud Keychain is end-to-end encrypted by Apple.")
                .font(.body)
                .foregroundStyle(.secondary)

            Toggle("Use iCloud Keychain sync for the keyring passphrase", isOn: $viewModel.icloudSyncChosen)
                .accessibilityHint("When enabled, the keyring passphrase syncs across your Apple devices.")
                .onChange(of: viewModel.icloudSyncChosen) { newValue in
                    _ = KeychainPassphraseStore.setICloudSyncEnabled(newValue)
                }

            Text("When enabled, the keyring passphrase is stored in a synchronizable Keychain item. The passphrase alone is useless without your paper-key backup.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

#Preview {
    let temp = FileManager.default.temporaryDirectory
        .appendingPathComponent("rnp-recovery-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: temp) }
    let km = try! KeyManager(directory: temp, password: "preview")
    let info = try? km.generateKey(userID: "Alice <alice@example.org>", algorithm: .ed25519)
    let vm = RecoverySheetViewModel(keyFingerprint: info!.fingerprint, keyManager: km)
    return RecoverySheetWizard(viewModel: vm)
}

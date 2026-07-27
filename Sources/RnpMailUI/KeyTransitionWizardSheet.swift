//
//  KeyTransitionWizardSheet.swift
//  RnpMailUI
//
//  Multi-step SwiftUI sheet wrapping the engine-layer KeyTransition
//  orchestrator. Walks the user through: choose new key algorithm,
//  confirm UIDs, certify with old key, revoke old as superseded,
//  publish and notify. Engine does the work; this view is purely
//  presentation + step ordering.
//

import KeyLifecycle
import MailSecurityEngine
import SwiftUI

@MainActor
public final class KeyTransitionWizardViewModel: ObservableObject {
    public enum Step: Int, CaseIterable {
        case chooseAlgorithm
        case confirmUIDs
        case certifyAndRevoke
        case publishAndNotify
        case finished
    }

    @Published public var step: Step = .chooseAlgorithm
    @Published public var newKeyAlgorithm: KeyAlgorithm = .ed25519
    @Published public var userIDsToCopy: [String] = []
    @Published public var publishAfterTransition: Bool = true
    @Published public var notifyContactsAfterTransition: Bool = true
    @Published public var inFlight: Bool = false
    @Published public var errorMessage: String?
    @Published public var result: KeyTransitionResult?

    public let oldFingerprint: String
    public let oldPrimaryUserID: String
    private let keyManager: KeyManager
    private let onComplete: ((KeyTransitionResult) -> Void)?

    public init(
        oldFingerprint: String,
        oldPrimaryUserID: String,
        keyManager: KeyManager,
        onComplete: ((KeyTransitionResult) -> Void)? = nil
    ) {
        self.oldFingerprint = oldFingerprint
        self.oldPrimaryUserID = oldPrimaryUserID
        self.keyManager = keyManager
        self.onComplete = onComplete
    }

    public var stepNumber: Int { step.rawValue + 1 }
    public var stepCount: Int { Step.allCases.count }

    public func advance() {
        if let next = Step(rawValue: step.rawValue + 1) {
            step = next
        }
    }

    public func cancel() {
        // No rollback needed: engine has not run yet.
    }

    public func run() {
        inFlight = true
        errorMessage = nil
        let transition = KeyTransition(keyManager: keyManager)
        let algorithm = newKeyAlgorithm
        let uids = userIDsToCopy
        Task {
            do {
                let result = try transition.run(
                    replacing: oldFingerprint,
                    newKeyAlgorithm: algorithm,
                    userIDsOverride: uids.isEmpty ? nil : uids
                )
                await MainActor.run {
                    self.result = result
                    self.inFlight = false
                    self.step = .finished
                    self.onComplete?(result)
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                    self.inFlight = false
                }
            }
        }
    }
}

public struct KeyTransitionWizardSheet: View {
    @StateObject public var viewModel: KeyTransitionWizardViewModel
    @Environment(\.dismiss) private var dismiss

    public init(viewModel: KeyTransitionWizardViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading) {
                    Text("Migrate to a new key")
                        .font(.title2.bold())
                    Text(viewModel.oldPrimaryUserID)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Text("Step \(viewModel.stepNumber) of \(viewModel.stepCount)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            ProgressView(value: Double(viewModel.stepNumber), total: Double(viewModel.stepCount))

            switch viewModel.step {
            case .chooseAlgorithm: algorithmStep
            case .confirmUIDs: uidsStep
            case .certifyAndRevoke: certifyStep
            case .publishAndNotify: publishStep
            case .finished: finishedStep
            }

            if let error = viewModel.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.caption)
            }

            Divider()
            navigationButtons
        }
        .padding()
        .frame(minWidth: 600, minHeight: 520)
    }

    @ViewBuilder
    private var algorithmStep: some View {
        Text("Pick the algorithm for the new key. The old key's UIDs will be copied onto the new key.")
            .foregroundStyle(.secondary)
        Picker("Algorithm", selection: $viewModel.newKeyAlgorithm) {
            Text("Ed25519 (recommended)").tag(KeyAlgorithm.ed25519)
            Text("ECDSA P-256").tag(KeyAlgorithm.ecdsa)
            Text("RSA-3072 (legacy compat)").tag(KeyAlgorithm.rsa)
            Text("Hybrid PQ (ML-DSA-65+ED25519)").tag(KeyAlgorithm.hybridPQ)
        }
        .pickerStyle(.radioGroup)
    }

    @ViewBuilder
    private var uidsStep: some View {
        Text("The UIDs from your old key will be copied to the new key. Adjust the list below if you want to drop any.")
            .foregroundStyle(.secondary)
        if viewModel.userIDsToCopy.isEmpty {
            Text("No UIDs selected — only the new key's placeholder UID will be used.")
                .font(.caption)
                .foregroundStyle(.orange)
        } else {
            ForEach(viewModel.userIDsToCopy, id: \.self) { uid in
                Text(uid)
                    .font(.system(.body, design: .monospaced))
            }
        }
    }

    @ViewBuilder
    private var certifyStep: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("The wizard will:")
                .font(.headline)
            VStack(alignment: .leading, spacing: 6) {
                Label("Certify each new-key UID with the old key (transition certification)", systemImage: "checkmark.shield")
                Label("Revoke the old key with reason `superseded`, naming the new fingerprint", systemImage: "minus.circle")
                Label("Archive the old key (decrypt-only) so historical mail still decrypts", systemImage: "archivebox")
            }
            .font(.body)
            Text("After this step, the old key cannot be used for new mail. Old encrypted mail still decrypts.")
                .font(.caption)
                .foregroundStyle(.orange)
        }
    }

    @ViewBuilder
    private var publishStep: some View {
        VStack(alignment: .leading, spacing: 8) {
            Toggle("Publish new (and revoked old) key to keyserver", isOn: $viewModel.publishAfterTransition)
            Toggle("Notify contacts who encrypted to me recently", isOn: $viewModel.notifyContactsAfterTransition)
            Text("Notifications use a templated email with the new fingerprint. Recipients are pulled from the per-message records.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var finishedStep: some View {
        if let result = viewModel.result {
            VStack(alignment: .leading, spacing: 8) {
                Label("Done", systemImage: "checkmark.seal.fill")
                    .font(.title3.bold())
                    .foregroundStyle(.green)
                Text("New key fingerprint:")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(result.newFingerprint)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                Text("Old key fingerprint (archived):")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(result.oldFingerprint)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                if result.transitionCertificationAdded {
                    Label("Certification signature added", systemImage: "checkmark")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Label("Certification skipped — notify contacts out-of-band", systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
        } else {
            ProgressView()
        }
    }

    @ViewBuilder
    private var navigationButtons: some View {
        HStack {
            Button("Cancel", role: .cancel) {
                viewModel.cancel()
                dismiss()
            }
            Spacer()
            if viewModel.step == .publishAndNotify {
                Button {
                    viewModel.run()
                } label: {
                    if viewModel.inFlight {
                        ProgressView()
                    } else {
                        Text("Run transition")
                    }
                }
                .keyboardShortcut(.return)
                .disabled(viewModel.inFlight)
            } else if viewModel.step == .finished {
                Button("Done") { dismiss() }
                    .keyboardShortcut(.return)
            } else {
                Button("Next") { viewModel.advance() }
                    .keyboardShortcut(.return)
            }
        }
    }
}

#Preview {
    let temp = FileManager.default.temporaryDirectory
        .appendingPathComponent("rnp-preview-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: temp) }
    let km = try! KeyManager(directory: temp, password: "preview")
    let info = try? km.generateKey(userID: "Alice <alice@example.org>", algorithm: .ed25519)
    let vm = KeyTransitionWizardViewModel(
        oldFingerprint: info!.fingerprint,
        oldPrimaryUserID: "Alice <alice@example.org>",
        keyManager: km
    )
    return KeyTransitionWizardSheet(viewModel: vm)
}

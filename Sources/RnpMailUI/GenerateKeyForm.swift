//
//  GenerateKeyForm.swift
//  swift-rnp
//
//  Key generation form used by the onboarding flow.
//

import SwiftUI
import MailSecurityEngine

/// Collects the details for a new OpenPGP key during onboarding.
public struct GenerateKeyForm: View {
    @ObservedObject var viewModel: OnboardingViewModel
    let onGenerate: () -> Void
    let onBack: () -> Void

    public init(
        viewModel: OnboardingViewModel,
        onGenerate: @escaping () -> Void,
        onBack: @escaping () -> Void
    ) {
        self.viewModel = viewModel
        self.onGenerate = onGenerate
        self.onBack = onBack
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: RnpSpacing.md) {
            HStack(spacing: RnpSpacing.xs) {
                Image(systemName: "key.fill")
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(Color.accentColor)
                    .accessibilityHidden(true)
                Text("generateForm.title")
                    .font(.headline)
            }

            HStack(spacing: RnpSpacing.sm) {
                TextField("generateForm.name.placeholder", text: $viewModel.name)
                    .accessibilityIdentifier("generateform.name")
                TextField("generateForm.email.placeholder", text: $viewModel.email)
                    .accessibilityIdentifier("generateform.email")
            }

            Picker("generateForm.algorithm.label", selection: $viewModel.algorithm) {
                Text("generateForm.algorithm.ed25519").tag(KeyAlgorithm.ed25519)
                Text("generateForm.algorithm.rsa").tag(KeyAlgorithm.rsa)
                Text("generateForm.algorithm.ecdsa").tag(KeyAlgorithm.ecdsa)
            }
            .pickerStyle(.segmented)
            .accessibilityIdentifier("generateform.algorithm")

            HStack {
                Text("generateForm.expires.label")
                Picker("generateForm.expires.label", selection: $viewModel.expirationDays) {
                    Text("generateForm.expiry.1year").tag(365)
                    Text("generateForm.expiry.2years").tag(730)
                    Text("generateForm.expiry.noExpiry").tag(0)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .accessibilityIdentifier("generateform.expiry")
            }

            VStack(alignment: .leading, spacing: RnpSpacing.xxs) {
                SecureField("generateForm.passphrase.placeholder", text: $viewModel.passphrase)
                    .accessibilityIdentifier("generateform.passphrase")
                PassphraseStrengthMeter(passphrase: viewModel.passphrase)
            }

            SecureField("generateForm.confirm.placeholder", text: $viewModel.confirmPassphrase)
                .accessibilityIdentifier("generateform.confirm-passphrase")

            if viewModel.passphrase != viewModel.confirmPassphrase, !viewModel.confirmPassphrase.isEmpty {
                RnpInlineError(
                    message: "generateForm.passphrase.mismatch".localized
                )
                .accessibilityIdentifier("generateform.mismatch-warning")
            }

            Toggle("generateForm.touchID", isOn: $viewModel.useTouchID)
                .accessibilityIdentifier("generateform.touchid")

            HStack {
                Button("button.back", action: onBack)
                    .accessibilityIdentifier("generateform.back")
                Spacer()
                if viewModel.isWorking {
                    ProgressView()
                        .controlSize(.small)
                        .accessibilityIdentifier("generateform.progress")
                }
                Button("generateForm.createButton") {
                    onGenerate()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!viewModel.canGenerate || viewModel.isWorking)
                .accessibilityIdentifier("generateform.create")
            }
        }
        .frame(width: 440)
        .padding(RnpSpacing.xl)
    }
}

#if DEBUG
struct GenerateKeyForm_Previews: PreviewProvider {
    static var previews: some View {
        GenerateKeyForm(viewModel: OnboardingViewModel(), onGenerate: {}, onBack: {})
    }
}
#endif

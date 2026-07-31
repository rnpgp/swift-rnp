//
//  ImportKeyForm.swift
//  swift-rnp
//
//  Key import form used by the onboarding flow.
//

import SwiftUI

/// Collects an armored OpenPGP key block during onboarding.
public struct ImportKeyForm: View {
    @ObservedObject var viewModel: OnboardingViewModel
    let onImport: () -> Void
    let onBack: () -> Void
    let onImportFromKeyring: (() -> Void)?

    public init(
        viewModel: OnboardingViewModel,
        onImport: @escaping () -> Void,
        onBack: @escaping () -> Void,
        onImportFromKeyring: (() -> Void)? = nil
    ) {
        self.viewModel = viewModel
        self.onImport = onImport
        self.onBack = onBack
        self.onImportFromKeyring = onImportFromKeyring
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: RnpSpacing.md) {
            HStack(spacing: RnpSpacing.xs) {
                Image(systemName: "square.and.arrow.down")
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(Color.accentColor)
                    .accessibilityHidden(true)
                Text("importForm.title")
                    .font(.headline)
            }

            if let onImportFromKeyring {
                Button {
                    onImportFromKeyring()
                } label: {
                    Label("importForm.fromKeyring", systemImage: "shippingbox")
                }
                .buttonStyle(.bordered)
                .controlSize(.regular)
                .accessibilityIdentifier("importform.from-keyring")
            }

            Text("importForm.message")
                .font(.callout)

            TextEditor(text: $viewModel.importText)
                .font(.system(.body, design: .monospaced))
                .frame(height: 180)
                .padding(RnpSpacing.xxs)
                .overlay(
                    RoundedRectangle(cornerRadius: RnpRadius.badge, style: .continuous)
                        .stroke(Color.secondary.opacity(0.25), lineWidth: 1)
                )
                .accessibilityIdentifier("importform.text")

            Button("importForm.fetchPlaceholder") {}
                .disabled(true)
                .font(.caption)
                .accessibilityIdentifier("importform.fetch")

            HStack {
                Button("button.back", action: onBack)
                    .accessibilityIdentifier("importform.back")
                Spacer()
                if viewModel.isWorking {
                    ProgressView()
                        .controlSize(.small)
                        .accessibilityIdentifier("importform.progress")
                }
                Button("button.import") {
                    onImport()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!viewModel.canImport || viewModel.isWorking)
                .accessibilityIdentifier("importform.import")
            }
        }
        .frame(width: 440)
        .padding(RnpSpacing.xl)
    }
}

#if DEBUG
struct ImportKeyForm_Previews: PreviewProvider {
    static var previews: some View {
        ImportKeyForm(
            viewModel: OnboardingViewModel(),
            onImport: {},
            onBack: {},
            onImportFromKeyring: {}
        )
    }
}
#endif

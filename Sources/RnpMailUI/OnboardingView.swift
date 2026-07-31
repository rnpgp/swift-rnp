//
//  OnboardingView.swift
//  swift-rnp
//
//  First-launch onboarding flow: welcome, create/import, done.
//
//  The welcome page leads with the app icon, a tagline, and three feature
//  highlight cards; steps crossfade with a subtle slide.
//

import AppKit
import SwiftUI
import MailSecurityEngine

/// First-launch onboarding sheet.
///
/// The view is driven by `OnboardingViewModel`; all side effects are provided
/// as closures so the view remains testable without a live keyring.
public struct OnboardingView: View {
    @Binding var isPresented: Bool
    @StateObject private var viewModel: OnboardingViewModel

    private let onGenerate: (String, KeyAlgorithm, String, UInt32, Bool) -> Result<OnboardingGenerationResult, Error>
    private let onImport: (Data) -> Result<[KeyInfo], Error>
    private let onComplete: () -> Void
    private let onImportFromKeyring: (() -> Void)?

    public init(
        isPresented: Binding<Bool>,
        viewModel: OnboardingViewModel = OnboardingViewModel(),
        onGenerate: @escaping (String, KeyAlgorithm, String, UInt32, Bool) -> Result<OnboardingGenerationResult, Error>,
        onImport: @escaping (Data) -> Result<[KeyInfo], Error>,
        onComplete: @escaping () -> Void = {},
        onImportFromKeyring: (() -> Void)? = nil
    ) {
        self._isPresented = isPresented
        self._viewModel = StateObject(wrappedValue: viewModel)
        self.onGenerate = onGenerate
        self.onImport = onImport
        self.onComplete = onComplete
        self.onImportFromKeyring = onImportFromKeyring
    }

    public var body: some View {
        VStack(spacing: RnpSpacing.lg) {
            progressIndicator
                .padding(.top, RnpSpacing.xxs)
            stepContent
                .id(stepIdentifier)
                .transition(
                    .asymmetric(
                        insertion: .move(edge: .trailing).combined(with: .opacity),
                        removal: .move(edge: .leading).combined(with: .opacity)
                    )
                )
        }
        .padding(RnpSpacing.xxl)
        .frame(minWidth: 560, minHeight: 420)
        .animation(.easeInOut(duration: 0.25), value: viewModel.currentStep)
        .alert(
            "error.onboarding.title",
            isPresented: Binding(
                get: { viewModel.errorMessage != nil },
                set: { if !$0 { viewModel.errorMessage = nil } }
            )
        ) {
            Button("button.ok") { viewModel.errorMessage = nil }
        } message: {
            Text(viewModel.errorMessage ?? "")
        }
    }

    @ViewBuilder
    private var stepContent: some View {
        switch viewModel.currentStep {
        case .welcome:
            welcomePage
        case .createOrImport:
            createOrImportPage
        case .generateForm:
            GenerateKeyForm(
                viewModel: viewModel,
                onGenerate: { viewModel.generate(using: onGenerate) },
                onBack: { viewModel.goBack() }
            )
        case .importForm:
            ImportKeyForm(
                viewModel: viewModel,
                onImport: { viewModel.importKeys(using: onImport) },
                onBack: { viewModel.goBack() },
                onImportFromKeyring: onImportFromKeyring
            )
        case .restoreFromBackup:
            PaperKeyRestoreView(viewModel: PaperKeyRestoreViewModel(
                service: nil,
                onComplete: { _ in viewModel.finishRestore() }
            ))
        case .done(let url):
            donePage(revocationURL: url)
        }
    }

    // MARK: - Progress

    /// Coarse phase for the progress dots: welcome, setup, done.
    private var stepIndex: Int {
        switch viewModel.currentStep {
        case .welcome:
            return 0
        case .createOrImport, .generateForm, .importForm, .restoreFromBackup:
            return 1
        case .done:
            return 2
        }
    }

    /// Distinct identity per step so the transition also fires between steps
    /// that share a progress phase.
    private var stepIdentifier: String {
        switch viewModel.currentStep {
        case .welcome:
            return "welcome"
        case .createOrImport:
            return "createOrImport"
        case .generateForm:
            return "generateForm"
        case .importForm:
            return "importForm"
        case .restoreFromBackup:
            return "restoreFromBackup"
        case .done:
            return "done"
        }
    }

    private var progressIndicator: some View {
        HStack(spacing: RnpSpacing.xs) {
            ForEach(0 ..< 3, id: \.self) { index in
                Capsule()
                    .fill(index <= stepIndex ? Color.accentColor : Color.secondary.opacity(0.25))
                    .frame(width: index == stepIndex ? 20 : 8, height: 8)
            }
        }
        .animation(.easeInOut(duration: 0.25), value: stepIndex)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(String(format: "onboarding.progress".localized, stepIndex + 1, 3))
    }

    // MARK: - Welcome

    /// The app's icon, when available (in unit tests there is no app bundle
    /// icon, so the hero falls back to a symbol).
    private var appIconImage: NSImage? {
        guard let icon = NSApplication.shared.applicationIconImage,
              !icon.representations.isEmpty
        else {
            return nil
        }
        return icon
    }

    private var welcomePage: some View {
        VStack(spacing: RnpSpacing.lg) {
            Spacer()
            if let icon = appIconImage {
                Image(nsImage: icon)
                    .resizable()
                    .frame(width: 88, height: 88)
                    .shadow(color: .black.opacity(0.18), radius: 6, y: 3)
                    .accessibilityHidden(true)
            } else {
                RnpLogoView(size: 88)
                    .shadow(color: .black.opacity(0.18), radius: 6, y: 3)
            }
            VStack(spacing: RnpSpacing.xs) {
                Text("onboarding.welcome.title")
                    .font(.largeTitle.weight(.semibold))
                Text("onboarding.welcome.subtitle")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 420)
            }
            HStack(spacing: RnpSpacing.sm) {
                OnboardingFeatureCard(
                    icon: "envelope.badge.shield.half.filled",
                    title: "onboarding.feature.mail.title",
                    subtitle: "onboarding.feature.mail.subtitle"
                )
                OnboardingFeatureCard(
                    icon: "touchid",
                    title: "onboarding.feature.touchid.title",
                    subtitle: "onboarding.feature.touchid.subtitle"
                )
                OnboardingFeatureCard(
                    icon: "checkmark.shield",
                    title: "onboarding.feature.tofu.title",
                    subtitle: "onboarding.feature.tofu.subtitle"
                )
            }
            .padding(.top, RnpSpacing.xxs)
            Button("onboarding.welcome.button") {
                viewModel.continueFromWelcome()
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .accessibilityIdentifier("onboarding.welcome.continue")
            .padding(.top, RnpSpacing.xxs)
            Button("onboarding.skip.button") {
                isPresented = false
            }
            .buttonStyle(.plain)
            .font(.caption)
            .foregroundStyle(.secondary)
            .keyboardShortcut(.escape, modifiers: [])
            .accessibilityIdentifier("onboarding.welcome.skip")
            Spacer()
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: - Create or import

    private var createOrImportPage: some View {
        VStack(spacing: RnpSpacing.xl) {
            Spacer()
            VStack(spacing: RnpSpacing.xs) {
                Text("onboarding.setup.title")
                    .font(.title2.weight(.semibold))
                Text("onboarding.setup.subtitle")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 420)
            }
            HStack(spacing: RnpSpacing.md) {
                OnboardingOptionCard(
                    title: "onboarding.createKey",
                    subtitle: "onboarding.option.create.subtitle",
                    icon: "key.fill",
                    identifier: "onboarding.create",
                    action: { viewModel.chooseCreate() }
                )
                OnboardingOptionCard(
                    title: "onboarding.importKey",
                    subtitle: "onboarding.option.import.subtitle",
                    icon: "square.and.arrow.down",
                    identifier: "onboarding.import",
                    action: { viewModel.chooseImport() }
                )
            }
            .padding(.top, RnpSpacing.xs)
            Button("onboarding.restoreFromBackup") {
                viewModel.chooseRestore()
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .accessibilityIdentifier("onboarding.restore")
            Button("onboarding.skip.button") {
                isPresented = false
            }
            .buttonStyle(.plain)
            .font(.caption)
            .foregroundStyle(.secondary)
            .keyboardShortcut(.escape, modifiers: [])
            .accessibilityIdentifier("onboarding.setup.skip")
            Spacer()
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: - Done

    private func donePage(revocationURL: URL?) -> some View {
        DonePage(
            revocationURL: revocationURL,
            onFinish: {
                onComplete()
                isPresented = false
            }
        )
    }
}

/// Completion step, split out so the checkmark animation state is scoped to
/// the page's lifetime.
private struct DonePage: View {
    let revocationURL: URL?
    let onFinish: () -> Void

    @State private var checkmarkAppeared = false

    var body: some View {
        VStack(spacing: RnpSpacing.md) {
            Spacer()
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 52))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(.green)
                .scaleEffect(checkmarkAppeared ? 1 : 0.4)
                .opacity(checkmarkAppeared ? 1 : 0)
                .animation(.spring(response: 0.45, dampingFraction: 0.6), value: checkmarkAppeared)
                .onAppear { checkmarkAppeared = true }
                .accessibilityHidden(true)
            Text("onboarding.done.title")
                .font(.title2.weight(.semibold))

            if let url = revocationURL {
                VStack(spacing: RnpSpacing.xs) {
                    Text("onboarding.done.revocationLabel")
                        .font(.callout.weight(.medium))
                    Text(url.path)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .accessibilityIdentifier("onboarding.done.revocation-path")
                    Text("onboarding.done.revocationHint")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(RnpSpacing.md)
                .frame(maxWidth: 440)
                .background(
                    .quaternary,
                    in: RoundedRectangle(cornerRadius: RnpRadius.panel, style: .continuous)
                )
            }

            Button("onboarding.done.publishPlaceholder") {}
                .disabled(true)
                .accessibilityIdentifier("onboarding.done.publish")

            Button("button.done", action: onFinish)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("onboarding.done.finish")
            Spacer()
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}

/// Feature highlight on the welcome page: SF Symbol, title, one-line caption.
private struct OnboardingFeatureCard: View {
    let icon: String
    let title: LocalizedStringKey
    let subtitle: LocalizedStringKey

    var body: some View {
        VStack(spacing: RnpSpacing.xs) {
            Image(systemName: icon)
                .font(.system(size: 24))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(Color.accentColor)
                .frame(height: 28)
                .accessibilityHidden(true)
            Text(title)
                .font(.callout.weight(.semibold))
                .multilineTextAlignment(.center)
            Text(subtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(width: 150)
        .padding(RnpSpacing.sm)
        .background(
            .ultraThinMaterial,
            in: RoundedRectangle(cornerRadius: RnpRadius.panel, style: .continuous)
        )
        .accessibilityElement(children: .combine)
    }
}

/// Card-style button used for the create/import choice.
private struct OnboardingOptionCard: View {
    let title: LocalizedStringKey
    let subtitle: LocalizedStringKey
    let icon: String
    let identifier: String
    let action: () -> Void

    @State private var isHovering = false

    var body: some View {
        Button(action: action) {
            VStack(spacing: RnpSpacing.xs) {
                Image(systemName: icon)
                    .font(.system(size: 28))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(Color.accentColor)
                    .frame(height: 32)
                    .accessibilityHidden(true)
                Text(title)
                    .font(.headline)
                    .multilineTextAlignment(.center)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(width: 190)
            .padding(.vertical, RnpSpacing.lg)
            .padding(.horizontal, RnpSpacing.sm)
            .background(
                .quaternary.opacity(isHovering ? 1 : 0.6),
                in: RoundedRectangle(cornerRadius: RnpRadius.panel, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: RnpRadius.panel, style: .continuous)
                    .strokeBorder(
                        isHovering ? Color.accentColor.opacity(0.5) : Color(nsColor: .separatorColor),
                        lineWidth: 1
                    )
            )
            .contentShape(RoundedRectangle(cornerRadius: RnpRadius.panel, style: .continuous))
        }
        .buttonStyle(.plain)
        .scaleEffect(isHovering ? 1.02 : 1.0)
        .animation(.easeOut(duration: 0.15), value: isHovering)
        .onHover { isHovering = $0 }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityIdentifier(identifier)
    }
}

#if DEBUG
struct OnboardingView_Previews: PreviewProvider {
    static var previews: some View {
        OnboardingView(
            isPresented: .constant(true),
            onGenerate: { _, _, _, _, _ in
                .success(OnboardingGenerationResult(
                    userID: "Preview <preview@example.com>",
                    fingerprint: "ABCD1234",
                    revocationCertificateURL: URL(fileURLWithPath: "/tmp/rev.asc")
                ))
            },
            onImport: { _ in .success([]) }
        )
    }
}
#endif

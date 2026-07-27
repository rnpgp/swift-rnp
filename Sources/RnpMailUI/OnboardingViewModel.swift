//
//  OnboardingViewModel.swift
//  swift-rnp
//
//  State machine for the first-launch onboarding flow.
//

import Combine
import Foundation
import MailSecurityEngine

/// The result of generating a key during onboarding.
public struct OnboardingGenerationResult {
    /// The generated user ID ("Name <email>").
    public let userID: String
    /// The primary key fingerprint.
    public let fingerprint: String
    /// File URL of the saved revocation certificate.
    public let revocationCertificateURL: URL

    public init(userID: String, fingerprint: String, revocationCertificateURL: URL) {
        self.userID = userID
        self.fingerprint = fingerprint
        self.revocationCertificateURL = revocationCertificateURL
    }
}

/// The current page of the onboarding flow.
public enum OnboardingStep: Equatable {
    case welcome
    case createOrImport
    case generateForm
    case importForm
    case restoreFromBackup
    case done(URL?)
}

/// Observable state for the onboarding flow.
public final class OnboardingViewModel: ObservableObject {
    @Published public var currentStep: OnboardingStep = .welcome
    @Published public var name = ""
    @Published public var email = ""
    @Published public var algorithm: KeyAlgorithm = .ed25519
    @Published public var passphrase = ""
    @Published public var confirmPassphrase = ""
    @Published public var useTouchID = true
    @Published public var expirationDays = 730
    @Published public var importText = ""
    @Published public var isWorking = false
    @Published public var errorMessage: String?

    public init() {}

    /// The OpenPGP user ID built from the name and email fields.
    public var userID: String {
        "\(name) <\(email)>"
    }

    /// Whether the generate form has enough information to create a key.
    public var canGenerate: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty
            && !email.trimmingCharacters(in: .whitespaces).isEmpty
            && email.contains("@")
            && passphrase == confirmPassphrase
            && !passphrase.isEmpty
            && passphrase.count >= 8
    }

    /// Whether the import form has text that looks like an armored OpenPGP
    /// block.
    public var canImport: Bool {
        importText.contains("BEGIN PGP")
    }

    public func continueFromWelcome() {
        currentStep = .createOrImport
    }

    public func chooseCreate() {
        currentStep = .generateForm
    }

    public func chooseImport() {
        currentStep = .importForm
    }

    public func chooseRestore() {
        currentStep = .restoreFromBackup
    }

    public func goBack() {
        switch currentStep {
        case .generateForm, .importForm, .restoreFromBackup:
            currentStep = .createOrImport
        case .createOrImport:
            currentStep = .welcome
        case .welcome, .done:
            break
        }
    }

    /// Generates a key by calling the supplied closure and advances to the
    /// done page on success.
    public func generate(
        using generate: (String, KeyAlgorithm, String, UInt32, Bool) -> Result<OnboardingGenerationResult, Error>
    ) {
        guard canGenerate else {
            errorMessage = "onboarding.error.incompleteForm".localized
            return
        }
        isWorking = true
        errorMessage = nil

        let expirationSeconds = UInt32(expirationDays * 24 * 60 * 60)
        let result = generate(userID, algorithm, passphrase, expirationSeconds, useTouchID)

        isWorking = false
        switch result {
        case .success(let info):
            currentStep = .done(info.revocationCertificateURL)
        case .failure(let error):
            errorMessage = humanFriendly(error)
        }
    }

    /// Imports keys from the pasted armored text and advances to the done
    /// page on success.
    public func importKeys(
        using importKeys: (Data) -> Result<[KeyInfo], Error>
    ) {
        guard canImport else {
            errorMessage = "onboarding.error.emptyImport".localized
            return
        }
        isWorking = true
        errorMessage = nil

        let result = importKeys(Data(importText.utf8))

        isWorking = false
        switch result {
        case .success:
            currentStep = .done(nil)
        case .failure(let error):
            errorMessage = humanFriendly(error)
        }
    }

    private func humanFriendly(_ error: Error) -> String {
        if let localized = error as? LocalizedError, let description = localized.errorDescription {
            return description
        }
        let text = error.localizedDescription
        return text.isEmpty ? "error.generic".localized : text
    }

    /// Advances from the restore step to done. The PaperKeyRestoreView's
    /// onComplete calls this after the service successfully imports the key.
    public func finishRestore() {
        currentStep = .done(nil)
    }
}

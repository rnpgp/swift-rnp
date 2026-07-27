//
//  MailSecurityBannerView+DecryptionFailure.swift
//  MailSecurityUI
//
//  Additive presentation layer that consumes a typed `DecryptionFailure`
//  and renders the appropriate banner text + action button. The base
//  banner keeps its string-based EncryptionInfo for backward compat;
//  this extension adds the typed path used by the engine-layer
//  classifier (PR #81).
//

import AppKit
import MailSecurityEngine

/// User-facing action offered for a `DecryptionFailure`. The container
/// app wires each case to an engine call.
public enum DecryptionFailureAction: Equatable, Sendable {
    case fetchFromKeyserver(keyID: String)
    case restoreFromArchive(fingerprint: String)
    case enterPassphrase
    case importKeyManually
    case refreshKeyring
    case checkForUpdates
    case openMessageSource
    case openDiagnostics
}

/// Pure presentation model produced from a `DecryptionFailure`.
public struct DecryptionFailurePresentation: Equatable, Sendable {
    public let bannerText: String
    public let primaryAction: DecryptionFailureAction?
    public let secondaryAction: DecryptionFailureAction?

    public init(bannerText: String, primaryAction: DecryptionFailureAction?, secondaryAction: DecryptionFailureAction?) {
        self.bannerText = bannerText
        self.primaryAction = primaryAction
        self.secondaryAction = secondaryAction
    }

    /// Maps a typed failure to its user-facing presentation. One place
    /// for the mapping (MECE); banner rendering reads from this.
    public static func presentation(for failure: DecryptionFailure) -> DecryptionFailurePresentation {
        switch failure {
        case let .missingSecretKey(_, action):
            switch action {
            case let .fetchFromKeyserver(keyID):
                return DecryptionFailurePresentation(
                    bannerText: failure.bannerText,
                    primaryAction: .fetchFromKeyserver(keyID: keyID),
                    secondaryAction: .importKeyManually
                )
            case let .restoreFromArchive(fingerprint, _):
                return DecryptionFailurePresentation(
                    bannerText: failure.bannerText,
                    primaryAction: .restoreFromArchive(fingerprint: fingerprint),
                    secondaryAction: nil
                )
            case .importKeyManually:
                return DecryptionFailurePresentation(
                    bannerText: failure.bannerText,
                    primaryAction: .importKeyManually,
                    secondaryAction: nil
                )
            case .none:
                return DecryptionFailurePresentation(
                    bannerText: failure.bannerText,
                    primaryAction: .refreshKeyring,
                    secondaryAction: nil
                )
            }

        case .wrongPassphrase:
            return DecryptionFailurePresentation(
                bannerText: failure.bannerText,
                primaryAction: .enterPassphrase,
                secondaryAction: nil
            )

        case .integrityFailure:
            // Tamper warning: no recovery action; the message must not
            // be trusted. Offer diagnostics for reporting.
            return DecryptionFailurePresentation(
                bannerText: failure.bannerText,
                primaryAction: .openDiagnostics,
                secondaryAction: nil
            )

        case .unsupportedAlgorithm:
            return DecryptionFailurePresentation(
                bannerText: failure.bannerText,
                primaryAction: .checkForUpdates,
                secondaryAction: .openMessageSource
            )

        case .symmetricEncryption:
            return DecryptionFailurePresentation(
                bannerText: failure.bannerText,
                primaryAction: .enterPassphrase,
                secondaryAction: nil
            )

        case .malformedArmor:
            return DecryptionFailurePresentation(
                bannerText: failure.bannerText,
                primaryAction: .openMessageSource,
                secondaryAction: .openDiagnostics
            )

        case .unknown:
            return DecryptionFailurePresentation(
                bannerText: failure.bannerText,
                primaryAction: .openDiagnostics,
                secondaryAction: nil
            )
        }
    }
}

public extension MailSecurityBannerView.EncryptionInfo {
    /// Convenience factory from a typed `DecryptionFailure`. Carries
    /// the banner text into the existing string-based field; the
    /// action buttons are surfaced separately via
    /// `DecryptionFailureAction.presentation(for:)`.
    static func from(_ failure: DecryptionFailure) -> MailSecurityBannerView.EncryptionInfo {
        MailSecurityBannerView.EncryptionInfo(
            isEncrypted: true,
            errorDescription: failure.bannerText
        )
    }
}

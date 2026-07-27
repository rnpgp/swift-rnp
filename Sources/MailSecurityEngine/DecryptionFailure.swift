//
//  DecryptionFailure.swift
//  MailSecurityEngine
//
//  Typed taxonomy of decryption failures with actionable recovery actions.
//  The Mail banner reads from this enum (via `DecryptionFailure.copy` and
//  `DecryptionFailure.primaryAction`) instead of branching on raw error
//  strings, so the mapping from engine to UI is concentrated in one
//  file (MECE) and new failure types extend the existing table without
//  editing call sites (OCP).
//

import Foundation

/// One discrete reason an OpenPGP message could not be decrypted.
///
/// The classifier in `DecryptionFailure.classify(...)` produces exactly
/// one of these per failure. Banner rendering and UI actions consult the
/// type, never the librnp error string.
public enum DecryptionFailure: Error, Equatable, Sendable {
    /// We do not have any of the keys the message was encrypted to. The
    /// `pkeskKeyIDs` carry the recipient key IDs observed in PKESK
    /// packets, when visible (v3 PKESK). For v6 PKESK the list may be
    /// empty; the suggested action then offers a keyring refresh.
    case missingSecretKey(pkeskKeyIDs: [String], suggestedAction: MissingKeyAction)

    /// The keyring passphrase did not unlock any matching secret key.
    case wrongPassphrase

    /// librnp reported an integrity-protection failure (MDC mismatch or
    /// AEAD authentication failure). The message was tampered with or
    /// corrupted in transit.
    case integrityFailure

    /// The message was encrypted with an algorithm or version librnp does
    /// not support. The offending algorithm name is included for the
    /// "check for updates" copy.
    case unsupportedAlgorithm(String)

    /// The message is symmetrically encrypted (no public-key recipient)
    /// and needs a passphrase to decrypt.
    case symmetricEncryption

    /// ASCII armor is malformed. Best-effort detail string is included
    /// (e.g., "invalid CRC at line 12").
    case malformedArmor(detail: String)

    /// Catch-all for errors librnp doesn't classify further. The original
    /// `librnpMessage` is preserved for diagnostics and crash reports.
    case unknown(librnpMessage: String)

    /// Maps a failure to one short user-facing sentence. Banner primary
    /// copy. Never raw librnp text.
    public var bannerText: String {
        switch self {
        case let .missingSecretKey(_, action):
            switch action {
            case let .fetchFromKeyserver(keyID):
                return "Encrypted to a key you don't have (key ID \(keyID))."
            case let .restoreFromArchive(fingerprint, _):
                let short = String(fingerprint.suffix(16))
                return "Encrypted to your archived key \(short)."
            case .importKeyManually:
                return "Encrypted to a key you don't have."
            case .none:
                return "Encrypted to a hidden recipient. Refresh your keyring and try again."
            }
        case .wrongPassphrase:
            return "Couldn't unlock your keyring."
        case .integrityFailure:
            return "This message was tampered with in transit. Do not trust its contents."
        case let .unsupportedAlgorithm(alg):
            return "Encrypted with \(alg), which this version of RNP doesn't support."
        case .symmetricEncryption:
            return "Encrypted with a passphrase."
        case let .malformedArmor(detail):
            return "This message's PGP armor is malformed (\(detail))."
        case let .unknown(message):
            return "Couldn't decrypt this message. \(message)"
        }
    }
}

/// The one-click action the UI should offer for a `missingSecretKey`
/// failure. Other failure types have their own fixed actions.
public enum MissingKeyAction: Equatable, Sendable {
    /// The PKESK carried a visible key ID; offer to fetch it from the
    /// configured keyserver.
    case fetchFromKeyserver(keyID: String)

    /// The matching key exists in the keyring but is archived (decrypt-
    /// only per `KeyStateStore`); offer to restore it.
    case restoreFromArchive(fingerprint: String, archivedDate: Date)

    /// No actionable key ID and no archived candidate; offer to import a
    /// key manually.
    case importKeyManually

    /// v6 anonymous PKESK with no key ID. The action is "refresh
    /// keyring," which is not a one-click banner action; this case is
    /// surfaced as a banner hint rather than a button.
    case none
}

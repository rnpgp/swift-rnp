//
//  KeyHealth.swift
//  MailSecurityEngine
//
//  Pure models for the key-health scenario table described in
//  TODO.roadmap/04-key-expiry-recovery.md. Each scenario is a tuple of
//  (key role, expiry state, secret availability) → (impact, recovery
//  action). Kept as a pure function so it is exhaustively unit-testable
//  without FFI or filesystem.
//

import Foundation
import KeyringStore
import KeyStateStore

/// Discrete health state for a single key. Surfaced in the Key Health
/// view; computed from a `KeyInfo` snapshot plus the secret-availability
/// and revocation context.
public enum KeyHealthState: String, Equatable, Sendable {
    case healthy
    case expiringSoon    // < 60 days, > 0
    case expired         // past expiration date
    case revoked
    case archived
    case conflict
}

/// Role of the key relative to the user: their own key (has secret) or a
/// recipient's key (public only). Affects which recovery actions are
/// available.
public enum KeyRole: String, Equatable, Sendable {
    case ownSecretAvailable
    case ownSecretMissing
    case recipient
}

/// One actionable step offered to the user.
public enum RecoveryAction: Equatable, Sendable {
    case extendExpiry(keyFingerprint: String, defaultYears: Int)
    case rotateEncryptionSubkey(keyFingerprint: String)
    case rotateSigningSubkey(keyFingerprint: String)
    case publishKey(keyFingerprint: String)
    case notifyContacts(keyFingerprint: String)
    case archiveKey(keyFingerprint: String)
    case generateReplacementKey(viaTransitionWizard: Bool)
    case fetchLatestFromKeyserver(address: String)
    case contactOutOfBand(address: String)
    case verifyFingerprint(keyFingerprint: String)
    case informationalOnly   // no action needed (e.g., own key expired but mail decrypts fine)
}

/// The full recovery recommendation for one scenario. The UI consumes
/// `primary` (one-click action), `secondary` (additional options), and
/// `explanation` (the human-readable sentence).
public struct RecoveryRecommendation: Equatable, Sendable {
    public let state: KeyHealthState
    public let role: KeyRole
    public let primary: RecoveryAction?
    public let secondary: [RecoveryAction]
    public let explanation: String

    public init(
        state: KeyHealthState,
        role: KeyRole,
        primary: RecoveryAction?,
        secondary: [RecoveryAction] = [],
        explanation: String
    ) {
        self.state = state
        self.role = role
        self.primary = primary
        self.secondary = secondary
        self.explanation = explanation
    }
}

/// The recovery mapping. Pure; deterministic. Inputs are domain types,
/// not raw librnp data, so the function is independent of the engine.
public enum ExpiryRecovery {
    /// The threshold below which "expiring soon" applies. 60 days, per
    /// the TODO.roadmap spec.
    public static let expiringSoonDays: Int = 60

    /// Returns the recovery recommendation for a key in a given state.
    public static func action(
        state: KeyHealthState,
        role: KeyRole,
        address: String?,
        fingerprint: String
    ) -> RecoveryRecommendation {
        switch (state, role) {
        case (.healthy, _):
            return RecoveryRecommendation(
                state: .healthy,
                role: role,
                primary: nil,
                explanation: "Key is healthy."
            )

        case (.expiringSoon, .ownSecretAvailable):
            return RecoveryRecommendation(
                state: .expiringSoon,
                role: role,
                primary: .extendExpiry(keyFingerprint: fingerprint, defaultYears: 2),
                secondary: [
                    .publishKey(keyFingerprint: fingerprint),
                    .notifyContacts(keyFingerprint: fingerprint),
                ],
                explanation: "Your key expires soon. Recipients may stop trusting new signatures."
            )

        case (.expiringSoon, .ownSecretMissing):
            // Cannot extend without secret; need replacement.
            return RecoveryRecommendation(
                state: .expiringSoon,
                role: role,
                primary: .generateReplacementKey(viaTransitionWizard: false),
                secondary: [
                    .notifyContacts(keyFingerprint: fingerprint),
                ],
                explanation: "Your key expires soon and you no longer have its secret material."
            )

        case (.expiringSoon, .recipient):
            return RecoveryRecommendation(
                state: .expiringSoon,
                role: role,
                primary: address.map { .fetchLatestFromKeyserver(address: $0) },
                secondary: address.map { [.contactOutOfBand(address: $0)] } ?? [],
                explanation: "This contact's key expires soon. A refresh may pick up an extension."
            )

        case (.expired, .ownSecretAvailable):
            return RecoveryRecommendation(
                state: .expired,
                role: role,
                primary: .extendExpiry(keyFingerprint: fingerprint, defaultYears: 2),
                secondary: [
                    .publishKey(keyFingerprint: fingerprint),
                    .notifyContacts(keyFingerprint: fingerprint),
                    .rotateEncryptionSubkey(keyFingerprint: fingerprint),
                ],
                explanation: "Your key has expired. Old mail still decrypts; you cannot sign or encrypt new mail."
            )

        case (.expired, .ownSecretMissing):
            return RecoveryRecommendation(
                state: .expired,
                role: role,
                primary: .generateReplacementKey(viaTransitionWizard: false),
                secondary: [
                    .notifyContacts(keyFingerprint: fingerprint),
                    .verifyFingerprint(keyFingerprint: fingerprint),
                ],
                explanation: "Your key has expired and you no longer have its secret material. Generate a new key and notify contacts."
            )

        case (.expired, .recipient):
            return RecoveryRecommendation(
                state: .expired,
                role: role,
                primary: address.map { .fetchLatestFromKeyserver(address: $0) },
                secondary: address.map { [.contactOutOfBand(address: $0)] } ?? [],
                explanation: "This contact's key has expired. Fetch the latest version; if still expired, contact them out-of-band."
            )

        case (.revoked, .ownSecretAvailable):
            return RecoveryRecommendation(
                state: .revoked,
                role: role,
                primary: .archiveKey(keyFingerprint: fingerprint),
                secondary: [
                    .generateReplacementKey(viaTransitionWizard: true),
                    .notifyContacts(keyFingerprint: fingerprint),
                ],
                explanation: "Key is revoked. Archive it to keep decrypting old mail; generate a replacement."
            )

        case (.revoked, .ownSecretMissing):
            return RecoveryRecommendation(
                state: .revoked,
                role: role,
                primary: .archiveKey(keyFingerprint: fingerprint),
                secondary: [
                    .generateReplacementKey(viaTransitionWizard: false),
                    .notifyContacts(keyFingerprint: fingerprint),
                ],
                explanation: "Key is revoked. Archive it; generate a replacement."
            )

        case (.revoked, .recipient):
            return RecoveryRecommendation(
                state: .revoked,
                role: role,
                primary: address.map { .fetchLatestFromKeyserver(address: $0) },
                explanation: "This contact's key is revoked. They may have published a replacement."
            )

        case (.archived, _):
            return RecoveryRecommendation(
                state: .archived,
                role: role,
                primary: nil,
                secondary: [.verifyFingerprint(keyFingerprint: fingerprint)],
                explanation: "Key is archived (decrypt-only). No action needed; mail encrypted to it still decrypts."
            )

        case (.conflict, _):
            return RecoveryRecommendation(
                state: .conflict,
                role: role,
                primary: .verifyFingerprint(keyFingerprint: fingerprint),
                secondary: [.archiveKey(keyFingerprint: fingerprint)],
                explanation: "Key fingerprint changed. Verify the new fingerprint before encrypting."
            )
        }
    }

    /// Convenience: computes the health state from a `KeyInfo` snapshot,
    /// the key's role, and the current date.
    public static func state(
        for info: KeyInfo,
        role: KeyRole,
        usageState: KeyUsageState,
        now: Date = Date()
    ) -> KeyHealthState {
        if usageState == .archived { return .archived }
        if info.isRevoked { return .revoked }
        if let expiration = info.expirationDate {
            if expiration <= now { return .expired }
            let daysUntil = Calendar.current.dateComponents([.day], from: now, to: expiration).day ?? 0
            if daysUntil <= expiringSoonDays { return .expiringSoon }
        }
        return .healthy
    }
}

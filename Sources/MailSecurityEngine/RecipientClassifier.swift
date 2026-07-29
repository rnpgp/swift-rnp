//
//  RecipientClassifier.swift
//  MailSecurityEngine
//
//  Pure classification of one recipient's status from an aggregated
//  snapshot. Previously inlined in
//  `MessageSecurityCore.classify(address:)`, which had to reach into
//  three stores (key-state, trust, rnp metadata) and apply precedence
//  rules between them — impossible to unit-test without librnp.
//
//  Now `MessageSecurityCore.recipientDiagnostics` builds a snapshot per
//  address (the part that needs the engine) and hands it to
//  `RecipientClassifier.classify` (the part that's pure). The precedence
//  rules live in one place and are testable with plain data.
//

import Foundation
import TrustStore

/// Aggregated view of one recipient's status, as needed for
/// classification. Built by the engine layer (`MessageSecurityCore`)
/// from the keyring, key-state store, and trust store; consumed by the
/// pure `RecipientClassifier`.
public struct RecipientSnapshot: Equatable {
    public let address: String
    /// The resolved key, if any. `nil` when the address has no known key
    /// or only an archived one.
    public let keyInfo: KeyInfo?
    /// `true` when the address has a key but it is archived (decrypt-only).
    /// Only meaningful when `keyInfo` is `nil`.
    public let isArchivedOnly: Bool
    /// Trust state of the address. Defaults to `.unverified` when no key
    /// is present.
    public let trustState: TrustState
    /// `true` when the trust store has flagged a key-change conflict for
    /// the address.
    public let hasTrustConflict: Bool

    public init(
        address: String,
        keyInfo: KeyInfo?,
        isArchivedOnly: Bool = false,
        trustState: TrustState = .unverified,
        hasTrustConflict: Bool = false
    ) {
        self.address = address
        self.keyInfo = keyInfo
        self.isArchivedOnly = isArchivedOnly
        self.trustState = trustState
        self.hasTrustConflict = hasTrustConflict
    }
}

/// Pure recipient-status classifier. Given a `RecipientSnapshot`,
/// returns the recipient's `EngineRecipientStatus.State`. No engine
/// access, no FFI, no filesystem — fully unit-testable.
public enum RecipientClassifier {
    /// Classifies a recipient snapshot.
    ///
    /// Precedence (highest first):
    /// 1. no key + archived-only  → `.archived`
    /// 2. no key                  → `.missingKey`
    /// 3. trust conflict OR problem → `.keyChangedConflict`
    /// 4. revoked                 → `.revoked`
    /// 5. expired (within 60d threshold) → `.expired(daysUntilExpiry)`
    /// 6. trust verified          → `.verified`
    /// 7. trust unverified        → `.unverified`
    public static func classify(
        _ snapshot: RecipientSnapshot,
        now: Date = Date(),
        upcomingExpiryThresholdDays: Int = 60
    ) -> EngineRecipientStatus.State {
        guard let info = snapshot.keyInfo else {
            return snapshot.isArchivedOnly ? .archived : .missingKey
        }
        if snapshot.hasTrustConflict || snapshot.trustState == .problem {
            return .keyChangedConflict
        }
        if info.isRevoked {
            return .revoked
        }
        if let expiration = info.expirationDate {
            if expiration <= now {
                return .expired(daysUntilExpiry: nil)
            }
            let days = Calendar.current.dateComponents([.day], from: now, to: expiration).day
            if let days, days < upcomingExpiryThresholdDays {
                return .expired(daysUntilExpiry: days)
            }
        }
        switch snapshot.trustState {
        case .verified: return .verified
        case .unverified: return .unverified
        case .problem: return .keyChangedConflict
        }
    }
}

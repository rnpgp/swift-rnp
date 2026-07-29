//
//  MessageSecurityCore+RecipientDiagnostics.swift
//  MailSecurityEngine
//
//  Helper for MailKit handlers that need a per-recipient status
//  breakdown for the compose banner. Produces an array of
//  ComposeRecipientStatus (from the RnpMailUI module's standpoint)
//  by aggregating engine state. Returns plain structs to avoid the
//  UI dependency.
//

import Foundation

/// Plain engine-layer representation of one recipient's status,
/// matching `ComposeRecipientStatus` in RnpMailUI but without
/// requiring the UI module at this layer. The UI translates.
public struct EngineRecipientStatus: Equatable, Sendable {
    public enum State: Equatable, Sendable {
        case verified
        case unverified
        case missingKey
        case expired(daysUntilExpiry: Int?)
        case keyChangedConflict
        case archived
        case revoked
    }

    public let address: String
    public let state: State
    public let fingerprintShort: String?
    public let algorithmLabel: String?

    public init(
        address: String,
        state: State,
        fingerprintShort: String? = nil,
        algorithmLabel: String? = nil
    ) {
        self.address = address
        self.state = state
        self.fingerprintShort = fingerprintShort
        self.algorithmLabel = algorithmLabel
    }
}

public extension MessageSecurityCore {
    /// Produces a per-recipient status breakdown for the compose UX.
    /// Reads from the engine's trust store, keyring, and key-state
    /// store to build a snapshot per address, then delegates the
    /// actual classification to the pure `RecipientClassifier`.
    func recipientDiagnostics(
        forRecipients addresses: [String]
    ) -> [EngineRecipientStatus] {
        addresses.map { address in
            let snapshot = makeSnapshot(for: address)
            let state = RecipientClassifier.classify(snapshot)
            return EngineRecipientStatus(
                address: snapshot.address,
                state: state,
                fingerprintShort: snapshot.keyInfo.map { shortFingerprint($0.fingerprint) },
                algorithmLabel: snapshot.keyInfo?.algorithmLabel
            )
        }
    }

    private func makeSnapshot(for address: String) -> RecipientSnapshot {
        let resolution = (try? engine.keyManager.resolveActiveRecipients(addresses: [address]))
            ?? RecipientResolution(resolved: [:], missing: [address], archivedOnly: [])
        let isMissing = resolution.missing.contains(address)
        let isArchivedOnly = resolution.archivedOnly.contains(address)
        let keyInfo: KeyInfo? = (isMissing || isArchivedOnly) ? nil : resolution.resolved[address]
        return RecipientSnapshot(
            address: address,
            keyInfo: keyInfo,
            isArchivedOnly: isArchivedOnly,
            trustState: engine.keyManager.trustStore.state(forEmail: address),
            hasTrustConflict: engine.keyManager.trustStore.hasConflict(forEmail: address)
        )
    }

    private func shortFingerprint(_ fpr: String) -> String {
        guard fpr.count >= 16 else { return fpr }
        return String(fpr.suffix(16))
    }
}

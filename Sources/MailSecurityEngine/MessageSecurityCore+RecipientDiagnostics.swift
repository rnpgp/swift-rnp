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
    /// store to classify each address.
    func recipientDiagnostics(
        forRecipients addresses: [String]
    ) -> [EngineRecipientStatus] {
        addresses.map { address in
            classify(address: address)
        }
    }

    private func classify(address: String) -> EngineRecipientStatus {
        do {
            let resolution = try engine.keyManager.resolveActiveRecipients(addresses: [address])
            if resolution.missing.contains(address) {
                // Missing OR archived-only — check archived.
                if resolution.archivedOnly.contains(address) {
                    return EngineRecipientStatus(address: address, state: .archived)
                }
                return EngineRecipientStatus(address: address, state: .missingKey)
            }
            guard let info = resolution.resolved[address] else {
                return EngineRecipientStatus(address: address, state: .missingKey)
            }
            // Trust state.
            if engine.keyManager.trustStore.hasConflict(forEmail: address) {
                return EngineRecipientStatus(
                    address: address,
                    state: .keyChangedConflict,
                    fingerprintShort: shortFingerprint(info.fingerprint),
                    algorithmLabel: info.algorithmLabel
                )
            }
            let trust = engine.keyManager.trustStore.state(forEmail: address)
            // Revoked key.
            if info.isRevoked {
                return EngineRecipientStatus(
                    address: address,
                    state: .revoked,
                    fingerprintShort: shortFingerprint(info.fingerprint),
                    algorithmLabel: info.algorithmLabel
                )
            }
            // Expired.
            if let expiration = info.expirationDate {
                let now = Date()
                if expiration <= now {
                    return EngineRecipientStatus(
                        address: address,
                        state: .expired(daysUntilExpiry: nil),
                        fingerprintShort: shortFingerprint(info.fingerprint),
                        algorithmLabel: info.algorithmLabel
                    )
                }
                let days = Calendar.current.dateComponents([.day], from: now, to: expiration).day
                if let days, days < 60 {
                    return EngineRecipientStatus(
                        address: address,
                        state: .expired(daysUntilExpiry: days),
                        fingerprintShort: shortFingerprint(info.fingerprint),
                        algorithmLabel: info.algorithmLabel
                    )
                }
            }
            // Healthy.
            switch trust {
            case .verified: return EngineRecipientStatus(
                address: address,
                state: .verified,
                fingerprintShort: shortFingerprint(info.fingerprint),
                algorithmLabel: info.algorithmLabel
            )
            case .unverified: return EngineRecipientStatus(
                address: address,
                state: .unverified,
                fingerprintShort: shortFingerprint(info.fingerprint),
                algorithmLabel: info.algorithmLabel
            )
            case .problem: return EngineRecipientStatus(
                address: address,
                state: .keyChangedConflict,
                fingerprintShort: shortFingerprint(info.fingerprint),
                algorithmLabel: info.algorithmLabel
            )
            }
        } catch {
            return EngineRecipientStatus(address: address, state: .missingKey)
        }
    }

    private func shortFingerprint(_ fpr: String) -> String {
        guard fpr.count >= 16 else { return fpr }
        return String(fpr.suffix(16))
    }
}

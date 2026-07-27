//
//  KeyUsageState.swift
//  KeyStateStore
//
//  Per-key usage policy: which keys are eligible for new operations
//  (signing, encryption) versus retained only for decrypting historical
//  mail. Mirrors the "soft-delete" pattern from GnuPG / Enigmail: a user
//  who revokes or retires a key should not have to choose between
//  clutter and orphaning every message ever encrypted to that key.
//

import Foundation

/// Discrete usage states for a primary key known to the engine.
///
/// - Note: This is an engine-layer concern, not a keyring-layer concern.
///   The state does not modify the key itself; it is consulted by the
///   engine when selecting keys for new operations. Decryption always
///   considers every secret in the keyring regardless of state, so
///   archived keys remain able to decrypt historical mail.
public enum KeyUsageState: String, Codable, Equatable, Sendable {
    /// Default state. The key participates in all operations for which it
    /// is technically eligible.
    case active
    /// Decrypt-only. The key is hidden from the default key list and is
    /// never selected for new signing or encryption. It still contributes
    /// its secret material to decryption of incoming mail and to
    /// verification of old signatures.
    case archived
}

/// One entry in the key-state store: a fingerprint paired with its current
/// usage state, a modification timestamp, and an optional human-readable
/// reason explaining how the state was reached.
public struct KeyStateRecord: Codable, Equatable, Sendable {
    public let fingerprint: String
    public let state: KeyUsageState
    public let lastModified: Date
    public let reason: String?

    public init(
        fingerprint: String,
        state: KeyUsageState,
        lastModified: Date = Date(),
        reason: String? = nil
    ) {
        self.fingerprint = fingerprint
        self.state = state
        self.lastModified = lastModified
        self.reason = reason
    }
}

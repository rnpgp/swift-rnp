//
//  KeyManager+UsageState.swift
//  MailSecurityEngine
//
//  Archive / restore API layered on top of `KeyManager`. The base type's
//  initializer gained an optional `keyStateStore` parameter (default
//  `nil`, lazy-created) — existing call sites are unchanged.
//
//  Design notes:
//  - Decryption is unchanged: librnp iterates the whole secret keyring,
//    so archived keys still decrypt historical mail by remaining in the
//    keyring.
//  - Signing and encryption selection consult `keyStateStore` via the
//    `activeSigningKey(forUserID:)` and `resolveActiveRecipients(...)`
//    helpers in this extension. Call sites in `MessageSecurityCore`
//    switch to these helpers (rather than branching on state themselves)
//    so the exclusion is concentrated in one place.
//

import Foundation
import KeyStateStore
import Rnp

/// Decoded view of a recipient address's resolution, used by the encode
/// pipeline to surface distinct cases ("no key" vs "only an archived key")
/// without leaking the engine's internals into UI code.
public struct RecipientResolution: Equatable {
    /// Addresses that resolved to an active key.
    public let resolved: [String: KeyInfo]
    /// Addresses with no resolvable key at all.
    public let missing: [String]
    /// Addresses whose only known key is archived — typically a stale
    /// contact. Surfaced separately so the compose UX can recommend
    /// re-fetching the latest key from a keyserver.
    public let archivedOnly: [String]

    public init(resolved: [String: KeyInfo], missing: [String], archivedOnly: [String]) {
        self.resolved = resolved
        self.missing = missing
        self.archivedOnly = archivedOnly
    }
}

extension KeyringStore {
    /// Current usage state for the fingerprint. Defaults to `.active` when
    /// the fingerprint has no recorded state.
    public func usageState(forFingerprint fingerprint: String) -> KeyUsageState {
        keyStateStore.state(forFingerprint: fingerprint)
    }

    /// The state record (including last-modified date and reason), or `nil`
    /// when the fingerprint has no recorded state.
    public func usageRecord(forFingerprint fingerprint: String) -> KeyStateRecord? {
        keyStateStore.record(forFingerprint: fingerprint)
    }

    /// Sets the usage state and records an optional human-readable reason.
    public func setUsageState(
        _ state: KeyUsageState,
        forFingerprint fingerprint: String,
        reason: String? = nil
    ) throws {
        try keyStateStore.setState(state, forFingerprint: fingerprint, reason: reason)
    }

    /// Sets the same usage state on multiple fingerprints atomically.
    public func setUsageState(
        _ state: KeyUsageState,
        forFingerprints fingerprints: [String],
        reason: String? = nil
    ) throws {
        try keyStateStore.setState(state, forFingerprints: fingerprints, reason: reason)
    }

    /// All keys whose usage state is `.active` (default for any key not in
    /// the store).
    public func activeKeys() throws -> [KeyInfo] {
        try listKeys().filter { usageState(forFingerprint: $0.fingerprint) == .active }
    }

    /// All keys whose usage state is `.archived`.
    public func archivedKeys() throws -> [KeyInfo] {
        try listKeys().filter { usageState(forFingerprint: $0.fingerprint) == .archived }
    }

    /// Removes the state record for a fingerprint. Used by "delete forever"
    /// after the key has been removed from the keyring.
    public func removeUsageRecord(forFingerprint fingerprint: String) throws {
        try keyStateStore.removeRecord(forFingerprint: fingerprint)
    }
}

/// Auto-archive hook for `KeyLifecycle.revoke(...)` paths. Call after the
/// revoke succeeds; pass the same reason code so the archive record carries
/// provenance. Separated from the revoke call itself so existing callers
/// don't need to change.
public extension KeyringStore {
    /// Records the post-revoke usage state for a key. When the revocation
    /// reason is `superseded`, the key is auto-archived (decrypt-only) so
    /// historical mail remains readable. Other revocation reasons are also
    /// auto-archived by default — the key cannot be used for new mail
    /// anyway, but its secret material is needed for old mail.
    func applyPostRevokeUsageState(
        fingerprint: String,
        revocationReason codeString: String
    ) throws {
        let reason = "auto-archived after revoke (\(codeString))"
        try setUsageState(.archived, forFingerprint: fingerprint, reason: reason)
    }
}

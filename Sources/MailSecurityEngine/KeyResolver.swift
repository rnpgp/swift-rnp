//
//  KeyResolver.swift
//  swift-rnp
//
//  Read-only key lookup and recipient resolution layered on top of
//  `KeyringStore`. A KeyResolver holds a reference to a KeyringStore and
//  acquires its lock internally — callers do not need to.
//
//  Splitting lookup from persistence lets callers depend on the narrow
//  resolver surface (UI, compose diagnostics) without dragging in the
//  mutating CRUD/generation/foreign-passphrase API. Crypto call sites
//  that need the live `Rnp` context still use `KeyringStore.withRnp`.
//

import Foundation
import KeyStateStore
import Rnp

/// Read-only key lookup and recipient resolution over a `KeyringStore`.
///
/// All methods acquire the store's lock internally; callers do not need to
/// hold it. The `...Unlocked` variants are provided for callers that are
/// already inside `KeyringStore.withRnp` (typically the engine's encode /
/// decode paths) so they can avoid re-entrant locking.
public final class KeyResolver {
    /// The backing persistence module.
    public let keyringStore: KeyringStore

    public init(keyringStore: KeyringStore) {
        self.keyringStore = keyringStore
    }

    // MARK: - Public lookup

    /// Finds a public key for a recipient identifier.
    ///
    /// The identifier may be a full user ID ("Alice <alice@example.com>") or
    /// a bare email address; email matching against the `<...>` part of
    /// stored user IDs is case-insensitive.
    public func publicKey(for identifier: String) throws -> RnpKey? {
        try keyringStore.withRnp { try publicKeyUnlocked(for: identifier, rnp: $0) }
    }

    /// Finds a key with secret material for a sender identifier (see
    /// `publicKey(for:)` for the matching rules).
    public func secretKey(forUserID identifier: String) throws -> RnpKey? {
        try keyringStore.withRnp { rnp in
            guard let key = try publicKeyUnlocked(for: identifier, rnp: rnp),
                  try key.hasSecret
            else {
                return nil
            }
            return key
        }
    }

    /// Selects the active secret key for `userID` (email or full UID),
    /// skipping any key whose usage state is `.archived`. Returns `nil`
    /// when no eligible key exists.
    public func activeSigningKey(forUserID userID: String) throws -> RnpKey? {
        try keyringStore.withRnp { rnp in
            guard let key = try rnp.locateKey(userID) else {
                return nil as RnpKey?
            }
            let fpr = try key.fingerprint
            guard keyringStore.usageState(forFingerprint: fpr) == .active else {
                return nil as RnpKey?
            }
            return key
        }
    }

    /// Resolves recipient addresses to active keys, distinguishing "no
    /// key at all" from "only an archived key." The encode pipeline uses
    /// this to surface distinct UX for the two cases.
    public func resolveActiveRecipients(
        addresses: [String]
    ) throws -> RecipientResolution {
        try keyringStore.withRnp { rnp in
            var resolved: [String: KeyInfo] = [:]
            var missing: [String] = []
            var archivedOnly: [String] = []
            for address in addresses {
                guard let key = try rnp.locateKey(address) else {
                    missing.append(address)
                    continue
                }
                let fpr = try key.fingerprint
                if keyringStore.usageState(forFingerprint: fpr) != .active {
                    archivedOnly.append(address)
                    continue
                }
                if let info = try? keyringStore.makeKeyInfo(key: key, primaryUserID: address) {
                    resolved[address] = info
                } else {
                    missing.append(address)
                }
            }
            return RecipientResolution(resolved: resolved, missing: missing, archivedOnly: archivedOnly)
        }
    }

    // MARK: - Lock-free variants for callers already inside withRnp

    /// Lock-free variant of `publicKey(for:)` for callers already holding
    /// the store lock (i.e. inside `KeyringStore.withRnp`).
    public func publicKeyUnlocked(for identifier: String, rnp: Rnp) throws -> RnpKey? {
        if let key = try rnp.locateKey(identifier) {
            return key
        }
        let email = KeyringStore.emailAddress(from: identifier) ?? identifier
        for userID in try rnp.allUserIDs() {
            let matches = userID.caseInsensitiveCompare(identifier) == .orderedSame
                || KeyringStore.emailAddress(from: userID)?.caseInsensitiveCompare(email) == .orderedSame
            if matches {
                return try rnp.locateKey(userID)
            }
        }
        return nil
    }

    /// Lock-free variant of `secretKey(forUserID:)` for callers already
    /// holding the store lock.
    public func secretKeyUnlocked(forUserID identifier: String, rnp: Rnp) throws -> RnpKey? {
        guard let key = try publicKeyUnlocked(for: identifier, rnp: rnp),
              try key.hasSecret
        else {
            return nil
        }
        return key
    }
}

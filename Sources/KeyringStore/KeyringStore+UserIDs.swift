//
//  KeyringStore+UserIDs.swift
//  MailSecurityEngine
//
//  Engine-layer convenience for adding user IDs to existing secret keys.
//  Wraps the librnp FFI call (RnpKey.addUserID) with persistence and a
//  returned KeyInfo snapshot so the UI gets the updated state without a
//  separate listKeys() round-trip.
//

import Foundation
import Librnp

public extension KeyringStore {
    /// Adds a user ID to the secret key with the given fingerprint and
    /// persists the keyrings.
    ///
    /// - Parameters:
    ///   - uid: full user ID string, e.g., `"Alex Wong <alex@personal.com>"`.
    ///   - fingerprint: the primary key fingerprint to add the UID to.
    ///   - primary: when `true`, the new UID is marked as primary on the key.
    ///   - hash: hash algorithm for the self-signature. `nil` = default.
    /// - Returns: updated `KeyInfo` snapshot for the key.
    @discardableResult
    func addUserID(
        _ uid: String,
        toKeyWithFingerprint fingerprint: String,
        primary: Bool = false,
        hash: String? = "SHA256"
    ) throws -> KeyInfo {
        try withRnp { rnp in
            let key = try rnp.requireKey(fingerprint, type: .fingerprint)
            try key.addUserID(uid, hash: hash, primary: primary)
            try persist(rnp)
            let primaryUserID = (try? key.primaryUserID) ?? uid
            return try makeKeyInfo(key: key, primaryUserID: primaryUserID)
        }
    }
}

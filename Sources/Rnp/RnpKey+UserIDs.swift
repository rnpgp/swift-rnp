//
//  RnpKey+UserIDs.swift
//  Rnp
//
//  Multi-UID API for OpenPGP keys. Wraps `rnp_key_add_uid` for adding
//  user IDs to existing secret keys. Setting a different UID as primary
//  is done at add-time via the `primary` parameter; for already-existing
//  UIDs, the primary-UID flag lives on the UID's self-signature and is
//  changed via `rnp_key_signature_set_primary_uid` (covered separately
//  by the transition-signature API in `05-key-transition-wizard`).
//

import CRnp
import Foundation

/// Key usage flags as defined by RFC 4880 §5.2.3.21. Used by `addUID`
/// to declare what the new UID's self-signature permits. Zero means
/// "no special handling" — the key's existing flags apply.
public struct UserIDKeyFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// This UID may be used to certify other keys.
    public static let certify = UserIDKeyFlags(rawValue: 0x01)
    /// This UID may be used to sign data.
    public static let sign = UserIDKeyFlags(rawValue: 0x02)
    /// This UID may be used for encryption (communications).
    public static let encryptCommunications = UserIDKeyFlags(rawValue: 0x04)
    /// This UID may be used for encryption (storage).
    public static let encryptStorage = UserIDKeyFlags(rawValue: 0x08)
    /// No special handling; inherit the key's existing usage.
    public static let none: UserIDKeyFlags = []
}

public extension RnpKey {
    /// Adds a user ID to this secret key, self-signing it with the primary.
    ///
    /// Wraps `rnp_key_add_uid` (`Sources/CRnp/rnp/rnp.h:2501`). Requires
    /// the key's secret material to be unlocked; librnp will prompt for
    /// the passphrase via the configured provider otherwise.
    ///
    /// - Parameters:
    ///   - uid: full user ID string, e.g., `"Alex Wong <alex@personal.com>"`.
    ///   - hash: hash algorithm for the self-signature (`"SHA256"`,
    ///     `"SHA384"`, `"SHA512"`). `nil` picks the librnp default.
    ///   - expirationSeconds: seconds until this UID's self-signature
    ///     expires. `0` for no expiry.
    ///   - flags: usage flags for this UID. `.none` to inherit defaults.
    ///   - primary: when `true`, this UID becomes the primary UID on the
    ///     key, demoting any previous primary. librnp handles the
    ///     self-signature subpacket update.
    func addUserID(
        _ uid: String,
        hash: String? = nil,
        expirationSeconds: UInt32 = 0,
        flags: UserIDKeyFlags = .none,
        primary: Bool = false
    ) throws {
        try uid.withCString { uidC in
            if let hash {
                try hash.withCString { hashC in
                    try rnpCheck(
                        rnp_key_add_uid(handle, uidC, hashC, expirationSeconds, flags.rawValue, primary),
                        operation: "add user ID"
                    )
                }
            } else {
                try rnpCheck(
                    rnp_key_add_uid(handle, uidC, nil, expirationSeconds, flags.rawValue, primary),
                    operation: "add user ID"
                )
            }
        }
    }
}

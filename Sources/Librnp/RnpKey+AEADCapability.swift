//
//  RnpKey+AEADCapability.swift
//  Rnp
//
//  Detects whether a key advertises AEAD support via the features
//  subpacket in its primary UID's most recent self-certification.
//  Wraps `rnp_signature_get_features` against the UID's self-sig.
//

import CRnp
import Foundation

/// librnp feature flag for MDC (RFC 4880). Always set for modern keys.
private let RNP_KEY_FEATURE_MDC: UInt32 = 1 << 0
/// librnp feature flag for AEAD-OCB (LibrePGP). What we care about here.
private let RNP_KEY_FEATURE_AEAD: UInt32 = 1 << 1
/// librnp feature flag for v5 key format.
private let RNP_KEY_FEATURE_V5: UInt32 = 1 << 2

public extension RnpKey {
    /// True when the key's primary UID self-signature advertises
    /// `RNP_KEY_FEATURE_AEAD`. Conservative: returns `false` on any
    /// error reading the signature (which is rare but possible for
    /// keys with unusual self-sig layouts).
    var supportsAEAD: Bool {
        get throws {
            let uid = try userID(at: 0)
            guard let uid else { return false }
            var count = 0
            try rnpCheck(
                rnp_uid_get_signature_count(uid.handle, &count),
                operation: "uid signature count"
            )
            guard count > 0 else { return false }
            var sigHandle: rnp_signature_handle_t?
            try rnpCheck(
                rnp_uid_get_signature_at(uid.handle, count - 1, &sigHandle),
                operation: "uid signature at"
            )
            guard let sigHandle else { return false }
            defer { rnp_signature_handle_destroy(sigHandle) }
            var features: UInt32 = 0
            try rnpCheck(
                rnp_signature_get_features(sigHandle, &features),
                operation: "signature features"
            )
            return (features & RNP_KEY_FEATURE_AEAD) != 0
        }
    }
}

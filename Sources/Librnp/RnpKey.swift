//
//  RnpKey.swift
//  swift-rnp
//
//  Handle to a key held by an `Rnp` context's keyrings.
//

import CRnp
import Foundation

/// A key located in (or generated into) an `Rnp` context's keyrings.
///
/// Wraps `rnp_key_handle_t`; the handle is released when the instance is
/// deallocated. Instances are obtained via `Rnp.locateKey` / `Rnp.requireKey`.
public final class RnpKey {
    internal let handle: rnp_key_handle_t

    internal init(handle: rnp_key_handle_t) {
        self.handle = handle
    }

    deinit {
        rnp_key_handle_destroy(handle)
    }

    /// Uppercase hexadecimal fingerprint of the key.
    public var fingerprint: String {
        get throws {
            var fprint: UnsafeMutablePointer<CChar>?
            try rnpCheck(rnp_key_get_fprint(handle, &fprint), operation: "key fingerprint")
            return try rnpTakeString(fprint, operation: "key fingerprint")
        }
    }

    /// All user IDs bound to the key.
    public var userIDs: [String] {
        get throws {
            var count = 0
            try rnpCheck(rnp_key_get_uid_count(handle, &count), operation: "key uid count")
            return try (0 ..< count).map { index in
                var uid: UnsafeMutablePointer<CChar>?
                try rnpCheck(rnp_key_get_uid_at(handle, index, &uid), operation: "key uid")
                return try rnpTakeString(uid, operation: "key uid")
            }
        }
    }

    /// The key's primary user ID.
    public var primaryUserID: String {
        get throws {
            var uid: UnsafeMutablePointer<CChar>?
            try rnpCheck(rnp_key_get_primary_uid(handle, &uid), operation: "key primary uid")
            return try rnpTakeString(uid, operation: "key primary uid")
        }
    }

    /// Whether the secret key material is available in the secret keyring.
    public var hasSecret: Bool {
        get throws {
            var result = false
            try rnpCheck(rnp_key_have_secret(handle, &result), operation: "key have secret")
            return result
        }
    }

    /// The key's 8-hex-digit key ID.
    public var keyID: String {
        get throws {
            var id: UnsafeMutablePointer<CChar>?
            try rnpCheck(rnp_key_get_keyid(handle, &id), operation: "key id")
            return try rnpTakeString(id, operation: "key id")
        }
    }

    /// The key's allowed usage flags, e.g. `["sign", "certify"]`.
    ///
    /// Only flags meaningful for the key type are queried; unsupported
    /// combinations are treated as `false` instead of throwing.
    public var capabilities: [String] {
        get throws {
            let allCapabilities = ["sign", "certify", "encrypt", "auth"]
            return allCapabilities.filter { (try? allowsUsage($0)) ?? false }
        }
    }

    private func allowsUsage(_ usage: String) throws -> Bool {
        var result = false
        try rnpCheck(rnp_key_allows_usage(handle, usage, &result), operation: "key allows usage")
        return result
    }

    /// Exports the key (including its subkeys) in OpenPGP format.
    ///
    /// - Parameters:
    ///   - secret: export the secret key material instead of the public part.
    ///   - armored: ASCII-armor the exported data.
    /// - Returns: the exported key data.
    public func exportKey(secret: Bool = false, armored: Bool = true) throws -> Data {
        var flags: UInt32 = RNP_KEY_EXPORT_SUBKEYS
        flags |= secret ? RNP_KEY_EXPORT_SECRET : RNP_KEY_EXPORT_PUBLIC
        if armored {
            flags |= RNP_KEY_EXPORT_ARMORED
        }
        let output = try MemoryOutput()
        try rnpCheck(rnp_key_export(handle, output.handle, flags), operation: "key export")
        return try output.readData()
    }

    // MARK: - Metadata

    /// The key's algorithm name, e.g. "RSA" or "ECDSA".
    public var algorithm: String {
        get throws {
            var alg: UnsafeMutablePointer<CChar>?
            try rnpCheck(rnp_key_get_alg(handle, &alg), operation: "key algorithm")
            return try rnpTakeString(alg, operation: "key algorithm")
        }
    }

    /// The number of bits in the key (or the curve size for EC-based keys).
    public var bits: Int {
        get throws {
            var value: UInt32 = 0
            try rnpCheck(rnp_key_get_bits(handle, &value), operation: "key bits")
            return Int(value)
        }
    }

    /// The curve name for EC-based keys, e.g. "NIST P-256"; `nil` for RSA/DSA.
    public var curve: String? {
        get throws {
            var curve: UnsafeMutablePointer<CChar>?
            let status = rnp_key_get_curve(handle, &curve)
            guard status == rnpStatusSuccess else {
                return nil
            }
            return try? rnpTakeString(curve, operation: "key curve")
        }
    }

    /// The key's creation date.
    public var creationDate: Date {
        get throws {
            var seconds: UInt32 = 0
            try rnpCheck(rnp_key_get_creation(handle, &seconds), operation: "key creation")
            return Date(timeIntervalSince1970: TimeInterval(seconds))
        }
    }

    /// The key's expiration time in seconds from creation, or `0` if it does not expire.
    public var expirationSeconds: UInt32 {
        get throws {
            var value: UInt32 = 0
            try rnpCheck(rnp_key_get_expiration(handle, &value), operation: "key expiration")
            return value
        }
    }

    /// Sets the key's expiration time in seconds from creation.
    ///
    /// Pass `0` to make the key not expire. Re-signing requires the secret
    /// primary key, so the passphrase provider may be invoked.
    public func setExpirationSeconds(_ value: UInt32) throws {
        try rnpCheck(rnp_key_set_expiration(handle, value), operation: "set key expiration")
    }

    /// The timestamp until which the key is considered valid, taking into account
    /// expiration and revocation.
    public var validTill: Date {
        get throws {
            var seconds: UInt64 = 0
            try rnpCheck(rnp_key_valid_till64(handle, &seconds), operation: "key valid till")
            return Date(timeIntervalSince1970: TimeInterval(seconds))
        }
    }

    /// Whether the key has been revoked.
    public var isRevoked: Bool {
        get throws {
            var result = false
            try rnpCheck(rnp_key_is_revoked(handle, &result), operation: "key is revoked")
            return result
        }
    }

    /// Whether the key is expired (its validity period has ended).
    public var isExpired: Bool {
        get throws {
            try validTill < Date()
        }
    }

    /// Human-readable revocation reason, if the key is revoked.
    public var revocationReason: String? {
        get throws {
            var reason: UnsafeMutablePointer<CChar>?
            let status = rnp_key_get_revocation_reason(handle, &reason)
            guard status == rnpStatusSuccess, reason != nil else {
                return nil
            }
            return try rnpTakeString(reason, operation: "key revocation reason")
        }
    }

    /// The key's subkeys.
    public var subkeys: [RnpKey] {
        get throws {
            var count = 0
            try rnpCheck(rnp_key_get_subkey_count(handle, &count), operation: "subkey count")
            return try (0 ..< count).map { index in
                var subkey: rnp_key_handle_t?
                try rnpCheck(
                    rnp_key_get_subkey_at(handle, index, &subkey),
                    operation: "subkey at index \(index)"
                )
                guard let subkey else {
                    throw RnpError.ffiFailed(
                        operation: "subkey at index \(index)",
                        code: rnpStatusSuccess,
                        message: "unexpected NULL subkey handle"
                    )
                }
                return RnpKey(handle: subkey)
            }
        }
    }

    // MARK: - Protection

    /// Whether the key's secret material is passphrase-protected.
    public var isProtected: Bool {
        get throws {
            var result = false
            try rnpCheck(rnp_key_is_protected(handle, &result), operation: "key is protected")
            return result
        }
    }

    /// Attempts to unlock the key's secret material with `password`.
    ///
    /// Succeeds without a password check for unprotected keys (unlocking is
    /// a no-op for them, per librnp semantics).
    ///
    /// - Returns: `true` when the password decrypted the secret material,
    ///   `false` when it did not (librnp reports a bad password).
    public func unlock(password: String) -> Bool {
        rnp_key_unlock(handle, password) == rnpStatusSuccess
    }

    /// Re-protects the key's secret material with `password`.
    ///
    /// The key must be unlocked first (see `unlock(password:)`); librnp's
    /// default cipher/hash and iteration count are used.
    public func protect(password: String) throws {
        try rnpCheck(
            rnp_key_protect(handle, password, nil, nil, nil, 0),
            operation: "key protect"
        )
    }

    // MARK: - Lifecycle

    /// Revokes the key, adding a revocation signature to the keyring.
    ///
    /// - Parameters:
    ///   - code: revocation reason code (`no`, `superseded`, `compromised`, `retired`).
    ///   - reason: optional free-form revocation reason text.
    ///   - hash: hash algorithm used for the revocation signature; `nil` selects the default.
    public func revoke(
        code: RevocationCode = .noReason,
        reason: String = "",
        hash: String? = nil
    ) throws {
        let codeString = code.rawValue
        let reasonString = reason.isEmpty ? nil : reason
        let hashString = hash
        try rnpCheck(
            rnp_key_revoke(
                handle,
                0,
                hashString,
                codeString,
                reasonString
            ),
            operation: "key revoke"
        )
    }

    /// Exports an armored revocation signature for this key.
    ///
    /// - Parameters:
    ///   - code: revocation reason code.
    ///   - reason: optional free-form revocation reason text.
    ///   - hash: hash algorithm used for the revocation signature; `nil` selects the default.
    /// - Returns: the armored revocation signature.
    public func exportRevocation(
        code: RevocationCode = .noReason,
        reason: String = "",
        hash: String? = nil
    ) throws -> Data {
        let output = try MemoryOutput()
        let codeString = code.rawValue
        let reasonString = reason.isEmpty ? nil : reason
        try rnpCheck(
            rnp_key_export_revocation(
                handle,
                output.handle,
                RNP_KEY_EXPORT_ARMORED,
                hash,
                codeString,
                reasonString
            ),
            operation: "export revocation"
        )
        return try output.readData()
    }
}

/// Reason codes for key revocation.
public enum RevocationCode: String {
    /// No reason specified.
    case noReason = "no"
    /// The key has been superseded.
    case superseded = "superseded"
    /// The key material has been compromised.
    case compromised = "compromised"
    /// The key is no longer used.
    case retired = "retired"
}

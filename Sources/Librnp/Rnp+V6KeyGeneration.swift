//
//  Rnp+V6KeyGeneration.swift
//  Rnp
//
//  Operation-based primary key generation that supports v6 keys.
//  The existing JSON-based `generateKey(json:)` path does not expose
//  the `"version"` member, so callers that want v6 (required for some
//  PQ algorithms and for SEIPDv2-by-default) must use this path.
//

import CRnp
import Foundation

public extension Rnp {
    /// Generates a primary key with optional v6 flag, returning the
    /// key handle. Used by the engine when the user opts into v6 in
    /// Settings → Encryption.
    ///
    /// - Parameters:
    ///   - algorithm: librnp algorithm string (e.g., "EDDSA",
    ///     "ML-DSA-65+ED25519").
    ///   - userID: user ID for the primary.
    ///   - hash: hash algorithm.
    ///   - expirationSeconds: 0 for no expiry.
    ///   - useV6Key: when `true`, calls `rnp_op_generate_set_v6_key`.
    func generatePrimaryKey(
        algorithm: String,
        userID: String,
        hash: String = "SHA256",
        expirationSeconds: UInt32 = 0,
        useV6Key: Bool = false
    ) throws -> RnpKey {
        var op: rnp_op_generate_t?
        try rnpCheck(
            rnp_op_generate_create(&op, ffi, algorithm),
            operation: "primary key generation create"
        )
        guard let operation = op else {
            throw RnpError.ffiFailed(
                operation: "primary key generation create",
                code: rnpStatusSuccess,
                message: "unexpected NULL generation operation"
            )
        }
        defer { rnp_op_generate_destroy(operation) }

        try userID.withCString { uidC in
            try rnpCheck(rnp_op_generate_set_userid(operation, uidC), operation: "primary set userid")
        }
        try rnpCheck(rnp_op_generate_set_hash(operation, hash), operation: "primary set hash")
        try rnpCheck(
            rnp_op_generate_set_expiration(operation, expirationSeconds),
            operation: "primary set expiration"
        )

        if useV6Key, let fn = ExperimentalSymbolTable.setV6Key {
            try rnpCheck(fn(operation), operation: "primary set v6 key")
        }

        guard let password = keyedPassphraseProvider("protect", nil) else {
            throw RnpError.invalidArgument("passphrase provider returned nil for primary protection")
        }
        try rnpCheck(
            rnp_op_generate_set_protection_password(operation, password),
            operation: "primary set protection password"
        )

        try rnpCheck(rnp_op_generate_execute(operation), operation: "primary generation execute")

        var handle: rnp_key_handle_t?
        try rnpCheck(rnp_op_generate_get_key(operation, &handle), operation: "primary get key")
        guard let handle else {
            throw RnpError.ffiFailed(
                operation: "primary get key",
                code: rnpStatusSuccess,
                message: "unexpected NULL primary key handle"
            )
        }
        return RnpKey(handle: handle)
    }
}

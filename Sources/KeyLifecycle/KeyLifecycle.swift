//
//  KeyLifecycle.swift
//  swift-rnp
//
//  High-level key lifecycle operations: rotation, expiry extension, and
//  revocation. Built on top of MailSecurityEngine.KeyManager and the Rnp
//  wrapper.
//

import Foundation
import MailSecurityEngine
import Rnp

/// Summary returned after a subkey rotation.
public struct RotationSummary: Equatable {
    /// Fingerprint of the primary key.
    public let primaryFingerprint: String
    /// Fingerprint of the newly generated subkey.
    public let newSubkeyFingerprint: String
    /// Fingerprint of the subkey whose expiry was shortened to the grace period.
    public let retiredSubkeyFingerprint: String?
    /// Human-readable description of what changed.
    public let message: String

    public init(
        primaryFingerprint: String,
        newSubkeyFingerprint: String,
        retiredSubkeyFingerprint: String?,
        message: String
    ) {
        self.primaryFingerprint = primaryFingerprint
        self.newSubkeyFingerprint = newSubkeyFingerprint
        self.retiredSubkeyFingerprint = retiredSubkeyFingerprint
        self.message = message
    }
}

/// Describes one key or subkey that is expired or expiring soon.
public struct KeyExpiryItem: Equatable, Identifiable {
    public enum Kind: Equatable {
        case primary
        case subkey(parentFingerprint: String)
    }

    /// The fingerprint of the key or subkey.
    public let fingerprint: String
    /// The primary user ID associated with the key.
    public let userID: String
    /// Whether this is the primary key or a subkey.
    public let kind: Kind
    /// The expiration date, if any.
    public let expirationDate: Date?
    /// Whether the key is already expired.
    public let isExpired: Bool

    public init(
        fingerprint: String,
        userID: String,
        kind: Kind,
        expirationDate: Date?,
        isExpired: Bool
    ) {
        self.fingerprint = fingerprint
        self.userID = userID
        self.kind = kind
        self.expirationDate = expirationDate
        self.isExpired = isExpired
    }

    public var id: String { fingerprint }
}

/// Lifecycle configuration constants.
public enum KeyLifecycleConfiguration {
    /// Grace period given to a retired encryption/signing subkey before it
    /// expires, in seconds (30 days).
    public static let rotationGraceSeconds: UInt32 = 30 * 24 * 60 * 60

    /// Threshold for reporting an upcoming expiry, in seconds (60 days).
    public static let expiryWarningThresholdSeconds: TimeInterval = 60 * 24 * 60 * 60

    /// Default hash used for new self-signatures.
    public static let defaultHash = "SHA256"
}

/// Errors thrown by `KeyLifecycle`.
public enum KeyLifecycleError: Error, Equatable {
    case keyNotFound(String)
    case noSubkeyToRotate(String)
    case unsupportedPrimaryAlgorithm(String)
    case invalidExpiryDate
}

extension KeyLifecycleError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .keyNotFound(let fingerprint):
            return "Key \(fingerprint) was not found in the keyring."
        case .noSubkeyToRotate(let fingerprint):
            return "Key \(fingerprint) has no subkey that can be rotated."
        case .unsupportedPrimaryAlgorithm(let algorithm):
            return "Rotating subkeys for \(algorithm) primary keys is not supported."
        case .invalidExpiryDate:
            return "The new expiry date must be in the future."
        }
    }
}

/// High-level key lifecycle operations.
public final class KeyLifecycle {
    private let keyManager: KeyManager

    public init(keyManager: KeyManager) {
        self.keyManager = keyManager
    }

    // MARK: - Rotation

    /// Rotates the encryption subkey for the key with the given fingerprint.
    ///
    /// A new encryption subkey is generated (matching the primary key's
    /// algorithm family) and the previous encryption subkey is set to expire
    /// after the configured grace period.
    @discardableResult
    public func rotateEncryptionSubkey(for fingerprint: String) throws -> RotationSummary {
        try rotateSubkey(for: fingerprint, usage: "encrypt")
    }

    /// Rotates the signing subkey for the key with the given fingerprint.
    @discardableResult
    public func rotateSigningSubkey(for fingerprint: String) throws -> RotationSummary {
        try rotateSubkey(for: fingerprint, usage: "sign")
    }

    private func rotateSubkey(for fingerprint: String, usage: String) throws -> RotationSummary {
        try keyManager.withRnp { rnp in
            let primary = try rnp.requireKey(fingerprint, type: .fingerprint)
            let primaryFPR = try primary.fingerprint
            let primaryAlg = try primary.algorithm

            guard let spec = SubkeySpec.matching(primaryAlgorithm: primaryAlg, usage: usage) else {
                throw KeyLifecycleError.unsupportedPrimaryAlgorithm(primaryAlg)
            }

            let now = Date()
            let grace = TimeInterval(KeyLifecycleConfiguration.rotationGraceSeconds)

            // Find the currently valid subkey with the requested usage.
            let candidate = try primary.subkeys.first { subkey in
                try subkey.capabilities.contains(usage)
                    && !(try subkey.isRevoked)
                    && (try subkey.validTill) > now
            }

            // Generate the replacement subkey with the same expiration as the primary.
            let primaryExpiration = try primary.expirationSeconds
            let newSubkey = try rnp.generateSubkey(
                for: primary,
                algorithm: spec.algorithm,
                bits: spec.bits,
                curve: spec.curve,
                hash: KeyLifecycleConfiguration.defaultHash,
                usage: [usage],
                expirationSeconds: primaryExpiration
            )
            let newSubkeyFPR = try newSubkey.fingerprint

            // Retire the old subkey by setting its expiry to now + grace.
            var retiredFPR: String?
            if let old = candidate {
                let creation = try old.creationDate
                let retireExpiry = UInt32(max(0, now.timeIntervalSince1970 + grace - creation.timeIntervalSince1970))
                try old.setExpirationSeconds(retireExpiry)
                retiredFPR = try old.fingerprint
            }

            try keyManager.save()

            let message = usage == "encrypt"
                ? "A new encryption subkey was generated. Old messages remain decryptable for 30 days."
                : "A new signing subkey was generated. Recipients should refresh your public key."

            return RotationSummary(
                primaryFingerprint: primaryFPR,
                newSubkeyFingerprint: newSubkeyFPR,
                retiredSubkeyFingerprint: retiredFPR,
                message: message
            )
        }
    }

    // MARK: - Expiry extension

    /// Extends the primary key's and all its subkeys' expiration to `newDate`.
    ///
    /// The date is converted to seconds from each key's original creation
    /// time, which is how OpenPGP stores expiration. Subkeys carry their own
    /// self-signatures, so each one is re-signed too — otherwise an expired
    /// encryption subkey would not be rescued, matching the behavior of
    /// `KeyManager.generateKey`.
    public func extendExpiry(for fingerprint: String, newDate: Date) throws {
        guard newDate > Date() else {
            throw KeyLifecycleError.invalidExpiryDate
        }

        try keyManager.withRnp { rnp in
            let key = try rnp.requireKey(fingerprint, type: .fingerprint)
            let creation = try key.creationDate
            let expirySeconds = UInt32(max(0, newDate.timeIntervalSince1970 - creation.timeIntervalSince1970))
            try key.setExpirationSeconds(expirySeconds)
            for subkey in try key.subkeys {
                let subkeyCreation = try subkey.creationDate
                let subkeyExpirySeconds = UInt32(max(0, newDate.timeIntervalSince1970 - subkeyCreation.timeIntervalSince1970))
                try subkey.setExpirationSeconds(subkeyExpirySeconds)
            }
            try keyManager.save()
        }
    }

    // MARK: - Revocation

    /// Revokes the key and returns an armored revocation certificate.
    public func revoke(
        for fingerprint: String,
        code: RevocationCode = .noReason,
        reason: String = ""
    ) throws -> Data {
        try keyManager.withRnp { rnp in
            let key = try rnp.requireKey(fingerprint, type: .fingerprint)
            try key.revoke(code: code, reason: reason)
            let certificate = try key.exportRevocation()
            try keyManager.save()
            return certificate
        }
    }

    // MARK: - Expiry report

    /// Returns all primary keys and subkeys that are expired or will expire
    /// within the configured warning threshold.
    public func expiryReport() throws -> [KeyExpiryItem] {
        let threshold = KeyLifecycleConfiguration.expiryWarningThresholdSeconds
        let now = Date()
        var items: [KeyExpiryItem] = []

        for key in try keyManager.listKeys() {
            let userID = key.primaryUserID
            if let expiration = key.expirationDate,
               expiration < now.addingTimeInterval(threshold) {
                items.append(KeyExpiryItem(
                    fingerprint: key.fingerprint,
                    userID: userID,
                    kind: .primary,
                    expirationDate: expiration,
                    isExpired: expiration < now
                ))
            }

            let subkeys = try keyManager.subkeys(for: key.fingerprint)
            for subkey in subkeys {
                if let expiration = subkey.expirationDate,
                   expiration < now.addingTimeInterval(threshold) {
                    items.append(KeyExpiryItem(
                        fingerprint: subkey.fingerprint,
                        userID: userID,
                        kind: .subkey(parentFingerprint: key.fingerprint),
                        expirationDate: expiration,
                        isExpired: expiration < now
                    ))
                }
            }
        }

        return items
    }
}

// MARK: - Subkey algorithm matching

private struct SubkeySpec {
    let algorithm: String
    let bits: UInt32?
    let curve: String?

    static func matching(primaryAlgorithm: String, usage: String) -> SubkeySpec? {
        let upper = primaryAlgorithm.uppercased()
        if upper.contains("RSA") {
            return SubkeySpec(algorithm: "RSA", bits: 3072, curve: nil)
        }
        if upper.contains("ECDSA") {
            return usage == "encrypt"
                ? SubkeySpec(algorithm: "ECDH", bits: nil, curve: "NIST P-256")
                : SubkeySpec(algorithm: "ECDSA", bits: nil, curve: "NIST P-256")
        }
        if upper.contains("EDDSA") || upper.contains("ED25519") {
            return usage == "encrypt"
                ? SubkeySpec(algorithm: "ECDH", bits: nil, curve: "Curve25519")
                : SubkeySpec(algorithm: "EDDSA", bits: nil, curve: nil)
        }
        return nil
    }
}

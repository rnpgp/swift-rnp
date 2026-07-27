//
//  KeyManager+V6KeyGeneration.swift
//  MailSecurityEngine
//
//  Engine-layer opt-in for v6 primary-key generation. v6 keys are
//  required for some PQ algorithms and for SEIPDv2 by default.
//

import Foundation
import Rnp

public extension KeyManager {
    /// Generates a v6 primary keypair with a matching encryption subkey
    /// and persists the keyrings.
    ///
    /// - Parameters:
    ///   - userID: user ID for the primary.
    ///   - algorithm: classical or hybrid algorithm for the primary.
    ///   - hash: hash algorithm.
    ///   - expirationSeconds: 0 for no expiry.
    /// - Returns: snapshot of the new key.
    @discardableResult
    func generateV6Key(
        userID: String,
        algorithm: KeyAlgorithm = .ed25519,
        hash: String = "SHA256",
        expirationSeconds: UInt32 = 0
    ) throws -> KeyInfo {
        try withRnp { rnp in
            let primaryAlgo: String
            switch algorithm {
            case .rsa: primaryAlgo = "RSA"
            case .ecdsa: primaryAlgo = "ECDSA"
            case .ed25519: primaryAlgo = "EDDSA"
            case .hybridPQ: primaryAlgo = "ML-DSA-65+ED25519"
            case .conservativePQ: primaryAlgo = "SLH-DSA-SHA2"
            }
            let key = try rnp.generatePrimaryKey(
                algorithm: primaryAlgo,
                userID: userID,
                hash: hash,
                expirationSeconds: expirationSeconds,
                useV6Key: true
            )
            if expirationSeconds > 0 {
                try key.setExpirationSeconds(expirationSeconds)
            }
            let info = try makeKeyInfo(key: key, primaryUserID: userID)
            try persist(rnp)
            return info
        }
    }
}

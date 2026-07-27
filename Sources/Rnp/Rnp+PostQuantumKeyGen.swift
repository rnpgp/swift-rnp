//
//  Rnp+PostQuantumKeyGen.swift
//  Rnp
//
//  JSON templates for post-quantum hybrid key generation. Mirrors the
//  shape of `rsaKeyGenJSON`, `ecdsaP256KeyGenJSON`, and
//  `ed25519KeyGenJSON`. The algorithm strings come from
//  `Sources/CRnp/rnp/rnp.h:4122–4135` (also catalogued in
//  `PostQuantum/PostQuantumAlgorithm.swift`).
//
//  Open-point: librnp's JSON keygen accepts the hybrid algorithm names
//  as the primary/sub `type`. This file uses the most-recommended
//  defaults (`ML-DSA-65+ED25519` primary, `ML-KEM-768+X25519` sub).
//  Conservative SLH-DSA-only generation is also templated.
//

import Foundation

public extension Rnp {
    /// Hybrid PQ primary (ML-DSA-65+ED25519) with hybrid PQ encryption
    /// subkey (ML-KEM-768+X25519). Recommended for long-term
    /// confidentiality; both halves are classical+PQ.
    static func hybridPQKeyGenJSON(userid: String, expirationSeconds: UInt32 = 0) -> String {
        """
        {
            "primary": {
                "type": "ML-DSA-65+ED25519",
                "userid": "\(userid)",
                "usage": ["sign"],
                "expiration": \(expirationSeconds),
                "protection": { "cipher": "AES256", "hash": "SHA256" }
            },
            "sub": {
                "type": "ML-KEM-768+X25519",
                "usage": ["encrypt"],
                "expiration": \(expirationSeconds),
                "protection": { "cipher": "AES256", "hash": "SHA256" }
            }
        }
        """
    }

    /// Conservative hash-based PQ primary (SLH-DSA-SHA2) with classical
    /// ECDH-Curve25519 encryption subkey. For users who explicitly
    /// distrust lattice-based cryptography. Large signatures.
    static func conservativePQKeyGenJSON(userid: String, expirationSeconds: UInt32 = 0) -> String {
        """
        {
            "primary": {
                "type": "SLH-DSA-SHA2",
                "userid": "\(userid)",
                "usage": ["sign"],
                "expiration": \(expirationSeconds),
                "protection": { "cipher": "AES256", "hash": "SHA256" }
            },
            "sub": {
                "type": "ECDH",
                "curve": "Curve25519",
                "usage": ["encrypt"],
                "expiration": \(expirationSeconds),
                "protection": { "cipher": "AES256", "hash": "SHA256" }
            }
        }
        """
    }
}

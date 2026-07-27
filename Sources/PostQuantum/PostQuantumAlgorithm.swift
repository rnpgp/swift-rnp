//
//  PostQuantumAlgorithm.swift
//  PostQuantum
//
//  Catalog of the post-quantum algorithms exposed by librnp, verified
//  against `Sources/CRnp/rnp/rnp.h:4122–4135`. The string values match
//  what `rnp_op_generate_set` and the key algorithm fields expect.
//
//  librnp exposes only classical+PQ hybrids (not PQ-only KEM); this
//  module mirrors that policy: there is no pure-PQ encryption algorithm
//  in the catalog, only pure-PQ signature algorithms (SLH-DSA).
//

import Foundation

/// Hybrid post-quantum key-encapsulation (encryption) algorithms exposed
/// by librnp. Each pairs a classical KEM with ML-KEM (FIPS 203).
public enum PostQuantumKEMAlgorithm: String, CaseIterable, Sendable {
    /// Recommended default. The same hybrid TLS uses (X25519 + ML-KEM-768).
    case mlKem768X25519 = "ML-KEM-768+X25519"
    case mlKem1024X448 = "ML-KEM-1024+X448"
    case mlKem768P256 = "ML-KEM-768+ECDH-P256"
    case mlKem1024P384 = "ML-KEM-1024+ECDH-P384"
    case mlKem768BP256 = "ML-KEM-768+ECDH-BP256"
    case mlKem1024BP384 = "ML-KEM-1024+ECDH-BP384"
}

/// Hybrid post-quantum signature algorithms exposed by librnp. Each pairs
/// a classical signing algorithm with ML-DSA (FIPS 204).
public enum PostQuantumSigningAlgorithm: String, CaseIterable, Sendable {
    /// Recommended default for new keys.
    case mlDsa65Ed25519 = "ML-DSA-65+ED25519"
    case mlDsa87Ed448 = "ML-DSA-87+ED448"
    case mlDsa65P256 = "ML-DSA-65+ECDSA-P256"
    case mlDsa87P384 = "ML-DSA-87+ECDSA-P384"
    case mlDsa65BP256 = "ML-DSA-65+ECDSA-BP256"
    case mlDsa87BP384 = "ML-DSA-87+ECDSA-BP384"
}

/// Conservative hash-based PQ signature algorithms (no lattice
/// assumptions). Very large signatures; suitable for users who want to
/// hedge against lattice-based breaks.
public enum PostQuantumConservativeSigningAlgorithm: String, CaseIterable, Sendable {
    case slhDsaSha2 = "SLH-DSA-SHA2"
    case slhDsaShake = "SLH-DSA-SHAKE"
}

/// Top-level policy: what class of cryptographic algorithm the engine
/// should use when generating new keys.
public enum PostQuantumPolicy: String, CaseIterable, Sendable {
    /// Default. Classical algorithms (Ed25519, RSA-3072, ECDSA P-256).
    /// Recipients still receive hybrid encryption when their key
    /// advertises a hybrid KEM subkey — that happens automatically inside
    /// librnp's encrypt op, independent of this policy.
    case classical

    /// Hybrid classical+PQ key generation. New primary keys use
    /// `ML-DSA-65+ED25519`; new encryption subkeys use
    /// `ML-KEM-768+X25519`. Larger keys, slightly slower, maximum
    /// long-term confidentiality.
    case hybrid

    /// PQ-only signatures (`SLH-DSA-SHA2`) with classical encryption
    /// subkeys. Signatures are PQ-secure; encryption is classical-only
    /// because librnp does not expose a PQ-only KEM. For users who
    /// distrust lattice-based cryptography.
    case conservative
}

/// Default algorithm pairing for each policy, used by the engine when
/// generating keys. Kept here (not in `MailSecurityEngine`) so the
/// algorithm catalog has one authoritative home.
public extension PostQuantumPolicy {
    /// Signing algorithm for this policy; `nil` for classical (the
    /// existing `KeyAlgorithm` enum covers that path).
    var signingAlgorithm: PostQuantumSigningAlgorithm? {
        switch self {
        case .classical: return nil
        case .hybrid: return .mlDsa65Ed25519
        case .conservative: return nil  // conservative uses SLH-DSA, not in this enum
        }
    }

    /// Conservative (SLH-DSA) signing algorithm; non-nil only for the
    /// `.conservative` policy.
    var conservativeSigningAlgorithm: PostQuantumConservativeSigningAlgorithm? {
        switch self {
        case .classical, .hybrid: return nil
        case .conservative: return .slhDsaSha2
        }
    }

    /// Encryption (KEM) algorithm for this policy; `nil` for classical.
    var kemAlgorithm: PostQuantumKEMAlgorithm? {
        switch self {
        case .classical, .conservative: return nil
        case .hybrid: return .mlKem768X25519
        }
    }
}

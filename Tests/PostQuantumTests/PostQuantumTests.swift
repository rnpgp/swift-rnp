//
//  PostQuantumTests.swift
//  PostQuantumTests
//
//  Catalog-level tests. Integration tests (actual key generation with
//  hybrid algorithms, encrypt/decrypt round-trips) live in the engine
//  test target and are gated on librnp availability.
//

import XCTest
@testable import PostQuantum

final class PostQuantumTests: XCTestCase {

    func testKEMCatalogMatchesLibrnpSurface() {
        // Cross-check against the algorithm strings documented in
        // Sources/CRnp/rnp/rnp.h:4122-4127. If librnp adds or removes
        // an algorithm, this test fails — forcing a deliberate update.
        let expected: Set<String> = [
            "ML-KEM-768+X25519",
            "ML-KEM-1024+X448",
            "ML-KEM-768+ECDH-P256",
            "ML-KEM-1024+ECDH-P384",
            "ML-KEM-768+ECDH-BP256",
            "ML-KEM-1024+ECDH-BP384",
        ]
        let actual = Set(PostQuantumKEMAlgorithm.allCases.map(\.rawValue))
        XCTAssertEqual(actual, expected)
    }

    func testSigningCatalogMatchesLibrnpSurface() {
        let expected: Set<String> = [
            "ML-DSA-65+ED25519",
            "ML-DSA-87+ED448",
            "ML-DSA-65+ECDSA-P256",
            "ML-DSA-87+ECDSA-P384",
            "ML-DSA-65+ECDSA-BP256",
            "ML-DSA-87+ECDSA-BP384",
        ]
        let actual = Set(PostQuantumSigningAlgorithm.allCases.map(\.rawValue))
        XCTAssertEqual(actual, expected)
    }

    func testConservativeCatalogMatchesLibrnpSurface() {
        let expected: Set<String> = [
            "SLH-DSA-SHA2",
            "SLH-DSA-SHAKE",
        ]
        let actual = Set(PostQuantumConservativeSigningAlgorithm.allCases.map(\.rawValue))
        XCTAssertEqual(actual, expected)
    }

    func testHybridPolicySelectsRecommendedAlgorithms() {
        XCTAssertEqual(PostQuantumPolicy.hybrid.signingAlgorithm, .mlDsa65Ed25519)
        XCTAssertEqual(PostQuantumPolicy.hybrid.kemAlgorithm, .mlKem768X25519)
    }

    func testClassicalPolicySelectsNoPQAlgorithms() {
        XCTAssertNil(PostQuantumPolicy.classical.signingAlgorithm)
        XCTAssertNil(PostQuantumPolicy.classical.kemAlgorithm)
        XCTAssertNil(PostQuantumPolicy.classical.conservativeSigningAlgorithm)
    }

    func testConservativePolicySelectsSLHDSA() {
        XCTAssertEqual(
            PostQuantumPolicy.conservative.conservativeSigningAlgorithm,
            .slhDsaSha2
        )
        // Conservative still has no PQ KEM because librnp doesn't expose one.
        XCTAssertNil(PostQuantumPolicy.conservative.kemAlgorithm)
        XCTAssertNil(PostQuantumPolicy.conservative.signingAlgorithm)
    }
}

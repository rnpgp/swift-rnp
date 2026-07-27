//
//  KeyStateStoreTests.swift
//  KeyStateStoreTests
//
//  Covers the on-disk signed persistence of per-key usage states and the
//  semantics of the public KeyStateStore API. Uses real filesystem
//  operations against a per-test temp directory (no mocks, no doubles).
//

import XCTest
import CryptoKit
@testable import KeyStateStore

final class KeyStateStoreTests: XCTestCase {

    private var tempDir: URL!

    override func setUp() {
        super.setUp()
        let unique = UUID().uuidString
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("KeyStateStoreTests-\(unique)", isDirectory: true)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempDir)
        tempDir = nil
        super.tearDown()
    }

    func testUnknownFingerprintDefaultsToActive() throws {
        let store = try KeyStateStore(directory: tempDir)
        XCTAssertEqual(store.state(forFingerprint: "ABCDEF0123456789"), .active)
        XCTAssertNil(store.record(forFingerprint: "ABCDEF0123456789"))
    }

    func testSetStatePersistsAndReloads() throws {
        let fpr = "0123456789ABCDEF"
        let store = try KeyStateStore(directory: tempDir)
        try store.setState(.archived, forFingerprint: fpr, reason: "test")

        let reloaded = try KeyStateStore(directory: tempDir)
        XCTAssertEqual(reloaded.state(forFingerprint: fpr), .archived)
        let record = try XCTUnwrap(reloaded.record(forFingerprint: fpr))
        XCTAssertEqual(record.reason, "test")
        XCTAssertEqual(record.state, .archived)
    }

    func testStateSetIsAtomicAcrossFingerprints() throws {
        let store = try KeyStateStore(directory: tempDir)
        try store.setState(.archived, forFingerprints: ["A1", "B2", "C3"], reason: "bulk")
        let reloaded = try KeyStateStore(directory: tempDir)
        XCTAssertEqual(reloaded.state(forFingerprint: "A1"), .archived)
        XCTAssertEqual(reloaded.state(forFingerprint: "B2"), .archived)
        XCTAssertEqual(reloaded.state(forFingerprint: "C3"), .archived)
    }

    func testRemoveRecordClearsEntry() throws {
        let store = try KeyStateStore(directory: tempDir)
        try store.setState(.archived, forFingerprint: "DEAD")
        XCTAssertEqual(store.state(forFingerprint: "DEAD"), .archived)
        try store.removeRecord(forFingerprint: "DEAD")
        XCTAssertEqual(store.state(forFingerprint: "DEAD"), .active)
    }

    func testFingerprintNormalizationIsWhitespaceAndCaseInsensitive() throws {
        let store = try KeyStateStore(directory: tempDir)
        try store.setState(.archived, forFingerprint: "  ab:cd:ef  ")
        XCTAssertEqual(store.state(forFingerprint: "ABCDEF"), .archived)
        XCTAssertEqual(store.state(forFingerprint: "abcdef"), .archived)
        XCTAssertEqual(store.state(forFingerprint: "  AB:CD:EF  "), .archived)
    }

    func testTamperedDatabaseResetsToEmpty() throws {
        let fpr = "FEDCBA9876"
        let store = try KeyStateStore(directory: tempDir)
        try store.setState(.archived, forFingerprint: fpr)

        let dbPath = tempDir.appendingPathComponent(KeyStateStore.databaseFilename)
        let original = try Data(contentsOf: dbPath)
        var bytes = Array(original)
        bytes[bytes.count / 2] ^= 0xFF
        try Data(bytes).write(to: dbPath)

        XCTAssertThrowsError(try KeyStateStore(directory: tempDir)) { error in
            guard case KeyStateStoreError.tampered = error else {
                XCTFail("expected tampered, got \(error)")
                return
            }
        }
        _ = original
    }

    func testTamperedSignatureResetsToEmpty() throws {
        let fpr = "FEDCBA9876"
        let store = try KeyStateStore(directory: tempDir)
        try store.setState(.archived, forFingerprint: fpr)

        let sigPath = tempDir.appendingPathComponent(KeyStateStore.signatureFilename)
        var sig = try Data(contentsOf: sigPath)
        sig[sig.count - 1] ^= 0xFF
        try sig.write(to: sigPath)

        XCTAssertThrowsError(try KeyStateStore(directory: tempDir)) { error in
            guard case KeyStateStoreError.tampered = error else {
                XCTFail("expected tampered, got \(error)")
                return
            }
        }
    }

    func testFingerprintsFilterByState() throws {
        let store = try KeyStateStore(directory: tempDir)
        try store.setState(.archived, forFingerprint: "1111")
        try store.setState(.active, forFingerprint: "2222")
        try store.setState(.archived, forFingerprint: "3333")

        let archived = store.fingerprints(in: .archived)
        let active = store.fingerprints(in: .active)
        XCTAssertEqual(Set(archived), Set(["1111", "3333"]))
        XCTAssertEqual(Set(active), Set(["2222"]))
    }

    func testStoreUsesDistinctSigningKeyFromTrustStore() throws {
        // Sanity: the KeyStateStore signing key is independent per service
        // account. We verify the on-disk signature round-trips with the
        // store's own public key, but a tampered signature generated by a
        // different key must fail.
        let store = try KeyStateStore(directory: tempDir)
        try store.setState(.archived, forFingerprint: "AAAA")

        let otherKey = Curve25519.Signing.PrivateKey()
        let dbPath = tempDir.appendingPathComponent(KeyStateStore.databaseFilename)
        let dbData = try Data(contentsOf: dbPath)
        let forged = try otherKey.signature(for: dbData)
        try forged.write(to: tempDir.appendingPathComponent(KeyStateStore.signatureFilename))

        XCTAssertThrowsError(try KeyStateStore(directory: tempDir)) { error in
            guard case KeyStateStoreError.tampered = error else {
                XCTFail("expected tampered, got \(error)")
                return
            }
        }
    }
}

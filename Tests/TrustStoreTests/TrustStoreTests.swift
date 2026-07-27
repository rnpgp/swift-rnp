//
//  TrustStoreTests.swift
//  swift-rnp
//
//  Tests for the tamper-detecting TrustStore: state transitions, conflict
//  detection, persistence, and signature verification.
//

import CryptoKit
import XCTest
@testable import TrustStore

final class TrustStoreTests: XCTestCase {
    private var tempDirectories: [URL] = []

    override func tearDownWithError() throws {
        for url in tempDirectories {
            try? FileManager.default.removeItem(at: url)
        }
        tempDirectories = []
    }

    private func makeDirectory() -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("swift-rnp-truststore-tests")
            .appendingPathComponent(UUID().uuidString)
        tempDirectories.append(url)
        return url
    }

    private func makeStore(directory: URL? = nil) throws -> TrustStore {
        try TrustStore(directory: directory ?? makeDirectory(), privateKey: Curve25519.Signing.PrivateKey())
    }

    // MARK: - State transitions

    func testUnknownFingerprintIsUnverified() throws {
        let store = try makeStore()
        XCTAssertEqual(store.state(forFpr: "AABBCCDD"), .unverified)
    }

    func testNoteSeenRecordsUnverifiedTOFU() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        XCTAssertEqual(store.state(forFpr: "FPR1"), .unverified)
        XCTAssertEqual(store.state(forEmail: "alice@example.com"), .unverified)
        XCTAssertTrue(store.conflicts().isEmpty)
    }

    func testMarkVerified() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.markVerified(fingerprint: "FPR1")
        XCTAssertEqual(store.state(forFpr: "FPR1"), .verified)
        XCTAssertEqual(store.state(forEmail: "alice@example.com"), .verified)
    }

    func testMarkProblem() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.markProblem(fingerprint: "FPR1")
        XCTAssertEqual(store.state(forFpr: "FPR1"), .problem)
    }

    // MARK: - Conflict detection

    func testDifferentFingerprintForSameEmailCreatesConflict() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR2")

        XCTAssertEqual(store.state(forEmail: "alice@example.com"), .problem)
        XCTAssertEqual(store.state(forFpr: "FPR2"), .problem)

        let conflicts = store.conflicts()
        XCTAssertEqual(conflicts.count, 1)
        XCTAssertEqual(conflicts.first?.email, "alice@example.com")
        XCTAssertEqual(conflicts.first?.existingFingerprint, "FPR1")
        XCTAssertEqual(conflicts.first?.newFingerprint, "FPR2")
        XCTAssertTrue(store.hasConflict(forEmail: "alice@example.com"))
    }

    func testMarkVerifiedResolvesConflict() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR2")
        XCTAssertFalse(store.conflicts().isEmpty)

        try store.markVerified(fingerprint: "FPR2")
        XCTAssertTrue(store.conflicts().isEmpty)
        XCTAssertEqual(store.state(forFpr: "FPR2"), .verified)
        XCTAssertEqual(store.state(forEmail: "alice@example.com"), .verified)
    }

    func testResolveConflictAcceptsNewFingerprint() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR2")
        try store.resolveConflict(email: "alice@example.com", fingerprint: "FPR2")
        XCTAssertTrue(store.conflicts().isEmpty)
        XCTAssertEqual(store.state(forEmail: "alice@example.com"), .verified)
        XCTAssertEqual(store.state(forFpr: "FPR2"), .verified)
    }

    func testEmailIsNormalized() throws {
        let store = try makeStore()
        try store.noteSeen(email: "Alice@Example.COM", fingerprint: "FPR1")
        try store.noteSeen(email: "  alice@example.com  ", fingerprint: "FPR2")
        XCTAssertEqual(store.conflicts().count, 1)
        XCTAssertEqual(store.conflicts().first?.email, "alice@example.com")
    }

    // MARK: - Persistence and tamper detection

    func testPersistsAcrossInstances() throws {
        let directory = makeDirectory()
        let key = Curve25519.Signing.PrivateKey()
        let first = try TrustStore(directory: directory, privateKey: key)
        try first.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try first.markVerified(fingerprint: "FPR1")

        let second = try TrustStore(directory: directory, privateKey: key)
        XCTAssertEqual(second.state(forEmail: "alice@example.com"), .verified)
    }

    func testTamperedDatabaseResetsToEmpty() throws {
        let directory = makeDirectory()
        let key = Curve25519.Signing.PrivateKey()
        let store = try TrustStore(directory: directory, privateKey: key)
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.markVerified(fingerprint: "FPR1")

        let databaseURL = directory.appendingPathComponent(TrustStore.databaseFilename)
        var data = try XCTUnwrap(Data(contentsOf: databaseURL))
        data[10] ^= 0x01
        try data.write(to: databaseURL, options: .atomic)

        let reopened = try TrustStore(directory: directory, privateKey: key)
        XCTAssertEqual(reopened.state(forEmail: "alice@example.com"), .unverified)
        XCTAssertTrue(reopened.conflicts().isEmpty)
    }

    func testTamperedSignatureResetsToEmpty() throws {
        let directory = makeDirectory()
        let key = Curve25519.Signing.PrivateKey()
        let store = try TrustStore(directory: directory, privateKey: key)
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.markVerified(fingerprint: "FPR1")

        let signatureURL = directory.appendingPathComponent(TrustStore.signatureFilename)
        var signature = try XCTUnwrap(Data(contentsOf: signatureURL))
        signature[0] ^= 0x01
        try signature.write(to: signatureURL, options: .atomic)

        let reopened = try TrustStore(directory: directory, privateKey: key)
        XCTAssertEqual(reopened.state(forEmail: "alice@example.com"), .unverified)
        XCTAssertTrue(reopened.conflicts().isEmpty)
    }

    func testWrongKeyRejectsDatabase() throws {
        let directory = makeDirectory()
        let firstKey = Curve25519.Signing.PrivateKey()
        let store = try TrustStore(directory: directory, privateKey: firstKey)
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.markVerified(fingerprint: "FPR1")

        let wrongKey = Curve25519.Signing.PrivateKey()
        let reopened = try TrustStore(directory: directory, privateKey: wrongKey)
        XCTAssertEqual(reopened.state(forEmail: "alice@example.com"), .unverified)
    }

    func testSchemaVersionIsPersisted() throws {
        let directory = makeDirectory()
        let store = try makeStore(directory: directory)
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")

        let databaseURL = directory.appendingPathComponent(TrustStore.databaseFilename)
        let data = try XCTUnwrap(Data(contentsOf: databaseURL))
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["version"] as? Int, 1)
    }

    // MARK: - Reject conflict

    func testRejectConflictRestoresVerifiedOldBinding() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.markVerified(fingerprint: "FPR1")
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR2")
        XCTAssertTrue(store.hasConflict(forEmail: "alice@example.com"))

        try store.rejectConflict(email: "alice@example.com", newFpr: "FPR2")

        XCTAssertTrue(store.conflicts().isEmpty)
        XCTAssertFalse(store.hasConflict(forEmail: "alice@example.com"))
        // The old binding is restored with its previous state...
        XCTAssertEqual(store.state(forEmail: "alice@example.com"), .verified)
        XCTAssertEqual(store.state(forFpr: "FPR1"), .verified)
        // ...and the rejected key stays marked as a problem.
        XCTAssertEqual(store.state(forFpr: "FPR2"), .problem)
    }

    func testRejectConflictRestoresUnverifiedOldBinding() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR2")

        try store.rejectConflict(email: "alice@example.com", newFpr: "FPR2")

        XCTAssertTrue(store.conflicts().isEmpty)
        XCTAssertEqual(store.state(forEmail: "alice@example.com"), .unverified)
        XCTAssertEqual(store.state(forFpr: "FPR1"), .unverified)
        XCTAssertEqual(store.state(forFpr: "FPR2"), .problem)
    }

    func testRejectConflictWithoutConflictDoesNothing() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")

        try store.rejectConflict(email: "alice@example.com", newFpr: "FPR2")

        XCTAssertTrue(store.conflicts().isEmpty)
        XCTAssertEqual(store.state(forEmail: "alice@example.com"), .unverified)
        XCTAssertEqual(store.state(forFpr: "FPR1"), .unverified)
    }

    func testRejectConflictUnwindsConflictChain() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR2")
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR3")
        XCTAssertEqual(store.conflicts().count, 2)

        // Rejecting the newest key restores the previous binding (still in
        // problem state, with its own conflict pending).
        try store.rejectConflict(email: "alice@example.com", newFpr: "FPR3")
        XCTAssertEqual(store.conflicts().count, 1)
        XCTAssertEqual(store.state(forEmail: "alice@example.com"), .problem)
        XCTAssertEqual(store.state(forFpr: "FPR3"), .problem)

        // Rejecting the remaining conflict restores the original binding.
        try store.rejectConflict(email: "alice@example.com", newFpr: "FPR2")
        XCTAssertTrue(store.conflicts().isEmpty)
        XCTAssertEqual(store.state(forEmail: "alice@example.com"), .unverified)
        XCTAssertEqual(store.state(forFpr: "FPR1"), .unverified)
        XCTAssertEqual(store.state(forFpr: "FPR2"), .problem)
        XCTAssertEqual(store.state(forFpr: "FPR3"), .problem)
    }

    func testRejectConflictPersistsAcrossInstances() throws {
        let directory = makeDirectory()
        let key = Curve25519.Signing.PrivateKey()
        let first = try TrustStore(directory: directory, privateKey: key)
        try first.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try first.markVerified(fingerprint: "FPR1")
        try first.noteSeen(email: "alice@example.com", fingerprint: "FPR2")
        try first.rejectConflict(email: "alice@example.com", newFpr: "FPR2")

        let second = try TrustStore(directory: directory, privateKey: key)
        XCTAssertTrue(second.conflicts().isEmpty)
        XCTAssertEqual(second.state(forEmail: "alice@example.com"), .verified)
        XCTAssertEqual(second.state(forFpr: "FPR1"), .verified)
        XCTAssertEqual(second.state(forFpr: "FPR2"), .problem)
    }

    func testMarkVerifiedAfterRejectPromotesNewKey() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR2")
        try store.rejectConflict(email: "alice@example.com", newFpr: "FPR2")
        XCTAssertEqual(store.state(forFpr: "FPR2"), .problem)

        // The user changes their mind and verifies the rejected key: it
        // becomes the active binding for the address.
        try store.markVerified(fingerprint: "FPR2")
        XCTAssertEqual(store.state(forEmail: "alice@example.com"), .verified)
        XCTAssertEqual(store.state(forFpr: "FPR2"), .verified)
    }

    // MARK: - Trust history

    func testHistoryRecordsStateTransitions() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.markVerified(fingerprint: "FPR1")
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR2")
        try store.rejectConflict(email: "alice@example.com", newFpr: "FPR2")

        let history = store.history(forEmail: "alice@example.com")
        // Most recent first: restored FPR1, rejected FPR2, conflict-time FPR2,
        // superseded FPR1, verified FPR1, first-seen FPR1.
        XCTAssertEqual(history.count, 6)
        XCTAssertEqual(history.map(\.fingerprint), ["FPR1", "FPR2", "FPR2", "FPR1", "FPR1", "FPR1"])
        XCTAssertEqual(history.map(\.state), [.verified, .problem, .problem, .verified, .verified, .unverified])
        XCTAssertTrue(history.allSatisfy { $0.email == "alice@example.com" })
    }

    func testHistoryNormalizesEmail() throws {
        let store = try makeStore()
        try store.noteSeen(email: "Alice@Example.COM", fingerprint: "FPR1")
        XCTAssertEqual(store.history(forEmail: "  alice@example.com ").count, 1)
    }

    func testHistoryIsScopedPerEmail() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.noteSeen(email: "bob@example.com", fingerprint: "FPR9")
        try store.markVerified(fingerprint: "FPR1")

        let aliceHistory = store.history(forEmail: "alice@example.com")
        XCTAssertEqual(aliceHistory.map(\.state), [.verified, .unverified])
        let bobHistory = store.history(forEmail: "bob@example.com")
        XCTAssertEqual(bobHistory.map(\.fingerprint), ["FPR9"])
        XCTAssertTrue(store.history(forEmail: "carol@example.com").isEmpty)
    }

    func testHistoryPersistsAcrossInstances() throws {
        let directory = makeDirectory()
        let key = Curve25519.Signing.PrivateKey()
        let first = try TrustStore(directory: directory, privateKey: key)
        try first.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try first.markVerified(fingerprint: "FPR1")

        let second = try TrustStore(directory: directory, privateKey: key)
        let history = second.history(forEmail: "alice@example.com")
        XCTAssertEqual(history.map(\.state), [.verified, .unverified])
    }

    func testReSeenBindingDoesNotSpamHistory() throws {
        let store = try makeStore()
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        XCTAssertEqual(store.history(forEmail: "alice@example.com").count, 1)
    }

    func testDatabaseWithoutHistoryLogDecodes() throws {
        let directory = makeDirectory()
        let key = Curve25519.Signing.PrivateKey()
        let store = try TrustStore(directory: directory, privateKey: key)
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR1")
        try store.markVerified(fingerprint: "FPR1")
        try store.noteSeen(email: "alice@example.com", fingerprint: "FPR2")

        // Simulate a database written before the history log existed: strip
        // the key and re-sign the payload.
        let databaseURL = directory.appendingPathComponent(TrustStore.databaseFilename)
        let signatureURL = directory.appendingPathComponent(TrustStore.signatureFilename)
        let data = try XCTUnwrap(Data(contentsOf: databaseURL))
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        json.removeValue(forKey: "history")
        let stripped = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys])
        try stripped.write(to: databaseURL, options: .atomic)
        let signature = try key.signature(for: stripped)
        try signature.write(to: signatureURL, options: .atomic)

        let reopened = try TrustStore(directory: directory, privateKey: key)
        XCTAssertEqual(reopened.state(forEmail: "alice@example.com"), .problem)
        XCTAssertTrue(reopened.hasConflict(forEmail: "alice@example.com"))
        XCTAssertTrue(reopened.history(forEmail: "alice@example.com").isEmpty)

        // Rejecting a conflict that predates the history log falls back to
        // restoring the old binding as unverified rather than losing it.
        try reopened.rejectConflict(email: "alice@example.com", newFpr: "FPR2")
        XCTAssertFalse(reopened.hasConflict(forEmail: "alice@example.com"))
        XCTAssertEqual(reopened.state(forEmail: "alice@example.com"), .unverified)
        XCTAssertEqual(reopened.state(forFpr: "FPR1"), .unverified)
        XCTAssertEqual(reopened.state(forFpr: "FPR2"), .problem)
    }
}

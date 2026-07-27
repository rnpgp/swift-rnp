//
//  KeyTransitionTests.swift
//  KeyLifecycleTests
//
//  Engine-layer tests. Skips when librnp is not installed locally.
//

import XCTest
@testable import KeyLifecycle
@testable import MailSecurityEngine
final class KeyTransitionTests: XCTestCase {
    private var tempDir: URL!

    override func setUp() {
        super.setUp()
        let unique = UUID().uuidString
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("KeyTransition-\(unique)", isDirectory: true)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempDir)
        tempDir = nil
        super.tearDown()
    }

    func testTransitionRefusesWhenOldKeyHasNoSecret() throws {
        try XCTSkipUnless(librnpAvailable(), "librnp not installed locally")
        let km = try KeyManager(directory: tempDir, password: "test-pass")
        let original = try km.generateKey(
            userID: "Alice <alice@example.org>",
            algorithm: .ed25519,
            expirationSeconds: 0
        )

        // Use a second, separate key manager with a different keyring
        // so we can simulate importing only the public half.
        let publicOnlyDir = tempDir.appendingPathComponent("public-only", isDirectory: true)
        try? FileManager.default.createDirectory(at: publicOnlyDir, withIntermediateDirectories: true)
        let kmPublic = try KeyManager(directory: publicOnlyDir, password: "test-pass")
        let armoredPublic = try km.exportKey(fingerprint: original.fingerprint, secret: false)
        _ = try kmPublic.importKeys(armoredPublic)

        let transition = KeyTransition(keyManager: kmPublic)
        XCTAssertThrowsError(
            try transition.run(
                replacing: original.fingerprint,
                newKeyAlgorithm: .ed25519
            )
        ) { error in
            guard case KeyTransitionError.oldKeyNotSecret = error else {
                XCTFail("expected oldKeyNotSecret, got \(error)")
                return
            }
        }
    }

    func testTransitionGeneratesNewAndArchivesOld() throws {
        try XCTSkipUnless(librnpAvailable(), "librnp not installed locally")
        let km = try KeyManager(directory: tempDir, password: "test-pass")
        let original = try km.generateKey(
            userID: "Alice <alice@example.org>",
            algorithm: .ed25519,
            expirationSeconds: 0
        )

        let transition = KeyTransition(keyManager: km)
        let result = try transition.run(
            replacing: original.fingerprint,
            newKeyAlgorithm: .ed25519
        )

        XCTAssertEqual(result.oldFingerprint, original.fingerprint)
        XCTAssertNotEqual(result.oldFingerprint, result.newFingerprint)
        XCTAssertTrue(result.oldKeyArchived)
        XCTAssertTrue(result.transitionCertificationAdded, "certification signature should be added when old secret is available")

        // Old key is now archived.
        XCTAssertEqual(km.usageState(forFingerprint: original.fingerprint), .archived)

        // Old key is still in the keyring (decrypt-only).
        let archived = try km.archivedKeys()
        XCTAssertTrue(archived.contains(where: { $0.fingerprint == original.fingerprint }))
    }

    /// Probes whether librnp is reachable.
    private func librnpAvailable() -> Bool {
        let probe = FileManager.default.temporaryDirectory
            .appendingPathComponent("librnp-probe-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: probe, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: probe) }
        do {
            _ = try KeyManager(directory: probe, password: "x")
            return true
        } catch {
            return false
        }
    }

    func testRunAsyncEnqueuesPublishActions() async throws {
        try XCTSkipUnless(librnpAvailable(), "librnp not installed locally")
        let km = try KeyManager(directory: tempDir, password: "test-pass")
        let original = try km.generateKey(
            userID: "Alice <alice@example.org>",
            algorithm: .ed25519,
            expirationSeconds: 0
        )

        // Queue URL inside the temp dir so cleanup catches it.
        let queueURL = tempDir.appendingPathComponent("publish-queue.json")
        let recorder = PublishRecorder()
        let queue = try OfflinePublishQueue(storeURL: queueURL) { action in
            recorder.record(action.fingerprint)
        }

        let transition = KeyTransition(keyManager: km, publishQueue: queue)
        let result = try await transition.runAsync(
            replacing: original.fingerprint,
            newKeyAlgorithm: .ed25519
        )

        // The queue's publisher should have been called for both the
        // new and revoked-old keys.
        let recorded = recorder.snapshot()
        XCTAssertEqual(Set(recorded), Set([result.newFingerprint, original.fingerprint]))
        XCTAssertTrue(queue.pending().isEmpty, "successful publishes should not stay queued")
    }
}

/// Thread-safe recorder for the publish closure. The closure is
/// `@Sendable` so a plain `var` capture would not compile.
private final class PublishRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var fingerprints: [String] = []

    func record(_ fingerprint: String) {
        lock.lock()
        defer { lock.unlock() }
        fingerprints.append(fingerprint)
    }

    func snapshot() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return fingerprints
    }
}

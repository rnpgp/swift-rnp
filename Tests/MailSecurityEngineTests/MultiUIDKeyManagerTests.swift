//
//  MultiUIDKeyManagerTests.swift
//  MailSecurityEngineTests
//
//  Round-trip: generate a key with one UID, add a second UID via the
//  engine wrapper, assert both UIDs are visible and the keyring persists.
//
//  Skips when librnp is not available on the test machine (CI keeps a
//  local librnp install; developers without it get a no-op).
//

import XCTest
@testable import MailSecurityEngine

final class MultiUIDKeyManagerTests: XCTestCase {
    private var tempDir: URL!

    override func setUp() {
        super.setUp()
        let unique = UUID().uuidString
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("MultiUID-\(unique)", isDirectory: true)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempDir)
        tempDir = nil
        super.tearDown()
    }

    func testAddingUserIDProducesVisibleUID() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not installed locally")

        let km = try KeyManager(directory: tempDir, password: "test-passphrase")
        let original = try km.generateKey(
            userID: "Alice <alice@work.com>",
            algorithm: .ed25519,
            expirationSeconds: 0
        )
        XCTAssertEqual(original.userIDs, ["Alice <alice@work.com>"])

        let updated = try km.addUserID(
            "Alice <alice@personal.com>",
            toKeyWithFingerprint: original.fingerprint,
            primary: false
        )
        XCTAssertEqual(Set(updated.userIDs), Set([
            "Alice <alice@work.com>",
            "Alice <alice@personal.com>",
        ]))
    }

    func testAddedUIDSurvivesReload() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not installed locally")

        let km = try KeyManager(directory: tempDir, password: "test-passphrase")
        let original = try km.generateKey(
            userID: "Bob <bob@example.org>",
            algorithm: .ed25519,
            expirationSeconds: 0
        )
        _ = try km.addUserID(
            "Bob <bob@personal.org>",
            toKeyWithFingerprint: original.fingerprint
        )

        let reloaded = try KeyManager(directory: tempDir, password: "test-passphrase")
        let keys = try reloaded.listKeys()
        let bob = try XCTUnwrap(keys.first(where: { $0.fingerprint == original.fingerprint }))
        XCTAssertEqual(Set(bob.userIDs), Set([
            "Bob <bob@example.org>",
            "Bob <bob@personal.org>",
        ]))
    }

    /// Probes whether librnp is reachable. The test bundle cannot link
    /// CRnp directly without breaking the engine module boundary, so we
    /// use KeyManager's constructor (which builds an Rnp context) as a
    /// proxy: if it throws on an empty directory, librnp is missing.
}

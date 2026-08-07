//
//  KeyResolverTests.swift
//  MailSecurityEngineTests
//
//  Locks in the KeyResolver contract introduced when KeyManager was split
//  into KeyringStore (persistence/CRUD) + KeyResolver (lookup). The
//  lookup methods previously lived on KeyManager; they must behave
//  identically on KeyResolver.
//

import Foundation
import XCTest
import MailSecurityEngine
import Librnp

final class KeyResolverTests: XCTestCase {
    private var tempDir: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        tempDir = TestSupport.makeTempDir(prefix: "keyresolver")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
        try super.tearDownWithError()
    }

    func testResolverLooksUpKeyByUserID() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not available")
        let store = try KeyringStore(directory: tempDir, password: "test-pass")
        let resolver = KeyResolver(keyringStore: store)
        _ = try store.generateKey(
            userID: "Alice <alice@example.com>",
            algorithm: .ed25519
        )
        let key = try resolver.publicKey(for: "Alice <alice@example.com>")
        XCTAssertNotNil(key)
        XCTAssertEqual(try key?.primaryUserID, "Alice <alice@example.com>")
    }

    func testResolverLooksUpKeyByBareEmail() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not available")
        let store = try KeyringStore(directory: tempDir, password: "test-pass")
        let resolver = KeyResolver(keyringStore: store)
        _ = try store.generateKey(userID: "Bob <bob@example.com>", algorithm: .ed25519)
        let key = try resolver.publicKey(for: "bob@example.com")
        XCTAssertNotNil(key, "Resolver should match the <email> part of stored user IDs")
    }

    func testResolverReturnsNilForUnknownIdentifier() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not available")
        let store = try KeyringStore(directory: tempDir, password: "test-pass")
        let resolver = KeyResolver(keyringStore: store)
        let key = try resolver.publicKey(for: "nobody@example.com")
        XCTAssertNil(key)
    }

    func testResolverDistinguishesMissingFromArchived() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not available")
        let store = try KeyringStore(directory: tempDir, password: "test-pass")
        let resolver = KeyResolver(keyringStore: store)
        let info = try store.generateKey(userID: "Carol <carol@example.com>", algorithm: .ed25519)
        try store.setUsageState(.archived, forFingerprint: info.fingerprint)

        // resolveActiveRecipients currently uses rnp.locateKey, which matches
        // on full user IDs — pass the full UID to exercise the archived path.
        let result = try resolver.resolveActiveRecipients(
            addresses: ["Carol <carol@example.com>", "Ghost <ghost@example.com>"]
        )
        XCTAssertEqual(Set(result.resolved.keys), [])
        XCTAssertEqual(result.archivedOnly, ["Carol <carol@example.com>"])
        XCTAssertEqual(result.missing, ["Ghost <ghost@example.com>"])
    }

    func testResolverExcludesArchivedKeyFromActiveSigningKey() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not available")
        let store = try KeyringStore(directory: tempDir, password: "test-pass")
        let resolver = KeyResolver(keyringStore: store)
        let info = try store.generateKey(userID: "Dave <dave@example.com>", algorithm: .ed25519)
        try store.setUsageState(.archived, forFingerprint: info.fingerprint)
        let key = try resolver.activeSigningKey(forUserID: "Dave <dave@example.com>")
        XCTAssertNil(key, "Archived keys must not be returned by activeSigningKey")
    }
}

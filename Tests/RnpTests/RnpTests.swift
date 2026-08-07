//
//  RnpTests.swift
//  swift-rnp
//
//  End-to-end tests of the Rnp wrapper against the linked librnp.
//

import XCTest
@testable import Librnp

final class RnpTests: XCTestCase {
    private static let userid = "Test <t@t>"
    private static let password = "password"

    /// Fresh context with a single password-protected RSA key generated.
    private func makeRnpWithRSAKey() throws -> Rnp {
        let rnp = try Rnp(password: Self.password)
        try rnp.generateKey(json: Rnp.rsaKeyGenJSON(userid: Self.userid))
        return rnp
    }

    private var message: Data {
        Data("The quick brown fox jumps over the lazy dog".utf8)
    }

    // MARK: - Library information

    func testVersionString() throws {
        XCTAssertFalse(Rnp.versionString.isEmpty)
        // Both supported librnp builds (release v0.18.1 and rnp main)
        // report 0.18.1.
        XCTAssertTrue(
            Rnp.versionString.hasPrefix("0.18"),
            "unexpected librnp version: \(Rnp.versionString)"
        )
        XCTAssertFalse(Rnp.versionStringFull.isEmpty)
    }

    // MARK: - Key generation and lookup

    func testGenerateRSAKey() throws {
        let rnp = try Rnp(password: Self.password)
        let results = try rnp.generateKey(json: Rnp.rsaKeyGenJSON(userid: Self.userid))
        XCTAssertTrue(results.contains("grip"))

        let key = try XCTUnwrap(rnp.locateKey(Self.userid))
        let fingerprint = try key.fingerprint
        XCTAssertEqual(fingerprint.count, 40)
        XCTAssertTrue(fingerprint.allSatisfy(\.isHexDigit))

        // The same key is locatable by its fingerprint, too.
        let byFingerprint = try XCTUnwrap(rnp.locateKey(fingerprint, type: .fingerprint))
        XCTAssertEqual(try byFingerprint.fingerprint, fingerprint)

        // Primary key and subkey are counted separately by librnp.
        XCTAssertEqual(try rnp.publicKeyCount, 2)
        XCTAssertEqual(try rnp.secretKeyCount, 2)
        XCTAssertNil(try rnp.locateKey("Nobody <nobody@example.com>"))
    }

    func testGenerateECDSAKey() throws {
        let rnp = try Rnp(password: Self.password)
        try rnp.generateKey(json: Rnp.ecdsaP256KeyGenJSON(userid: Self.userid))
        XCTAssertNotNil(try rnp.locateKey(Self.userid))
    }

    // MARK: - Encryption

    func testEncryptDecryptRoundtrip() throws {
        let rnp = try makeRnpWithRSAKey()
        let key = try rnp.requireKey(Self.userid)

        let encrypted = try rnp.encrypt(message, for: [key])
        XCTAssertNotEqual(encrypted, message)

        let decrypted = try rnp.decrypt(encrypted)
        XCTAssertEqual(decrypted, message)
    }

    // MARK: - Signing

    func testSignVerifyEmbedded() throws {
        let rnp = try makeRnpWithRSAKey()
        let key = try rnp.requireKey(Self.userid)

        let signed = try rnp.sign(message, with: key)
        let verified = try rnp.verify(signed)
        XCTAssertEqual(verified, message)
    }

    func testSignVerifyDetached() throws {
        let rnp = try makeRnpWithRSAKey()
        let key = try rnp.requireKey(Self.userid)

        let signature = try rnp.signDetached(message, with: key)
        XCTAssertNotEqual(signature, message)
        XCTAssertNoThrow(try rnp.verifyDetached(signature: signature, data: message))
    }

    func testTamperedMessageFailsVerification() throws {
        let rnp = try makeRnpWithRSAKey()
        let key = try rnp.requireKey(Self.userid)

        // Embedded signature: tamper with the signed data itself.
        var signed = try rnp.sign(message, with: key)
        let flipIndex = signed.count / 2
        signed[flipIndex] ^= 0xFF
        XCTAssertThrowsError(try rnp.verify(signed))

        // Detached signature: tamper with the data under verification.
        let signature = try rnp.signDetached(message, with: key)
        var tampered = message
        tampered[0] ^= 0xFF
        XCTAssertThrowsError(try rnp.verifyDetached(signature: signature, data: tampered))
    }

    // MARK: - Key export / import

    func testExportImportRoundtrip() throws {
        let source = try makeRnpWithRSAKey()
        let key = try source.requireKey(Self.userid)
        let fingerprint = try key.fingerprint

        let publicData = try key.exportKey()
        let secretData = try key.exportKey(secret: true)
        XCTAssertTrue(String(decoding: publicData, as: UTF8.self).contains("BEGIN PGP PUBLIC KEY BLOCK"))
        XCTAssertTrue(String(decoding: secretData, as: UTF8.self).contains("BEGIN PGP PRIVATE KEY BLOCK"))

        let destination = try Rnp(password: Self.password)
        XCTAssertEqual(try destination.publicKeyCount, 0)
        try destination.importKeys(publicData)
        try destination.importKeys(secretData)
        XCTAssertEqual(try destination.publicKeyCount, 2)
        XCTAssertEqual(try destination.secretKeyCount, 2)

        // The imported key is usable end-to-end.
        let imported = try destination.requireKey(fingerprint, type: .fingerprint)
        let encrypted = try destination.encrypt(message, for: [imported])
        XCTAssertEqual(try destination.decrypt(encrypted), message)
    }

    // MARK: - Keyring save / load

    func testSaveLoadKeyrings() throws {
        let source = try makeRnpWithRSAKey()
        let fingerprint = try source.requireKey(Self.userid).fingerprint

        let publicKeyring = try source.savePublicKeys()
        let secretKeyring = try source.saveSecretKeys()
        XCTAssertTrue(String(decoding: publicKeyring, as: UTF8.self).contains("BEGIN PGP PUBLIC KEY BLOCK"))
        XCTAssertTrue(String(decoding: secretKeyring, as: UTF8.self).contains("BEGIN PGP PRIVATE KEY BLOCK"))

        let destination = try Rnp(password: Self.password)
        try destination.loadKeys(publicKeyring, secret: false)
        try destination.loadKeys(secretKeyring, public: false)
        XCTAssertEqual(try destination.publicKeyCount, 2)
        XCTAssertEqual(try destination.secretKeyCount, 2)

        // Cross-context: data encrypted by the source is decryptable after
        // reloading the keyrings into a fresh context.
        let sourceKey = try source.requireKey(Self.userid)
        let encrypted = try source.encrypt(message, for: [sourceKey])
        XCTAssertEqual(try destination.decrypt(encrypted), message)

        let loaded = try destination.requireKey(fingerprint, type: .fingerprint)
        XCTAssertEqual(try loaded.fingerprint, fingerprint)
    }

    // MARK: - Key metadata

    func testRSAKeyMetadata() throws {
        let rnp = try Rnp(password: Self.password)
        try rnp.generateKey(json: Rnp.rsaKeyGenJSON(userid: Self.userid))
        let key = try rnp.requireKey(Self.userid)

        XCTAssertEqual(try key.algorithm, "RSA")
        XCTAssertEqual(try key.bits, 3072)
        XCTAssertNil(try key.curve)
        XCTAssertFalse(try key.isRevoked)
        XCTAssertNil(try key.revocationReason)

        let subs = try key.subkeys
        XCTAssertEqual(subs.count, 1)
        XCTAssertEqual(try subs[0].algorithm, "RSA")

        let creation = try key.creationDate
        let validTill = try key.validTill
        XCTAssertGreaterThan(validTill.timeIntervalSince1970, creation.timeIntervalSince1970)
    }

    func testECDSAKeyMetadata() throws {
        let rnp = try Rnp(password: Self.password)
        try rnp.generateKey(json: Rnp.ecdsaP256KeyGenJSON(userid: Self.userid))
        let key = try rnp.requireKey(Self.userid)

        XCTAssertEqual(try key.algorithm, "ECDSA")
        XCTAssertEqual(try key.bits, 256)
        XCTAssertEqual(try key.curve, "NIST P-256")
    }

    func testKeyRevocation() throws {
        let rnp = try makeRnpWithRSAKey()
        let key = try rnp.requireKey(Self.userid)

        let revocation = try key.exportRevocation(code: .retired, reason: "No longer used")
        XCTAssertTrue(String(decoding: revocation, as: UTF8.self).contains("BEGIN PGP PUBLIC KEY BLOCK"))

        // In-memory key is not yet revoked until the revocation signature is imported.
        XCTAssertFalse(try key.isRevoked)
    }

    // MARK: - Keyed passphrase provider

    func testKeyedProviderReceivesPrimaryFingerprint() throws {
        var seen: [(context: String, fingerprint: String?)] = []
        let rnp = try Rnp(keyedPassphraseProvider: { context, fingerprint in
            seen.append((context, fingerprint))
            return Self.password
        })
        try rnp.generateKey(json: Rnp.ed25519KeyGenJSON(userid: Self.userid))
        let key = try rnp.requireKey(Self.userid)
        let fingerprint = try key.fingerprint

        // Signing unlocks the primary key, decryption the encryption subkey;
        // both must surface the primary key's fingerprint.
        _ = try rnp.sign(message, with: key)
        let encrypted = try rnp.encrypt(message, for: [key])
        _ = try rnp.decrypt(encrypted)

        XCTAssertTrue(seen.contains { $0.fingerprint == fingerprint })
        XCTAssertFalse(seen.contains { $0.fingerprint != nil && $0.fingerprint != fingerprint })
    }

    // MARK: - Key protection

    func testKeyUnlockAndProtectionState() throws {
        let rnp = try Rnp(password: Self.password)
        try rnp.generateKey(json: Rnp.ed25519KeyGenJSON(userid: Self.userid))
        let key = try rnp.requireKey(Self.userid)
        let subkey = try XCTUnwrap(key.subkeys.first)

        // Generated keys are protected; a wrong password does not unlock.
        XCTAssertTrue(try key.isProtected)
        XCTAssertTrue(try subkey.isProtected)
        XCTAssertFalse(key.unlock(password: "wrong-password"))
        XCTAssertFalse(subkey.unlock(password: "wrong-password"))
        XCTAssertTrue(key.unlock(password: Self.password))
        XCTAssertTrue(subkey.unlock(password: Self.password))

        // Re-protecting with a new password persists into the secret export:
        // a fresh context only accepts the new password for the subkey.
        try key.protect(password: "new-password")
        try subkey.protect(password: "new-password")
        let secretData = try key.exportKey(secret: true)
        let reloaded = try Rnp(password: "new-password")
        try reloaded.importKeys(secretData)
        let reloadedSubkey = try XCTUnwrap(reloaded.requireKey(Self.userid).subkeys.first)
        XCTAssertFalse(reloadedSubkey.unlock(password: Self.password))
        XCTAssertTrue(reloadedSubkey.unlock(password: "new-password"))
    }
}

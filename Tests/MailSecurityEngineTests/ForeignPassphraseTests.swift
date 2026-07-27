//
//  ForeignPassphraseTests.swift
//  swift-rnp
//
//  Tests for imported secret keys protected by a foreign passphrase (one
//  different from the keyring passphrase): detection after import, per-key
//  passphrase verification, re-protecting with the keyring passphrase, and
//  per-key passphrase storage in the Keychain.
//

import XCTest
@testable import MailSecurityEngine
import Rnp

final class ForeignPassphraseTests: XCTestCase {
    private static let keyringPassword = "keyring-password"
    private static let foreignPassword = "foreign-secret"
    private static let alice = "Alice <alice@example.com>"
    private static let aliceEmail = "alice@example.com"

    private var tempDirectories: [URL] = []

    override func tearDownWithError() throws {
        for url in tempDirectories {
            try? FileManager.default.removeItem(at: url)
        }
        tempDirectories = []
    }

    // MARK: - Fixtures

    private func makeTempDirectory() -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("swift-rnp-tests")
            .appendingPathComponent(UUID().uuidString)
        tempDirectories.append(url)
        return url
    }

    /// Engine backed by a fresh temporary keyring whose passphrase provider
    /// always answers `password`.
    private func makeEngine(
        password: String = ForeignPassphraseTests.keyringPassword,
        directory: URL? = nil
    ) throws -> MailSecurityEngine {
        try MailSecurityEngine(
            directory: directory ?? makeTempDirectory(),
            passphraseProvider: { _ in password }
        )
    }

    /// Engine backed by a fresh temporary keyring with a keyed passphrase
    /// provider.
    private func makeEngine(
        keyedPassphraseProvider: @escaping Rnp.KeyedPassphraseProvider
    ) throws -> MailSecurityEngine {
        MailSecurityEngine(keyManager: try KeyManager(
            directory: makeTempDirectory(),
            keyedPassphraseProvider: keyedPassphraseProvider
        ))
    }

    /// Generates an Ed25519 key (fast) for Alice protected by the foreign
    /// passphrase and returns its armored secret export and fingerprint.
    private func makeForeignProtectedKey() throws -> (secretData: Data, fingerprint: String) {
        let source = try makeEngine(password: Self.foreignPassword)
        let info = try source.keyManager.generateKey(userID: Self.alice, algorithm: .ed25519)
        let secretData = try source.keyManager.exportKey(fingerprint: info.fingerprint, secret: true)
        return (secretData, info.fingerprint)
    }

    private func plainMessage(body: String = "Hello, Alice!") -> Data {
        let lines = [
            "From: \(Self.alice)",
            "To: \(Self.alice)",
            "Subject: foreign passphrase test",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=\"utf-8\"",
        ]
        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n" + body).utf8)
    }

    // MARK: - Detection

    func testLockedSecretKeysDetectsForeignPassphraseKey() throws {
        let (secretData, fingerprint) = try makeForeignProtectedKey()
        let destination = try makeEngine()
        let imported = try destination.keyManager.importKeys(secretData)
        XCTAssertEqual(imported.first?.fingerprint, fingerprint)

        // The keyring passphrase does not unlock the foreign key...
        let locked = try destination.keyManager.lockedSecretKeys(
            keyringPassphrase: Self.keyringPassword,
            among: [fingerprint]
        )
        XCTAssertEqual(locked, [LockedSecretKeyInfo(fingerprint: fingerprint, primaryUserID: Self.alice)])

        // ...but the foreign passphrase does, so it is not reported then.
        let unlockedByForeign = try destination.keyManager.lockedSecretKeys(
            keyringPassphrase: Self.foreignPassword,
            among: [fingerprint]
        )
        XCTAssertTrue(unlockedByForeign.isEmpty)
    }

    func testLockedSecretKeysIgnoresPublicOnlyAndKeyringProtectedKeys() throws {
        let (secretData, fingerprint) = try makeForeignProtectedKey()
        let destination = try makeEngine()

        // Public-only import carries no secret material to unlock.
        let publicOnly = try destination.keyManager.importKeys(publicExport(of: secretData))
        XCTAssertEqual(publicOnly.first?.fingerprint, fingerprint)
        var locked = try destination.keyManager.lockedSecretKeys(
            keyringPassphrase: Self.keyringPassword,
            among: [fingerprint]
        )
        XCTAssertTrue(locked.isEmpty)

        // A key generated inside the keyring is protected by the keyring
        // passphrase and must never be reported.
        let own = try destination.keyManager.generateKey(userID: "Carol <carol@example.com>", algorithm: .ed25519)
        locked = try destination.keyManager.lockedSecretKeys(keyringPassphrase: Self.keyringPassword)
        XCTAssertTrue(locked.isEmpty)
        XCTAssertNotEqual(own.fingerprint, fingerprint)
    }

    /// Extracts the public-key armor from an armored secret key export by
    /// importing it into a throwaway engine and re-exporting the public part.
    private func publicExport(of secretData: Data) throws -> Data {
        let throwaway = try makeEngine(password: Self.foreignPassword)
        let imported = try throwaway.keyManager.importKeys(secretData)
        let fingerprint = try XCTUnwrap(imported.first?.fingerprint)
        return try throwaway.keyManager.exportKey(fingerprint: fingerprint)
    }

    // MARK: - Verification

    func testUnlockSecretKeyVerifiesPassphrase() throws {
        let (secretData, fingerprint) = try makeForeignProtectedKey()
        let destination = try makeEngine()
        try destination.keyManager.importKeys(secretData)

        XCTAssertFalse(try destination.keyManager.unlockSecretKey(
            fingerprint: fingerprint,
            passphrase: "wrong-passphrase"
        ))
        XCTAssertTrue(try destination.keyManager.unlockSecretKey(
            fingerprint: fingerprint,
            passphrase: Self.foreignPassword
        ))
    }

    // MARK: - Re-protect

    func testReprotectSecretKeySwitchesToKeyringPassphrase() throws {
        let (secretData, fingerprint) = try makeForeignProtectedKey()
        let directory = makeTempDirectory()
        let destination = try makeEngine(directory: directory)
        try destination.keyManager.importKeys(secretData)

        // A wrong current passphrase is rejected and changes nothing.
        XCTAssertThrowsError(try destination.keyManager.reprotectSecretKey(
            fingerprint: fingerprint,
            currentPassphrase: "wrong-passphrase",
            newPassphrase: Self.keyringPassword
        )) { error in
            guard case KeyManagerError.wrongPassphrase(let failing) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(failing, fingerprint)
        }
        XCTAssertFalse(try destination.keyManager.lockedSecretKeys(
            keyringPassphrase: Self.keyringPassword,
            among: [fingerprint]
        ).isEmpty)

        // The correct foreign passphrase re-protects the key.
        try destination.keyManager.reprotectSecretKey(
            fingerprint: fingerprint,
            currentPassphrase: Self.foreignPassword,
            newPassphrase: Self.keyringPassword
        )
        XCTAssertTrue(try destination.keyManager.lockedSecretKeys(
            keyringPassphrase: Self.keyringPassword,
            among: [fingerprint]
        ).isEmpty)

        // The keyring passphrase now drives signing and decryption.
        let encoded = try destination.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.aliceEmail],
            sign: true,
            encrypt: true
        ))
        let decoded = try XCTUnwrap(destination.decode(encoded.rawData))
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)

        // The re-protected keyring is persisted: a fresh manager on the same
        // directory signs without ever seeing the foreign passphrase.
        let reloaded = try makeEngine(directory: directory)
        let reloadedEncoded = try reloaded.encode(EncodingRequest(
            message: plainMessage(body: "reloaded"),
            sender: Self.aliceEmail,
            recipients: [Self.aliceEmail],
            sign: true,
            encrypt: false
        ))
        XCTAssertTrue(reloadedEncoded.isSigned)
    }

    // MARK: - Per-key passphrase at runtime

    func testKeyedProviderUnlocksForeignKeyAtRuntime() throws {
        let (secretData, fingerprint) = try makeForeignProtectedKey()

        // Provider answering with the per-key passphrase for the foreign key
        // and the keyring passphrase otherwise; records what librnp asks for.
        var seenFingerprints: [String?] = []
        let destination = try makeEngine(keyedPassphraseProvider: { _, requested in
            seenFingerprints.append(requested)
            return requested == fingerprint ? Self.foreignPassword : Self.keyringPassword
        })
        try destination.keyManager.importKeys(secretData)

        // Signing unlocks the primary key; decryption unlocks the encryption
        // subkey. Both must be answered with the foreign passphrase via the
        // primary key's fingerprint.
        let encoded = try destination.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.aliceEmail],
            sign: true,
            encrypt: true
        ))
        let decoded = try XCTUnwrap(destination.decode(encoded.rawData))
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)
        XCTAssertTrue(decoded.security.isEncrypted)

        XCTAssertTrue(seenFingerprints.contains(fingerprint))
        XCTAssertFalse(seenFingerprints.contains { $0 != nil && $0 != fingerprint })
    }

    // MARK: - Keychain per-key storage

    func testKeychainStoresPerKeyPassphrase() {
        KeychainPassphraseStore.reset()
        let fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
        XCTAssertNil(KeychainPassphraseStore.passphrase(forKeyFingerprint: fingerprint))

        XCTAssertNil(KeychainPassphraseStore.setPassphrase("key-secret", forKeyFingerprint: fingerprint))
        XCTAssertEqual(KeychainPassphraseStore.passphrase(forKeyFingerprint: fingerprint), "key-secret")

        // Overwriting replaces the stored value.
        XCTAssertNil(KeychainPassphraseStore.setPassphrase("new-secret", forKeyFingerprint: fingerprint))
        XCTAssertEqual(KeychainPassphraseStore.passphrase(forKeyFingerprint: fingerprint), "new-secret")

        // The per-key item is independent of the keyring passphrase.
        XCTAssertNotEqual(KeychainPassphraseStore.sharedPassphrase(), "new-secret")

        KeychainPassphraseStore.removePassphrase(forKeyFingerprint: fingerprint)
        XCTAssertNil(KeychainPassphraseStore.passphrase(forKeyFingerprint: fingerprint))

        // reset() wipes per-key items along with the keyring passphrase.
        XCTAssertNil(KeychainPassphraseStore.setPassphrase("key-secret", forKeyFingerprint: fingerprint))
        KeychainPassphraseStore.reset()
        XCTAssertNil(KeychainPassphraseStore.passphrase(forKeyFingerprint: fingerprint))
    }

    func testResolvingProviderPrefersPerKeyPassphrase() {
        KeychainPassphraseStore.reset()
        let shared = KeychainPassphraseStore.sharedPassphrase()
        let fingerprint = "FEDCBA0987654321FEDCBA0987654321FEDCBA09"
        let otherFingerprint = "AAAA0000BBBB1111CCCC2222DDDD3333EEEE4444"
        let provider = KeychainPassphraseStore.resolvingProvider()

        // Without a per-key entry every request gets the keyring passphrase.
        XCTAssertEqual(provider("sign", fingerprint), shared)
        XCTAssertEqual(provider("decrypt", nil), shared)

        // With a per-key entry only that key's requests get the per-key
        // passphrase; other keys and keyless requests get the shared one.
        XCTAssertNil(KeychainPassphraseStore.setPassphrase("key-secret", forKeyFingerprint: fingerprint))
        XCTAssertEqual(provider("sign", fingerprint), "key-secret")
        XCTAssertEqual(provider("sign", otherFingerprint), shared)
        XCTAssertEqual(provider("sign", nil), shared)

        KeychainPassphraseStore.removePassphrase(forKeyFingerprint: fingerprint)
        XCTAssertEqual(provider("sign", fingerprint), shared)
    }
}

//
//  MailSecurityEngineTests.swift
//  swift-rnp
//
//  End-to-end tests of the mail security engine: PGP/MIME and inline-PGP
//  encode/decode roundtrips, multi-recipient encryption, error reporting
//  (missing keys, wrong passphrase, tampering), and KeyManager CRUD against
//  temporary keyring directories.
//

import XCTest
@testable import MailSecurityEngine
import Librnp
import TrustStore

final class MailSecurityEngineTests: XCTestCase {
    private static let password = "password"
    private static let alice = "Alice <alice@example.com>"
    private static let aliceEmail = "alice@example.com"
    private static let bob = "Bob <bob@example.com>"
    private static let bobEmail = "bob@example.com"
    private static let carol = "Carol <carol@example.com>"
    private static let carolEmail = "carol@example.com"

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

    /// Engine backed by a fresh temporary keyring, with the given keys
    /// generated (ECDSA is used by default because it generates fast).
    private func makeEngine(
        keys userIDs: [String] = [],
        algorithm: KeyAlgorithm = .ecdsa,
        directory: URL? = nil,
        password: String = MailSecurityEngineTests.password
    ) throws -> MailSecurityEngine {
        let engine = try MailSecurityEngine(
            directory: directory ?? makeTempDirectory(),
            passphraseProvider: { _ in password }
        )
        for userID in userIDs {
            try engine.keyManager.generateKey(userID: userID, algorithm: algorithm)
        }
        return engine
    }

    private func plainMessage(
        body: String = "Hello, Bob!",
        contentType: String? = "text/plain; charset=\"utf-8\"",
        extraHeaders: [String] = []
    ) -> Data {
        var lines = [
            "From: \(Self.alice)",
            "To: \(Self.bob)",
            "Subject: engine test",
            "MIME-Version: 1.0",
        ]
        if let contentType {
            lines.append("Content-Type: \(contentType)")
        }
        lines.append(contentsOf: extraHeaders)
        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n" + body).utf8)
    }

    private func utf8(_ data: Data?) -> String {
        guard let data else { return "" }
        return String(decoding: data, as: UTF8.self)
    }

    /// Imports the public key of `keyOwner` into `into`'s keyring.
    private func importPublicKey(of keyOwner: MailSecurityEngine, into: MailSecurityEngine) throws {
        let fingerprint = try XCTUnwrap(keyOwner.keyManager.listKeys().first?.fingerprint)
        let publicKey = try keyOwner.keyManager.exportKey(fingerprint: fingerprint)
        try into.keyManager.importKeys(publicKey)
    }

    // MARK: - PGP/MIME roundtrips

    func testPGPMimeSignRoundtrip() throws {
        let engine = try makeEngine(keys: [Self.alice])
        let message = plainMessage()
        let encoded = try engine.encode(EncodingRequest(
            message: message,
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: false
        ))
        XCTAssertTrue(encoded.isSigned)
        XCTAssertFalse(encoded.isEncrypted)
        let encodedText = utf8(encoded.rawData)
        XCTAssertTrue(encodedText.contains("multipart/signed"))
        XCTAssertTrue(encodedText.contains("application/pgp-signature"))

        let decoded = try XCTUnwrap(engine.decode(encoded.rawData))
        XCTAssertFalse(decoded.security.isEncrypted)
        XCTAssertNil(decoded.security.signingError)
        XCTAssertNil(decoded.security.encryptionError)
        let signer = try XCTUnwrap(decoded.security.signers.first)
        XCTAssertEqual(signer.status, .valid)
        XCTAssertEqual(signer.userID, Self.alice)
        // The unwrapped message shows the original content again.
        XCTAssertTrue(utf8(decoded.data).contains("Hello, Bob!"))
        XCTAssertTrue(utf8(decoded.data).contains("Content-Type: text/plain"))
    }

    func testPGPMimeEncryptRoundtrip() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: false,
            encrypt: true
        ))
        XCTAssertFalse(encoded.isSigned)
        XCTAssertTrue(encoded.isEncrypted)
        XCTAssertTrue(utf8(encoded.rawData).contains("multipart/encrypted"))
        XCTAssertTrue(utf8(encoded.rawData).contains("application/pgp-encrypted"))

        let decoded = try XCTUnwrap(engine.decode(encoded.rawData))
        XCTAssertTrue(decoded.security.isEncrypted)
        XCTAssertTrue(decoded.security.signers.isEmpty)
        XCTAssertNil(decoded.security.encryptionError)
        XCTAssertTrue(utf8(decoded.data).contains("Hello, Bob!"))
    }

    func testPGPMimeSignEncryptRoundtrip() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: true
        ))
        XCTAssertTrue(encoded.isSigned)
        XCTAssertTrue(encoded.isEncrypted)

        let decoded = try XCTUnwrap(engine.decode(encoded.rawData))
        XCTAssertTrue(decoded.security.isEncrypted)
        XCTAssertNil(decoded.security.signingError)
        XCTAssertNil(decoded.security.encryptionError)
        let signer = try XCTUnwrap(decoded.security.signers.first)
        XCTAssertEqual(signer.status, .valid)
        XCTAssertEqual(signer.userID, Self.alice)
        XCTAssertTrue(utf8(decoded.data).contains("Hello, Bob!"))
    }

    func testPGPMimeSignEncryptRSAKeys() throws {
        // RSA-3072 keys: same flow, exercising the default mail key type.
        let engine = try makeEngine(keys: [Self.alice, Self.bob], algorithm: .rsa)
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: true
        ))
        let decoded = try XCTUnwrap(engine.decode(encoded.rawData))
        XCTAssertTrue(decoded.security.isEncrypted)
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)
        XCTAssertTrue(utf8(decoded.data).contains("Hello, Bob!"))
    }

    func testMultiRecipientEncryption() throws {
        let alice = try makeEngine(keys: [Self.alice])
        let bob = try makeEngine(keys: [Self.bob])
        let carol = try makeEngine(keys: [Self.carol])

        // Alice needs both recipients' public keys; each recipient needs
        // Alice's public key to verify her signature.
        try importPublicKey(of: bob, into: alice)
        try importPublicKey(of: carol, into: alice)
        try importPublicKey(of: alice, into: bob)
        try importPublicKey(of: alice, into: carol)

        let encoded = try alice.encode(EncodingRequest(
            message: plainMessage(body: "Group secret"),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail, Self.carolEmail],
            sign: true,
            encrypt: true
        ))

        for recipient in [bob, carol] {
            let decoded = try XCTUnwrap(recipient.decode(encoded.rawData))
            XCTAssertTrue(decoded.security.isEncrypted)
            XCTAssertEqual(decoded.security.signers.first?.status, .valid)
            XCTAssertEqual(decoded.security.signers.first?.userID, Self.alice)
            XCTAssertTrue(utf8(decoded.data).contains("Group secret"))
        }
    }

    // MARK: - Inline PGP roundtrips

    func testInlineSignRoundtrip() throws {
        let engine = try makeEngine(keys: [Self.alice])
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: false,
            format: .inlinePGP
        ))
        XCTAssertTrue(encoded.isSigned)
        let encodedText = utf8(encoded.rawData)
        XCTAssertTrue(encodedText.contains("-----BEGIN PGP MESSAGE-----"))
        XCTAssertFalse(encodedText.contains("multipart/"))

        let decoded = try XCTUnwrap(engine.decode(encoded.rawData))
        XCTAssertFalse(decoded.security.isEncrypted)
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)
        XCTAssertEqual(decoded.security.signers.first?.userID, Self.alice)
        XCTAssertTrue(utf8(decoded.data).contains("Hello, Bob!"))
        XCTAssertFalse(utf8(decoded.data).contains("BEGIN PGP"))
    }

    func testInlineEncryptRoundtrip() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: false,
            encrypt: true,
            format: .inlinePGP
        ))
        XCTAssertTrue(encoded.isEncrypted)
        XCTAssertTrue(utf8(encoded.rawData).contains("-----BEGIN PGP MESSAGE-----"))

        let decoded = try XCTUnwrap(engine.decode(encoded.rawData))
        XCTAssertTrue(decoded.security.isEncrypted)
        XCTAssertTrue(decoded.security.signers.isEmpty)
        XCTAssertTrue(utf8(decoded.data).contains("Hello, Bob!"))
    }

    func testInlineSignEncryptRoundtrip() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: true,
            format: .inlinePGP
        ))
        let decoded = try XCTUnwrap(engine.decode(encoded.rawData))
        XCTAssertTrue(decoded.security.isEncrypted)
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)
        XCTAssertEqual(decoded.security.signers.first?.userID, Self.alice)
        XCTAssertTrue(utf8(decoded.data).contains("Hello, Bob!"))
    }

    func testInlineQuotedPrintableBodyRoundtrip() throws {
        // A MIME-encoded (quoted-printable) body is decoded before signing
        // and comes back as readable text.
        let engine = try makeEngine(keys: [Self.alice])
        let message = plainMessage(
            body: "Gr=C3=BC=C3=9Fe=20aus=20Berlin",
            extraHeaders: ["Content-Transfer-Encoding: quoted-printable"]
        )
        let encoded = try engine.encode(EncodingRequest(
            message: message,
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: false,
            format: .inlinePGP
        ))
        let decoded = try XCTUnwrap(engine.decode(encoded.rawData))
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)
        XCTAssertTrue(utf8(decoded.data).contains("Grüße aus Berlin"))
    }

    func testInlineMultipartMessageRejected() throws {
        let engine = try makeEngine(keys: [Self.alice])
        let message = attachmentMessage()
        XCTAssertThrowsError(try engine.encode(EncodingRequest(
            message: message,
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: false,
            format: .inlinePGP
        ))) { error in
            XCTAssertEqual(error as? MailSecurityError, .multipartNotSupportedForInline)
        }
    }

    func testInlineArmorInsideMultipartDecoded() throws {
        // Foreign-style message: an armored block inside a multipart/mixed
        // text part (not a PGP/MIME structure) is still handled.
        let engine = try makeEngine(keys: [Self.alice])
        let armored = try engine.encode(EncodingRequest(
            message: plainMessage(body: "inline secret"),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: false,
            format: .inlinePGP
        ))
        let armorText = MimeMessage.parse(armored.rawData).body
        let mixed = Data(("""
        From: \(Self.alice)\r
        To: \(Self.bob)\r
        Subject: forwarded\r
        Content-Type: multipart/mixed; boundary="mix"\r
        \r
        --mix\r
        Content-Type: text/plain\r
        \r

        """).utf8)
            + armorText
            + Data("""
            \r
            --mix\r
            Content-Type: text/plain\r
            \r
            see above\r
            --mix--\r

            """.utf8)

        let decoded = try XCTUnwrap(engine.decode(mixed))
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)
        let text = utf8(decoded.data)
        XCTAssertTrue(text.contains("inline secret"))
        XCTAssertTrue(text.contains("see above"))
        XCTAssertFalse(text.contains("BEGIN PGP MESSAGE"))
    }

    // MARK: - Content preservation

    func testPGPMimePreservesBase64BodyByteExact() throws {
        // The base64 payload must survive a sign roundtrip byte-exactly: the
        // detached signature covers the raw entity bytes.
        let engine = try makeEngine(keys: [Self.alice])
        let base64Body = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\r\n"
        let message = plainMessage(
            body: base64Body,
            extraHeaders: ["Content-Transfer-Encoding: base64"]
        )
        let encoded = try engine.encode(EncodingRequest(
            message: message,
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: false
        ))
        let decoded = try XCTUnwrap(engine.decode(encoded.rawData))
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)
        XCTAssertTrue(utf8(decoded.data).contains(base64Body))
        XCTAssertTrue(utf8(decoded.data).contains("Content-Transfer-Encoding: base64"))
    }

    func testNonASCIIBodyRoundtrip() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let body = "Grüße, 日本語のテキスト, emoji 🎉, and ünïcödé everywhere"
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(body: body),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: true
        ))
        let decoded = try XCTUnwrap(engine.decode(encoded.rawData))
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)
        XCTAssertTrue(utf8(decoded.data).contains(body))
    }

    func testAttachmentRoundtrip() throws {
        // A multipart/mixed message carrying an attachment survives
        // PGP/MIME sign+encrypt with the attachment bytes intact.
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let message = attachmentMessage()
        let encoded = try engine.encode(EncodingRequest(
            message: message,
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: true
        ))
        let decoded = try XCTUnwrap(engine.decode(encoded.rawData))
        XCTAssertTrue(decoded.security.isEncrypted)
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)
        let text = utf8(decoded.data)
        XCTAssertTrue(text.contains("multipart/mixed"))
        XCTAssertTrue(text.contains("filename=\"file.bin\""))
        // Base64 attachment payload preserved byte-exactly.
        XCTAssertTrue(text.contains("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="))
    }

    /// Message with an attachment-shaped MIME part (multipart/mixed with a
    /// base64 application/octet-stream part).
    private func attachmentMessage() -> Data {
        Data(("""
        From: \(Self.alice)\r
        To: \(Self.bob)\r
        Subject: with attachment\r
        MIME-Version: 1.0\r
        Content-Type: multipart/mixed; boundary="attach-boundary"\r
        \r
        --attach-boundary\r
        Content-Type: text/plain; charset="utf-8"\r
        \r
        See attached.\r
        --attach-boundary\r
        Content-Type: application/octet-stream; name="file.bin"\r
        Content-Transfer-Encoding: base64\r
        Content-Disposition: attachment; filename="file.bin"\r
        \r
        AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\r
        --attach-boundary--\r

        """).utf8)
    }

    // MARK: - Error reporting

    func testMissingRecipientKeyThrows() throws {
        let engine = try makeEngine(keys: [Self.alice])
        XCTAssertThrowsError(try engine.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: ["nobody@example.com"],
            sign: false,
            encrypt: true
        ))) { error in
            guard case let MailSecurityError.missingRecipientKeys(missing) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(missing, ["nobody@example.com"])
        }
    }

    func testNoSecretKeyForSenderThrows() throws {
        let engine = try makeEngine(keys: [Self.alice])
        XCTAssertThrowsError(try engine.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.bobEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: false
        ))) { error in
            XCTAssertEqual(error as? MailSecurityError, .noSecretKeyForSender(Self.bobEmail))
        }
    }

    func testWrongPassphraseFailsDecryption() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: false,
            encrypt: true
        ))

        // Same keyring directory, wrong passphrase.
        let directory = engine.keyManager.directory
        let wrongEngine = try makeEngine(directory: directory, password: "wrong")
        let decoded = try XCTUnwrap(wrongEngine.decode(encoded.rawData))
        XCTAssertNil(decoded.data)
        XCTAssertNotNil(decoded.security.encryptionError)
    }

    func testWrongPassphraseFailsSigning() throws {
        // Keys protected by the right passphrase, but the provider answers
        // signing requests with a wrong one.
        let directory = makeTempDirectory()
        _ = try makeEngine(keys: [Self.alice], directory: directory)
        let wrongEngine = try makeEngine(directory: directory, password: "wrong")
        XCTAssertThrowsError(try wrongEngine.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: false
        )))
    }

    func testTamperedSignatureFailsVerification() throws {
        let engine = try makeEngine(keys: [Self.alice])
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(body: "Hello, Bob!"),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: false
        ))
        // Modify the signed content inside the multipart/signed structure.
        var tampered = utf8(encoded.rawData)
        tampered = tampered.replacingOccurrences(of: "Hello, Bob!", with: "Hello, Mallory!")
        let decoded = try XCTUnwrap(engine.decode(Data(tampered.utf8)))
        XCTAssertEqual(decoded.security.signers.first?.status, .invalid)
        XCTAssertNotNil(decoded.security.signingError)
        XCTAssertFalse(decoded.security.hasValidSignature)
    }

    func testTamperedCiphertextFailsDecryption() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: false,
            encrypt: true
        ))
        // Flip one byte inside the armored ciphertext, just ahead of the
        // END marker; the integrity protection (MDC) must catch it.
        var bytes = encoded.rawData
        let endMarker = Data("-----END PGP MESSAGE-----".utf8)
        let endRange = try XCTUnwrap(bytes.range(of: endMarker))
        bytes[endRange.lowerBound - 10] ^= 0x01
        let decoded = try XCTUnwrap(engine.decode(bytes))
        XCTAssertNil(decoded.data)
        XCTAssertNotNil(decoded.security.encryptionError)
    }

    func testUnsignedMessageReturnsNil() throws {
        let engine = try makeEngine(keys: [Self.alice])
        XCTAssertNil(try engine.decode(plainMessage()))
        // A multipart message without OpenPGP content is not ours either.
        XCTAssertNil(try engine.decode(attachmentMessage()))
    }

    func testUnknownSignerReported() throws {
        let alice = try makeEngine(keys: [Self.alice])
        let bob = try makeEngine(keys: [Self.bob])
        // Bob can decrypt (his key is inside via Alice's copy) — set up
        // Alice to encrypt to Bob, but Bob does not have Alice's public key.
        try importPublicKey(of: bob, into: alice)
        let encoded = try alice.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: false
        ))
        let decoded = try XCTUnwrap(bob.decode(encoded.rawData))
        XCTAssertEqual(decoded.security.signers.first?.status, .signerUnknown)
        XCTAssertNil(decoded.security.signers.first?.fingerprint)
        XCTAssertEqual(
            decoded.security.signingError as? MailSecurityError,
            .signatureUnknownSigner
        )
    }

    func testEncodingStatus() throws {
        let alice = try makeEngine(keys: [Self.alice])
        let bob = try makeEngine(keys: [Self.bob])
        try importPublicKey(of: bob, into: alice)

        let status = try alice.encodingStatus(
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail, "nobody@example.com"]
        )
        XCTAssertTrue(status.canSign)
        XCTAssertFalse(status.canEncrypt)
        XCTAssertEqual(status.missingRecipientKeys, ["nobody@example.com"])

        let complete = try alice.encodingStatus(
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail]
        )
        XCTAssertTrue(complete.canSign)
        XCTAssertTrue(complete.canEncrypt)
        XCTAssertTrue(complete.missingRecipientKeys.isEmpty)

        let noSecret = try bob.encodingStatus(sender: Self.aliceEmail, recipients: [])
        XCTAssertFalse(noSecret.canSign)
    }

    // MARK: - KeyManager

    func testKeyManagerGenerateListExportDelete() throws {
        let engine = try makeEngine()
        let manager = engine.keyManager
        XCTAssertEqual(try manager.listKeys(), [])

        let rsa = try manager.generateKey(userID: Self.alice, algorithm: .rsa)
        XCTAssertEqual(rsa.primaryUserID, Self.alice)
        XCTAssertTrue(rsa.hasSecret)
        XCTAssertEqual(rsa.fingerprint.count, 40)

        let ecdsa = try manager.generateKey(userID: Self.bob, algorithm: .ecdsa)
        XCTAssertEqual(ecdsa.primaryUserID, Self.bob)

        let keys = try manager.listKeys()
        XCTAssertEqual(keys.count, 2)
        XCTAssertEqual(keys.map(\.fingerprint).sorted(), [rsa.fingerprint, ecdsa.fingerprint].sorted())

        // Armored exports carry the expected armor headers.
        let publicExport = try manager.exportKey(fingerprint: rsa.fingerprint)
        XCTAssertTrue(utf8(publicExport).contains("BEGIN PGP PUBLIC KEY BLOCK"))
        let secretExport = try manager.exportKey(fingerprint: rsa.fingerprint, secret: true)
        XCTAssertTrue(utf8(secretExport).contains("BEGIN PGP PRIVATE KEY BLOCK"))

        try manager.deleteKey(fingerprint: rsa.fingerprint)
        let remaining = try manager.listKeys()
        XCTAssertEqual(remaining.count, 1)
        XCTAssertEqual(remaining.first?.fingerprint, ecdsa.fingerprint)

        XCTAssertThrowsError(try manager.deleteKey(fingerprint: rsa.fingerprint))
    }

    func testKeyManagerPersistenceAcrossInstances() throws {
        let directory = makeTempDirectory()
        let first = try makeEngine(keys: [Self.alice], directory: directory)
        let fingerprint = try XCTUnwrap(first.keyManager.listKeys().first?.fingerprint)
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: directory.appendingPathComponent("pubring.gpg").path
        ))
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: directory.appendingPathComponent("secring.gpg").path
        ))

        // A second manager on the same directory sees the same keys, and a
        // message encrypted by the first engine decrypts with the second.
        let second = try makeEngine(directory: directory)
        XCTAssertEqual(try second.keyManager.listKeys().map(\.fingerprint), [fingerprint])

        let encoded = try second.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.aliceEmail],
            sign: true,
            encrypt: true
        ))
        let decoded = try XCTUnwrap(second.decode(encoded.rawData))
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)

        // Deleting the last key removes the keyring files entirely.
        try second.keyManager.deleteKey(fingerprint: fingerprint)
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: directory.appendingPathComponent("secring.gpg").path
        ))
        let third = try makeEngine(directory: directory)
        XCTAssertEqual(try third.keyManager.listKeys(), [])
    }

    func testKeyManagerImportPublicThenSecret() throws {
        let source = try makeEngine(keys: [Self.alice], algorithm: .rsa)
        let fingerprint = try XCTUnwrap(source.keyManager.listKeys().first?.fingerprint)
        let publicData = try source.keyManager.exportKey(fingerprint: fingerprint)
        let secretData = try source.keyManager.exportKey(fingerprint: fingerprint, secret: true)

        let destination = try makeEngine()
        let imported = try destination.keyManager.importKeys(publicData)
        XCTAssertEqual(imported.count, 1)
        XCTAssertEqual(imported.first?.fingerprint, fingerprint)
        XCTAssertEqual(imported.first?.primaryUserID, Self.alice)
        XCTAssertEqual(try destination.keyManager.listKeys().first?.hasSecret, false)

        try destination.keyManager.importKeys(secretData)
        XCTAssertEqual(try destination.keyManager.listKeys().first?.hasSecret, true)
    }

    func testRecipientResolutionByEmail() throws {
        let engine = try makeEngine(keys: [Self.alice])
        let manager = engine.keyManager
        // Full user ID, bare email, case-insensitive email.
        XCTAssertNotNil(try manager.publicKey(for: Self.alice))
        XCTAssertNotNil(try manager.publicKey(for: Self.aliceEmail))
        XCTAssertNotNil(try manager.publicKey(for: "ALICE@EXAMPLE.COM"))
        XCTAssertNil(try manager.publicKey(for: "nobody@example.com"))

        XCTAssertNotNil(try manager.secretKey(forUserID: Self.aliceEmail))
    }

    // MARK: - Key metadata round-trip

    func testKeyInfoMetadataForRSA() throws {
        let engine = try makeEngine()
        let manager = engine.keyManager

        let info = try manager.generateKey(
            userID: Self.alice,
            algorithm: .rsa,
            expirationSeconds: 63072000 // 2 years
        )

        XCTAssertEqual(info.primaryUserID, Self.alice)
        XCTAssertTrue(info.hasSecret)
        XCTAssertEqual(info.algorithm, "RSA")
        XCTAssertEqual(info.bits, 3072)
        XCTAssertFalse(info.isRevoked)
        XCTAssertEqual(info.subkeyCount, 1)
        XCTAssertNotNil(info.expirationDate)

        let subkeys = try manager.subkeys(for: info.fingerprint)
        XCTAssertEqual(subkeys.count, 1)
        XCTAssertEqual(subkeys.first?.algorithm, "RSA")

        // Export and re-import; metadata must survive.
        let publicData = try manager.exportKey(fingerprint: info.fingerprint)
        let fresh = try makeEngine()
        let imported = try fresh.keyManager.importKeys(publicData)
        XCTAssertEqual(imported.first?.fingerprint, info.fingerprint)
        XCTAssertEqual(imported.first?.algorithm, "RSA")
        XCTAssertEqual(imported.first?.bits, 3072)
        XCTAssertEqual(imported.first?.subkeyCount, 1)
        XCTAssertFalse(imported.first?.hasSecret ?? true)
    }

    func testKeyInfoMetadataForEd25519() throws {
        let engine = try makeEngine()
        let manager = engine.keyManager

        let info = try manager.generateKey(
            userID: Self.bob,
            algorithm: .ed25519,
            expirationSeconds: 31536000 // 1 year
        )

        XCTAssertEqual(info.primaryUserID, Self.bob)
        XCTAssertTrue(info.hasSecret)
        XCTAssertEqual(info.algorithm, "EDDSA")
        XCTAssertEqual(info.bits, 255)
        XCTAssertEqual(info.subkeyCount, 1)
        XCTAssertNotNil(info.expirationDate)

        let subkeys = try manager.subkeys(for: info.fingerprint)
        XCTAssertEqual(subkeys.count, 1)
        XCTAssertEqual(subkeys.first?.algorithm, "ECDH")
        XCTAssertEqual(subkeys.first?.curve, "Curve25519")
    }

    func testRevocationCertificateIsSaved() throws {
        let engine = try makeEngine()
        let manager = engine.keyManager

        let info = try manager.generateKey(userID: Self.alice, algorithm: .rsa)
        let url = try manager.saveRevocationCertificate(fingerprint: info.fingerprint)

        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
        let data = try Data(contentsOf: url)
        // librnp armors revocation signatures inside a public-key block.
        XCTAssertTrue(utf8(data).contains("BEGIN PGP"))
    }

    // MARK: - Keychain passphrase storage

    func testKeychainStoresAndRetrievesPassphrase() {
        KeychainPassphraseStore.reset()
        let passphrase = KeychainPassphraseStore.sharedPassphrase()
        XCTAssertFalse(passphrase.isEmpty)

        let second = KeychainPassphraseStore.sharedPassphrase()
        XCTAssertEqual(second, passphrase)
    }

    func testKeychainBiometryFallbackReturnsWarningOrNil() {
        KeychainPassphraseStore.reset()
        let (biometricPassphrase, warning) = KeychainPassphraseStore.sharedPassphrase(requiresBiometry: true)
        // On Macs without Touch ID and in unsigned builds the fallback path
        // returns a warning and keeps the passphrase in the plain item;
        // where biometric storage works the warning is nil and the
        // passphrase moves behind Touch ID. Either outcome is acceptable.
        if let warning = warning {
            XCTAssertFalse(warning.message.isEmpty)
            XCTAssertFalse(KeychainPassphraseStore.isBiometricProtectionEnabled)
        } else {
            XCTAssertTrue(KeychainPassphraseStore.isBiometricProtectionEnabled)
        }

        // Either way the same passphrase is served back to callers (from the
        // session cache, so no Touch ID prompt appears in the test runner).
        let passphrase = KeychainPassphraseStore.sharedPassphrase()
        XCTAssertFalse(passphrase.isEmpty)
        XCTAssertEqual(passphrase, biometricPassphrase)
    }

    // MARK: - Trust and key-change conflicts

    func testTrustConflictBlocksEncryption() throws {
        // Alice has Bob's old key. Importing a new key for Bob creates a
        // conflict, and encryption to Bob must fail until it is resolved.
        let alice = try makeEngine(keys: [Self.alice])
        let bob = try makeEngine(keys: [Self.bob])
        try importPublicKey(of: bob, into: alice)

        // Generate a second Bob key in a fresh engine and import it into
        // Alice's keyring to simulate a key change.
        let bob2 = try makeEngine(keys: [Self.bob])
        let bob2Fingerprint = try XCTUnwrap(bob2.keyManager.listKeys().first?.fingerprint)
        let bob2Public = try bob2.keyManager.exportKey(fingerprint: bob2Fingerprint)
        _ = try alice.keyManager.importKeys(bob2Public)

        XCTAssertThrowsError(try alice.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: false,
            encrypt: true
        ))) { error in
            guard case let MailSecurityError.trustConflict(recipient) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(recipient, Self.bobEmail)
        }
    }

    func testTrustConflictOnSenderDoesNotBlockEncryption() throws {
        // A key-change conflict on the sender's own address must not block
        // encryption: the sender's own key is implicitly trusted
        // (encrypt-to-self).
        let alice = try makeEngine(keys: [Self.alice])
        let bob = try makeEngine(keys: [Self.bob])
        try importPublicKey(of: bob, into: alice)

        let aliceFingerprint = try XCTUnwrap(alice.keyManager.listKeys().first?.fingerprint)
        try alice.keyManager.trustStore.noteSeen(email: Self.aliceEmail, fingerprint: aliceFingerprint)
        try alice.keyManager.trustStore.noteSeen(
            email: Self.aliceEmail,
            fingerprint: "DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444"
        )
        XCTAssertTrue(alice.keyManager.trustStore.hasConflict(forEmail: Self.aliceEmail))

        let encoded = try alice.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail, Self.aliceEmail],
            sign: true,
            encrypt: true
        ))
        XCTAssertTrue(encoded.isEncrypted)

        let decoded = try XCTUnwrap(alice.decode(encoded.rawData))
        XCTAssertTrue(decoded.security.isEncrypted)
        XCTAssertNil(decoded.security.encryptionError)
        XCTAssertTrue(utf8(decoded.data).contains("Hello, Bob!"))
    }

    func testMarkVerifiedAllowsEncryptionAfterConflict() throws {
        let alice = try makeEngine(keys: [Self.alice])
        let bob = try makeEngine(keys: [Self.bob])
        try importPublicKey(of: bob, into: alice)

        let bob2 = try makeEngine(keys: [Self.bob])
        let bob2Fingerprint = try XCTUnwrap(bob2.keyManager.listKeys().first?.fingerprint)
        let bob2Public = try bob2.keyManager.exportKey(fingerprint: bob2Fingerprint)
        let imported = try alice.keyManager.importKeys(bob2Public)
        XCTAssertFalse(imported.isEmpty)

        // Verify the new key and remove the old one to simulate retirement.
        try alice.keyManager.trustStore.markVerified(fingerprint: bob2Fingerprint)
        let bobFingerprint = try XCTUnwrap(bob.keyManager.listKeys().first?.fingerprint)
        try alice.keyManager.deleteKey(fingerprint: bobFingerprint)

        let encoded = try alice.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: false,
            encrypt: true
        ))
        XCTAssertTrue(encoded.isEncrypted)
    }

    func testRejectConflictEncryptsToOldKey() throws {
        // Alice has Bob's old key. A new key for Bob appears, raising a
        // conflict; rejecting it keeps the old binding, so encryption
        // proceeds to Bob's old key instead of the rejected new key.
        let alice = try makeEngine(keys: [Self.alice])
        let bob = try makeEngine(keys: [Self.bob])
        try importPublicKey(of: bob, into: alice)

        let bob2 = try makeEngine(keys: [Self.bob])
        let bob2Fingerprint = try XCTUnwrap(bob2.keyManager.listKeys().first?.fingerprint)
        let bob2Public = try bob2.keyManager.exportKey(fingerprint: bob2Fingerprint)
        _ = try alice.keyManager.importKeys(bob2Public)
        XCTAssertTrue(alice.keyManager.trustStore.hasConflict(forEmail: Self.bobEmail))

        try alice.keyManager.trustStore.rejectConflict(email: Self.bobEmail, newFpr: bob2Fingerprint)
        XCTAssertFalse(alice.keyManager.trustStore.hasConflict(forEmail: Self.bobEmail))
        XCTAssertEqual(alice.keyManager.trustStore.state(forFpr: bob2Fingerprint), .problem)

        let encoded = try alice.encode(EncodingRequest(
            message: plainMessage(),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: false,
            encrypt: true
        ))
        XCTAssertTrue(encoded.isEncrypted)

        // The old key can decrypt the message...
        let decoded = try XCTUnwrap(bob.decode(encoded.rawData))
        XCTAssertTrue(decoded.security.isEncrypted)
        XCTAssertNil(decoded.security.encryptionError)
        XCTAssertTrue(utf8(decoded.data).contains("Hello, Bob!"))

        // ...the rejected new key cannot.
        let rejected = try XCTUnwrap(bob2.decode(encoded.rawData))
        XCTAssertNotNil(rejected.security.encryptionError)
    }

    // MARK: - Signer trust view model mapping

    func testSignerTrustMappingExhaustive() {
        let cases: [(RnpSignatureStatus, TrustState, SignerTrustIntent, Bool)] = [
            (.valid, .verified, .positive, false),
            (.valid, .unverified, .neutral, true),
            (.valid, .problem, .critical, true),
            (.expired, .verified, .caution, false),
            (.expired, .unverified, .caution, true),
            (.expired, .problem, .critical, true),
            (.signerUnknown, .verified, .critical, false),
            (.signerUnknown, .unverified, .critical, false),
            (.signerUnknown, .problem, .critical, false),
            // Invalid signatures offer the key detail view (reason unknown
            // here, so the signing key may be known); see
            // InvalidSignatureWarningTests for the per-reason link rules.
            (.invalid, .verified, .critical, true),
            (.invalid, .unverified, .critical, true),
            (.invalid, .problem, .critical, true),
            (.unknown, .verified, .caution, false),
            (.unknown, .unverified, .caution, true),
            (.unknown, .problem, .critical, true),
        ]

        for (status, trust, expectedIntent, review) in cases {
            let model = mapSignerTrust(status: status, trust: trust)
            XCTAssertEqual(
                model.intent,
                expectedIntent,
                "intent mismatch for status=\(status), trust=\(trust)"
            )
            XCTAssertEqual(
                model.reviewDeepLink,
                review,
                "review link mismatch for status=\(status), trust=\(trust)"
            )
            XCTAssertFalse(model.label.isEmpty)
            XCTAssertFalse(model.detail.isEmpty)
        }
    }
}

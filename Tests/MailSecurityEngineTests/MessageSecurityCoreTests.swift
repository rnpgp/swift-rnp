//
//  MessageSecurityCoreTests.swift
//  swift-rnp
//
//  Unit tests for the MailKit-independent message-security core.
//

import XCTest
@testable import MailSecurityEngine

final class MessageSecurityCoreTests: XCTestCase {
    private static let alice = "Alice <alice@example.com>"
    private static let aliceEmail = "alice@example.com"
    private static let bob = "Bob <bob@example.com>"
    private static let bobEmail = "bob@example.com"
    private static let password = "test-password"

    private var tempDirectories: [URL] = []

    override func tearDownWithError() throws {
        for url in tempDirectories {
            try? FileManager.default.removeItem(at: url)
        }
        tempDirectories = []
    }

    private func makeTempDirectory() -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("swift-rnp-tests")
            .appendingPathComponent(UUID().uuidString)
        tempDirectories.append(url)
        return url
    }

    private func makeEngine(keys userIDs: [String] = []) throws -> MailSecurityEngine {
        let engine = try MailSecurityEngine(
            directory: makeTempDirectory(),
            passphraseProvider: { _ in Self.password }
        )
        for userID in userIDs {
            try engine.keyManager.generateKey(userID: userID, algorithm: .ecdsa)
        }
        return engine
    }

    private func makeCore(keys userIDs: [String] = []) throws -> MessageSecurityCore {
        MessageSecurityCore(engine: try makeEngine(keys: userIDs))
    }

    private func plainMessage(
        from: String = "alice@example.com",
        to: String = "bob@example.com",
        body: String = "Hello, Bob!"
    ) -> Data {
        let lines = [
            "From: \(from)",
            "To: \(to)",
            "Subject: core test",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=\"utf-8\"",
        ]
        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n" + body).utf8)
    }

    // MARK: - Mocks

    private struct MockMessage: MailMessage {
        var rawData: Data?
        var fromAddress: String
        var recipientAddresses: [String]
        var isSending: Bool
    }

    private struct MockComposeContext: MailComposeContext {
        var shouldSign: Bool
        var shouldEncrypt: Bool
    }

    private struct MockSigner: MailMessageSigner {
        var signerEmailAddresses: [String]
        var signerLabel: String
        var context: Data
    }

    // MARK: - getEncodingStatus

    func testGetEncodingStatusWithKey() throws {
        let core = try makeCore(keys: [Self.alice])
        let message = MockMessage(
            rawData: nil,
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: false)
        let status = core.getEncodingStatus(for: message, composeContext: context)

        XCTAssertTrue(status.canSign)
        XCTAssertFalse(status.canEncrypt)
        XCTAssertEqual(status.addressesFailingEncryption, [Self.bobEmail])
    }

    func testGetEncodingStatusWithoutKey() throws {
        let core = try makeCore()
        let message = MockMessage(
            rawData: nil,
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: true)
        let status = core.getEncodingStatus(for: message, composeContext: context)

        XCTAssertFalse(status.canSign)
        XCTAssertFalse(status.canEncrypt)
        XCTAssertEqual(status.addressesFailingEncryption, [Self.bobEmail])
    }

    // MARK: - getEncodingStatus trust warnings

    func testGetEncodingStatusUnverifiedRecipientWarnsButDoesNotBlock() throws {
        let core = try makeCore(keys: [Self.alice, Self.bob])
        let message = MockMessage(
            rawData: nil,
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: true)
        let status = core.getEncodingStatus(for: message, composeContext: context)

        XCTAssertTrue(status.canSign)
        XCTAssertTrue(status.canEncrypt)
        XCTAssertEqual(status.addressesFailingEncryption, [])
        let warning = try XCTUnwrap(status.securityError as? RecipientTrustWarning)
        XCTAssertEqual(warning.issues, [RecipientTrustIssue(recipient: Self.bobEmail, kind: .unverified)])
        XCTAssertTrue(warning.blockedRecipients.isEmpty)
    }

    func testGetEncodingStatusVerifiedRecipientHasNoWarning() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let core = MessageSecurityCore(engine: engine)
        let bobFingerprint = try XCTUnwrap(fingerprint(of: Self.bob, in: engine))
        try core.trustStore.noteSeen(email: Self.bobEmail, fingerprint: bobFingerprint)
        try core.trustStore.markVerified(fingerprint: bobFingerprint)

        let message = MockMessage(
            rawData: nil,
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: true)
        let status = core.getEncodingStatus(for: message, composeContext: context)

        XCTAssertTrue(status.canEncrypt)
        XCTAssertEqual(status.addressesFailingEncryption, [])
        XCTAssertNil(status.securityError)
    }

    func testGetEncodingStatusProblemRecipientBlocksEncryption() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let core = MessageSecurityCore(engine: engine)
        let bobFingerprint = try XCTUnwrap(fingerprint(of: Self.bob, in: engine))
        try core.trustStore.noteSeen(email: Self.bobEmail, fingerprint: bobFingerprint)
        try core.trustStore.markProblem(fingerprint: bobFingerprint)

        let message = MockMessage(
            rawData: nil,
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: true)
        let status = core.getEncodingStatus(for: message, composeContext: context)

        XCTAssertFalse(status.canEncrypt)
        XCTAssertEqual(status.addressesFailingEncryption, [Self.bobEmail])
        let warning = try XCTUnwrap(status.securityError as? RecipientTrustWarning)
        XCTAssertEqual(warning.issues, [RecipientTrustIssue(recipient: Self.bobEmail, kind: .problem)])
        XCTAssertEqual(warning.blockedRecipients, [Self.bobEmail])
    }

    func testGetEncodingStatusConflictRecipientBlocksEncryption() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let core = MessageSecurityCore(engine: engine)
        let bobFingerprint = try XCTUnwrap(fingerprint(of: Self.bob, in: engine))
        try core.trustStore.noteSeen(email: Self.bobEmail, fingerprint: bobFingerprint)
        // A different key appearing for the same address opens a conflict.
        try core.trustStore.noteSeen(
            email: Self.bobEmail,
            fingerprint: "DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444"
        )

        let message = MockMessage(
            rawData: nil,
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: true)
        let status = core.getEncodingStatus(for: message, composeContext: context)

        XCTAssertFalse(status.canEncrypt)
        XCTAssertEqual(status.addressesFailingEncryption, [Self.bobEmail])
        let warning = try XCTUnwrap(status.securityError as? RecipientTrustWarning)
        XCTAssertEqual(warning.issues, [RecipientTrustIssue(recipient: Self.bobEmail, kind: .conflict)])
    }

    func testGetEncodingStatusWarningSuppressedWhenNotEncrypting() throws {
        let core = try makeCore(keys: [Self.alice, Self.bob])
        let message = MockMessage(
            rawData: nil,
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: false)
        let status = core.getEncodingStatus(for: message, composeContext: context)

        XCTAssertTrue(status.canEncrypt)
        XCTAssertEqual(status.addressesFailingEncryption, [])
        XCTAssertNil(status.securityError)
    }

    func testRecipientTrustWarningDescriptionListsAllIssues() {
        let warning = RecipientTrustWarning(issues: [
            RecipientTrustIssue(recipient: "a@example.com", kind: .conflict),
            RecipientTrustIssue(recipient: "b@example.com", kind: .problem),
            RecipientTrustIssue(recipient: "c@example.com", kind: .unverified),
        ])
        let description = warning.errorDescription ?? ""
        XCTAssertTrue(description.contains("a@example.com"))
        XCTAssertTrue(description.contains("b@example.com"))
        XCTAssertTrue(description.contains("c@example.com"))
        XCTAssertEqual(warning.blockedRecipients, ["a@example.com", "b@example.com"])
    }

    /// Fingerprint of the key whose primary user ID equals `userID`.
    private func fingerprint(of userID: String, in engine: MailSecurityEngine) throws -> String? {
        try engine.keyManager.listKeys().first { $0.primaryUserID == userID }?.fingerprint
    }

    // MARK: - encode

    func testEncodeSignOnly() throws {
        let core = try makeCore(keys: [Self.alice])
        let message = MockMessage(
            rawData: plainMessage(),
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: false)
        let result = core.encode(message, composeContext: context)

        XCTAssertNotNil(result.encodedMessage)
        XCTAssertTrue(result.encodedMessage?.isSigned ?? false)
        XCTAssertFalse(result.encodedMessage?.isEncrypted ?? true)
        XCTAssertNil(result.signingError)
        XCTAssertNil(result.encryptionError)
    }

    func testEncodeNotSendingReturnsNoEncoding() throws {
        let core = try makeCore(keys: [Self.alice])
        let message = MockMessage(
            rawData: plainMessage(),
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: false
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: false)
        let result = core.encode(message, composeContext: context)

        XCTAssertNil(result.encodedMessage)
        XCTAssertNil(result.signingError)
        XCTAssertNil(result.encryptionError)
    }

    func testEncodeMissingSecretKeyReturnsSigningError() throws {
        let core = try makeCore()
        let message = MockMessage(
            rawData: plainMessage(),
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: false)
        let result = core.encode(message, composeContext: context)

        XCTAssertNil(result.encodedMessage)
        XCTAssertNotNil(result.signingError)
        XCTAssertNil(result.encryptionError)
    }

    func testEncodeMissingRecipientKeyReturnsEncryptionError() throws {
        let core = try makeCore(keys: [Self.alice])
        let message = MockMessage(
            rawData: plainMessage(),
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: false, shouldEncrypt: true)
        let result = core.encode(message, composeContext: context)

        XCTAssertNil(result.encodedMessage)
        XCTAssertNil(result.signingError)
        XCTAssertNotNil(result.encryptionError)
    }

    // MARK: - encode encrypt-to-self

    /// Imports the public key of `keyOwner` into `into`'s keyring.
    private func importPublicKey(of keyOwner: MailSecurityEngine, into: MailSecurityEngine) throws {
        let fingerprint = try XCTUnwrap(keyOwner.keyManager.listKeys().first?.fingerprint)
        let publicKey = try keyOwner.keyManager.exportKey(fingerprint: fingerprint)
        try into.keyManager.importKeys(publicKey)
    }

    private func utf8(_ data: Data?) -> String {
        guard let data else { return "" }
        return String(decoding: data, as: UTF8.self)
    }

    func testEncodeEncryptToSelfSenderCanDecrypt() throws {
        let aliceEngine = try makeEngine(keys: [Self.alice])
        let bobEngine = try makeEngine(keys: [Self.bob])
        // Alice needs Bob's public key to encrypt; Bob needs Alice's public
        // key to verify her signature.
        try importPublicKey(of: bobEngine, into: aliceEngine)
        try importPublicKey(of: aliceEngine, into: bobEngine)

        let aliceCore = MessageSecurityCore(engine: aliceEngine)
        let bobCore = MessageSecurityCore(engine: bobEngine)

        let message = MockMessage(
            rawData: plainMessage(),
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: true)
        let result = aliceCore.encode(message, composeContext: context)
        let encoded = try XCTUnwrap(result.encodedMessage)
        XCTAssertTrue(encoded.isSigned)
        XCTAssertTrue(encoded.isEncrypted)

        // The recipient can decrypt.
        let bobDecoded = try XCTUnwrap(bobCore.decodedMessage(forMessageData: encoded.rawData))
        XCTAssertTrue(bobDecoded.securityInformation.isEncrypted)
        XCTAssertNil(bobDecoded.securityInformation.encryptionError)
        XCTAssertTrue(utf8(bobDecoded.data).contains("Hello, Bob!"))

        // Encrypt-to-self: the sender can decrypt their own sent message.
        let aliceDecoded = try XCTUnwrap(aliceCore.decodedMessage(forMessageData: encoded.rawData))
        XCTAssertTrue(aliceDecoded.securityInformation.isEncrypted)
        XCTAssertNil(aliceDecoded.securityInformation.encryptionError)
        XCTAssertTrue(utf8(aliceDecoded.data).contains("Hello, Bob!"))
    }

    func testEncodeEncryptWithoutSenderKeyStillSucceeds() throws {
        // Only Bob's key exists: the sender has no key, so encrypt-to-self
        // does not apply and must not fail the send.
        let core = try makeCore(keys: [Self.bob])
        let message = MockMessage(
            rawData: plainMessage(),
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: false, shouldEncrypt: true)
        let result = core.encode(message, composeContext: context)

        let encoded = try XCTUnwrap(result.encodedMessage)
        XCTAssertFalse(encoded.isSigned)
        XCTAssertTrue(encoded.isEncrypted)
        XCTAssertNil(result.signingError)
        XCTAssertNil(result.encryptionError)

        let decoded = try XCTUnwrap(core.decodedMessage(forMessageData: encoded.rawData))
        XCTAssertTrue(decoded.securityInformation.isEncrypted)
        XCTAssertNil(decoded.securityInformation.encryptionError)
    }

    func testEncodeEncryptToSelfIgnoresSenderTrustConflict() throws {
        let aliceEngine = try makeEngine(keys: [Self.alice])
        let bobEngine = try makeEngine(keys: [Self.bob])
        try importPublicKey(of: bobEngine, into: aliceEngine)
        let aliceCore = MessageSecurityCore(engine: aliceEngine)

        // A different key appearing for the sender's own address opens a
        // conflict; the sender's own key is implicitly trusted, so the
        // conflict must not block encrypting to self.
        let aliceFingerprint = try XCTUnwrap(fingerprint(of: Self.alice, in: aliceEngine))
        try aliceCore.trustStore.noteSeen(email: Self.aliceEmail, fingerprint: aliceFingerprint)
        try aliceCore.trustStore.noteSeen(
            email: Self.aliceEmail,
            fingerprint: "DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444"
        )
        XCTAssertTrue(aliceCore.trustStore.hasConflict(forEmail: Self.aliceEmail))

        let message = MockMessage(
            rawData: plainMessage(),
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: true)
        let result = aliceCore.encode(message, composeContext: context)
        let encoded = try XCTUnwrap(result.encodedMessage)
        XCTAssertTrue(encoded.isEncrypted)

        let decoded = try XCTUnwrap(aliceCore.decodedMessage(forMessageData: encoded.rawData))
        XCTAssertNil(decoded.securityInformation.encryptionError)
        XCTAssertTrue(utf8(decoded.data).contains("Hello, Bob!"))
    }

    func testEncodeEncryptToSelfIgnoresSenderProblemState() throws {
        let aliceEngine = try makeEngine(keys: [Self.alice])
        let bobEngine = try makeEngine(keys: [Self.bob])
        try importPublicKey(of: bobEngine, into: aliceEngine)
        let aliceCore = MessageSecurityCore(engine: aliceEngine)

        // The sender's own key marked as a problem key (e.g. superseded) must
        // not block encrypting to self.
        let aliceFingerprint = try XCTUnwrap(fingerprint(of: Self.alice, in: aliceEngine))
        try aliceCore.trustStore.noteSeen(email: Self.aliceEmail, fingerprint: aliceFingerprint)
        try aliceCore.trustStore.markProblem(fingerprint: aliceFingerprint)

        let message = MockMessage(
            rawData: plainMessage(),
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: true)
        let result = aliceCore.encode(message, composeContext: context)
        let encoded = try XCTUnwrap(result.encodedMessage)
        XCTAssertTrue(encoded.isEncrypted)

        let decoded = try XCTUnwrap(aliceCore.decodedMessage(forMessageData: encoded.rawData))
        XCTAssertNil(decoded.securityInformation.encryptionError)
    }

    func testGetEncodingStatusDoesNotFlagSenderWithConflict() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let core = MessageSecurityCore(engine: engine)

        // Conflict on the sender's own address; the sender also appears as an
        // explicit recipient (sending to themselves).
        let aliceFingerprint = try XCTUnwrap(fingerprint(of: Self.alice, in: engine))
        try core.trustStore.noteSeen(email: Self.aliceEmail, fingerprint: aliceFingerprint)
        try core.trustStore.noteSeen(
            email: Self.aliceEmail,
            fingerprint: "DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444"
        )

        let message = MockMessage(
            rawData: nil,
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.aliceEmail, Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: true)
        let status = core.getEncodingStatus(for: message, composeContext: context)

        XCTAssertTrue(status.canSign)
        XCTAssertTrue(status.canEncrypt)
        // The sender must not be flagged as a failing recipient.
        XCTAssertEqual(status.addressesFailingEncryption, [])
        let warning = try XCTUnwrap(status.securityError as? RecipientTrustWarning)
        XCTAssertEqual(warning.issues, [RecipientTrustIssue(recipient: Self.bobEmail, kind: .unverified)])
    }

    // MARK: - decodedMessage

    func testDecodedMessagePlainReturnsNil() throws {
        let core = try makeCore(keys: [Self.alice])
        let decoded = core.decodedMessage(forMessageData: plainMessage())
        XCTAssertNil(decoded)
    }

    func testDecodedMessageSignedReturnsSigners() throws {
        let aliceEngine = try makeEngine(keys: [Self.alice])
        let bobEngine = try makeEngine(keys: [Self.bob])

        // Bob needs Alice's public key to verify the signature.
        let aliceFingerprint = try XCTUnwrap(aliceEngine.keyManager.listKeys().first?.fingerprint)
        let alicePublicKey = try aliceEngine.keyManager.exportKey(fingerprint: aliceFingerprint)
        try bobEngine.keyManager.importKeys(alicePublicKey)

        let aliceCore = MessageSecurityCore(engine: aliceEngine)
        let bobCore = MessageSecurityCore(engine: bobEngine)

        let message = MockMessage(
            rawData: plainMessage(),
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: false)
        let result = aliceCore.encode(message, composeContext: context)
        let encoded = try XCTUnwrap(result.encodedMessage)

        let decoded = try XCTUnwrap(bobCore.decodedMessage(forMessageData: encoded.rawData))
        XCTAssertEqual(decoded.securityInformation.signers.count, 1)
        XCTAssertFalse(decoded.securityInformation.isEncrypted)
        XCTAssertNil(decoded.securityInformation.signingError)

        let signer = try XCTUnwrap(decoded.securityInformation.signers.first)
        XCTAssertEqual(signer.emailAddresses, [Self.alice])
        XCTAssertEqual(signer.signatureLabel, Self.alice)

        let signerContext = try XCTUnwrap(bobCore.signerContext(for: signer))
        XCTAssertEqual(signerContext.status, "valid")
        XCTAssertNotNil(signerContext.fingerprint)
    }

    // MARK: - signerContext

    func testSignerContextEmptyReturnsNil() throws {
        let core = try makeCore()
        let signer = MockSigner(signerEmailAddresses: [], signerLabel: "", context: Data())
        XCTAssertNil(core.signerContext(for: signer))
    }

    func testSignerContextInvalidJSONReturnsNil() throws {
        let core = try makeCore()
        let signer = MockSigner(signerEmailAddresses: [], signerLabel: "", context: Data("not json".utf8))
        XCTAssertNil(core.signerContext(for: signer))
    }
}

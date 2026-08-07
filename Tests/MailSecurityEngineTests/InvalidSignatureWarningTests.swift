//
//  InvalidSignatureWarningTests.swift
//  swift-rnp
//
//  Tests for the invalid-signature warning: the decode-time reason
//  classification attached to `SignerContext.invalidReason` (tampered
//  content, revoked key, unknown key) and the per-reason detail text and
//  review-link rules in `mapSignerTrust`.
//

import XCTest
import Librnp
import TrustStore
@testable import MailSecurityEngine

final class InvalidSignatureWarningTests: XCTestCase {
    private static let alice = "Alice <alice@example.com>"
    private static let aliceEmail = "alice@example.com"
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

    private func makeCore() throws -> (MessageSecurityCore, MailSecurityEngine) {
        let engine = try MailSecurityEngine(
            directory: makeTempDirectory(),
            passphraseProvider: { _ in Self.password }
        )
        try engine.keyManager.generateKey(userID: Self.alice, algorithm: .ecdsa)
        return (MessageSecurityCore(engine: engine), engine)
    }

    private func plainMessage(body: String = "Hello, Bob!") -> Data {
        let lines = [
            "From: alice@example.com",
            "To: bob@example.com",
            "Subject: invalid reason",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=\"utf-8\"",
        ]
        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n" + body).utf8)
    }

    private func signedMessage(engine: MailSecurityEngine, body: String = "Hello, Bob!") throws -> Data {
        try engine.encode(EncodingRequest(
            message: plainMessage(body: body),
            sender: Self.aliceEmail,
            recipients: [],
            sign: true,
            encrypt: false
        )).rawData
    }

    // MARK: - Banner view model mapping

    func testInvalidSignatureDetailContentMismatch() {
        for trust: TrustState in [.verified, .unverified, .problem] {
            let model = mapSignerTrust(status: .invalid, trust: trust, invalidReason: .contentMismatch)
            XCTAssertEqual(
                model.detail,
                "The signature does not match the message content; the message may have been modified after signing.",
                "detail mismatch for trust=\(trust)"
            )
            XCTAssertEqual(model.label, "Invalid signature")
            XCTAssertEqual(model.intent, .critical)
        }
    }

    func testInvalidSignatureDetailKeyUnknown() {
        let model = mapSignerTrust(status: .invalid, trust: .unverified, invalidReason: .keyUnknown)
        XCTAssertEqual(
            model.detail,
            "The signature was made by an unknown or revoked key, so it could not be verified."
        )
        // No key to deep-link to; the banner's fetch action applies instead.
        XCTAssertFalse(model.reviewDeepLink)
    }

    func testInvalidSignatureDetailKeyRevoked() {
        let model = mapSignerTrust(status: .invalid, trust: .verified, invalidReason: .keyRevoked)
        XCTAssertEqual(
            model.detail,
            "The signature was made by a key that has been revoked. Do not trust this message."
        )
    }

    func testInvalidSignatureDetailKeyExpired() {
        let model = mapSignerTrust(status: .invalid, trust: .verified, invalidReason: .keyExpired)
        XCTAssertEqual(model.detail, "The signature was made by an expired key.")
    }

    func testInvalidSignatureDetailKeyExpiredIncludesDate() {
        let expiration = Date(timeIntervalSince1970: 1_800_000_000)
        let model = mapSignerTrust(
            status: .invalid,
            trust: .verified,
            keyExpiration: expiration,
            invalidReason: .keyExpired
        )
        XCTAssertTrue(
            model.detail.contains("The key expired on \(formatKeyExpirationDate(expiration))."),
            "detail missing expiration date: \(model.detail)"
        )
    }

    func testInvalidSignatureDetailWithoutReasonKeepsOriginalText() {
        let model = mapSignerTrust(status: .invalid, trust: .verified)
        XCTAssertEqual(model.detail, "The signature does not verify; the message may have been modified.")
    }

    func testInvalidSignatureReviewDeepLinkRules() {
        // The key detail view is offered whenever the signing key may be
        // known — only an unknown key has nothing to show.
        XCTAssertTrue(mapSignerTrust(status: .invalid, trust: .verified).reviewDeepLink)
        XCTAssertTrue(mapSignerTrust(status: .invalid, trust: .verified, invalidReason: .contentMismatch).reviewDeepLink)
        XCTAssertTrue(mapSignerTrust(status: .invalid, trust: .verified, invalidReason: .keyRevoked).reviewDeepLink)
        XCTAssertTrue(mapSignerTrust(status: .invalid, trust: .verified, invalidReason: .keyExpired).reviewDeepLink)
        XCTAssertFalse(mapSignerTrust(status: .invalid, trust: .verified, invalidReason: .keyUnknown).reviewDeepLink)
    }

    // MARK: - SignerContext plumbing

    func testSignerContextRoundTripsInvalidReason() throws {
        let context = SignerContext(
            fingerprint: "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111",
            status: RnpSignatureStatus.invalid.rawValue,
            invalidReason: InvalidSignatureReason.keyRevoked.rawValue
        )

        let decoded = try JSONDecoder().decode(SignerContext.self, from: JSONEncoder().encode(context))

        XCTAssertEqual(decoded, context)
        XCTAssertEqual(decoded.invalidReason, "key-revoked")
    }

    func testSignerContextWithoutInvalidReasonStillDecodes() throws {
        // Payloads written by older extension versions lack the field.
        let legacy = """
        {"fingerprint":"AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111","status":"invalid"}
        """

        let decoded = try JSONDecoder().decode(SignerContext.self, from: Data(legacy.utf8))

        XCTAssertNil(decoded.invalidReason)
        XCTAssertEqual(decoded.status, RnpSignatureStatus.invalid.rawValue)
    }

    // MARK: - Decode-time reason classification

    func testDecodedMessageAttachesContentMismatchReason() throws {
        let (core, engine) = try makeCore()
        let signed = try signedMessage(engine: engine)
        // Modify the signed content inside the multipart/signed structure.
        let tampered = String(decoding: signed, as: UTF8.self)
            .replacingOccurrences(of: "Hello, Bob!", with: "Hello, Mallory!")

        let decoded = try XCTUnwrap(core.decodedMessage(forMessageData: Data(tampered.utf8)))
        let signer = try XCTUnwrap(decoded.securityInformation.signers.first)
        let context = try XCTUnwrap(core.signerContext(for: signer))

        XCTAssertEqual(context.status, RnpSignatureStatus.invalid.rawValue)
        XCTAssertEqual(context.invalidReason, InvalidSignatureReason.contentMismatch.rawValue)
    }

    func testDecodedMessageAttachesRevokedKeyReason() throws {
        let (core, engine) = try makeCore()
        let fingerprint = try XCTUnwrap(engine.keyManager.listKeys().first?.fingerprint)
        let signed = try signedMessage(engine: engine)

        // Revoke the signing key after the message was signed.
        try engine.keyManager.withRnp { rnp in
            try rnp.requireKey(fingerprint, type: .fingerprint).revoke(code: .compromised)
        }

        let decoded = try XCTUnwrap(core.decodedMessage(forMessageData: signed))
        let signer = try XCTUnwrap(decoded.securityInformation.signers.first)
        let context = try XCTUnwrap(core.signerContext(for: signer))

        XCTAssertEqual(context.status, RnpSignatureStatus.invalid.rawValue)
        XCTAssertEqual(context.invalidReason, InvalidSignatureReason.keyRevoked.rawValue)
    }

    func testDecodedMessageAttachesNoReasonForValidSignature() throws {
        let (core, engine) = try makeCore()
        let signed = try signedMessage(engine: engine)

        let decoded = try XCTUnwrap(core.decodedMessage(forMessageData: signed))
        let signer = try XCTUnwrap(decoded.securityInformation.signers.first)
        let context = try XCTUnwrap(core.signerContext(for: signer))

        XCTAssertEqual(context.status, RnpSignatureStatus.valid.rawValue)
        XCTAssertNil(context.invalidReason)
    }
}

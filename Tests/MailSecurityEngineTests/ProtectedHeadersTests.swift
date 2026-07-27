//
//  ProtectedHeadersTests.swift
//  swift-rnp
//
//  Protected headers ("Memory Hole", protected-headers="v1") tests: the
//  Subject and other sensitive envelope headers move into the encrypted
//  payload of PGP/MIME messages (K-9 Mail / Thunderbird interop), a generic
//  placeholder stays outside, and decoding restores the real headers.
//  Includes backward-compatibility coverage for messages without protected
//  headers.
//

import XCTest
@testable import MailSecurityEngine
import Rnp
import TrustStore

final class ProtectedHeadersTests: XCTestCase {
    private static let password = "password"
    private static let alice = "Alice <alice@example.com>"
    private static let aliceEmail = "alice@example.com"
    private static let bob = "Bob <bob@example.com>"
    private static let bobEmail = "bob@example.com"

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

    private func makeEngine(keys userIDs: [String]) throws -> MailSecurityEngine {
        let engine = try MailSecurityEngine(
            directory: makeTempDirectory(),
            passphraseProvider: { _ in Self.password }
        )
        for userID in userIDs {
            try engine.keyManager.generateKey(userID: userID, algorithm: .ecdsa)
        }
        return engine
    }

    private func plainMessage(
        subject: String = "engine test",
        body: String = "Hello, Bob!",
        extraHeaders: [String] = []
    ) -> Data {
        var lines = [
            "From: \(Self.alice)",
            "To: \(Self.bob)",
            "Subject: \(subject)",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=\"utf-8\"",
        ]
        lines.append(contentsOf: extraHeaders)
        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n" + body).utf8)
    }

    /// Message with an attachment-shaped MIME part (multipart/mixed with a
    /// base64 application/octet-stream part).
    private func attachmentMessage(subject: String = "with attachment") -> Data {
        Data(("""
        From: \(Self.alice)\r
        To: \(Self.bob)\r
        Subject: \(subject)\r
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

    private func utf8(_ data: Data?) -> String {
        guard let data else { return "" }
        return String(decoding: data, as: UTF8.self)
    }

    /// Encrypts an arbitrary payload to Bob using the engine's keyring; used
    /// to build foreign-style PGP/MIME messages by hand.
    private func encryptPayload(_ payload: Data, using engine: MailSecurityEngine) throws -> Data {
        try engine.keyManager.withRnp { rnp in
            let key = try XCTUnwrap(engine.keyManager.publicKeyUnlocked(for: Self.bobEmail, rnp: rnp))
            return try rnp.encrypt(payload, for: [key], armored: true)
        }
    }

    /// Wraps armored ciphertext in a multipart/encrypted message, with or
    /// without the protected-headers="v1" parameter.
    private func multipartEncryptedMessage(
        ciphertext: Data,
        subject: String = ProtectedHeaders.placeholderSubject,
        protectedHeaders: Bool
    ) -> Data {
        var contentType = "multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"pgp-outer\""
        if protectedHeaders {
            contentType += "; protected-headers=\"v1\""
        }
        return Data(("""
        From: \(Self.alice)\r
        To: \(Self.bob)\r
        Subject: \(subject)\r
        MIME-Version: 1.0\r
        Content-Type: \(contentType)\r
        \r
        --pgp-outer\r
        Content-Type: application/pgp-encrypted\r
        \r
        Version: 1\r
        \r
        --pgp-outer\r
        Content-Type: application/octet-stream; name="encrypted.asc"\r
        \r

        """).utf8)
            + ciphertext
            + Data("\r\n--pgp-outer--\r\n".utf8)
    }

    // MARK: - Encoding

    func testEncryptHidesSubjectBehindPlaceholder() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let secret = "Secret launch plans \u{1F680}"
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(subject: secret),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: false,
            encrypt: true
        ))
        let text = utf8(encoded.rawData)
        XCTAssertTrue(text.contains("multipart/encrypted"))
        XCTAssertTrue(text.contains(#"protected-headers="v1""#))
        XCTAssertTrue(text.contains("Subject: \(ProtectedHeaders.placeholderSubject)"))
        // The real subject must not leak in plaintext anywhere.
        XCTAssertFalse(text.contains(secret))
    }

    func testProtectedHeadersInnerStructure() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(subject: "Inner structure check"),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: false,
            encrypt: true
        ))
        let outer = MimeMessage.parse(encoded.rawData)
        XCTAssertEqual(outer.contentType?.parameters["protected-headers"], "v1")
        let parts = try XCTUnwrap(outer.parts)

        // Decrypt the payload by hand to inspect the protected structure.
        let payload = try engine.keyManager.withRnp { rnp in
            try XCTUnwrap(try rnp.verifyDetailed(parts[1].decodedBody()).payload)
        }
        let inner = MimeMessage.parse(payload)
        XCTAssertEqual(inner.contentType?.type, "multipart")
        XCTAssertEqual(inner.contentType?.subtype, "mixed")
        XCTAssertEqual(inner.contentType?.parameters["protected-headers"], "v1")
        let innerParts = try XCTUnwrap(inner.parts)
        XCTAssertEqual(innerParts.count, 2)

        // First part: the protected header block.
        let headersPart = innerParts[0]
        XCTAssertEqual(headersPart.contentType?.type, "text")
        XCTAssertEqual(headersPart.contentType?.subtype, "rfc822-headers")
        let protected = MimeMessage.parse(headersPart.decodedBody())
        XCTAssertEqual(protected.header("Subject"), "Inner structure check")
        XCTAssertEqual(protected.header("From"), Self.alice)
        XCTAssertEqual(protected.header("To"), Self.bob)

        // Second part: the original MIME entity.
        let content = innerParts[1]
        XCTAssertEqual(content.contentType?.type, "text")
        XCTAssertEqual(content.contentType?.subtype, "plain")
        XCTAssertTrue(utf8(content.body).contains("Hello, Bob!"))
    }

    func testSignOnlyKeepsSubjectInClear() throws {
        // Backward compatibility: protected headers apply to encryption
        // only; a signed-only message keeps its envelope untouched.
        let engine = try makeEngine(keys: [Self.alice])
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(subject: "visible subject"),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: false
        ))
        let text = utf8(encoded.rawData)
        XCTAssertTrue(text.contains("multipart/signed"))
        XCTAssertTrue(text.contains("Subject: visible subject"))
        XCTAssertFalse(text.contains("protected-headers"))
    }

    // MARK: - Decoding

    func testProtectedHeadersRoundtripRestoresRealHeaders() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let secret = "Secret launch plans \u{1F680}"
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(
                subject: secret,
                extraHeaders: ["Message-ID: <secret-123@example.com>"]
            ),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: true
        ))
        let decoded = try XCTUnwrap(engine.decode(encoded.rawData))
        XCTAssertTrue(decoded.security.isEncrypted)
        XCTAssertNil(decoded.security.signingError)
        XCTAssertNil(decoded.security.encryptionError)
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)

        let restored = MimeMessage.parse(try XCTUnwrap(decoded.data))
        XCTAssertEqual(restored.header("Subject"), secret)
        XCTAssertEqual(restored.header("From"), Self.alice)
        XCTAssertEqual(restored.header("To"), Self.bob)
        XCTAssertEqual(restored.header("Message-ID"), "<secret-123@example.com>")
        // The protected copies replace the outer headers exactly once.
        XCTAssertEqual(
            restored.headers.filter { $0.name.caseInsensitiveCompare("Subject") == .orderedSame }.count,
            1
        )
        XCTAssertEqual(
            restored.headers.filter { $0.name.caseInsensitiveCompare("From") == .orderedSame }.count,
            1
        )
        XCTAssertTrue(utf8(restored.body).contains("Hello, Bob!"))
        XCTAssertFalse(utf8(decoded.data).contains(ProtectedHeaders.placeholderSubject))
    }

    func testProtectedHeadersAttachmentRoundtrip() throws {
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let encoded = try engine.encode(EncodingRequest(
            message: attachmentMessage(subject: "attachment plans"),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: true
        ))
        XCTAssertFalse(utf8(encoded.rawData).contains("attachment plans"))

        let decoded = try XCTUnwrap(engine.decode(encoded.rawData))
        XCTAssertTrue(decoded.security.isEncrypted)
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)
        let restored = MimeMessage.parse(try XCTUnwrap(decoded.data))
        XCTAssertEqual(restored.header("Subject"), "attachment plans")
        let text = utf8(decoded.data)
        XCTAssertTrue(text.contains("multipart/mixed"))
        XCTAssertTrue(text.contains(#"filename="file.bin""#))
        XCTAssertTrue(text.contains("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="))
    }

    func testTamperedOuterSubjectIsIgnored() throws {
        // The outer (placeholder) headers are unauthenticated; a tampered
        // outer Subject must not affect what is displayed.
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let encoded = try engine.encode(EncodingRequest(
            message: plainMessage(subject: "the real subject"),
            sender: Self.aliceEmail,
            recipients: [Self.bobEmail],
            sign: true,
            encrypt: true
        ))
        var tampered = utf8(encoded.rawData)
        tampered = tampered.replacingOccurrences(
            of: "Subject: \(ProtectedHeaders.placeholderSubject)",
            with: "Subject: forged subject"
        )
        XCTAssertTrue(tampered.contains("Subject: forged subject"))

        let decoded = try XCTUnwrap(engine.decode(Data(tampered.utf8)))
        XCTAssertEqual(decoded.security.signers.first?.status, .valid)
        let restored = MimeMessage.parse(try XCTUnwrap(decoded.data))
        XCTAssertEqual(restored.header("Subject"), "the real subject")
        XCTAssertFalse(utf8(decoded.data).contains("forged subject"))
    }

    // MARK: - Foreign layouts and backward compatibility

    func testLegacyEncryptedMessageWithoutProtectedHeadersDecodes() throws {
        // Backward compatibility: a PGP/MIME message without the
        // protected-headers parameter shows its outer headers.
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let payload = Data("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\nlegacy body".utf8)
        let message = multipartEncryptedMessage(
            ciphertext: try encryptPayload(payload, using: engine),
            subject: "legacy outer subject",
            protectedHeaders: false
        )
        let decoded = try XCTUnwrap(engine.decode(message))
        XCTAssertTrue(decoded.security.isEncrypted)
        XCTAssertNil(decoded.security.encryptionError)
        let restored = MimeMessage.parse(try XCTUnwrap(decoded.data))
        XCTAssertEqual(restored.header("Subject"), "legacy outer subject")
        XCTAssertTrue(utf8(decoded.data).contains("legacy body"))
    }

    func testThunderbirdStyleProtectedHeadersDecoded() throws {
        // Thunderbird layout: the decrypted payload is a full RFC 822
        // message whose leading headers are the protected ones.
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let payload = Data((
            "Subject: Thunderbird secret\r\n" +
            "From: \(Self.alice)\r\n" +
            "To: \(Self.bob)\r\n" +
            "Content-Type: text/plain; charset=\"utf-8\"\r\n" +
            "\r\n" +
            "thunderbird body"
        ).utf8)
        let message = multipartEncryptedMessage(
            ciphertext: try encryptPayload(payload, using: engine),
            protectedHeaders: true
        )
        let decoded = try XCTUnwrap(engine.decode(message))
        XCTAssertTrue(decoded.security.isEncrypted)
        XCTAssertNil(decoded.security.encryptionError)
        let restored = MimeMessage.parse(try XCTUnwrap(decoded.data))
        XCTAssertEqual(restored.header("Subject"), "Thunderbird secret")
        XCTAssertEqual(restored.header("From"), Self.alice)
        XCTAssertEqual(restored.contentType?.type, "text")
        XCTAssertEqual(restored.contentType?.subtype, "plain")
        XCTAssertTrue(utf8(restored.body).contains("thunderbird body"))
    }

    func testK9StyleMultiPartContentIsRebuilt() throws {
        // K-9 layout with more than one content part: the remaining parts
        // are reassembled into a multipart/mixed entity.
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let payload = Data((
            "Content-Type: multipart/mixed; boundary=\"k9-inner\"; protected-headers=\"v1\"\r\n" +
            "\r\n" +
            "--k9-inner\r\n" +
            "Content-Type: text/rfc822-headers; protected-headers=\"v1\"\r\n" +
            "Content-Disposition: inline\r\n" +
            "\r\n" +
            "Subject: K-9 multi-part secret\r\n" +
            "\r\n" +
            "\r\n" +
            "--k9-inner\r\n" +
            "Content-Type: text/plain; charset=\"utf-8\"\r\n" +
            "\r\n" +
            "part one\r\n" +
            "\r\n" +
            "--k9-inner\r\n" +
            "Content-Type: text/plain; charset=\"utf-8\"\r\n" +
            "\r\n" +
            "part two\r\n" +
            "\r\n" +
            "--k9-inner--\r\n"
        ).utf8)
        let message = multipartEncryptedMessage(
            ciphertext: try encryptPayload(payload, using: engine),
            protectedHeaders: true
        )
        let decoded = try XCTUnwrap(engine.decode(message))
        XCTAssertTrue(decoded.security.isEncrypted)
        XCTAssertNil(decoded.security.encryptionError)
        let restored = MimeMessage.parse(try XCTUnwrap(decoded.data))
        XCTAssertEqual(restored.header("Subject"), "K-9 multi-part secret")
        XCTAssertEqual(restored.contentType?.type, "multipart")
        XCTAssertEqual(restored.contentType?.subtype, "mixed")
        let text = utf8(restored.body)
        XCTAssertTrue(text.contains("part one"))
        XCTAssertTrue(text.contains("part two"))
    }

    func testProtectedHeadersParameterWithoutHeadersFallsBack() throws {
        // A message claiming protected-headers="v1" but carrying no
        // protected headers inside degrades to the outer headers.
        let engine = try makeEngine(keys: [Self.alice, Self.bob])
        let payload = Data("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\nplain body".utf8)
        let message = multipartEncryptedMessage(
            ciphertext: try encryptPayload(payload, using: engine),
            subject: "outer fallback subject",
            protectedHeaders: true
        )
        let decoded = try XCTUnwrap(engine.decode(message))
        XCTAssertTrue(decoded.security.isEncrypted)
        let restored = MimeMessage.parse(try XCTUnwrap(decoded.data))
        XCTAssertEqual(restored.header("Subject"), "outer fallback subject")
        XCTAssertTrue(utf8(decoded.data).contains("plain body"))
    }
}

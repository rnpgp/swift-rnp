//
//  MimeMessageTests.swift
//  swift-rnp
//
//  Unit tests for the internal MIME parser: header parsing, multipart
//  decomposition (byte-exact, as OpenPGP/MIME signature verification
//  requires), transfer decoding and CRLF canonicalization.
//

import XCTest
@testable import MailSecurityEngine

final class MimeMessageTests: XCTestCase {
    func testHeaderParsing() throws {
        let raw = """
        From: Alice <alice@example.com>\r
        To: Bob <bob@example.com>\r
        Subject: a long subject\r
        \tthat continues\r
        Content-Type: multipart/signed; boundary="abc;def";\r
         protocol="application/pgp-signature"\r
        \r
        body text
        """
        let message = MimeMessage.parse(Data(raw.utf8))
        XCTAssertEqual(message.header("from"), "Alice <alice@example.com>")
        XCTAssertEqual(message.header("Subject"), "a long subject that continues")
        let contentType = try XCTUnwrap(message.contentType)
        XCTAssertEqual(contentType.mediaType, "multipart/signed")
        XCTAssertTrue(contentType.isMultipart)
        // A quoted parameter containing a semicolon stays one value.
        XCTAssertEqual(contentType.boundary, "abc;def")
        XCTAssertEqual(contentType.parameters["protocol"], "application/pgp-signature")
        XCTAssertEqual(message.body, Data("body text".utf8))
    }

    func testLFOnlyMessage() throws {
        let raw = "Content-Type: text/plain\nX-Test: 1\n\nline one\nline two\n"
        let message = MimeMessage.parse(Data(raw.utf8))
        XCTAssertEqual(message.eol, .lf)
        XCTAssertEqual(message.header("X-Test"), "1")
        XCTAssertEqual(message.body, Data("line one\nline two\n".utf8))
    }

    func testMessageWithoutHeaders() throws {
        let message = MimeMessage.parse(Data("just a body".utf8))
        XCTAssertTrue(message.headers.isEmpty)
        XCTAssertEqual(message.body, Data("just a body".utf8))
    }

    func testMultipartSplitPreservesBytes() throws {
        let part1 = "Content-Type: text/plain\r\n\r\nHello,\r\nBob!\r\n"
        let part2 = "Content-Type: application/pgp-signature\r\n\r\nSIGNATURE\r\n"
        let raw = "Content-Type: multipart/mixed; boundary=\"bnd\"\r\n\r\n"
            + "preamble to ignore\r\n"
            + "--bnd\r\n" + part1
            + "--bnd\r\n" + part2
            + "--bnd--\r\n"
            + "epilogue to ignore"
        let message = MimeMessage.parse(Data(raw.utf8))
        let parts = try XCTUnwrap(message.parts)
        let rawParts = try XCTUnwrap(message.rawPartEntities)
        XCTAssertEqual(parts.count, 2)
        // The raw entity is preserved byte-exactly (the CRLF before the next
        // boundary delimiter belongs to the delimiter, not to the part).
        XCTAssertEqual(rawParts[0], Data(part1.utf8).dropLast(2))
        XCTAssertEqual(rawParts[1], Data(part2.utf8).dropLast(2))
        XCTAssertEqual(parts[0].header("Content-Type"), "text/plain")
        XCTAssertEqual(parts[0].body, Data("Hello,\r\nBob!".utf8))
        XCTAssertEqual(parts[1].body, Data("SIGNATURE".utf8))
    }

    func testNestedMultipart() throws {
        let inner = "Content-Type: text/plain\r\n\r\nleaf body\r\n"
        let innerMultipart = "Content-Type: multipart/alternative; boundary=\"inner\"\r\n\r\n"
            + "--inner\r\n" + inner + "--inner--\r\n"
        let raw = "Content-Type: multipart/mixed; boundary=\"outer\"\r\n\r\n"
            + "--outer\r\n" + innerMultipart + "--outer--\r\n"
        let message = MimeMessage.parse(Data(raw.utf8))
        let outer = try XCTUnwrap(message.parts)
        XCTAssertEqual(outer.count, 1)
        let leaf = try XCTUnwrap(outer[0].parts)
        XCTAssertEqual(leaf.count, 1)
        XCTAssertEqual(leaf[0].body, Data("leaf body".utf8))
    }

    func testBase64BodyDecoding() throws {
        let raw = "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            + "SGVsbG8s\r\nIHdvcmxkIQ==\r\n"
        let message = MimeMessage.parse(Data(raw.utf8))
        XCTAssertEqual(message.decodedBody(), Data("Hello, world!".utf8))
    }

    func testQuotedPrintableDecoding() throws {
        // "Hello, wörld" + soft line break + "soft"
        let qp = "=48=65=6C=6C=6F=2C=20w=C3=B6rld=\r\nsoft"
        XCTAssertEqual(
            MimeMessage.decodeQuotedPrintable(Data(qp.utf8)),
            Data("Hello, wörldsoft".utf8)
        )
    }

    func testCRLFNormalization() throws {
        let input = Data("a\nb\r\nc\rd".utf8)
        XCTAssertEqual(
            MimeMessage.crlfNormalized(input),
            Data("a\r\nb\r\nc\rd".utf8)
        )
        // Idempotent on already-normalized data.
        let normalized = MimeMessage.crlfNormalized(input)
        XCTAssertEqual(MimeMessage.crlfNormalized(normalized), normalized)
    }
}

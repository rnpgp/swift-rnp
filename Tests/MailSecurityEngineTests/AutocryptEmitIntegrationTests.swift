//
//  AutocryptEmitIntegrationTests.swift
//  MailSecurityEngineTests
//
//  Verifies the Autocrypt header is spliced into encoded output when
//  the policy says to emit it, and is absent otherwise.
//

import XCTest
import Autocrypt
@testable import MailSecurityEngine

final class AutocryptEmitIntegrationTests: XCTestCase {

    /// Stand-in MimeMessage conformance for tests; we synthesize a
    /// minimal RFC 822 message and exercise the splicing helper
    /// directly. Full encode tests require librnp and live elsewhere.
    func testSpliceInsertsHeaderAfterFirstLine() {
        let original = Data("From: alice@x\r\nTo: bob@x\r\nSubject: Hi\r\n\r\nBody\r\n".utf8)
        let spliced = MailSecurityEngine.spliceAutocryptHeader(
            into: original,
            headerValue: "addr=alice@x; prefer-encrypt=mutual; keydata=AA=="
        )
        let text = String(data: spliced, encoding: .utf8) ?? ""
        XCTAssertTrue(text.contains("Autocrypt: addr=alice@x;"))
        // The Autocrypt header should appear AFTER the From: line (i.e.
        // not at the start of the message), proving it was spliced in
        // rather than prepended.
        let fromRange = text.range(of: "From: alice@x\r\n")!
        let autocryptRange = text.range(of: "Autocrypt:")!
        XCTAssertLessThan(fromRange.lowerBound, autocryptRange.lowerBound)
    }

    func testSplicePreservesBody() {
        let original = Data("From: alice@x\r\n\r\nBody line 1\r\nBody line 2\r\n".utf8)
        let spliced = MailSecurityEngine.spliceAutocryptHeader(
            into: original,
            headerValue: "addr=alice@x; keydata=AA=="
        )
        let text = String(data: spliced, encoding: .utf8) ?? ""
        XCTAssertTrue(text.contains("Body line 1"))
        XCTAssertTrue(text.contains("Body line 2"))
    }

    func testSpliceHandlesNoCRLFInputGracefully() {
        // Input without any CRLF (malformed) — should return unchanged.
        let original = Data("no headers here".utf8)
        let spliced = MailSecurityEngine.spliceAutocryptHeader(
            into: original,
            headerValue: "addr=a@x; keydata=AA=="
        )
        XCTAssertEqual(spliced, original)
    }

    func testPolicyNeverSkipsEmit() {
        let policy: AutocryptEmitPolicy = .never
        let decision = policy.resolve(signerAddress: "a@x", isEncrypted: true, isSigned: true)
        XCTAssertEqual(decision, .skip)
    }
}

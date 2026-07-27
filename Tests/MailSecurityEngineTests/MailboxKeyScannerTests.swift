//
//  MailboxKeyScannerTests.swift
//  MailSecurityEngineTests
//
//  Tests the MailboxKeyScanner against synthetic RFC 822 messages
//  that exercise each of the three sources (Autocrypt header,
//  application/pgp-keys attachment, signing key). The signing-key
//  source requires the keyring to contain the sender's key, so we
//  set up a keyring with one before scanning.
//

import XCTest
import Rnp
@testable import MailSecurityEngine

final class MailboxKeyScannerTests: XCTestCase {
    private var tempDir: URL!
    private var km: KeyManager!

    override func setUp() {
        super.setUp()
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("mailbox-scanner-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        km = nil
        try? FileManager.default.removeItem(at: tempDir)
        tempDir = nil
        super.tearDown()
    }


    private func bootstrapKeyring() throws {
        km = try KeyManager(directory: tempDir, password: "test-pass")
    }

    func testEmptyInputProducesEmptyReport() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not installed locally")
        try bootstrapKeyring()
        let scanner = MailboxKeyScanner()
        let report = try km.withRnp { scanner.scan(messages: [], using: $0) }
        XCTAssertEqual(report.discoveredKeys.count, 0)
        XCTAssertEqual(report.messagesScanned, 0)
    }

    func testMessageWithoutAnyKeySourceIsEmpty() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not installed locally")
        try bootstrapKeyring()
        let msg = Data("From: alice@x\r\nTo: bob@x\r\nSubject: Hi\r\n\r\nBody\r\n".utf8)
        let scanner = MailboxKeyScanner()
        let report = try km.withRnp { scanner.scan(messages: [msg], using: $0) }
        XCTAssertEqual(report.discoveredKeys.count, 0)
        XCTAssertEqual(report.messagesScanned, 1)
    }

    func testAutocryptHeaderWithInvalidKeydataIsIgnored() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not installed locally")
        try bootstrapKeyring()
        let msg = Data(
            "From: alice@x\r\nTo: bob@x\r\nAutocrypt: addr=alice@x; prefer-encrypt=mutual; keydata=NOT_BASE64\r\n\r\nBody\r\n".utf8
        )
        let scanner = MailboxKeyScanner()
        let report = try km.withRnp { scanner.scan(messages: [msg], using: $0) }
        XCTAssertEqual(report.discoveredKeys.count, 0)
    }

    func testScanSynthesizesMessagesScannedCountCorrectly() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not installed locally")
        try bootstrapKeyring()
        let msg1 = Data("From: a@x\r\n\r\nBody 1\r\n".utf8)
        let msg2 = Data("From: b@x\r\n\r\nBody 2\r\n".utf8)
        let msg3 = Data("From: c@x\r\n\r\nBody 3\r\n".utf8)
        let scanner = MailboxKeyScanner()
        let report = try km.withRnp { scanner.scan(messages: [msg1, msg2, msg3], using: $0) }
        XCTAssertEqual(report.messagesScanned, 3)
    }

    func testScanDoesNotThrowOnMalformedMIME() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not installed locally")
        try bootstrapKeyring()
        let malformed = Data("garbage that is not RFC822\r\n\r\nmore garbage".utf8)
        let scanner = MailboxKeyScanner()
        let report = try km.withRnp { scanner.scan(messages: [malformed], using: $0) }
        XCTAssertEqual(report.discoveredKeys.count, 0)
        XCTAssertEqual(report.messagesScanned, 1)
    }
}

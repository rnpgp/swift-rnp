//
//  AutocryptDecodeObservationTests.swift
//  MailSecurityEngineTests
//
//  Verifies that MailSecurityEngine.decode populates the
//  autocryptStore from incoming messages' Autocrypt headers.
//

import XCTest
import Autocrypt
@testable import MailSecurityEngine

final class AutocryptDecodeObservationTests: XCTestCase {

    private var tempDir: URL!
    private var engine: MailSecurityEngine!

    override func setUp() {
        super.setUp()
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("autocrypt-decode-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        engine = nil
        try? FileManager.default.removeItem(at: tempDir)
        tempDir = nil
        super.tearDown()
    }


    /// A message with an Autocrypt header is parsed; the store gets
    /// an observation even though the message body isn't OpenPGP.
    func testAutocryptHeaderPopulatesStore() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not installed locally")
        engine = try MailSecurityEngine(directory: tempDir, passphraseProvider: { _ in "test" })
        // Synthesize a message with a syntactically-valid Autocrypt
        // header pointing at alice@example.org. The keydata is fake
        // (just base64 of "X") so the store observes the address +
        // prefer-encrypt even though the key bytes won't actually
        // import as OpenPGP.
        let keydata = Data("X".utf8).base64EncodedString()
        let raw = """
        From: alice@example.org\r
        To: bob@example.org\r
        Subject: Hi\r
        Date: Mon, 01 Jan 2024 00:00:00 +0000\r
        Autocrypt: addr=alice@example.org; prefer-encrypt=mutual; keydata=\(keydata)\r
        \r
        Body text.\r
        """
        _ = try? engine.decode(Data(raw.utf8))
        let obs = engine.autocryptStore.observation(forAddress: "alice@example.org")
        XCTAssertNotNil(obs, "Autocrypt store should have an observation for alice@example.org")
        XCTAssertEqual(obs?.preferEncrypt, .mutual)
    }

    /// Messages without an Autocrypt header leave the store empty.
    func testMessageWithoutAutocryptLeavesStoreEmpty() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not installed locally")
        engine = try MailSecurityEngine(directory: tempDir, passphraseProvider: { _ in "test" })
        let raw = """
        From: alice@example.org\r
        To: bob@example.org\r
        Subject: Hi\r
        \r
        Body text.\r
        """
        _ = try? engine.decode(Data(raw.utf8))
        XCTAssertNil(engine.autocryptStore.observation(forAddress: "alice@example.org"))
    }

    /// Multiple messages from the same sender: latest wins.
    func testLatestAutocryptHeaderWins() throws {
        try XCTSkipUnless(TestSupport.librnpAvailable(), "librnp not installed locally")
        engine = try MailSecurityEngine(directory: tempDir, passphraseProvider: { _ in "test" })
        let keydata1 = Data("X1".utf8).base64EncodedString()
        let keydata2 = Data("X2".utf8).base64EncodedString()
        let early = """
        From: alice@example.org\r
        Date: Mon, 01 Jan 2024 00:00:00 +0000\r
        Autocrypt: addr=alice@example.org; prefer-encrypt=mutual; keydata=\(keydata1)\r
        \r
        Body 1.\r
        """
        let late = """
        From: alice@example.org\r
        Date: Tue, 02 Jan 2024 00:00:00 +0000\r
        Autocrypt: addr=alice@example.org; prefer-encrypt=nopreference; keydata=\(keydata2)\r
        \r
        Body 2.\r
        """
        _ = try? engine.decode(Data(early.utf8))
        _ = try? engine.decode(Data(late.utf8))

        let obs = engine.autocryptStore.observation(forAddress: "alice@example.org")
        XCTAssertEqual(obs?.preferEncrypt, .nopreference)
        XCTAssertEqual(obs?.keydataBase64, keydata2)
    }
}

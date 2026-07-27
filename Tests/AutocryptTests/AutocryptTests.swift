//
//  AutocryptTests.swift
//  AutocryptTests
//

import XCTest
@testable import Autocrypt

final class AutocryptTests: XCTestCase {

    // MARK: - Header parsing

    func testParsesCanonicalHeader() throws {
        let raw = "addr=alice@example.org; prefer-encrypt=mutual; keydata=AAECAwQFBgcICQ=="
        let header = try AutocryptHeaderParser.parse(raw)
        XCTAssertEqual(header.address, "alice@example.org")
        XCTAssertEqual(header.preferEncrypt, .mutual)
        XCTAssertEqual(header.keydataBase64, "AAECAwQFBgcICQ==")
        XCTAssertEqual(header.keydata, Data([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]))
    }

    func testParsesAttributesInAnyOrder() throws {
        let raw = "keydata=AA==; prefer-encrypt=nopreference; addr=bob@example.org"
        let header = try AutocryptHeaderParser.parse(raw)
        XCTAssertEqual(header.address, "bob@example.org")
        XCTAssertEqual(header.preferEncrypt, .nopreference)
        XCTAssertEqual(header.keydataBase64, "AA==")
    }

    func testStripsFoldingWhitespaceFromKeydata() throws {
        let raw = """
        addr=alice@example.org; prefer-encrypt=mutual; \
        keydata=AAEC\
        AwQFBgcI\
        CQ==
        """
        let header = try AutocryptHeaderParser.parse(raw)
        XCTAssertEqual(header.keydataBase64, "AAECAwQFBgcICQ==")
    }

    func testThrowsOnMissingAddress() {
        XCTAssertThrowsError(try AutocryptHeaderParser.parse("keydata=AA==")) { error in
            guard case AutocryptHeaderParser.ParseError.missingAddress = error else {
                XCTFail("expected missingAddress, got \(error)")
                return
            }
        }
    }

    func testThrowsOnMissingKeydata() {
        XCTAssertThrowsError(
            try AutocryptHeaderParser.parse("addr=alice@example.org; prefer-encrypt=mutual")
        ) { error in
            guard case AutocryptHeaderParser.ParseError.missingKeydata = error else {
                XCTFail("expected missingKeydata, got \(error)")
                return
            }
        }
    }

    func testThrowsOnUnknownPreferEncrypt() {
        XCTAssertThrowsError(
            try AutocryptHeaderParser.parse("addr=a@b; prefer-encrypt=always; keydata=AA==")
        ) { error in
            guard case AutocryptHeaderParser.ParseError.unknownPreferEncrypt = error else {
                XCTFail("expected unknownPreferEncrypt, got \(error)")
                return
            }
        }
    }

    func testRendersHeaderRoundTripsThroughParse() throws {
        let original = AutocryptHeader(
            address: "alice@example.org",
            preferEncrypt: .mutual,
            keydataBase64: "AAECAwQFBgcICQ=="
        )
        let rendered = original.renderedHeaderValue()
        let reparsed = try AutocryptHeaderParser.parse(rendered)
        XCTAssertEqual(reparsed, original)
    }

    // MARK: - Store

    func testStoreKeepsLatestObservationPerAddress() throws {
        let store = try AutocryptStore(storeURL: nil)
        let early = Date(timeIntervalSince1970: 1_000)
        let late = Date(timeIntervalSince1970: 2_000)

        try store.observe(
            address: "Alice@Example.org",
            preferEncrypt: .nopreference,
            keydataBase64: "AA==",
            messageDate: early
        )
        try store.observe(
            address: "alice@example.org",
            preferEncrypt: .mutual,
            keydataBase64: "BB==",
            messageDate: late
        )

        let obs = try XCTUnwrap(store.observation(forAddress: "ALICE@example.org"))
        XCTAssertEqual(obs.preferEncrypt, .mutual)
        XCTAssertEqual(obs.keydataBase64, "BB==")
    }

    func testStoreIgnoresOlderObservation() throws {
        let store = try AutocryptStore(storeURL: nil)
        let early = Date(timeIntervalSince1970: 1_000)
        let late = Date(timeIntervalSince1970: 2_000)

        try store.observe(
            address: "a@b",
            preferEncrypt: .mutual,
            keydataBase64: "BB==",
            messageDate: late
        )
        try store.observe(
            address: "a@b",
            preferEncrypt: .nopreference,
            keydataBase64: "AA==",
            messageDate: early
        )

        let obs = try XCTUnwrap(store.observation(forAddress: "a@b"))
        XCTAssertEqual(obs.preferEncrypt, .mutual)
        XCTAssertEqual(obs.keydataBase64, "BB==")
    }

    func testMutualEncryptionPossibleRequiresBothPartiesMutual() throws {
        let store = try AutocryptStore(storeURL: nil)
        let date = Date()
        try store.observe(address: "alice@x", preferEncrypt: .mutual, keydataBase64: "AA==", messageDate: date)
        try store.observe(address: "bob@x", preferEncrypt: .mutual, keydataBase64: "BB==", messageDate: date)
        XCTAssertTrue(store.mutualEncryptionPossible(senderAddress: "alice@x", recipientAddress: "bob@x"))
    }

    func testMutualEncryptionNotPossibleWhenEitherLacksMutual() throws {
        let store = try AutocryptStore(storeURL: nil)
        let date = Date()
        try store.observe(address: "alice@x", preferEncrypt: .mutual, keydataBase64: "AA==", messageDate: date)
        try store.observe(address: "bob@x", preferEncrypt: .nopreference, keydataBase64: "BB==", messageDate: date)
        XCTAssertFalse(store.mutualEncryptionPossible(senderAddress: "alice@x", recipientAddress: "bob@x"))
    }

    func testStorePersistsAcrossInstances() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("autocrypt-test-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }

        let store1 = try AutocryptStore(storeURL: url)
        try store1.observe(
            address: "alice@x",
            preferEncrypt: .mutual,
            keydataBase64: "AA==",
            messageDate: Date()
        )

        let store2 = try AutocryptStore(storeURL: url)
        XCTAssertNotNil(store2.observation(forAddress: "alice@x"))
    }
}

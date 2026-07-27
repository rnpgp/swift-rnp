//
//  AutocryptGossipTests.swift
//  AutocryptTests
//

import XCTest
@testable import Autocrypt

final class AutocryptGossipTests: XCTestCase {

    func testParsesCanonicalGossipHeader() throws {
        let raw = "addr=bob@example.org; keydata=AAECAwQFBgcICQ=="
        let header = try AutocryptGossipParser.parse(raw)
        XCTAssertEqual(header.address, "bob@example.org")
        XCTAssertEqual(header.keydataBase64, "AAECAwQFBgcICQ==")
    }

    func testThrowsOnMissingAddress() {
        XCTAssertThrowsError(try AutocryptGossipParser.parse("keydata=AA==")) { error in
            guard case AutocryptGossipParser.ParseError.missingAddress = error else {
                XCTFail("expected missingAddress, got \(error)")
                return
            }
        }
    }

    func testThrowsOnMissingKeydata() {
        XCTAssertThrowsError(try AutocryptGossipParser.parse("addr=a@b")) { error in
            guard case AutocryptGossipParser.ParseError.missingKeydata = error else {
                XCTFail("expected missingKeydata, got \(error)")
                return
            }
        }
    }

    func testRendersRoundTripThroughParse() throws {
        let original = AutocryptGossipHeader(
            address: "carol@example.org",
            keydataBase64: "AAECAwQFBgcICQ=="
        )
        let rendered = original.renderedHeaderValue()
        let reparsed = try AutocryptGossipParser.parse(rendered)
        XCTAssertEqual(reparsed, original)
    }

    func testObserveGossipPreservesExistingPreferEncrypt() throws {
        let store = try AutocryptStore(storeURL: nil)
        let date = Date()
        try store.observe(
            address: "bob@x",
            preferEncrypt: .mutual,
            keydataBase64: "AA==",
            messageDate: date
        )
        let gossip = AutocryptGossipHeader(address: "bob@x", keydataBase64: "BB==")
        try store.observeGossip(gossip, messageDate: date.addingTimeInterval(60))
        let obs = try XCTUnwrap(store.observation(forAddress: "bob@x"))
        XCTAssertEqual(obs.preferEncrypt, .mutual)
        XCTAssertEqual(obs.keydataBase64, "BB==")
    }

    func testObserveGossipDefaultsToNoPreferenceWhenAddressNew() throws {
        let store = try AutocryptStore(storeURL: nil)
        let gossip = AutocryptGossipHeader(address: "new@x", keydataBase64: "BB==")
        try store.observeGossip(gossip, messageDate: Date())
        let obs = try XCTUnwrap(store.observation(forAddress: "new@x"))
        XCTAssertEqual(obs.preferEncrypt, .nopreference)
    }
}

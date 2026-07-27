//
//  AccountKeyedPolicyStoreTests.swift
//  AutocryptTests
//

import XCTest
@testable import Autocrypt

final class AccountKeyedPolicyStoreTests: XCTestCase {

    private var tempURL: URL!

    override func setUp() {
        super.setUp()
        tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("account-policy-\(UUID().uuidString).json")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempURL)
        tempURL = nil
        super.tearDown()
    }

    func testReturnsDefaultWhenNoOverride() throws {
        let store = try AccountKeyedPolicyStore(storeURL: tempURL)
        XCTAssertEqual(store.preferEncrypt(forAccount: "alice@x", default: .mutual), .mutual)
    }

    func testSetOverrideIsReturned() throws {
        let store = try AccountKeyedPolicyStore(storeURL: tempURL)
        try store.setPreferEncrypt(.nopreference, forAccount: "alice@x")
        XCTAssertEqual(store.preferEncrypt(forAccount: "alice@x", default: .mutual), .nopreference)
    }

    func testAddressIsCaseInsensitive() throws {
        let store = try AccountKeyedPolicyStore(storeURL: tempURL)
        try store.setPreferEncrypt(.encrypt, forAccount: "Alice@X")
        XCTAssertEqual(store.preferEncrypt(forAccount: "alice@x", default: .mutual), .encrypt)
        XCTAssertEqual(store.preferEncrypt(forAccount: "ALICE@X", default: .mutual), .encrypt)
    }

    func testPersistsAcrossInstances() throws {
        let store1 = try AccountKeyedPolicyStore(storeURL: tempURL)
        try store1.setPreferEncrypt(.disable, forAccount: "bob@x")
        let store2 = try AccountKeyedPolicyStore(storeURL: tempURL)
        XCTAssertEqual(store2.preferEncrypt(forAccount: "bob@x", default: .mutual), .disable)
    }

    func testClearRemovesOverride() throws {
        let store = try AccountKeyedPolicyStore(storeURL: tempURL)
        try store.setPreferEncrypt(.encrypt, forAccount: "carol@x")
        try store.clear(account: "carol@x")
        XCTAssertEqual(store.preferEncrypt(forAccount: "carol@x", default: .mutual), .mutual)
    }
}

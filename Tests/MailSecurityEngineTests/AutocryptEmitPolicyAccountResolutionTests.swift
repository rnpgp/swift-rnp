//
//  AutocryptEmitPolicyAccountResolutionTests.swift
//  MailSecurityEngineTests
//
//  The `resolved(forAccount:from:)` extension lives in
//  MailSecurityEngine (because AutocryptEmitPolicy does too), so its
//  tests live here rather than in AutocryptTests.
//

import XCTest
import Autocrypt
@testable import MailSecurityEngine

final class AutocryptEmitPolicyAccountResolutionTests: XCTestCase {

    private var tempURL: URL!

    override func setUp() {
        super.setUp()
        tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("account-res-\(UUID().uuidString).json")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempURL)
        tempURL = nil
        super.tearDown()
    }

    func testAlwaysPolicyUsesAccountOverride() throws {
        let store = try AccountKeyedPolicyStore(storeURL: tempURL)
        try store.setPreferEncrypt(.nopreference, forAccount: "alice@x")
        let resolved = AutocryptEmitPolicy.always(preferEncrypt: .mutual)
            .resolved(forAccount: "alice@x", from: store)
        if case let .always(preferEncrypt) = resolved {
            XCTAssertEqual(preferEncrypt, .nopreference)
        } else {
            XCTFail("expected .always, got \(resolved)")
        }
    }

    func testNeverPolicyStaysNeverRegardlessOfOverride() throws {
        let store = try AccountKeyedPolicyStore(storeURL: tempURL)
        try store.setPreferEncrypt(.mutual, forAccount: "alice@x")
        let resolved = AutocryptEmitPolicy.never
            .resolved(forAccount: "alice@x", from: store)
        XCTAssertEqual(resolved, .never)
    }

    func testOnlyWhenEncryptedPolicyUsesOverride() throws {
        let store = try AccountKeyedPolicyStore(storeURL: tempURL)
        try store.setPreferEncrypt(.encrypt, forAccount: "alice@x")
        let resolved = AutocryptEmitPolicy.onlyWhenEncrypted(preferEncrypt: .mutual)
            .resolved(forAccount: "alice@x", from: store)
        if case let .onlyWhenEncrypted(preferEncrypt) = resolved {
            XCTAssertEqual(preferEncrypt, .encrypt)
        } else {
            XCTFail("expected .onlyWhenEncrypted, got \(resolved)")
        }
    }

    func testFallsBackToDefaultWhenNoOverride() throws {
        let store = try AccountKeyedPolicyStore(storeURL: tempURL)
        let resolved = AutocryptEmitPolicy.always(preferEncrypt: .mutual)
            .resolved(forAccount: "new@x", from: store)
        if case let .always(preferEncrypt) = resolved {
            XCTAssertEqual(preferEncrypt, .mutual)
        } else {
            XCTFail("expected .always, got \(resolved)")
        }
    }
}

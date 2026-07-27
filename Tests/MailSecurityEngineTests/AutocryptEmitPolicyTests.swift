//
//  AutocryptEmitPolicyTests.swift
//  MailSecurityEngineTests
//

import XCTest
import Autocrypt
@testable import MailSecurityEngine

final class AutocryptEmitPolicyTests: XCTestCase {

    func testAlwaysEmitsForEncrypted() {
        let policy: AutocryptEmitPolicy = .always()
        let decision = policy.resolve(
            signerAddress: "alice@x",
            isEncrypted: true,
            isSigned: false
        )
        XCTAssertEqual(decision, .emit(preferEncrypt: .mutual, address: "alice@x"))
    }

    func testAlwaysEmitsForSignedOnly() {
        let policy: AutocryptEmitPolicy = .always()
        let decision = policy.resolve(
            signerAddress: "alice@x",
            isEncrypted: false,
            isSigned: true
        )
        XCTAssertEqual(decision, .emit(preferEncrypt: .mutual, address: "alice@x"))
    }

    func testAlwaysEmitsForPlaintextWhenMutual() {
        let policy: AutocryptEmitPolicy = .always(preferEncrypt: .mutual)
        let decision = policy.resolve(
            signerAddress: "alice@x",
            isEncrypted: false,
            isSigned: false
        )
        XCTAssertEqual(decision, .emit(preferEncrypt: .mutual, address: "alice@x"))
    }

    func testAlwaysSkipsForPlaintextWhenNotMutual() {
        let policy: AutocryptEmitPolicy = .always(preferEncrypt: .nopreference)
        let decision = policy.resolve(
            signerAddress: "alice@x",
            isEncrypted: false,
            isSigned: false
        )
        XCTAssertEqual(decision, .skip)
    }

    func testOnlyWhenEncryptedSkipsSignedOnly() {
        let policy: AutocryptEmitPolicy = .onlyWhenEncrypted()
        let decision = policy.resolve(
            signerAddress: "alice@x",
            isEncrypted: false,
            isSigned: true
        )
        XCTAssertEqual(decision, .skip)
    }

    func testOnlyWhenEncryptedEmitsWhenEncrypted() {
        let policy: AutocryptEmitPolicy = .onlyWhenEncrypted()
        let decision = policy.resolve(
            signerAddress: "alice@x",
            isEncrypted: true,
            isSigned: false
        )
        XCTAssertEqual(decision, .emit(preferEncrypt: .mutual, address: "alice@x"))
    }

    func testNeverAlwaysSkips() {
        let policy: AutocryptEmitPolicy = .never
        let encrypted = policy.resolve(signerAddress: "alice@x", isEncrypted: true, isSigned: true)
        let signed = policy.resolve(signerAddress: "alice@x", isEncrypted: false, isSigned: true)
        let plaintext = policy.resolve(signerAddress: "alice@x", isEncrypted: false, isSigned: false)
        XCTAssertEqual(encrypted, .skip)
        XCTAssertEqual(signed, .skip)
        XCTAssertEqual(plaintext, .skip)
    }

    func testSkipsWhenNoSignerAddress() {
        let policy: AutocryptEmitPolicy = .always()
        let decision = policy.resolve(signerAddress: nil, isEncrypted: true, isSigned: true)
        XCTAssertEqual(decision, .skip)
    }

    func testSkipsWhenSignerAddressEmpty() {
        let policy: AutocryptEmitPolicy = .always()
        let decision = policy.resolve(signerAddress: "", isEncrypted: true, isSigned: true)
        XCTAssertEqual(decision, .skip)
    }
}

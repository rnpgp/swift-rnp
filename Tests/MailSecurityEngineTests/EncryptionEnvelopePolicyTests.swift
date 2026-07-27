//
//  EncryptionEnvelopePolicyTests.swift
//  MailSecurityEngineTests
//

import XCTest
@testable import MailSecurityEngine

final class EncryptionEnvelopePolicyTests: XCTestCase {

    private func cap(_ address: String, aead: Bool, v6: Bool) -> RecipientEncryptionCapability {
        RecipientEncryptionCapability(address: address, supportsAEAD: aead, supportsV6: v6)
    }

    func testAutomaticPicksV6WhenEveryoneSupportsIt() {
        let result = EncryptionEnvelopeResolver.decide(
            capabilities: [
                cap("a@x", aead: true, v6: true),
                cap("b@x", aead: true, v6: true),
            ],
            policy: .automatic
        )
        XCTAssertEqual(result, .aeadOCBWithV6PKESK)
    }

    func testAutomaticFallsBackToAEADV3WhenV6NotUniversal() {
        let result = EncryptionEnvelopeResolver.decide(
            capabilities: [
                cap("a@x", aead: true, v6: true),
                cap("b@x", aead: true, v6: false),
            ],
            policy: .automatic
        )
        XCTAssertEqual(result, .aeadOCBWithV3PKESK)
    }

    func testAutomaticFallsBackToCFBWhenAnyRecipientLacksAEAD() {
        let result = EncryptionEnvelopeResolver.decide(
            capabilities: [
                cap("a@x", aead: true, v6: true),
                cap("b@x", aead: false, v6: false),
            ],
            policy: .automatic
        )
        XCTAssertEqual(result, .cfbWithMDC)
    }

    func testForceAEADRefusesWhenAnyRecipientLacksAEAD() {
        let result = EncryptionEnvelopeResolver.decide(
            capabilities: [
                cap("a@x", aead: true, v6: true),
                cap("b@x", aead: false, v6: false),
            ],
            policy: .forceAEAD
        )
        XCTAssertEqual(result, .refused(recipientsWithoutAEAD: ["b@x"]))
    }

    func testForceAEADSucceedsWithV6WhenAllSupportIt() {
        let result = EncryptionEnvelopeResolver.decide(
            capabilities: [
                cap("a@x", aead: true, v6: true),
                cap("b@x", aead: true, v6: true),
            ],
            policy: .forceAEAD
        )
        XCTAssertEqual(result, .aeadOCBWithV6PKESK)
    }

    func testForceAEADFallsBackToV3WhenNotAllV6() {
        let result = EncryptionEnvelopeResolver.decide(
            capabilities: [
                cap("a@x", aead: true, v6: false),
                cap("b@x", aead: true, v6: true),
            ],
            policy: .forceAEAD
        )
        XCTAssertEqual(result, .aeadOCBWithV3PKESK)
    }

    func testForceLegacyAlwaysCFB() {
        let result = EncryptionEnvelopeResolver.decide(
            capabilities: [
                cap("a@x", aead: true, v6: true),
                cap("b@x", aead: false, v6: false),
            ],
            policy: .forceLegacy
        )
        XCTAssertEqual(result, .cfbWithMDC)
    }
}

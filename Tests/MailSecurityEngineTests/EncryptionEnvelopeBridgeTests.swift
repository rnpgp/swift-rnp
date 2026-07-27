//
//  EncryptionEnvelopeBridgeTests.swift
//  MailSecurityEngineTests
//

import XCTest
import Rnp
@testable import MailSecurityEngine
final class EncryptionEnvelopeBridgeTests: XCTestCase {

    func testV6DecisionMapsToOCBAndV6() {
        let params = EncryptionEnvelopeResolver.Decision.aeadOCBWithV6PKESK.encryptParameters
        XCTAssertEqual(params?.aead, .ocb)
        XCTAssertEqual(params?.pkeskVersion, .v6)
    }

    func testV3DecisionMapsToOCBAndV3() {
        let params = EncryptionEnvelopeResolver.Decision.aeadOCBWithV3PKESK.encryptParameters
        XCTAssertEqual(params?.aead, .ocb)
        XCTAssertEqual(params?.pkeskVersion, .v3)
    }

    func testCFBDecisionMapsToNoAEADAndV3() throws {
        let params = try XCTUnwrap(EncryptionEnvelopeResolver.Decision.cfbWithMDC.encryptParameters)
        XCTAssertEqual(params.aead, .none)
        XCTAssertEqual(params.pkeskVersion, .v3)
    }
    func testRefusedReturnsNil() {
        let params = EncryptionEnvelopeResolver.Decision
            .refused(recipientsWithoutAEAD: ["a@x"])
            .encryptParameters
        XCTAssertNil(params)
    }

    func testLegacyStaticIsCFBAndV3() {
        XCTAssertEqual(EncryptEnvelopeParameters.legacy.aead, .none)
        XCTAssertEqual(EncryptEnvelopeParameters.legacy.pkeskVersion, .v3)
    }
}

//
//  DesignSystemTests.swift
//  swift-rnp
//
//  Unit tests for the shared design-system helpers in RnpMailUI.
//

import XCTest
@testable import RnpMailUI
import TrustStore

final class DesignSystemTests: CIBaseTestCase {
    func testGroupedFingerprintBlocks() {
        XCTAssertEqual("ABCD1234EFGH".groupedFingerprintBlocks, "ABCD 1234 EFGH")
        XCTAssertEqual("ABC".groupedFingerprintBlocks, "ABC")
        XCTAssertEqual("".groupedFingerprintBlocks, "")

        let fingerprint = "74E2A1E008CB1B1021192AA05225D37282795A2F"
        XCTAssertEqual(
            fingerprint.groupedFingerprintBlocks,
            "74E2 A1E0 08CB 1B10 2119 2AA0 5225 D372 8279 5A2F"
        )
    }

    func testGroupedFingerprintAbbreviated() {
        let fingerprint = "74E2A1E008CB1B1021192AA05225D37282795A2F"
        XCTAssertEqual(fingerprint.groupedFingerprintAbbreviated, "74E2 A1E0 08CB 1B10 …")
        // Short strings are grouped but not given an ellipsis.
        XCTAssertEqual("ABCD1234".groupedFingerprintAbbreviated, "ABCD 1234")
    }

    func testTrustPresentationMapping() {
        let verified = TrustPresentation(state: .verified)
        XCTAssertEqual(verified.iconName, "checkmark.shield.fill")
        XCTAssertEqual(verified.labelKey, "trust.verified")

        let unverified = TrustPresentation(state: .unverified)
        XCTAssertEqual(unverified.iconName, "questionmark.shield")
        XCTAssertEqual(unverified.labelKey, "trust.unverified")

        let problem = TrustPresentation(state: .problem)
        XCTAssertEqual(problem.iconName, "exclamationmark.shield.fill")
        XCTAssertEqual(problem.labelKey, "trust.conflict")

        // Every state has a non-empty description key for the trust card.
        for state in [TrustState.verified, .unverified, .problem] {
            XCTAssertFalse(TrustPresentation(state: state).descriptionKey.isEmpty)
        }
    }
}

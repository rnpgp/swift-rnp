//
//  DecryptionFailurePresentationTests.swift
//  MailSecurityUITests
//

import XCTest
import MailSecurityEngine
@testable import MailSecurityUI

final class DecryptionFailurePresentationTests: XCTestCase {

    func testMissingKeyFetchActionSurfacesFetchButton() {
        let failure = DecryptionFailure.missingSecretKey(
            pkeskKeyIDs: ["ABCDEF0123456789"],
            suggestedAction: .fetchFromKeyserver(keyID: "ABCDEF0123456789")
        )
        let p = DecryptionFailurePresentation.presentation(for: failure)
        XCTAssertEqual(p.primaryAction, .fetchFromKeyserver(keyID: "ABCDEF0123456789"))
        XCTAssertEqual(p.secondaryAction, .importKeyManually)
    }

    func testMissingKeyArchivedSurfacesRestoreButton() {
        let failure = DecryptionFailure.missingSecretKey(
            pkeskKeyIDs: ["1111111111111111"],
            suggestedAction: .restoreFromArchive(
                fingerprint: "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ",
                archivedDate: Date()
            )
        )
        let p = DecryptionFailurePresentation.presentation(for: failure)
        XCTAssertEqual(p.primaryAction, .restoreFromArchive(fingerprint: "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ"))
        XCTAssertNil(p.secondaryAction)
    }

    func testMissingKeyAnonymousSurfacesRefreshButton() {
        let failure = DecryptionFailure.missingSecretKey(
            pkeskKeyIDs: [],
            suggestedAction: .none
        )
        let p = DecryptionFailurePresentation.presentation(for: failure)
        XCTAssertEqual(p.primaryAction, .refreshKeyring)
    }

    func testWrongPassphraseSurfacesEnterPassphrase() {
        let p = DecryptionFailurePresentation.presentation(for: .wrongPassphrase)
        XCTAssertEqual(p.primaryAction, .enterPassphrase)
    }

    func testIntegrityFailureSurfacesDiagnostics() {
        let p = DecryptionFailurePresentation.presentation(for: .integrityFailure)
        XCTAssertEqual(p.primaryAction, .openDiagnostics)
        XCTAssertNil(p.secondaryAction)
    }

    func testUnsupportedAlgorithmSurfacesCheckForUpdates() {
        let p = DecryptionFailurePresentation.presentation(for: .unsupportedAlgorithm("experimental-cipher"))
        XCTAssertEqual(p.primaryAction, .checkForUpdates)
        XCTAssertEqual(p.secondaryAction, .openMessageSource)
    }

    func testSymmetricEncryptionSurfacesEnterPassphrase() {
        let p = DecryptionFailurePresentation.presentation(for: .symmetricEncryption)
        XCTAssertEqual(p.primaryAction, .enterPassphrase)
    }

    func testMalformedArmorSurfacesOpenMessageSource() {
        let p = DecryptionFailurePresentation.presentation(for: .malformedArmor(detail: "CRC error"))
        XCTAssertEqual(p.primaryAction, .openMessageSource)
        XCTAssertEqual(p.secondaryAction, .openDiagnostics)
    }

    func testUnknownFailureSurfacesDiagnostics() {
        let p = DecryptionFailurePresentation.presentation(for: .unknown(librnpMessage: "generic"))
        XCTAssertEqual(p.primaryAction, .openDiagnostics)
    }

    func testEncryptionInfoFromPreservesBannerText() {
        let failure = DecryptionFailure.wrongPassphrase
        let info = MailSecurityBannerView.EncryptionInfo.from(failure)
        XCTAssertTrue(info.isEncrypted)
        XCTAssertEqual(info.errorDescription, failure.bannerText)
    }
}

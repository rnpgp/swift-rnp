//
//  DecryptionFailureClassifierTests.swift
//  MailSecurityEngineTests
//
//  Exhaustive table-driven tests for the pure failure classifier. The
//  classifier takes a librnp error string + a `PacketDump` (or nil) + a
//  keyring-lookup closure; tests construct inputs directly without
//  touching FFI or filesystem.
//

import XCTest
@testable import MailSecurityEngine

final class DecryptionFailureClassifierTests: XCTestCase {

    func testIntegrityFailureRecognizedFromMDCMessage() {
        let result = DecryptionFailureClassifier.classify(
            librnpError: "MDC check failed",
            dump: nil,
            context: .noOp
        )
        XCTAssertEqual(result, .integrityFailure)
    }

    func testIntegrityFailureRecognizedFromAEADAuthMessage() {
        let result = DecryptionFailureClassifier.classify(
            librnpError: "AEAD auth tag mismatch",
            dump: nil,
            context: .noOp
        )
        XCTAssertEqual(result, .integrityFailure)
    }

    func testWrongPassphraseRecognizedFromPassphraseMessage() {
        let result = DecryptionFailureClassifier.classify(
            librnpError: "invalid passphrase / wrong key password",
            dump: PacketDump(
                pkeskKeyIDs: ["ABCDEF0123456789"],
                usesAnonymousPKESK: false,
                symmetricallyEncrypted: false,
                aeadAlgorithm: nil,
                unsupportedAlgorithm: nil
            ),
            context: .init(lookup: { _ in
                DecryptionFailureClassifier.KeyHit(
                    fingerprint: "FFFFFFFF", isArchived: false
                )
            })
        )
        XCTAssertEqual(result, .wrongPassphrase)
    }

    func testMissingSecretKeyWithKnownKeyIDSuggestsFetch() {
        let dump = PacketDump(
            pkeskKeyIDs: ["ABCDEF0123456789"],
            usesAnonymousPKESK: false,
            symmetricallyEncrypted: false,
            aeadAlgorithm: nil,
            unsupportedAlgorithm: nil
        )
        let result = DecryptionFailureClassifier.classify(
            librnpError: "failed to decrypt",
            dump: dump,
            context: .noOp
        )
        XCTAssertEqual(
            result,
            .missingSecretKey(
                pkeskKeyIDs: ["ABCDEF0123456789"],
                suggestedAction: .fetchFromKeyserver(keyID: "ABCDEF0123456789")
            )
        )
    }

    func testMissingSecretKeyWithArchivedMatchSuggestsRestore() {
        let archivedDate = Date(timeIntervalSince1970: 1_700_000_000)
        let dump = PacketDump(
            pkeskKeyIDs: ["ABCDEF0123456789"],
            usesAnonymousPKESK: false,
            symmetricallyEncrypted: false,
            aeadAlgorithm: nil,
            unsupportedAlgorithm: nil
        )
        let context = DecryptionFailureClassifier.KeyringContext(lookup: { _ in
            DecryptionFailureClassifier.KeyHit(
                fingerprint: "FFFFFFFFFFFFFFFF",
                isArchived: true,
                archivedDate: archivedDate
            )
        })
        let result = DecryptionFailureClassifier.classify(
            librnpError: "failed to decrypt",
            dump: dump,
            context: context
        )
        XCTAssertEqual(
            result,
            .missingSecretKey(
                pkeskKeyIDs: ["ABCDEF0123456789"],
                suggestedAction: .restoreFromArchive(
                    fingerprint: "FFFFFFFFFFFFFFFF",
                    archivedDate: archivedDate
                )
            )
        )
    }

    func testAnonymousV6PKESKSurfacesAsNoAction() {
        let dump = PacketDump(
            pkeskKeyIDs: [],
            usesAnonymousPKESK: true,
            symmetricallyEncrypted: false,
            aeadAlgorithm: nil,
            unsupportedAlgorithm: nil
        )
        let result = DecryptionFailureClassifier.classify(
            librnpError: "no key",
            dump: dump,
            context: .noOp
        )
        XCTAssertEqual(
            result,
            .missingSecretKey(pkeskKeyIDs: [], suggestedAction: .none)
        )
    }

    func testSymmetricEncryptionDetectedWhenNoPKESK() {
        let dump = PacketDump(
            pkeskKeyIDs: [],
            usesAnonymousPKESK: false,
            symmetricallyEncrypted: true,
            aeadAlgorithm: nil,
            unsupportedAlgorithm: nil
        )
        let result = DecryptionFailureClassifier.classify(
            librnpError: "failed",
            dump: dump,
            context: .noOp
        )
        XCTAssertEqual(result, .symmetricEncryption)
    }

    func testUnsupportedAlgorithmSurfacedByName() {
        let dump = PacketDump(
            pkeskKeyIDs: ["1111111111111111"],
            usesAnonymousPKESK: false,
            symmetricallyEncrypted: false,
            aeadAlgorithm: nil,
            unsupportedAlgorithm: "experimental-cipher-42"
        )
        let result = DecryptionFailureClassifier.classify(
            librnpError: "unknown algo",
            dump: dump,
            context: .noOp
        )
        XCTAssertEqual(result, .unsupportedAlgorithm("experimental-cipher-42"))
    }

    func testMalformedArmorWhenNoDumpAndArmorText() {
        let result = DecryptionFailureClassifier.classify(
            librnpError: "armor CRC error at line 12",
            dump: nil,
            context: .noOp
        )
        XCTAssertEqual(result, .malformedArmor(detail: "armor CRC error at line 12"))
    }

    func testUnknownFallbackPreservesLibrnpMessage() {
        let result = DecryptionFailureClassifier.classify(
            librnpError: "rnp_unknown generic failure",
            dump: nil,
            context: .noOp
        )
        XCTAssertEqual(result, .unknown(librnpMessage: "rnp_unknown generic failure"))
    }

    // MARK: - Packet-dump parsing

    func testParseDumpsPKESKKeyIDs() {
        let json = """
        {
          "packets": [
            {"type": "pkesk v3", "keyid": "ABCDEF0123456789"},
            {"type": "pkesk v3", "keyid": "FFFFFFFFFFFFFFFF"},
            {"type": "seipd v1"}
          ]
        }
        """
        let dump = PacketDump.parse(json: json)
        XCTAssertEqual(dump?.pkeskKeyIDs, ["ABCDEF0123456789", "FFFFFFFFFFFFFFFF"])
        XCTAssertEqual(dump?.usesAnonymousPKESK, false)
        XCTAssertEqual(dump?.symmetricallyEncrypted, false)
    }

    func testParseRecognizesAnonymousV6PKESK() {
        let json = """
        {
          "packets": [
            {"type": "pkesk v6"},
            {"type": "seipd v2"}
          ]
        }
        """
        let dump = PacketDump.parse(json: json)
        XCTAssertEqual(dump?.pkeskKeyIDs, [])
        XCTAssertEqual(dump?.usesAnonymousPKESK, true)
    }

    func testParseRecognizesSymmetricEncryption() {
        let json = """
        {
          "packets": [
            {"type": "skesk"},
            {"type": "sed"}
          ]
        }
        """
        let dump = PacketDump.parse(json: json)
        XCTAssertEqual(dump?.symmetricallyEncrypted, true)
        XCTAssertEqual(dump?.pkeskKeyIDs, [])
    }

    func testParseFlagsExperimentalCipherAsUnsupported() {
        let json = """
        {
          "packets": [
            {"type": "aead-encrypted", "cipher": "experimental-101"}
          ]
        }
        """
        let dump = PacketDump.parse(json: json)
        XCTAssertEqual(dump?.unsupportedAlgorithm, "experimental-101")
    }

    // MARK: - Banner copy

    func testBannerTextForMissingKeyFetchAction() {
        let failure = DecryptionFailure.missingSecretKey(
            pkeskKeyIDs: ["ABCDEF0123456789"],
            suggestedAction: .fetchFromKeyserver(keyID: "ABCDEF0123456789")
        )
        XCTAssertEqual(
            failure.bannerText,
            "Encrypted to a key you don't have (key ID ABCDEF0123456789)."
        )
    }

    func testBannerTextForRestoreFromArchive() {
        let failure = DecryptionFailure.missingSecretKey(
            pkeskKeyIDs: ["ABCDEF0123456789"],
            suggestedAction: .restoreFromArchive(
                fingerprint: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                archivedDate: Date()
            )
        )
        XCTAssertEqual(
            failure.bannerText,
            "Encrypted to your archived key FFFFFFFFFFFFFFFF."
        )
    }
}

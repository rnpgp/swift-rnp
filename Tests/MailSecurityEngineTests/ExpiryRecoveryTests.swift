//
//  ExpiryRecoveryTests.swift
//  MailSecurityEngineTests
//
//  Exhaustive table-driven tests for the recovery mapping. Each scenario
//  from TODO.roadmap/04-key-expiry-recovery.md produces a specific
//  recommendation.
//

import XCTest
@testable import MailSecurityEngine
import KeyStateStore

final class ExpiryRecoveryTests: XCTestCase {

    private let fpr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    // MARK: - Own key, secret available

    func testHealthyOwnKeyNoAction() {
        let rec = ExpiryRecovery.action(
            state: .healthy,
            role: .ownSecretAvailable,
            address: nil,
            fingerprint: fpr
        )
        XCTAssertNil(rec.primary)
        XCTAssertEqual(rec.explanation, "Key is healthy.")
    }

    func testExpiringSoonOwnKeySuggestsExtend() {
        let rec = ExpiryRecovery.action(
            state: .expiringSoon,
            role: .ownSecretAvailable,
            address: nil,
            fingerprint: fpr
        )
        XCTAssertEqual(rec.primary, .extendExpiry(keyFingerprint: fpr, defaultYears: 2))
        XCTAssertTrue(rec.secondary.contains(.publishKey(keyFingerprint: fpr)))
        XCTAssertTrue(rec.secondary.contains(.notifyContacts(keyFingerprint: fpr)))
    }

    func testExpiredOwnKeySuggestsExtendAndRotate() {
        let rec = ExpiryRecovery.action(
            state: .expired,
            role: .ownSecretAvailable,
            address: nil,
            fingerprint: fpr
        )
        XCTAssertEqual(rec.primary, .extendExpiry(keyFingerprint: fpr, defaultYears: 2))
        XCTAssertTrue(rec.secondary.contains(.rotateEncryptionSubkey(keyFingerprint: fpr)))
    }

    // MARK: - Own key, secret missing

    func testExpiringSoonOwnKeyNoSecretSuggestsGenerateReplacement() {
        let rec = ExpiryRecovery.action(
            state: .expiringSoon,
            role: .ownSecretMissing,
            address: nil,
            fingerprint: fpr
        )
        XCTAssertEqual(rec.primary, .generateReplacementKey(viaTransitionWizard: false))
    }

    func testExpiredOwnKeyNoSecretSuggestsGenerateReplacementAndVerify() {
        let rec = ExpiryRecovery.action(
            state: .expired,
            role: .ownSecretMissing,
            address: nil,
            fingerprint: fpr
        )
        XCTAssertEqual(rec.primary, .generateReplacementKey(viaTransitionWizard: false))
        XCTAssertTrue(rec.secondary.contains(.verifyFingerprint(keyFingerprint: fpr)))
    }

    // MARK: - Recipient key

    func testExpiringSoonRecipientSuggestsFetch() {
        let rec = ExpiryRecovery.action(
            state: .expiringSoon,
            role: .recipient,
            address: "bob@x",
            fingerprint: fpr
        )
        XCTAssertEqual(rec.primary, .fetchLatestFromKeyserver(address: "bob@x"))
        XCTAssertTrue(rec.secondary.contains(.contactOutOfBand(address: "bob@x")))
    }

    func testExpiredRecipientSuggestsFetchThenOutOfBand() {
        let rec = ExpiryRecovery.action(
            state: .expired,
            role: .recipient,
            address: "bob@x",
            fingerprint: fpr
        )
        XCTAssertEqual(rec.primary, .fetchLatestFromKeyserver(address: "bob@x"))
        XCTAssertTrue(rec.secondary.contains(.contactOutOfBand(address: "bob@x")))
    }

    func testRevokedRecipientSuggestsFetch() {
        let rec = ExpiryRecovery.action(
            state: .revoked,
            role: .recipient,
            address: "bob@x",
            fingerprint: fpr
        )
        XCTAssertEqual(rec.primary, .fetchLatestFromKeyserver(address: "bob@x"))
    }

    // MARK: - Revoked own key

    func testRevokedOwnKeySuggestsArchiveThenGenerate() {
        let rec = ExpiryRecovery.action(
            state: .revoked,
            role: .ownSecretAvailable,
            address: nil,
            fingerprint: fpr
        )
        XCTAssertEqual(rec.primary, .archiveKey(keyFingerprint: fpr))
        XCTAssertTrue(rec.secondary.contains(.generateReplacementKey(viaTransitionWizard: true)))
    }

    // MARK: - Archived

    func testArchivedKeyHasNoPrimaryAction() {
        let rec = ExpiryRecovery.action(
            state: .archived,
            role: .ownSecretAvailable,
            address: nil,
            fingerprint: fpr
        )
        XCTAssertNil(rec.primary)
        XCTAssertTrue(rec.explanation.contains("archived"))
    }

    // MARK: - Conflict

    func testConflictKeySuggestsVerify() {
        let rec = ExpiryRecovery.action(
            state: .conflict,
            role: .recipient,
            address: "bob@x",
            fingerprint: fpr
        )
        XCTAssertEqual(rec.primary, .verifyFingerprint(keyFingerprint: fpr))
    }

    // MARK: - State derivation from KeyInfo

    func testStateDerivationForExpiringSoon() {
        let info = makeInfo(expirationOffset: +30 * 24 * 3600)
        let state = ExpiryRecovery.state(
            for: info,
            role: .ownSecretAvailable,
            usageState: .active
        )
        XCTAssertEqual(state, .expiringSoon)
    }

    func testStateDerivationForExpired() {
        let info = makeInfo(expirationOffset: -1 * 24 * 3600)
        let state = ExpiryRecovery.state(
            for: info,
            role: .ownSecretAvailable,
            usageState: .active
        )
        XCTAssertEqual(state, .expired)
    }

    func testStateDerivationForArchivedOverride() {
        let info = makeInfo(expirationOffset: +365 * 24 * 3600)
        let state = ExpiryRecovery.state(
            for: info,
            role: .ownSecretAvailable,
            usageState: .archived
        )
        XCTAssertEqual(state, .archived)
    }

    func testStateDerivationForRevokedOverridesExpiry() {
        let info = makeInfo(expirationOffset: -10 * 24 * 3600, revoked: true)
        let state = ExpiryRecovery.state(
            for: info,
            role: .ownSecretAvailable,
            usageState: .active
        )
        XCTAssertEqual(state, .revoked)
    }

    private func makeInfo(expirationOffset: TimeInterval, revoked: Bool = false) -> KeyInfo {
        KeyInfo(
            fingerprint: fpr,
            primaryUserID: "test@example.org",
            userIDs: ["test@example.org"],
            hasSecret: true,
            algorithm: "Ed25519",
            bits: 256,
            creationDate: Date().addingTimeInterval(-365 * 24 * 3600),
            expirationDate: Date().addingTimeInterval(expirationOffset),
            isRevoked: revoked,
            subkeyCount: 1
        )
    }
}

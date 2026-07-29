//
//  RecipientClassifierTests.swift
//  MailSecurityEngineTests
//
//  Unit tests for the pure RecipientClassifier. These do NOT need
//  librnp — the classifier operates on plain RecipientSnapshot values,
//  which is the whole point of having extracted it from
//  MessageSecurityCore.classify.
//

import Foundation
import XCTest
import MailSecurityEngine
import TrustStore

final class RecipientClassifierTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func key(
        fingerprint: String = "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        expirationDate: Date? = nil,
        isRevoked: Bool = false
    ) -> KeyInfo {
        KeyInfo(
            fingerprint: fingerprint,
            primaryUserID: "x",
            userIDs: [],
            hasSecret: false,
            algorithm: "Ed25519",
            bits: 256,
            creationDate: Date(timeIntervalSince1970: 0),
            expirationDate: expirationDate,
            isRevoked: isRevoked,
            subkeyCount: 0
        )
    }

    // MARK: - Missing / archived

    func testNoKeyAndNotArchivedIsMissingKey() {
        let snapshot = RecipientSnapshot(
            address: "a@x",
            keyInfo: nil,
            isArchivedOnly: false
        )
        XCTAssertEqual(RecipientClassifier.classify(snapshot, now: now), .missingKey)
    }

    func testNoKeyButArchivedOnlyIsArchived() {
        let snapshot = RecipientSnapshot(
            address: "a@x",
            keyInfo: nil,
            isArchivedOnly: true
        )
        XCTAssertEqual(RecipientClassifier.classify(snapshot, now: now), .archived)
    }

    // MARK: - Conflict beats everything else

    func testExplicitConflictBeatsRevoked() {
        let snapshot = RecipientSnapshot(
            address: "a@x",
            keyInfo: key(isRevoked: true),
            trustState: .verified,
            hasTrustConflict: true
        )
        XCTAssertEqual(RecipientClassifier.classify(snapshot, now: now), .keyChangedConflict)
    }

    func testTrustProblemBeatsRevoked() {
        let snapshot = RecipientSnapshot(
            address: "a@x",
            keyInfo: key(isRevoked: true),
            trustState: .problem,
            hasTrustConflict: false
        )
        XCTAssertEqual(RecipientClassifier.classify(snapshot, now: now), .keyChangedConflict)
    }

    // MARK: - Revoked

    func testRevokedKeyWithNoConflictIsRevoked() {
        let snapshot = RecipientSnapshot(
            address: "a@x",
            keyInfo: key(isRevoked: true),
            trustState: .verified
        )
        XCTAssertEqual(RecipientClassifier.classify(snapshot, now: now), .revoked)
    }

    // MARK: - Expiry

    func testAlreadyExpiredKeyIsExpiredWithNilDays() {
        let snapshot = RecipientSnapshot(
            address: "a@x",
            keyInfo: key(expirationDate: now.addingTimeInterval(-1)),
            trustState: .verified
        )
        XCTAssertEqual(
            RecipientClassifier.classify(snapshot, now: now),
            .expired(daysUntilExpiry: nil)
        )
    }

    func testUpcomingExpiryWithinThresholdIsExpiredWithDays() {
        let inTenDays = now.addingTimeInterval(10 * 24 * 60 * 60)
        let snapshot = RecipientSnapshot(
            address: "a@x",
            keyInfo: key(expirationDate: inTenDays),
            trustState: .verified
        )
        XCTAssertEqual(
            RecipientClassifier.classify(snapshot, now: now),
            .expired(daysUntilExpiry: 10)
        )
    }

    func testExpiryBeyondThresholdDoesNotCount() {
        let inAHundredDays = now.addingTimeInterval(100 * 24 * 60 * 60)
        let snapshot = RecipientSnapshot(
            address: "a@x",
            keyInfo: key(expirationDate: inAHundredDays),
            trustState: .verified
        )
        XCTAssertEqual(RecipientClassifier.classify(snapshot, now: now), .verified)
    }

    // MARK: - Healthy

    func testVerifiedTrustAndNoIssuesIsVerified() {
        let snapshot = RecipientSnapshot(
            address: "a@x",
            keyInfo: key(),
            trustState: .verified
        )
        XCTAssertEqual(RecipientClassifier.classify(snapshot, now: now), .verified)
    }

    func testUnverifiedTrustAndNoIssuesIsUnverified() {
        let snapshot = RecipientSnapshot(
            address: "a@x",
            keyInfo: key(),
            trustState: .unverified
        )
        XCTAssertEqual(RecipientClassifier.classify(snapshot, now: now), .unverified)
    }
}

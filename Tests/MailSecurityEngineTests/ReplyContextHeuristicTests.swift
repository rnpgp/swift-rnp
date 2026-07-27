//
//  ReplyContextHeuristicTests.swift
//  MailSecurityEngineTests
//

import XCTest
@testable import MailSecurityEngine

final class ReplyContextHeuristicTests: XCTestCase {

    func testReplyToEncryptedDefaultsToEncryptedSigned() {
        let ctx = ReplyContext(
            originalWasEncrypted: true,
            originalWasSigned: true,
            replyToAddress: "alice@x",
            hasUsableKeyForReplyTo: true,
            userHasSigningKey: true
        )
        let rec = ReplyContextHeuristic.recommend(for: ctx)
        XCTAssertTrue(rec.shouldEncrypt)
        XCTAssertTrue(rec.shouldSign)
    }

    func testReplyToEncryptedWithoutSigningKeyStillEncrypts() {
        let ctx = ReplyContext(
            originalWasEncrypted: true,
            originalWasSigned: false,
            replyToAddress: "alice@x",
            hasUsableKeyForReplyTo: true,
            userHasSigningKey: false
        )
        let rec = ReplyContextHeuristic.recommend(for: ctx)
        XCTAssertTrue(rec.shouldEncrypt)
        XCTAssertFalse(rec.shouldSign)
    }

    func testReplyToSignedWithBothKeysDefaultsToEncryptedSigned() {
        let ctx = ReplyContext(
            originalWasEncrypted: false,
            originalWasSigned: true,
            replyToAddress: "alice@x",
            hasUsableKeyForReplyTo: true,
            userHasSigningKey: true
        )
        let rec = ReplyContextHeuristic.recommend(for: ctx)
        XCTAssertTrue(rec.shouldEncrypt)
        XCTAssertTrue(rec.shouldSign)
    }

    func testReplyToPlaintextUnsignedLeavesDefaultsAtPlaintext() {
        let ctx = ReplyContext(
            originalWasEncrypted: false,
            originalWasSigned: false,
            replyToAddress: "alice@x",
            hasUsableKeyForReplyTo: true,
            userHasSigningKey: true
        )
        let rec = ReplyContextHeuristic.recommend(for: ctx)
        XCTAssertFalse(rec.shouldEncrypt)
        XCTAssertFalse(rec.shouldSign)
    }

    func testNoUsableKeyForReplyToDisablesEncryption() {
        let ctx = ReplyContext(
            originalWasEncrypted: true,
            originalWasSigned: true,
            replyToAddress: "alice@x",
            hasUsableKeyForReplyTo: false,
            userHasSigningKey: true
        )
        let rec = ReplyContextHeuristic.recommend(for: ctx)
        XCTAssertFalse(rec.shouldEncrypt)
        // Sign is kept if original was signed and user has a signing key.
        XCTAssertTrue(rec.shouldSign)
    }

    func testNoUsableKeyAndUnsignedOriginalDisablesSign() {
        let ctx = ReplyContext(
            originalWasEncrypted: false,
            originalWasSigned: false,
            replyToAddress: "alice@x",
            hasUsableKeyForReplyTo: false,
            userHasSigningKey: true
        )
        let rec = ReplyContextHeuristic.recommend(for: ctx)
        XCTAssertFalse(rec.shouldEncrypt)
        XCTAssertFalse(rec.shouldSign)
    }
}

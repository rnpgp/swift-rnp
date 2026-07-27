//
//  NotifyContactsTemplateTests.swift
//  MailSecurityEngineTests
//

import XCTest
@testable import MailSecurityEngine

final class NotifyContactsTemplateTests: XCTestCase {

    private let fpr = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
    private let shortFpr = "0123456789ABCDEF"

    func testExtendExpiryMentionsDate() {
        let date = Date(timeIntervalSince1970: 1_834_000_000)  // 2028-02-11ish
        let email = NotifyContactsTemplate.render(
            trigger: .extendExpiry(newExpiration: date),
            senderName: "Alice",
            senderAddress: "alice@example.org",
            primaryUserID: "Alice <alice@example.org>",
            fingerprint: fpr,
            shortFingerprint: shortFpr
        )
        XCTAssertTrue(email.subject.contains("expiry extended"))
        XCTAssertTrue(email.body.contains("2028"))
    }

    func testRotateEncryptionSubkeyMentionsRefresh() {
        let email = NotifyContactsTemplate.render(
            trigger: .rotateEncryptionSubkey,
            senderName: "Alice",
            senderAddress: "alice@example.org",
            primaryUserID: "Alice <alice@example.org>",
            fingerprint: fpr,
            shortFingerprint: shortFpr
        )
        XCTAssertTrue(email.subject.contains("encryption subkey"))
        XCTAssertTrue(email.body.contains("refresh"))
    }

    func testRotateSigningSubkeyMentionsRefresh() {
        let email = NotifyContactsTemplate.render(
            trigger: .rotateSigningSubkey,
            senderName: "Alice",
            senderAddress: "alice@example.org",
            primaryUserID: "Alice <alice@example.org>",
            fingerprint: fpr,
            shortFingerprint: shortFpr
        )
        XCTAssertTrue(email.subject.contains("signing subkey"))
    }

    func testRevokeIncludesReason() {
        let email = NotifyContactsTemplate.render(
            trigger: .revoke(reason: "compromised"),
            senderName: "Alice",
            senderAddress: "alice@example.org",
            primaryUserID: "Alice <alice@example.org>",
            fingerprint: fpr,
            shortFingerprint: shortFpr
        )
        XCTAssertTrue(email.subject.contains("revoked"))
        XCTAssertTrue(email.body.contains("compromised"))
    }

    func testTransitionToNewKeyIncludesNewFingerprint() {
        let newFpr = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"
        let email = NotifyContactsTemplate.render(
            trigger: .transitionToNewKey(newFingerprint: newFpr),
            senderName: "Alice",
            senderAddress: "alice@example.org",
            primaryUserID: "Alice <alice@example.org>",
            fingerprint: fpr,
            shortFingerprint: shortFpr
        )
        XCTAssertTrue(email.subject.contains("new fingerprint"))
        // The body groups the new fingerprint into 4-hex chunks, so the
        // check needs the grouped form OR a substring of it.
        XCTAssertTrue(email.body.contains("FEDC BA98 7654 3210"))
        XCTAssertTrue(email.body.contains("superseded"))
    }

    func testSignatureFallsBackToUserIDNameWhenSenderNameEmpty() {
        let email = NotifyContactsTemplate.render(
            trigger: .rotateEncryptionSubkey,
            senderName: "",
            senderAddress: "alice@example.org",
            primaryUserID: "Alex Wong <alice@example.org>",
            fingerprint: fpr,
            shortFingerprint: shortFpr
        )
        XCTAssertTrue(email.body.contains("Alex Wong"))
    }

    func testGroupedFingerprintFormat() {
        let grouped = NotifyContactsTemplate.groupedFingerprint(fpr)
        XCTAssertEqual(grouped, "ABCD EF01 2345 6789 ABCD EF01 2345 6789 ABCD EF01")
    }

    func testGroupedFingerprintStripsExistingSeparators() {
        let grouped = NotifyContactsTemplate.groupedFingerprint("ab:cd:ef 01 23 45")
        XCTAssertEqual(grouped, "ABCD EF01 2345")
    }

    func testSuggestedRecipientsPropagated() {
        let email = NotifyContactsTemplate.render(
            trigger: .rotateEncryptionSubkey,
            senderName: "Alice",
            senderAddress: "alice@example.org",
            primaryUserID: "Alice <alice@example.org>",
            fingerprint: fpr,
            shortFingerprint: shortFpr,
            suggestedRecipients: ["bob@example.org", "carol@example.org"]
        )
        XCTAssertEqual(email.suggestedRecipients, ["bob@example.org", "carol@example.org"])
    }
}

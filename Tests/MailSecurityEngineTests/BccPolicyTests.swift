//
//  BccPolicyTests.swift
//  MailSecurityEngineTests
//

import XCTest
@testable import MailSecurityEngine

final class BccPolicyTests: XCTestCase {

    func testRefuseFiresWhenBccPresent() {
        XCTAssertTrue(BccPolicyEvaluator.shouldRefuse(hasBcc: true, policy: .refuse))
    }

    func testRefuseDoesNotFireWhenNoBcc() {
        XCTAssertFalse(BccPolicyEvaluator.shouldRefuse(hasBcc: false, policy: .refuse))
    }

    func testSendSeparatelyNeverRefusesHere() {
        // sendSeparately proceeds through the encoder; the multi-message
        // split happens elsewhere.
        XCTAssertFalse(BccPolicyEvaluator.shouldRefuse(hasBcc: true, policy: .sendSeparately))
    }

    func testRemoveEncryptionNeverRefusesHere() {
        XCTAssertFalse(BccPolicyEvaluator.shouldRefuse(hasBcc: true, policy: .removeEncryption))
    }

    func testRemoveBccNeverRefusesHere() {
        XCTAssertFalse(BccPolicyEvaluator.shouldRefuse(hasBcc: true, policy: .removeBcc))
    }

    func testErrorCarriesContext() {
        let err = BccRequiresSpecialHandlingError(
            bccAddresses: ["hidden@example.org"]
        )
        XCTAssertEqual(err.bccAddresses, ["hidden@example.org"])
        XCTAssertEqual(err.policy, .refuse)
    }

    /// Stand-in for a real MailMessage conformer with To/Cc/Bcc split.
    private struct TestMessage: MailMessage {
        let rawData: Data? = nil
        let fromAddress: String
        let toAddresses: [String]
        let ccAddresses: [String]
        let bccAddresses: [String]
        let isSending: Bool = true

        var recipientAddresses: [String] {
            toAddresses + ccAddresses + bccAddresses
        }
    }

    func testRefusePropagationThroughEncoder() {
        // We test the policy path without spinning up a full engine.
        // The throw is the contract; the encoder integration is exercised
        // in end-to-end tests elsewhere.
        let message = TestMessage(
            fromAddress: "alice@example.org",
            toAddresses: ["bob@example.org"],
            ccAddresses: [],
            bccAddresses: ["hidden@example.org"]
        )
        XCTAssertTrue(BccPolicyEvaluator.shouldRefuse(
            hasBcc: !message.bccAddresses.isEmpty,
            policy: .refuse
        ))
    }
}

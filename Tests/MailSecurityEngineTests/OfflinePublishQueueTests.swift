//
//  OfflinePublishQueueTests.swift
//  MailSecurityEngineTests
//

import XCTest
@testable import MailSecurityEngine

final class OfflinePublishQueueTests: XCTestCase {

    private var tempURL: URL!

    override func setUp() {
        super.setUp()
        tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("offline-pub-\(UUID().uuidString).json")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempURL)
        tempURL = nil
        super.tearDown()
    }

    private func makeAction(_ fpr: String = "DEADBEEF") -> QueuedPublishAction {
        QueuedPublishAction(
            kind: .publishKey,
            fingerprint: fpr,
            armoredKey: "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END-----"
        )
    }

    func testEnqueuePersists() throws {
        let queue = try OfflinePublishQueue(storeURL: tempURL, publisher: { _ in })
        try queue.enqueue(makeAction())
        let reloaded = try OfflinePublishQueue(storeURL: tempURL, publisher: { _ in })
        XCTAssertEqual(reloaded.pending().count, 1)
    }

    func testRunDueActionsRemovesSucceeded() async throws {
        let expectation = XCTestExpectation(description: "publisher called")
        let queue = try OfflinePublishQueue(storeURL: tempURL) { action in
            XCTAssertEqual(action.fingerprint, "DEADBEEF")
            expectation.fulfill()
        }
        try queue.enqueue(makeAction())
        let succeeded = await queue.runDueActions(now: Date())
        XCTAssertEqual(succeeded, 1)
        XCTAssertEqual(queue.pending().count, 0)
        await fulfillment(of: [expectation])
    }

    func testFailedActionStaysInQueueWithBumpedRetry() async throws {
        let queue = try OfflinePublishQueue(storeURL: tempURL) { _ in
            throw NSError(domain: "test", code: 1)
        }
        let action = makeAction()
        try queue.enqueue(action)
        // The action's nextRetryAt was set to Date() at creation time.
        // Run due actions with a `now` strictly later so the action
        // qualifies as due.
        let later = Date().addingTimeInterval(1)
        await queue.runDueActions(now: later)
        let pending = queue.pending()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending[0].attemptCount, 1)
        XCTAssertGreaterThan(pending[0].nextRetryAt, later)
    }

    func testRemoveAction() throws {
        let queue = try OfflinePublishQueue(storeURL: tempURL, publisher: { _ in })
        let action = makeAction()
        try queue.enqueue(action)
        try queue.remove(id: action.id)
        XCTAssertTrue(queue.pending().isEmpty)
    }

    func testNextRetryDelayExponential() {
        XCTAssertEqual(OfflinePublishQueue.nextRetryDelay(attempts: 0), 30, accuracy: 0.01)
        XCTAssertEqual(OfflinePublishQueue.nextRetryDelay(attempts: 1), 60, accuracy: 0.01)
        XCTAssertEqual(OfflinePublishQueue.nextRetryDelay(attempts: 2), 120, accuracy: 0.01)
        XCTAssertEqual(OfflinePublishQueue.nextRetryDelay(attempts: 3), 240, accuracy: 0.01)
        XCTAssertEqual(OfflinePublishQueue.nextRetryDelay(attempts: 10), 600, accuracy: 0.01)
    }

    func testPersistsAcrossInstances() throws {
        let queue1 = try OfflinePublishQueue(storeURL: tempURL, publisher: { _ in })
        try queue1.enqueue(makeAction("AAAA"))
        try queue1.enqueue(makeAction("BBBB"))

        let queue2 = try OfflinePublishQueue(storeURL: tempURL, publisher: { _ in })
        XCTAssertEqual(queue2.pending().count, 2)
    }
}

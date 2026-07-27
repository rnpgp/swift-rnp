//
//  MailboxScanDriverTests.swift
//  MailSecurityEngineTests
//

import XCTest
@testable import MailSecurityEngine

final class MailboxScanDriverTests: XCTestCase {

    func testInMemoryDriverReturnsBatchesInOrder() async {
        let messages = (0..<10).map { idx in
            Data("From: sender\(idx)@x\r\n\r\nBody \(idx)\r\n".utf8)
        }
        let driver = InMemoryMailboxScanDriver(messages: messages)
        let batch1 = await driver.nextBatch(maxCount: 4)
        let batch2 = await driver.nextBatch(maxCount: 4)
        let batch3 = await driver.nextBatch(maxCount: 4)
        let batch4 = await driver.nextBatch(maxCount: 4)
        XCTAssertEqual(batch1.count, 4)
        XCTAssertEqual(batch2.count, 4)
        XCTAssertEqual(batch3.count, 2)
        XCTAssertEqual(batch4.count, 0)
    }

    func testEstimatedMessageCountMatches() async {
        let messages = (0..<7).map { _ in Data("From: x\r\n\r\n".utf8) }
        let driver = InMemoryMailboxScanDriver(messages: messages)
        let count = await driver.estimatedMessageCount
        XCTAssertEqual(count, 7)
    }

    func testRunnerYieldsAggregatedReportForEmptyInput() async throws {
        let driver = InMemoryMailboxScanDriver(messages: [])
        let runner = MailboxScanRunner()
        // The runner needs a KeyManager; the engine-layer test target
        // already constructs them. We accept that librnp may not be
        // installed locally — the run still completes (with empty
        // result) because the driver yields nothing.
        let probe = FileManager.default.temporaryDirectory
            .appendingPathComponent("scan-runner-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: probe, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: probe) }
        guard let km = try? KeyManager(directory: probe, password: "test") else {
            throw XCTSkip("librnp not available locally")
        }
        let report = await runner.run(driver: driver, using: km)
        XCTAssertEqual(report.messagesScanned, 0)
        XCTAssertEqual(report.discoveredKeys.count, 0)
    }

    func testRunnerProgressCallbackInvoked() async throws {
        let messages = (0..<10).map { idx in
            Data("From: sender\(idx)@x\r\n\r\nBody \(idx)\r\n".utf8)
        }
        let driver = InMemoryMailboxScanDriver(messages: messages)
        let runner = MailboxScanRunner(batchSize: 3)
        let probe = FileManager.default.temporaryDirectory
            .appendingPathComponent("scan-progress-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: probe, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: probe) }
        guard let km = try? KeyManager(directory: probe, password: "test") else {
            throw XCTSkip("librnp not available locally")
        }
        let progress = ProgressRecorder()
        _ = await runner.run(driver: driver, using: km) { processed, total in
            progress.record(processed: processed, total: total)
        }
        let snapshots = progress.snapshots()
        XCTAssertFalse(snapshots.isEmpty)
        // Last snapshot should show all messages processed.
        if let last = snapshots.last {
            XCTAssertEqual(last.total, 10)
            XCTAssertEqual(last.processed, 10)
        }
    }
}

private final class ProgressRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [(processed: Int, total: Int)] = []
    func record(processed: Int, total: Int) {
        lock.lock(); defer { lock.unlock() }
        entries.append((processed, total))
    }
    func snapshots() -> [(processed: Int, total: Int)] {
        lock.lock(); defer { lock.unlock() }
        return entries
    }
}

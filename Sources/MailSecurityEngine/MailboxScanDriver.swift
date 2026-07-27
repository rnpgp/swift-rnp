//
//  MailboxScanDriver.swift
//  MailSecurityEngine
//
//  Protocol the container app conforms to bridge MailKit's mailbox-
//  enumeration API to the engine's MailboxKeyScanner. The engine
//  drives the scan; the container app supplies raw RFC 822 bytes.
//

import Foundation

/// Abstracts mailbox enumeration. The container app conforms to this
/// via its MailKit-backed implementation; tests use a synthetic
/// implementation with a fixed `[Data]`.
public protocol MailboxScanDriver: Sendable {
    /// Total number of messages the driver will hand out. Surfaced so
    /// the UI can render a progress bar.
    var estimatedMessageCount: Int { get async }

    /// Returns the next batch of message bytes, or `nil` when the
    /// mailbox is exhausted. `maxCount` caps the batch size so the
    /// UI can yield between chunks.
    func nextBatch(maxCount: Int) async -> [Data]

    /// Releases any underlying resources (database cursor, etc.).
    func close() async
}

/// One-shot driver backed by an in-memory array. Used by tests and
/// by the container app when it has already collected the messages
/// into memory.
public final class InMemoryMailboxScanDriver: MailboxScanDriver, @unchecked Sendable {
    private let messages: [Data]
    private let lock = NSLock()
    private var index = 0

    public init(messages: [Data]) {
        self.messages = messages
    }

    public var estimatedMessageCount: Int {
        messages.count
    }

    public func nextBatch(maxCount: Int) -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        let upper = Swift.min(index + maxCount, messages.count)
        let slice = Array(messages[index..<upper])
        index = upper
        return slice
    }

    public func close() {}
}

/// Wraps the MailboxKeyScanner + MailboxScanDriver into a single
/// async-scan entry point the container app calls. Yields progress
/// via the supplied callback.
public final class MailboxScanRunner {
    private let scanner: MailboxKeyScanner
    private let batchSize: Int

    public init(scanner: MailboxKeyScanner = MailboxKeyScanner(), batchSize: Int = 50) {
        self.scanner = scanner
        self.batchSize = batchSize
    }

    /// Runs the scan over `driver`, yielding batches to the engine's
    /// key manager. Returns the aggregated report.
    public func run(
        driver: MailboxScanDriver,
        using keyManager: KeyManager,
        onProgress: @Sendable (Int, Int) async -> Void = { _, _ in }
    ) async -> MailboxScanReport {
        var aggregated = MailboxScanReport(discoveredKeys: [], messagesScanned: 0, errors: [])
        let total = await driver.estimatedMessageCount

        while true {
            let batch = await driver.nextBatch(maxCount: batchSize)
            if batch.isEmpty { break }
            let partial = (try? keyManager.withRnp { rnp in
                self.scanner.scan(messages: batch, using: rnp)
            }) ?? MailboxScanReport(discoveredKeys: [], messagesScanned: batch.count, errors: ["batch failed"])
            aggregated = MailboxScanReport(
                discoveredKeys: merge(aggregated.discoveredKeys, partial.discoveredKeys),
                messagesScanned: aggregated.messagesScanned + partial.messagesScanned,
                errors: aggregated.errors + partial.errors
            )
            await onProgress(aggregated.messagesScanned, total)
        }
        await driver.close()
        return aggregated
    }

    /// Deduplicates by fingerprint, preferring the most-recent observation.
    private func merge(_ lhs: [DiscoveredKey], _ rhs: [DiscoveredKey]) -> [DiscoveredKey] {
        var merged: [String: DiscoveredKey] = [:]
        for entry in lhs + rhs {
            if let existing = merged[entry.fingerprint] {
                if entry.observedDate > existing.observedDate {
                    merged[entry.fingerprint] = entry
                }
            } else {
                merged[entry.fingerprint] = entry
            }
        }
        return Array(merged.values).sorted { $0.fingerprint < $1.fingerprint }
    }
}

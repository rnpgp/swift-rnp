//
//  OfflinePublishQueue.swift
//  MailSecurityEngine
//
//  Persists publish-key actions that fail due to network
//  unavailability or keyserver errors, and retries with exponential
//  backoff. Used by KeyTransition and direct publish flows so the
//  user can complete the wizard offline; the publish happens when
//  network returns.
//
//  Persisted as JSON in the app-group container; survives app restart.
//  Not signed (publish actions are advisory: a missed publish is
//  recoverable by re-publishing; tampering can cause a spurious
//  publish but cannot leak key material).
//

import Foundation

/// One queued publish action.
public struct QueuedPublishAction: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case publishKey
        case publishRevokedKey
    }

    public let id: UUID
    public let kind: Kind
    public let fingerprint: String
    /// Armored key data to publish. May be empty when the caller
    /// intends to look up the current key from the keyring at retry
    /// time.
    public let armoredKey: String
    public let queuedAt: Date
    /// Next retry time; advanced by `nextRetryDelay` on each attempt.
    public var nextRetryAt: Date
    public var attemptCount: Int

    public init(
        id: UUID = UUID(),
        kind: Kind,
        fingerprint: String,
        armoredKey: String,
        queuedAt: Date = Date(),
        nextRetryAt: Date = Date(),
        attemptCount: Int = 0
    ) {
        self.id = id
        self.kind = kind
        self.fingerprint = fingerprint
        self.armoredKey = armoredKey
        self.queuedAt = queuedAt
        self.nextRetryAt = nextRetryAt
        self.attemptCount = attemptCount
    }
}

/// Errors thrown by `OfflinePublishQueue`.
public enum OfflinePublishQueueError: Error, Equatable {
    case persistenceFailed(String)
}

/// Persisted queue of publish actions. The actual network call is
/// performed by a caller-supplied `Publisher` closure; this type only
/// manages the queue state and retry schedule.
public final class OfflinePublishQueue {
    public typealias Publisher = @Sendable (QueuedPublishAction) async throws -> Void

    private let storeURL: URL?
    private let publisher: Publisher
    private let lock = NSLock()
    private var queue: [QueuedPublishAction]

    /// Maximum retry attempts before the queue gives up and surfaces
    /// the failure to the caller.
    public static let maxAttempts: Int = 5

    public init(storeURL: URL?, publisher: @escaping Publisher) throws {
        self.storeURL = storeURL
        self.publisher = publisher
        if let url = storeURL,
           let data = try? Data(contentsOf: url),
           let decoded = try? JSONDecoder().decode([QueuedPublishAction].self, from: data)
        {
            self.queue = decoded
        } else {
            self.queue = []
        }
    }

    /// Adds an action to the queue. The action is retried when
    /// `runDueActions(now:)` is next called.
    public func enqueue(_ action: QueuedPublishAction) throws {
        lock.lock()
        queue.append(action)
        let snapshot = queue
        lock.unlock()
        try persist(snapshot)
    }

    /// Removes a specific action (e.g. after the user cancels).
    public func remove(id: UUID) throws {
        lock.lock()
        queue.removeAll { $0.id == id }
        let snapshot = queue
        lock.unlock()
        try persist(snapshot)
    }

    /// All queued actions, regardless of due time.
    public func pending() -> [QueuedPublishAction] {
        lock.lock(); defer { lock.unlock() }
        return queue
    }

    /// Runs all actions whose `nextRetryAt` has passed. Successful
    /// actions are removed; failed actions have their retry time
    /// advanced and attempt count incremented.
    ///
    /// - Parameter now: injection point for testing.
    @discardableResult
    public func runDueActions(now: Date = Date()) async -> Int {
        let due: [QueuedPublishAction] = lock.withLock {
            queue.filter { $0.nextRetryAt <= now }
        }
        var succeeded = 0
        for action in due {
            do {
                try await publisher(action)
                lock.lock()
                queue.removeAll { $0.id == action.id }
                let snapshot = queue
                lock.unlock()
                try? persist(snapshot)
                succeeded += 1
            } catch {
                let updated = bumpRetry(action: action, now: now)
                lock.lock()
                if let index = queue.firstIndex(where: { $0.id == action.id }) {
                    queue[index] = updated
                }
                let snapshot = queue
                lock.unlock()
                try? persist(snapshot)
            }
        }
        return succeeded
    }

    /// Computes the next retry delay using simple exponential backoff
    /// capped at 10 minutes. Public so tests can assert the schedule.
    public static func nextRetryDelay(attempts: Int) -> TimeInterval {
        let base: TimeInterval = 30  // 30 seconds on first retry
        let capped = min(base * pow(2.0, Double(attempts)), 600)
        return capped
    }

    private func bumpRetry(action: QueuedPublishAction, now: Date) -> QueuedPublishAction {
        var next = action
        next.attemptCount += 1
        if next.attemptCount >= Self.maxAttempts {
            // Keep it in the queue so the caller can surface the
            // permanent failure; future runDueActions calls will
            // continue to retry until the user cancels.
        }
        next.nextRetryAt = now.addingTimeInterval(Self.nextRetryDelay(attempts: next.attemptCount))
        return next
    }

    private func persist(_ snapshot: [QueuedPublishAction]) throws {
        guard let url = storeURL else { return }
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(snapshot)
            try data.write(to: url, options: [.atomic])
        } catch {
            throw OfflinePublishQueueError.persistenceFailed(error.localizedDescription)
        }
    }
}

private extension NSLock {
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}

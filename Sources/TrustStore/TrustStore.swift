//
//  TrustStore.swift
//  swift-rnp
//
//  Tamper-detecting persistence of per-address OpenPGP key trust.
//

import CryptoKit
import Foundation
import KeyStateStore
import os
import Security

/// Errors thrown by `TrustStore`.
public enum TrustStoreError: Error, Equatable {
    /// The trust database could not be read or written.
    case persistenceFailed(String)
    /// The signature on the trust database failed verification; the data may
    /// have been tampered with.
    case tampered
}

/// On-disk representation of the trust database.
private struct TrustDatabase: Codable, Equatable {
    /// Schema version for migration safety.
    var version: Int
    /// Active trust records, keyed by normalized email address.
    var records: [String: TrustRecord]
    /// Unresolved key-change conflicts.
    var conflicts: [TrustConflict]
    /// Append-only log of binding snapshots: every recorded state a binding
    /// went through (first seen, verified, marked problem, superseded by a
    /// conflict, restored by a rejection). Powers the trust history view and
    /// lets `rejectConflict` restore the previous binding with its state.
    var history: [TrustRecord]

    init(
        version: Int = 1,
        records: [String: TrustRecord] = [:],
        conflicts: [TrustConflict] = [],
        history: [TrustRecord] = []
    ) {
        self.version = version
        self.records = records
        self.conflicts = conflicts
        self.history = history
    }

    private enum CodingKeys: String, CodingKey {
        case version, records, conflicts, history
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        records = try container.decode([String: TrustRecord].self, forKey: .records)
        conflicts = try container.decode([TrustConflict].self, forKey: .conflicts)
        // Databases written before the history log existed decode as empty.
        history = try container.decodeIfPresent([TrustRecord].self, forKey: .history) ?? []
    }
}

/// Stores and queries per-recipient trust: TOFU first-seen, manual
/// fingerprint verification, and key-change conflict detection.
///
/// The database is persisted as JSON with a detached Ed25519 signature. The
/// signing key is supplied by the caller; a convenience initializer stores and
/// retrieves a per-install key from the Keychain. Tampering with either file
/// causes the store to reset to empty (fail-closed to `unverified`) rather than
/// trust corrupted data.
public final class TrustStore {
    /// File name of the trust database inside the store directory.
    public static let databaseFilename = "trust.json"
    /// File name of the detached Ed25519 signature.
    public static let signatureFilename = "trust.json.sig"

    /// Directory holding `trust.json` and `trust.json.sig`.
    public let directory: URL

    /// Ed25519 private key used to sign the database.
    public var privateKey: Curve25519.Signing.PrivateKey { jsonStore.privateKey }

    private let lock = NSRecursiveLock()
    private var database: TrustDatabase
    private let jsonStore: SignedJSONStore<TrustDatabase>
    private let logger = Logger(subsystem: "com.rnpgp.RNPForMail", category: "TrustStore")

    /// Creates a trust store in `directory` using the supplied signing key.
    public init(directory: URL, privateKey: Curve25519.Signing.PrivateKey) throws {
        self.directory = directory
        let store = try SignedJSONStore<TrustDatabase>(
            directory: directory,
            databaseFilename: Self.databaseFilename,
            signatureFilename: Self.signatureFilename,
            privateKey: privateKey,
            dateEncodingStrategy: .iso8601,
            dateDecodingStrategy: .iso8601,
            resetOnTamper: true
        )
        self.jsonStore = store
        self.database = (try? store.load()) ?? TrustDatabase()
    }

    /// Convenience initializer that uses a per-install Ed25519 signing key
    /// stored in the Keychain.
    ///
    /// If no key exists, one is generated and saved. If reading an existing
    /// key from the Keychain fails, or if a newly generated key cannot be
    /// saved, the initializer throws `TrustStoreError.persistenceFailed`.
    /// This prevents an ephemeral in-process key from silently breaking
    /// cross-process trust verification.
    public init(
        directory: URL,
        keychainAccessGroup: String? = Bundle.main.object(forInfoDictionaryKey: "RNPMAILKeychainAccessGroup") as? String
    ) throws {
        self.directory = directory
        let store = try SignedJSONStore<TrustDatabase>(
            directory: directory,
            databaseFilename: Self.databaseFilename,
            signatureFilename: Self.signatureFilename,
            keychainService: Self.trustSigningKeyService,
            keychainAccount: Self.trustSigningKeyAccount,
            keychainAccessGroup: keychainAccessGroup,
            dateEncodingStrategy: .iso8601,
            dateDecodingStrategy: .iso8601
        )
        self.jsonStore = store
        self.database = (try? store.load()) ?? TrustDatabase()
    }

    private static let trustSigningKeyService = "RNP for Mail trust signing"
    private static let trustSigningKeyAccount = "trust-signing-key"

    // MARK: - Queries

    /// Trust state for the given fingerprint, or `unverified` when unknown.
    ///
    /// Falls back to the most recent history snapshot when the fingerprint
    /// has no active record (e.g. a key that was rejected in favor of the
    /// previous binding), so a superseded key keeps its last known state.
    public func state(forFpr fingerprint: String) -> TrustState {
        lock.lock()
        defer { lock.unlock() }
        if let record = database.records.values.first(where: { $0.fingerprint == fingerprint }) {
            return record.state
        }
        if let snapshot = database.history.last(where: { $0.fingerprint == fingerprint }) {
            return snapshot.state
        }
        return .unverified
    }

    /// Trust state for the given email address, or `unverified` when unknown.
    public func state(forEmail email: String) -> TrustState {
        let normalized = Self.normalizeEmail(email)
        lock.lock()
        defer { lock.unlock() }
        return database.records[normalized]?.state ?? .unverified
    }

    /// All unresolved key-change conflicts.
    public func conflicts() -> [TrustConflict] {
        lock.lock()
        defer { lock.unlock() }
        return database.conflicts
    }

    /// Whether the given email address has an unresolved key-change conflict.
    public func hasConflict(forEmail email: String) -> Bool {
        let normalized = Self.normalizeEmail(email)
        lock.lock()
        defer { lock.unlock() }
        return database.conflicts.contains { $0.email == normalized }
    }

    /// History of trust snapshots recorded for the given email address,
    /// most recent first: every binding seen for the address and the states
    /// it went through (`unverified`, `verified`, `problem`). In each entry,
    /// `lastSeen` is the time that state was recorded.
    public func history(forEmail email: String) -> [TrustRecord] {
        let normalized = Self.normalizeEmail(email)
        lock.lock()
        defer { lock.unlock() }
        return database.history.filter { $0.email == normalized }.reversed()
    }

    // MARK: - Mutations

    /// Records that `fingerprint` was seen for `email`.
    ///
    /// - If this is the first fingerprint for the address, it is recorded with
    ///   state `unverified` (TOFU).
    /// - If the same fingerprint was already recorded, its `lastSeen` timestamp
    ///   is updated.
    /// - If a different fingerprint was already recorded, a `TrustConflict` is
    ///   created (unless one already exists) and the new fingerprint is marked
    ///   `problem`. The superseded binding is preserved in the history log so
    ///   `rejectConflict(email:newFpr:)` can restore it.
    ///
    /// First sightings and newly detected conflicts append a snapshot to the
    /// history log; re-sightings of a known binding only touch `lastSeen`.
    public func noteSeen(email: String, fingerprint: String) throws {
        let normalized = Self.normalizeEmail(email)
        lock.lock()
        defer { lock.unlock() }

        if let existing = database.records[normalized] {
            if existing.fingerprint.caseInsensitiveCompare(fingerprint) == .orderedSame {
                var updated = existing
                updated.lastSeen = Date()
                database.records[normalized] = updated
            } else {
                let conflictExists = database.conflicts.contains {
                    $0.email == normalized &&
                    $0.existingFingerprint == existing.fingerprint &&
                    $0.newFingerprint == fingerprint
                }
                if !conflictExists {
                    database.conflicts.append(TrustConflict(
                        email: normalized,
                        existingFingerprint: existing.fingerprint,
                        newFingerprint: fingerprint
                    ))
                    // Preserve the outgoing binding so a rejection can restore
                    // it with its original state.
                    database.history.append(existing)
                }
                // Ensure the new fingerprint has a record in problem state.
                let newRecord = database.records.values.first {
                    $0.email == normalized && $0.fingerprint == fingerprint
                } ?? TrustRecord(email: normalized, fingerprint: fingerprint, state: .problem)
                database.records[normalized] = newRecord
                if !conflictExists {
                    database.history.append(newRecord)
                }
            }
        } else {
            let record = TrustRecord(
                email: normalized,
                fingerprint: fingerprint,
                state: .unverified
            )
            database.records[normalized] = record
            database.history.append(record)
        }
        try saveLocked()
    }

    /// Marks the given fingerprint as verified by the user.
    ///
    /// Also resolves any conflicts where this fingerprint is the newly seen
    /// key, so encryption can proceed after the user accepts a key change.
    /// When the fingerprint only exists in the history log (e.g. a key the
    /// user previously rejected), verifying it promotes it back to the active
    /// binding for its address.
    public func markVerified(fingerprint: String) throws {
        lock.lock()
        defer { lock.unlock() }
        var matchedActive = false
        for email in database.records.keys {
            if database.records[email]?.fingerprint.caseInsensitiveCompare(fingerprint) == .orderedSame {
                database.records[email]?.state = .verified
                if var snapshot = database.records[email] {
                    snapshot.lastSeen = Date()
                    database.history.append(snapshot)
                }
                matchedActive = true
            }
        }
        if !matchedActive {
            var promotedEmails: Set<String> = []
            for snapshot in database.history.reversed()
            where snapshot.fingerprint.caseInsensitiveCompare(fingerprint) == .orderedSame
                && !promotedEmails.contains(snapshot.email)
            {
                var record = snapshot
                record.state = .verified
                record.lastSeen = Date()
                database.records[record.email] = record
                database.history.append(record)
                promotedEmails.insert(record.email)
            }
        }
        database.conflicts.removeAll { $0.newFingerprint == fingerprint }
        try saveLocked()
    }

    /// Marks the given fingerprint as having a problem (expired, revoked, etc).
    public func markProblem(fingerprint: String) throws {
        lock.lock()
        defer { lock.unlock() }
        for email in database.records.keys {
            if database.records[email]?.fingerprint.caseInsensitiveCompare(fingerprint) == .orderedSame {
                database.records[email]?.state = .problem
                if var snapshot = database.records[email] {
                    snapshot.lastSeen = Date()
                    database.history.append(snapshot)
                }
            }
        }
        try saveLocked()
    }

    /// Removes all trust records and conflicts associated with the given
    /// fingerprint (e.g. when the key is deleted from the keyring).
    public func removeRecords(forFpr fingerprint: String) throws {
        lock.lock()
        defer { lock.unlock() }
        for email in database.records.keys {
            if database.records[email]?.fingerprint.caseInsensitiveCompare(fingerprint) == .orderedSame {
                database.records.removeValue(forKey: email)
            }
        }
        database.conflicts.removeAll {
            $0.existingFingerprint.caseInsensitiveCompare(fingerprint) == .orderedSame
                || $0.newFingerprint.caseInsensitiveCompare(fingerprint) == .orderedSame
        }
        database.history.removeAll {
            $0.fingerprint.caseInsensitiveCompare(fingerprint) == .orderedSame
        }
        try saveLocked()
    }

    /// Resolves a conflict by accepting `fingerprint` as the new binding for
    /// `email`. The old binding is removed.
    public func resolveConflict(email: String, fingerprint: String) throws {
        let normalized = Self.normalizeEmail(email)
        lock.lock()
        defer { lock.unlock() }
        database.conflicts.removeAll { $0.email == normalized }
        let record = TrustRecord(
            email: normalized,
            fingerprint: fingerprint,
            state: .verified
        )
        database.records[normalized] = record
        database.history.append(record)
        try saveLocked()
    }

    /// Resolves a conflict by rejecting the newly seen key `newFpr` for
    /// `email`: the previous binding is restored as the active record with
    /// the state it had when it was superseded, and the rejected key stays
    /// marked `problem` in the history log. Encryption therefore keeps going
    /// to the previous key instead of the rejected one.
    ///
    /// Does nothing when no matching conflict exists.
    public func rejectConflict(email: String, newFpr: String) throws {
        let normalized = Self.normalizeEmail(email)
        lock.lock()
        defer { lock.unlock() }
        guard let conflict = database.conflicts.first(where: {
            $0.email == normalized && $0.newFingerprint == newFpr
        }) else {
            return
        }
        database.conflicts.removeAll { $0.email == normalized && $0.newFingerprint == newFpr }

        // Only the common case rewrites the active record: the rejected key
        // is the current binding for the address. When another conflict chain
        // has already moved the binding elsewhere, removing the conflict is
        // enough.
        guard let outgoing = database.records[normalized],
              outgoing.fingerprint.caseInsensitiveCompare(conflict.newFingerprint) == .orderedSame
        else {
            try saveLocked()
            return
        }

        // Preserve the rejected key's problem record in the history log.
        var rejected = outgoing
        rejected.state = .problem
        rejected.lastSeen = Date()
        database.history.append(rejected)

        // Restore the previous binding with the state it had when it was
        // superseded; fall back to `unverified` when no snapshot exists
        // (e.g. the conflict predates the history log).
        let previous = database.history.last {
            $0.email == normalized &&
            $0.fingerprint.caseInsensitiveCompare(conflict.existingFingerprint) == .orderedSame
        }
        var restored = previous ?? TrustRecord(
            email: normalized,
            fingerprint: conflict.existingFingerprint,
            state: .unverified
        )
        restored.lastSeen = Date()
        database.records[normalized] = restored
        database.history.append(restored)
        try saveLocked()
    }

    // MARK: - Persistence

    private var databaseURL: URL {
        directory.appendingPathComponent(Self.databaseFilename)
    }

    private var signatureURL: URL {
        directory.appendingPathComponent(Self.signatureFilename)
    }


    private func saveLocked() throws {
        try jsonStore.save(database)
    }

    private static func normalizeEmail(_ email: String) -> String {
        email.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

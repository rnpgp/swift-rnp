//
//  KeyStateStore.swift
//  KeyStateStore
//
//  Tamper-detecting persistence of per-key usage states. Refactored
//  to use the generic SignedJSONStore, eliminating ~60 lines of
//  duplicated sign/verify/persist/Keychain code.
//

import Foundation

/// Errors thrown by `KeyStateStore` (alias to the generic store's error).
public typealias KeyStateStoreError = SignedJSONStoreError

/// Stores per-key usage states (`active` / `archived`) keyed by fingerprint.
public final class KeyStateStore {
    public static let databaseFilename = "key-states.json"
    public static let signatureFilename = "key-states.json.sig"

    /// Keychain item service for the per-install signing key.
    private static let signingKeyService = "RNP for Mail key-state signing key"
    /// Keychain item account. Distinct from TrustStore's account so the two
    /// never share a key.
    private static let signingKeyAccount = "key-state-store"

    private let store: SignedJSONStore<[String: KeyStateRecord]>

    public init(
        directory: URL,
        keychainAccessGroup: String? = Bundle.main.object(forInfoDictionaryKey: "RNPMAILKeychainAccessGroup") as? String
    ) throws {
        store = try SignedJSONStore(
            directory: directory,
            databaseFilename: Self.databaseFilename,
            signatureFilename: Self.signatureFilename,
            keychainService: Self.signingKeyService,
            keychainAccount: Self.signingKeyAccount,
            keychainAccessGroup: keychainAccessGroup
        )
    }

    // MARK: - Queries

    public func state(forFingerprint fingerprint: String) -> KeyUsageState {
        (try? store.load())?[normalize(fingerprint)]?.state ?? .active
    }

    public func record(forFingerprint fingerprint: String) -> KeyStateRecord? {
        (try? store.load())?[normalize(fingerprint)]
    }

    public func allRecords() -> [KeyStateRecord] {
        guard let records = try? store.load() else { return [] }
        return Array(records.values).sorted { $0.fingerprint < $1.fingerprint }
    }

    public func fingerprints(in state: KeyUsageState) -> [String] {
        guard let records = try? store.load() else { return [] }
        return records.values
            .filter { $0.state == state }
            .map(\.fingerprint)
            .sorted()
    }

    // MARK: - Mutations

    public func setState(
        _ state: KeyUsageState,
        forFingerprint fingerprint: String,
        reason: String? = nil
    ) throws {
        var records = (try? store.load()) ?? [:]
        records[normalize(fingerprint)] = KeyStateRecord(
            fingerprint: normalize(fingerprint),
            state: state,
            reason: reason
        )
        try store.save(records)
    }

    public func setState(
        _ state: KeyUsageState,
        forFingerprints fingerprints: [String],
        reason: String? = nil
    ) throws {
        var records = (try? store.load()) ?? [:]
        let now = Date()
        for fpr in fingerprints {
            let normalized = normalize(fpr)
            records[normalized] = KeyStateRecord(
                fingerprint: normalized,
                state: state,
                lastModified: now,
                reason: reason
            )
        }
        try store.save(records)
    }

    public func removeRecord(forFingerprint fingerprint: String) throws {
        var records = (try? store.load()) ?? [:]
        records[normalize(fingerprint)] = nil
        try store.save(records)
    }

    // MARK: - Internals

    private func normalize(_ fingerprint: String) -> String {
        fingerprint.uppercased()
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: ":", with: "")
    }
}

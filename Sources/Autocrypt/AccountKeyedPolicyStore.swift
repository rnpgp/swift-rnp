//
//  AccountKeyedPolicyStore.swift
//  Autocrypt
//
//  Persists Autocrypt `prefer-encrypt` per email account (From
//  address). Lets the user opt in to mutual encryption for some
//  accounts (e.g. work) and disable it for others (e.g. a shared
//  mailbox) without affecting the global default.
//
//  Persisted as JSON next to the AutocryptStore. Not signed
//  (low-sensitivity: a tampered record can at most change the
//  opportunistic-encryption default for outgoing mail, which the
//  user can override per-message).
//

import Foundation

/// Errors thrown by `AccountKeyedPolicyStore`.
public enum AccountKeyedPolicyStoreError: Error, Equatable {
    case persistenceFailed(String)
}

/// JSON-persisted map of account address → prefer-encrypt value.
public final class AccountKeyedPolicyStore {
    private let lock = NSLock()
    private var entries: [String: AutocryptPreferEncrypt]
    private let storeURL: URL?

    public init(storeURL: URL? = nil) throws {
        self.storeURL = storeURL
        if let url = storeURL,
           let data = try? Data(contentsOf: url),
           let decoded = try? JSONDecoder().decode([String: String].self, from: data)
        {
            entries = decoded.compactMapValues { AutocryptPreferEncrypt(rawValue: $0) }
        } else {
            entries = [:]
        }
    }

    /// Non-throwing convenience for creating an in-memory-only store.
    public static func inMemory() -> AccountKeyedPolicyStore {
        try! AccountKeyedPolicyStore(storeURL: nil)
    }

    /// Returns the per-account prefer-encrypt, or `default` when the
    /// account has no override.
    public func preferEncrypt(forAccount address: String, default fallback: AutocryptPreferEncrypt) -> AutocryptPreferEncrypt {
        lock.lock(); defer { lock.unlock() }
        return entries[address.lowercased()] ?? fallback
    }

    /// Sets the per-account prefer-encrypt.
    public func setPreferEncrypt(
        _ value: AutocryptPreferEncrypt,
        forAccount address: String
    ) throws {
        lock.lock()
        entries[address.lowercased()] = value
        let snapshot = entries
        lock.unlock()
        try persist(snapshot)
    }

    /// Clears the override for an account.
    public func clear(account address: String) throws {
        lock.lock()
        entries[address.lowercased()] = nil
        let snapshot = entries
        lock.unlock()
        try persist(snapshot)
    }

    /// All overrides currently in the store.
    public func allOverrides() -> [String: AutocryptPreferEncrypt] {
        lock.lock(); defer { lock.unlock() }
        return entries
    }

    private func persist(_ snapshot: [String: AutocryptPreferEncrypt]) throws {
        guard let url = storeURL else { return }
        let stringKeyed: [String: String] = snapshot.mapValues { $0.rawValue }
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
            let data = try encoder.encode(stringKeyed)
            try data.write(to: url, options: [.atomic])
        } catch {
            throw AccountKeyedPolicyStoreError.persistenceFailed(error.localizedDescription)
        }
    }
}

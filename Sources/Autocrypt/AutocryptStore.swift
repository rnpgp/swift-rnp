//
//  AutocryptStore.swift
//  Autocrypt
//
//  Per-address cache of the latest valid Autocrypt key seen, following
//  the level 1 algorithm: newer messages replace older ones; invalid
//  keys are ignored; lookups return the most recent observation.
//
//  The store does NOT call out to keyservers or merge keys into a PGP
//  keyring. It is a pure cache consulted by the encryption pipeline
//  when resolving recipient keys.
//

import Foundation

/// One stored observation of an Autocrypt header.
public struct AutocryptObservation: Equatable, Sendable, Codable {
    public let address: String
    public let preferEncrypt: AutocryptPreferEncrypt
    public let keydataBase64: String
    public let messageDate: Date

    public init(
        address: String,
        preferEncrypt: AutocryptPreferEncrypt,
        keydataBase64: String,
        messageDate: Date
    ) {
        self.address = address
        self.preferEncrypt = preferEncrypt
        self.keydataBase64 = keydataBase64
        self.messageDate = messageDate
    }
}

/// Errors thrown by `AutocryptStore`.
public enum AutocryptStoreError: Error, Equatable {
    case persistenceFailed(String)
}

/// Per-address Autocrypt state, persisted as JSON.
public final class AutocryptStore {
    private let lock = NSLock()
    private var observations: [String: AutocryptObservation] = [:]
    private let storeURL: URL?

    /// Creates an in-memory store when `storeURL` is `nil`, or a
    /// persisted store that loads and saves JSON to the given URL.
    public init(storeURL: URL? = nil) throws {
        self.storeURL = storeURL
        if let url = storeURL, let data = try? Data(contentsOf: url) {
            observations = (try? JSONDecoder().decode([String: AutocryptObservation].self, from: data)) ?? [:]
        }
    }

    /// Non-throwing convenience for creating an in-memory-only store.
    /// Use when persistence is not needed (tests, fallbacks, previews).
    public static func inMemory() -> AutocryptStore {
        // Safe to force-try: init only throws on corrupted existing
        // JSON; with nil URL there is nothing to load.
        // swiftlint:disable:next force_try
        try! AutocryptStore(storeURL: nil)
    }

    /// Records an observation. Following level 1: a newer messageDate
    /// replaces an older one; an older or equal-date message is ignored.
    public func observe(
        address: String,
        preferEncrypt: AutocryptPreferEncrypt,
        keydataBase64: String,
        messageDate: Date
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        let normalized = address.lowercased()
        if let existing = observations[normalized], existing.messageDate >= messageDate {
            return
        }
        observations[normalized] = AutocryptObservation(
            address: normalized,
            preferEncrypt: preferEncrypt,
            keydataBase64: keydataBase64,
            messageDate: messageDate
        )
        try persist()
    }

    /// Convenience: parses and records a raw `Autocrypt:` header value.
    public func observe(rawHeader: String, messageDate: Date) throws {
        let parsed = try AutocryptHeaderParser.parse(rawHeader)
        try observe(
            address: parsed.address,
            preferEncrypt: parsed.preferEncrypt,
            keydataBase64: parsed.keydataBase64,
            messageDate: messageDate
        )
    }

    /// Returns the latest observation for an address, or `nil`.
    public func observation(forAddress address: String) -> AutocryptObservation? {
        lock.lock(); defer { lock.unlock() }
        return observations[address.lowercased()]
    }

    /// Whether both the sender and a recipient have advertised
    /// `prefer-encrypt=mutual`, the trigger for opportunistic
    /// encryption under Autocrypt.
    public func mutualEncryptionPossible(
        senderAddress: String,
        recipientAddress: String
    ) -> Bool {
        guard let sender = observation(forAddress: senderAddress),
              let recipient = observation(forAddress: recipientAddress)
        else {
            return false
        }
        return sender.preferEncrypt == .mutual && recipient.preferEncrypt == .mutual
    }

    /// All observations, for debugging and the (future) Autocrypt UI.
    public func allObservations() -> [AutocryptObservation] {
        lock.lock(); defer { lock.unlock() }
        return Array(observations.values).sorted { $0.address < $1.address }
    }

    /// Forgets the observation for an address.
    public func forget(address: String) throws {
        lock.lock(); defer { lock.unlock() }
        observations[address.lowercased()] = nil
        try persist()
    }

    private func persist() throws {
        guard let url = storeURL else { return }
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
            let data = try encoder.encode(observations)
            try data.write(to: url, options: [.atomic])
        } catch {
            throw AutocryptStoreError.persistenceFailed(error.localizedDescription)
        }
    }
}

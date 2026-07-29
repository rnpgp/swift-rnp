//
//  KeyringStore.swift
//  swift-rnp
//
//  Persistent OpenPGP keyring storage for the mail security engine.
//
//  A KeyringStore owns an `Rnp` context whose in-memory keyrings are loaded
//  from (and persisted to) a keyring directory holding classic GPG keyring
//  files (pubring.gpg / secring.gpg). Passphrases are supplied by the
//  caller-provided `Rnp.PassphraseProvider`, so secret storage (Keychain on
//  Apple platforms) stays outside of this package.
//
//  Lookup and recipient-resolution logic lives on `KeyResolver`; this type
//  owns the lock, the filesystem, and mutating operations only.
//

import Foundation
import KeyStateStore
import Rnp
import TrustStore

/// Key usage state: active vs archived (decrypt-only).

/// Key generation algorithms supported by `KeyringStore.generateKey`.
public enum KeyAlgorithm: String, CaseIterable {
    /// RSA-3072 signing primary with an RSA-3072 encryption subkey.
    case rsa = "RSA"
    /// ECDSA P-256 signing primary with an ECDH P-256 encryption subkey.
    case ecdsa = "ECDSA"
    /// Ed25519 signing primary with a Curve25519 encryption subkey.
    case ed25519 = "Ed25519"
    /// Post-quantum hybrid: ML-DSA-65+ED25519 primary with
    /// ML-KEM-768+X25519 encryption subkey. Larger keys; maximum
    /// long-term confidentiality.
    case hybridPQ = "HybridPQ"
    /// Conservative post-quantum: SLH-DSA-SHA2 primary (hash-based, no
    /// lattice assumptions) with classical ECDH-Curve25519 encryption
    /// subkey. Very large signatures.
    case conservativePQ = "ConservativePQ"
}

/// A snapshot description of one primary key in the keyring.
public struct KeyInfo: Equatable, Identifiable {
    public let fingerprint: String
    public let primaryUserID: String
    public let userIDs: [String]
    public let hasSecret: Bool
    public let algorithm: String
    public let bits: Int
    public let creationDate: Date
    public let expirationDate: Date?
    public let isRevoked: Bool
    public let subkeyCount: Int

    public init(
        fingerprint: String,
        primaryUserID: String,
        userIDs: [String],
        hasSecret: Bool,
        algorithm: String = "",
        bits: Int = 0,
        creationDate: Date = Date(timeIntervalSince1970: 0),
        expirationDate: Date? = nil,
        isRevoked: Bool = false,
        subkeyCount: Int = 0
    ) {
        self.fingerprint = fingerprint
        self.primaryUserID = primaryUserID
        self.userIDs = userIDs
        self.hasSecret = hasSecret
        self.algorithm = algorithm
        self.bits = bits
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        self.isRevoked = isRevoked
        self.subkeyCount = subkeyCount
    }

    public var id: String { fingerprint }

    /// Short, user-facing label like "RSA-3072" or "ECDSA P-256".
    public var algorithmLabel: String {
        algorithm.isEmpty ? "OpenPGP" : bits > 0 ? "\(algorithm)-\(bits)" : algorithm
    }

    /// Whether the key has expired.
    public var isExpired: Bool {
        guard let expiration = expirationDate else { return false }
        return expiration < Date()
    }

    /// Days until expiry; `nil` for non-expiring keys.
    public var daysUntilExpiry: Int? {
        guard let expiration = expirationDate else { return nil }
        return Calendar.current.dateComponents([.day], from: Date(), to: expiration).day
    }
}

/// A snapshot description of one subkey.
public struct SubkeyInfo: Equatable, Identifiable {
    public let fingerprint: String
    public let keyID: String
    public let algorithm: String
    public let bits: Int
    public let curve: String?
    public let creationDate: Date
    public let expirationDate: Date?
    public let capabilities: [String]

    public init(
        fingerprint: String,
        keyID: String,
        algorithm: String,
        bits: Int,
        curve: String? = nil,
        creationDate: Date,
        expirationDate: Date? = nil,
        capabilities: [String] = []
    ) {
        self.fingerprint = fingerprint
        self.keyID = keyID
        self.algorithm = algorithm
        self.bits = bits
        self.curve = curve
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        self.capabilities = capabilities
    }

    public var id: String { fingerprint }

    /// User-facing label like "RSA-3072" or "Ed25519".
    public var algorithmLabel: String {
        if let curve = curve, !curve.isEmpty {
            return "\(algorithm) \(curve)"
        }
        return bits > 0 ? "\(algorithm)-\(bits)" : algorithm
    }
}

/// Errors thrown by `KeyringStore`.
public enum KeyManagerError: Error, Equatable {
    /// A keyring file exists but could not be read.
    case keyringUnreadable(String)
    /// The supplied passphrase did not unlock the key's secret material.
    case wrongPassphrase(String)
}

/// A secret key that is passphrase-protected but cannot be unlocked with the
/// keyring passphrase — typically a freshly imported key still protected by
/// its original (foreign) passphrase.
public struct LockedSecretKeyInfo: Equatable, Identifiable {
    /// Fingerprint of the primary key.
    public let fingerprint: String
    /// The key's primary user ID, for display in the unlock prompt.
    public let primaryUserID: String

    public init(fingerprint: String, primaryUserID: String) {
        self.fingerprint = fingerprint
        self.primaryUserID = primaryUserID
    }

    public var id: String { fingerprint }
}

/// Owns an OpenPGP keyring directory's persistence: the `Rnp` context, the
/// lock serializing access to it, and the keyring files on disk. Also owns
/// the trust store and per-key usage-state store that live alongside.
///
/// Lookup of keys by user ID / email, and recipient resolution, live on
/// `KeyResolver` — obtain one via `KeyResolver(keyringStore:)`.
///
/// All operations run serialized on an internal lock; instances are safe to
/// share between MailKit callback threads and UI code.
public final class KeyringStore {
    /// File name of the public keyring inside the keyring directory.
    public static let publicKeyringFilename = "pubring.gpg"
    /// File name of the secret keyring inside the keyring directory.
    public static let secretKeyringFilename = "secring.gpg"

    /// Directory holding the keyring files.
    public let directory: URL
    /// Trust store that records seen keys and conflicts for recipient keys.
    public let trustStore: TrustStore
    /// Per-key usage-state store (active vs archived). Lazily created on
    /// first access when the caller does not supply one in the initializer.
    public private(set) var keyStateStore: KeyStateStore!

    private let lock = NSRecursiveLock()
    private let rnp: Rnp

    /// Creates a manager, creating the directory and loading any existing
    /// keyring files.
    ///
    /// - Parameters:
    ///   - directory: directory holding `pubring.gpg` / `secring.gpg`.
    ///   - passphraseProvider: callback supplying passphrases for secret keys.
    ///   - trustStore: optional trust store; if omitted, one is created in the
    ///     same directory.
    ///   - keychainAccessGroup: Keychain access group used when creating the
    ///     default trust store. Defaults to the `RNPMAILKeychainAccessGroup`
    ///     value from `Bundle.main`.
    public convenience init(
        directory: URL,
        passphraseProvider: @escaping Rnp.PassphraseProvider,
        trustStore: TrustStore? = nil,
        keychainAccessGroup: String? = Bundle.main.object(forInfoDictionaryKey: "RNPMAILKeychainAccessGroup") as? String
    ) throws {
        try self.init(
            directory: directory,
            keyedPassphraseProvider: { context, _ in passphraseProvider(context) },
            trustStore: trustStore,
            keychainAccessGroup: keychainAccessGroup
        )
    }

    /// Creates a manager with a passphrase callback that is told which key
    /// is being unlocked, so imported keys protected by a foreign passphrase
    /// can be answered with their per-key passphrase.
    ///
    /// - Parameters:
    ///   - directory: directory holding `pubring.gpg` / `secring.gpg`.
    ///   - keyedPassphraseProvider: callback receiving the passphrase context
    ///     and the fingerprint of the key being unlocked (the primary key's
    ///     fingerprint for subkeys), or `nil` when no key is involved.
    ///   - trustStore: optional trust store; if omitted, one is created in the
    ///     same directory.
    ///   - keychainAccessGroup: Keychain access group used when creating the
    ///     default trust store. Defaults to the `RNPMAILKeychainAccessGroup`
    ///     value from `Bundle.main`.
    public init(
        directory: URL,
        keyedPassphraseProvider: @escaping Rnp.KeyedPassphraseProvider,
        trustStore: TrustStore? = nil,
        keychainAccessGroup: String? = Bundle.main.object(forInfoDictionaryKey: "RNPMAILKeychainAccessGroup") as? String
    ) throws {
        self.directory = directory
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        if let trustStore {
            self.trustStore = trustStore
        } else {
            self.trustStore = try TrustStore(
                directory: directory,
                keychainAccessGroup: keychainAccessGroup
            )
        }
        self.keyStateStore = try KeyStateStore(
            directory: directory.appendingPathComponent("KeyStateStore", isDirectory: true),
            keychainAccessGroup: keychainAccessGroup
        )
        rnp = try Rnp(keyedPassphraseProvider: keyedPassphraseProvider)
        try loadKeyring(publicKeyringURL, public: true, secret: false)
        try loadKeyring(secretKeyringURL, public: false, secret: true)
    }

    /// Convenience manager answering every passphrase request with `password`.
    public convenience init(directory: URL, password: String) throws {
        try self.init(directory: directory, passphraseProvider: { _ in password })
    }

    private var publicKeyringURL: URL {
        directory.appendingPathComponent(Self.publicKeyringFilename)
    }

    private var secretKeyringURL: URL {
        directory.appendingPathComponent(Self.secretKeyringFilename)
    }

    private func loadKeyring(_ url: URL, public: Bool, secret: Bool) throws {
        guard let data = FileManager.default.contents(atPath: url.path), !data.isEmpty else {
            return
        }
        do {
            try rnp.loadKeys(data, public: `public`, secret: secret)
        } catch {
            throw KeyManagerError.keyringUnreadable(url.lastPathComponent)
        }
    }

    /// Runs `body` with the managed `Rnp` context under the store lock.
    ///
    /// Used by `MailSecurityEngine` and the `KeyLifecycle` target to perform
    /// crypto operations on the shared keyrings without racing other callers.
    /// For key lookups, prefer `KeyResolver` — its methods acquire this lock
    /// internally so callers don't need to.
    public func withRnp<T>(_ body: (Rnp) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body(rnp)
    }

    // MARK: - Listing

    /// All primary keys in the keyring, in enumeration order.
    public func listKeys() throws -> [KeyInfo] {
        try withRnp { rnp in
            var order: [String] = []
            var infos: [String: KeyInfo] = [:]
            for userID in try rnp.allUserIDs() {
                guard let key = try rnp.locateKey(userID) else {
                    continue
                }
                let fingerprint = try key.fingerprint
                if let existing = infos[fingerprint] {
                    infos[fingerprint] = KeyInfo(
                        fingerprint: existing.fingerprint,
                        primaryUserID: existing.primaryUserID,
                        userIDs: existing.userIDs + [userID],
                        hasSecret: existing.hasSecret,
                        algorithm: existing.algorithm,
                        bits: existing.bits,
                        creationDate: existing.creationDate,
                        expirationDate: existing.expirationDate,
                        isRevoked: existing.isRevoked,
                        subkeyCount: existing.subkeyCount
                    )
                } else {
                    order.append(fingerprint)
                    infos[fingerprint] = try makeKeyInfo(key: key, primaryUserID: userID)
                }
            }
            return order.compactMap { infos[$0] }
        }
    }

    internal func makeKeyInfo(key: RnpKey, primaryUserID: String) throws -> KeyInfo {
        let fingerprint = try key.fingerprint
        let expirationSeconds = try key.expirationSeconds
        let expirationDate: Date? = expirationSeconds > 0
            ? try key.creationDate.addingTimeInterval(TimeInterval(expirationSeconds))
            : nil
        return KeyInfo(
            fingerprint: fingerprint,
            primaryUserID: (try? key.primaryUserID) ?? primaryUserID,
            userIDs: (try? key.userIDs) ?? [],
            hasSecret: (try? key.hasSecret) ?? false,
            algorithm: (try? key.algorithm) ?? "",
            bits: (try? key.bits) ?? 0,
            creationDate: (try? key.creationDate) ?? Date(timeIntervalSince1970: 0),
            expirationDate: expirationDate,
            isRevoked: (try? key.isRevoked) ?? false,
            subkeyCount: (try? key.subkeys.count) ?? 0
        )
    }

    // MARK: - Generation

    /// Generates a new key pair and persists the keyrings.
    ///
    /// - Parameters:
    ///   - userID: the OpenPGP user ID for the primary key.
    ///   - algorithm: the key algorithm to generate.
    ///   - expirationSeconds: seconds until the primary key and subkey expire,
    ///     or `0` for keys that do not expire.
    @discardableResult
    public func generateKey(
        userID: String,
        algorithm: KeyAlgorithm = .rsa,
        expirationSeconds: UInt32 = 0
    ) throws -> KeyInfo {
        return try withRnp { rnp in
            let json: String
            switch algorithm {
            case .rsa:
                json = Rnp.rsaKeyGenJSON(userid: userID, expirationSeconds: expirationSeconds)
            case .ecdsa:
                json = Rnp.ecdsaP256KeyGenJSON(userid: userID, expirationSeconds: expirationSeconds)
            case .ed25519:
                json = Rnp.ed25519KeyGenJSON(userid: userID, expirationSeconds: expirationSeconds)
            case .hybridPQ:
                json = Rnp.hybridPQKeyGenJSON(userid: userID, expirationSeconds: expirationSeconds)
            case .conservativePQ:
                json = Rnp.conservativePQKeyGenJSON(userid: userID, expirationSeconds: expirationSeconds)
            }
            try rnp.generateKey(json: json)
            let key = try rnp.requireKey(userID)

            // librnp's JSON generator may ignore the "expiration" field when
            // protection is also supplied, so explicitly set the requested
            // expiration on the primary key and all subkeys.
            if expirationSeconds > 0 {
                try key.setExpirationSeconds(expirationSeconds)
                for subkey in try key.subkeys {
                    try subkey.setExpirationSeconds(expirationSeconds)
                }
            }

            let info = try makeKeyInfo(key: key, primaryUserID: userID)
            try persist(rnp)
            return info
        }
    }

    // MARK: - Import / export

    /// Imports keys (armored or binary) and persists the keyrings.
    ///
    /// After a successful import, each imported primary key is reported to the
    /// trust store so key-change conflicts can be detected. If the trust store
    /// cannot record a seen key or a key-change conflict, the import fails and
    /// the error is propagated.
    ///
    /// - Returns: snapshots of the imported primary keys.
    @discardableResult
    public func importKeys(_ data: Data) throws -> [KeyInfo] {
        try withRnp { rnp in
            let results = try rnp.importKeys(data)
            try persist(rnp)
            // The results JSON lists every imported key packet, including
            // subkeys; keep primary keys (those carrying user IDs) only.
            let infos = Self.importedFingerprints(fromJSON: results).compactMap { fingerprint -> KeyInfo? in
                guard let key = try? rnp.locateKey(fingerprint, type: .fingerprint),
                      let userIDs = try? key.userIDs, !userIDs.isEmpty
                else {
                    return nil
                }
                return try? makeKeyInfo(key: key, primaryUserID: userIDs[0])
            }
            for info in infos {
                for userID in info.userIDs {
                    if let email = Self.emailAddress(from: userID) {
                        try trustStore.noteSeen(email: email, fingerprint: info.fingerprint)
                    }
                }
            }
            return infos
        }
    }

    /// Exports a key by fingerprint (armored by default).
    public func exportKey(fingerprint: String, secret: Bool = false, armored: Bool = true) throws -> Data {
        try withRnp { rnp in
            try rnp.requireKey(fingerprint, type: .fingerprint)
                .exportKey(secret: secret, armored: armored)
        }
    }

    // MARK: - Foreign passphrases

    /// Secret keys among `fingerprints` (all keys when `nil`) that are
    /// passphrase-protected and cannot be unlocked with `keyringPassphrase`
    /// — i.e. keys imported while protected by a foreign passphrase.
    ///
    /// The probe unlocks matching parts in memory as a side effect when the
    /// keyring passphrase does fit; such keys are not reported.
    public func lockedSecretKeys(
        keyringPassphrase: String,
        among fingerprints: [String]? = nil
    ) throws -> [LockedSecretKeyInfo] {
        try withRnp { rnp in
            let candidates: [String]
            if let fingerprints {
                candidates = fingerprints
            } else {
                candidates = try listKeys().filter(\.hasSecret).map(\.fingerprint)
            }
            var locked: [LockedSecretKeyInfo] = []
            for fingerprint in candidates {
                guard let key = try rnp.locateKey(fingerprint, type: .fingerprint),
                      (try? key.hasSecret) == true
                else {
                    continue
                }
                let protectedParts = protectedSecretParts(of: key)
                guard !protectedParts.isEmpty else {
                    continue
                }
                let fitsKeyring = protectedParts.allSatisfy { $0.unlock(password: keyringPassphrase) }
                if !fitsKeyring {
                    locked.append(LockedSecretKeyInfo(
                        fingerprint: fingerprint,
                        primaryUserID: (try? key.primaryUserID) ?? ""
                    ))
                }
            }
            return locked
        }
    }

    /// Whether `passphrase` unlocks every protected secret part of the key
    /// (primary and subkeys). Successful parts stay unlocked in memory.
    public func unlockSecretKey(fingerprint: String, passphrase: String) throws -> Bool {
        try withRnp { rnp in
            let key = try rnp.requireKey(fingerprint, type: .fingerprint)
            return protectedSecretParts(of: key).allSatisfy { $0.unlock(password: passphrase) }
        }
    }

    /// Re-protects the key's secret material (primary and subkeys) with
    /// `newPassphrase`, so the key can subsequently be used with the keyring
    /// passphrase alone, and persists the keyrings.
    ///
    /// - Throws: `KeyManagerError.wrongPassphrase` when `currentPassphrase`
    ///   does not unlock every protected part of the key.
    public func reprotectSecretKey(
        fingerprint: String,
        currentPassphrase: String,
        newPassphrase: String
    ) throws {
        try withRnp { rnp in
            let key = try rnp.requireKey(fingerprint, type: .fingerprint)
            let parts = protectedSecretParts(of: key)
            guard parts.allSatisfy({ $0.unlock(password: currentPassphrase) }) else {
                throw KeyManagerError.wrongPassphrase(fingerprint)
            }
            for part in parts {
                try part.protect(password: newPassphrase)
            }
            try persist(rnp)
        }
    }

    /// The primary key and subkeys holding passphrase-protected secret
    /// material. Caller must hold the manager lock.
    private func protectedSecretParts(of key: RnpKey) -> [RnpKey] {
        ([key] + ((try? key.subkeys) ?? [])).filter {
            ((try? $0.hasSecret) ?? false) && ((try? $0.isProtected) ?? false)
        }
    }

    /// Fingerprints found in an `rnp_import_keys` results JSON document.
    static func importedFingerprints(fromJSON json: String) -> [String] {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let keys = object["keys"] as? [[String: Any]]
        else {
            return []
        }
        return keys.compactMap { $0["fingerprint"] as? String }
    }

    // MARK: - Deletion

    /// Removes a key (public, secret and subkeys) and persists the keyrings.
    public func deleteKey(fingerprint: String) throws {
        try withRnp { rnp in
            let key = try rnp.requireKey(fingerprint, type: .fingerprint)
            let hasSecret = (try? key.hasSecret) ?? false
            try rnp.remove(key: key, public: true, secret: hasSecret, subkeys: true)
            try persist(rnp)
        }
        try trustStore.removeRecords(forFpr: fingerprint)
        try? keyStateStore.removeRecord(forFingerprint: fingerprint)
    }

    // MARK: - Detail

    /// Returns a snapshot of the subkeys belonging to the key with the given
    /// fingerprint.
    public func subkeys(for fingerprint: String) throws -> [SubkeyInfo] {
        try withRnp { rnp in
            let key = try rnp.requireKey(fingerprint, type: .fingerprint)
            return try key.subkeys.map(makeSubkeyInfo)
        }
    }

    private func makeSubkeyInfo(key: RnpKey) throws -> SubkeyInfo {
        let fingerprint = try key.fingerprint
        let expirationSeconds = try key.expirationSeconds
        let expirationDate: Date? = expirationSeconds > 0
            ? try key.creationDate.addingTimeInterval(TimeInterval(expirationSeconds))
            : nil
        return SubkeyInfo(
            fingerprint: fingerprint,
            keyID: (try? key.keyID) ?? "",
            algorithm: (try? key.algorithm) ?? "",
            bits: (try? key.bits) ?? 0,
            curve: try? key.curve,
            creationDate: (try? key.creationDate) ?? Date(timeIntervalSince1970: 0),
            expirationDate: expirationDate,
            capabilities: (try? key.capabilities) ?? []
        )
    }

    // MARK: - Revocation certificate

    /// Exports an armored revocation certificate for the given fingerprint.
    public func exportRevocationCertificate(fingerprint: String) throws -> Data {
        try withRnp { rnp in
            try rnp.requireKey(fingerprint, type: .fingerprint)
                .exportRevocation()
        }
    }

    /// Writes an armored revocation certificate for the given fingerprint to
    /// the keyring directory.
    ///
    /// - Returns: the URL of the saved certificate.
    @discardableResult
    public func saveRevocationCertificate(fingerprint: String) throws -> URL {
        let data = try exportRevocationCertificate(fingerprint: fingerprint)
        let url = directory
            .appendingPathComponent("\(fingerprint)-revocation")
            .appendingPathExtension("asc")
        try data.write(to: url, options: .atomic)
        return url
    }

    // MARK: - Address utilities

    /// Extracts the email address from a user ID of the form
    /// "Name <email@example.com>", or returns the input itself when it looks
    /// like a bare email address. Used by `importKeys` (here) and by
    /// `KeyResolver` lookups.
    public static func emailAddress(from userID: String) -> String? {
        if let open = userID.lastIndex(of: "<"),
           let close = userID.lastIndex(of: ">"), open < close
        {
            return String(userID[userID.index(after: open) ..< close])
        }
        return userID.contains("@") ? userID : nil
    }

    /// Case-insensitive equality of two address identifiers, comparing the
    /// email addresses extracted from user-ID form when present.
    static func addressesMatch(_ lhs: String, _ rhs: String) -> Bool {
        let left = emailAddress(from: lhs) ?? lhs
        let right = emailAddress(from: rhs) ?? rhs
        return left.caseInsensitiveCompare(right) == .orderedSame
    }

    // MARK: - Persistence

    /// Writes the in-memory keyrings back to the keyring directory.
    ///
    /// Keyrings that hold no keys are removed instead of written, so a
    /// freshly initialized or fully emptied manager leaves no files that a
    /// later load would choke on.
    public func save() throws {
        try withRnp { try persist($0) }
    }

    internal func persist(_ rnp: Rnp) throws {
        let publicKeys = try rnp.publicKeyCount > 0 ? rnp.savePublicKeys(armored: false) : nil
        let secretKeys = try rnp.secretKeyCount > 0 ? rnp.saveSecretKeys(armored: false) : nil
        try persistKeyring(publicKeys, to: publicKeyringURL)
        try persistKeyring(secretKeys, to: secretKeyringURL)
    }

    private func persistKeyring(_ data: Data?, to url: URL) throws {
        if let data {
            try data.write(to: url, options: .atomic)
        } else {
            try? FileManager.default.removeItem(at: url)
        }
    }
}

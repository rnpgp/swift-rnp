//
//  KeyManager.swift
//  swift-rnp
//
//  Deprecated façade preserved for source compatibility.
//
//  Historically, `KeyManager` bundled keyring persistence, CRUD, foreign-
//  passphrase handling, and key lookup into one type. That coupling made
//  callers that only needed lookup (UI, compose diagnostics) drag in the
//  full mutating API, and forced KeyLifecycle to depend on all of
//  MailSecurityEngine just to reach the keyring.
//
//  The responsibilities are now split:
//    - `KeyringStore` — owns the `Rnp` context, the lock, the keyring
//      files, the trust store, and the usage-state store. Persistence
//      and mutation live here.
//    - `KeyResolver` — read-only key lookup and recipient resolution
//      layered on top of a `KeyringStore`.
//
//  New code should depend on `KeyringStore` (for crypto / mutation) or
//  `KeyResolver` (for lookup), not on `KeyManager`. This façade forwards
//  every method to the appropriate underlying type so existing callers
//  keep compiling.
//

import Foundation
import KeyStateStore
import Rnp
import TrustStore

@available(*, deprecated, message: "Use KeyringStore (persistence/CRUD) and KeyResolver (lookup) directly")
public final class KeyManager {
    public static let publicKeyringFilename = KeyringStore.publicKeyringFilename
    public static let secretKeyringFilename = KeyringStore.secretKeyringFilename

    public let keyringStore: KeyringStore
    public let resolver: KeyResolver

    public var directory: URL { keyringStore.directory }
    public var trustStore: TrustStore { keyringStore.trustStore }
    public var keyStateStore: KeyStateStore! { keyringStore.keyStateStore }

    // MARK: - Initializers (delegate to KeyringStore)

    public convenience init(
        directory: URL,
        passphraseProvider: @escaping Rnp.PassphraseProvider,
        trustStore: TrustStore? = nil,
        keychainAccessGroup: String? = Bundle.main.object(forInfoDictionaryKey: "RNPMAILKeychainAccessGroup") as? String
    ) throws {
        let store = try KeyringStore(
            directory: directory,
            passphraseProvider: passphraseProvider,
            trustStore: trustStore,
            keychainAccessGroup: keychainAccessGroup
        )
        self.init(keyringStore: store)
    }

    public convenience init(
        directory: URL,
        keyedPassphraseProvider: @escaping Rnp.KeyedPassphraseProvider,
        trustStore: TrustStore? = nil,
        keychainAccessGroup: String? = Bundle.main.object(forInfoDictionaryKey: "RNPMAILKeychainAccessGroup") as? String
    ) throws {
        let store = try KeyringStore(
            directory: directory,
            keyedPassphraseProvider: keyedPassphraseProvider,
            trustStore: trustStore,
            keychainAccessGroup: keychainAccessGroup
        )
        self.init(keyringStore: store)
    }

    public convenience init(directory: URL, password: String) throws {
        let store = try KeyringStore(directory: directory, password: password)
        self.init(keyringStore: store)
    }

    public init(keyringStore: KeyringStore) {
        self.keyringStore = keyringStore
        self.resolver = KeyResolver(keyringStore: keyringStore)
    }

    // MARK: - Persistence (forwarded to KeyringStore)

    public func withRnp<T>(_ body: (Rnp) throws -> T) throws -> T {
        try keyringStore.withRnp(body)
    }

    public func save() throws { try keyringStore.save() }

    // MARK: - Listing / generation / import-export (forwarded to KeyringStore)

    public func listKeys() throws -> [KeyInfo] { try keyringStore.listKeys() }

    @discardableResult
    public func generateKey(
        userID: String,
        algorithm: KeyAlgorithm = .rsa,
        expirationSeconds: UInt32 = 0
    ) throws -> KeyInfo {
        try keyringStore.generateKey(userID: userID, algorithm: algorithm, expirationSeconds: expirationSeconds)
    }

    @discardableResult
    public func importKeys(_ data: Data) throws -> [KeyInfo] { try keyringStore.importKeys(data) }

    public func exportKey(fingerprint: String, secret: Bool = false, armored: Bool = true) throws -> Data {
        try keyringStore.exportKey(fingerprint: fingerprint, secret: secret, armored: armored)
    }

    public func deleteKey(fingerprint: String) throws { try keyringStore.deleteKey(fingerprint: fingerprint) }

    public func subkeys(for fingerprint: String) throws -> [SubkeyInfo] {
        try keyringStore.subkeys(for: fingerprint)
    }

    public func exportRevocationCertificate(fingerprint: String) throws -> Data {
        try keyringStore.exportRevocationCertificate(fingerprint: fingerprint)
    }

    @discardableResult
    public func saveRevocationCertificate(fingerprint: String) throws -> URL {
        try keyringStore.saveRevocationCertificate(fingerprint: fingerprint)
    }

    // MARK: - Foreign passphrase (forwarded to KeyringStore)

    public func lockedSecretKeys(
        keyringPassphrase: String,
        among fingerprints: [String]? = nil
    ) throws -> [LockedSecretKeyInfo] {
        try keyringStore.lockedSecretKeys(keyringPassphrase: keyringPassphrase, among: fingerprints)
    }

    public func unlockSecretKey(fingerprint: String, passphrase: String) throws -> Bool {
        try keyringStore.unlockSecretKey(fingerprint: fingerprint, passphrase: passphrase)
    }

    public func reprotectSecretKey(
        fingerprint: String,
        currentPassphrase: String,
        newPassphrase: String
    ) throws {
        try keyringStore.reprotectSecretKey(
            fingerprint: fingerprint,
            currentPassphrase: currentPassphrase,
            newPassphrase: newPassphrase
        )
    }

    // MARK: - Lookup (forwarded to KeyResolver)

    public func publicKey(for identifier: String) throws -> RnpKey? {
        try resolver.publicKey(for: identifier)
    }

    public func secretKey(forUserID identifier: String) throws -> RnpKey? {
        try resolver.secretKey(forUserID: identifier)
    }

    public func publicKeyUnlocked(for identifier: String, rnp: Rnp) throws -> RnpKey? {
        try resolver.publicKeyUnlocked(for: identifier, rnp: rnp)
    }

    public func secretKeyUnlocked(forUserID identifier: String, rnp: Rnp) throws -> RnpKey? {
        try resolver.secretKeyUnlocked(forUserID: identifier, rnp: rnp)
    }

    public func activeSigningKey(forUserID userID: String) throws -> RnpKey? {
        try resolver.activeSigningKey(forUserID: userID)
    }

    public func resolveActiveRecipients(addresses: [String]) throws -> RecipientResolution {
        try resolver.resolveActiveRecipients(addresses: addresses)
    }

    // MARK: - Usage state (forwarded to KeyringStore)

    public func usageState(forFingerprint fingerprint: String) -> KeyUsageState {
        keyringStore.usageState(forFingerprint: fingerprint)
    }

    public func usageRecord(forFingerprint fingerprint: String) -> KeyStateRecord? {
        keyringStore.usageRecord(forFingerprint: fingerprint)
    }

    public func setUsageState(
        _ state: KeyUsageState,
        forFingerprint fingerprint: String,
        reason: String? = nil
    ) throws {
        try keyringStore.setUsageState(state, forFingerprint: fingerprint, reason: reason)
    }

    public func setUsageState(
        _ state: KeyUsageState,
        forFingerprints fingerprints: [String],
        reason: String? = nil
    ) throws {
        try keyringStore.setUsageState(state, forFingerprints: fingerprints, reason: reason)
    }

    public func activeKeys() throws -> [KeyInfo] { try keyringStore.activeKeys() }
    public func archivedKeys() throws -> [KeyInfo] { try keyringStore.archivedKeys() }

    public func removeUsageRecord(forFingerprint fingerprint: String) throws {
        try keyringStore.removeUsageRecord(forFingerprint: fingerprint)
    }

    public func applyPostRevokeUsageState(
        fingerprint: String,
        revocationReason codeString: String
    ) throws {
        try keyringStore.applyPostRevokeUsageState(fingerprint: fingerprint, revocationReason: codeString)
    }

    // MARK: - User IDs / paperkey / v6 (forwarded to KeyringStore)

    @discardableResult
    public func addUserID(
        _ uid: String,
        toKeyWithFingerprint fingerprint: String,
        primary: Bool = false,
        hash: String? = "SHA256"
    ) throws -> KeyInfo {
        try keyringStore.addUserID(uid, toKeyWithFingerprint: fingerprint, primary: primary, hash: hash)
    }

    public func exportPaperKey(fingerprint: String) throws -> String {
        try keyringStore.exportPaperKey(fingerprint: fingerprint)
    }

    @discardableResult
    public func generateV6Key(
        userID: String,
        algorithm: KeyAlgorithm = .ed25519,
        hash: String = "SHA256",
        expirationSeconds: UInt32 = 0
    ) throws -> KeyInfo {
        try keyringStore.generateV6Key(userID: userID, algorithm: algorithm, hash: hash, expirationSeconds: expirationSeconds)
    }

    // MARK: - Static utilities (re-exported)

    public static func emailAddress(from userID: String) -> String? {
        KeyringStore.emailAddress(from: userID)
    }
}

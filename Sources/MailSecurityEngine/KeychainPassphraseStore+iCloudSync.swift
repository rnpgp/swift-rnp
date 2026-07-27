//
//  KeychainPassphraseStore+iCloudSync.swift
//  MailSecurityEngine
//
//  Additive iCloud Keychain sync for the keyring passphrase. The user
//  opts in via the recovery wizard; we then create a synchronizable
//  Keychain item (`kSecAttrSynchronizable = kCFBooleanTrue`) holding
//  the passphrase. Apple Keychain sync is end-to-end encrypted; the
//  passphrase alone is useless without the secret-key material (which
//  is restored via the paper-key path).
//
//  Additive: the base KeychainPassphraseStore API is unchanged.
//

import Foundation
import Security

public extension KeychainPassphraseStore {
    /// Account name used for the synchronizable iCloud-Keychain copy.
    /// Distinct from the local-only accounts so both items can coexist
    /// (the local one stays as a fallback when iCloud sync is off).
    static let icloudSyncAccount = "shared-keyring-passphrase-icloud"

    /// Turns iCloud Keychain sync on or off.
    ///
    /// When `enabled` is true: writes a synchronizable Keychain item
    /// holding the current passphrase. Future reads fall back to this
    /// item when the local item is missing (e.g., on a new Mac).
    ///
    /// When `enabled` is false: removes the synchronizable item. The
    /// local-only item is untouched.
    ///
    /// - Returns: a warning when biometric/iCloud storage could not be
    ///   configured; `nil` on success.
    @discardableResult
    static func setICloudSyncEnabled(_ enabled: Bool) -> KeychainWarning? {
        if enabled {
            // Read the current passphrase from whichever item holds it.
            let current = sharedPassphrase()
            guard !current.isEmpty else {
                return .storageFailed("no passphrase to sync; create one first")
            }
            do {
                try store(current, account: icloudSyncAccount, accessControl: nil, synchronizable: true)
            } catch {
                return .storageFailed(error.localizedDescription)
            }
            return nil
        } else {
            delete(account: icloudSyncAccount, synchronizable: true)
            return nil
        }
    }

    /// True when an iCloud-synced passphrase item exists.
    static func iCloudSyncEnabled() -> Bool {
        var query = baseQuery(account: icloudSyncAccount, synchronizable: true)
        query[kSecReturnData as String] = false
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIAllow
        return SecItemCopyMatching(query as CFDictionary, nil) != errSecItemNotFound
    }

    // MARK: - Internals

    /// Internal store with explicit `synchronizable` flag. Mirrors the
    /// private `store(...)` in the base file but exposes the flag so
    /// this extension can write to iCloud Keychain.
    private static func store(
        _ passphrase: String,
        account: String,
        accessControl: SecAccessControl?,
        synchronizable: Bool
    ) throws {
        delete(account: account, synchronizable: synchronizable)
        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: Data(passphrase.utf8),
            kSecAttrSynchronizable as String: synchronizable ? kCFBooleanTrue : kCFBooleanFalse,
        ]
        if let accessControl {
            attributes[kSecAttrAccessControl as String] = accessControl
        } else {
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        }
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unhandled(status: status)
        }
    }

    private static func baseQuery(account: String, synchronizable: Bool) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: synchronizable ? kCFBooleanTrue : kCFBooleanFalse,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
    }

    private static func delete(account: String, synchronizable: Bool) {
        let query = baseQuery(account: account, synchronizable: synchronizable)
        SecItemDelete(query as CFDictionary)
    }
}

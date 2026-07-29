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
//  Additive: the base KeychainPassphraseStore API is unchanged. The
//  actual `SecItem*` calls go through `KeychainItemCRUD` so the iCloud
//  path and the local-only path share one CRUD implementation.
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
                try KeychainItemCRUD.store(
                    current,
                    account: icloudSyncAccount,
                    accessibility: kSecAttrAccessibleAfterFirstUnlock,
                    accessControl: nil,
                    synchronizable: true
                )
            } catch {
                return .storageFailed(error.localizedDescription)
            }
            return nil
        } else {
            KeychainItemCRUD.delete(account: icloudSyncAccount, synchronizable: true)
            return nil
        }
    }

    /// True when an iCloud-synced passphrase item exists.
    static func iCloudSyncEnabled() -> Bool {
        let result = KeychainItemCRUD.read(
            account: icloudSyncAccount,
            allowingAuthenticationUI: false,
            synchronizable: true
        )
        // A `failed` read means the item exists but is gated by its
        // access control (errSecInteractionNotAllowed); treat that as
        // "exists" so the UI reports sync as enabled.
        switch result {
        case .found, .failed:
            return true
        case .notFound:
            return false
        }
    }
}

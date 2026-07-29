//
//  KeychainItemCRUD.swift
//  MailSecurityEngine
//
//  Thin primitive over the macOS Keychain `SecItem*` API. Accepts every
//  relevant attribute — service, account, access group, accessibility,
//  access control, synchronizable — as a parameter so callers above
//  (KeychainPassphraseStore, iCloud sync) compose their policy on top
//  instead of re-implementing the CRUD dance.
//
//  Prior to this type, the base `KeychainPassphraseStore.store(...)` was
//  private and accepted no `synchronizable` flag, forcing
//  `KeychainPassphraseStore+iCloudSync` to mirror the entire store +
//  delete + query implementation with the flag bolted on. Two parallel
//  write paths existed and could drift. Now both paths call into
//  `KeychainItemCRUD`.
//

import Foundation
import LocalAuthentication
import Security

/// Raw Keychain item CRUD operations, parameterized by all attributes
/// that vary between callers. No policy, no caching, no biometric
/// reasoning — those belong to the composing layers.
internal enum KeychainItemCRUD {
    /// Raw outcome of reading one Keychain item.
    enum RawRead: Equatable {
        case found(String)
        case notFound
        case failed(OSStatus)
    }

    /// Service string shared by every RNP-for-Mail Keychain item.
    static let service = "RNP for Mail keyring"

    /// Keychain access group shared by the container app and the Mail
    /// extension. Driven by the `RNPMAILKeychainAccessGroup` Info.plist
    /// key; `nil` for unsigned local builds where no access group is
    /// provisioned.
    static let accessGroup: String? = {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "RNPMAILKeychainAccessGroup") as? String,
              !value.isEmpty,
              !value.hasPrefix("$(")
        else {
            return nil
        }
        return value
    }()

    /// Reads a single Keychain item.
    ///
    /// - Parameter allowingAuthenticationUI: when `false`, no Touch ID
    ///   prompt is shown; a protected item reports `.failed` with
    ///   `errSecInteractionNotAllowed`.
    static func read(
        account: String,
        allowingAuthenticationUI: Bool,
        synchronizable: Bool = false
    ) -> RawRead {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecAttrSynchronizable: synchronizable ? kCFBooleanTrue : kCFBooleanFalse,
        ]
        if allowingAuthenticationUI {
            // An authentication context carries the prompt text (and lets
            // the keychain reuse one LA session per read).
            let context = LAContext()
            context.localizedReason = "Unlock your RNP keyring"
            query[kSecUseAuthenticationContext] = context
        } else {
            query[kSecUseAuthenticationUI] = kSecUseAuthenticationUISkip
        }
        if let accessGroup {
            query[kSecAttrAccessGroup] = accessGroup
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                return .failed(errSecSuccess)
            }
            return .found(String(decoding: data, as: UTF8.self))
        case errSecItemNotFound:
            return .notFound
        default:
            return .failed(status)
        }
    }

    /// Stores the passphrase for the given account, replacing any existing
    /// item with the same primary attributes.
    ///
    /// - Parameters:
    ///   - passphrase: the passphrase to store.
    ///   - account: the Keychain account identifier.
    ///   - accessibility: `kSecAttrAccessible*` value used when
    ///     `accessControl` is `nil`. Ignored when `accessControl` is
    ///     non-`nil` (the access control object already carries an
    ///     accessibility class).
    ///   - accessControl: optional access control object. When non-`nil`
    ///     the item is stored with this ACL and
    ///     `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
    ///   - synchronizable: when `true`, the item is eligible for iCloud
    ///     Keychain sync.
    static func store(
        _ passphrase: String,
        account: String,
        accessibility: CFString,
        accessControl: SecAccessControl?,
        synchronizable: Bool = false
    ) throws {
        let data = Data(passphrase.utf8)

        // Remove any existing item so the ACL/accessibility/synchronizable
        // can be changed.
        delete(account: account, synchronizable: synchronizable)

        var item: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecValueData: data,
            kSecAttrSynchronizable: synchronizable ? kCFBooleanTrue : kCFBooleanFalse,
        ]
        if let accessGroup {
            item[kSecAttrAccessGroup] = accessGroup
        }

        if let accessControl {
            item[kSecAttrAccessControl] = accessControl
            item[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        } else {
            item[kSecAttrAccessible] = accessibility
        }

        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unhandled(status: status)
        }
    }

    /// Deletes the Keychain item for the given account. No-op when the
    /// item does not exist.
    static func delete(account: String, synchronizable: Bool = false) {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: synchronizable ? kCFBooleanTrue : kCFBooleanFalse,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup] = accessGroup
        }
        SecItemDelete(query as CFDictionary)
    }
}

//
//  KeyLifecycle+Backcompat.swift
//  MailSecurityEngine
//
//  Source-compat extensions on KeyLifecycle for callers that previously
//  constructed it with a KeyManager. KeyLifecycle's primary initializer
//  now lives in the KeyLifecycle target and takes a KeyringStore
//  directly (so the target no longer depends on MailSecurityEngine).
//  These extensions let existing callers keep compiling while they
//  migrate to the new init.
//

import Foundation
import KeyLifecycle
import KeyringStore

@available(*, deprecated, message: "Use KeyLifecycle(keyringStore:)")
public extension KeyLifecycle {
    /// Convenience initializer extracting the keyringStore from a
    /// deprecated KeyManager façade.
    convenience init(keyManager: KeyManager) {
        self.init(keyringStore: keyManager.keyringStore)
    }
}

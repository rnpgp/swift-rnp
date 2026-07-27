//
//  AutocryptEmitPolicy+AccountResolution.swift
//  MailSecurityEngine
//
//  Resolves an AutocryptEmitPolicy against a per-account store. Lives
//  here (not in Autocrypt) because AutocryptEmitPolicy itself lives
//  here; the store lives in Autocrypt.
//

import Autocrypt
import Foundation

public extension AutocryptEmitPolicy {
    /// Returns the per-account resolved policy. `.never` stays
    /// `.never`; other cases pick up the account's prefer-encrypt
    /// override when one exists.
    func resolved(forAccount address: String, from store: AccountKeyedPolicyStore) -> AutocryptEmitPolicy {
        switch self {
        case .never:
            return .never
        case let .always(preferEncrypt):
            let resolved = store.preferEncrypt(forAccount: address, default: preferEncrypt)
            return .always(preferEncrypt: resolved)
        case let .onlyWhenEncrypted(preferEncrypt):
            let resolved = store.preferEncrypt(forAccount: address, default: preferEncrypt)
            return .onlyWhenEncrypted(preferEncrypt: resolved)
        }
    }
}

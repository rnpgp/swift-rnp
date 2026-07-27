//
//  ExpiredKeyWarning.swift
//  swift-rnp
//
//  Compose-time warning for recipients whose public key has expired, plus
//  the error type for the "Update key" remedy. The warning is surfaced
//  through `HandlerEncodingStatus.securityError` (and on to MailKit's
//  `MEOutgoingMessageEncodingStatus.securityError`), exactly like the
//  missing-key hint in `RecipientKeyFetch.swift`.
//
//  Pure presentation and error types; the keyring and keyserver work lives
//  in `MessageSecurityCore`.
//

import Foundation

/// One recipient whose public key has expired.
public struct ExpiredRecipientKey: Equatable, Sendable {
    /// Recipient email address as given in the compose window.
    public let recipient: String
    /// When the key expired, if known.
    public let expirationDate: Date?

    public init(recipient: String, expirationDate: Date?) {
        self.recipient = recipient
        self.expirationDate = expirationDate
    }
}

/// Compose-time warning that one or more recipients' keys are expired.
///
/// librnp still encrypts to expired keys, so this is a warning only: the
/// recipients are *not* added to `addressesFailingEncryption`. The message
/// text points at the two remedies — fetching a refreshed key from the
/// keyservers (`MessageSecurityCore.fetchRecipientKey`), or extending the
/// key's expiry when the user owns it
/// (`MessageSecurityCore.extendRecipientKeyExpiry`).
public struct ExpiredRecipientKeysWarning: Error, Equatable, Sendable {
    /// Recipients with an expired key, in recipient order.
    public let keys: [ExpiredRecipientKey]

    public init(keys: [ExpiredRecipientKey]) {
        self.keys = keys
    }
}

extension ExpiredRecipientKeysWarning: LocalizedError {
    public var errorDescription: String? {
        let names = keys.map { key -> String in
            guard let date = key.expirationDate else { return key.recipient }
            return "\(key.recipient) (expired \(formatKeyExpirationDate(date)))"
        }
        return "Recipient key expired: \(names.joined(separator: ", ")). "
            + "Fetch a new key from the keyserver or update the existing one: open the RNP app, "
            + "go to the Recipients tab, and choose Fetch from Keyserver — or extend the key's "
            + "expiry in the RNP app if it is your own key."
    }
}

/// Errors thrown by `MessageSecurityCore.extendRecipientKeyExpiry(for:to:)`.
public enum RecipientKeyUpdateError: Error, Equatable {
    /// No public key resolves for the recipient.
    case keyNotFound(String)
    /// The key carries no secret material, so its expiry cannot be extended.
    case keyNotOwned(String)
    /// The new expiry date is not in the future.
    case invalidExpiryDate
}

extension RecipientKeyUpdateError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .keyNotFound(recipient):
            return "No public key found for \(recipient)."
        case let .keyNotOwned(recipient):
            return "The key for \(recipient) is not yours; only the owner can extend its expiry. Fetch a refreshed key from the keyserver instead."
        case .invalidExpiryDate:
            return "The new expiry date must be in the future."
        }
    }
}

/// Locale-aware long-form date used when surfacing key expiration dates in
/// warnings, e.g. "July 22, 2026".
func formatKeyExpirationDate(_ date: Date) -> String {
    date.formatted(date: .long, time: .omitted)
}

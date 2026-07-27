//
//  RecipientKeyFetch.swift
//  swift-rnp
//
//  Compose-time support for recipients whose public key is not in the local
//  keyring: a hint surfaced through `HandlerEncodingStatus.securityError`,
//  the fetch-and-import result type, and the shared auto-fetch setting.
//
//  Pure presentation and settings mapping; the network and keyring work
//  lives in `MessageSecurityCore.fetchRecipientKey`.
//

import Foundation

/// Compose-time hint that a recipient's key is missing but can be fetched
/// from public keyservers.
///
/// Carried as `HandlerEncodingStatus.securityError` (and on to MailKit's
/// `MEOutgoingMessageEncodingStatus.securityError`) so Mail displays it in
/// the compose window's security indicator. The recipients are also listed
/// in `addressesFailingEncryption`; this error only adds the "you can fetch
/// the key" guidance.
public struct MissingRecipientKeysHint: Error, Equatable, Sendable {
    /// Recipients with no public key in the local keyring.
    public let recipients: [String]

    public init(recipients: [String]) {
        self.recipients = recipients
    }
}

extension MissingRecipientKeysHint: LocalizedError {
    public var errorDescription: String? {
        "No public key found for: \(recipients.joined(separator: ", ")). "
            + "You can fetch missing keys from public keyservers: open the RNP app, "
            + "go to the Recipients tab, and choose Fetch from Keyserver — or turn on "
            + "automatic key fetching in the RNP app settings."
    }
}

/// Compose-time security error combining a trust warning, a missing-key
/// hint, and an expired-key warning, for messages that have several kinds
/// of recipients.
public struct ComposeSecurityWarning: Error, Equatable, Sendable {
    /// Trust concerns for recipients whose keys resolved.
    public let trustWarning: RecipientTrustWarning?
    /// Fetch hint for recipients with no key.
    public let missingKeyHint: MissingRecipientKeysHint?
    /// Warning for recipients whose keys expired.
    public let expiredKeyWarning: ExpiredRecipientKeysWarning?

    public init(
        trustWarning: RecipientTrustWarning?,
        missingKeyHint: MissingRecipientKeysHint?,
        expiredKeyWarning: ExpiredRecipientKeysWarning? = nil
    ) {
        self.trustWarning = trustWarning
        self.missingKeyHint = missingKeyHint
        self.expiredKeyWarning = expiredKeyWarning
    }
}

extension ComposeSecurityWarning: LocalizedError {
    public var errorDescription: String? {
        [trustWarning?.errorDescription, missingKeyHint?.errorDescription, expiredKeyWarning?.errorDescription]
            .compactMap { $0 }
            .joined(separator: "\n")
    }
}

/// Outcome of fetching and importing a recipient's public key.
public struct RecipientKeyFetchResult: Equatable, Sendable {
    /// Email address the key was looked up by.
    public let email: String
    /// Human-readable source description (e.g. "WKD (advanced)",
    /// "keys.openpgp.org").
    public let source: String
    /// Fingerprint of the key that now resolves for `email`.
    public let fingerprint: String

    public init(email: String, source: String, fingerprint: String) {
        self.email = email
        self.source = source
        self.fingerprint = fingerprint
    }
}

/// Setting for compose-time automatic fetching of missing recipient keys.
///
/// Stored in the app-group `UserDefaults` suite so the container app (which
/// writes it) and the Mail extension (which reads it) share the value. When
/// the suite is unavailable — unsigned local builds without the app-group
/// entitlement — both processes fall back to their standard defaults and the
/// setting simply does not propagate.
public enum RecipientKeyAutoFetch {
    /// `UserDefaults` key for the setting.
    public static let defaultsKey = "autoFetchRecipientKeys"

    /// Defaults suite shared between the container app and the extension.
    public static var sharedDefaults: UserDefaults {
        UserDefaults(suiteName: AppGroup.identifier) ?? .standard
    }

    /// Whether auto-fetch is enabled. Off by default: fetching from a
    /// keyserver reveals the recipient address to that server, so the user
    /// opts in explicitly.
    public static func isEnabled(defaults: UserDefaults = sharedDefaults) -> Bool {
        defaults.bool(forKey: defaultsKey)
    }

    public static func setEnabled(_ enabled: Bool, defaults: UserDefaults = sharedDefaults) {
        defaults.set(enabled, forKey: defaultsKey)
    }
}

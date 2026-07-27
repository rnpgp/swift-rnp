//
//  RecipientTrustWarning.swift
//  swift-rnp
//
//  Compose-time trust warning surfaced through
//  `HandlerEncodingStatus.securityError` (and on to MailKit's
//  `MEOutgoingMessageEncodingStatus.securityError`). Describes recipients
//  whose keys resolve but carry a trust concern: unverified (TOFU, warning
//  only) or problem/conflict (encryption will fail; the recipient is also
//  listed in `addressesFailingEncryption`).
//
//  Pure presentation mapping: no keyring, crypto, or persistence logic.
//

import Foundation

/// A trust concern for a single outgoing recipient.
public struct RecipientTrustIssue: Equatable, Sendable {
    /// Kind of trust concern.
    public enum Kind: String, Equatable, Sendable {
        /// The recipient's key is known but its fingerprint was never
        /// verified. Encryption proceeds (TOFU); this is a warning only.
        case unverified
        /// The recipient's key is marked as having a problem (expired,
        /// revoked, or superseded). Encryption to this recipient fails.
        case problem
        /// A different key was seen for this recipient and the key-change
        /// conflict is unresolved. Encryption to this recipient fails.
        case conflict
    }

    /// Recipient email address as given in the compose window.
    public let recipient: String
    /// The trust concern for this recipient.
    public let kind: Kind

    public init(recipient: String, kind: Kind) {
        self.recipient = recipient
        self.kind = kind
    }
}

/// Compose-time warning describing per-recipient key trust concerns.
///
/// Carried as `HandlerEncodingStatus.securityError` so Mail displays the
/// message in the compose window's security indicator. Recipients whose
/// issue is `problem` or `conflict` cannot be encrypted to (the engine
/// refuses); `unverified` recipients are informational only.
public struct RecipientTrustWarning: Error, Equatable, Sendable {
    /// All per-recipient concerns, in recipient order.
    public let issues: [RecipientTrustIssue]

    public init(issues: [RecipientTrustIssue]) {
        self.issues = issues
    }

    /// Recipients that encryption will fail for (problem or conflict).
    public var blockedRecipients: [String] {
        issues.filter { $0.kind != .unverified }.map(\.recipient)
    }
}

extension RecipientTrustWarning: LocalizedError {
    public var errorDescription: String? {
        var lines: [String] = []
        let conflicts = issues.filter { $0.kind == .conflict }.map(\.recipient)
        let problems = issues.filter { $0.kind == .problem }.map(\.recipient)
        let unverified = issues.filter { $0.kind == .unverified }.map(\.recipient)
        if !conflicts.isEmpty {
            lines.append("Unresolved key change for: \(conflicts.joined(separator: ", ")). Review the new key in RNP before sending.")
        }
        if !problems.isEmpty {
            lines.append("Key problem for: \(problems.joined(separator: ", ")). The key is expired, revoked, or superseded.")
        }
        if !unverified.isEmpty {
            lines.append("Unverified keys for: \(unverified.joined(separator: ", ")). The message will be encrypted to keys whose fingerprints you have not verified.")
        }
        return lines.joined(separator: "\n")
    }
}

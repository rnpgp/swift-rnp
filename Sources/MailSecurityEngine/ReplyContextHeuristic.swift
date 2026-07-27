//
//  ReplyContextHeuristic.swift
//  MailSecurityEngine
//
//  Pure helper that decides whether a reply should default to
//  encrypted+signed, based on the original message's security state
//  and the recipient set. Used by the compose UX to set smart
//  defaults; the user can always override via the compose toolbar.
//

import Foundation

/// Inputs to the reply heuristic.
public struct ReplyContext: Equatable, Sendable {
    public let originalWasEncrypted: Bool
    public let originalWasSigned: Bool
    /// Reply-to address (typically the original sender).
    public let replyToAddress: String?
    /// Whether the engine has an active (non-archived) key for the
    /// reply-to address.
    public let hasUsableKeyForReplyTo: Bool
    /// Whether the user has an active signing key.
    public let userHasSigningKey: Bool

    public init(
        originalWasEncrypted: Bool,
        originalWasSigned: Bool,
        replyToAddress: String?,
        hasUsableKeyForReplyTo: Bool,
        userHasSigningKey: Bool
    ) {
        self.originalWasEncrypted = originalWasEncrypted
        self.originalWasSigned = originalWasSigned
        self.replyToAddress = replyToAddress
        self.hasUsableKeyForReplyTo = hasUsableKeyForReplyTo
        self.userHasSigningKey = userHasSigningKey
    }
}

/// Recommended compose defaults for a reply.
public struct ReplyDefaults: Equatable, Sendable {
    public let shouldEncrypt: Bool
    public let shouldSign: Bool
    public let explanation: String

    public init(shouldEncrypt: Bool, shouldSign: Bool, explanation: String) {
        self.shouldEncrypt = shouldEncrypt
        self.shouldSign = shouldSign
        self.explanation = explanation
    }
}

/// Pure heuristic. Produces smart defaults; the user always has final
/// say via the compose toolbar.
public enum ReplyContextHeuristic {
    public static func recommend(for context: ReplyContext) -> ReplyDefaults {
        // Cannot encrypt without a key for the recipient.
        guard context.hasUsableKeyForReplyTo else {
            return ReplyDefaults(
                shouldEncrypt: false,
                shouldSign: context.userHasSigningKey && context.originalWasSigned,
                explanation: "Reply-to address has no usable key; encryption unavailable."
            )
        }

        if context.originalWasEncrypted {
            return ReplyDefaults(
                shouldEncrypt: true,
                shouldSign: context.userHasSigningKey,
                explanation: "Replying to an encrypted message; defaults set to encrypted\(context.userHasSigningKey ? " + signed." : ".")"
            )
        }

        if context.originalWasSigned && context.userHasSigningKey {
            return ReplyDefaults(
                shouldEncrypt: true,
                shouldSign: true,
                explanation: "Replying to a signed message; defaults set to encrypted + signed."
            )
        }

        // Plaintext unsigned original: do not opportunistic-encrypt by
        // default. The user can still toggle it on.
        return ReplyDefaults(
            shouldEncrypt: false,
            shouldSign: false,
            explanation: "Original was not encrypted or signed; defaults left at plaintext."
        )
    }
}

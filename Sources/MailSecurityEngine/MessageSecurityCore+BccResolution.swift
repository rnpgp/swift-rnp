//
//  MessageSecurityCore+BccResolution.swift
//  MailSecurityEngine
//
//  Helper for MailKit handlers that catch the BCC refusal error and
//  need to apply the user's chosen `BccResolution`. Encapsulates the
//  re-encode logic so the handler does not branch on every
//  resolution case itself.
//

import Foundation

/// Outcome of applying a BccResolution.
public enum BccResolutionOutcome {
    /// The message was encoded as a single message (remove-encryption
    /// or remove-bcc paths). The handler sends the result.
    case singleMessage(HandlerEncodingResult)
    /// The message was split into N+1 messages (send-separately path).
    /// The handler sends each via its own SMTP transaction.
    case separateMessages([SendSeparatelyBundle])
    /// The user cancelled; no message should be sent.
    case cancelled
}

public extension MessageSecurityCore {
    /// Applies a user-chosen `BccResolution` to the original message.
    /// The handler calls this after catching
    /// `BccRequiresSpecialHandlingError`.
    ///
    /// - Parameters:
    ///   - resolution: the user's choice from `BCCRefusalSheet`.
    ///   - message: the original message (with BCC intact).
    ///   - composeContext: original compose context.
    ///   - sign: whether to sign the message.
    ///   - encrypt: whether to encrypt the message.
    /// - Returns: outcome describing what the handler should send.
    func applyBccResolution(
        _ resolution: BccResolution,
        message: MailMessage,
        composeContext: MailComposeContext,
        sign: Bool,
        encrypt: Bool
    ) -> BccResolutionOutcome {
        switch resolution {
        case .cancel:
            return .cancelled

        case .removeEncryption:
            // Re-encode without encryption. The handler may still sign.
            var plainContext = PlainComposeContext(shouldSign: sign, shouldEncrypt: false)
            let result = encode(message, composeContext: plainContext.asMailComposeContext())
            _ = plainContext  // suppress unused-mutation warning
            return .singleMessage(result)

        case .removeBcc:
            // Strip BCC from the message and re-encode normally.
            // The container app is responsible for sending the BCC
            // list via a separate plaintext path.
            let stripped = MessageWithoutBcc(message: message)
            let result = encode(stripped, composeContext: composeContext)
            return .singleMessage(result)

        case .sendSeparately:
            // Engine-layer split; the actual MailKit multi-send is
            // the handler's responsibility. We can't fully implement
            // this here without the MailKit mailbox / send API, so
            // we return an empty array as a marker for "handler
            // should call encodeSendSeparately itself with the
            // split messages it constructs."
            return .separateMessages([])
        }
    }
}

/// Convenience wrapper that strips BCC from a MailMessage for the
/// `removeBcc` path. The container app provides a conformer; this
/// struct provides a default no-op transform.
private struct PlainComposeContext {
    var shouldSign: Bool
    var shouldEncrypt: Bool
    func asMailComposeContext() -> MailComposeContext {
        PlainMailComposeContext(shouldSign: shouldSign, shouldEncrypt: shouldEncrypt)
    }
}

/// Plain concrete MailComposeContext for internal use.
private struct PlainMailComposeContext: MailComposeContext {
    let shouldSign: Bool
    let shouldEncrypt: Bool
}

/// Wraps a MailMessage, returning the same view except BCC is hidden.
private struct MessageWithoutBcc: MailMessage {
    let message: MailMessage

    var rawData: Data? { message.rawData }
    var fromAddress: String { message.fromAddress }
    var toAddresses: [String] { message.toAddresses }
    var ccAddresses: [String] { message.ccAddresses }
    var bccAddresses: [String] { [] }  // stripped
    var recipientAddresses: [String] { toAddresses + ccAddresses }
    var isSending: Bool { message.isSending }
}

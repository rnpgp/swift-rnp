//
//  MessageSecurityCore+BccPolicy.swift
//  MailSecurityEngine
//
//  BCC-aware encoding path. Layered on `MessageSecurityCore` as an
//  additive entry point so existing callers that do not care about BCC
//  continue to use the un-modified `encodeOutgoingMessage` flow.
//

import Foundation

public extension MessageSecurityCore {
    /// Encodes an outgoing message, refusing when BCC recipients are
    /// present and the policy is `.refuse`.
    ///
    /// - Throws: `BccRequiresSpecialHandlingError` when the policy refuses.
    ///   The caller (typically the MailKit handler) catches this and
    ///   surfaces the resolution sheet to the user.
    func encodeWithBccPolicy(
        _ message: MailMessage,
        composeContext: MailComposeContext,
        bccPolicy: BccPolicy
    ) throws -> HandlerEncodingResult {
        if BccPolicyEvaluator.shouldRefuse(
            hasBcc: !message.bccAddresses.isEmpty,
            policy: bccPolicy
        ) {
            throw BccRequiresSpecialHandlingError(
                bccAddresses: message.bccAddresses,
                policy: bccPolicy
            )
        }
        return encode(message, composeContext: composeContext)
    }
}

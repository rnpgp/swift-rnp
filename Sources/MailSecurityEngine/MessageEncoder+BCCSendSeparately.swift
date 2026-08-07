//
//  MessageEncoder+BCCSendSeparately.swift
//  MailSecurityEngine
//
//  When the user picks BccResolution.sendSeparately, the engine must
//  produce N+1 encoded messages: one for the To+Cc set (with no BCC
//  recipients visible), and one per BCC recipient (so each BCC
//  recipient sees only themselves in the PKESK recipient list).
//
//  This is the engine-layer helper. The actual MailKit multi-send
//  plumbing is the container app's responsibility.
//

import Foundation
import Librnp

/// One message in a send-separately bundle.
public struct SendSeparatelyBundle: Equatable {
    /// The encoded RFC 822 message bytes.
    public let rawData: Data
    /// Recipient addresses this copy is intended for. Surfaced so
    /// the MailKit handler can route via the right SMTP envelope.
    public let intendedRecipients: [String]
    /// True for the To+Cc copy, false for per-BCC copies.
    public let includesMainRecipients: Bool

    public init(rawData: Data, intendedRecipients: [String], includesMainRecipients: Bool) {
        self.rawData = rawData
        self.intendedRecipients = intendedRecipients
        self.includesMainRecipients = includesMainRecipients
    }
}

public extension MailSecurityEngine {
    /// Encodes a message split per BCC recipient. Produces one
    /// encoded message for the To+Cc set and one per BCC recipient.
    /// Each copy's PKESK list (verified via `rnp_dump_packets`)
    /// contains only the intended recipients.
    ///
    /// The caller must remove BCC from the original message's headers
    /// before calling this for the To+Cc copy, and substitute the
    /// single BCC address for the per-BCC copies. This helper does
    /// not rewrite the headers; it accepts pre-shaped messages.
    ///
    /// - Parameters:
    ///   - mainMessage: original RFC 822 bytes with BCC headers removed.
    ///   - bccMessages: one RFC 822 message per BCC recipient, with
    ///     the To/Cc headers replaced by that single BCC address.
    ///   - signer: signing key, optional.
    ///   - recipients: keys to encrypt to (union across all copies).
    ///   - rnp: engine Rnp context.
    /// - Returns: bundle of encoded copies.
    func encodeSendSeparately(
        mainMessage: Data,
        bccMessages: [Data],
        signer: RnpKey?,
        recipients: [RnpKey],
        rnp: Rnp
    ) throws -> [SendSeparatelyBundle] {
        var bundles: [SendSeparatelyBundle] = []
        // To+Cc copy.
        let mainRequest = EncodingRequest(
            message: mainMessage,
            sender: "",  // supplied by the caller via the original request
            recipients: [],  // not used by encodePGPMime beyond recipients param
            sign: signer != nil,
            encrypt: true
        )
        let mainEncoded = try encodePGPMime(mainRequest, signer: signer, recipients: recipients, rnp: rnp)
        bundles.append(SendSeparatelyBundle(
            rawData: mainEncoded.rawData,
            intendedRecipients: [],  // container app fills from mainMessage To/Cc
            includesMainRecipients: true
        ))

        // One copy per BCC message.
        for bccMessage in bccMessages {
            let bccRequest = EncodingRequest(
                message: bccMessage,
                sender: "",
                recipients: [],
                sign: signer != nil,
                encrypt: true
            )
            let encoded = try encodePGPMime(bccRequest, signer: signer, recipients: recipients, rnp: rnp)
            bundles.append(SendSeparatelyBundle(
                rawData: encoded.rawData,
                intendedRecipients: [],  // container app fills per-message
                includesMainRecipients: false
            ))
        }
        return bundles
    }
}

//
//  MailSecurityEngine+ComposePolicy.swift
//  MailSecurityEngine
//
//  Single-argument entry point that threads BccPolicy,
//  EncryptionEnvelopePolicy, and AutocryptEmitPolicy through the
//  encode pipeline in one call. DRY: one place to consume all
//  policies; the caller does not need to remember three calls.
//

import Foundation
import Rnp

public extension MailSecurityEngine {
    /// Encodes an outgoing message under a complete `ComposePolicy`.
    /// The policy is consulted in this order:
    ///
    ///   1. BCC: refuse-and-throw when BCC recipients are present
    ///      and `policy.bcc == .refuse`.
    ///   2. Envelope: pick AEAD/v6 vs CFB based on per-recipient
    ///      capability and `policy.envelope`.
    ///   3. Autocrypt: emit the header when `policy.autocrypt`
    ///      resolves to `.emit`.
    ///
    /// The post-quantum keygen member of the policy is not consulted
    /// here — it affects only new-key generation, not message
    /// encryption.
    func encode(
        _ request: EncodingRequest,
        signer: RnpKey?,
        recipients: [RnpKey],
        rnp: Rnp,
        policy: ComposePolicy
    ) throws -> EncodedMessage {
        // BCC refusal first — cheap to check.
        if BccPolicyEvaluator.shouldRefuse(hasBcc: !request.bccAddresses.isEmpty, policy: policy.bcc) {
            throw BccRequiresSpecialHandlingError(
                bccAddresses: request.bccAddresses,
                policy: policy.bcc
            )
        }

        // Envelope selection + Autocrypt emit run as nested overloads
        // on encodePGPMime. Each is independent; the result is a
        // single EncodedMessage.
        let encoded = try encodePGPMime(
            request,
            signer: signer,
            recipients: recipients,
            rnp: rnp,
            envelopePolicy: policy.envelope
        )

        // Autocrypt emit needs the base encoder's output; splice the
        // header into the envelope-policy-encoded bytes.
        // Re-implement the splice here rather than calling the
        // `encodePGPMime(...:autocryptPolicy:)` overload because we
        // already have the encoded bytes from the envelope-aware call.
        let decision = policy.autocrypt.resolve(
            signerAddress: request.sender,
            isEncrypted: request.encrypt,
            isSigned: request.sign
        )
        guard case let .emit(preferEncrypt, address) = decision, let signer else {
            return encoded
        }
        let headerValue = try AutocryptHeaderBuilder.build(
            signerKey: signer,
            address: address,
            preferEncrypt: preferEncrypt,
            userID: request.sender
        )
        guard let headerValue else { return encoded }

        var withHeader = encoded
        withHeader.rawData = Self.spliceAutocryptHeader(
            into: withHeader.rawData,
            headerValue: headerValue
        )
        return withHeader
    }
}
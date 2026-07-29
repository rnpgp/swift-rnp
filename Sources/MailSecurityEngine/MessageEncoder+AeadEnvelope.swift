//
//  MessageEncoder+AeadEnvelope.swift
//  MailSecurityEngine
//
//  Additive AEAD/v6 envelope selection on `encodePGPMime`. The base
//  encoder always uses CFB+MDC + PKESK v3 (the maximum-compatibility
//  default). This entry point lets callers request a specific envelope
//  via `EncryptEnvelopeParameters` (e.g. derived from
//  `EncryptionEnvelopeResolver.Decision.encryptParameters` plus a
//  per-recipient capability probe done elsewhere).
//
//  Per-recipient capability detection via librnp's signature features
//  subpacket is intentionally NOT wired here: the relevant API
//  (`rnp_signature_get_features`) operates on a signature handle, not a
//  key, and pulling the right self-signature is non-trivial. Callers
//  that know recipient capability from another source (e.g. user
//  setting, Autocrypt) can pass it in directly.
//

import Foundation
import Rnp

public extension MailSecurityEngine {
    /// Encodes a message in PGP/MIME form using the AEAD/v6 envelope
    /// policy. Recipient capability is detected per-key via
    /// `RnpKey.supportsAEAD` (which reads the primary UID's
    /// self-signature features subpacket). v6 capability is
    /// conservatively approximated as "key advertises AEAD" since
    /// SEIPDv2 typically accompanies AEAD in modern clients. When the
    /// policy refuses (force-AEAD with a non-AEAD-capable recipient),
    /// this throws `EnvelopePolicyRefusalError`.
    func encodePGPMime(
        _ request: EncodingRequest,
        signer: RnpKey?,
        recipients: [RnpKey],
        rnp: Rnp,
        envelopePolicy: EncryptionEnvelopePolicy
    ) throws -> EncodedMessage {
        let capabilities = recipients.map { key in
            let supportsAEAD = (try? key.supportsAEAD) ?? false
            return RecipientEncryptionCapability(
                address: "",
                supportsAEAD: supportsAEAD,
                supportsV6: supportsAEAD
            )
        }
        let decision = EncryptionEnvelopeResolver.decide(
            capabilities: capabilities,
            policy: envelopePolicy
        )
        if case let .refused(addresses) = decision {
            throw EnvelopePolicyRefusalError(failedAddresses: addresses)
        }
        let parameters = decision.encryptParameters ?? .legacy
        return try encodePGPMime(
            request,
            signer: signer,
            recipients: recipients,
            rnp: rnp,
            envelope: parameters
        )
    }

    /// Encodes a message in PGP/MIME form using a specific envelope.
    /// Used by callers that have already decided on the envelope (e.g.
    /// always-AEAD for a power user; legacy for backward compat).
    ///
    /// Shares `parseMessageEntity`, `buildEncryptionPlaintext`, and
    /// `wrapEncryptedBody` with the base encoder so the MIME wrapping,
    /// protected-headers handling, and signing steps cannot drift between
    /// the two paths. Only the `rnp.encrypt` call differs (custom AEAD
    /// and PKESK version).
    func encodePGPMime(
        _ request: EncodingRequest,
        signer: RnpKey?,
        recipients: [RnpKey],
        rnp: Rnp,
        envelope: EncryptEnvelopeParameters
    ) throws -> EncodedMessage {
        guard request.encrypt else {
            return try encodePGPMime(request, signer: signer, recipients: recipients, rnp: rnp)
        }

        let parsed = parseMessageEntity(request.message)
        let plaintext = try buildEncryptionPlaintext(
            entity: parsed.entity,
            topHeaders: parsed.topHeaders,
            request: request,
            signer: signer,
            rnp: rnp,
            eol: parsed.eol
        )
        let ciphertext = try rnp.encrypt(
            plaintext.data,
            for: recipients,
            aead: envelope.aead,
            pkeskVersion: envelope.pkeskVersion,
            armored: true
        )
        let (body, topLevelType) = wrapEncryptedBody(
            ciphertext: ciphertext,
            boundary: parsed.boundary,
            hasProtected: plaintext.hasProtected,
            eol: parsed.eol
        )
        return EncodedMessage(
            rawData: serialize(headers: plaintext.topHeaders + [topLevelType], body: body, eol: parsed.eol),
            isSigned: request.sign,
            isEncrypted: true
        )
    }
}

/// Error thrown when `forceAEAD` policy cannot be satisfied because one
/// or more recipients lack AEAD support.
public struct EnvelopePolicyRefusalError: Error, Equatable {
    public let failedAddresses: [String]
    public init(failedAddresses: [String]) {
        self.failedAddresses = failedAddresses
    }
}

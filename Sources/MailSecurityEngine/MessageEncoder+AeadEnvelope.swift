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
    /// The base encoder is called first; its encrypt output is then
    /// replaced by a new encrypt using the chosen envelope. The MIME
    /// wrapping, protected headers, and signing are unchanged.
    func encodePGPMime(
        _ request: EncodingRequest,
        signer: RnpKey?,
        recipients: [RnpKey],
        rnp: Rnp,
        envelope: EncryptEnvelopeParameters
    ) throws -> EncodedMessage {
        let legacyEncoded = try encodePGPMime(request, signer: signer, recipients: recipients, rnp: rnp)

        guard request.encrypt else { return legacyEncoded }

        // Re-derive the plaintext the base encoder produced by
        // replaying the same header splitting + signing steps.
        let parsed = MimeMessage.parse(request.message)
        var contentHeaders: [MimeMessage.Header] = []
        for header in parsed.headers where header.name.lowercased().hasPrefix("content-") {
            contentHeaders.append(header)
        }
        if contentHeaders.isEmpty {
            contentHeaders = [MimeMessage.Header(
                name: "Content-Type",
                value: "text/plain; charset=\"utf-8\""
            )]
        }
        var entity = Data()
        let eol: EndOfLine = .crlf
        for header in contentHeaders {
            entity.append(Data("\(header.name): \(header.value)".utf8))
            entity.append(eol.data)
        }
        entity.append(eol.data)
        entity.append(parsed.body)
        var plaintext = entity
        if request.sign, let signer {
            plaintext = try rnp.sign(plaintext, with: signer, armored: false)
        }
        let ciphertext = try rnp.encrypt(
            plaintext,
            for: recipients,
            aead: envelope.aead,
            pkeskVersion: envelope.pkeskVersion,
            armored: true
        )

        // Splice the new ciphertext into the encoded message in place
        // of the original ASCII-armored PGP MESSAGE block.
        var data = legacyEncoded.rawData
        let beginMarker = Data("-----BEGIN PGP MESSAGE-----".utf8)
        let endMarker = Data("-----END PGP MESSAGE-----".utf8)
        guard let beginRange = data.range(of: beginMarker),
              let endRange = data.range(of: endMarker, in: beginRange.upperBound..<data.endIndex)
        else {
            return legacyEncoded
        }
        var replaceEnd = endRange.upperBound
        if replaceEnd + 1 < data.count, data[replaceEnd] == 0x0A {
            replaceEnd += 1
        } else if replaceEnd + 2 <= data.count,
                  data[replaceEnd] == 0x0D,
                  data[replaceEnd + 1] == 0x0A {
            replaceEnd += 2
        }
        var result = Data()
        result.append(data.subdata(in: 0..<beginRange.lowerBound))
        result.append(ciphertext)
        result.append(Data("\r\n".utf8))
        result.append(data.subdata(in: replaceEnd..<data.count))
        data = result
        return EncodedMessage(
            rawData: data,
            isSigned: legacyEncoded.isSigned,
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

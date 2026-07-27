//
//  MessageEncoder+AutocryptEmit.swift
//  MailSecurityEngine
//
//  Additive entry point that augments `encodePGPMime` with Autocrypt
//  header emit. The base encoder is unchanged; callers that want
//  Autocrypt use the new entry point with an explicit policy.
//

import Autocrypt
import Foundation
import Rnp

extension MailSecurityEngine {
    /// Encodes a message in PGP/MIME form, attaching the Autocrypt
    /// header when the policy decides to. The header is built from the
    /// signer's key via `AutocryptHeaderBuilder.build(...)` and prepended
    /// to the outer envelope headers. The header is added to the outer
    /// message (NOT the protected headers) because Autocrypt is routing
    /// metadata that recipients' clients must see without decrypting.
    ///
    /// - Parameters:
    ///   - request: encode request (carries `sender`).
    ///   - signer: signing key (used for the Autocrypt keydata export).
    ///   - recipients: encryption recipient keys.
    ///   - rnp: engine Rnp context.
    ///   - autocryptPolicy: emit policy. `.never` produces identical
    ///     output to the base `encodePGPMime(...)` call.
    func encodePGPMime(
        _ request: EncodingRequest,
        signer: RnpKey?,
        recipients: [RnpKey],
        rnp: Rnp,
        autocryptPolicy: AutocryptEmitPolicy
    ) throws -> EncodedMessage {
        // First, run the base encoder. We cannot inject the header into
        // the running encode because the encoder owns `topHeaders`; the
        // cleanest OCP-respecting path is to encode first, then splice
        // the header into the produced bytes below the existing envelope
        // headers. (Autocrypt headers are positionally fine anywhere in
        // the outer header block.)
        var encoded = try encodePGPMime(request, signer: signer, recipients: recipients, rnp: rnp)

        let decision = autocryptPolicy.resolve(
            signerAddress: request.sender,
            isEncrypted: request.encrypt,
            isSigned: request.sign
        )
        guard case let .emit(preferEncrypt, address) = decision,
              let signer
        else {
            return encoded
        }

        let headerValue = try AutocryptHeaderBuilder.build(
            signerKey: signer,
            address: address,
            preferEncrypt: preferEncrypt,
            userID: request.sender
        )
        guard let headerValue else { return encoded }

        encoded.rawData = Self.spliceAutocryptHeader(
            into: encoded.rawData,
            headerValue: headerValue
        )
        return encoded
    }

    /// Splices an `Autocrypt:` header into the outer header block of an
    /// already-encoded RFC 822 message. The header is inserted
    /// immediately after the first envelope header (typically `From`),
    /// matching the placement Autocrypt level 1 suggests for visibility.
    ///
    /// Returns the input unchanged when no header boundary is found
    /// (defensive — should not happen for valid encode output).
    static func spliceAutocryptHeader(
        into data: Data,
        headerValue: String
    ) -> Data {
        // Locate the first CRLF (end of the first header line) and
        // insert our header right after it. This is byte-exact and does
        // not re-parse the whole message.
        let crlf = Data([0x0D, 0x0A])
        guard let firstCRLFRange = data.range(of: crlf) else {
            return data
        }
        let insertAt = firstCRLFRange.upperBound
        let headerLine = Data("Autocrypt: \(headerValue)\r\n".utf8)
        var result = Data()
        result.append(data.subdata(in: 0..<insertAt))
        result.append(headerLine)
        result.append(data.subdata(in: insertAt..<data.count))
        return result
    }
}

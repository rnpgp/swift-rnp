//
//  MessageEncoder.swift
//  swift-rnp
//
//  Encoding side of the mail security engine: wraps an outgoing RFC 822
//  message into PGP/MIME (RFC 3156) or inline-PGP form.
//

import Foundation
import Rnp

/// Constants for protected headers ("Memory Hole"): sensitive envelope
/// headers travel inside the encrypted payload of a PGP/MIME message, as
/// produced by K-9 Mail and Thunderbird (`protected-headers="v1"`).
enum ProtectedHeaders {
    /// Envelope headers (lowercased) copied into the encrypted payload for
    /// authenticated display. Routing headers (From, To, Date, ...) stay at
    /// the outer level as well — the message list needs them — but the
    /// protected copies win when the message is displayed.
    static let names: Set<String> = [
        "subject", "from", "to", "cc", "date",
        "message-id", "references", "in-reply-to", "reply-to",
    ]

    /// Generic outer Subject used while the real one is encrypted.
    static let placeholderSubject = "Encrypted message"
}

extension MailSecurityEngine {
    /// Encodes a message in PGP/MIME form (RFC 3156 sections 4 and 5).
    ///
    /// The protected content is the original message's MIME entity: its
    /// Content-* headers and body are moved into the protected part, while
    /// envelope headers (From, To, Subject, ...) stay at the top level. For
    /// encrypted messages the sensitive envelope headers additionally move
    /// into the encrypted payload (protected-headers="v1", "Memory Hole")
    /// and the outer Subject is replaced by a generic placeholder. Signed
    /// data is CRLF-canonicalized as required by RFC 3156.
    func encodePGPMime(
        _ request: EncodingRequest,
        signer: RnpKey?,
        recipients: [RnpKey],
        rnp: Rnp
    ) throws -> EncodedMessage {
        let parsed = parseMessageEntity(request.message)

        var body = Data()
        let topLevelType: MimeMessage.Header
        var topHeaders = parsed.topHeaders
        if request.encrypt {
            let plaintext = try buildEncryptionPlaintext(
                entity: parsed.entity,
                topHeaders: topHeaders,
                request: request,
                signer: signer,
                rnp: rnp,
                eol: parsed.eol
            )
            topHeaders = plaintext.topHeaders
            let ciphertext = try rnp.encrypt(plaintext.data, for: recipients, armored: true)
            let (encryptedBody, mediaHeader) = wrapEncryptedBody(
                ciphertext: ciphertext,
                boundary: parsed.boundary,
                hasProtected: plaintext.hasProtected,
                eol: parsed.eol
            )
            body = encryptedBody
            topLevelType = mediaHeader
        } else if request.sign, let signer {
            let signedEntity = MimeMessage.crlfNormalized(parsed.entity)
            let signature = try rnp.signDetached(signedEntity, with: signer, armored: true)
            appendLine("--\(parsed.boundary)", to: &body, eol: parsed.eol)
            body.append(signedEntity)
            appendPartEndOfLine(&body, eol: parsed.eol)
            appendLine("--\(parsed.boundary)", to: &body, eol: parsed.eol)
            appendLine("Content-Type: application/pgp-signature; name=\"signature.asc\"", to: &body, eol: parsed.eol)
            appendLine("Content-Description: OpenPGP digital signature", to: &body, eol: parsed.eol)
            appendLine("Content-Disposition: attachment; filename=\"signature.asc\"", to: &body, eol: parsed.eol)
            appendLine("", to: &body, eol: parsed.eol)
            body.append(signature)
            appendPartEndOfLine(&body, eol: parsed.eol)
            appendLine("--\(parsed.boundary)--", to: &body, eol: parsed.eol)
            topLevelType = MimeMessage.Header(
                name: "Content-Type",
                value: "multipart/signed; micalg=\"pgp-sha256\"; protocol=\"application/pgp-signature\"; boundary=\"\(parsed.boundary)\""
            )
        } else {
            // Unreachable: encode() rejects requests with both flags off and
            // PGP/MIME encryption without a recipient list.
            preconditionFailure("PGP/MIME encode without sign or encrypt")
        }

        return EncodedMessage(
            rawData: serialize(headers: topHeaders + [topLevelType], body: body, eol: parsed.eol),
            isSigned: request.sign,
            isEncrypted: request.encrypt
        )
    }

    /// Encodes a message in inline-PGP form: the body text is replaced by an
    /// ASCII-armored OpenPGP message. Only single-part messages can be
    /// protected this way.
    func encodeInline(
        _ request: EncodingRequest,
        signer: RnpKey?,
        recipients: [RnpKey],
        rnp: Rnp
    ) throws -> EncodedMessage {
        let parsed = MimeMessage.parse(request.message)
        if let contentType = parsed.contentType, contentType.isMultipart {
            throw MailSecurityError.multipartNotSupportedForInline
        }

        // The protected payload is the decoded body text.
        var payload = parsed.decodedBody()
        if request.sign, let signer {
            payload = try rnp.sign(payload, with: signer, armored: !request.encrypt)
        }
        if request.encrypt {
            payload = try rnp.encrypt(payload, for: recipients, armored: true)
        }

        // The armored payload is 7bit-clean ASCII.
        var headers = parsed.headers
        if let index = headers.firstIndex(where: {
            $0.name.caseInsensitiveCompare("Content-Transfer-Encoding") == .orderedSame
        }) {
            headers[index] = MimeMessage.Header(name: "Content-Transfer-Encoding", value: "7bit")
        }
        return EncodedMessage(
            rawData: serialize(headers: headers, body: payload, eol: parsed.eol),
            isSigned: request.sign,
            isEncrypted: request.encrypt
        )
    }

    // MARK: - Building blocks

    /// Parsed-and-prepared MIME entity, ready to be either signed-only or
    /// fed to `buildEncryptionPlaintext` for encryption.
    struct ParsedMessageEntity {
        let topHeaders: [MimeMessage.Header]
        let entity: Data
        let boundary: String
        let eol: EndOfLine
    }

    /// Splits the raw RFC 822 message into top-level envelope headers
    /// (From/To/Subject/MIME-Version/etc.) and the MIME entity that will
    /// be protected (Content-* headers + body). Ensures a Content-Type
    /// and MIME-Version exist. Picks a boundary that does not collide
    /// with the entity. Shared by the base and AEAD encoder paths so
    /// they cannot drift on header-splitting rules.
    func parseMessageEntity(_ message: Data) -> ParsedMessageEntity {
        let parsed = MimeMessage.parse(message)
        let eol: EndOfLine = .crlf

        var topHeaders: [MimeMessage.Header] = []
        var contentHeaders: [MimeMessage.Header] = []
        for header in parsed.headers {
            if header.name.lowercased().hasPrefix("content-") {
                contentHeaders.append(header)
            } else {
                topHeaders.append(header)
            }
        }
        if contentHeaders.isEmpty {
            contentHeaders = [MimeMessage.Header(
                name: "Content-Type",
                value: "text/plain; charset=\"utf-8\""
            )]
        }
        if !topHeaders.contains(where: { $0.name.caseInsensitiveCompare("MIME-Version") == .orderedSame }) {
            topHeaders.append(MimeMessage.Header(name: "MIME-Version", value: "1.0"))
        }

        var entity = Data()
        for header in contentHeaders {
            entity.append(Data("\(header.name): \(header.value)".utf8))
            entity.append(eol.data)
        }
        entity.append(eol.data)
        entity.append(parsed.body)

        let boundary = makeBoundary(avoiding: entity)
        return ParsedMessageEntity(topHeaders: topHeaders, entity: entity, boundary: boundary, eol: eol)
    }

    /// The signed plaintext (and updated outer headers) that gets handed
    /// to `rnp.encrypt`. Shared by the base encoder and the AEAD overload
    /// so both produce byte-identical plaintext for the same input —
    /// previously the AEAD path re-derived this independently and could
    /// drift.
    struct EncryptionPlaintext {
        let data: Data
        let topHeaders: [MimeMessage.Header]
        let hasProtected: Bool
    }

    func buildEncryptionPlaintext(
        entity: Data,
        topHeaders: [MimeMessage.Header],
        request: EncodingRequest,
        signer: RnpKey?,
        rnp: Rnp,
        eol: EndOfLine
    ) throws -> EncryptionPlaintext {
        var topHeaders = topHeaders
        let protected = topHeaders.filter {
            ProtectedHeaders.names.contains($0.name.lowercased())
        }
        var plaintext = entity
        var hasProtected = false
        if !protected.isEmpty {
            hasProtected = true
            plaintext = protectedHeadersEntity(protected: protected, entity: entity, eol: eol)
            if let index = topHeaders.firstIndex(where: {
                $0.name.caseInsensitiveCompare("Subject") == .orderedSame
            }) {
                topHeaders[index] = MimeMessage.Header(
                    name: topHeaders[index].name,
                    value: ProtectedHeaders.placeholderSubject
                )
            }
        }
        if request.sign, let signer {
            plaintext = try rnp.sign(plaintext, with: signer, armored: false)
        }
        return EncryptionPlaintext(data: plaintext, topHeaders: topHeaders, hasProtected: hasProtected)
    }

    /// Wraps an ASCII-armored PGP ciphertext in the multipart/encrypted
    /// structure (RFC 3156 §4). The same wrapper is used by the base
    /// encoder and the AEAD overload — the only thing that differs
    /// between them is the ciphertext bytes.
    func wrapEncryptedBody(
        ciphertext: Data,
        boundary: String,
        hasProtected: Bool,
        eol: EndOfLine
    ) -> (body: Data, topLevelType: MimeMessage.Header) {
        var body = Data()
        appendLine("--\(boundary)", to: &body, eol: eol)
        appendLine("Content-Type: application/pgp-encrypted", to: &body, eol: eol)
        appendLine("", to: &body, eol: eol)
        appendLine("Version: 1", to: &body, eol: eol)
        appendLine("", to: &body, eol: eol)
        appendLine("--\(boundary)", to: &body, eol: eol)
        appendLine("Content-Type: application/octet-stream; name=\"encrypted.asc\"", to: &body, eol: eol)
        appendLine("Content-Description: OpenPGP encrypted message", to: &body, eol: eol)
        appendLine("Content-Disposition: inline; filename=\"encrypted.asc\"", to: &body, eol: eol)
        appendLine("", to: &body, eol: eol)
        body.append(ciphertext)
        appendPartEndOfLine(&body, eol: eol)
        appendLine("--\(boundary)--", to: &body, eol: eol)
        var mediaType = "multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"\(boundary)\""
        if hasProtected {
            mediaType += "; protected-headers=\"v1\""
        }
        return (body, MimeMessage.Header(name: "Content-Type", value: mediaType))
    }

    /// Wraps the MIME entity being encrypted together with the protected
    /// envelope headers, K-9/Thunderbird style: a `multipart/mixed` whose
    /// first part (`text/rfc822-headers`) carries the protected headers and
    /// whose second part is the original MIME entity. The whole structure is
    /// what gets signed and encrypted, so the protected headers are covered
    /// by the signature as well.
    func protectedHeadersEntity(
        protected: [MimeMessage.Header],
        entity: Data,
        eol: EndOfLine
    ) -> Data {
        let innerBoundary = makeBoundary(avoiding: entity)
        var payload = Data()
        appendLine(
            "Content-Type: multipart/mixed; boundary=\"\(innerBoundary)\"; protected-headers=\"v1\"",
            to: &payload,
            eol: eol
        )
        appendLine("", to: &payload, eol: eol)
        appendLine("--\(innerBoundary)", to: &payload, eol: eol)
        appendLine("Content-Type: text/rfc822-headers; protected-headers=\"v1\"", to: &payload, eol: eol)
        appendLine("Content-Disposition: inline", to: &payload, eol: eol)
        appendLine("", to: &payload, eol: eol)
        for header in protected {
            appendLine("\(header.name): \(header.value)", to: &payload, eol: eol)
        }
        // Blank line terminating the RFC 822 header block of the
        // text/rfc822-headers part, plus the EOL that belongs to the next
        // boundary delimiter (RFC 2046 5.1.1) — both are needed for the
        // part body to parse back as a well-formed header block.
        appendLine("", to: &payload, eol: eol)
        appendPartEndOfLine(&payload, eol: eol)
        appendLine("--\(innerBoundary)", to: &payload, eol: eol)
        payload.append(entity)
        appendPartEndOfLine(&payload, eol: eol)
        appendLine("--\(innerBoundary)--", to: &payload, eol: eol)
        return payload
    }

    /// Generates a multipart boundary that does not occur in the content.
    func makeBoundary(avoiding content: Data) -> String {
        var boundary: String
        repeat {
            boundary = "----rnp-boundary-\(UUID().uuidString)"
        } while content.range(of: Data(boundary.utf8)) != nil
        return boundary
    }

    func appendLine(_ line: String, to data: inout Data, eol: EndOfLine) {
        data.append(Data(line.utf8))
        data.append(eol.data)
    }

    /// Appends exactly one EOL after part content, ahead of a boundary
    /// delimiter. This is unconditional on purpose: the EOL preceding a
    /// delimiter belongs to the delimiter (RFC 2046 5.1.1), so content that
    /// itself ends with an EOL must be followed by two. Skipping the append
    /// would corrupt byte-exact part extraction (and signature
    /// verification) for such content.
    func appendPartEndOfLine(_ data: inout Data, eol: EndOfLine) {
        data.append(eol.data)
    }
}

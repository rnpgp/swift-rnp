//
//  MessageDecoder.swift
//  swift-rnp
//
//  Decoding side of the mail security engine: detects OpenPGP content in an
//  incoming RFC 822 message (PGP/MIME or inline), decrypts and verifies it,
//  and unwraps it back into a plain message for Mail to display.
//

import Foundation
import Rnp

extension MailSecurityEngine {
    /// Accumulated security outcome of a decode pass.
    struct DecodeOutcome {
        var processedAny = false
        var isEncrypted = false
        var signers: [RnpSignatureInfo] = []
        var signingError: Error?
        var encryptionError: Error?
        /// Typed decryption failure produced by the failure classifier.
        /// `nil` on success paths. Set only when `encryptionError` is
        /// also set; consumes the librnp error string and the packet
        /// dump, if available.
        var decryptionFailure: DecryptionFailure?
        /// Attachments the decoder found encrypted (PGP/MIME part or
        /// `.pgp`/`.gpg`/`.asc` filename) and successfully decrypted.
        /// Surfaced through `SecurityInformation.decryptedAttachments`.
        var decryptedAttachments: [DecryptedAttachment] = []
    }

    /// Entry point running under the key manager lock; see `decode(_:)`.
    func decodeUnlocked(_ message: Data, rnp: Rnp) throws -> DecodedMessage? {
        let parsed = MimeMessage.parse(message)
        let contentType = parsed.contentType
        let mediaType = (contentType?.type ?? "", contentType?.subtype ?? "")
        let pgpProtocol = contentType?.parameters["protocol"] ?? ""

        switch (mediaType, pgpProtocol) {
        case (("multipart", "signed"), "application/pgp-signature"):
            return try decodePGPMimeSigned(parsed, rnp: rnp)
        case (("multipart", "encrypted"), "application/pgp-encrypted"):
            return try decodePGPMimeEncrypted(parsed, rnp: rnp)
        case (("multipart", _), _):
            return try decodeInlineMultipart(parsed, rnp: rnp)
        default:
            return try decodeInlineSingle(parsed, rnp: rnp)
        }
    }

    // MARK: - PGP/MIME

    /// Decodes a multipart/signed message (RFC 3156 section 5): verifies the
    /// detached signature in the second part against the exact bytes of the
    /// first part, then unwraps the message for display.
    private func decodePGPMimeSigned(_ parsed: MimeMessage, rnp: Rnp) throws -> DecodedMessage? {
        guard let rawParts = parsed.rawPartEntities, rawParts.count >= 2,
              let parts = parsed.parts, parts.count >= 2
        else {
            throw MailSecurityError.malformedMessage(
                "multipart/signed with fewer than two parts"
            )
        }
        let signedData = MimeMessage.crlfNormalized(rawParts[0])
        let signature = parts[1].decodedBody()
        let verification = try rnp.verifyDetachedDetailed(signature: signature, data: signedData)

        let signers = signerInfos(verification.signatures, rnp: rnp)
        let error = signingError(for: signers)

        // Unwrap: drop the multipart wrapping, promote the signed entity's
        // Content-* headers to the top level.
        let inner = parts[0]
        var headers = nonContentHeaders(of: parsed)
        headers.append(contentsOf: inner.headers)
        let data = serialize(headers: headers, body: inner.body, eol: parsed.eol)
        return DecodedMessage(
            data: data,
            security: SecurityInformation(
                isEncrypted: false,
                signers: signers,
                signingError: error,
                encryptionError: nil
            )
        )
    }

    /// Decodes a multipart/encrypted message (RFC 3156 section 4): decrypts
    /// the second part (also verifying nested signatures), then unwraps the
    /// recovered MIME entity for display.
    private func decodePGPMimeEncrypted(_ parsed: MimeMessage, rnp: Rnp) throws -> DecodedMessage? {
        guard let parts = parsed.parts, parts.count >= 2 else {
            throw MailSecurityError.malformedMessage(
                "multipart/encrypted with fewer than two parts"
            )
        }
        let ciphertext = parts[1].decodedBody()
        let (decrypted, outcome) = processOpenPGPBlob(ciphertext, rnp: rnp)
        guard outcome.processedAny else {
            // Decryption failed (wrong passphrase, missing key, tampered
            // integrity protection): let Mail show the original message with
            // the error reported in the security banner.
            return DecodedMessage(
                data: nil,
                security: SecurityInformation(
                    isEncrypted: true,
                    signers: [],
                    signingError: nil,
                    encryptionError: outcome.encryptionError
                        ?? MailSecurityError.malformedMessage("undecryptable content")
                )
            )
        }

        let signers = signerInfos(outcome.signers, rnp: rnp)
        let security = SecurityInformation(
            isEncrypted: true,
            signers: signers,
            signingError: signingError(for: signers),
            encryptionError: nil
        )
        // Protected headers ("Memory Hole", protected-headers="v1"): the real
        // envelope headers travel inside the encrypted payload and win over
        // the outer (placeholder) ones for display.
        if parsed.contentType?.parameters["protected-headers"]?.lowercased() == "v1",
           let payload = decrypted,
           let extraction = extractProtectedHeaders(from: payload, eol: parsed.eol)
        {
            let headers = mergingProtectedHeaders(extraction.headers, into: nonContentHeaders(of: parsed))
            let data = serialize(
                headers: headers + extraction.contentHeaders,
                body: extraction.body,
                eol: parsed.eol
            )
            return DecodedMessage(data: data, security: security)
        }

        // The decrypted entity carries its own Content-* headers; splicing
        // it after the envelope headers restores the original message.
        let data = serialize(
            headers: nonContentHeaders(of: parsed),
            body: decrypted ?? Data(),
            eol: parsed.eol
        )
        return DecodedMessage(data: data, security: security)
    }

    /// Result of lifting protected headers out of a decrypted payload.
    private struct ProtectedHeaderExtraction {
        /// Envelope headers recovered from the encrypted payload.
        var headers: [MimeMessage.Header]
        /// Content-* headers of the recovered MIME entity.
        var contentHeaders: [MimeMessage.Header]
        /// Body of the recovered MIME entity.
        var body: Data
    }

    /// Recovers the protected envelope headers and the original MIME entity
    /// from a decrypted payload carrying protected headers.
    ///
    /// Two layouts are recognized: the K-9 Mail style, a multipart whose
    /// first part is `text/rfc822-headers` holding the protected header
    /// block (also what `encodePGPMime` produces), and the Thunderbird
    /// style, where the payload itself is a full RFC 822 message whose
    /// non-Content-* headers are the protected ones. Returns `nil` when the
    /// payload has no recoverable protected headers.
    private func extractProtectedHeaders(
        from payload: Data,
        eol: EndOfLine
    ) -> ProtectedHeaderExtraction? {
        let inner = MimeMessage.parse(payload)

        // K-9 style: multipart with a leading text/rfc822-headers part.
        if let parts = inner.parts, let rawParts = inner.rawPartEntities,
           parts.count >= 2,
           let first = parts.first,
           first.contentType?.type == "text",
           first.contentType?.subtype == "rfc822-headers"
        {
            let protected = MimeMessage.parse(first.decodedBody()).headers
            guard !protected.isEmpty else {
                return nil
            }
            if parts.count == 2 {
                let content = parts[1]
                return ProtectedHeaderExtraction(
                    headers: protected,
                    contentHeaders: content.headers,
                    body: content.body
                )
            }
            // More than one content part: rebuild a multipart/mixed entity
            // from the remaining raw parts.
            guard let boundary = inner.contentType?.boundary else {
                return nil
            }
            var body = Data()
            for rawPart in rawParts.dropFirst() {
                appendLine("--\(boundary)", to: &body, eol: eol)
                body.append(rawPart)
                appendPartEndOfLine(&body, eol: eol)
            }
            appendLine("--\(boundary)--", to: &body, eol: eol)
            return ProtectedHeaderExtraction(
                headers: protected,
                contentHeaders: [MimeMessage.Header(
                    name: "Content-Type",
                    value: "multipart/mixed; boundary=\"\(boundary)\""
                )],
                body: body
            )
        }

        // Thunderbird style: the payload itself carries the protected
        // headers ahead of its Content-* headers.
        let protected = inner.headers.filter { !$0.name.lowercased().hasPrefix("content-") }
        guard !protected.isEmpty else {
            return nil
        }
        let contentHeaders = inner.headers.filter { $0.name.lowercased().hasPrefix("content-") }
        return ProtectedHeaderExtraction(
            headers: protected,
            contentHeaders: contentHeaders,
            body: inner.body
        )
    }

    /// Replaces envelope headers with their protected counterparts: a
    /// protected header wins over the same-named outer header, keeping the
    /// outer header's position; protected headers with no outer counterpart
    /// are inserted where the first replacement happened.
    private func mergingProtectedHeaders(
        _ protected: [MimeMessage.Header],
        into outer: [MimeMessage.Header]
    ) -> [MimeMessage.Header] {
        let protectedNames = Set(protected.map { $0.name.lowercased() })
        var headers: [MimeMessage.Header] = []
        var inserted = false
        for header in outer {
            if protectedNames.contains(header.name.lowercased()) {
                if !inserted {
                    headers.append(contentsOf: protected)
                    inserted = true
                }
            } else {
                headers.append(header)
            }
        }
        if !inserted {
            headers.append(contentsOf: protected)
        }
        return headers
    }

    // MARK: - Inline PGP

    /// Decodes a single-part message whose body carries inline OpenPGP
    /// armor. Returns `nil` when the body has no armor blocks.
    private func decodeInlineSingle(_ parsed: MimeMessage, rnp: Rnp) throws -> DecodedMessage? {
        let body = parsed.decodedBody()
        var outcome = DecodeOutcome()
        guard let newBody = processArmorBlocks(in: body, outcome: &outcome, rnp: rnp) else {
            return nil
        }
        var headers = parsed.headers
        replaceTransferEncoding(in: &headers, with: "8bit")
        return DecodedMessage(
            data: serialize(headers: headers, body: newBody, eol: parsed.eol),
            security: securityInformation(for: outcome, rnp: rnp)
        )
    }

    /// Decodes a multipart message that is not itself PGP/MIME by scanning
    /// leaf parts for inline armor. Returns `nil` when nothing is found.
    private func decodeInlineMultipart(_ parsed: MimeMessage, rnp: Rnp) throws -> DecodedMessage? {
        var outcome = DecodeOutcome()
        guard let newBody = processEntityBody(parsed, outcome: &outcome, rnp: rnp) else {
            return nil
        }
        return DecodedMessage(
            data: serialize(headers: parsed.headers, body: newBody, eol: parsed.eol),
            security: securityInformation(for: outcome, rnp: rnp)
        )
    }

    /// Recursively processes a multipart body, replacing leaf parts that
    /// carried armor. Returns the rebuilt body, or `nil` when no leaf
    /// changed.
    private func processEntityBody(
        _ entity: MimeMessage,
        outcome: inout DecodeOutcome,
        rnp: Rnp
    ) -> Data? {
        guard let parts = entity.parts, let rawParts = entity.rawPartEntities,
              let boundary = entity.contentType?.boundary
        else {
            return nil
        }
        var changed = false
        var newParts: [Data] = []
        for (part, rawPart) in zip(parts, rawParts) {
            if part.parts != nil {
                // Nested multipart: rebuild it and re-wrap with its headers.
                if let rebuilt = processEntityBody(part, outcome: &outcome, rnp: rnp) {
                    newParts.append(serialize(headers: part.headers, body: rebuilt, eol: part.eol))
                    changed = true
                } else {
                    newParts.append(rawPart)
                }
            } else {
                let body = part.decodedBody()
                // First: is this an encrypted attachment? Try decrypting
                // before falling through to inline-armor scanning.
                if let rebuilt = processEncryptedAttachment(
                    part: part,
                    body: body,
                    rawPart: rawPart,
                    outcome: &outcome,
                    rnp: rnp
                ) {
                    newParts.append(rebuilt)
                    changed = true
                    continue
                }
                if let newBody = processArmorBlocks(in: body, outcome: &outcome, rnp: rnp) {
                    var headers = part.headers
                    replaceTransferEncoding(in: &headers, with: "8bit")
                    newParts.append(serialize(headers: headers, body: newBody, eol: part.eol))
                    changed = true
                } else {
                    newParts.append(rawPart)
                }
            }
        }
        guard changed else {
            return nil
        }
        var body = Data()
        for part in newParts {
            appendLine("--\(boundary)", to: &body, eol: entity.eol)
            body.append(part)
            appendPartEndOfLine(&body, eol: entity.eol)
        }
        appendLine("--\(boundary)--", to: &body, eol: entity.eol)
        return body
    }

    // MARK: - Armor block processing

    /// Finds and processes OpenPGP armor blocks in `body`. Returns the body
    /// with processed blocks replaced by their payload, or `nil` when no
    /// block produced a security outcome.
    private func processArmorBlocks(
        in body: Data,
        outcome: inout DecodeOutcome,
        rnp: Rnp
    ) -> Data? {
        let blocks = armorBlocks(in: body)
        guard !blocks.isEmpty else {
            return nil
        }
        var result = body
        var foundAny = false
        // Replace from the end so earlier ranges stay valid.
        for block in blocks.reversed() {
            let (payload, blockOutcome) = processOpenPGPBlob(block.data, rnp: rnp)
            guard blockOutcome.processedAny else {
                continue
            }
            foundAny = true
            outcome.processedAny = true
            outcome.isEncrypted = outcome.isEncrypted || blockOutcome.isEncrypted
            outcome.signers.append(contentsOf: blockOutcome.signers)
            outcome.signingError = outcome.signingError ?? blockOutcome.signingError
            outcome.encryptionError = outcome.encryptionError ?? blockOutcome.encryptionError
            if let payload {
                result.replaceSubrange(block.range, with: payload)
            }
        }
        return foundAny ? result : nil
    }

    /// A located ASCII armor block.
    private struct ArmorBlock {
        let range: Range<Int>
        let data: Data
    }

    /// Locates "BEGIN PGP MESSAGE"/"BEGIN PGP SIGNED MESSAGE" armor blocks.
    private func armorBlocks(in body: Data) -> [ArmorBlock] {
        var blocks: [ArmorBlock] = []
        let markers: [(begin: Data, end: Data)] = [
            (Data("-----BEGIN PGP MESSAGE-----".utf8), Data("-----END PGP MESSAGE-----".utf8)),
            (
                Data("-----BEGIN PGP SIGNED MESSAGE-----".utf8),
                Data("-----END PGP SIGNATURE-----".utf8)
            ),
        ]
        for marker in markers {
            var searchStart = body.startIndex
            while let begin = body.range(of: marker.begin, in: searchStart ..< body.endIndex),
                  let end = body.range(of: marker.end, in: begin.upperBound ..< body.endIndex)
            {
                // Include the END line's trailing newline when present.
                var blockEnd = end.upperBound
                if body[blockEnd...].starts(with: Data("\r\n".utf8)) {
                    blockEnd += 2
                } else if blockEnd < body.endIndex, body[blockEnd] == 0x0A {
                    blockEnd += 1
                }
                blocks.append(ArmorBlock(
                    range: begin.lowerBound ..< blockEnd,
                    data: Data(body[begin.lowerBound ..< blockEnd])
                ))
                searchStart = blockEnd
            }
        }
        return blocks.sorted { $0.range.lowerBound < $1.range.lowerBound }
    }

    // MARK: - OpenPGP blob processing

    /// Processes one OpenPGP blob (armored or binary): decrypts it when
    /// encrypted and verifies any embedded or cleartext signatures.
    ///
    /// `verifyDetailed` drives both decryption and signature verification in
    /// librnp, so sign+encrypt is handled in one pass; when librnp reports
    /// no signatures but the payload is itself OpenPGP data (implementations
    /// that do not verify nested signatures), one nested pass is attempted.
    ///
    /// On the failure path, the outcome carries a typed
    /// `DecryptionFailure` derived from a packet-dump inspection of the
    /// blob, so the Mail banner can offer the right one-click action.
    private func processOpenPGPBlob(
        _ blob: Data,
        rnp: Rnp
    ) -> (payload: Data?, outcome: DecodeOutcome) {
        var outcome = DecodeOutcome()
        let verification: RnpVerification
        do {
            verification = try rnp.verifyDetailed(blob)
        } catch {
            // Not processable: undecryptable (wrong passphrase, missing key,
            // broken integrity) or not OpenPGP data at all. Classify the
            // failure so the banner can offer a recovery action.
            outcome.encryptionError = error
            outcome.decryptionFailure = classifyFailure(error: error, blob: blob, rnp: rnp)
            return (nil, outcome)
        }

        var payload = verification.payload
        outcome.signers = verification.signatures
        outcome.isEncrypted = verification.encryption != nil

        if verification.signatures.isEmpty, let data = payload, !data.isEmpty,
           let nested = try? rnp.verifyDetailed(data), !nested.signatures.isEmpty
        {
            payload = nested.payload
            outcome.signers = nested.signatures
        }

        let meaningful = outcome.isEncrypted || !outcome.signers.isEmpty
        outcome.processedAny = meaningful
        return meaningful ? (payload, outcome) : (nil, outcome)
    }

    /// Builds a typed `DecryptionFailure` from a librnp error and a packet
    /// dump of the blob. Best-effort: if dumping also fails (e.g., the
    /// blob is not valid OpenPGP data), the classifier falls back to
    /// `.unknown` or `.malformedArmor`.
    private func classifyFailure(error: Error, blob: Data, rnp: Rnp) -> DecryptionFailure {
        let message = (error as? LocalizedError)?.errorDescription ?? "\(error)"
        let dump: PacketDump?
        if let json = try? rnp.dumpPacketsAsJSON(blob) {
            dump = PacketDump.parse(json: json)
        } else {
            dump = nil
        }
        return DecryptionFailureClassifier.classify(
            librnpError: message,
            dump: dump,
            context: .noOp
        )
    }

    // MARK: - Encrypted attachments

    /// If `part` is an encrypted attachment (Content-Disposition: attachment
    /// with a `.pgp`/`.gpg`/`.asc` filename, or Content-Type
    /// `application/pgp-encrypted` / `application/pgp`), attempt decryption
    /// and return the rebuilt part for splicing into the multipart body.
    /// On success, appends to `outcome.decryptedAttachments`. Returns `nil`
    /// when the part isn't an encrypted attachment or decryption fails —
    /// the caller falls through to inline-armor scanning in the former case
    /// and surfaces `encryptionError` in the latter.
    private func processEncryptedAttachment(
        part: MimeMessage,
        body: Data,
        rawPart: Data,
        outcome: inout DecodeOutcome,
        rnp: Rnp
    ) -> Data? {
        guard let filename = attachmentFilename(part) else { return nil }
        guard looksLikeEncryptedAttachment(filename: filename, contentType: part.contentType) else {
            return nil
        }
        let (decrypted, blockOutcome) = processOpenPGPBlob(body, rnp: rnp)
        guard blockOutcome.processedAny, let decrypted else {
            if let error = blockOutcome.encryptionError {
                outcome.encryptionError = outcome.encryptionError ?? error
            }
            return nil
        }
        outcome.processedAny = true
        outcome.isEncrypted = true
        outcome.signers.append(contentsOf: blockOutcome.signers)
        outcome.signingError = outcome.signingError ?? blockOutcome.signingError

        let suggested = suggestDecryptedFilename(from: filename)
        let mime = sniffMimeType(for: suggested)
        outcome.decryptedAttachments.append(DecryptedAttachment(
            originalFilename: filename,
            suggestedFilename: suggested,
            data: decrypted,
            mimeType: mime
        ))

        // Rebuild the part with the decrypted body + adjusted headers.
        var headers = part.headers
        replaceFilename(in: &headers, with: suggested)
        replaceTransferEncoding(in: &headers, with: "base64")
        replaceContentType(in: &headers, with: mime, filename: suggested)
        let encodedBody = Data(decrypted.base64EncodedString().utf8)
        return serialize(headers: headers, body: encodedBody, eol: part.eol)
    }

    /// Returns the attachment filename declared in Content-Disposition
    /// (preferred) or Content-Type name= parameter.
    private func attachmentFilename(_ part: MimeMessage) -> String? {
        for header in part.headers where header.name.lowercased() == "content-disposition" {
            // filename="..." or filename=...
            if let range = header.value.range(of: #"filename\s*=\s*"?([^";]+)"?#, options: .regularExpression) {
                let raw = header.value[range]
                if let eq = raw.firstIndex(of: "=") {
                    var value = String(raw[raw.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                    value = value.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                    return value.isEmpty ? nil : value
                }
            }
        }
        if let ct = part.contentType, let name = ct.parameters["name"], !name.isEmpty {
            return name
        }
        return nil
    }

    /// True when the filename extension or declared MIME type suggests an
    /// encrypted attachment the decoder should attempt to decrypt.
    private func looksLikeEncryptedAttachment(filename: String, contentType: MimeMessage.ContentType?) -> Bool {
        let lower = filename.lowercased()
        if lower.hasSuffix(".pgp") || lower.hasSuffix(".gpg") || lower.hasSuffix(".asc") {
            return true
        }
        if let ct = contentType {
            let mediaType = "\(ct.type)/\(ct.subtype)".lowercased()
            if mediaType == "application/pgp-encrypted" || mediaType == "application/pgp" {
                return true
            }
        }
        return false
    }

    /// Strips PGP-specific extensions from `filename` to suggest the
    /// decrypted filename.
    private func suggestDecryptedFilename(from filename: String) -> String {
        let lower = filename.lowercased()
        for ext in [".pgp", ".gpg", ".asc"] {
            if lower.hasSuffix(ext) {
                return String(filename.dropLast(ext.count))
            }
        }
        return filename
    }

    /// Sniffs a MIME type from the decrypted file extension, falling back
    /// to `application/octet-stream`.
    private func sniffMimeType(for filename: String) -> String {
        let ext = (filename as NSString).pathExtension.lowercased()
        switch ext {
        case "pdf": return "application/pdf"
        case "txt": return "text/plain"
        case "json": return "application/json"
        case "png": return "image/png"
        case "jpg", "jpeg": return "image/jpeg"
        case "gif": return "image/gif"
        case "zip": return "application/zip"
        case "doc": return "application/msword"
        case "docx": return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        case "xls": return "application/vnd.ms-excel"
        case "xlsx": return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        default: return "application/octet-stream"
        }
    }

    private func replaceFilename(in headers: inout [MimeMessage.Header], with newFilename: String) {
        for i in headers.indices where headers[i].name.lowercased() == "content-disposition" {
            let regex = #"filename\s*=\s*"?[^";]+"?"#
            if let _ = headers[i].value.range(of: regex, options: .regularExpression) {
                headers[i].value = headers[i].value.replacingOccurrences(
                    of: regex,
                    with: "filename=\"\(newFilename)\"",
                    options: .regularExpression
                )
                return
            }
        }
    }

    private func replaceContentType(in headers: inout [MimeMessage.Header], with mimeType: String, filename: String) {
        for i in headers.indices where headers[i].name.lowercased() == "content-type" {
            headers[i].value = "\(mimeType); name=\"\(filename)\""
            return
        }
    }

    // MARK: - Small helpers

    /// Builds security information from a decode outcome, resolving signer
    /// user IDs against the keyring.
    private func securityInformation(for outcome: DecodeOutcome, rnp: Rnp) -> SecurityInformation {
        let signers = signerInfos(outcome.signers, rnp: rnp)
        return SecurityInformation(
            isEncrypted: outcome.isEncrypted,
            signers: signers,
            signingError: outcome.signingError ?? signingError(for: signers),
            encryptionError: outcome.encryptionError,
            decryptedAttachments: outcome.decryptedAttachments
        )
    }

    /// Envelope headers of an entity: everything except Content-* headers.
    private func nonContentHeaders(of entity: MimeMessage) -> [MimeMessage.Header] {
        entity.headers.filter { !$0.name.lowercased().hasPrefix("content-") }
    }

    /// Replaces (or appends) the Content-Transfer-Encoding header.
    private func replaceTransferEncoding(
        in headers: inout [MimeMessage.Header],
        with value: String
    ) {
        if let index = headers.firstIndex(where: {
            $0.name.caseInsensitiveCompare("Content-Transfer-Encoding") == .orderedSame
        }) {
            headers[index] = MimeMessage.Header(name: headers[index].name, value: value)
        }
    }
}

//
//  MimeMessage.swift
//  swift-rnp
//
//  Minimal RFC 822 / RFC 2045 MIME parser for the mail security engine.
//
//  The parser is byte-exact: multipart parts keep their raw bytes (headers
//  and body) untouched, which is required for OpenPGP/MIME detached
//  signature verification (RFC 3156) where the signed data is the exact
//  first part of a multipart/signed entity.
//

import Foundation

/// Line ending style of a message.
enum EndOfLine: String {
    case crlf = "\r\n"
    case lf = "\n"

    var data: Data { Data(rawValue.utf8) }
}

/// A parsed MIME entity: headers plus raw body, with multipart entities
/// recursively decomposed into parts.
struct MimeMessage {
    struct Header: Equatable {
        var name: String
        var value: String
    }

    /// Parsed `Content-Type` header value.
    struct ContentType: Equatable {
        var type: String
        var subtype: String
        var parameters: [String: String]

        var mediaType: String { "\(type)/\(subtype)" }
        var boundary: String? { parameters["boundary"] }
        var isMultipart: Bool { type == "multipart" }
    }

    /// Entity headers, in original order and casing, unfolded.
    private(set) var headers: [Header]
    /// Raw body bytes (everything after the header/body separator).
    private(set) var body: Data
    /// Line ending detected while parsing (CRLF preferred).
    private(set) var eol: EndOfLine

    /// Sub-entities when the entity is multipart; `nil` otherwise.
    private(set) var parts: [MimeMessage]?
    /// Raw bytes of each sub-entity (headers and body), parallel to `parts`.
    /// Needed for byte-exact signature verification.
    private(set) var rawPartEntities: [Data]?

    init(headers: [Header], body: Data, eol: EndOfLine = .crlf) {
        self.headers = headers
        self.body = body
        self.eol = eol
        parts = nil
        rawPartEntities = nil
    }

    // MARK: - Header access

    func header(_ name: String) -> String? {
        headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
    }

    var contentType: ContentType? {
        header("Content-Type").map(MimeMessage.parseContentType)
    }

    /// Content-Transfer-Encoding, lowercased; "7bit" when absent.
    var contentTransferEncoding: String {
        header("Content-Transfer-Encoding")?
            .trimmingCharacters(in: .whitespaces)
            .lowercased() ?? "7bit"
    }

    // MARK: - Parsing

    /// Parses a MIME entity from raw bytes, recursing into multipart bodies.
    static func parse(_ data: Data) -> MimeMessage {
        var message = parseSingle(data)
        message.parsePartsIfMultipart()
        return message
    }

    /// Parses headers and body without multipart decomposition.
    private static func parseSingle(_ data: Data) -> MimeMessage {
        let eol = detectEndOfLine(data)
        guard let (headerRange, bodyStart) = headerBlockRange(in: data) else {
            return MimeMessage(headers: [], body: data, eol: eol)
        }
        let headers = parseHeaders(data[headerRange], eol: eol)
        return MimeMessage(headers: headers, body: data[bodyStart...], eol: eol)
    }

    private static func detectEndOfLine(_ data: Data) -> EndOfLine {
        data.contains(0x0D) ? .crlf : .lf
    }

    /// Locates the header block and the body start in a MIME entity.
    private static func headerBlockRange(in data: Data) -> (Range<Int>, Int)? {
        if let range = data.range(of: Data([0x0D, 0x0A, 0x0D, 0x0A])) {
            return (data.startIndex ..< range.lowerBound, range.upperBound)
        }
        if let range = data.range(of: Data([0x0A, 0x0A])) {
            return (data.startIndex ..< range.lowerBound, range.upperBound)
        }
        return nil
    }

    /// Parses a raw header block into unfolded headers.
    private static func parseHeaders(_ block: Data.SubSequence, eol: EndOfLine) -> [Header] {
        guard let text = String(data: block, encoding: .utf8) else {
            return []
        }
        var headers: [Header] = []
        for line in text.components(separatedBy: eol.rawValue) {
            guard !line.isEmpty else {
                continue
            }
            // Continuation lines (folded headers) start with whitespace.
            if line.first == " " || line.first == "\t", !headers.isEmpty {
                headers[headers.count - 1].value += " " + line.trimmingCharacters(in: .whitespaces)
                continue
            }
            guard let colon = line.firstIndex(of: ":") else {
                continue
            }
            let name = String(line[..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            headers.append(Header(name: name, value: value))
        }
        return headers
    }

    /// Parses a `Content-Type` header value, honoring quoted parameters.
    static func parseContentType(_ value: String) -> ContentType {
        let tokens = splitParameters(value)
        let mediaType = tokens.first?.lowercased() ?? ""
        let components = mediaType.split(separator: "/", maxSplits: 1).map(String.init)
        var parameters: [String: String] = [:]
        for token in tokens.dropFirst() {
            guard let equals = token.firstIndex(of: "=") else {
                continue
            }
            let name = String(token[..<equals])
                .trimmingCharacters(in: .whitespaces)
                .lowercased()
            var tokenValue = String(token[token.index(after: equals)...])
                .trimmingCharacters(in: .whitespaces)
            if tokenValue.count >= 2, tokenValue.hasPrefix("\""), tokenValue.hasSuffix("\"") {
                tokenValue = String(tokenValue.dropFirst().dropLast())
                    .replacingOccurrences(of: "\\\"", with: "\"")
                    .replacingOccurrences(of: "\\\\", with: "\\")
            }
            parameters[name] = tokenValue
        }
        return ContentType(
            type: components.first ?? "",
            subtype: components.count > 1 ? components[1] : "",
            parameters: parameters
        )
    }

    /// Splits a header parameter list on `;` outside of quoted strings.
    private static func splitParameters(_ value: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var inQuotes = false
        var escaped = false
        for character in value {
            if escaped {
                current.append(character)
                escaped = false
                continue
            }
            switch character {
            case "\\" where inQuotes:
                current.append(character)
                escaped = true
            case "\"":
                current.append(character)
                inQuotes.toggle()
            case ";" where !inQuotes:
                tokens.append(current)
                current = ""
            default:
                current.append(character)
            }
        }
        tokens.append(current)
        return tokens.map { $0.trimmingCharacters(in: .whitespaces) }
    }

    // MARK: - Multipart decomposition

    /// Replaces the entity's body with a decomposition into sub-entities
    /// when the Content-Type is multipart and carries a boundary.
    private mutating func parsePartsIfMultipart() {
        guard let contentType, contentType.isMultipart, let boundary = contentType.boundary,
              !boundary.isEmpty
        else {
            return
        }
        let rawParts = MimeMessage.splitMultipartBody(body, boundary: boundary, eol: eol)
        rawPartEntities = rawParts
        parts = rawParts.map { part -> MimeMessage in
            var entity = MimeMessage.parseSingle(part)
            entity.eol = eol
            entity.parsePartsIfMultipart()
            return entity
        }
    }

    /// Splits a multipart body into raw part entities, preserving exact
    /// bytes. The preamble and epilogue are discarded.
    static func splitMultipartBody(_ body: Data, boundary: String, eol: EndOfLine) -> [Data] {
        struct DelimiterLine {
            /// Index of the "--boundary" match.
            let start: Int
            /// Index right after the delimiter line's trailing EOL (or EOF).
            let contentStart: Int
            let isClosing: Bool
        }

        let delimiter = Data("--".utf8) + Data(boundary.utf8)
        let eolData = eol.data

        // Locate all delimiter lines: positions where `--boundary` appears at
        // a line start. The CRLF immediately preceding a delimiter belongs to
        // the delimiter, not to the preceding part (RFC 2046 5.1.1).
        var lines: [DelimiterLine] = []
        var searchStart = body.startIndex
        while let match = body.range(of: delimiter, in: searchStart ..< body.endIndex) {
            defer { searchStart = match.upperBound }
            let atLineStart = match.lowerBound == body.startIndex
                || (match.lowerBound - body.startIndex >= eolData.count
                    && body[(match.lowerBound - eolData.count) ..< match.lowerBound]
                    .elementsEqual(eolData))
            guard atLineStart else {
                continue
            }
            var cursor = match.upperBound
            let isClosing = body[cursor...].starts(with: Data("--".utf8))
            if isClosing {
                cursor += 2
            }
            // Skip transport padding to the end of the delimiter line.
            while cursor < body.endIndex, body[cursor] == 0x20 || body[cursor] == 0x09 {
                cursor += 1
            }
            if body[cursor...].starts(with: eolData) {
                cursor += eolData.count
            } else {
                cursor = body.endIndex
            }
            lines.append(DelimiterLine(start: match.lowerBound, contentStart: cursor, isClosing: isClosing))
        }

        var parts: [Data] = []
        for (index, line) in lines.enumerated() {
            guard !line.isClosing else {
                break
            }
            let end = index + 1 < lines.count
                ? lines[index + 1].start - eolData.count
                : body.endIndex
            // Tolerate truncated messages with a missing closing delimiter.
            guard end >= line.contentStart else {
                continue
            }
            parts.append(Data(body[line.contentStart ..< end]))
        }
        return parts
    }

    // MARK: - Content-Transfer-Encoding

    /// Body bytes with Content-Transfer-Encoding applied (base64 and
    /// quoted-printable are decoded; other encodings pass through).
    func decodedBody() -> Data {
        switch contentTransferEncoding {
        case "base64":
            let stripped = body.filter { ![0x20, 0x09, 0x0D, 0x0A].contains($0) }
            return Data(base64Encoded: stripped) ?? body
        case "quoted-printable":
            return MimeMessage.decodeQuotedPrintable(body)
        default:
            return body
        }
    }

    static func decodeQuotedPrintable(_ data: Data) -> Data {
        var output = Data()
        output.reserveCapacity(data.count)
        var index = data.startIndex
        while index < data.endIndex {
            let byte = data[index]
            if byte == 0x3D { // '='
                let next = index + 1
                if next < data.endIndex {
                    // Soft line break: "=\r\n" or "=\n".
                    if data[next] == 0x0A {
                        index = next + 1
                        continue
                    }
                    if data[next] == 0x0D, next + 1 < data.endIndex, data[next + 1] == 0x0A {
                        index = next + 2
                        continue
                    }
                    // Hex octet "=XX".
                    if next + 1 < data.endIndex,
                       let high = hexValue(data[next]), let low = hexValue(data[next + 1])
                    {
                        output.append(high << 4 | low)
                        index = next + 2
                        continue
                    }
                }
                output.append(byte)
                index += 1
            } else {
                output.append(byte)
                index += 1
            }
        }
        return output
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30 ... 0x39: return byte - 0x30
        case 0x41 ... 0x46: return byte - 0x41 + 10
        case 0x61 ... 0x66: return byte - 0x61 + 10
        default: return nil
        }
    }

    // MARK: - Byte utilities

    /// Returns a copy with line endings normalized to CRLF. Idempotent.
    static func crlfNormalized(_ data: Data) -> Data {
        var output = Data()
        output.reserveCapacity(data.count)
        var index = data.startIndex
        while index < data.endIndex {
            let byte = data[index]
            if byte == 0x0A, index == data.startIndex || data[index - 1] != 0x0D {
                output.append(contentsOf: [0x0D, 0x0A])
            } else {
                output.append(byte)
            }
            index += 1
        }
        return output
    }
}

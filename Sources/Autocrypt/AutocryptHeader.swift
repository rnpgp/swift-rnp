//
//  AutocryptHeader.swift
//  Autocrypt
//
//  Parser and serializer for the Autocrypt level 1 header (RFC-style
//  spec at https://autocrypt.org/level1.html). The header carries a
//  user's public key directly in outgoing mail so recipients can pick
//  it up without a keyserver round-trip.
//
//  Format:
//    Autocrypt: addr=alice@example.org; prefer-encrypt=mutual;
//               keydata=<base64 of minimal OpenPGP key>
//

import Foundation

/// Encryption preference declared in the Autocrypt header.
public enum AutocryptPreferEncrypt: String, Equatable, Sendable, Codable {
    /// Default. Encrypt opportunistically when the recipient also
    /// advertises `mutual`.
    case mutual = "mutual"
    /// Do not auto-encrypt; only when the user explicitly asks.
    case nopreference = "nopreference"
    /// Never auto-encrypt; only on explicit user action.
    case encrypt = "encrypt"  // rare
    /// Disable Autocrypt for this address entirely.
    case disable = "disable"
}

/// One parsed Autocrypt header.
public struct AutocryptHeader: Equatable, Sendable {
    public let address: String
    public let preferEncrypt: AutocryptPreferEncrypt
    /// Raw Base64 keydata as it appears in the header. The bytes decode
    /// to a minimal OpenPGP public key (5 packets: primary, UID, self-
    /// sig, encryption subkey, subkey self-sig) as produced by
    /// `rnp_key_export_autocrypt`.
    public let keydataBase64: String

    public init(
        address: String,
        preferEncrypt: AutocryptPreferEncrypt,
        keydataBase64: String
    ) {
        self.address = address
        self.preferEncrypt = preferEncrypt
        self.keydataBase64 = keydataBase64
    }

    /// Decoded key bytes, or `nil` when the base64 is malformed.
    public var keydata: Data? {
        Data(base64Encoded: keydataBase64)
    }

    /// Renders the header value (without the `"Autocrypt: "` prefix)
    /// suitable for insertion into an outgoing message.
    public func renderedHeaderValue() -> String {
        "addr=\(address); prefer-encrypt=\(preferEncrypt.rawValue); keydata=\(keydataBase64)"
    }
}

/// Parser for the Autocrypt header. Tolerant of attribute order and
/// whitespace, matching the level 1 spec.
public enum AutocryptHeaderParser {
    public enum ParseError: Error, Equatable {
        case missingAddress
        case missingKeydata
        case unknownPreferEncrypt(String)
    }

    public static func parse(_ raw: String) throws -> AutocryptHeader {
        var address: String?
        var preferEncrypt: AutocryptPreferEncrypt = .nopreference
        var keydata: String?

        for attribute in splitAttributes(raw) {
            let (name, value) = attribute
            switch name.lowercased() {
            case "addr":
                address = value
            case "prefer-encrypt":
                guard let parsed = AutocryptPreferEncrypt(rawValue: value) else {
                    throw ParseError.unknownPreferEncrypt(value)
                }
                preferEncrypt = parsed
            case "keydata":
                // The keydata attribute may have internal whitespace
                // (line continuations); strip it before base64-decoding.
                keydata = value.replacingOccurrences(of: " ", with: "")
                                .replacingOccurrences(of: "\t", with: "")
                                .replacingOccurrences(of: "\n", with: "")
                                .replacingOccurrences(of: "\r", with: "")
            default:
                continue
            }
        }

        guard let address else { throw ParseError.missingAddress }
        guard let keydata else { throw ParseError.missingKeydata }

        return AutocryptHeader(
            address: address,
            preferEncrypt: preferEncrypt,
            keydataBase64: keydata
        )
    }

    /// Splits the header on `;` respecting the line-folding rules of
    /// RFC 5322. Returns name-value pairs lowercased by name with the
    /// value's whitespace trimmed.
    private static func splitAttributes(_ raw: String) -> [(name: String, value: String)] {
        var pairs: [(String, String)] = []
        for piece in raw.split(separator: ";") {
            let trimmed = piece.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let equalsIndex = trimmed.firstIndex(of: "=") else { continue }
            let name = String(trimmed[..<equalsIndex]).trimmingCharacters(in: .whitespaces)
            let value = String(trimmed[trimmed.index(after: equalsIndex)...])
                .trimmingCharacters(in: .whitespaces)
            pairs.append((name, value))
        }
        return pairs
    }
}

//
//  AutocryptGossip.swift
//  Autocrypt
//
//  Level 1.1 Autocrypt-Gossip header support. Gossip headers carry
//  public keys for non-To recipients (Cc/Bcc), letting each recipient
//  learn about the others. They travel inside the encrypted payload,
//  so only decrypting recipients see them.
//
//  Format identical to the regular Autocrypt header but with the
//  header name `Autocrypt-Gossip`. Multiple gossip headers may appear
//  in one message (one per recipient being gossiped).
//

import Foundation

/// One parsed `Autocrypt-Gossip:` header. Same shape as
/// `AutocryptHeader` minus the `prefer-encrypt` attribute (gossip
/// headers do not carry it per the level 1.1 spec).
public struct AutocryptGossipHeader: Equatable, Sendable {
    public let address: String
    public let keydataBase64: String

    public init(address: String, keydataBase64: String) {
        self.address = address
        self.keydataBase64 = keydataBase64
    }

    public var keydata: Data? { Data(base64Encoded: keydataBase64) }

    public func renderedHeaderValue() -> String {
        "addr=\(address); keydata=\(keydataBase64)"
    }
}

public enum AutocryptGossipParser {
    public enum ParseError: Error, Equatable {
        case missingAddress
        case missingKeydata
    }

    public static func parse(_ raw: String) throws -> AutocryptGossipHeader {
        var address: String?
        var keydata: String?
        for attribute in splitAttributes(raw) {
            switch attribute.name.lowercased() {
            case "addr":
                address = attribute.value
            case "keydata":
                keydata = attribute.value
                    .replacingOccurrences(of: " ", with: "")
                    .replacingOccurrences(of: "\t", with: "")
                    .replacingOccurrences(of: "\n", with: "")
                    .replacingOccurrences(of: "\r", with: "")
            default:
                continue
            }
        }
        guard let address else { throw ParseError.missingAddress }
        guard let keydata else { throw ParseError.missingKeydata }
        return AutocryptGossipHeader(address: address, keydataBase64: keydata)
    }

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

public extension AutocryptStore {
    /// Observes a parsed gossip header, recording the address→key
    /// binding in the same way as a regular Autocrypt header. Gossip
    /// observations do not influence `prefer-encrypt` decisions
    /// (gossip has no prefer-encrypt attribute); the existing
    /// `preferEncrypt` for the address is preserved.
    func observeGossip(_ header: AutocryptGossipHeader, messageDate: Date) throws {
        let existing = observation(forAddress: header.address)
        let preferEncrypt = existing?.preferEncrypt ?? .nopreference
        try observe(
            address: header.address,
            preferEncrypt: preferEncrypt,
            keydataBase64: header.keydataBase64,
            messageDate: messageDate
        )
    }
}

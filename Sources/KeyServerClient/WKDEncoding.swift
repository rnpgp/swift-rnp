//
//  WKDEncoding.swift
//  swift-rnp
//
//  Web Key Directory local-part hashing and URL construction.
//

import CryptoKit
import Foundation

/// WKD URL construction utilities.
public enum WKDEncoding {
    /// z-base-32 alphabet from RFC 6189 section 5.1.6.
    private static let alphabet = Array("ybndrfg8ejkmcpqxot1uwisza345h769")

    /// Hashes and encodes the local-part of an email address for WKD.
    ///
    /// - Parameter email: The email address.
    /// - Returns: The encoded local-part hash (`hu` value).
    /// - Throws: `KeyServerError.invalidEmail` if the address has no local part.
    public static func encodedLocalPart(for email: String) throws -> String {
        guard let localPart = email.split(separator: "@", maxSplits: 1).first else {
            throw KeyServerError.invalidEmail
        }
        let normalized = String(localPart).lowercasedASCIIOnly()
        let digest = Insecure.SHA1.hash(data: Data(normalized.utf8))
        return zbase32Encode(Data(digest))
    }

    /// Builds a WKD lookup URL.
    ///
    /// - Parameters:
    ///   - email: The email address to look up.
    ///   - advanced: Use the advanced method (`openpgpkey` subdomain) when `true`,
    ///     otherwise the direct method.
    /// - Throws: `KeyServerError.invalidEmail` if the address is malformed.
    public static func url(for email: String, advanced: Bool) throws -> URL {
        let parts = email.split(separator: "@", maxSplits: 1)
        guard parts.count == 2,
              let localPart = parts.first,
              let domainPart = parts.last else {
            throw KeyServerError.invalidEmail
        }

        let domain = String(domainPart).lowercased()
        let hu = try encodedLocalPart(for: email)
        let encodedLocal = String(localPart)
            .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? String(localPart)

        let path: String
        if advanced {
            path = "https://openpgpkey.\(domain)/.well-known/openpgpkey/\(domain)/hu/\(hu)?l=\(encodedLocal)"
        } else {
            path = "https://\(domain)/.well-known/openpgpkey/hu/\(hu)?l=\(encodedLocal)"
        }

        guard let url = URL(string: path) else {
            throw KeyServerError.invalidEmail
        }
        return url
    }

    /// Encodes data using z-base-32.
    private static func zbase32Encode(_ data: Data) -> String {
        var result = ""
        let bits = data.flatMap { byte -> [Bool] in
            (0..<8).map { bit in
                (byte >> (7 - bit)) & 1 == 1
            }
        }

        for i in stride(from: 0, to: bits.count, by: 5) {
            var value = 0
            for offset in 0..<5 {
                let index = i + offset
                value <<= 1
                if index < bits.count {
                    value |= bits[index] ? 1 : 0
                }
            }
            result.append(alphabet[value])
        }

        return result
    }
}

private extension String {
    /// Lowercases ASCII characters only, leaving non-ASCII characters unchanged.
    func lowercasedASCIIOnly() -> String {
        self.unicodeScalars.map { scalar in
            scalar.value >= 65 && scalar.value <= 90
                ? String(UnicodeScalar(scalar.value + 32)!)
                : String(scalar)
        }.joined()
    }
}

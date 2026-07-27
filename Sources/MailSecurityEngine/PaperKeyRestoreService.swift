//
//  PaperKeyRestoreService.swift
//  MailSecurityEngine
//
//  Restores a secret key from paper-key text. Uses PaperKeyHexFormatter
//  (in the Rnp module) to parse the hex back to binary, then loads it
//  into the keyring via the existing import path.
//

import Foundation
import Rnp

/// Errors thrown by `PaperKeyRestoreService`.
public enum PaperKeyRestoreError: Error, Equatable {
    /// The paper-key text could not be parsed (missing offset prefix,
    /// non-hex characters, etc.).
    case malformedPaperKey
    /// The parsed bytes could not be imported as an OpenPGP secret key.
    case invalidKeyMaterial(String)
}

/// Engine-layer service that restores a secret key from paper-key text.
public final class PaperKeyRestoreService {
    private let keyManager: KeyManager

    public init(keyManager: KeyManager) {
        self.keyManager = keyManager
    }

    /// Parses `paperKeyText` and imports the resulting secret-key
    /// material into the keyring.
    ///
    /// - Parameters:
    ///   - paperKeyText: full paper-key text, including the comment
    ///     header lines. Whitespace- and case-insensitive.
    /// - Returns: snapshots of the imported primary keys.
    @discardableResult
    public func restore(fromText paperKeyText: String) throws -> [KeyInfo] {
        guard let binary = PaperKeyHexFormatter.parse(paperKeyText) else {
            throw PaperKeyRestoreError.malformedPaperKey
        }
        do {
            return try keyManager.importKeys(binary)
        } catch {
            throw PaperKeyRestoreError.invalidKeyMaterial(error.localizedDescription)
        }
    }

    /// Quick check: does the text look like a paper-key? Used by UI to
    /// enable/disable the Restore button before the user finishes typing.
    public static func looksLikePaperKey(_ text: String) -> Bool {
        // Heuristic: contains the standard header OR has at least one
        // line that starts with an 8-hex offset prefix.
        if text.contains("paperkey") { return true }
        let lines = text.split(separator: "\n")
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.count >= 9 {
                let prefix = trimmed.prefix(8)
                let ninth = trimmed.dropFirst(8).first
                if prefix.allSatisfy({ $0.isHexDigit }), ninth == ":" {
                    return true
                }
            }
        }
        return false
    }
}

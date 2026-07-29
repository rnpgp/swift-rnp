//
//  KeyringStore+PaperKey.swift
//  MailSecurityEngine
//
//  Engine-layer convenience for paper-key export. Wraps
//  `RnpKey.exportPaperKeyText` with the key's metadata filled in.
//

import Foundation
import Rnp

public extension KeyringStore {
    /// Produces a paperkey-format text export of the secret key,
    /// including header lines identifying the key and a hex body
    /// suitable for printing.
    func exportPaperKey(fingerprint: String) throws -> String {
        try withRnp { rnp in
            let key = try rnp.requireKey(fingerprint, type: .fingerprint)
            let algorithm = (try? key.algorithm) ?? "OpenPGP"
            let bits = (try? key.bits) ?? 0
            return try key.exportPaperKeyText(
                fingerprint: fingerprint,
                algorithm: algorithm,
                bits: bits
            )
        }
    }
}

//
//  RnpKey+Autocrypt.swift
//  Rnp
//
//  Autocrypt-key exporter. Wraps `rnp_key_export_autocrypt`
//  (`Sources/CRnp/rnp/rnp.h:1293`), which produces the minimal 5-packet
//  key (primary, UID, self-sig, encryption subkey, subkey self-sig)
//  suitable for inclusion in an Autocrypt header.
//

import CRnp
import Foundation

/// Flag value matching `RNP_KEY_EXPORT_BASE64` in librnp.
private let RNP_KEY_EXPORT_BASE64: UInt32 = 0x02

public extension RnpKey {
    /// Exports a minimal Autocrypt-form key for `uid`, optionally pinned
    /// to a specific encryption subkey.
    ///
    /// - Parameters:
    ///   - uid: the user ID (typically `"Real Name <email>"`) to feature
    ///     in the export. `nil` selects the only UID when the key has one.
    ///   - subkey: the encryption subkey to include. `nil` picks the
    ///     first suitable one.
    ///   - base64: when `true`, the bytes are base64-encoded as
    ///     `RNP_KEY_EXPORT_BASE64` requests (what `Autocrypt:` headers
    ///     expect).
    /// - Returns: the exported key bytes (binary or base64).
    func exportAutocryptKey(
        uid: String? = nil,
        subkey: RnpKey? = nil,
        base64: Bool = true
    ) throws -> Data {
        let output = try MemoryOutput()
        let flags: UInt32 = base64 ? RNP_KEY_EXPORT_BASE64 : 0
        if let uid {
            try uid.withCString { uidC in
                try rnpCheck(
                    rnp_key_export_autocrypt(
                        handle,
                        subkey?.handle,
                        uidC,
                        output.handle,
                        flags
                    ),
                    operation: "export autocrypt"
                )
            }
        } else {
            try rnpCheck(
                rnp_key_export_autocrypt(
                    handle,
                    subkey?.handle,
                    nil,
                    output.handle,
                    flags
                ),
                operation: "export autocrypt"
            )
        }
        return try output.readData()
    }
}

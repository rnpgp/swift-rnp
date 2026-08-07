//
//  DecryptionFailureClassifier.swift
//  MailSecurityEngine
//
//  Turns a librnp failure into a `DecryptionFailure`. The classifier
//  inspects the ciphertext's packet structure (via `rnp_dump_packets_to_json`)
//  to distinguish "missing key" from "wrong passphrase" from "tampered"
//  without relying on librnp's error string.
//

import Foundation
import Librnp

/// Pure data extracted from `rnp_dump_packets_to_json` output: the PKESK
/// key IDs we observed and the algorithms used. The classifier consumes
/// this; the parser that produces it is isolated so tests can construct
/// synthetic inputs without going through FFI.
public struct PacketDump: Equatable, Sendable {
    public let pkeskKeyIDs: [String]
    public let usesAnonymousPKESK: Bool
    public let symmetricallyEncrypted: Bool
    public let aeadAlgorithm: String?
    public let unsupportedAlgorithm: String?

    public init(
        pkeskKeyIDs: [String],
        usesAnonymousPKESK: Bool,
        symmetricallyEncrypted: Bool,
        aeadAlgorithm: String?,
        unsupportedAlgorithm: String?
    ) {
        self.pkeskKeyIDs = pkeskKeyIDs
        self.usesAnonymousPKESK = usesAnonymousPKESK
        self.symmetricallyEncrypted = symmetricallyEncrypted
        self.aeadAlgorithm = aeadAlgorithm
        self.unsupportedAlgorithm = unsupportedAlgorithm
    }
}

/// Classifier turning `(error, ciphertext, keyring context)` into a
/// `DecryptionFailure`. Kept as a pure function (no I/O) so it is
/// exhaustively unit-testable; the caller supplies the packet dump and
/// the per-key-id lookup result.
public enum DecryptionFailureClassifier {
    /// Inputs the classifier needs that depend on live state.
    public struct KeyringContext: Sendable {
        /// For each PKESK key ID present in the ciphertext: the
        /// fingerprint of the matching key (when found in the keyring),
        /// plus whether that key is currently archived.
        public let lookup: @Sendable (String) -> KeyHit?

        public init(lookup: @escaping @Sendable (String) -> KeyHit?) {
            self.lookup = lookup
        }

        public static let noOp = KeyringContext(lookup: { _ in nil })
    }

    /// What `KeyringContext.lookup` returns for one PKESK key ID.
    public struct KeyHit: Equatable, Sendable {
        public let fingerprint: String
        public let isArchived: Bool
        public let archivedDate: Date?

        public init(fingerprint: String, isArchived: Bool, archivedDate: Date? = nil) {
            self.fingerprint = fingerprint
            self.isArchived = isArchived
            self.archivedDate = archivedDate
        }
    }

    /// Classify a decryption failure.
    ///
    /// - Parameters:
    ///   - librnpError: the raw error string reported by librnp.
    ///   - dump: the packet dump of the ciphertext, or `nil` if dumping
    ///     also failed (the message is not OpenPGP data at all, or the
    ///     armor is malformed).
    ///   - context: keyring lookup helper for PKESK key IDs.
    public static func classify(
        librnpError: String,
        dump: PacketDump?,
        context: KeyringContext
    ) -> DecryptionFailure {
        let lower = librnpError.lowercased()

        // Tampering / integrity failures have specific librnp messages.
        if lower.contains("mdc") || lower.contains("integrity")
            || lower.contains("aead") && lower.contains("auth") {
            return .integrityFailure
        }

        // Wrong passphrase is identifiable from librnp's text.
        if lower.contains("passphrase") || lower.contains("password")
            || lower.contains("wrong key password") {
            return .wrongPassphrase
        }

        // Symmetric-only encryption: no PKESK packets at all.
        if let dump, dump.pkeskKeyIDs.isEmpty, !dump.usesAnonymousPKESK,
           dump.symmetricallyEncrypted {
            return .symmetricEncryption
        }

        // Unsupported algorithm.
        if let dump, let alg = dump.unsupportedAlgorithm {
            return .unsupportedAlgorithm(alg)
        }

        // Missing secret key with visible PKESK key IDs.
        if let dump, !dump.pkeskKeyIDs.isEmpty {
            for keyID in dump.pkeskKeyIDs {
                if let hit = context.lookup(keyID) {
                    if hit.isArchived, let archivedDate = hit.archivedDate {
                        return .missingSecretKey(
                            pkeskKeyIDs: dump.pkeskKeyIDs,
                            suggestedAction: .restoreFromArchive(
                                fingerprint: hit.fingerprint,
                                archivedDate: archivedDate
                            )
                        )
                    }
                    // The key is present and active — if we got here, the
                    // failure must be wrong passphrase after all. Fall
                    // through to that conclusion.
                    return .wrongPassphrase
                }
            }
            // No PKESK key ID matched anything in the keyring.
            let action: MissingKeyAction = if let keyID = dump.pkeskKeyIDs.first {
                .fetchFromKeyserver(keyID: keyID)
            } else {
                .importKeyManually
            }
            return .missingSecretKey(pkeskKeyIDs: dump.pkeskKeyIDs, suggestedAction: action)
        }

        // v6 anonymous PKESK — we cannot tell which key is needed.
        if let dump, dump.usesAnonymousPKESK {
            return .missingSecretKey(pkeskKeyIDs: [], suggestedAction: .none)
        }

        // No dump at all: either armor is broken or this isn't OpenPGP.
        if dump == nil {
            if lower.contains("armor") || lower.contains("base64") || lower.contains("crc") {
                return .malformedArmor(detail: librnpError)
            }
        }

        return .unknown(librnpMessage: librnpError)
    }
}

// MARK: - Packet-dump parsing

extension PacketDump {
    /// Parses `rnp_dump_packets_to_json` output into the flat structure
    /// the classifier consumes. Tolerant of new packet types added by
    /// newer librnp versions: unknown packets are skipped, not rejected.
    public static func parse(json: String) -> PacketDump? {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return nil
        }
        return parse(object: object)
    }

    /// Parser entry point that takes the already-decoded JSON object —
    /// split out so tests can construct packets directly.
    public static func parse(object: [String: Any]) -> PacketDump {
        var pkeskKeyIDs: [String] = []
        var anonymousPKESK = false
        var symmetricallyEncrypted = false
        var aead: String?
        var unsupported: String?

        let packets = (object["packets"] as? [[String: Any]]) ?? [object]
        for packet in packets {
            guard let kind = packet["type"] as? String else { continue }
            switch kind.lowercased() {
            case "pkesk", "pkesk v3", "pkesk v6":
                if let id = packet["keyid"] as? String, !id.isEmpty {
                    pkeskKeyIDs.append(id)
                } else {
                    anonymousPKESK = true
                }
            case "skesk":
                symmetricallyEncrypted = true
            case "seipd", "seipd v1", "seipd v2", "sed", "aead-encrypted":
                if let alg = packet["aead"] as? String, aead == nil {
                    aead = alg
                }
                if let alg = packet["cipher"] as? String,
                   let known = Self.unsupportedAlgorithmHint(alg),
                   unsupported == nil {
                    unsupported = known
                }
            default:
                break
            }
        }
        return PacketDump(
            pkeskKeyIDs: pkeskKeyIDs,
            usesAnonymousPKESK: anonymousPKESK,
            symmetricallyEncrypted: symmetricallyEncrypted,
            aeadAlgorithm: aead,
            unsupportedAlgorithm: unsupported
        )
    }

    /// Recognizes cipher names librnp cannot handle in the current build
    /// (placeholders for future algorithms). Conservative: returns `nil`
    /// for anything we don't explicitly know is unsupported.
    private static func unsupportedAlgorithmHint(_ name: String) -> String? {
        let lower = name.lowercased()
        let knownUnsupported = ["unknown", "experimental", "private-use"]
        if knownUnsupported.contains(where: { lower.contains($0) }) {
            return name
        }
        return nil
    }
}

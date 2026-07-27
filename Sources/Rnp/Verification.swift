//
//  Verification.swift
//  swift-rnp
//
//  Detailed signature verification results (per-signature status, signer,
//  hash algorithm, creation time) on top of rnp_op_verify_t.
//

import CRnp
import Foundation

/// Verification status of a single signature, mapped from the
/// `rnp_op_verify_signature_get_status()` result codes.
public enum RnpSignatureStatus: String, Equatable, Sendable {
    /// Signature verified successfully (`RNP_SUCCESS`).
    case valid
    /// Signature is valid but expired (`RNP_ERROR_SIGNATURE_EXPIRED`).
    case expired
    /// The signer's public key is not in the keyring
    /// (`RNP_ERROR_KEY_NOT_FOUND`).
    case signerUnknown
    /// Data or signature was modified (`RNP_ERROR_SIGNATURE_INVALID`).
    case invalid
    /// Any other status (`RNP_ERROR_SIGNATURE_UNKNOWN` and beyond).
    case unknown
}

/// librnp status codes used for the status mapping. The codes live in an
/// anonymous C enum in rnp_err.h, which the Swift importer does not surface.
private let rnpStatusSignatureExpired: rnp_result_t = 0x1200_000C
private let rnpStatusKeyNotFound: rnp_result_t = 0x1200_0005
private let rnpStatusSignatureInvalid: rnp_result_t = 0x1200_0002

/// Information about one signature found in verified data.
public struct RnpSignatureInfo: Equatable {
    public let status: RnpSignatureStatus
    /// Fingerprint of the signing key, or `nil` when the key is not
    /// available in the keyring.
    public let fingerprint: String?
    /// Hash algorithm used for the signature, e.g. "SHA256".
    public let hashAlgorithm: String?
    /// Signature creation time.
    public let creationDate: Date?
}

/// Encryption status of verified data, when it was encrypted
/// (`rnp_op_verify_get_protection_info`).
public struct RnpEncryptionInfo: Equatable {
    /// Protection mode, e.g. "cfb-mdc" or "aead-eax".
    public let mode: String?
    /// Symmetric cipher used, e.g. "AES256".
    public let cipher: String?
    /// Whether integrity protection (MDC or AEAD) was present and validated.
    public let integrityProtected: Bool
}

/// Result of `Rnp.verifyDetailed` / `Rnp.verifyDetachedDetailed`.
public struct RnpVerification: Equatable {
    /// The verified payload, or `nil` when no payload could be extracted
    /// (invalid signature, or a detached verification, which has none).
    public let payload: Data?
    /// Per-signature details, in message order.
    public let signatures: [RnpSignatureInfo]
    /// Encryption details when the data was encrypted, `nil` otherwise.
    public let encryption: RnpEncryptionInfo?

    /// Whether at least one signature verified successfully.
    public var hasValidSignature: Bool {
        signatures.contains { $0.status == .valid }
    }
}

extension Rnp {
    /// Verifies data carrying an embedded signature, returning per-signature
    /// details instead of just failing on the first invalid signature.
    ///
    /// - Throws: `RnpError.ffiFailed` when the input could not be processed
    ///   at all (e.g. it is not OpenPGP data). An *invalid signature* is
    ///   reported via `RnpVerification.signatures`, not thrown.
    @discardableResult
    public func verifyDetailed(_ signedMessage: Data) throws -> RnpVerification {
        let output = try MemoryOutput()
        return try withMemoryInput(signedMessage, operation: "verify") { input in
            var handle: rnp_op_verify_t?
            try rnpCheck(rnp_op_verify_create(&handle, ffi, input, output.handle), operation: "verify create")
            guard let operation = handle else {
                throw RnpError.ffiFailed(
                    operation: "verify create",
                    code: rnpStatusSuccess,
                    message: "unexpected NULL operation"
                )
            }
            defer { rnp_op_verify_destroy(operation) }
            let status = rnp_op_verify_execute(operation)
            let signatures = collectSignatures(operation: operation)
            guard status == rnpStatusSuccess || !signatures.isEmpty else {
                throw RnpError.ffiFailed(
                    operation: "verify execute",
                    code: status,
                    message: String(cString: rnp_result_to_string(status))
                )
            }
            return RnpVerification(
                payload: status == rnpStatusSuccess ? try? output.readData() : nil,
                signatures: signatures,
                encryption: encryptionInfo(operation: operation)
            )
        }
    }

    /// Verifies a detached signature against the original data, returning
    /// per-signature details. The result's `payload` is always `nil`.
    ///
    /// - Throws: `RnpError.ffiFailed` when the signature could not be
    ///   processed at all; an *invalid signature* is reported via
    ///   `RnpVerification.signatures`, not thrown.
    public func verifyDetachedDetailed(signature: Data, data: Data) throws -> RnpVerification {
        try withMemoryInput(data, operation: "verify detached") { dataInput in
            try withMemoryInput(signature, operation: "verify detached") { signatureInput in
                var handle: rnp_op_verify_t?
                try rnpCheck(
                    rnp_op_verify_detached_create(&handle, ffi, dataInput, signatureInput),
                    operation: "verify detached create"
                )
                guard let operation = handle else {
                    throw RnpError.ffiFailed(
                        operation: "verify detached create",
                        code: rnpStatusSuccess,
                        message: "unexpected NULL operation"
                    )
                }
                defer { rnp_op_verify_destroy(operation) }
                let status = rnp_op_verify_execute(operation)
                let signatures = collectSignatures(operation: operation)
                guard status == rnpStatusSuccess || !signatures.isEmpty else {
                    throw RnpError.ffiFailed(
                        operation: "verify detached execute",
                        code: status,
                        message: String(cString: rnp_result_to_string(status))
                    )
                }
                return RnpVerification(
                    payload: nil,
                    signatures: signatures,
                    encryption: encryptionInfo(operation: operation)
                )
            }
        }
    }

    /// Reads the encryption status of an executed verify operation.
    private func encryptionInfo(operation: rnp_op_verify_t) -> RnpEncryptionInfo? {
        var mode: UnsafeMutablePointer<CChar>?
        var cipher: UnsafeMutablePointer<CChar>?
        var valid = false
        guard rnp_op_verify_get_protection_info(operation, &mode, &cipher, &valid) == rnpStatusSuccess else {
            return nil
        }
        // librnp reports the literal string "none" (not NULL) for data that
        // was not encrypted.
        let modeString = mode.map { String(cString: $0) }
        let cipherString = cipher.map { String(cString: $0) }
        defer {
            if let mode { rnp_buffer_destroy(mode) }
            if let cipher { rnp_buffer_destroy(cipher) }
        }
        guard let modeString, modeString != "none" else {
            return nil
        }
        return RnpEncryptionInfo(
            mode: modeString,
            cipher: cipherString == "none" ? nil : cipherString,
            integrityProtected: valid
        )
    }

    /// Reads the signature list of an executed verify operation.
    private func collectSignatures(operation: rnp_op_verify_t) -> [RnpSignatureInfo] {
        var count = 0
        guard rnp_op_verify_get_signature_count(operation, &count) == rnpStatusSuccess else {
            return []
        }
        return (0 ..< count).compactMap { index in
            var signature: rnp_op_verify_signature_t?
            guard rnp_op_verify_get_signature_at(operation, index, &signature) == rnpStatusSuccess,
                  let signature
            else {
                return nil
            }
            return signatureInfo(signature)
        }
    }

    private func signatureInfo(_ signature: rnp_op_verify_signature_t) -> RnpSignatureInfo {
        let status: RnpSignatureStatus
        switch rnp_op_verify_signature_get_status(signature) {
        case rnpStatusSuccess:
            status = .valid
        case rnpStatusSignatureExpired:
            status = .expired
        case rnpStatusKeyNotFound:
            status = .signerUnknown
        case rnpStatusSignatureInvalid:
            status = .invalid
        default:
            status = .unknown
        }

        // The returned handle is newly allocated and owned by the caller;
        // RnpKey's deinitializer releases it.
        var fingerprint: String?
        var keyHandle: rnp_key_handle_t?
        if rnp_op_verify_signature_get_key(signature, &keyHandle) == rnpStatusSuccess,
           let keyHandle
        {
            fingerprint = try? RnpKey(handle: keyHandle).fingerprint
        }

        var hashAlgorithm: String?
        var hash: UnsafeMutablePointer<CChar>?
        if rnp_op_verify_signature_get_hash(signature, &hash) == rnpStatusSuccess {
            hashAlgorithm = try? rnpTakeString(hash, operation: "signature hash")
        }

        var creation: UInt32 = 0
        var creationDate: Date?
        if rnp_op_verify_signature_get_times(signature, &creation, nil) == rnpStatusSuccess {
            creationDate = Date(timeIntervalSince1970: TimeInterval(creation))
        }

        return RnpSignatureInfo(
            status: status,
            fingerprint: fingerprint,
            hashAlgorithm: hashAlgorithm,
            creationDate: creationDate
        )
    }
}

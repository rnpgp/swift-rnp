//
//  RnpKey+Certification.swift
//  Rnp
//
//  Wrappers around `rnp_key_certification_create` and
//  `rnp_key_signature_sign` for issuing OpenPGP certification
//  signatures (RFC 4880 §5.2.1, type 0x10–0x13). Used by the key
//  transition flow to certify a new key's UID with an old key.
//

import CRnp
import Foundation

/// Certification signature types per RFC 4880 §5.2.1. The default for
/// certifying another key is `.generic`; the default for self-sig is
/// `.positive`.
public enum CertificationType: String, Sendable {
    case generic = "generic"
    case persona = "persona"
    case casual = "casual"
    case positive = "positive"
}

/// RAII wrapper around `rnp_signature_handle_t`. Releases the handle on
/// deinit. Callers receive one from `RnpKey.makeCertification(...)` and
/// pass it to `finalize()` to actually emit the signature bytes into
/// the keyring.
public final class RnpSignature {
    let handle: rnp_signature_handle_t

    init(handle: rnp_signature_handle_t) {
        self.handle = handle
    }

    deinit {
        rnp_signature_handle_destroy(handle)
    }

    /// Sets the hash algorithm for the signature. Must be called before
    /// `finalize()`; defaults to librnp's choice otherwise.
    public func setHash(_ hash: String) throws {
        try rnpCheck(rnp_key_signature_set_hash(handle, hash), operation: "signature set hash")
    }

    /// Sets the signature creation time. Defaults to now.
    public func setCreation(_ date: Date) throws {
        try rnpCheck(
            rnp_key_signature_set_creation(handle, UInt32(date.timeIntervalSince1970)),
            operation: "signature set creation"
        )
    }

    /// Finalizes the signature: librnp computes the cryptographic
    /// material and writes it into the keyring. After this call the
    /// signature is part of the key.
    public func finalize() throws {
        try rnpCheck(rnp_key_signature_sign(handle), operation: "signature sign")
    }
}

public extension RnpKey {
    /// Creates a certification signature of `type` over `targetUID`,
    /// issued by `self` (which must be a secret key). The returned
    /// `RnpSignature` is configured with default hash and creation
    /// time; customize via `setHash` / `setCreation` and then call
    /// `finalize()`.
    ///
    /// For transition certifications: `self` is the OLD primary,
    /// `targetUID` is a UID handle on the NEW primary.
    func makeCertification(
        of targetUID: RnpUserID,
        type: CertificationType = .generic
    ) throws -> RnpSignature {
        var sigHandle: rnp_signature_handle_t?
        try rnpCheck(
            rnp_key_certification_create(handle, targetUID.handle, type.rawValue, &sigHandle),
            operation: "certification create"
        )
        guard let sigHandle else {
            throw RnpError.ffiFailed(
                operation: "certification create",
                code: rnpStatusSuccess,
                message: "unexpected NULL signature handle"
            )
        }
        return RnpSignature(handle: sigHandle)
    }
}

//
//  InvalidSignatureWarning.swift
//  swift-rnp
//
//  Reason classification behind the banner's invalid-signature warning.
//

import Foundation

/// Why an `.invalid` signature failed verification.
///
/// Determined at decode time from the detailed verification result
/// (`RnpVerification.signatures`: whether librnp could report the signing
/// key's fingerprint) and the signing key's state in the keyring, then
/// carried to the banner in `SignerContext.invalidReason` as the raw value —
/// mirroring how `SignerContext.status` carries `RnpSignatureStatus`.
public enum InvalidSignatureReason: String, Equatable, Sendable {
    /// The signature does not match the message content: the message (or
    /// the signature) was modified after signing.
    case contentMismatch = "content-mismatch"
    /// The signing key is not in the keyring, so the signature could not be
    /// checked. Fetching the key is the remedy.
    case keyUnknown = "key-unknown"
    /// The signing key is in the keyring but has been revoked.
    case keyRevoked = "key-revoked"
    /// The signing key is in the keyring but has expired. Defensive: librnp
    /// currently still verifies signatures of expired keys (the signature
    /// predates the expiry), so this is not produced in practice.
    case keyExpired = "key-expired"
}

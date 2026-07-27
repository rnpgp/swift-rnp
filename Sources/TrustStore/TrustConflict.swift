//
//  TrustConflict.swift
//  swift-rnp
//
//  A key-change conflict detected for a known email address.
//

import Foundation

/// A conflict raised when a different fingerprint is seen for an address that
/// already has a recorded binding.
///
/// Conflicts block encryption to the affected address until the user verifies
/// the new fingerprint (or otherwise resolves the conflict).
public struct TrustConflict: Codable, Equatable, Sendable {
    /// Normalized email address whose binding changed.
    public var email: String
    /// Fingerprint previously recorded for the address.
    public var existingFingerprint: String
    /// Newly seen fingerprint for the address.
    public var newFingerprint: String
    /// When the conflict was detected.
    public var detectedAt: Date

    public init(
        email: String,
        existingFingerprint: String,
        newFingerprint: String,
        detectedAt: Date = Date()
    ) {
        self.email = email
        self.existingFingerprint = existingFingerprint
        self.newFingerprint = newFingerprint
        self.detectedAt = detectedAt
    }
}

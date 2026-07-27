//
//  TrustRecord.swift
//  swift-rnp
//
//  One persisted trust association between an email address and a fingerprint.
//

import Foundation

/// A persisted trust record for one address-to-fingerprint binding.
public struct TrustRecord: Codable, Equatable, Sendable {
    /// Normalized email address (lowercased, trimmed).
    public var email: String
    /// Primary key fingerprint bound to the address.
    public var fingerprint: String
    /// Current trust state of this binding.
    public var state: TrustState
    /// When the binding was first recorded.
    public var firstSeen: Date
    /// When the binding was last observed.
    public var lastSeen: Date

    public init(
        email: String,
        fingerprint: String,
        state: TrustState,
        firstSeen: Date = Date(),
        lastSeen: Date = Date()
    ) {
        self.email = email
        self.fingerprint = fingerprint
        self.state = state
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }
}

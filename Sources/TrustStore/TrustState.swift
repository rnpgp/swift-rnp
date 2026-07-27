//
//  TrustState.swift
//  swift-rnp
//
//  Trust state for a single OpenPGP key.
//

import Foundation

/// Per-key trust state used by `TrustStore`.
///
/// - `unverified`: first-seen key for an address (TOFU). Safe to use, but the
///   user has not yet verified the fingerprint.
/// - `verified`: the user explicitly confirmed the fingerprint.
/// - `problem`: the key is expired, revoked, or a different key was seen for an
///   already-known address. Operations should halt until the user resolves it.
public enum TrustState: String, Codable, Equatable, Sendable {
    case unverified
    case verified
    case problem
}

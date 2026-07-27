//
//  SignerKeyFetch.swift
//  swift-rnp
//
//  Result type for the "fetch signer key" flow: when a signed message
//  arrives whose signing key is not in the local keyring, the Mail banner
//  offers to look the key up on public keyservers and import it.
//
//  Pure result typing; the network and keyring work lives in
//  `MessageSecurityCore.fetchSignerKey`.
//

import Foundation

/// Outcome of fetching and importing an unknown signer's public key.
public struct SignerKeyFetchResult: Equatable, Sendable {
    /// Fingerprint of the imported signer key, as it resolved in the keyring
    /// after import.
    public let fingerprint: String
    /// Human-readable source description (e.g. "keys.openpgp.org",
    /// "keyserver.ubuntu.com (HKPS)", "WKD (advanced)").
    public let source: String

    public init(fingerprint: String, source: String) {
        self.fingerprint = fingerprint
        self.source = source
    }
}

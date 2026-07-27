//
//  SignerTrustViewModel.swift
//  swift-rnp
//
//  Pure mapping from signature verification status + key trust to a
//  Mail-extension banner view model. Kept free of MailKit types so it is
//  unit-testable with plain XCTest.
//

import Foundation
import Rnp
import TrustStore

/// Visual intent for a signer trust line.
public enum SignerTrustIntent: Equatable, Sendable {
    /// Verified signature + verified key.
    case positive
    /// Verified signature but key not verified, or neutral state.
    case neutral
    /// Signature or trust problem that deserves attention.
    case caution
    /// Hard failure: invalid signature or key marked problem.
    case critical
}

/// View model describing how to present one signer's trust in Mail's security
/// banner.
public struct SignerTrustViewModel: Equatable, Sendable {
    /// Short headline, e.g. "Verified key" or "Key not verified".
    public let label: String
    /// Longer explanation shown below the headline.
    public let detail: String
    /// Visual intent driving the banner color.
    public let intent: SignerTrustIntent
    /// Whether the banner should offer a deep link to review the key.
    public let reviewDeepLink: Bool

    public init(
        label: String,
        detail: String,
        intent: SignerTrustIntent,
        reviewDeepLink: Bool
    ) {
        self.label = label
        self.detail = detail
        self.intent = intent
        self.reviewDeepLink = reviewDeepLink
    }
}

/// Maps a signature verification status and the signer's trust state to a
/// presentation model for the Mail extension banner.
///
/// The mapping is deliberately simple and does not include web-of-trust or
/// ownertrust semantics. `keyExpiration` — the signing key's expiration
/// date, when known — is appended to the detail text of expired-signature
/// states so the user sees when the key expired. `invalidReason` — the
/// decode-time classification of an `.invalid` signature — replaces the
/// generic invalid-signature detail with the specific cause; contexts
/// written by older extension versions carry no reason and keep the generic
/// text.
public func mapSignerTrust(
    status: RnpSignatureStatus,
    trust: TrustState,
    keyExpiration: Date? = nil,
    invalidReason: InvalidSignatureReason? = nil
) -> SignerTrustViewModel {
    switch (status, trust) {
    case (.valid, .verified):
        return SignerTrustViewModel(
            label: "Verified key",
            detail: "This signature was made by a key whose fingerprint you verified.",
            intent: .positive,
            reviewDeepLink: false
        )
    case (.valid, .problem):
        return SignerTrustViewModel(
            label: "Key problem",
            detail: "This key is marked as having a problem (expired, revoked, or changed). Do not trust this signature without checking the fingerprint.",
            intent: .critical,
            reviewDeepLink: true
        )
    case (.valid, .unverified):
        return SignerTrustViewModel(
            label: "Key not verified",
            detail: "The signature is valid, but you have not verified this key's fingerprint. Verify it before trusting the signature.",
            intent: .neutral,
            reviewDeepLink: true
        )
    case (.expired, .verified):
        return SignerTrustViewModel(
            label: "Verified key, expired signature",
            detail: expiredSignatureDetail("The key is verified, but the signature has expired.", keyExpiration: keyExpiration),
            intent: .caution,
            reviewDeepLink: false
        )
    case (.expired, .problem):
        return SignerTrustViewModel(
            label: "Key problem, expired signature",
            detail: expiredSignatureDetail("The key is marked as having a problem and the signature has expired.", keyExpiration: keyExpiration),
            intent: .critical,
            reviewDeepLink: true
        )
    case (.expired, .unverified):
        return SignerTrustViewModel(
            label: "Key not verified, expired signature",
            detail: expiredSignatureDetail("The signature has expired and the key has not been verified.", keyExpiration: keyExpiration),
            intent: .caution,
            reviewDeepLink: true
        )
    case (.signerUnknown, _):
        return SignerTrustViewModel(
            label: "Unknown signer",
            detail: "The signer's public key is not in your keyring.",
            intent: .critical,
            reviewDeepLink: false
        )
    case (.invalid, _):
        return SignerTrustViewModel(
            label: "Invalid signature",
            detail: invalidSignatureDetail(reason: invalidReason, keyExpiration: keyExpiration),
            intent: .critical,
            // Offer the key detail view whenever the signing key is known;
            // for an unknown key there is nothing to show — the banner's
            // "Fetch signer key" action applies instead.
            reviewDeepLink: invalidReason != .keyUnknown
        )
    case (.unknown, .verified):
        return SignerTrustViewModel(
            label: "Verified key, unknown signature status",
            detail: "The key is verified, but the signature status is unknown.",
            intent: .caution,
            reviewDeepLink: false
        )
    case (.unknown, .problem):
        return SignerTrustViewModel(
            label: "Key problem, unknown signature status",
            detail: "The key is marked as having a problem and the signature status is unknown.",
            intent: .critical,
            reviewDeepLink: true
        )
    case (.unknown, .unverified):
        return SignerTrustViewModel(
            label: "Key not verified, unknown signature status",
            detail: "The signature status is unknown and the key has not been verified.",
            intent: .caution,
            reviewDeepLink: true
        )
    }
}

/// Appends the signing key's expiration date to an expired-signature detail
/// text when the date is known.
private func expiredSignatureDetail(_ base: String, keyExpiration: Date?) -> String {
    guard let keyExpiration else { return base }
    return "\(base) The key expired on \(formatKeyExpirationDate(keyExpiration))."
}

/// Detail text for an invalid signature, naming the specific cause when the
/// decode-time classification is known. Without a reason (contexts written
/// by older extension versions) the original generic text is kept.
private func invalidSignatureDetail(reason: InvalidSignatureReason?, keyExpiration: Date?) -> String {
    switch reason {
    case .none:
        return "The signature does not verify; the message may have been modified."
    case .contentMismatch:
        return "The signature does not match the message content; the message may have been modified after signing."
    case .keyUnknown:
        return "The signature was made by an unknown or revoked key, so it could not be verified."
    case .keyRevoked:
        return "The signature was made by a key that has been revoked. Do not trust this message."
    case .keyExpired:
        let base = "The signature was made by an expired key."
        guard let keyExpiration else { return base }
        return "\(base) The key expired on \(formatKeyExpirationDate(keyExpiration))."
    }
}

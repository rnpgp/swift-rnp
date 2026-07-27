//
//  EncryptionEnvelopePolicy.swift
//  MailSecurityEngine
//
//  Controls which OpenPGP envelope (CFB+MDC vs AEAD-OCB; PKESK v3 vs v6)
//  the encoder uses when encrypting. Mirrors the policy described in
//  TODO.roadmap/12-aead-v6.md: automatic by default, force-AEAD for
//  power users, force-legacy for backward compat.
//

import Foundation

/// User-facing envelope policy. Per-recipient capability detection is
/// done at encode time; the policy controls how the encoder resolves
/// conflicts (mixed capabilities across recipients of one message).
public enum EncryptionEnvelopePolicy: String, CaseIterable, Sendable {
    /// Default. Use AEAD-OCB + v6 PKESK when every recipient supports it;
    /// fall back to AEAD-OCB + v3 PKESK when at least one supports AEAD;
    /// fall back to CFB + MDC when any recipient is legacy-only.
    case automatic

    /// Refuse to encrypt when any recipient lacks AEAD support. Use when
    /// the user has explicitly chosen to enforce modern crypto.
    case forceAEAD

    /// Always emit CFB + MDC. Maximum compatibility with very old
    /// clients; appropriate for correspondents on legacy PGP software.
    case forceLegacy
}

/// Per-recipient capability summary, populated by inspecting the
/// recipient's key flags. Wraps `RNP_KEY_FEATURE_AEAD` and the v6 key
/// version check.
public struct RecipientEncryptionCapability: Equatable, Sendable {
    public let address: String
    public let supportsAEAD: Bool
    public let supportsV6: Bool

    public init(address: String, supportsAEAD: Bool, supportsV6: Bool) {
        self.address = address
        self.supportsAEAD = supportsAEAD
        self.supportsV6 = supportsV6
    }
}

/// Pure decision function: given per-recipient capabilities and a policy,
/// returns the envelope the encoder should produce. Kept separate from
/// the encoder so it can be exhaustively unit-tested.
public enum EncryptionEnvelopeResolver {
    /// The envelope the encoder should use, or a refusal when the policy
    /// says "force-AEAD" but a recipient cannot do AEAD.
    public enum Decision: Equatable {
        case aeadOCBWithV6PKESK
        case aeadOCBWithV3PKESK
        case cfbWithMDC
        case refused(recipientsWithoutAEAD: [String])
    }

    public static func decide(
        capabilities: [RecipientEncryptionCapability],
        policy: EncryptionEnvelopePolicy
    ) -> Decision {
        guard !capabilities.isEmpty else {
            // No recipients is invalid; the caller handles that case
            // before getting here. Default to legacy for safety.
            return .cfbWithMDC
        }

        let withoutAEAD = capabilities.filter { !$0.supportsAEAD }.map(\.address)

        switch policy {
        case .automatic:
            let allAEAD = withoutAEAD.isEmpty
            let allV6 = capabilities.allSatisfy { $0.supportsV6 }
            if allAEAD, allV6 { return .aeadOCBWithV6PKESK }
            if allAEAD { return .aeadOCBWithV3PKESK }
            return .cfbWithMDC
        case .forceAEAD:
            if withoutAEAD.isEmpty {
                let allV6 = capabilities.allSatisfy { $0.supportsV6 }
                return allV6 ? .aeadOCBWithV6PKESK : .aeadOCBWithV3PKESK
            }
            return .refused(recipientsWithoutAEAD: withoutAEAD)
        case .forceLegacy:
            return .cfbWithMDC
        }
    }
}

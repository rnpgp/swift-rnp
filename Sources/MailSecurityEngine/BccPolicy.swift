//
//  BccPolicy.swift
//  MailSecurityEngine
//
//  Policy for handling BCC recipients in outgoing encrypted mail.
//
//  Background: PGP/MIME produces a single ciphertext with one PKESK per
//  recipient. Any decrypting recipient can enumerate the PKESK key IDs
//  and discover every other recipient — including BCC. RFC 3156 §6
//  explicitly calls this out. The only safe options are:
//
//  1. Refuse and offer the user a path forward (the default).
//  2. Re-encrypt separately per BCC set (non-standard; interop-poor).
//  3. Drop encryption for the whole message.
//  4. Drop the BCC recipients.
//
//  This type captures the policy decision; the encoder and the compose
//  UI read from it rather than scattering the branching across the
//  codebase.
//

import Foundation

/// Discrete policy for how an encrypted send with BCC recipients should
/// be handled.
public enum BccPolicy: Equatable, Sendable {
    /// Default. The encode path refuses and produces a
    /// `MailSecurityError.bccRequiresSpecialHandling` error; the UI
    /// offers the user a choice of `BccResolution`.
    case refuse

    /// Re-encrypt the body separately for the To+Cc set and once per BCC
    /// recipient. Non-standard; produces N+1 messages from one compose.
    /// Reserved for a future release; documented as not supported in 1.0.
    case sendSeparately

    /// Drop encryption for the entire message. BCC works normally; no
    /// metadata leak.
    case removeEncryption

    /// Drop the BCC recipients from the encrypted send. Encryption
    /// proceeds normally to To+Cc; the BCC list is sent unencrypted via
    /// a separate plaintext send (the caller's responsibility).
    case removeBcc
}

/// The user-facing recovery options when the refuse policy fires. Each
/// option carries enough context for the UI to render without consulting
/// engine internals.
public enum BccResolution: Equatable, Sendable {
    /// Proceed with `sendSeparately` — N+1 messages.
    case sendSeparately
    /// Strip encryption, send as plaintext (or signed-only) so BCC works.
    case removeEncryption
    /// Strip BCC from the encrypted send; the BCC list goes via a
    /// separate plaintext path the caller wires up.
    case removeBcc(bccAddresses: [String])
    /// Cancel: go back and let the user edit the message.
    case cancel
}

/// Structured error carrying the BCC context. The compose pipeline throws
/// this when the policy is `refuse` and the message has BCC recipients;
/// the UI consumes the `bccAddresses` field to populate its resolution
/// sheet.
public struct BccRequiresSpecialHandlingError: Error, Equatable, Sendable {
    public let bccAddresses: [String]
    public let policy: BccPolicy

    public init(bccAddresses: [String], policy: BccPolicy = .refuse) {
        self.bccAddresses = bccAddresses
        self.policy = policy
    }
}

/// Pure helper that decides whether a recipient list needs BCC handling
/// under a given policy. Kept separate from the encoder so the compose UX
/// can call it for live UI feedback without running the encoder.
public enum BccPolicyEvaluator {
    /// Returns `true` when the policy requires the encoder to refuse.
    public static func shouldRefuse(
        hasBcc: Bool,
        policy: BccPolicy
    ) -> Bool {
        guard hasBcc else { return false }
        return policy == .refuse
    }
}

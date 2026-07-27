//
//  ComposePolicy.swift
//  MailSecurityEngine
//
//  Aggregate of the per-message encode policies. Groups the four
//  policy enums (BccPolicy, EncryptionEnvelopePolicy, AutocryptEmitPolicy,
//  PQPolicyChoice) so the encode pipeline takes a single argument
//  instead of four. Reduces parameter-list noise and lets callers
//  persist/restore a complete policy as one value.
//
//  MECE: each member policy is owned by its source module
//  (BccPolicy here, EncryptionEnvelopePolicy here, AutocryptEmitPolicy
//  here, PQPolicyChoice lives in RnpMailUI as a UI mirror). The
//  aggregate is a value type — no behavior — so concerns stay where
//  they belong.
//

import Autocrypt
import Foundation
import PostQuantum
import Rnp

/// Bundle of per-encode policies. `default` produces the safe,
/// maximum-compatibility, maximum-interop set.
public struct ComposePolicy: Equatable, Sendable {
    public var bcc: BccPolicy
    public var envelope: EncryptionEnvelopePolicy
    public var autocrypt: AutocryptEmitPolicy
    /// Post-quantum policy for new-key generation (does not affect
    /// encryption to existing recipients — that's driven by the
    /// recipient's key capability).
    public var postQuantumKeygen: PostQuantumPolicy

    public init(
        bcc: BccPolicy = .refuse,
        envelope: EncryptionEnvelopePolicy = .automatic,
        autocrypt: AutocryptEmitPolicy = .always(),
        postQuantumKeygen: PostQuantumPolicy = .classical
    ) {
        self.bcc = bcc
        self.envelope = envelope
        self.autocrypt = autocrypt
        self.postQuantumKeygen = postQuantumKeygen
    }

    /// Safe defaults for opportunistic-encryption users. Same as the
    /// default initializer; named for readability at call sites.
    public static let recommended = ComposePolicy()

    /// Maximum-compatibility set: legacy envelope, no Autocrypt, classical PQ.
    /// Use for correspondents on very old PGP clients.
    public static let maximumCompatibility = ComposePolicy(
        bcc: .refuse,
        envelope: .forceLegacy,
        autocrypt: .never,
        postQuantumKeygen: .classical
    )

    /// Maximum-security set: AEAD enforced, Autocrypt mutual, hybrid PQ keygen.
    /// Use for power users who correspond only with modern clients.
    public static let maximumSecurity = ComposePolicy(
        bcc: .refuse,
        envelope: .forceAEAD,
        autocrypt: .always(preferEncrypt: .mutual),
        postQuantumKeygen: .hybrid
    )
}

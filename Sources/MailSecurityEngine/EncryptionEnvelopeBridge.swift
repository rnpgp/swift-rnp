//
//  EncryptionEnvelopeBridge.swift
//  MailSecurityEngine
//
//  Bridge from the pure `EncryptionEnvelopeResolver.Decision` to the
//  Rnp encrypt-operation parameters. Kept separate from both the
//  resolver and the encoder so neither knows about the other's
//  representation (MECE).
//

import Foundation
import Rnp

/// Translation of an envelope decision into the parameters the FFI
/// `encrypt(...:aead:pkeskVersion:...)` call expects.
public struct EncryptEnvelopeParameters: Equatable, Sendable {
    public let aead: Rnp.EncryptAEAD
    public let pkeskVersion: Rnp.EncryptPKESKVersion

    public init(aead: Rnp.EncryptAEAD, pkeskVersion: Rnp.EncryptPKESKVersion) {
        self.aead = aead
        self.pkeskVersion = pkeskVersion
    }

    /// The legacy default: CFB + MDC, PKESK v3.
    public static let legacy = EncryptEnvelopeParameters(aead: .none, pkeskVersion: .v3)
}

public extension EncryptionEnvelopeResolver.Decision {
    /// Translates the resolver decision into Rnp encrypt parameters.
    /// Returns `nil` for `.refused`; callers must guard before encoding.
    var encryptParameters: EncryptEnvelopeParameters? {
        switch self {
        case .aeadOCBWithV6PKESK:
            return EncryptEnvelopeParameters(aead: .ocb, pkeskVersion: .v6)
        case .aeadOCBWithV3PKESK:
            return EncryptEnvelopeParameters(aead: .ocb, pkeskVersion: .v3)
        case .cfbWithMDC:
            return EncryptEnvelopeParameters(aead: .none, pkeskVersion: .v3)
        case .refused:
            return nil
        }
    }
}

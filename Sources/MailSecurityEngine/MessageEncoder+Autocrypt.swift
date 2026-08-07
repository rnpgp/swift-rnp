//
//  MessageEncoder+Autocrypt.swift
//  MailSecurityEngine
//
//  Autocrypt header emit, additive on `MessageEncoder`. The encoder calls
//  `AutocryptEmitPolicy.resolve(...)` once per outgoing message to decide
//  whether to attach a header, then `AutocryptHeaderBuilder.build(...)`
//  produces the header value. Both are pure; the only FFI call is the
//  existing `RnpKey.exportAutocryptKey` from the Rnp module.
//
//  OCP: existing `encodePGPMime` / `encodeInline` are unchanged. Callers
//  that want Autocrypt call the new entry point
//  `encodePGPMimeIncludingAutocrypt(...)` instead. A future refactor can
//  fold the new entry point into the base one with a default policy
//  argument.
//

import Autocrypt
import Foundation
import Librnp

/// User-facing policy controlling when the Autocrypt header is emitted.
public enum AutocryptEmitPolicy: Equatable, Sendable {
    /// Default. Emit on every signed or encrypted outgoing message, plus
    /// on plaintext replies when `prefer-encrypt=mutual`. Matches the
    /// Autocrypt level 1 recommendation.
    case always(preferEncrypt: AutocryptPreferEncrypt = .mutual)

    /// Emit only when the message is encrypted.
    case onlyWhenEncrypted(preferEncrypt: AutocryptPreferEncrypt = .mutual)

    /// Never emit. Used when the user has disabled Autocrypt in Settings.
    case never
}

/// Decision produced by `AutocryptEmitPolicy.resolve(...)`. Carries the
/// resolved prefer-encrypt value or indicates the header should be
/// skipped.
public enum AutocryptEmitDecision: Equatable, Sendable {
    case emit(preferEncrypt: AutocryptPreferEncrypt, address: String)
    case skip
}

public extension AutocryptEmitPolicy {
    /// Resolves the policy against the outgoing message context.
    /// - Parameters:
    ///   - signerAddress: the From: address that the header should be
    ///     keyed on. Required for emit decisions.
    ///   - isEncrypted: whether the outgoing message will be encrypted.
    ///   - isSigned: whether the outgoing message will be signed.
    func resolve(
        signerAddress: String?,
        isEncrypted: Bool,
        isSigned: Bool
    ) -> AutocryptEmitDecision {
        guard let signerAddress, !signerAddress.isEmpty else {
            return .skip
        }
        switch self {
        case let .always(preferEncrypt):
            if isEncrypted || isSigned {
                return .emit(preferEncrypt: preferEncrypt, address: signerAddress)
            }
            // Plaintext unsigned: emit only when prefer-encrypt is mutual,
            // matching the level 1 opportunistic-encryption flow.
            return preferEncrypt == .mutual
                ? .emit(preferEncrypt: preferEncrypt, address: signerAddress)
                : .skip
        case let .onlyWhenEncrypted(preferEncrypt):
            return isEncrypted
                ? .emit(preferEncrypt: preferEncrypt, address: signerAddress)
                : .skip
        case .never:
            return .skip
        }
    }
}

/// Builds the `Autocrypt:` header value via the librnp FFI. Pure on top
/// of the FFI: same inputs produce the same header value.
public enum AutocryptHeaderBuilder {
    /// Produces the header value, or `nil` when the FFI cannot produce a
    /// minimal key (e.g., the signer has no encryption subkey).
    public static func build(
        signerKey: RnpKey,
        address: String,
        preferEncrypt: AutocryptPreferEncrypt,
        userID: String? = nil
    ) throws -> String? {
        let keydata = try signerKey.exportAutocryptKey(uid: userID, base64: true)
        guard !keydata.isEmpty else { return nil }
        let keydataBase64 = keydata.base64EncodedString()
        return AutocryptHeader(
            address: address,
            preferEncrypt: preferEncrypt,
            keydataBase64: keydataBase64
        ).renderedHeaderValue()
    }
}

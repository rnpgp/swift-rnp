//
//  MailSecurityEngine.swift
//  swift-rnp
//
//  OpenPGP message security engine for Apple Mail extensions.
//
//  The engine encodes (signs and/or encrypts) and decodes (decrypts and
//  verifies) RFC 822 message data in PGP/MIME (RFC 3156) and inline-PGP
//  forms. It contains no MailKit types, so the whole pipeline is testable
//  with plain XCTest; the MailKit target adapts `MEMessageSecurityHandler`
//  callbacks to this API.
//

import Autocrypt
import Foundation
import Rnp
import TrustStore

/// Wire format used when encoding a message.
public enum MessageFormat {
    /// PGP/MIME (RFC 3156): multipart/signed and multipart/encrypted
    /// structures. Handles arbitrary MIME content, including attachments.
    case pgpMime
    /// Inline PGP: ASCII-armored OpenPGP data inside a text/plain body.
    /// Only suitable for single-part text messages.
    case inlinePGP
}

/// Parameters of an encode operation.
public struct EncodingRequest {
    /// Raw RFC 822 message data, as handed to the extension by Mail.
    public var message: Data
    /// Sender address or user ID; the signing key is resolved from it.
    public var sender: String
    /// Recipient addresses; encryption keys are resolved from them.
    public var recipients: [String]
    /// BCC recipient addresses, when known separately from the flat
    /// `recipients` list. The BCC policy reads this to decide whether
    /// encrypted send should be refused. Empty by default (back-compat
    /// with callers that only supply the flat list).
    public var bccAddresses: [String]
    public var sign: Bool
    public var encrypt: Bool
    public var format: MessageFormat

    public init(
        message: Data,
        sender: String,
        recipients: [String],
        sign: Bool,
        encrypt: Bool,
        format: MessageFormat = .pgpMime,
        bccAddresses: [String] = []
    ) {
        self.message = message
        self.sender = sender
        self.recipients = recipients
        self.sign = sign
        self.encrypt = encrypt
        self.format = format
        self.bccAddresses = bccAddresses
    }
}

/// Result of an encode operation.
public struct EncodedMessage {
    /// The encoded RFC 822 message data to hand back to Mail.
    public var rawData: Data
    public let isSigned: Bool
    public let isEncrypted: Bool

    public init(rawData: Data, isSigned: Bool, isEncrypted: Bool) {
        self.rawData = rawData
        self.isSigned = isSigned
        self.isEncrypted = isEncrypted
    }
}

/// Capability report used for Mail's compose-window status.
public struct EncodingStatus {
    /// A secret signing key is available for the sender.
    public let canSign: Bool
    /// Public keys are available for every recipient.
    public let canEncrypt: Bool
    /// Recipients for which no public key was found.
    public let missingRecipientKeys: [String]

    public init(canSign: Bool, canEncrypt: Bool, missingRecipientKeys: [String]) {
        self.canSign = canSign
        self.canEncrypt = canEncrypt
        self.missingRecipientKeys = missingRecipientKeys
    }
}

/// One verified signer of a decoded message.
public struct SignerInfo: Equatable {
    /// Fingerprint of the signing key, when known to the keyring.
    public let fingerprint: String?
    /// Primary user ID of the signing key, when known to the keyring.
    public let userID: String?
    /// Verification status of the signature.
    public let status: RnpSignatureStatus

    public init(fingerprint: String?, userID: String?, status: RnpSignatureStatus) {
        self.fingerprint = fingerprint
        self.userID = userID
        self.status = status
    }
}

/// Security outcome of a decode operation, mapped by the MailKit layer to
/// `MEMessageSecurityInformation`.
public struct SecurityInformation {
    /// The message was encrypted (and successfully decrypted).
    public let isEncrypted: Bool
    /// Signatures found in the message, with per-signature status.
    public let signers: [SignerInfo]
    /// Signing-side failure to report (invalid signature, unknown signer).
    public let signingError: Error?
    /// Encryption-side failure to report (undecryptable message).
    public let encryptionError: Error?

    public init(
        isEncrypted: Bool,
        signers: [SignerInfo],
        signingError: Error?,
        encryptionError: Error?
    ) {
        self.isEncrypted = isEncrypted
        self.signers = signers
        self.signingError = signingError
        self.encryptionError = encryptionError
    }

    /// Whether at least one signature verified successfully.
    public var hasValidSignature: Bool {
        signers.contains { $0.status == .valid }
    }
}

/// Result of a decode operation.
public struct DecodedMessage {
    /// The decoded RFC 822 message for display, or `nil` when the original
    /// message should be shown as-is (e.g. decryption failed).
    public let data: Data?
    public let security: SecurityInformation

    public init(data: Data?, security: SecurityInformation) {
        self.data = data
        self.security = security
    }
}

/// Errors thrown by `MailSecurityEngine`.
public enum MailSecurityError: Error, Equatable {
    /// The message handed to `encode` is empty.
    case emptyMessage
    /// No secret key is available for the sender address.
    case noSecretKeyForSender(String)
    /// No public keys were found for the listed recipients.
    case missingRecipientKeys([String])
    /// Inline PGP cannot protect multipart messages (attachments).
    case multipartNotSupportedForInline
    /// The PGP/MIME structure of the message is malformed.
    case malformedMessage(String)
    /// The signature does not verify; the message was modified in transit.
    case signatureInvalid
    /// The signer's public key is not in the keyring.
    case signatureUnknownSigner
    /// A recipient has an unresolved key-change conflict.
    case trustConflict(String)
}

extension MailSecurityError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .emptyMessage:
            return "The message is empty."
        case let .noSecretKeyForSender(sender):
            return "No secret key found for \(sender). Generate or import one in the container app."
        case let .missingRecipientKeys(recipients):
            return "No public key found for: \(recipients.joined(separator: ", "))."
        case .multipartNotSupportedForInline:
            return "Inline PGP does not support messages with attachments; use PGP/MIME."
        case let .malformedMessage(reason):
            return "Malformed PGP/MIME message: \(reason)."
        case .signatureInvalid:
            return "The OpenPGP signature does not verify; the message was modified."
        case .signatureUnknownSigner:
            return "The signer's public key is not in the keyring."
        case let .trustConflict(recipient):
            return "The key for \(recipient) changed. Verify the new fingerprint before encrypting."
        }
    }
}

/// OpenPGP security engine for the Mail extension.
///
/// All operations are serialized through the key manager's lock, so a shared
/// instance can serve MailKit callbacks from any thread.
public final class MailSecurityEngine {
    /// The key manager backing this engine.
    public let keyManager: KeyManager

    /// Per-address Autocrypt observation store, fed from incoming mail
    /// by `MessageDecoder`. Lazily created on first access so existing
    /// callers pay no cost. The store lives in the engine's keyring
    /// directory (`<dir>/Autocrypt/autocrypt.json`).
    public private(set) lazy var autocryptStore: AutocryptStore = {
        let url = keyManager.directory
            .appendingPathComponent("Autocrypt", isDirectory: true)
            .appendingPathComponent("autocrypt.json")
        if let store = try? AutocryptStore(storeURL: url) {
            return store
        }
        return AutocryptStore.inMemory()
    }()

    public init(keyManager: KeyManager) {
        self.keyManager = keyManager
    }

    /// Convenience initializer building a key manager in-place.
    public convenience init(directory: URL, passphraseProvider: @escaping Rnp.PassphraseProvider) throws {
        self.init(keyManager: try KeyManager(directory: directory, passphraseProvider: passphraseProvider))
    }

    // MARK: - Encoding

    /// Reports signing/encryption capability for the compose window.
    public func encodingStatus(sender: String, recipients: [String]) throws -> EncodingStatus {
        try keyManager.withRnp { rnp in
            let canSign = try keyManager.secretKeyUnlocked(forUserID: sender, rnp: rnp) != nil
            var missing: [String] = []
            for recipient in recipients {
                if try keyManager.publicKeyUnlocked(for: recipient, rnp: rnp) == nil {
                    missing.append(recipient)
                }
            }
            return EncodingStatus(
                canSign: canSign,
                canEncrypt: !recipients.isEmpty && missing.isEmpty,
                missingRecipientKeys: missing
            )
        }
    }

    /// Signs and/or encrypts an outgoing message.
    ///
    /// With both `sign` and `encrypt` off the message passes through
    /// unchanged. Failures throw `MailSecurityError` (key resolution,
    /// malformed input) or `RnpError` (crypto failures, e.g. a wrong
    /// passphrase from the provider).
    public func encode(_ request: EncodingRequest) throws -> EncodedMessage {
        guard !request.message.isEmpty else {
            throw MailSecurityError.emptyMessage
        }
        guard request.sign || request.encrypt else {
            return EncodedMessage(rawData: request.message, isSigned: false, isEncrypted: false)
        }
        return try keyManager.withRnp { rnp in
            var signer: RnpKey?
            if request.sign {
                guard let key = try keyManager.secretKeyUnlocked(forUserID: request.sender, rnp: rnp) else {
                    throw MailSecurityError.noSecretKeyForSender(request.sender)
                }
                signer = key
            }
            var recipientKeys: [RnpKey] = []
            if request.encrypt {
                var missing: [String] = []
                for recipient in request.recipients {
                    if let key = try keyManager.publicKeyUnlocked(for: recipient, rnp: rnp) {
                        let fingerprint = try key.fingerprint
                        // Auto-flag expired or revoked recipient keys as problem so
                        // the trust store surfaces them in the UI and the banner.
                        if try key.isRevoked || key.isExpired {
                            try keyManager.trustStore.markProblem(fingerprint: fingerprint)
                        }
                        // The sender's own key is implicitly trusted
                        // (encrypt-to-self): a trust problem or key-change
                        // conflict recorded for the sender's address must not
                        // block encrypting to oneself.
                        let isSender = KeyManager.addressesMatch(recipient, request.sender)
                        if !isSender,
                           keyManager.trustStore.state(forFpr: fingerprint) == .problem
                            || keyManager.trustStore.hasConflict(forEmail: recipient)
                        {
                            throw MailSecurityError.trustConflict(recipient)
                        }
                        recipientKeys.append(key)
                    } else {
                        missing.append(recipient)
                    }
                }
                guard missing.isEmpty, !recipientKeys.isEmpty else {
                    throw MailSecurityError.missingRecipientKeys(missing)
                }
            }
            switch request.format {
            case .pgpMime:
                return try encodePGPMime(request, signer: signer, recipients: recipientKeys, rnp: rnp)
            case .inlinePGP:
                return try encodeInline(request, signer: signer, recipients: recipientKeys, rnp: rnp)
            }
        }
    }

    // MARK: - Decoding

    /// Decrypts and/or verifies an incoming message.
    ///
    /// - Returns: the decoded message and its security information, or `nil`
    ///   when the message carries no OpenPGP content at all — the MailKit
    ///   layer must then return `nil` as well so Mail shows the message
    ///   untouched.
    /// - Throws: only for structurally malformed input; cryptographic
    ///   failures (undecryptable data, invalid signatures) are reported via
    ///   `SecurityInformation`, not thrown.
    public func decode(_ message: Data) throws -> DecodedMessage? {
        guard !message.isEmpty else {
            return nil
        }
        observeAutocryptIfPresent(in: message)
        return try keyManager.withRnp { rnp in
            try decodeUnlocked(message, rnp: rnp)
        }
    }

    /// Best-effort Autocrypt header observation on incoming mail. Runs
    /// before the crypto decode so the store is updated for every
    /// message, not just OpenPGP ones. Failures (no Autocrypt header,
    /// malformed value, persistence error) are silently swallowed —
    /// Autocrypt is opportunistic and must not block decode.
    private func observeAutocryptIfPresent(in message: Data) {
        let parsed = MimeMessage.parse(message)
        let date = parseMessageDate(parsed) ?? Date()
        for header in parsed.headers where header.name.lowercased() == "autocrypt" {
            try? autocryptStore.observe(rawHeader: header.value, messageDate: date)
        }
    }

    /// Parses the `Date:` header (RFC 5322 §3.6.1) into a `Date`.
    /// Returns `nil` when the header is absent or unparseable.
    private func parseMessageDate(_ message: MimeMessage) -> Date? {
        guard let raw = message.header("Date") else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
        return formatter.date(from: raw.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    // MARK: - Shared helpers

    /// Maps verified signatures to signer infos, resolving user IDs against
    /// the keyring. Caller must hold the key manager lock.
    func signerInfos(_ signatures: [RnpSignatureInfo], rnp: Rnp) -> [SignerInfo] {
        signatures.map { signature in
            var userID: String?
            if let fingerprint = signature.fingerprint,
               let key = try? rnp.locateKey(fingerprint, type: .fingerprint)
            {
                userID = try? key.primaryUserID
            }
            return SignerInfo(
                fingerprint: signature.fingerprint,
                userID: userID,
                status: signature.status
            )
        }
    }

    /// Signing-side error for a signature list that failed to verify.
    func signingError(for signers: [SignerInfo]) -> Error? {
        guard !signers.isEmpty, !signers.contains(where: { $0.status == .valid }) else {
            return nil
        }
        if signers.contains(where: { $0.status == .signerUnknown }) {
            return MailSecurityError.signatureUnknownSigner
        }
        return MailSecurityError.signatureInvalid
    }

    /// Serializes headers and body into RFC 822 data.
    func serialize(headers: [MimeMessage.Header], body: Data, eol: EndOfLine) -> Data {
        var data = Data()
        for header in headers {
            data.append(Data("\(header.name): \(header.value)".utf8))
            data.append(eol.data)
        }
        data.append(eol.data)
        data.append(body)
        return data
    }
}

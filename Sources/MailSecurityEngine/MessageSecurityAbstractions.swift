//
//  MessageSecurityAbstractions.swift
//  swift-rnp
//
//  Protocol abstractions and result types for the message-security handler.
//  These mirror the MailKit surface so the core logic can be unit-tested
//  without loading Mail.app.
//

import Foundation

/// A message as the handler sees it, mirroring `MEMessage`.
public protocol MailMessage {
    /// RFC 822 message data, if available.
    var rawData: Data? { get }
    /// Sender address (raw string).
    var fromAddress: String { get }
    /// All recipient addresses (To/Cc/Bcc), raw strings.
    var recipientAddresses: [String] { get }
    /// Whether the message is being sent (not a draft/received copy).
    var isSending: Bool { get }
    /// To-recipient addresses only, raw strings. Defaulted to `[]` so
    /// existing conformers continue to compile; consumers that care about
    /// BCC handling should override.
    var toAddresses: [String] { get }
    /// Cc-recipient addresses only. See `toAddresses`.
    var ccAddresses: [String] { get }
    /// Bcc-recipient addresses only. See `toAddresses`.
    var bccAddresses: [String] { get }
}

extension MailMessage {
    /// Default To/Cc/Bcc split for conformers that have not been updated:
    /// everything is in `recipientAddresses`, BCC and Cc are empty. This
    /// preserves backward compatibility (no BCC handling) for existing
    /// conformers while letting new conformers surface the breakdown.
    public var toAddresses: [String] { recipientAddresses }
    public var ccAddresses: [String] { [] }
    public var bccAddresses: [String] { [] }
}

/// Compose context, mirroring `MEComposeContext`.
public protocol MailComposeContext {
    var shouldSign: Bool { get }
    var shouldEncrypt: Bool { get }
}

/// A signer as the handler sees it, mirroring `MEMessageSigner`.
public protocol MailMessageSigner {
    /// Signer email addresses as raw strings.
    var signerEmailAddresses: [String] { get }
    /// Human-readable signer label.
    var signerLabel: String { get }
    /// Opaque context data attached by the handler.
    var context: Data { get }
}

/// Status reported for an outgoing message, mirroring `MEOutgoingMessageEncodingStatus`.
public struct HandlerEncodingStatus {
    public var canSign: Bool
    public var canEncrypt: Bool
    public var securityError: Error?
    public var addressesFailingEncryption: [String]

    public init(canSign: Bool, canEncrypt: Bool, securityError: Error? = nil, addressesFailingEncryption: [String] = []) {
        self.canSign = canSign
        self.canEncrypt = canEncrypt
        self.securityError = securityError
        self.addressesFailingEncryption = addressesFailingEncryption
    }
}

/// Encoded outgoing message, mirroring `MEEncodedOutgoingMessage`.
public struct HandlerEncodedMessage {
    public var rawData: Data
    public var isSigned: Bool
    public var isEncrypted: Bool

    public init(rawData: Data, isSigned: Bool, isEncrypted: Bool) {
        self.rawData = rawData
        self.isSigned = isSigned
        self.isEncrypted = isEncrypted
    }
}

/// Result of an encode operation, mirroring `MEMessageEncodingResult`.
public struct HandlerEncodingResult {
    public var encodedMessage: HandlerEncodedMessage?
    public var signingError: Error?
    public var encryptionError: Error?

    public init(encodedMessage: HandlerEncodedMessage?, signingError: Error?, encryptionError: Error?) {
        self.encodedMessage = encodedMessage
        self.signingError = signingError
        self.encryptionError = encryptionError
    }
}

/// Signer info carried in a decoded message's security information.
public struct HandlerSignerInfo: MailMessageSigner {
    public var emailAddresses: [String]
    public var signatureLabel: String
    public var context: Data

    public init(emailAddresses: [String], signatureLabel: String, context: Data) {
        self.emailAddresses = emailAddresses
        self.signatureLabel = signatureLabel
        self.context = context
    }

    public var signerEmailAddresses: [String] { emailAddresses }
    public var signerLabel: String { signatureLabel }
}

/// Security information for a decoded message, mirroring `MEMessageSecurityInformation`.
public struct HandlerSecurityInformation {
    public var signers: [HandlerSignerInfo]
    public var isEncrypted: Bool
    public var signingError: Error?
    public var encryptionError: Error?

    public init(signers: [HandlerSignerInfo], isEncrypted: Bool, signingError: Error?, encryptionError: Error?) {
        self.signers = signers
        self.isEncrypted = isEncrypted
        self.signingError = signingError
        self.encryptionError = encryptionError
    }
}

/// Decoded message, mirroring `MEDecodedMessage`.
public struct HandlerDecodedMessage {
    public var data: Data?
    public var securityInformation: HandlerSecurityInformation

    public init(data: Data?, securityInformation: HandlerSecurityInformation) {
        self.data = data
        self.securityInformation = securityInformation
    }
}

//
//  SecurityStateRecorder.swift
//  swift-rnp
//
//  Persists the outcome of message decoding as small JSON records so the
//  end-to-end test harness (scripts/test-mail-e2e*.sh) can assert the
//  security-banner state without reading MailKit UI. Written on a
//  best-effort basis: a failing write must never break decoding.
//

import Foundation

/// One signer in a recorded decode outcome.
public struct RecordedSigner: Codable, Equatable, Sendable {
    /// Display label, matching the banner signer label (user ID or fingerprint).
    public let label: String
    /// OpenPGP fingerprint of the signing key, when known to the keyring.
    public let fingerprint: String?
    /// `RnpSignatureStatus` raw value ("valid", "invalid", ...).
    public let status: String
    /// `TrustState` raw value for the signing key ("unverified", "verified",
    /// "problem"), when the fingerprint is known. Together with `status` this
    /// determines the banner line ("Verified key" / "Key not verified" /
    /// "Key problem", see `mapSignerTrust`).
    public let trust: String?

    public init(label: String, fingerprint: String?, status: String, trust: String?) {
        self.label = label
        self.fingerprint = fingerprint
        self.status = status
        self.trust = trust
    }
}

/// Recorded security outcome of one decoded message.
public struct RecordedMessageSecurity: Codable, Equatable, Sendable {
    /// Record format version; bump when fields change.
    public let recordVersion: Int
    /// RFC 822 `Message-ID` header, when present.
    public let messageID: String?
    /// RFC 822 `Subject` header, when present.
    public let subject: String?
    /// RFC 822 `From` header, when present.
    public let from: String?
    /// The message was encrypted (and could be decrypted).
    public let isEncrypted: Bool
    /// Signatures found in the message, with per-signer status and trust.
    public let signers: [RecordedSigner]
    /// Signing-side failure description, when any.
    public let signingError: String?
    /// Encryption-side failure description, when any.
    public let encryptionError: String?
    /// When the record was written.
    public let recordedAt: Date

    public init(
        recordVersion: Int = 1,
        messageID: String?,
        subject: String?,
        from: String?,
        isEncrypted: Bool,
        signers: [RecordedSigner],
        signingError: String?,
        encryptionError: String?,
        recordedAt: Date = Date()
    ) {
        self.recordVersion = recordVersion
        self.messageID = messageID
        self.subject = subject
        self.from = from
        self.isEncrypted = isEncrypted
        self.signers = signers
        self.signingError = signingError
        self.encryptionError = encryptionError
        self.recordedAt = recordedAt
    }
}

/// Writes decode outcomes as JSON files into a state directory.
///
/// Layout inside `directory`:
/// - `last-message.json`: the most recent record (overwritten each time).
/// - `messages/<sanitized-message-id>.json`: one file per message, so a test
///   can correlate the banner state with a specific message even when other
///   messages are decoded in between.
///
/// All writes are atomic and best-effort; failures are logged, not thrown.
public final class SecurityStateRecorder {
    /// Directory the records are written into.
    public let directory: URL

    public init(directory: URL) {
        self.directory = directory
    }

    /// File name used for the per-message record of the given Message-ID.
    public static func stateFilename(forMessageID messageID: String) -> String {
        sanitizedMessageID(messageID) + ".json"
    }

    /// Maps a Message-ID to a filesystem-safe token. Keep in sync with the
    /// test harness, which computes the same name with
    /// `LC_ALL=C tr -c 'A-Za-z0-9' '-'`.
    public static func sanitizedMessageID(_ messageID: String) -> String {
        String(messageID.map { character -> Character in
            guard character.isASCII, character.isLetter || character.isNumber else {
                return "-"
            }
            return character
        })
    }

    /// Persists the record. Best-effort: encoding or I/O failures only log.
    public func record(_ record: RecordedMessageSecurity) {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(record)

            let fileManager = FileManager.default
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
            try data.write(
                to: directory.appendingPathComponent("last-message.json"),
                options: .atomic
            )
            if let messageID = record.messageID, !messageID.isEmpty {
                let messagesDirectory = directory.appendingPathComponent("messages", isDirectory: true)
                try fileManager.createDirectory(at: messagesDirectory, withIntermediateDirectories: true)
                try data.write(
                    to: messagesDirectory.appendingPathComponent(Self.stateFilename(forMessageID: messageID)),
                    options: .atomic
                )
            }
        } catch {
            NSLog("SecurityStateRecorder: failed to write state record: \(error.localizedDescription)")
        }
    }
}

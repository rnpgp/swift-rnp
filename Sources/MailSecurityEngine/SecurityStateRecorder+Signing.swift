//
//  SecurityStateRecorder+Signing.swift
//  MailSecurityEngine
//
//  Promotes the existing SecurityStateRecorder output to tamper-evident
//  signed records, matching the pattern used by TrustStore and
//  KeyStateStore. Records are written alongside a `.sig` file holding
//  a detached Ed25519 signature; readers verify and fail-closed to
//  "no record" on tamper.
//
//  Additive: the base recorder stays unchanged for callers that don't
//  configure a signing key. Callers that do get signed records via a
//  new initializer and a reader (`SecurityStateRecordStore`) that
//  verifies them.
//

import CryptoKit
import Foundation
import KeyStateStore
import Security

/// Errors thrown by `SecurityStateRecordStore` (the reader for signed
/// `SecurityStateRecorder` output).
public enum SecurityStateRecordStoreError: Error, Equatable {
    case persistenceFailed(String)
    case tampered
}

/// Reader for signed SecurityStateRecorder output. Loads records from
/// disk, verifies each one's detached signature, and fails closed to
/// "no record" on tamper (same pattern as TrustStore / KeyStateStore).
///
/// The signing key is created at first launch and stored in the
/// Keychain (per-install, distinct from TrustStore's and
/// KeyStateStore's). This means a compromise of one store's key
/// cannot forge records in another.
public final class SecurityStateRecordStore {
    public static let lastMessageFilename = "last-message.json"
    public static let lastMessageSignatureFilename = "last-message.json.sig"
    public static let messagesSubdirectory = "messages"

    private static let signingKeyService = "RNP for Mail state signing key"
    private static let signingKeyAccount = "security-state"

    public let directory: URL
    public let privateKey: Curve25519.Signing.PrivateKey

    private let lock = NSLock()

    public init(
        directory: URL,
        keychainAccessGroup: String? = Bundle.main.object(forInfoDictionaryKey: "RNPMAILKeychainAccessGroup") as? String
    ) throws {
        self.directory = directory
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let key = try KeychainSigningKeyHelper.loadOrCreate(
            service: Self.signingKeyService,
            account: Self.signingKeyAccount,
            keychainAccessGroup: keychainAccessGroup
        )
        self.privateKey = key
    }

    /// Returns the most recent signed record, or `nil` if no record
    /// exists or the record's signature failed verification.
    public func loadLastMessage() throws -> RecordedMessageSecurity? {
        try loadVerified(
            recordURL: directory.appendingPathComponent(Self.lastMessageFilename),
            signatureURL: directory.appendingPathComponent(Self.lastMessageSignatureFilename)
        )
    }

    /// Returns the signed record for a Message-ID, or `nil` when the
    /// record is absent or tampered.
    public func loadRecord(forMessageID messageID: String) throws -> RecordedMessageSecurity? {
        let messagesDir = directory.appendingPathComponent(Self.messagesSubdirectory, isDirectory: true)
        let recordURL = messagesDir.appendingPathComponent(SecurityStateRecorder.stateFilename(forMessageID: messageID))
        let signatureURL = messagesDir.appendingPathComponent(
            SecurityStateRecorder.stateFilename(forMessageID: messageID) + ".sig"
        )
        return try loadVerified(recordURL: recordURL, signatureURL: signatureURL)
    }

    /// All per-message records currently in the store, with their
    /// signature status. Useful for diagnostics.
    public func loadAllRecords() -> [(record: RecordedMessageSecurity, signatureValid: Bool)] {
        let messagesDir = directory.appendingPathComponent(Self.messagesSubdirectory, isDirectory: true)
        guard let entries = try? FileManager.default.contentsOfDirectory(at: messagesDir, includingPropertiesForKeys: nil)
        else { return [] }
        var result: [(RecordedMessageSecurity, Bool)] = []
        for entry in entries where entry.pathExtension == "json" {
            let sigURL = entry.deletingPathExtension().appendingPathExtension("json.sig")
            do {
                if let signed = try loadVerified(recordURL: entry, signatureURL: sigURL) {
                    result.append((signed, true))
                    continue
                }
            } catch {
                // Tampered or unparseable; fall through to the
                // unsigned-attempt path below.
            }
            if let data = try? Data(contentsOf: entry) {
                let decoder = JSONDecoder()
                decoder.dateDecodingStrategy = .iso8601
                if let record = try? decoder.decode(RecordedMessageSecurity.self, from: data) {
                    result.append((record, false))
                }
            }
        }
        return result
    }

    /// Migrates any unsigned records (no `.sig` file alongside) by
    /// signing them in place. Called once at app launch by callers
    /// that opt into signed records.
    public func migrateUnsignedRecords() {
        signIfMissing(
            recordURL: directory.appendingPathComponent(Self.lastMessageFilename),
            signatureURL: directory.appendingPathComponent(Self.lastMessageSignatureFilename)
        )
        let messagesDir = directory.appendingPathComponent(Self.messagesSubdirectory, isDirectory: true)
        guard let entries = try? FileManager.default.contentsOfDirectory(at: messagesDir, includingPropertiesForKeys: nil)
        else { return }
        for entry in entries where entry.pathExtension == "json" {
            let sigURL = entry.deletingPathExtension().appendingPathExtension("json.sig")
            signIfMissing(recordURL: entry, signatureURL: sigURL)
        }
    }

    // MARK: - Internals

    private func loadVerified(
        recordURL: URL,
        signatureURL: URL
    ) throws -> RecordedMessageSecurity? {
        guard FileManager.default.fileExists(atPath: recordURL.path),
              FileManager.default.fileExists(atPath: signatureURL.path)
        else { return nil }
        let data: Data
        let signature: Data
        do {
            data = try Data(contentsOf: recordURL)
            signature = try Data(contentsOf: signatureURL)
        } catch {
            throw SecurityStateRecordStoreError.persistenceFailed(error.localizedDescription)
        }
        guard privateKey.publicKey.isValidSignature(signature, for: data) else {
            throw SecurityStateRecordStoreError.tampered
        }
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return try decoder.decode(RecordedMessageSecurity.self, from: data)
        } catch {
            throw SecurityStateRecordStoreError.persistenceFailed(error.localizedDescription)
        }
    }

    private func signIfMissing(recordURL: URL, signatureURL: URL) {
        guard FileManager.default.fileExists(atPath: recordURL.path),
              !FileManager.default.fileExists(atPath: signatureURL.path)
        else { return }
        guard let data = try? Data(contentsOf: recordURL),
              let signature = try? privateKey.signature(for: data)
        else { return }
        try? signature.write(to: signatureURL, options: [.atomic])
    }
}

/// Additive convenience: SecurityStateRecorder gains a `signedRecorder`
/// property when given access to a SecurityStateRecordStore. After
/// record-write, the signature file is also written. The base class
/// stays unchanged.
public extension SecurityStateRecorder {
    /// Records + signs in one call. The signature file is written
    /// next to each JSON file. Failures are still logged, not thrown,
    /// to preserve the recorder's best-effort contract.
    func record(_ entry: RecordedMessageSecurity, signingWith store: SecurityStateRecordStore) {
        record(entry)
        // Sign the last-message.json and any per-message file written.
        let lastURL = directory.appendingPathComponent(SecurityStateRecordStore.lastMessageFilename)
        signIfPossible(at: lastURL, with: store)
        if let messageID = entry.messageID, !messageID.isEmpty {
            let messagesDir = directory.appendingPathComponent(SecurityStateRecordStore.messagesSubdirectory, isDirectory: true)
            let perMessageURL = messagesDir.appendingPathComponent(SecurityStateRecorder.stateFilename(forMessageID: messageID))
            signIfPossible(at: perMessageURL, with: store)
        }
    }

    private func signIfPossible(at recordURL: URL, with store: SecurityStateRecordStore) {
        guard let data = try? Data(contentsOf: recordURL),
              let signature = try? store.privateKey.signature(for: data)
        else { return }
        let actualSigURL = recordURL.deletingPathExtension().appendingPathExtension("json.sig")
        try? signature.write(to: actualSigURL, options: [.atomic])
    }
}

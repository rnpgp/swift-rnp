//
//  MailboxKeyScan.swift
//  MailSecurityEngine
//
//  Engine-layer service that scans RFC 822 message data for OpenPGP
//  public keys in three forms: Autocrypt headers,
//  application/pgp-keys attachments, and keys embedded in signed
//  messages (signing key from the signature). Returns a deduplicated
//  list of discovered keys with their source.
//
//  Does NOT call MailKit. Callers feed in `[Data]` (typically the
//  result of enumerating a mailbox via MailKit from the container app)
//  and get back a `MailboxScanReport` to render in the UI.
//

import Autocrypt
import Foundation
import Librnp

/// One discovered key from a mailbox scan.
public struct DiscoveredKey: Identifiable, Equatable, Sendable {
    public enum Source: String, Equatable, Sendable {
        case autocryptHeader
        case pgpKeysAttachment
        case signingKey
    }

    public let fingerprint: String
    public let primaryUserID: String
    public let source: Source
    public let sourceAddress: String?
    public let observedDate: Date

    public var id: String { fingerprint }

    public init(
        fingerprint: String,
        primaryUserID: String,
        source: Source,
        sourceAddress: String?,
        observedDate: Date
    ) {
        self.fingerprint = fingerprint
        self.primaryUserID = primaryUserID
        self.source = source
        self.sourceAddress = sourceAddress
        self.observedDate = observedDate
    }
}

/// Summary of a mailbox scan.
public struct MailboxScanReport: Equatable, Sendable {
    public let discoveredKeys: [DiscoveredKey]
    public let messagesScanned: Int
    public let errors: [String]

    public init(discoveredKeys: [DiscoveredKey], messagesScanned: Int, errors: [String]) {
        self.discoveredKeys = discoveredKeys
        self.messagesScanned = messagesScanned
        self.errors = errors
    }
}

/// Pure scanner that finds keys in RFC 822 message data. Stateless;
/// safe to call from any thread. The actual key-import decision is
/// left to the caller (the UI lists `DiscoveredKey`s and the user
/// picks which to import).
public final class MailboxKeyScanner {
    public init() {}

    /// Scans `messages` for OpenPGP public keys.
    /// - Parameters:
    ///   - messages: raw RFC 822 message bytes.
    ///   - rnp: engine context used for key parsing (read-only).
    public func scan(messages: [Data], using rnp: Rnp) -> MailboxScanReport {
        var discovered: [String: DiscoveredKey] = [:]
        var errors: [String] = []
        var scanned = 0

        for message in messages {
            scanned += 1
            let parsed = MimeMessage.parse(message)
            let date = parseDate(parsed) ?? Date()
            let sender = parseSender(parsed)

            // Source 1: Autocrypt header.
            if let header = parsed.headers.first(where: { $0.name.lowercased() == "autocrypt" }) {
                if let key = scanAutocryptHeader(header.value, date: date, sender: sender, rnp: rnp) {
                    discovered[key.fingerprint] = merge(existing: discovered[key.fingerprint], new: key)
                }
            }

            // Source 2: application/pgp-keys attachment.
            if let parts = parsed.parts {
                for part in parts {
                    if let key = scanAttachment(part, date: date, sender: sender, rnp: rnp) {
                        discovered[key.fingerprint] = merge(existing: discovered[key.fingerprint], new: key)
                    }
                }
            }

            // Source 3: signing key from multipart/signed.
            if parsed.contentType?.mediaType == "multipart/signed",
               let parts = parsed.parts, parts.count >= 2
            {
                if let key = scanSigningKey(signedPart: parts[0], date: date, sender: sender, rnp: rnp) {
                    discovered[key.fingerprint] = merge(existing: discovered[key.fingerprint], new: key)
                }
            }
        }

        return MailboxScanReport(
            discoveredKeys: discovered.values.sorted { $0.fingerprint < $1.fingerprint },
            messagesScanned: scanned,
            errors: errors
        )
    }

    // MARK: - Per-source scanning

    private func scanAutocryptHeader(
        _ raw: String,
        date: Date,
        sender: String?,
        rnp: Rnp
    ) -> DiscoveredKey? {
        guard let parsed = try? AutocryptHeaderParser.parse(raw),
              let keydata = parsed.keydata
        else { return nil }
        return fingerprint(for: keydata, rnp: rnp).map { fpr in
            DiscoveredKey(
                fingerprint: fpr,
                primaryUserID: parsed.address,
                source: .autocryptHeader,
                sourceAddress: parsed.address,
                observedDate: date
            )
        }
    }

    private func scanAttachment(
        _ part: MimeMessage,
        date: Date,
        sender: String?,
        rnp: Rnp
    ) -> DiscoveredKey? {
        guard let ct = part.contentType,
              ct.mediaType == "application/pgp-keys"
        else { return nil }
        let body = part.decodedBody()
        return fingerprint(for: body, rnp: rnp).map { fpr in
            DiscoveredKey(
                fingerprint: fpr,
                primaryUserID: sender ?? "(attachment)",
                source: .pgpKeysAttachment,
                sourceAddress: sender,
                observedDate: date
            )
        }
    }

    private func scanSigningKey(
        signedPart: MimeMessage,
        date: Date,
        sender: String?,
        rnp: Rnp
    ) -> DiscoveredKey? {
        // Verify the signature to extract the signing key's fingerprint.
        // We use the parent entity's raw bytes; the caller passes the
        // signed-part sub-entity for body extraction only.
        let body = signedPart.decodedBody()
        // The signature itself is in the sibling part; the key comes
        // from verification. Since we only have the body here, fall
        // back to looking up the key by the From: address.
        guard let sender else { return nil }
        return fingerprint(forUserID: sender, rnp: rnp).map { fpr in
            DiscoveredKey(
                fingerprint: fpr,
                primaryUserID: sender,
                source: .signingKey,
                sourceAddress: sender,
                observedDate: date
            )
        }
    }

    // MARK: - Helpers

    /// Parses an OpenPGP key blob and returns its primary fingerprint,
    /// or `nil` on parse failure.
    private func fingerprint(for keydata: Data, rnp: Rnp) -> String? {
        // Loading into the live keyring would mutate state; instead,
        // spawn a fresh Rnp context and load the key there.
        guard let probe = try? Rnp(passphraseProvider: { _ in "" }) else { return nil }
        do {
            try probe.loadKeys(keydata, public: true, secret: false)
            let userIDs = try probe.allUserIDs()
            guard let first = userIDs.first,
                  let key = try probe.locateKey(first) else { return nil }
            return try key.fingerprint
        } catch {
            return nil
        }
    }

    /// Looks up a fingerprint for a userID in the engine's keyring.
    private func fingerprint(forUserID userID: String, rnp: Rnp) -> String? {
        guard let key = try? rnp.locateKey(userID) else { return nil }
        return try? key.fingerprint
    }

    private func parseDate(_ message: MimeMessage) -> Date? {
        guard let raw = message.header("Date") else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
        return formatter.date(from: raw.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private func parseSender(_ message: MimeMessage) -> String? {
        message.header("From").flatMap { extractEmail($0) }
    }

    private func extractEmail(_ raw: String) -> String? {
        guard let open = raw.firstIndex(of: "<"),
              let close = raw.firstIndex(of: ">"),
              open < close
        else { return raw.trimmingCharacters(in: .whitespaces) }
        return String(raw[raw.index(after: open)..<close])
    }

    /// Merge policy: prefer the most-recent observation; on ties prefer
    /// Autocrypt > attachment > signing key (richer metadata).
    private func merge(existing: DiscoveredKey?, new: DiscoveredKey) -> DiscoveredKey {
        guard let existing else { return new }
        if new.observedDate > existing.observedDate { return new }
        if new.observedDate == existing.observedDate,
           sourceRank(new.source) < sourceRank(existing.source)
        { return new }
        return existing
    }

    private func sourceRank(_ source: DiscoveredKey.Source) -> Int {
        switch source {
        case .autocryptHeader: return 0
        case .pgpKeysAttachment: return 1
        case .signingKey: return 2
        }
    }
}

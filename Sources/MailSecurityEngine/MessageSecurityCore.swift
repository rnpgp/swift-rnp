//
//  MessageSecurityCore.swift
//  swift-rnp
//
//  MailKit-independent core of the message-security handler. All OpenPGP and
//  MIME work is delegated to MailSecurityEngine; this type only translates
//  between the handler's protocol abstractions and engine types.
//

import Foundation
import Rnp
import TrustStore

/// MailKit-independent message-security handler.
public final class MessageSecurityCore {
    let engine: MailSecurityEngine
    /// Records decode outcomes for the end-to-end test harness, when set.
    private let stateRecorder: SecurityStateRecorder?
    /// Keyserver discovery used by recipient-key fetches.
    private let keyServerService: KeyServerService
    /// Whether compose-time auto-fetch of missing recipient keys is enabled.
    /// Read through a closure so the container app's setting takes effect
    /// without restarting the extension.
    private let autoFetchEnabled: () -> Bool
    /// Recent auto-fetch attempts per recipient, so Mail's frequent
    /// `getEncodingStatus` callbacks do not hammer the keyservers.
    private var fetchAttempts: [String: Date] = [:]
    private let fetchAttemptsLock = NSLock()
    /// Minimum interval between two fetch attempts for the same recipient.
    private static let fetchAttemptInterval: TimeInterval = 5 * 60

    public init(
        engine: MailSecurityEngine,
        stateRecorder: SecurityStateRecorder? = nil,
        keyServerService: KeyServerService = KeyServerService(),
        autoFetchEnabled: @escaping () -> Bool = { RecipientKeyAutoFetch.isEnabled() }
    ) {
        self.engine = engine
        self.stateRecorder = stateRecorder
        self.keyServerService = keyServerService
        self.autoFetchEnabled = autoFetchEnabled
    }

    /// Trust store used by the view layer to look up per-signer trust.
    public var trustStore: TrustStore {
        engine.keyManager.trustStore
    }

    // MARK: - Encoding

    public func getEncodingStatus(
        for message: MailMessage,
        composeContext: MailComposeContext
    ) -> HandlerEncodingStatus {
        let status = (try? engine.encodingStatus(
            sender: message.fromAddress,
            recipients: message.recipientAddresses
        )) ?? EncodingStatus(canSign: false, canEncrypt: false, missingRecipientKeys: [])

        // Per-recipient key trust, for recipients that resolve to a key.
        // Problem keys and unresolved conflicts block encryption exactly the
        // way `encode` does; unverified keys only produce a warning, matching
        // the engine's TOFU behavior. The sender is skipped: their own key is
        // implicitly trusted (encrypt-to-self), so they must never be flagged
        // as a failing recipient.
        var issues: [RecipientTrustIssue] = []
        // Recipients whose keys expired. librnp still encrypts to expired
        // keys, so this stays a warning; it takes precedence over the
        // unverified note because it carries the fetch/update remedies.
        var expiredKeys: [ExpiredRecipientKey] = []
        for recipient in message.recipientAddresses where !status.missingRecipientKeys.contains(recipient) {
            if KeyringStore.addressesMatch(recipient, message.fromAddress) {
                continue
            }
            if trustStore.hasConflict(forEmail: recipient) {
                issues.append(RecipientTrustIssue(recipient: recipient, kind: .conflict))
                continue
            }
            let trustState = trustStore.state(forEmail: recipient)
            if trustState == .problem {
                issues.append(RecipientTrustIssue(recipient: recipient, kind: .problem))
                continue
            }
            if let expiration = expiredKeyExpiration(for: recipient) {
                expiredKeys.append(ExpiredRecipientKey(recipient: recipient, expirationDate: expiration))
                continue
            }
            if trustState == .unverified {
                issues.append(RecipientTrustIssue(recipient: recipient, kind: .unverified))
            }
        }

        let warning = issues.isEmpty ? nil : RecipientTrustWarning(issues: issues)
        let blocked = warning?.blockedRecipients ?? []
        let expiredWarning = expiredKeys.isEmpty ? nil : ExpiredRecipientKeysWarning(keys: expiredKeys)

        // Missing keys get a fetch hint; combined with the trust and expiry
        // warnings when the message has several kinds of recipients. Only
        // surfaced when the user actually asked for encryption; there is no
        // point nagging about recipient keys for a plaintext send.
        let hint = status.missingRecipientKeys.isEmpty
            ? nil
            : MissingRecipientKeysHint(recipients: status.missingRecipientKeys)
        let securityError: Error?
        if composeContext.shouldEncrypt {
            switch (warning, hint, expiredWarning) {
            case (.none, .none, .none):
                securityError = nil
            case let (.some(warning), .none, .none):
                securityError = warning
            case let (.none, .some(hint), .none):
                securityError = hint
            case let (.none, .none, .some(expiredWarning)):
                securityError = expiredWarning
            default:
                securityError = ComposeSecurityWarning(
                    trustWarning: warning,
                    missingKeyHint: hint,
                    expiredKeyWarning: expiredWarning
                )
            }
        } else {
            securityError = nil
        }

        return HandlerEncodingStatus(
            canSign: status.canSign,
            canEncrypt: status.canEncrypt && blocked.isEmpty,
            securityError: securityError,
            addressesFailingEncryption: status.missingRecipientKeys + blocked
        )
    }

    // MARK: - Recipient key fetch

    /// Fetches a recipient's public key from the keyservers (WKD first, then
    /// VKS) and imports it into the keyring.
    ///
    /// The import is accepted only when a key actually resolves for `email`
    /// afterwards: a keyserver answer whose user IDs do not match the
    /// queried address is rejected, so a hostile or broken server cannot
    /// substitute somebody else's key. Imported keys land in the trust store
    /// as unverified (TOFU), exactly like a manual import.
    @discardableResult
    public func fetchRecipientKey(for email: String) async -> Result<RecipientKeyFetchResult, KeyServerError> {
        switch await keyServerService.discoverByEmail(email) {
        case let .failure(error):
            return .failure(error)
        case let .success(fetched):
            do {
                _ = try engine.keyManager.importKeys(fetched.data)
            } catch {
                return .failure(.malformedKey)
            }
            guard let key = try? engine.keyManager.publicKey(for: email),
                  let fingerprint = try? key.fingerprint
            else {
                return .failure(.invalidResponse)
            }
            return .success(RecipientKeyFetchResult(
                email: email,
                source: fetched.source,
                fingerprint: fingerprint
            ))
        }
    }

    /// Encoding status with opt-in auto-fetch of missing recipient keys.
    ///
    /// When the user enabled auto-fetch and encryption is requested, every
    /// recipient without a local key is looked up on the keyservers and
    /// imported before the status is computed — so a key that was simply
    /// never fetched no longer blocks the send. Lookups are throttled per
    /// recipient (`fetchAttemptInterval`) because Mail calls
    /// `getEncodingStatus` on every compose edit. With auto-fetch disabled
    /// this is exactly `getEncodingStatus`.
    public func getEncodingStatusWithAutoFetch(
        for message: MailMessage,
        composeContext: MailComposeContext
    ) async -> HandlerEncodingStatus {
        guard composeContext.shouldEncrypt, autoFetchEnabled() else {
            return getEncodingStatus(for: message, composeContext: composeContext)
        }
        let status = try? engine.encodingStatus(
            sender: message.fromAddress,
            recipients: message.recipientAddresses
        )
        for recipient in status?.missingRecipientKeys ?? [] where shouldAttemptFetch(for: recipient) {
            // Failures are ignored here: the status below still reports the
            // recipient as missing, with the fetch hint.
            await fetchRecipientKey(for: recipient)
        }
        return getEncodingStatus(for: message, composeContext: composeContext)
    }

    /// Whether a fetch for `recipient` should start now; records the attempt
    /// when returning `true`.
    private func shouldAttemptFetch(for recipient: String) -> Bool {
        fetchAttemptsLock.lock()
        defer { fetchAttemptsLock.unlock() }
        let now = Date()
        if let last = fetchAttempts[recipient],
           now.timeIntervalSince(last) < Self.fetchAttemptInterval
        {
            return false
        }
        fetchAttempts[recipient] = now
        return true
    }

    // MARK: - Expired recipient keys

    /// Expiration date of the recipient's key when it can no longer encrypt:
    /// the primary key expired, or every encryption-capable subkey did.
    /// `nil` when the recipient has no key or the key is still valid.
    private func expiredKeyExpiration(for recipient: String) -> Date? {
        try? engine.keyManager.withRnp { rnp in
            guard let key = try engine.keyManager.publicKeyUnlocked(for: recipient, rnp: rnp) else {
                return nil
            }
            return try Self.expiredForEncryption(key)
        }
    }

    /// Whether `key` is expired for encryption, returning the relevant
    /// expiration date. An expired primary kills the whole key; otherwise the
    /// key is unusable once every encryption-capable subkey has expired (a
    /// non-expiring subkey never does).
    static func expiredForEncryption(_ key: RnpKey, now: Date = Date()) throws -> Date? {
        if let primaryExpiry = try expirationDate(of: key), primaryExpiry < now {
            return primaryExpiry
        }
        let encryptionSubkeys = try key.subkeys.filter { try $0.capabilities.contains("encrypt") }
        var expirations: [Date] = []
        for subkey in encryptionSubkeys {
            guard let expiry = try expirationDate(of: subkey) else {
                return nil
            }
            guard expiry < now else {
                return nil
            }
            expirations.append(expiry)
        }
        return expirations.max()
    }

    /// Expiration date of a key or subkey, or `nil` when it does not expire.
    static func expirationDate(of key: RnpKey) throws -> Date? {
        let seconds = try key.expirationSeconds
        guard seconds > 0 else { return nil }
        return try key.creationDate.addingTimeInterval(TimeInterval(seconds))
    }

    /// Extends the expiry of the recipient's key — the "Update key" remedy
    /// for an expired recipient key the user owns.
    ///
    /// Re-signing requires the secret key, so a recipient key that is public
    /// only fails with `RecipientKeyUpdateError.keyNotOwned`; the remedy for
    /// those is `fetchRecipientKey(for:)`. The primary key and all its
    /// subkeys are extended, so an expired encryption subkey is rescued too.
    /// Duplicates `KeyLifecycle.extendExpiry`, which this module cannot
    /// import (KeyLifecycle depends on MailSecurityEngine, not vice versa).
    public func extendRecipientKeyExpiry(for email: String, to newDate: Date) throws {
        guard newDate > Date() else {
            throw RecipientKeyUpdateError.invalidExpiryDate
        }
        try engine.keyManager.withRnp { rnp in
            guard let key = try engine.keyManager.publicKeyUnlocked(for: email, rnp: rnp) else {
                throw RecipientKeyUpdateError.keyNotFound(email)
            }
            guard (try? key.hasSecret) ?? false else {
                throw RecipientKeyUpdateError.keyNotOwned(email)
            }
            let creation = try key.creationDate
            let expirySeconds = UInt32(max(0, newDate.timeIntervalSince1970 - creation.timeIntervalSince1970))
            try key.setExpirationSeconds(expirySeconds)
            for subkey in try key.subkeys {
                let subkeyCreation = try subkey.creationDate
                let subkeyExpirySeconds = UInt32(max(0, newDate.timeIntervalSince1970 - subkeyCreation.timeIntervalSince1970))
                try subkey.setExpirationSeconds(subkeyExpirySeconds)
            }
        }
        try engine.keyManager.save()
    }

    // MARK: - Signer key fetch

    /// Fetches an unknown signer's public key from the keyservers and imports
    /// it into the keyring.
    ///
    /// The lookup goes by fingerprint first (VKS, then HKP keyservers) and
    /// falls back to email discovery (WKD, then VKS) when the fingerprint is
    /// unavailable — librnp does not report one for unknown signers — or not
    /// found. The import is accepted only when the keyring afterwards holds
    /// the exact fingerprint asked for, or a key resolving to the queried
    /// address, so a hostile or broken server cannot substitute somebody
    /// else's key. Imported keys land in the trust store as unverified
    /// (TOFU), exactly like a manual import. The caller is expected to
    /// re-decode the message afterwards to refresh the signature status.
    @discardableResult
    public func fetchSignerKey(fingerprint: String?, email: String?) async -> Result<SignerKeyFetchResult, KeyServerError> {
        let address = email.flatMap { KeyManager.emailAddress(from: $0) } ?? email
        switch await keyServerService.discover(fingerprint: fingerprint, email: address) {
        case let .failure(error):
            return .failure(error)
        case let .success(fetched):
            do {
                _ = try engine.keyManager.importKeys(fetched.data)
            } catch {
                return .failure(.malformedKey)
            }
            return validateImportedSignerKey(fingerprint: fingerprint, email: address, source: fetched.source)
        }
    }

    /// Substitution guard for `fetchSignerKey`: the keyring must now hold
    /// the exact key that was looked up.
    private func validateImportedSignerKey(
        fingerprint: String?,
        email: String?,
        source: String
    ) -> Result<SignerKeyFetchResult, KeyServerError> {
        if let fingerprint, !fingerprint.isEmpty {
            let known = ((try? engine.keyManager.listKeys()) ?? []).map(\.fingerprint)
            guard let match = known.first(where: { $0.caseInsensitiveCompare(fingerprint) == .orderedSame }) else {
                return .failure(.invalidResponse)
            }
            return .success(SignerKeyFetchResult(fingerprint: match, source: source))
        }
        if let email, !email.isEmpty,
           let key = try? engine.keyManager.publicKey(for: email),
           let resolved = try? key.fingerprint
        {
            return .success(SignerKeyFetchResult(fingerprint: resolved, source: source))
        }
        return .failure(.invalidResponse)
    }

    public func encode(
        _ message: MailMessage,
        composeContext: MailComposeContext
    ) -> HandlerEncodingResult {
        let noEncoding = HandlerEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil)

        guard message.isSending,
              composeContext.shouldSign || composeContext.shouldEncrypt,
              let rawData = message.rawData
        else {
            return noEncoding
        }

        let request = EncodingRequest(
            message: rawData,
            sender: message.fromAddress,
            recipients: encryptionRecipients(for: message, composeContext: composeContext),
            sign: composeContext.shouldSign,
            encrypt: composeContext.shouldEncrypt,
            bccAddresses: message.bccAddresses
        )
        do {
            let encoded = try engine.encode(request)
            let outgoing = HandlerEncodedMessage(
                rawData: encoded.rawData,
                isSigned: encoded.isSigned,
                isEncrypted: encoded.isEncrypted
            )
            return HandlerEncodingResult(encodedMessage: outgoing, signingError: nil, encryptionError: nil)
        } catch {
            var signingError: Error?
            var encryptionError: Error?
            switch error {
            case MailSecurityError.noSecretKeyForSender:
                signingError = error
            case MailSecurityError.missingRecipientKeys:
                encryptionError = error
            default:
                if composeContext.shouldEncrypt {
                    encryptionError = error
                } else {
                    signingError = error
                }
            }
            return HandlerEncodingResult(encodedMessage: nil, signingError: signingError, encryptionError: encryptionError)
        }
    }

    /// Recipient list for an encode request.
    ///
    /// When encryption is requested and a secret key exists for the sender,
    /// the sender is added to the recipients (encrypt-to-self) so they can
    /// decrypt their own sent messages. A sender without a key is left out:
    /// encrypt-to-self is best-effort and must never break a send that would
    /// otherwise succeed. The sender's own key is implicitly trusted; the
    /// engine skips its trust check for the sender.
    private func encryptionRecipients(
        for message: MailMessage,
        composeContext: MailComposeContext
    ) -> [String] {
        let recipients = message.recipientAddresses
        guard composeContext.shouldEncrypt,
              senderKeyAvailable(message.fromAddress),
              !recipients.contains(where: { KeyringStore.addressesMatch($0, message.fromAddress) })
        else {
            return recipients
        }
        return recipients + [message.fromAddress]
    }

    /// Whether a secret key for `userID` exists in the keyring. Keyring
    /// failures are treated as "no key".
    private func senderKeyAvailable(_ userID: String) -> Bool {
        let key = try? engine.keyManager.withRnp { rnp in
            try engine.keyManager.secretKeyUnlocked(forUserID: userID, rnp: rnp)
        }
        return key != nil
    }

    // MARK: - Decoding

    public func decodedMessage(forMessageData data: Data) -> HandlerDecodedMessage? {
        guard let decoded = try? engine.decode(data) else {
            return nil
        }
        // Best-effort signer address for unknown signers: the signer is
        // almost always the sender, so the From: address feeds the banner's
        // "Fetch signer key" fallback when no fingerprint is available.
        let parsed = MimeMessage.parse(data)
        let senderEmail = parsed.headers
            .first { $0.name.caseInsensitiveCompare("From") == .orderedSame }
            .flatMap { KeyManager.emailAddress(from: $0.value) }
        let signers = decoded.security.signers.map { signer in
            let context = SignerContext(
                fingerprint: signer.fingerprint,
                status: signer.status.rawValue,
                isEncrypted: decoded.security.isEncrypted,
                encryptionError: decoded.security.encryptionError?.localizedDescription,
                email: signer.userID.flatMap { KeyManager.emailAddress(from: $0) } ?? senderEmail,
                keyExpiration: signer.fingerprint.flatMap { signerKeyExpiration(for: $0) },
                invalidReason: signer.status == .invalid
                    ? invalidSignatureReason(for: signer).rawValue
                    : nil
            )
            let contextData = (try? JSONEncoder().encode(context)) ?? Data()
            return HandlerSignerInfo(
                emailAddresses: signer.userID.map { [$0] } ?? [],
                signatureLabel: signer.userID ?? signer.fingerprint ?? "Unknown signer",
                context: contextData
            )
        }
        let information = HandlerSecurityInformation(
            signers: signers,
            isEncrypted: decoded.security.isEncrypted,
            signingError: decoded.security.signingError,
            encryptionError: decoded.security.encryptionError
        )
        recordState(rawMessage: data, decoded: decoded)
        return HandlerDecodedMessage(data: decoded.data, securityInformation: information)
    }

    // MARK: - State recording

    /// Writes the decode outcome to the state recorder, when configured.
    /// Header fields are read from the raw message so the harness can
    /// correlate the record with the message it injected.
    private func recordState(rawMessage data: Data, decoded: DecodedMessage) {
        guard let stateRecorder else { return }
        let parsed = MimeMessage.parse(data)
        func header(_ name: String) -> String? {
            parsed.headers.first(where: {
                $0.name.caseInsensitiveCompare(name) == .orderedSame
            })?.value
        }
        let signers = decoded.security.signers.map { signer in
            RecordedSigner(
                label: signer.userID ?? signer.fingerprint ?? "Unknown signer",
                fingerprint: signer.fingerprint,
                status: signer.status.rawValue,
                trust: signer.fingerprint.map { trustStore.state(forFpr: $0).rawValue }
            )
        }
        stateRecorder.record(RecordedMessageSecurity(
            messageID: header("Message-ID"),
            subject: header("Subject"),
            from: header("From"),
            isEncrypted: decoded.security.isEncrypted,
            signers: signers,
            signingError: decoded.security.signingError?.localizedDescription,
            encryptionError: decoded.security.encryptionError?.localizedDescription
        ))
    }

    // MARK: - Signer context

    /// Decodes the `SignerContext` attached to a signer, if present.
    public func signerContext(for signer: MailMessageSigner) -> SignerContext? {
        guard !signer.context.isEmpty else { return nil }
        return try? JSONDecoder().decode(SignerContext.self, from: signer.context)
    }

    /// Expiration date of the signing key with the given fingerprint, when
    /// the key is in the keyring and has one. Best-effort: lookup failures
    /// are treated as "no expiration known".
    private func signerKeyExpiration(for fingerprint: String) -> Date? {
        try? engine.keyManager.withRnp { rnp in
            guard let key = try rnp.locateKey(fingerprint, type: .fingerprint) else {
                return nil
            }
            return try Self.expirationDate(of: key)
        }
    }

    /// Best-effort reason an `.invalid` signature failed verification, from
    /// the detailed verification result and the signing key's keyring state:
    /// a signature whose key is unknown (or no longer locatable) cannot be
    /// checked at all, a revoked or expired key explains the failure, and
    /// anything else means the signed content was modified after signing.
    private func invalidSignatureReason(for signer: SignerInfo) -> InvalidSignatureReason {
        guard let fingerprint = signer.fingerprint else {
            return .keyUnknown
        }
        let reason = try? engine.keyManager.withRnp { rnp -> InvalidSignatureReason in
            guard let key = try rnp.locateKey(fingerprint, type: .fingerprint) else {
                return .keyUnknown
            }
            if (try? key.isRevoked) ?? false {
                return .keyRevoked
            }
            if let expiration = try Self.expirationDate(of: key), expiration < Date() {
                return .keyExpired
            }
            return .contentMismatch
        }
        return reason ?? .keyUnknown
    }
}

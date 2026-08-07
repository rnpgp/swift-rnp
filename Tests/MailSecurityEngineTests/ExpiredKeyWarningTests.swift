//
//  ExpiredKeyWarningTests.swift
//  swift-rnp
//
//  Tests for the recipient key expired warning in `getEncodingStatus`, the
//  "Fetch new key" refresh flow, the "Update key" expiry extension, and the
//  signer-key expiration plumbing behind the banner's expired warning.
//

import KeyServerClient
import Librnp
import TrustStore
import XCTest
@testable import MailSecurityEngine

final class ExpiredKeyWarningTests: XCTestCase {
    private static let alice = "Alice <alice@example.com>"
    private static let aliceEmail = "alice@example.com"
    private static let bob = "Bob <bob@example.com>"
    private static let bobEmail = "bob@example.com"
    private static let carolEmail = "carol@example.com"
    private static let password = "test-password"

    private var tempDirectories: [URL] = []

    override func tearDownWithError() throws {
        for url in tempDirectories {
            try? FileManager.default.removeItem(at: url)
        }
        tempDirectories = []
    }

    private func makeTempDirectory() -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("swift-rnp-tests")
            .appendingPathComponent(UUID().uuidString)
        tempDirectories.append(url)
        return url
    }

    private func makeEngine() throws -> MailSecurityEngine {
        try MailSecurityEngine(
            directory: makeTempDirectory(),
            passphraseProvider: { _ in Self.password }
        )
    }

    private func makeCore(engine: MailSecurityEngine) -> MessageSecurityCore {
        MessageSecurityCore(
            engine: engine,
            keyServerService: KeyServerService(client: MockKeyServerClient()),
            autoFetchEnabled: { false }
        )
    }

    /// Engine holding Alice's key; Bob's key is generated with the given
    /// expiry (seconds, or `0` for none) in the same keyring, so the client
    /// owns it.
    private func makeCore(bobExpirationSeconds: UInt32) throws -> (MessageSecurityCore, KeyInfo) {
        let engine = try makeEngine()
        try engine.keyManager.generateKey(userID: Self.alice, algorithm: .ecdsa)
        let bob = try engine.keyManager.generateKey(
            userID: Self.bob,
            algorithm: .ecdsa,
            expirationSeconds: bobExpirationSeconds
        )
        return (makeCore(engine: engine), bob)
    }

    /// Waits until a key created with a 1-second expiry is actually expired.
    private func waitForExpiry(of key: KeyInfo) {
        guard let expiry = key.expirationDate else { return }
        let wait = expiry.timeIntervalSinceNow + 0.5
        if wait > 0 {
            Thread.sleep(forTimeInterval: wait)
        }
    }

    /// Marks Bob's key verified so trust warnings cannot mask the expiry
    /// warning under test.
    private func markBobVerified(in core: MessageSecurityCore, fingerprint: String) throws {
        try core.trustStore.noteSeen(email: Self.bobEmail, fingerprint: fingerprint)
        try core.trustStore.markVerified(fingerprint: fingerprint)
    }

    // MARK: - Mocks

    private struct MockMessage: MailMessage {
        var rawData: Data?
        var fromAddress: String
        var recipientAddresses: [String]
        var isSending: Bool
    }

    private struct MockComposeContext: MailComposeContext {
        var shouldSign: Bool
        var shouldEncrypt: Bool
    }

    private func composeMessage(recipients: [String]) -> MockMessage {
        MockMessage(
            rawData: nil,
            fromAddress: Self.aliceEmail,
            recipientAddresses: recipients,
            isSending: true
        )
    }

    private func encryptingStatus(
        _ core: MessageSecurityCore,
        recipients: [String]
    ) -> HandlerEncodingStatus {
        core.getEncodingStatus(
            for: composeMessage(recipients: recipients),
            composeContext: MockComposeContext(shouldSign: true, shouldEncrypt: true)
        )
    }

    private func encryptingStatus(_ core: MessageSecurityCore) -> HandlerEncodingStatus {
        encryptingStatus(core, recipients: [Self.bobEmail])
    }

    // MARK: - Compose-time expired key warning

    func testExpiredRecipientKeyProducesWarning() throws {
        let (core, bob) = try makeCore(bobExpirationSeconds: 1)
        try markBobVerified(in: core, fingerprint: bob.fingerprint)
        waitForExpiry(of: bob)

        let status = encryptingStatus(core)

        // librnp still encrypts to expired keys: warning only, no blocking.
        XCTAssertTrue(status.canEncrypt)
        XCTAssertEqual(status.addressesFailingEncryption, [])
        let warning = try XCTUnwrap(status.securityError as? ExpiredRecipientKeysWarning)
        XCTAssertEqual(warning.keys.count, 1)
        XCTAssertEqual(warning.keys.first?.recipient, Self.bobEmail)
        XCTAssertNotNil(warning.keys.first?.expirationDate)
        let description = warning.errorDescription ?? ""
        XCTAssertTrue(description.contains(Self.bobEmail))
        XCTAssertTrue(description.contains("expired"))
        XCTAssertTrue(description.contains("Fetch a new key"))
    }

    func testExpiredRecipientWarningIncludesExpirationDate() throws {
        let (core, bob) = try makeCore(bobExpirationSeconds: 1)
        try markBobVerified(in: core, fingerprint: bob.fingerprint)
        waitForExpiry(of: bob)

        let status = encryptingStatus(core)

        let warning = try XCTUnwrap(status.securityError as? ExpiredRecipientKeysWarning)
        let expiration = try XCTUnwrap(warning.keys.first?.expirationDate)
        XCTAssertEqual(expiration.timeIntervalSince1970, bob.expirationDate?.timeIntervalSince1970 ?? 0, accuracy: 2)
        let description = warning.errorDescription ?? ""
        XCTAssertTrue(description.contains(formatKeyExpirationDate(expiration)))
    }

    func testExpiredRecipientWarningSuppressedWhenNotEncrypting() throws {
        let (core, bob) = try makeCore(bobExpirationSeconds: 1)
        try markBobVerified(in: core, fingerprint: bob.fingerprint)
        waitForExpiry(of: bob)

        let status = core.getEncodingStatus(
            for: composeMessage(recipients: [Self.bobEmail]),
            composeContext: MockComposeContext(shouldSign: true, shouldEncrypt: false)
        )

        XCTAssertNil(status.securityError)
        XCTAssertTrue(status.canEncrypt)
    }

    func testNonExpiredRecipientKeyHasNoExpiryWarning() throws {
        let (core, bob) = try makeCore(bobExpirationSeconds: 365 * 24 * 60 * 60)
        try markBobVerified(in: core, fingerprint: bob.fingerprint)

        let status = encryptingStatus(core)

        XCTAssertNil(status.securityError)
        XCTAssertTrue(status.canEncrypt)
    }

    func testExpiredUnverifiedRecipientShowsExpiryWarningOnly() throws {
        // Bob is expired AND unverified: the expiry warning wins because it
        // carries the fetch/update remedies.
        let (core, bob) = try makeCore(bobExpirationSeconds: 1)
        waitForExpiry(of: bob)

        let status = encryptingStatus(core)

        XCTAssertNotNil(status.securityError as? ExpiredRecipientKeysWarning)
        XCTAssertNil(status.securityError as? RecipientTrustWarning)
    }

    func testExpiredSenderKeyIsNotFlagged() throws {
        // The sender's own key is implicitly trusted (encrypt-to-self) and
        // must never be flagged, even when expired.
        let engine = try makeEngine()
        let alice = try engine.keyManager.generateKey(
            userID: Self.alice,
            algorithm: .ecdsa,
            expirationSeconds: 1
        )
        try engine.keyManager.generateKey(userID: Self.bob, algorithm: .ecdsa)
        let core = makeCore(engine: engine)
        let bobFingerprint = try XCTUnwrap(
            engine.keyManager.listKeys().first { $0.primaryUserID == Self.bob }?.fingerprint
        )
        try markBobVerified(in: core, fingerprint: bobFingerprint)
        waitForExpiry(of: alice)

        let status = encryptingStatus(core)

        XCTAssertNil(status.securityError)
    }

    func testExpiredCombinedWithMissingKeyHint() throws {
        let (core, bob) = try makeCore(bobExpirationSeconds: 1)
        try markBobVerified(in: core, fingerprint: bob.fingerprint)
        waitForExpiry(of: bob)

        let status = encryptingStatus(core, recipients: [Self.bobEmail, Self.carolEmail])

        XCTAssertEqual(status.addressesFailingEncryption, [Self.carolEmail])
        let combined = try XCTUnwrap(status.securityError as? ComposeSecurityWarning)
        XCTAssertEqual(combined.expiredKeyWarning?.keys.map(\.recipient), [Self.bobEmail])
        XCTAssertEqual(combined.missingKeyHint?.recipients, [Self.carolEmail])
        XCTAssertNil(combined.trustWarning)
        let description = combined.errorDescription ?? ""
        XCTAssertTrue(description.contains(Self.bobEmail))
        XCTAssertTrue(description.contains(Self.carolEmail))
    }

    func testExpiredEncryptionSubkeyOnlyProducesWarning() throws {
        // The primary stays valid but the encryption subkey expires: the key
        // is just as unusable for new messages.
        let engine = try makeEngine()
        try engine.keyManager.generateKey(userID: Self.alice, algorithm: .ecdsa)
        let bob = try engine.keyManager.generateKey(userID: Self.bob, algorithm: .ecdsa)
        let core = makeCore(engine: engine)
        try markBobVerified(in: core, fingerprint: bob.fingerprint)
        // Set the encryption subkey's expiry to 1 second from its creation.
        try engine.keyManager.withRnp { rnp in
            let key = try rnp.requireKey(bob.fingerprint, type: .fingerprint)
            for subkey in try key.subkeys {
                if try subkey.capabilities.contains("encrypt") {
                    try subkey.setExpirationSeconds(1)
                }
            }
        }
        try engine.keyManager.save()
        Thread.sleep(forTimeInterval: 1.6)

        let status = encryptingStatus(core)

        let warning = try XCTUnwrap(status.securityError as? ExpiredRecipientKeysWarning)
        XCTAssertEqual(warning.keys.map(\.recipient), [Self.bobEmail])
    }

    // MARK: - Update key action

    func testExtendRecipientKeyExpiryExtendsOwnedKey() throws {
        let engine = try makeEngine()
        try engine.keyManager.generateKey(userID: Self.alice, algorithm: .ecdsa)
        let bob = try engine.keyManager.generateKey(
            userID: Self.bob,
            algorithm: .ecdsa,
            expirationSeconds: 1
        )
        let core = makeCore(engine: engine)
        try markBobVerified(in: core, fingerprint: bob.fingerprint)
        waitForExpiry(of: bob)
        XCTAssertNotNil(encryptingStatus(core).securityError as? ExpiredRecipientKeysWarning)

        let newDate = Date().addingTimeInterval(365 * 24 * 60 * 60)
        try core.extendRecipientKeyExpiry(for: Self.bobEmail, to: newDate)

        // The warning clears, for the primary key and the encryption subkey.
        XCTAssertNil(encryptingStatus(core).securityError)
        let updated = try XCTUnwrap(
            engine.keyManager.listKeys().first { $0.fingerprint == bob.fingerprint }
        )
        XCTAssertEqual(
            updated.expirationDate?.timeIntervalSince1970 ?? 0,
            newDate.timeIntervalSince1970,
            accuracy: 2
        )
        let subkeys = try engine.keyManager.subkeys(for: bob.fingerprint)
        XCTAssertEqual(
            subkeys.first?.expirationDate?.timeIntervalSince1970 ?? 0,
            newDate.timeIntervalSince1970,
            accuracy: 2
        )
    }

    func testExtendRecipientKeyExpiryRejectsUnownedKey() throws {
        // Bob's key exists but is public-only (imported): only the owner can
        // extend its expiry.
        let server = try makeEngine()
        let bob = try server.keyManager.generateKey(userID: Self.bob, algorithm: .ecdsa)
        let publicData = try server.keyManager.exportKey(fingerprint: bob.fingerprint)
        let engine = try makeEngine()
        try engine.keyManager.generateKey(userID: Self.alice, algorithm: .ecdsa)
        try engine.keyManager.importKeys(publicData)
        let core = makeCore(engine: engine)

        XCTAssertThrowsError(
            try core.extendRecipientKeyExpiry(
                for: Self.bobEmail,
                to: Date().addingTimeInterval(365 * 24 * 60 * 60)
            )
        ) { error in
            XCTAssertEqual(error as? RecipientKeyUpdateError, .keyNotOwned(Self.bobEmail))
        }
    }

    func testExtendRecipientKeyExpiryRejectsUnknownRecipient() throws {
        let engine = try makeEngine()
        try engine.keyManager.generateKey(userID: Self.alice, algorithm: .ecdsa)
        let core = makeCore(engine: engine)

        XCTAssertThrowsError(
            try core.extendRecipientKeyExpiry(
                for: Self.carolEmail,
                to: Date().addingTimeInterval(365 * 24 * 60 * 60)
            )
        ) { error in
            XCTAssertEqual(error as? RecipientKeyUpdateError, .keyNotFound(Self.carolEmail))
        }
    }

    func testExtendRecipientKeyExpiryRejectsPastDate() throws {
        let (core, _) = try makeCore(bobExpirationSeconds: 0)

        XCTAssertThrowsError(
            try core.extendRecipientKeyExpiry(
                for: Self.bobEmail,
                to: Date().addingTimeInterval(-3600)
            )
        ) { error in
            XCTAssertEqual(error as? RecipientKeyUpdateError, .invalidExpiryDate)
        }
    }

    // MARK: - Fetch new key action

    func testFetchRecipientKeyRefreshesExpiredKey() async throws {
        // The "keyserver" copy of Bob's key, expiring almost immediately.
        let server = try makeEngine()
        let serverBob = try server.keyManager.generateKey(
            userID: Self.bob,
            algorithm: .ecdsa,
            expirationSeconds: 1
        )
        let staleExport = try server.keyManager.exportKey(fingerprint: serverBob.fingerprint)

        // The client keyring holds the stale, soon-to-be-expired copy.
        let engine = try makeEngine()
        try engine.keyManager.generateKey(userID: Self.alice, algorithm: .ecdsa)
        try engine.keyManager.importKeys(staleExport)
        let client = MockKeyServerClient()
        let core = MessageSecurityCore(
            engine: engine,
            keyServerService: KeyServerService(client: client),
            autoFetchEnabled: { false }
        )
        try markBobVerified(in: core, fingerprint: serverBob.fingerprint)
        waitForExpiry(of: serverBob)
        XCTAssertNotNil(encryptingStatus(core).securityError as? ExpiredRecipientKeysWarning)

        // The owner extends the key's expiry on the server side; the client
        // fetches the refreshed key and the warning clears.
        let serverCore = makeCore(engine: server)
        let newDate = Date().addingTimeInterval(365 * 24 * 60 * 60)
        try serverCore.extendRecipientKeyExpiry(for: Self.bobEmail, to: newDate)
        let refreshedExport = try server.keyManager.exportKey(fingerprint: serverBob.fingerprint)
        client.responses = MockKeyServerResponses(byEmailResult: .success(refreshedExport))

        let result = await core.fetchRecipientKey(for: Self.bobEmail)

        guard case let .success(fetched) = result else {
            XCTFail("fetch failed: \(result)")
            return
        }
        XCTAssertEqual(fetched.fingerprint, serverBob.fingerprint)
        XCTAssertEqual(fetched.source, "keys.openpgp.org")
        XCTAssertNil(encryptingStatus(core).securityError)
    }

    // MARK: - Signer key expiration plumbing

    func testDecodedMessageAttachesSignerKeyExpiration() throws {
        let engine = try makeEngine()
        let alice = try engine.keyManager.generateKey(
            userID: Self.alice,
            algorithm: .ecdsa,
            expirationSeconds: 365 * 24 * 60 * 60
        )
        let core = makeCore(engine: engine)
        let message = Data((
            "From: alice@example.com\r\n"
                + "To: bob@example.com\r\n"
                + "Subject: expiry plumbing\r\n"
                + "MIME-Version: 1.0\r\n"
                + "Content-Type: text/plain; charset=\"utf-8\"\r\n"
                + "\r\n"
                + "Hello!"
        ).utf8)
        let signed = try engine.encode(EncodingRequest(
            message: message,
            sender: Self.aliceEmail,
            recipients: [],
            sign: true,
            encrypt: false
        ))

        let decoded = try XCTUnwrap(core.decodedMessage(forMessageData: signed.rawData))
        let signer = try XCTUnwrap(decoded.securityInformation.signers.first)
        let context = try XCTUnwrap(core.signerContext(for: signer))

        XCTAssertEqual(context.status, RnpSignatureStatus.valid.rawValue)
        XCTAssertEqual(
            context.keyExpiration?.timeIntervalSince1970 ?? 0,
            alice.expirationDate?.timeIntervalSince1970 ?? 0,
            accuracy: 2
        )
    }

    func testSignerContextRoundTripsKeyExpiration() throws {
        let expiration = Date(timeIntervalSince1970: 1_800_000_000)
        let context = SignerContext(
            fingerprint: "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111",
            status: RnpSignatureStatus.expired.rawValue,
            keyExpiration: expiration
        )

        let decoded = try JSONDecoder().decode(SignerContext.self, from: JSONEncoder().encode(context))

        XCTAssertEqual(decoded, context)
        XCTAssertEqual(decoded.keyExpiration?.timeIntervalSince1970 ?? 0, expiration.timeIntervalSince1970, accuracy: 0.001)
    }

    func testSignerContextWithoutKeyExpirationStillDecodes() throws {
        // Payloads written by older extension versions lack the field.
        let legacy = """
        {"fingerprint":"AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111","status":"expired"}
        """

        let decoded = try JSONDecoder().decode(SignerContext.self, from: Data(legacy.utf8))

        XCTAssertNil(decoded.keyExpiration)
        XCTAssertEqual(decoded.status, RnpSignatureStatus.expired.rawValue)
    }

    // MARK: - Banner view model mapping

    func testMapSignerTrustExpiredIncludesExpirationDate() {
        let expiration = Date(timeIntervalSince1970: 1_800_000_000)
        let formatted = formatKeyExpirationDate(expiration)

        for trust: TrustState in [.verified, .unverified, .problem] {
            let model = mapSignerTrust(status: .expired, trust: trust, keyExpiration: expiration)
            XCTAssertTrue(
                model.detail.contains("The key expired on \(formatted)."),
                "detail missing expiration date for trust=\(trust): \(model.detail)"
            )
        }
    }

    func testMapSignerTrustExpiredWithoutDateKeepsOriginalDetail() {
        let model = mapSignerTrust(status: .expired, trust: .verified)
        XCTAssertEqual(model.detail, "The key is verified, but the signature has expired.")
    }
}

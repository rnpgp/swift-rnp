//
//  RecipientKeyFetchTests.swift
//  swift-rnp
//
//  Tests for compose-time recipient-key fetching: the missing-key hint in
//  `getEncodingStatus`, keyserver fetch-and-import, and opt-in auto-fetch.
//

import KeyServerClient
import TrustStore
import XCTest
@testable import MailSecurityEngine

final class RecipientKeyFetchTests: XCTestCase {
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

    private func makeEngine(keys userIDs: [String] = []) throws -> MailSecurityEngine {
        let engine = try MailSecurityEngine(
            directory: makeTempDirectory(),
            passphraseProvider: { _ in Self.password }
        )
        for userID in userIDs {
            try engine.keyManager.generateKey(userID: userID, algorithm: .ecdsa)
        }
        return engine
    }

    private func makeCore(
        keys userIDs: [String] = [],
        keyServerService: KeyServerService = KeyServerService(client: MockKeyServerClient()),
        autoFetchEnabled: @escaping () -> Bool = { false }
    ) throws -> MessageSecurityCore {
        MessageSecurityCore(
            engine: try makeEngine(keys: userIDs),
            keyServerService: keyServerService,
            autoFetchEnabled: autoFetchEnabled
        )
    }

    /// Armored public key data for `userID`, exported from a throwaway
    /// keyring standing in for the keyserver's copy; also returns the key's
    /// fingerprint for assertions.
    private func publicKeyData(for userID: String) throws -> (data: Data, fingerprint: String) {
        let server = try makeEngine(keys: [userID])
        let fingerprint = try XCTUnwrap(server.keyManager.listKeys().first?.fingerprint)
        return (try server.keyManager.exportKey(fingerprint: fingerprint), fingerprint)
    }

    /// Mock service with scripted WKD and VKS by-email results; the backing
    /// client is returned for call assertions.
    private func mockService(
        wkd: Result<Data, KeyServerError> = .failure(.notFound),
        byEmail: Result<Data, KeyServerError> = .failure(.notFound)
    ) -> (KeyServerService, MockKeyServerClient) {
        let client = MockKeyServerClient(responses: MockKeyServerResponses(
            byEmailResult: byEmail,
            wkdResult: wkd
        ))
        return (KeyServerService(client: client), client)
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

    private func composeMessage() -> MockMessage {
        composeMessage(recipients: [Self.bobEmail])
    }

    // MARK: - Missing-key hint in getEncodingStatus

    func testGetEncodingStatusMissingKeyHintWhenEncrypting() throws {
        let core = try makeCore(keys: [Self.alice])
        let status = core.getEncodingStatus(
            for: composeMessage(),
            composeContext: MockComposeContext(shouldSign: true, shouldEncrypt: true)
        )

        XCTAssertFalse(status.canEncrypt)
        XCTAssertEqual(status.addressesFailingEncryption, [Self.bobEmail])
        let hint = try XCTUnwrap(status.securityError as? MissingRecipientKeysHint)
        XCTAssertEqual(hint.recipients, [Self.bobEmail])
        XCTAssertTrue(hint.errorDescription?.contains(Self.bobEmail) ?? false)
    }

    func testGetEncodingStatusMissingKeyHintSuppressedWhenNotEncrypting() throws {
        let core = try makeCore(keys: [Self.alice])
        let status = core.getEncodingStatus(
            for: composeMessage(),
            composeContext: MockComposeContext(shouldSign: true, shouldEncrypt: false)
        )

        XCTAssertNil(status.securityError)
        XCTAssertEqual(status.addressesFailingEncryption, [Self.bobEmail])
    }

    func testGetEncodingStatusCombinesTrustWarningAndMissingKeyHint() throws {
        let core = try makeCore(keys: [Self.alice, Self.bob])
        // Bob resolves (unverified → warning); Carol has no key (→ hint).
        let message = composeMessage(recipients: [Self.bobEmail, Self.carolEmail])
        let status = core.getEncodingStatus(
            for: message,
            composeContext: MockComposeContext(shouldSign: true, shouldEncrypt: true)
        )

        XCTAssertEqual(status.addressesFailingEncryption, [Self.carolEmail])
        let combined = try XCTUnwrap(status.securityError as? ComposeSecurityWarning)
        XCTAssertEqual(combined.trustWarning?.issues, [
            RecipientTrustIssue(recipient: Self.bobEmail, kind: .unverified),
        ])
        XCTAssertEqual(combined.missingKeyHint?.recipients, [Self.carolEmail])
        let description = combined.errorDescription ?? ""
        XCTAssertTrue(description.contains(Self.bobEmail))
        XCTAssertTrue(description.contains(Self.carolEmail))
    }

    // MARK: - fetchRecipientKey

    func testFetchRecipientKeyImportsKeyFromVKS() async throws {
        let bobKey = try publicKeyData(for: Self.bob)
        let (service, client) = mockService(byEmail: .success(bobKey.data))
        let core = try makeCore(keys: [Self.alice], keyServerService: service)

        let result = await core.fetchRecipientKey(for: Self.bobEmail)

        let fetched = try XCTUnwrap(result.success)
        XCTAssertEqual(fetched.email, Self.bobEmail)
        XCTAssertEqual(fetched.source, "keys.openpgp.org")
        XCTAssertEqual(fetched.fingerprint, bobKey.fingerprint)
        // WKD was tried before VKS.
        XCTAssertEqual(client.fetchedWKDs.count, 2)
        XCTAssertEqual(client.fetchedEmails, [Self.bobEmail])
        // The key now resolves for the recipient and is tracked as
        // unverified (TOFU), exactly like a manual import.
        XCTAssertFalse(core.missingRecipientKeys([Self.bobEmail]))
        XCTAssertEqual(core.trustStore.state(forEmail: Self.bobEmail), .unverified)
    }

    func testFetchRecipientKeyPrefersWKD() async throws {
        let bobKey = try publicKeyData(for: Self.bob)
        let (service, client) = mockService(wkd: .success(bobKey.data))
        let core = try makeCore(keys: [Self.alice], keyServerService: service)

        let result = await core.fetchRecipientKey(for: Self.bobEmail)

        let fetched = try XCTUnwrap(result.success)
        XCTAssertEqual(fetched.source, "WKD (advanced)")
        XCTAssertTrue(client.fetchedEmails.isEmpty)
    }

    func testFetchRecipientKeyNotFound() async throws {
        let (service, _) = mockService()
        let core = try makeCore(keys: [Self.alice], keyServerService: service)

        let result = await core.fetchRecipientKey(for: Self.bobEmail)

        XCTAssertEqual(result.failure, .notFound)
        XCTAssertTrue(core.missingRecipientKeys([Self.bobEmail]))
    }

    func testFetchRecipientKeyRejectsKeyForDifferentAddress() async throws {
        // The server answers with a key whose user IDs do not include the
        // queried address; it must not be treated as the recipient's key.
        let aliceKey = try publicKeyData(for: Self.alice)
        let (service, _) = mockService(byEmail: .success(aliceKey.data))
        let core = try makeCore(keyServerService: service)

        let result = await core.fetchRecipientKey(for: Self.bobEmail)

        XCTAssertEqual(result.failure, .invalidResponse)
        XCTAssertTrue(core.missingRecipientKeys([Self.bobEmail]))
    }

    // MARK: - Auto-fetch on compose

    func testAutoFetchImportsMissingKeyBeforeReportingStatus() async throws {
        let bobKey = try publicKeyData(for: Self.bob)
        let (service, client) = mockService(byEmail: .success(bobKey.data))
        let core = try makeCore(
            keys: [Self.alice],
            keyServerService: service,
            autoFetchEnabled: { true }
        )

        let status = await core.getEncodingStatusWithAutoFetch(
            for: composeMessage(),
            composeContext: MockComposeContext(shouldSign: true, shouldEncrypt: true)
        )

        XCTAssertEqual(client.fetchedEmails, [Self.bobEmail])
        XCTAssertTrue(status.canEncrypt)
        XCTAssertEqual(status.addressesFailingEncryption, [])
        // The fetched key is unverified: warning only, no missing-key hint.
        XCTAssertNil(status.securityError as? MissingRecipientKeysHint)
    }

    func testAutoFetchDisabledDoesNotFetch() async throws {
        let bobKey = try publicKeyData(for: Self.bob)
        let (service, client) = mockService(byEmail: .success(bobKey.data))
        let core = try makeCore(
            keys: [Self.alice],
            keyServerService: service,
            autoFetchEnabled: { false }
        )

        let status = await core.getEncodingStatusWithAutoFetch(
            for: composeMessage(),
            composeContext: MockComposeContext(shouldSign: true, shouldEncrypt: true)
        )

        XCTAssertTrue(client.fetchedEmails.isEmpty)
        XCTAssertFalse(status.canEncrypt)
        XCTAssertNotNil(status.securityError as? MissingRecipientKeysHint)
    }

    func testAutoFetchSkipsFetchWhenNotEncrypting() async throws {
        let bobKey = try publicKeyData(for: Self.bob)
        let (service, client) = mockService(byEmail: .success(bobKey.data))
        let core = try makeCore(
            keys: [Self.alice],
            keyServerService: service,
            autoFetchEnabled: { true }
        )

        let status = await core.getEncodingStatusWithAutoFetch(
            for: composeMessage(),
            composeContext: MockComposeContext(shouldSign: true, shouldEncrypt: false)
        )

        XCTAssertTrue(client.fetchedEmails.isEmpty)
        XCTAssertNil(status.securityError)
    }

    func testAutoFetchFailureStillReportsMissingAndThrottlesRetries() async throws {
        let (service, client) = mockService()
        let core = try makeCore(
            keys: [Self.alice],
            keyServerService: service,
            autoFetchEnabled: { true }
        )
        let message = composeMessage()
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: true)

        let first = await core.getEncodingStatusWithAutoFetch(for: message, composeContext: context)
        let second = await core.getEncodingStatusWithAutoFetch(for: message, composeContext: context)

        XCTAssertFalse(first.canEncrypt)
        XCTAssertNotNil(first.securityError as? MissingRecipientKeysHint)
        // The second status call must not hit the keyserver again: Mail
        // re-queries the status on every compose edit.
        XCTAssertEqual(client.fetchedEmails, [Self.bobEmail])
        XCTAssertFalse(second.canEncrypt)
    }

    // MARK: - Auto-fetch setting

    func testAutoFetchSettingRoundTripsAndDefaultsToOff() throws {
        let suiteName = "test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        XCTAssertFalse(RecipientKeyAutoFetch.isEnabled(defaults: defaults))
        RecipientKeyAutoFetch.setEnabled(true, defaults: defaults)
        XCTAssertTrue(RecipientKeyAutoFetch.isEnabled(defaults: defaults))
        RecipientKeyAutoFetch.setEnabled(false, defaults: defaults)
        XCTAssertFalse(RecipientKeyAutoFetch.isEnabled(defaults: defaults))
    }
}

private extension MessageSecurityCore {
    struct ProbeMessage: MailMessage {
        var rawData: Data? { nil }
        let fromAddress: String
        let recipientAddresses: [String]
        var isSending: Bool { true }
    }

    struct ProbeContext: MailComposeContext {
        var shouldSign: Bool { false }
        var shouldEncrypt: Bool { true }
    }

    /// Whether any of `recipients` currently fails encryption (no key, or a
    /// blocking trust problem), probed through the public status API.
    func missingRecipientKeys(_ recipients: [String]) -> Bool {
        let status = getEncodingStatus(
            for: ProbeMessage(fromAddress: "probe@example.com", recipientAddresses: recipients),
            composeContext: ProbeContext()
        )
        return !status.addressesFailingEncryption.isEmpty
    }
}

private extension Result {
    var success: Success? {
        if case let .success(value) = self { return value }
        return nil
    }

    var failure: Failure? {
        if case let .failure(error) = self { return error }
        return nil
    }
}

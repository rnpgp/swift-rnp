//
//  SignerKeyFetchTests.swift
//  swift-rnp
//
//  Tests for the "fetch signer key" flow: keyserver discovery by fingerprint
//  with HKPS and email fallbacks, import with substitution guards, and the
//  re-decode that turns an unknown signer into a verified one.
//

import KeyServerClient
import Librnp
import TrustStore
import XCTest
@testable import MailSecurityEngine

final class SignerKeyFetchTests: XCTestCase {
    private static let alice = "Alice <alice@example.com>"
    private static let aliceEmail = "alice@example.com"
    private static let bob = "Bob <bob@example.com>"
    private static let bobEmail = "bob@example.com"
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

    /// Armored public key data for `userID`, exported from a throwaway
    /// keyring standing in for the keyserver's copy; also returns the key's
    /// fingerprint for assertions.
    private func publicKeyData(for userID: String) throws -> (data: Data, fingerprint: String) {
        let server = try makeEngine(keys: [userID])
        let fingerprint = try XCTUnwrap(server.keyManager.listKeys().first?.fingerprint)
        return (try server.keyManager.exportKey(fingerprint: fingerprint), fingerprint)
    }

    /// Mock service with scripted fingerprint/email results; the backing
    /// client is returned for call assertions.
    private func mockService(
        byFingerprint: Result<Data, KeyServerError> = .failure(.notFound),
        hkps: Result<Data, KeyServerError> = .failure(.notFound),
        wkd: Result<Data, KeyServerError> = .failure(.notFound),
        byEmail: Result<Data, KeyServerError> = .failure(.notFound)
    ) -> (KeyServerService, MockKeyServerClient) {
        let client = MockKeyServerClient(responses: MockKeyServerResponses(
            byEmailResult: byEmail,
            byFingerprintResult: byFingerprint,
            wkdResult: wkd,
            hkpsResult: hkps
        ))
        return (KeyServerService(client: client), client)
    }

    private func makeCore(
        keys userIDs: [String] = [],
        keyServerService: KeyServerService
    ) throws -> MessageSecurityCore {
        MessageSecurityCore(
            engine: try makeEngine(keys: userIDs),
            keyServerService: keyServerService
        )
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

    private func plainMessage(
        from: String = "alice@example.com",
        to: String = "bob@example.com",
        body: String = "Hello, Bob!"
    ) -> Data {
        let lines = [
            "From: \(from)",
            "To: \(to)",
            "Subject: signer fetch test",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=\"utf-8\"",
        ]
        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n" + body).utf8)
    }

    // MARK: - Fetch by fingerprint

    func testFetchSignerKeyByFingerprintImportsKey() async throws {
        let aliceKey = try publicKeyData(for: Self.alice)
        let (service, client) = mockService(byFingerprint: .success(aliceKey.data))
        let core = try makeCore(keyServerService: service)

        let result = await core.fetchSignerKey(fingerprint: aliceKey.fingerprint, email: nil)

        let fetched = try XCTUnwrap(result.success)
        XCTAssertEqual(fetched.fingerprint, aliceKey.fingerprint)
        XCTAssertEqual(fetched.source, "keys.openpgp.org")
        XCTAssertEqual(client.fetchedFingerprints, [aliceKey.fingerprint])
        XCTAssertTrue(client.fetchedHKPS.isEmpty)
        // The key is now in the keyring, tracked as unverified (TOFU),
        // exactly like a manual import.
        XCTAssertEqual(core.trustStore.state(forFpr: aliceKey.fingerprint), .unverified)
    }

    func testFetchSignerKeyFallsBackToHKPS() async throws {
        let aliceKey = try publicKeyData(for: Self.alice)
        let (service, client) = mockService(
            byFingerprint: .failure(.notFound),
            hkps: .success(aliceKey.data)
        )
        let core = try makeCore(keyServerService: service)

        let result = await core.fetchSignerKey(fingerprint: aliceKey.fingerprint, email: nil)

        let fetched = try XCTUnwrap(result.success)
        XCTAssertEqual(fetched.fingerprint, aliceKey.fingerprint)
        XCTAssertEqual(fetched.source, "keys.openpgp.org (HKPS)")
        XCTAssertEqual(client.fetchedHKPS.first?.0, aliceKey.fingerprint)
    }

    func testFetchSignerKeyFallsBackToEmail() async throws {
        let aliceKey = try publicKeyData(for: Self.alice)
        let (service, client) = mockService(byEmail: .success(aliceKey.data))
        let core = try makeCore(keyServerService: service)

        let result = await core.fetchSignerKey(
            fingerprint: aliceKey.fingerprint,
            email: Self.aliceEmail
        )

        let fetched = try XCTUnwrap(result.success)
        XCTAssertEqual(fetched.fingerprint, aliceKey.fingerprint)
        XCTAssertEqual(fetched.source, "keys.openpgp.org")
        // Fingerprint was tried first (VKS + both HKPS servers), then email.
        XCTAssertEqual(client.fetchedFingerprints, [aliceKey.fingerprint])
        XCTAssertEqual(client.fetchedHKPS.count, HKPSServer.allCases.count)
        XCTAssertEqual(client.fetchedEmails, [Self.aliceEmail])
    }

    func testFetchSignerKeyByEmailResolvesImportedFingerprint() async throws {
        let aliceKey = try publicKeyData(for: Self.alice)
        let (service, _) = mockService(byEmail: .success(aliceKey.data))
        let core = try makeCore(keyServerService: service)

        let result = await core.fetchSignerKey(fingerprint: nil, email: Self.aliceEmail)

        let fetched = try XCTUnwrap(result.success)
        XCTAssertEqual(fetched.fingerprint, aliceKey.fingerprint)
        XCTAssertEqual(core.trustStore.state(forFpr: aliceKey.fingerprint), .unverified)
    }

    // MARK: - Substitution guards and failures

    func testFetchSignerKeyRejectsKeyWithDifferentFingerprint() async throws {
        // The server answers the fingerprint query with somebody else's key;
        // it must not be treated as the signer's key.
        let bobKey = try publicKeyData(for: Self.bob)
        let aliceKey = try publicKeyData(for: Self.alice)
        let (service, _) = mockService(
            byFingerprint: .success(bobKey.data),
            hkps: .success(bobKey.data)
        )
        let engine = try makeEngine()
        let core = MessageSecurityCore(engine: engine, keyServerService: service)

        let result = await core.fetchSignerKey(fingerprint: aliceKey.fingerprint, email: nil)

        XCTAssertEqual(result.failure, .invalidResponse)
        // Alice's key is not in the keyring (Bob's key was imported, but
        // rejected as the answer to Alice's fingerprint).
        let known = try engine.keyManager.listKeys().map(\.fingerprint)
        XCTAssertFalse(known.contains { $0.caseInsensitiveCompare(aliceKey.fingerprint) == .orderedSame })
    }

    func testFetchSignerKeyByEmailRejectsKeyForDifferentAddress() async throws {
        let bobKey = try publicKeyData(for: Self.bob)
        let (service, _) = mockService(byEmail: .success(bobKey.data))
        let core = try makeCore(keyServerService: service)

        let result = await core.fetchSignerKey(fingerprint: nil, email: Self.aliceEmail)

        XCTAssertEqual(result.failure, .invalidResponse)
    }

    func testFetchSignerKeyNotFound() async throws {
        let aliceKey = try publicKeyData(for: Self.alice)
        let (service, _) = mockService()
        let core = try makeCore(keyServerService: service)

        let result = await core.fetchSignerKey(
            fingerprint: aliceKey.fingerprint,
            email: Self.aliceEmail
        )

        XCTAssertEqual(result.failure, .notFound)
    }

    func testFetchSignerKeyWithoutIdentifiersDoesNotHitNetwork() async throws {
        let (service, client) = mockService()
        let core = try makeCore(keyServerService: service)

        let result = await core.fetchSignerKey(fingerprint: nil, email: nil)

        XCTAssertEqual(result.failure, .notFound)
        XCTAssertTrue(client.fetchedFingerprints.isEmpty)
        XCTAssertTrue(client.fetchedHKPS.isEmpty)
        XCTAssertTrue(client.fetchedEmails.isEmpty)
        XCTAssertTrue(client.fetchedWKDs.isEmpty)
    }

    // MARK: - End-to-end: unknown signer → fetch → re-decode verifies

    func testFetchSignerKeyThenRedecodeVerifiesSignature() async throws {
        let aliceEngine = try makeEngine(keys: [Self.alice])
        let aliceFingerprint = try XCTUnwrap(aliceEngine.keyManager.listKeys().first?.fingerprint)
        let alicePublicKey = try aliceEngine.keyManager.exportKey(fingerprint: aliceFingerprint)
        let bobEngine = try makeEngine(keys: [Self.bob])

        // Alice signs; Bob does not have her key.
        let aliceCore = MessageSecurityCore(engine: aliceEngine)
        let encoded = try XCTUnwrap(aliceCore.encode(
            MockMessage(
                rawData: plainMessage(),
                fromAddress: Self.aliceEmail,
                recipientAddresses: [Self.bobEmail],
                isSending: true
            ),
            composeContext: MockComposeContext(shouldSign: true, shouldEncrypt: false)
        ).encodedMessage)

        let (service, client) = mockService(byEmail: .success(alicePublicKey))
        let bobCore = MessageSecurityCore(engine: bobEngine, keyServerService: service)

        // Decode once: unknown signer. librnp reports no fingerprint for an
        // unknown key, so the context carries the From: address as the email
        // fallback.
        let decoded = try XCTUnwrap(bobCore.decodedMessage(forMessageData: encoded.rawData))
        let signer = try XCTUnwrap(decoded.securityInformation.signers.first)
        let context = try XCTUnwrap(bobCore.signerContext(for: signer))
        XCTAssertEqual(context.status, RnpSignatureStatus.signerUnknown.rawValue)
        XCTAssertNil(context.fingerprint)
        XCTAssertEqual(context.email, Self.aliceEmail)

        // The banner action: fetch by the identifiers the context carries.
        let result = await bobCore.fetchSignerKey(
            fingerprint: context.fingerprint,
            email: context.email
        )
        let fetched = try XCTUnwrap(result.success)
        XCTAssertEqual(fetched.fingerprint, aliceFingerprint)
        XCTAssertEqual(client.fetchedEmails, [Self.aliceEmail])
        XCTAssertTrue(client.fetchedFingerprints.isEmpty)

        // Re-decode: the signature now verifies against the imported key.
        let refreshed = try XCTUnwrap(bobCore.decodedMessage(forMessageData: encoded.rawData))
        let refreshedSigner = try XCTUnwrap(refreshed.securityInformation.signers.first)
        XCTAssertEqual(refreshedSigner.signatureLabel, Self.alice)
        let refreshedContext = try XCTUnwrap(bobCore.signerContext(for: refreshedSigner))
        XCTAssertEqual(refreshedContext.status, RnpSignatureStatus.valid.rawValue)
        XCTAssertEqual(refreshedContext.fingerprint, aliceFingerprint)
        XCTAssertEqual(refreshedContext.email, Self.aliceEmail)
        XCTAssertNil(refreshed.securityInformation.signingError)
    }

    // MARK: - SignerContext wire format

    func testSignerContextRoundTripsEmail() throws {
        let context = SignerContext(
            fingerprint: nil,
            status: RnpSignatureStatus.signerUnknown.rawValue,
            isEncrypted: false,
            email: Self.aliceEmail
        )
        let decoded = try JSONDecoder().decode(SignerContext.self, from: JSONEncoder().encode(context))
        XCTAssertEqual(decoded, context)
        XCTAssertEqual(decoded.email, Self.aliceEmail)
    }

    func testSignerContextDecodesPayloadWithoutEmail() throws {
        // Payload written by an older extension version (no "email" key)
        // must still decode.
        let json = Data(#"{"fingerprint":"ABC123","status":"signerUnknown","isEncrypted":true}"#.utf8)
        let context = try JSONDecoder().decode(SignerContext.self, from: json)
        XCTAssertEqual(context.fingerprint, "ABC123")
        XCTAssertEqual(context.status, "signerUnknown")
        XCTAssertEqual(context.isEncrypted, true)
        XCTAssertNil(context.email)
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

//
//  KeyServerServiceSettingsTests.swift
//  swift-rnp
//
//  Tests that KeyServerService follows the configured keyserver list:
//  priority order, per-kind applicability, and fallback when a server
//  fails.
//

import KeyServerClient
import XCTest
@testable import MailSecurityEngine

final class KeyServerServiceSettingsTests: XCTestCase {
    private static let fingerprint = "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"
    private static let email = "alice@example.com"
    private static let keyData = Data("armored-key".utf8)

    private func makeService(
        settings: KeyServerSettings,
        responses: MockKeyServerResponses
    ) -> (KeyServerService, MockKeyServerClient) {
        let client = MockKeyServerClient(responses: responses)
        return (KeyServerService(client: client, fixedSettings: settings), client)
    }

    // MARK: - Fingerprint discovery

    func testDiscoverByFingerprintHonorsConfiguredOrder() async {
        let (service, client) = makeService(
            settings: KeyServerSettings(servers: [
                KeyServer(kind: .hkps, host: "keys.example.com"),
                KeyServer(kind: .vks, host: "keys.openpgp.org"),
            ]),
            responses: MockKeyServerResponses(
                byFingerprintResult: .success(Self.keyData),
                hkpsResult: .success(Self.keyData)
            )
        )
        let result = await service.discoverByFingerprint(Self.fingerprint)
        guard case let .success(key) = result else {
            return XCTFail("Expected success, got \(result)")
        }
        XCTAssertEqual(key.source, "keys.example.com (HKPS)")
        XCTAssertEqual(client.fetchedHKPS.map { $0.1 }, [HKPSServer(rawValue: "keys.example.com")])
        XCTAssertTrue(client.fetchedFingerprints.isEmpty, "VKS must not be tried after HKPS succeeds")
    }

    func testDiscoverByFingerprintFallsBackFromHKPSToVKS() async {
        let (service, client) = makeService(
            settings: KeyServerSettings(servers: [
                KeyServer(kind: .hkps, host: "keys.example.com"),
                KeyServer(kind: .vks, host: "keys.openpgp.org"),
            ]),
            responses: MockKeyServerResponses(
                byFingerprintResult: .success(Self.keyData),
                hkpsResult: .failure(.notFound)
            )
        )
        let result = await service.discoverByFingerprint(Self.fingerprint)
        guard case let .success(key) = result else {
            return XCTFail("Expected success, got \(result)")
        }
        XCTAssertEqual(key.source, "keys.openpgp.org")
        XCTAssertEqual(client.fetchedHKPS.count, 1)
        XCTAssertEqual(client.fetchedFingerprints, [Self.fingerprint])
    }

    func testDiscoverByFingerprintSkipsWKD() async {
        let (service, client) = makeService(
            settings: KeyServerSettings(servers: [
                KeyServer(kind: .wkd, host: ""),
                KeyServer(kind: .hkps, host: "keys.example.com"),
            ]),
            responses: MockKeyServerResponses(
                wkdResult: .success(Self.keyData),
                hkpsResult: .success(Self.keyData)
            )
        )
        let result = await service.discoverByFingerprint(Self.fingerprint)
        guard case let .success(key) = result else {
            return XCTFail("Expected success, got \(result)")
        }
        XCTAssertEqual(key.source, "keys.example.com (HKPS)")
        XCTAssertTrue(client.fetchedWKDs.isEmpty, "WKD does not apply to fingerprint lookups")
    }

    func testDiscoverByFingerprintFailsWhenAllServersFail() async {
        let (service, _) = makeService(
            settings: KeyServerSettings(servers: [
                KeyServer(kind: .vks, host: "keys.openpgp.org"),
                KeyServer(kind: .hkps, host: "keys.example.com"),
            ]),
            responses: MockKeyServerResponses(
                byFingerprintResult: .failure(.notFound),
                hkpsResult: .failure(.network(underlying: "offline"))
            )
        )
        let result = await service.discoverByFingerprint(Self.fingerprint)
        guard case let .failure(error) = result else {
            return XCTFail("Expected failure, got \(result)")
        }
        XCTAssertEqual(error, .network(underlying: "offline"))
    }

    // MARK: - Email discovery

    func testDiscoverByEmailHonorsConfiguredOrder() async {
        let (service, client) = makeService(
            settings: KeyServerSettings(servers: [
                KeyServer(kind: .vks, host: "keys.openpgp.org"),
                KeyServer(kind: .wkd, host: ""),
            ]),
            responses: MockKeyServerResponses(
                byEmailResult: .success(Self.keyData),
                wkdResult: .success(Self.keyData)
            )
        )
        let result = await service.discoverByEmail(Self.email)
        guard case let .success(key) = result else {
            return XCTFail("Expected success, got \(result)")
        }
        XCTAssertEqual(key.source, "keys.openpgp.org")
        XCTAssertEqual(client.fetchedEmails, [Self.email])
        XCTAssertTrue(client.fetchedWKDs.isEmpty, "WKD must not be tried after VKS succeeds")
    }

    func testDiscoverByEmailFallsBackToWKD() async {
        let (service, client) = makeService(
            settings: KeyServerSettings(servers: [
                KeyServer(kind: .vks, host: "keys.openpgp.org"),
                KeyServer(kind: .wkd, host: ""),
            ]),
            responses: MockKeyServerResponses(
                byEmailResult: .failure(.notFound),
                wkdResult: .success(Self.keyData)
            )
        )
        let result = await service.discoverByEmail(Self.email)
        guard case let .success(key) = result else {
            return XCTFail("Expected success, got \(result)")
        }
        XCTAssertEqual(key.source, "WKD (advanced)")
        XCTAssertEqual(client.fetchedWKDs, ["\(Self.email) (advanced=true)"])
    }

    func testDiscoverByEmailSkipsHKPS() async {
        let (service, client) = makeService(
            settings: KeyServerSettings(servers: [
                KeyServer(kind: .hkps, host: "keys.example.com"),
                KeyServer(kind: .vks, host: "keys.openpgp.org"),
            ]),
            responses: MockKeyServerResponses(
                byEmailResult: .success(Self.keyData),
                hkpsResult: .success(Self.keyData)
            )
        )
        let result = await service.discoverByEmail(Self.email)
        guard case .success = result else {
            return XCTFail("Expected success, got \(result)")
        }
        XCTAssertTrue(client.fetchedHKPS.isEmpty, "HKPS does not apply to email lookups")
    }

    // MARK: - Publishing

    func testUploadPrefersConfiguredHKPS() async throws {
        let (service, client) = makeService(
            settings: KeyServerSettings(servers: [
                KeyServer(kind: .hkps, host: "keys.example.com"),
                KeyServer(kind: .vks, host: "keys.openpgp.org"),
            ]),
            responses: MockKeyServerResponses(
                uploadResult: .success(UploadReceipt(body: "vks")),
                hkpsUploadResult: .success(UploadReceipt(body: "hkps"))
            )
        )
        let receipt = try await service.upload(armoredKey: "armored-key")
        XCTAssertEqual(receipt.body, "hkps")
        XCTAssertEqual(client.hkpsUploads.count, 1)
        XCTAssertTrue(client.uploadedKeys.isEmpty, "VKS must not be tried after HKPS succeeds")
    }

    func testUploadFallsBackToVKS() async throws {
        let (service, client) = makeService(
            settings: KeyServerSettings(servers: [
                KeyServer(kind: .hkps, host: "keys.example.com"),
                KeyServer(kind: .vks, host: "keys.openpgp.org"),
            ]),
            responses: MockKeyServerResponses(
                uploadResult: .success(UploadReceipt(body: "vks")),
                hkpsUploadResult: .failure(.server(statusCode: 500, message: nil))
            )
        )
        let receipt = try await service.upload(armoredKey: "armored-key")
        XCTAssertEqual(receipt.body, "vks")
        XCTAssertEqual(client.hkpsUploads.count, 1)
        XCTAssertEqual(client.uploadedKeys, ["armored-key"])
    }

    func testUploadSkipsWKDAndThrowsLastError() async {
        let (service, client) = makeService(
            settings: KeyServerSettings(servers: [
                KeyServer(kind: .wkd, host: ""),
                KeyServer(kind: .hkps, host: "keys.example.com"),
            ]),
            responses: MockKeyServerResponses(
                hkpsUploadResult: .failure(.network(underlying: "offline"))
            )
        )
        do {
            _ = try await service.upload(armoredKey: "armored-key")
            XCTFail("Expected the HKPS failure to surface")
        } catch {
            XCTAssertEqual(error as? KeyServerError, .network(underlying: "offline"))
        }
        XCTAssertEqual(client.hkpsUploads.count, 1)
        XCTAssertTrue(client.uploadedKeys.isEmpty)
    }
}

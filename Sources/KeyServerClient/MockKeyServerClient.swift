//
//  MockKeyServerClient.swift
//  swift-rnp
//
//  Scripted mock keyserver client for tests.
//

import Foundation

/// Scripted responses for the mock keyserver client.
public struct MockKeyServerResponses: Sendable {
    public var uploadResult: Result<UploadReceipt, KeyServerError>?
    public var byEmailResult: Result<Data, KeyServerError>?
    public var byFingerprintResult: Result<Data, KeyServerError>?
    public var wkdResult: Result<Data, KeyServerError>?
    public var hkpsResult: Result<Data, KeyServerError>?
    public var hkpsUploadResult: Result<UploadReceipt, KeyServerError>?

    public init(
        uploadResult: Result<UploadReceipt, KeyServerError>? = nil,
        byEmailResult: Result<Data, KeyServerError>? = nil,
        byFingerprintResult: Result<Data, KeyServerError>? = nil,
        wkdResult: Result<Data, KeyServerError>? = nil,
        hkpsResult: Result<Data, KeyServerError>? = nil,
        hkpsUploadResult: Result<UploadReceipt, KeyServerError>? = nil
    ) {
        self.uploadResult = uploadResult
        self.byEmailResult = byEmailResult
        self.byFingerprintResult = byFingerprintResult
        self.wkdResult = wkdResult
        self.hkpsResult = hkpsResult
        self.hkpsUploadResult = hkpsUploadResult
    }
}

/// Mock keyserver client with fixed responses.
public final class MockKeyServerClient: KeyServerClient, @unchecked Sendable {
    public var responses: MockKeyServerResponses
    public private(set) var uploadedKeys: [String] = []
    public private(set) var fetchedEmails: [String] = []
    public private(set) var fetchedFingerprints: [String] = []
    public private(set) var fetchedWKDs: [String] = []
    public private(set) var fetchedHKPS: [(String, HKPSServer)] = []
    public private(set) var hkpsUploads: [(String, HKPSServer)] = []

    public init(responses: MockKeyServerResponses = MockKeyServerResponses()) {
        self.responses = responses
    }

    public func upload(armoredKey: String) async throws -> UploadReceipt {
        uploadedKeys.append(armoredKey)
        guard let result = responses.uploadResult else {
            throw KeyServerError.invalidResponse
        }
        return try result.get()
    }

    public func fetchByEmail(_ email: String) async throws -> Data {
        fetchedEmails.append(email)
        guard let result = responses.byEmailResult else {
            throw KeyServerError.invalidResponse
        }
        return try result.get()
    }

    public func fetchByFingerprint(_ fingerprint: String) async throws -> Data {
        fetchedFingerprints.append(fingerprint)
        guard let result = responses.byFingerprintResult else {
            throw KeyServerError.invalidResponse
        }
        return try result.get()
    }

    public func fetchWKD(email: String, advanced: Bool) async throws -> Data {
        fetchedWKDs.append("\(email) (advanced=\(advanced))")
        guard let result = responses.wkdResult else {
            throw KeyServerError.invalidResponse
        }
        return try result.get()
    }

    public func fetchHKPS(fingerprint: String, server: HKPSServer) async throws -> Data {
        fetchedHKPS.append((fingerprint, server))
        guard let result = responses.hkpsResult else {
            throw KeyServerError.invalidResponse
        }
        return try result.get()
    }

    public func uploadHKPS(armoredKey: String, server: HKPSServer) async throws -> UploadReceipt {
        hkpsUploads.append((armoredKey, server))
        guard let result = responses.hkpsUploadResult else {
            throw KeyServerError.invalidResponse
        }
        return try result.get()
    }
}

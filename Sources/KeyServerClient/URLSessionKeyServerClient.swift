//
//  URLSessionKeyServerClient.swift
//  swift-rnp
//
//  URLSession-backed implementation of the keyserver client.
//

import Foundation

/// Default keyserver client using `URLSession`.
public final class URLSessionKeyServerClient: KeyServerClient {
    private let session: URLSession
    private let uploadURL: URL
    private let baseURL: URL

    /// Creates a client.
    ///
    /// - Parameters:
    ///   - session: The URLSession to use. Defaults to `.shared`.
    ///   - baseURL: Base URL for VKS lookups. Defaults to keys.openpgp.org.
    ///   - uploadURL: URL for key uploads. Defaults to keys.openpgp.org upload endpoint.
    public init(
        session: URLSession = .shared,
        baseURL: URL = URL(string: "https://keys.openpgp.org")!,
        uploadURL: URL = URL(string: "https://keys.openpgp.org/vks/v1/upload")!
    ) {
        self.session = session
        self.baseURL = baseURL
        self.uploadURL = uploadURL
    }

    public func upload(armoredKey: String) async throws -> UploadReceipt {
        var request = URLRequest(url: uploadURL)
        request.httpMethod = "POST"
        request.setValue("text/plain", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(armoredKey.utf8)

        let (data, response) = try await session.data(for: request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
        let body = String(decoding: data, as: UTF8.self)

        switch statusCode {
        case 200:
            return UploadReceipt(body: body)
        case 400:
            throw KeyServerError.malformedKey
        default:
            throw KeyServerError.server(statusCode: statusCode, message: body)
        }
    }

    public func fetchByEmail(_ email: String) async throws -> Data {
        let encodedEmail = email.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? email
        let url = baseURL.appendingPathComponent("vks/v1/by-email/\(encodedEmail)")
        return try await fetchData(from: url)
    }

    public func fetchByFingerprint(_ fingerprint: String) async throws -> Data {
        let cleaned = fingerprint.uppercased().filter { $0.isHexDigit }
        guard cleaned.count >= 16 else {
            throw KeyServerError.invalidFingerprint
        }
        let url = baseURL.appendingPathComponent("vks/v1/by-fingerprint/\(cleaned)")
        return try await fetchData(from: url)
    }

    public func fetchWKD(email: String, advanced: Bool) async throws -> Data {
        let url = try WKDEncoding.url(for: email, advanced: advanced)
        return try await fetchData(from: url)
    }

    public func fetchHKPS(fingerprint: String, server: HKPSServer) async throws -> Data {
        let cleaned = fingerprint.uppercased().filter { $0.isHexDigit }
        guard cleaned.count >= 16 else {
            throw KeyServerError.invalidFingerprint
        }
        guard var components = URLComponents(string: server.lookupURL) else {
            throw KeyServerError.invalidFingerprint
        }
        components.queryItems = [
            URLQueryItem(name: "op", value: "get"),
            URLQueryItem(name: "options", value: "mr"),
            URLQueryItem(name: "search", value: "0x\(cleaned)")
        ]
        guard let url = components.url else {
            throw KeyServerError.invalidFingerprint
        }
        return try await fetchData(from: url)
    }

    public func uploadHKPS(armoredKey: String, server: HKPSServer) async throws -> UploadReceipt {
        guard let url = URL(string: server.addURL) else {
            throw KeyServerError.invalidResponse
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        let encoded = armoredKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? armoredKey
        request.httpBody = Data("keytext=\(encoded)".utf8)

        let (data, response) = try await session.data(for: request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
        let body = String(decoding: data, as: UTF8.self)

        switch statusCode {
        case 200:
            return UploadReceipt(body: body)
        case 400:
            throw KeyServerError.malformedKey
        default:
            throw KeyServerError.server(statusCode: statusCode, message: body)
        }
    }

    private func fetchData(from url: URL) async throws -> Data {
        let (data, response) = try await session.data(from: url)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0

        switch statusCode {
        case 200:
            return data
        case 404:
            throw KeyServerError.notFound
        default:
            let body = String(decoding: data, as: UTF8.self)
            throw KeyServerError.server(statusCode: statusCode, message: body)
        }
    }
}

private extension Character {
    var isHexDigit: Bool {
        self.isASCII && (
            (self >= "0" && self <= "9") ||
            (self >= "A" && self <= "F") ||
            (self >= "a" && self <= "f")
        )
    }
}

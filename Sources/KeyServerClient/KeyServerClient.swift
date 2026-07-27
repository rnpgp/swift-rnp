//
//  KeyServerClient.swift
//  swift-rnp
//
//  Protocol and types for keyserver publishing and discovery.
//

import Foundation

/// Errors thrown by keyserver operations.
public enum KeyServerError: Error, Equatable {
    case invalidEmail
    case invalidFingerprint
    case network(underlying: String)
    case notFound
    case invalidResponse
    case server(statusCode: Int, message: String?)
    case malformedKey
}

extension KeyServerError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidEmail:
            return "The email address is not valid."
        case .invalidFingerprint:
            return "The fingerprint is not valid."
        case .network(let message):
            return "Network error: \(message)"
        case .notFound:
            return "The key was not found on the server."
        case .invalidResponse:
            return "The server returned an unexpected response."
        case .server(let code, let message):
            return "Server error \(code): \(message ?? "no details")"
        case .malformedKey:
            return "The downloaded key data is malformed."
        }
    }
}

/// Receipt returned after a successful key upload.
public struct UploadReceipt: Equatable, Sendable {
    /// Raw response body from the server.
    public let body: String
    /// Token extracted from the response, if present.
    public let token: String?
    /// Human-readable server message.
    public let message: String?

    public init(body: String, token: String? = nil, message: String? = nil) {
        self.body = body
        self.token = token
        self.message = message
    }
}

/// Client for publishing and discovering OpenPGP keys on public keyservers.
public protocol KeyServerClient: Sendable {
    /// Uploads an armored public key to the configured keyserver.
    func upload(armoredKey: String) async throws -> UploadReceipt

    /// Fetches a key by email address from the configured VKS server.
    func fetchByEmail(_ email: String) async throws -> Data

    /// Fetches a key by fingerprint from the configured VKS server.
    func fetchByFingerprint(_ fingerprint: String) async throws -> Data

    /// Fetches a key using the Web Key Directory protocol.
    func fetchWKD(email: String, advanced: Bool) async throws -> Data

    /// Fetches a key by fingerprint from an HKPS server.
    func fetchHKPS(fingerprint: String, server: HKPSServer) async throws -> Data

    /// Uploads an armored public key to an HKPS server (`/pks/add`).
    func uploadHKPS(armoredKey: String, server: HKPSServer) async throws -> UploadReceipt
}

/// An HKP keyserver reached over HTTPS.
///
/// `RawRepresentable` over the host name, so `HKPSServer(rawValue:)` works
/// the way the former enum's raw-value initializer did — but accepts any
/// host, which is what user-configured (custom) HKPS servers need.
public struct HKPSServer: RawRepresentable, Equatable, Hashable, Sendable {
    /// Host name, e.g. "keys.openpgp.org".
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    /// keys.openpgp.org's HKP endpoint.
    public static let keysOpenPGP = HKPSServer(rawValue: "keys.openpgp.org")
    /// keyserver.ubuntu.com.
    public static let ubuntu = HKPSServer(rawValue: "keyserver.ubuntu.com")
    /// Built-in servers, in the order they are tried as HKPS fallbacks.
    public static let allCases: [HKPSServer] = [.keysOpenPGP, .ubuntu]

    /// HKP lookup endpoint (`op=get`).
    public var lookupURL: String { "https://\(rawValue)/pks/lookup" }
    /// HKP add endpoint accepting key uploads.
    public var addURL: String { "https://\(rawValue)/pks/add" }
}

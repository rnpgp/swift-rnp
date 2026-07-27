//
//  KeyServerService.swift
//  swift-rnp
//
//  High-level keyserver publish/discovery operations backed by
//  KeyServerClient.
//

@_exported import KeyServerClient
import Foundation

/// Result of fetching a key from a keyserver.
public struct FetchedKey: Equatable {
    /// Raw key data (armored or binary).
    public let data: Data
    /// Human-readable source description.
    public let source: String

    public init(data: Data, source: String) {
        self.data = data
        self.source = source
    }
}

/// High-level service for publishing and discovering keys.
///
/// The servers tried — and their order — come from `KeyServerSettings`,
/// loaded from the app-group defaults on every call so edits made in the
/// container app take effect without restarting either process. The
/// built-in defaults reproduce the behavior that used to be hardcoded:
/// WKD then VKS for email lookups, VKS then the HKP servers for
/// fingerprint lookups, VKS for uploads.
public final class KeyServerService: Sendable {
    private let client: KeyServerClient
    private let settingsProvider: @Sendable () -> KeyServerSettings

    public init(client: KeyServerClient = URLSessionKeyServerClient()) {
        self.client = client
        self.settingsProvider = { KeyServerSettingsStore().load() }
    }

    /// Creates a service with a fixed keyserver list instead of the shared
    /// store. Used by tests.
    init(client: KeyServerClient, fixedSettings: KeyServerSettings) {
        self.client = client
        self.settingsProvider = { fixedSettings }
    }

    /// Uploads an armored public key, following the configured server
    /// order.
    ///
    /// HKPS servers accept uploads via `/pks/add`; the VKS entry uploads to
    /// keys.openpgp.org (which emails a verification link). WKD cannot
    /// accept uploads and is skipped. The next server is tried when one
    /// fails, so a failing HKPS server falls back to VKS and vice versa.
    public func upload(armoredKey: String) async throws -> UploadReceipt {
        var lastError: KeyServerError = .network(underlying: "No keyserver configured for uploads.")
        for server in settingsProvider().servers {
            do {
                switch server.kind {
                case .vks:
                    return try await client.upload(armoredKey: armoredKey)
                case .hkps:
                    return try await client.uploadHKPS(armoredKey: armoredKey, server: HKPSServer(rawValue: server.host))
                case .wkd:
                    continue
                }
            } catch {
                lastError = error as? KeyServerError ?? .network(underlying: error.localizedDescription)
            }
        }
        throw lastError
    }

    /// Looks up a key by email, following the configured server order.
    ///
    /// WKD entries try the advanced method, then the direct method; VKS
    /// entries query the by-email API. HKPS entries are skipped: HKP
    /// lookups are by fingerprint/key ID, not by email.
    public func discoverByEmail(_ email: String) async -> Result<FetchedKey, KeyServerError> {
        var lastError: KeyServerError = .notFound
        for server in settingsProvider().servers {
            switch server.kind {
            case .wkd:
                switch await fetchWKD(email: email, advanced: true) {
                case let .success(data):
                    return .success(FetchedKey(data: data, source: "WKD (advanced)"))
                case let .failure(error):
                    lastError = error as? KeyServerError ?? .network(underlying: error.localizedDescription)
                }
                switch await fetchWKD(email: email, advanced: false) {
                case let .success(data):
                    return .success(FetchedKey(data: data, source: "WKD (direct)"))
                case let .failure(error):
                    lastError = error as? KeyServerError ?? .network(underlying: error.localizedDescription)
                }
            case .vks:
                do {
                    let data = try await client.fetchByEmail(email)
                    return .success(FetchedKey(data: data, source: server.host))
                } catch {
                    lastError = error as? KeyServerError ?? .network(underlying: error.localizedDescription)
                }
            case .hkps:
                continue
            }
        }
        return .failure(lastError)
    }

    /// Looks up a key by fingerprint, following the configured server
    /// order.
    ///
    /// VKS (keys.openpgp.org) only serves keys with verified user IDs, so a
    /// key that was never uploaded there — or whose email was never
    /// verified — is missed. The configured HKPS servers carry unverified
    /// uploads too and are tried in their configured positions, so a
    /// failing HKPS server falls back to VKS and vice versa. WKD entries
    /// are skipped: WKD derives from an email address, not a fingerprint.
    public func discoverByFingerprint(_ fingerprint: String) async -> Result<FetchedKey, KeyServerError> {
        var lastError: KeyServerError = .notFound
        for server in settingsProvider().servers {
            do {
                switch server.kind {
                case .vks:
                    let data = try await client.fetchByFingerprint(fingerprint)
                    return .success(FetchedKey(data: data, source: server.host))
                case .hkps:
                    let data = try await client.fetchHKPS(fingerprint: fingerprint, server: HKPSServer(rawValue: server.host))
                    return .success(FetchedKey(data: data, source: "\(server.host) (HKPS)"))
                case .wkd:
                    continue
                }
            } catch {
                lastError = error as? KeyServerError ?? .network(underlying: error.localizedDescription)
            }
        }
        return .failure(lastError)
    }

    /// Looks up a key by fingerprint, falling back to email discovery.
    ///
    /// Fingerprint lookup is tried first when a fingerprint is available —
    /// it identifies the exact key, unlike an email search, which can return
    /// any key carrying the address. When the fingerprint is unavailable or
    /// not found on any server, the email path (`discoverByEmail`: WKD, then
    /// VKS) is tried. Returns `.notFound` when neither identifier is given.
    public func discover(fingerprint: String?, email: String?) async -> Result<FetchedKey, KeyServerError> {
        var lastError: KeyServerError = .notFound
        if let fingerprint, !fingerprint.isEmpty {
            switch await discoverByFingerprint(fingerprint) {
            case let .success(key):
                return .success(key)
            case let .failure(error):
                lastError = error
            }
        }
        if let email, !email.isEmpty {
            switch await discoverByEmail(email) {
            case let .success(key):
                return .success(key)
            case let .failure(error):
                lastError = error
            }
        }
        return .failure(lastError)
    }

    private func fetchWKD(email: String, advanced: Bool) async -> Result<Data, Error> {
        do {
            let data = try await client.fetchWKD(email: email, advanced: advanced)
            return .success(data)
        } catch {
            return .failure(error)
        }
    }
}

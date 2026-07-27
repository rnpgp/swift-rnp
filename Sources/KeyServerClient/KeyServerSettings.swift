//
//  KeyServerSettings.swift
//  swift-rnp
//
//  User-configurable keyserver list: which servers are used for key
//  discovery and publishing, and in which priority order. Persisted in the
//  app-group `UserDefaults` suite so the container app (which edits the
//  list) and the Mail extension (which reads it) share the configuration.
//

import Foundation

/// The protocol a keyserver speaks.
public enum KeyServerKind: String, Codable, Sendable, CaseIterable {
    /// keys.openpgp.org's Verified Keyserver API (`/vks/v1/...`).
    case vks
    /// Web Key Directory, derived from the email address domain.
    case wkd
    /// HKP over HTTPS (`/pks/lookup`, `/pks/add`).
    case hkps
}

/// One entry in the keyserver priority list.
public struct KeyServer: Codable, Equatable, Hashable, Sendable, Identifiable {
    /// The protocol this server speaks.
    public var kind: KeyServerKind
    /// Host name (e.g. "keys.openpgp.org"). Empty for WKD, which derives
    /// the host from each looked-up email address.
    public var host: String

    public init(kind: KeyServerKind, host: String) {
        self.kind = kind
        self.host = host
    }

    public var id: String { "\(kind.rawValue):\(host)" }

    /// Whether this server is a user-added entry (i.e. not one of the
    /// built-in defaults). Only custom servers can be removed in the UI.
    public var isCustom: Bool {
        !KeyServerSettings.defaultServers.contains(self)
    }
}

/// The ordered keyserver list. Earlier entries are tried first; when a
/// server fails or does not apply to the lookup, the next one is tried
/// (fallback).
public struct KeyServerSettings: Codable, Equatable, Sendable {
    /// Servers in priority order.
    public var servers: [KeyServer]

    public init(servers: [KeyServer] = KeyServerSettings.defaultServers) {
        self.servers = servers
    }

    /// Built-in configuration: WKD and keys.openpgp.org (VKS) for email
    /// discovery, keys.openpgp.org (VKS) and the HKP servers for
    /// fingerprint discovery. Matches the behavior that used to be
    /// hardcoded in `KeyServerService`.
    public static let defaultServers: [KeyServer] = [
        KeyServer(kind: .wkd, host: ""),
        KeyServer(kind: .vks, host: "keys.openpgp.org"),
        KeyServer(kind: .hkps, host: "keys.openpgp.org"),
        KeyServer(kind: .hkps, host: "keyserver.ubuntu.com"),
    ]

    /// Validates and normalizes a user-entered HKPS host name.
    ///
    /// Accepts bare host names ("keys.example.com") as well as pasted URLs
    /// ("https://keys.example.com/pks"), which are reduced to their host.
    /// Returns `nil` when the input is not a valid DNS host name.
    public static func normalizedHKPSHost(_ input: String) -> String? {
        var host = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if let schemeRange = host.range(of: "://") {
            host = String(host[schemeRange.upperBound...])
        }
        // Drop any path, query, or port the user may have pasted.
        if let slash = host.firstIndex(of: "/") {
            host = String(host[..<slash])
        }
        if let colon = host.firstIndex(of: ":") {
            host = String(host[..<colon])
        }
        host = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard isValidHostName(host) else {
            return nil
        }
        return host
    }

    /// RFC 1123 host name: dot-separated labels of letters, digits, and
    /// interior hyphens.
    private static func isValidHostName(_ host: String) -> Bool {
        guard !host.isEmpty, host.count <= 253 else {
            return false
        }
        let labelPattern = #"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"#
        return host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            !label.isEmpty && label.count <= 63
                && label.range(of: labelPattern, options: .regularExpression) != nil
        }
    }

    /// Removes duplicates and entries with invalid hosts.
    public func sanitized() -> KeyServerSettings {
        var seen = Set<KeyServer>()
        var result: [KeyServer] = []
        for server in servers {
            let valid: Bool
            switch server.kind {
            case .wkd:
                valid = server.host.isEmpty
            case .vks, .hkps:
                valid = Self.normalizedHKPSHost(server.host) == server.host
            }
            if valid, !seen.contains(server) {
                seen.insert(server)
                result.append(server)
            }
        }
        return KeyServerSettings(servers: result)
    }
}

/// Loads and saves `KeyServerSettings` in a `UserDefaults` suite.
///
/// The default suite is the app group shared with the Mail extension, so
/// the container app's edits are visible to the extension without a
/// restart. When the suite is unavailable (unsigned local builds without
/// the app-group entitlement) the standard defaults are used instead.
public final class KeyServerSettingsStore: @unchecked Sendable {
    /// `UserDefaults` key under which the JSON-encoded settings are stored.
    public static let defaultsKey = "keyServers"

    private let defaults: UserDefaults

    /// Defaults suite shared between the container app and the extension.
    public static var sharedDefaults: UserDefaults {
        UserDefaults(suiteName: appGroupIdentifier) ?? .standard
    }

    public init(defaults: UserDefaults = KeyServerSettingsStore.sharedDefaults) {
        self.defaults = defaults
    }

    /// Loads the settings, falling back to the built-in defaults when
    /// nothing is stored, the data is corrupt, or sanitizing drops every
    /// entry.
    public func load() -> KeyServerSettings {
        guard let data = defaults.data(forKey: Self.defaultsKey),
              let decoded = try? JSONDecoder().decode(KeyServerSettings.self, from: data)
        else {
            return KeyServerSettings()
        }
        let sanitized = decoded.sanitized()
        return sanitized.servers.isEmpty ? KeyServerSettings() : sanitized
    }

    public func save(_ settings: KeyServerSettings) {
        let sanitized = settings.sanitized()
        guard let data = try? JSONEncoder().encode(sanitized) else {
            return
        }
        defaults.set(data, forKey: Self.defaultsKey)
    }

    /// Removes the stored settings so the next load returns the defaults.
    public func reset() {
        defaults.removeObject(forKey: Self.defaultsKey)
    }

    /// App group identifier shared by the container app and the Mail
    /// extension.
    ///
    /// Mirrors `AppGroup.identifier` in MailSecurityEngine — duplicated
    /// here because KeyServerClient is a dependency of MailSecurityEngine
    /// and cannot import it. The value is injected via the
    /// `RNPMAILAppGroup` Info.plist key; a hardcoded fallback keeps
    /// unsigned local builds working.
    private static let appGroupIdentifier: String = {
        if let value = Bundle.main.object(forInfoDictionaryKey: "RNPMAILAppGroup") as? String,
           !value.isEmpty,
           !value.hasPrefix("$(") {
            return value
        }
        return "group.com.rnpgp.RNPForMail"
    }()
}

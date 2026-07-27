//
//  OperationVerification.swift
//  swift-rnp
//
//  Opt-in per-operation user verification ("require Touch ID for each
//  sign/encrypt/decrypt operation") with a session timeout.
//
//  The setting lives in the app-group `UserDefaults` suite so the container
//  app (which writes it) and the Mail extension (which reads it from the
//  passphrase-provider path) share the value. When the suite is unavailable
//  — unsigned local builds without the app-group entitlement — both
//  processes fall back to their standard defaults and the setting simply
//  does not propagate.
//

import Foundation

/// Setting for per-operation user verification of secret-key operations.
///
/// When enabled, `KeychainPassphraseStore` requires a fresh user-presence
/// verification (Touch ID, with the login-password fallback) before handing
/// out a passphrase, once per `sessionTimeout` window rather than once per
/// process lifetime. A burst of librnp passphrase requests within one
/// operation therefore triggers a single prompt.
public enum OperationVerification {
    /// `UserDefaults` key for the enabled flag.
    public static let enabledDefaultsKey = "requireTouchIDPerOperation"
    /// `UserDefaults` key for the session timeout, in seconds.
    public static let timeoutDefaultsKey = "operationVerificationTimeoutSeconds"
    /// Timeout used when none (or a non-positive value) is stored.
    public static let defaultTimeout: TimeInterval = 30

    /// Defaults suite shared between the container app and the extension.
    public static var sharedDefaults: UserDefaults {
        UserDefaults(suiteName: AppGroup.identifier) ?? .standard
    }

    /// Whether per-operation verification is enabled. Off by default: the
    /// keyring-unlock behavior alone governs passphrase access until the
    /// user opts in.
    public static func isEnabled(defaults: UserDefaults = sharedDefaults) -> Bool {
        defaults.bool(forKey: enabledDefaultsKey)
    }

    public static func setEnabled(_ enabled: Bool, defaults: UserDefaults = sharedDefaults) {
        defaults.set(enabled, forKey: enabledDefaultsKey)
    }

    /// How long a successful verification authorizes secret-key operations,
    /// in seconds. Non-positive stored values fall back to `defaultTimeout`.
    public static func sessionTimeout(defaults: UserDefaults = sharedDefaults) -> TimeInterval {
        let value = defaults.double(forKey: timeoutDefaultsKey)
        return value > 0 ? value : defaultTimeout
    }

    public static func setSessionTimeout(_ timeout: TimeInterval, defaults: UserDefaults = sharedDefaults) {
        defaults.set(timeout, forKey: timeoutDefaultsKey)
    }
}

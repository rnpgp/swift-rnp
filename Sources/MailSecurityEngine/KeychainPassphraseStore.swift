//
//  KeychainPassphraseStore.swift
//  swift-rnp
//
//  Keyring passphrase storage in the macOS Keychain.
//
//  A single passphrase protects all keys in the shared keyring. It is stored
//  as a generic password; with both targets listing the same keychain access
//  group in their entitlements, the item is shared between the container app
//  and the Mail extension. (Keychain sharing requires proper code signing —
//  see README.md; unsigned local builds still work because macOS Keychain
//  does not isolate unsigned clients the way iOS does.)
//
//  Touch ID: when the user opts in during onboarding, the passphrase lives
//  ONLY in a second item guarded by a `SecAccessControl` with `.userPresence`,
//  so every read prompts for Touch ID (with the system login-password
//  fallback). The plain item is removed in that case — keeping it would let
//  every reader bypass biometry, which is exactly the "zero runtime effect"
//  this store is meant to avoid. Reads route to the biometric item whenever
//  it exists, and a cancelled/failed authentication never creates or
//  overwrites a passphrase (which would lock the keyring permanently).
//
//  Biometric storage needs a signed build with the keychain entitlements:
//  `SecItemAdd` with an access control fails with `errSecMissingEntitlement`
//  in unsigned processes. In that case the store falls back to the plain
//  item and returns a warning instead of losing the passphrase.
//
//  Per-operation verification (opt-in, `OperationVerification`): instead of
//  caching the unlocked passphrase for the whole process lifetime, the store
//  requires a fresh user-presence verification once per session-timeout
//  window before handing it out. With biometric storage the fresh Keychain
//  read itself prompts for Touch ID; with plain storage the store evaluates
//  LocalAuthentication directly (Touch ID, falling back to the login
//  password). A burst of librnp passphrase requests within the window — one
//  sign/encrypt/decrypt operation — triggers a single prompt, and a
//  manually entered (key-verified) passphrase also counts as verification.
//

import Foundation
import LocalAuthentication
import Librnp
import Security

/// A non-fatal warning surfaced when Touch ID storage cannot be used or when
/// plain Keychain storage fails.
public enum KeychainWarning: Equatable {
    /// The device or keychain does not support the requested biometric ACL.
    case biometryUnavailable
    /// Biometric storage failed with the given explanation.
    case biometryFailed(String)
    /// Plain Keychain storage failed with the given explanation.
    case storageFailed(String)
    /// The stored passphrase is Touch ID-protected and authentication was
    /// cancelled or failed; nothing was read, created, or changed.
    case authenticationRequired

    /// Human-friendly sentence describing the warning.
    public var message: String {
        switch self {
        case .biometryUnavailable:
            return "Touch ID is not available on this Mac. The passphrase was saved without it."
        case .biometryFailed(let reason):
            return "Could not save the passphrase with Touch ID: \(reason). It was saved without biometric protection."
        case .storageFailed(let reason):
            return "The passphrase could not be saved to the Keychain. \(reason)"
        case .authenticationRequired:
            return "The keyring is locked. Unlock it with Touch ID or enter the keyring passphrase."
        }
    }
}

/// Keychain operation failures.
public enum KeychainError: Error {
    case unhandled(status: OSStatus)
}

extension KeychainError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unhandled(let status):
            return "Keychain error (\(status)): \(SecCopyErrorMessageString(status, nil) as String? ?? "unknown")"
        }
    }
}

/// Result of attempting to read the shared keyring passphrase.
public enum PassphraseReadResult: Equatable {
    /// The passphrase was read (after Touch ID when it is protected).
    case success(String)
    /// No keyring passphrase is stored yet.
    case notFound
    /// A Touch ID-protected passphrase exists, but authentication was
    /// cancelled, failed, or cannot be shown. The stored item is untouched,
    /// so the user can retry or fall back to entering the passphrase.
    case authenticationFailed(OSStatus)
}

/// Stores and retrieves the keyring passphrase in the login Keychain.
public enum KeychainPassphraseStore {
    static let service = KeychainItemCRUD.service
    /// Internal (not private) so `@testable` clients can probe individual
    /// items without going through the prompting read path.
    static let plainAccount = "keyring-passphrase"
    static let biometricAccount = "keyring-passphrase.biometric"

    /// Keychain access group shared by the container app and the Mail
    /// extension. Re-exported from `KeychainItemCRUD` for source compat
    /// with existing internal callers.
    static var accessGroup: String? { KeychainItemCRUD.accessGroup }

    // MARK: - Session cache

    /// Unlocked passphrase cached for the remainder of the process lifetime.
    /// Keychain ACL authorization is per-process, so without the cache every
    /// librnp passphrase request would re-prompt for Touch ID.
    private static let sessionLock = NSLock()
    private static var cachedPassphrase: String?
    /// Time of the last cancelled/failed biometric read, used to avoid
    /// re-prompting on every librnp request right after the user cancels.
    private static var lastAuthenticationFailure: Date?
    /// How long provider reads stay silent after a cancelled Touch ID prompt.
    private static let authenticationFailureBackoff: TimeInterval = 30

    private static func cachedValue() -> String? {
        sessionLock.lock()
        defer { sessionLock.unlock() }
        return cachedPassphrase
    }

    private static func cache(_ passphrase: String) {
        sessionLock.lock()
        cachedPassphrase = passphrase
        lastAuthenticationFailure = nil
        sessionLock.unlock()
    }

    private static func noteAuthenticationFailure() {
        sessionLock.lock()
        lastAuthenticationFailure = Date()
        sessionLock.unlock()
    }

    private static func withinAuthenticationBackoff() -> Bool {
        sessionLock.lock()
        defer { sessionLock.unlock() }
        guard let lastAuthenticationFailure else {
            return false
        }
        return Date().timeIntervalSince(lastAuthenticationFailure) < authenticationFailureBackoff
    }

    /// Clears the in-memory session state. `reset()` calls this; also used
    /// by tests that need to observe Keychain behavior without the cache.
    static func clearSessionState() {
        sessionLock.lock()
        cachedPassphrase = nil
        lastAuthenticationFailure = nil
        lastUserPresenceVerification = nil
        sessionLock.unlock()
    }

    // MARK: - Per-operation verification

    /// Time of the last successful user-presence verification (Touch ID,
    /// the login password, or a manually entered key-verified passphrase).
    /// Internal so tests can age the timestamp without sleeping.
    static var lastUserPresenceVerification: Date?

    /// The prompt step of `verifyOperationAccess()`. Internal so tests can
    /// stub out the system prompt; `resetOperationVerifier()` restores the
    /// system implementation.
    static var operationVerifier: () -> Bool = KeychainPassphraseStore.defaultOperationVerifier

    /// Restores the system prompt implementation after a test stubbed
    /// `operationVerifier`.
    static func resetOperationVerifier() {
        operationVerifier = KeychainPassphraseStore.defaultOperationVerifier
    }

    private static func noteUserPresenceVerification() {
        sessionLock.lock()
        lastUserPresenceVerification = Date()
        sessionLock.unlock()
    }

    /// Whether a user-presence verification happened within the configured
    /// session timeout, so the current operation needs no new prompt.
    private static func userPresenceVerificationFresh() -> Bool {
        sessionLock.lock()
        let last = lastUserPresenceVerification
        sessionLock.unlock()
        guard let last else {
            return false
        }
        return Date().timeIntervalSince(last) < OperationVerification.sessionTimeout()
    }

    /// Gate for secret-key operations when per-operation verification is
    /// enabled (`OperationVerification`).
    ///
    /// Returns `true` immediately when the setting is off or the last
    /// verification is still within the session-timeout window. Otherwise it
    /// prompts once (Touch ID, with the login-password fallback) and records
    /// the outcome: success re-arms the window; failure starts the usual
    /// short backoff so a cancelled prompt does not re-appear for every
    /// librnp request in the same operation.
    static func verifyOperationAccess() -> Bool {
        guard OperationVerification.isEnabled() else {
            return true
        }
        if userPresenceVerificationFresh() {
            return true
        }
        if withinAuthenticationBackoff() {
            return false
        }
        let verified = operationVerifier()
        if verified {
            noteUserPresenceVerification()
        } else {
            noteAuthenticationFailure()
        }
        return verified
    }

    /// System prompt backing `verifyOperationAccess()`.
    ///
    /// With biometric storage a fresh read of the ACL-protected item (which
    /// bypasses the session cache) shows the Touch ID prompt and returns the
    /// passphrase straight into the cache. With plain storage the store
    /// evaluates LocalAuthentication directly instead.
    private static func defaultOperationVerifier() -> Bool {
        if isBiometricProtectionEnabled {
            switch read(account: biometricAccount, allowingAuthenticationUI: true) {
            case .found(let passphrase):
                cache(passphrase)
                return true
            case .notFound, .failed:
                return false
            }
        }
        return evaluateUserPresence(
            reason: "Authorize signing and decryption with your OpenPGP keys"
        )
    }

    /// Synchronously evaluates device-owner authentication (Touch ID,
    /// falling back to the login password). The passphrase provider is
    /// synchronous, so the async LocalAuthentication API is bridged with a
    /// semaphore; the prompt is shown by the system and does not need the
    /// calling run loop.
    private static func evaluateUserPresence(reason: String) -> Bool {
        let context = LAContext()
        var laError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &laError) else {
            return false
        }
        var verified = false
        let semaphore = DispatchSemaphore(value: 0)
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
            verified = success
            semaphore.signal()
        }
        semaphore.wait()
        return verified
    }

    // MARK: - Shared passphrase

    /// Whether the keyring passphrase is stored with Touch ID protection
    /// (the biometric item exists). Never prompts.
    public static var isBiometricProtectionEnabled: Bool {
        switch read(account: biometricAccount, allowingAuthenticationUI: false) {
        case .found, .failed:
            // A failed no-UI read means the item exists but is gated by its
            // access control (errSecInteractionNotAllowed).
            return true
        case .notFound:
            return false
        }
    }

    /// The shared passphrase, creating and storing a random one on first
    /// use.
    ///
    /// This variant is non-throwing and returns only the passphrase, so it
    /// can be used directly by the Mail security engine's passphrase
    /// provider. When the passphrase is Touch ID-protected and the user
    /// cancels the prompt, it returns an empty string (callers should treat
    /// this as "keyring locked") and stays silent for a short backoff so a
    /// burst of librnp requests does not spam prompts. It never creates a
    /// new passphrase while one is stored but locked.
    ///
    /// When per-operation verification is enabled (`OperationVerification`)
    /// and the last verification is older than the session timeout, the
    /// user is prompted first; a cancelled or failed prompt returns an
    /// empty string, exactly like a locked keyring.
    public static func sharedPassphrase() -> String {
        guard verifyOperationAccess() else {
            return ""
        }
        if let cached = cachedValue() {
            return cached
        }
        if withinAuthenticationBackoff() {
            return ""
        }
        switch readSharedPassphrase() {
        case .success(let passphrase):
            return passphrase
        case .notFound:
            let created = randomPassphrase()
            _ = setPassphrase(created, requiresBiometry: false)
            return created
        case .authenticationFailed:
            noteAuthenticationFailure()
            return ""
        }
    }

    /// Reads the stored passphrase, routing to the Touch ID-protected item
    /// when it exists.
    ///
    /// - Parameter allowingAuthenticationUI: when `false`, no Touch ID prompt
    ///   is shown and the session cache is bypassed, giving a live view of
    ///   the Keychain; a protected item reports `.authenticationFailed` with
    ///   `errSecInteractionNotAllowed`.
    public static func readSharedPassphrase(
        allowingAuthenticationUI: Bool = true
    ) -> PassphraseReadResult {
        if allowingAuthenticationUI, let cached = cachedValue() {
            return .success(cached)
        }
        switch read(account: biometricAccount, allowingAuthenticationUI: allowingAuthenticationUI) {
        case .found(let passphrase):
            if allowingAuthenticationUI {
                // Reading the ACL-protected item required user presence.
                noteUserPresenceVerification()
            }
            cache(passphrase)
            return .success(passphrase)
        case .failed(let status):
            return .authenticationFailed(status)
        case .notFound:
            break
        }
        switch read(account: plainAccount, allowingAuthenticationUI: true) {
        case .found(let passphrase):
            cache(passphrase)
            return .success(passphrase)
        case .notFound:
            return .notFound
        case .failed(let status):
            // The plain item has no access control, so this is not an
            // authentication issue; surface it in the same shape.
            return .authenticationFailed(status)
        }
    }

    /// The shared passphrase, optionally reading from or creating the
    /// biometric Keychain item.
    ///
    /// - Parameter requiresBiometry: when `true`, the passphrase is read from
    ///   the biometric item, creating it protected by Touch ID if it does not
    ///   already exist (migrating an existing plain passphrase, which is then
    ///   removed from the plain item). When `false`, behaves exactly like
    ///   `sharedPassphrase()`.
    /// - Returns: the passphrase and an optional warning for the UI. The
    ///   passphrase is empty when the keyring is locked behind Touch ID and
    ///   authentication did not complete.
    public static func sharedPassphrase(requiresBiometry: Bool) -> (passphrase: String, warning: KeychainWarning?) {
        guard requiresBiometry else {
            return (sharedPassphrase(), nil)
        }
        switch readSharedPassphrase() {
        case .success(let existing):
            if isBiometricProtectionEnabled {
                return (existing, nil)
            }
            // Only the plain item exists: move the passphrase behind
            // Touch ID.
            let warning = setPassphrase(existing, requiresBiometry: true)
            return (existing, warning)
        case .notFound:
            let created = randomPassphrase()
            let warning = setPassphrase(created, requiresBiometry: true)
            return (created, warning)
        case .authenticationFailed:
            return ("", .authenticationRequired)
        }
    }

    /// Stores a specific passphrase.
    ///
    /// When `requiresBiometry` is `true`, the passphrase is stored ONLY in
    /// the Touch ID-protected item and the plain item is removed, so every
    /// subsequent read requires Touch ID. If biometric storage is not
    /// possible (no Touch ID, unsigned build), the passphrase is kept in the
    /// plain item and a warning is returned instead of losing it.
    ///
    /// When `requiresBiometry` is `false`, the passphrase is stored in the
    /// plain item protected by `kSecAttrAccessibleWhenUnlocked` and any
    /// biometric item is removed.
    ///
    /// - Parameters:
    ///   - passphrase: the passphrase to store.
    ///   - requiresBiometry: when `true`, store with biometric access
    ///     control.
    /// - Returns: `nil` on full success, or a warning describing the failure.
    @discardableResult
    public static func setPassphrase(_ passphrase: String, requiresBiometry: Bool) -> KeychainWarning? {
        if requiresBiometry {
            if let warning = storeWithBiometry(passphrase) {
                // Biometric storage unavailable: fall back to the plain item
                // so the passphrase is not lost, and report the warning. A
                // stale biometric item must go too — reads route to it
                // first, so it would otherwise shadow this passphrase.
                delete(account: biometricAccount)
                do {
                    try store(passphrase, account: plainAccount, accessControl: nil)
                    cache(passphrase)
                } catch {
                    return .storageFailed(error.localizedDescription)
                }
                return warning
            }
            // The biometric item is now the only copy: Touch ID is required
            // to read the passphrase.
            delete(account: plainAccount)
            cache(passphrase)
            return nil
        }

        do {
            try store(passphrase, account: plainAccount, accessControl: nil)
        } catch {
            return .storageFailed(error.localizedDescription)
        }
        delete(account: biometricAccount)
        cache(passphrase)
        return nil
    }

    /// Caches an externally verified passphrase for the remainder of this
    /// process without touching the stored items.
    ///
    /// Used by the manual-entry fallback after the passphrase has been
    /// verified against a key: the Keychain item stays Touch ID-protected,
    /// but this process stops prompting until it exits. The manual entry
    /// also counts as user verification for per-operation verification, so
    /// the next operations within the session-timeout window do not prompt.
    public static func cacheVerifiedPassphrase(_ passphrase: String) {
        cache(passphrase)
        noteUserPresenceVerification()
    }

    /// Deletes the stored passphrase (e.g. when wiping the keyring).
    ///
    /// Per-key passphrases stored under key fingerprints are removed as
    /// well: with the keyring gone they no longer protect anything.
    public static func reset() {
        delete(account: plainAccount)
        delete(account: biometricAccount)
        deleteAllKeyPassphrases()
        clearSessionState()
    }

    // MARK: - Per-key passphrases

    /// Keychain account holding the passphrase of one specific key.
    ///
    /// Distinct per-key items share the service with the keyring passphrase;
    /// the account prefix keeps them apart.
    private static func keyAccount(forFingerprint fingerprint: String) -> String {
        "key-passphrase." + fingerprint.uppercased()
    }

    /// The passphrase stored for the key with the given fingerprint, or
    /// `nil` when the key has no per-key passphrase.
    public static func passphrase(forKeyFingerprint fingerprint: String) -> String? {
        switch read(account: keyAccount(forFingerprint: fingerprint), allowingAuthenticationUI: true) {
        case .found(let passphrase):
            return passphrase
        case .notFound, .failed:
            return nil
        }
    }

    /// Stores a per-key passphrase for the key with the given fingerprint,
    /// replacing any existing entry.
    ///
    /// Per-key passphrases are always stored in a plain Keychain item: they
    /// must be readable by the Mail extension without user interaction, like
    /// the keyring passphrase itself.
    ///
    /// - Returns: `nil` on success, or a warning describing the failure.
    @discardableResult
    public static func setPassphrase(_ passphrase: String, forKeyFingerprint fingerprint: String) -> KeychainWarning? {
        do {
            try store(passphrase, account: keyAccount(forFingerprint: fingerprint), accessControl: nil)
            return nil
        } catch {
            return .storageFailed(error.localizedDescription)
        }
    }

    /// Deletes the per-key passphrase stored for the given fingerprint
    /// (e.g. after the key has been re-protected or removed).
    public static func removePassphrase(forKeyFingerprint fingerprint: String) {
        delete(account: keyAccount(forFingerprint: fingerprint))
    }

    /// Removes every per-key passphrase item (all accounts with the
    /// per-key prefix under this service).
    private static func deleteAllKeyPassphrases() {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnAttributes: true,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup] = accessGroup
        }
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let items = item as? [[CFString: Any]]
        else {
            return
        }
        for attributes in items {
            guard let account = attributes[kSecAttrAccount] as? String,
                  account.hasPrefix("key-passphrase.")
            else {
                continue
            }
            delete(account: account)
        }
    }

    /// Passphrase provider resolving per-key passphrases before the keyring
    /// passphrase.
    ///
    /// When librnp asks for the passphrase of a key that has a per-key
    /// passphrase stored under its fingerprint, that passphrase is returned;
    /// every other request (including requests without a key) is answered
    /// with the shared keyring passphrase. When the keyring is locked behind
    /// Touch ID and the user cancels, `nil` is returned so librnp aborts the
    /// operation gracefully instead of trying an empty passphrase.
    ///
    /// Per-operation verification (`OperationVerification`) gates every
    /// request, including keys with a per-key passphrase: a cancelled or
    /// failed prompt returns `nil` and aborts the operation.
    public static func resolvingProvider() -> Rnp.KeyedPassphraseProvider {
        { _, fingerprint in
            guard verifyOperationAccess() else {
                return nil
            }
            if let fingerprint,
               let perKey = passphrase(forKeyFingerprint: fingerprint)
            {
                return perKey
            }
            let passphrase = sharedPassphrase()
            return passphrase.isEmpty ? nil : passphrase
        }
    }

    // MARK: - Private

    /// Raw outcome of reading one Keychain item. Re-exported from
    /// `KeychainItemCRUD` for `@testable` clients that already reference
    /// it via `KeychainPassphraseStore.RawRead`.
    typealias RawRead = KeychainItemCRUD.RawRead

    /// Reads a single item. Internal so `@testable` clients can verify which
    /// items exist and whether they enforce authentication.
    static func read(account: String, allowingAuthenticationUI: Bool) -> RawRead {
        KeychainItemCRUD.read(account: account, allowingAuthenticationUI: allowingAuthenticationUI)
    }

    /// Stores the passphrase for the given account, replacing any existing item.
    ///
    /// - Parameters:
    ///   - passphrase: the passphrase to store.
    ///   - account: the Keychain account identifier.
    ///   - accessControl: an optional access control object. When `nil` the
    ///     item is protected by the standard device-unlocked policy.
    private static func store(_ passphrase: String, account: String, accessControl: SecAccessControl?) throws {
        try KeychainItemCRUD.store(
            passphrase,
            account: account,
            accessibility: kSecAttrAccessibleWhenUnlocked,
            accessControl: accessControl
        )
    }

    /// Attempts to store the passphrase with Touch ID protection.
    ///
    /// - Returns: `nil` on success, or a warning describing why biometric
    ///   storage could not be used.
    private static func storeWithBiometry(_ passphrase: String) -> KeychainWarning? {
        // Preflight: without usable biometric hardware the ACL would make
        // the item hard or impossible to read; fall back to plain storage
        // with a warning instead. (This also reports false in closed
        // clamshell mode, where Touch ID cannot be reached.)
        let context = LAContext()
        var laError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laError) else {
            return .biometryUnavailable
        }

        // `.userPresence` alone is the only valid constraint here: combining
        // it with `.biometryCurrentSet` is rejected with errSecParam, which
        // is what previously made biometric storage silently never happen.
        // `.userPresence` prompts for Touch ID and offers the login password
        // as the system-level fallback.
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.userPresence],
            &error
        ) else {
            let reason = error?.takeRetainedValue().localizedDescription
                ?? "the keychain refused the biometric access control"
            return .biometryFailed(reason)
        }

        do {
            try store(passphrase, account: biometricAccount, accessControl: accessControl)
            return nil
        } catch {
            if case let KeychainError.unhandled(status) = error,
               status == errSecMissingEntitlement
            {
                return .biometryFailed(
                    "this build is not signed with the keychain entitlements biometric storage requires"
                )
            }
            let reason = (error as? KeychainError)?.errorDescription ?? error.localizedDescription
            return .biometryFailed(reason)
        }
    }

    private static func delete(account: String) {
        KeychainItemCRUD.delete(account: account)
    }

    private static func randomPassphrase() -> String {
        var bytes = [UInt8](repeating: 0, count: 24)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64EncodedString()
    }
}

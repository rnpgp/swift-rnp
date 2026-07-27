//
//  OperationVerificationTests.swift
//  swift-rnp
//
//  Tests for the opt-in per-operation verification gate: the shared
//  setting, the session-timeout window, the failure backoff, and the
//  interaction with the passphrase provider and the manual-unlock
//  fallback.
//
//  Tests never trigger a real Touch ID prompt: the store's
//  `operationVerifier` is stubbed, and the setting is written to (and
//  removed from) the shared defaults suite around each test.
//

import XCTest
@testable import MailSecurityEngine

final class OperationVerificationTests: XCTestCase {

    override func setUp() {
        super.setUp()
        KeychainPassphraseStore.reset()
        KeychainPassphraseStore.resetOperationVerifier()
        removeSetting()
    }

    override func tearDown() {
        removeSetting()
        KeychainPassphraseStore.resetOperationVerifier()
        KeychainPassphraseStore.reset()
        super.tearDown()
    }

    private func removeSetting() {
        let defaults = OperationVerification.sharedDefaults
        defaults.removeObject(forKey: OperationVerification.enabledDefaultsKey)
        defaults.removeObject(forKey: OperationVerification.timeoutDefaultsKey)
    }

    private func setEnabled(_ enabled: Bool) {
        OperationVerification.setEnabled(enabled, defaults: OperationVerification.sharedDefaults)
    }

    /// Counting stub for the system prompt.
    private final class VerifierStub {
        var calls = 0
        var result: Bool
        init(result: Bool) { self.result = result }
        func verify() -> Bool {
            calls += 1
            return result
        }
    }

    // MARK: - Setting

    func testSettingRoundTripsAndDefaultsToOff() throws {
        let suiteName = "test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        XCTAssertFalse(OperationVerification.isEnabled(defaults: defaults))
        OperationVerification.setEnabled(true, defaults: defaults)
        XCTAssertTrue(OperationVerification.isEnabled(defaults: defaults))
        OperationVerification.setEnabled(false, defaults: defaults)
        XCTAssertFalse(OperationVerification.isEnabled(defaults: defaults))

        XCTAssertEqual(OperationVerification.sessionTimeout(defaults: defaults), 30)
        OperationVerification.setSessionTimeout(60, defaults: defaults)
        XCTAssertEqual(OperationVerification.sessionTimeout(defaults: defaults), 60)
        // A non-positive stored value falls back to the default.
        OperationVerification.setSessionTimeout(0, defaults: defaults)
        XCTAssertEqual(OperationVerification.sessionTimeout(defaults: defaults), 30)
    }

    // MARK: - Gate disabled

    /// With the setting off (default), no prompt is shown and the provider
    /// behaves exactly as before.
    func testGateDisabledDoesNotPrompt() {
        XCTAssertNil(KeychainPassphraseStore.setPassphrase("secret", requiresBiometry: false))
        KeychainPassphraseStore.clearSessionState()
        let stub = VerifierStub(result: true)
        KeychainPassphraseStore.operationVerifier = stub.verify

        XCTAssertTrue(KeychainPassphraseStore.verifyOperationAccess())
        XCTAssertEqual(KeychainPassphraseStore.sharedPassphrase(), "secret")
        XCTAssertEqual(KeychainPassphraseStore.resolvingProvider()("ctx", nil), "secret")
        XCTAssertEqual(stub.calls, 0)
        XCTAssertNil(KeychainPassphraseStore.lastUserPresenceVerification)
    }

    // MARK: - Gate enabled

    /// With the setting enabled, the first passphrase request prompts; the
    /// rest of the session-timeout window does not.
    func testGateEnabledPromptsOncePerTimeoutWindow() {
        XCTAssertNil(KeychainPassphraseStore.setPassphrase("secret", requiresBiometry: false))
        KeychainPassphraseStore.clearSessionState()
        setEnabled(true)
        let stub = VerifierStub(result: true)
        KeychainPassphraseStore.operationVerifier = stub.verify

        XCTAssertEqual(KeychainPassphraseStore.sharedPassphrase(), "secret")
        XCTAssertEqual(stub.calls, 1)
        XCTAssertNotNil(KeychainPassphraseStore.lastUserPresenceVerification)

        XCTAssertEqual(KeychainPassphraseStore.sharedPassphrase(), "secret")
        XCTAssertEqual(KeychainPassphraseStore.resolvingProvider()("ctx", nil), "secret")
        XCTAssertEqual(stub.calls, 1)
    }

    /// A verification older than the session timeout re-prompts.
    func testStaleVerificationRePrompts() {
        XCTAssertNil(KeychainPassphraseStore.setPassphrase("secret", requiresBiometry: false))
        KeychainPassphraseStore.clearSessionState()
        setEnabled(true)
        let stub = VerifierStub(result: true)
        KeychainPassphraseStore.operationVerifier = stub.verify

        XCTAssertEqual(KeychainPassphraseStore.sharedPassphrase(), "secret")
        XCTAssertEqual(stub.calls, 1)

        // Age the verification past the 30-second default timeout.
        KeychainPassphraseStore.lastUserPresenceVerification = Date().addingTimeInterval(-3600)
        XCTAssertEqual(KeychainPassphraseStore.sharedPassphrase(), "secret")
        XCTAssertEqual(stub.calls, 2)
    }

    /// A cancelled/failed prompt denies the passphrase (the operation fails
    /// gracefully) and backs off instead of re-prompting on every librnp
    /// request in the same burst.
    func testFailedVerificationDeniesAndBacksOff() {
        XCTAssertNil(KeychainPassphraseStore.setPassphrase("secret", requiresBiometry: false))
        KeychainPassphraseStore.clearSessionState()
        setEnabled(true)
        let stub = VerifierStub(result: false)
        KeychainPassphraseStore.operationVerifier = stub.verify

        XCTAssertEqual(KeychainPassphraseStore.sharedPassphrase(), "")
        XCTAssertNil(KeychainPassphraseStore.resolvingProvider()("ctx", nil))
        XCTAssertEqual(stub.calls, 1)
    }

    /// A new operation after the backoff prompts again.
    func testVerificationRetriesAfterBackoff() {
        XCTAssertNil(KeychainPassphraseStore.setPassphrase("secret", requiresBiometry: false))
        KeychainPassphraseStore.clearSessionState()
        setEnabled(true)
        let stub = VerifierStub(result: false)
        KeychainPassphraseStore.operationVerifier = stub.verify

        XCTAssertEqual(KeychainPassphraseStore.sharedPassphrase(), "")
        XCTAssertEqual(stub.calls, 1)

        // Simulate the backoff expiring (it is 30 seconds).
        stub.result = true
        KeychainPassphraseStore.lastUserPresenceVerification = nil
        // `clearSessionState` also clears the failure timestamp; use it to
        // model the elapsed backoff without sleeping.
        KeychainPassphraseStore.clearSessionState()
        XCTAssertEqual(KeychainPassphraseStore.sharedPassphrase(), "secret")
        XCTAssertEqual(stub.calls, 2)
    }

    // MARK: - Manual fallback

    /// The manual passphrase fallback counts as user verification: after
    /// entering the keyring passphrase in the container app, operations
    /// within the timeout window do not prompt again.
    func testManualUnlockCountsAsVerification() {
        XCTAssertNil(KeychainPassphraseStore.setPassphrase("secret", requiresBiometry: false))
        KeychainPassphraseStore.clearSessionState()
        setEnabled(true)
        let stub = VerifierStub(result: true)
        KeychainPassphraseStore.operationVerifier = stub.verify

        // What `KeysManager.unlockKeyringManually` does after verifying the
        // typed passphrase against a key.
        KeychainPassphraseStore.cacheVerifiedPassphrase("secret")

        XCTAssertEqual(KeychainPassphraseStore.sharedPassphrase(), "secret")
        XCTAssertEqual(KeychainPassphraseStore.resolvingProvider()("ctx", nil), "secret")
        XCTAssertEqual(stub.calls, 0)
    }

    // MARK: - Per-key passphrases

    /// The gate covers keys with a per-key passphrase too: a failed
    /// verification aborts the operation instead of handing out the
    /// silently readable per-key passphrase.
    func testPerKeyPassphraseIsGatedAsWell() {
        let fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
        XCTAssertNil(KeychainPassphraseStore.setPassphrase("key-secret", forKeyFingerprint: fingerprint))
        KeychainPassphraseStore.clearSessionState()
        setEnabled(true)
        let stub = VerifierStub(result: false)
        KeychainPassphraseStore.operationVerifier = stub.verify

        XCTAssertNil(KeychainPassphraseStore.resolvingProvider()("ctx", fingerprint))
        XCTAssertEqual(stub.calls, 1)

        // Retry after the (simulated) backoff with a successful prompt.
        stub.result = true
        KeychainPassphraseStore.clearSessionState()
        XCTAssertEqual(KeychainPassphraseStore.resolvingProvider()("ctx", fingerprint), "key-secret")
        XCTAssertEqual(stub.calls, 2)
    }
}

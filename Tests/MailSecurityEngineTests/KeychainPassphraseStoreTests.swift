//
//  KeychainPassphraseStoreTests.swift
//  swift-rnp
//
//  Tests for the Touch ID runtime effect of the keyring passphrase store:
//  biometric ACL storage, the plain fallback when biometric storage is not
//  possible, and the manual-unlock session cache.
//
//  Biometric storage requires a signed process with the keychain
//  entitlements (`SecItemAdd` with an access control fails with
//  errSecMissingEntitlement in unsigned ones) AND usable Touch ID hardware,
//  so the test runner usually exercises the fallback branch. Every test
//  therefore accepts both outcomes and asserts the invariants of whichever
//  branch was taken — the same pattern as the pre-existing biometry test.
//
//  Tests never trigger a real Touch ID prompt: enforcement is verified with
//  `allowingAuthenticationUI: false` reads, which the Keychain refuses with
//  errSecInteractionNotAllowed for protected items.
//

import XCTest
@testable import MailSecurityEngine

final class KeychainPassphraseStoreTests: XCTestCase {

    override func setUp() {
        super.setUp()
        KeychainPassphraseStore.reset()
    }

    override func tearDown() {
        KeychainPassphraseStore.reset()
        super.tearDown()
    }

    // MARK: - Plain storage

    func testPlainStorageRoundTripWithoutBiometry() {
        let warning = KeychainPassphraseStore.setPassphrase("plain-secret", requiresBiometry: false)
        XCTAssertNil(warning)
        XCTAssertFalse(KeychainPassphraseStore.isBiometricProtectionEnabled)

        // Probe the live Keychain (no cache, no UI).
        KeychainPassphraseStore.clearSessionState()
        XCTAssertEqual(
            KeychainPassphraseStore.readSharedPassphrase(allowingAuthenticationUI: false),
            .success("plain-secret")
        )
        XCTAssertEqual(
            KeychainPassphraseStore.read(
                account: KeychainPassphraseStore.plainAccount,
                allowingAuthenticationUI: false
            ),
            .found("plain-secret")
        )
        XCTAssertEqual(
            KeychainPassphraseStore.read(
                account: KeychainPassphraseStore.biometricAccount,
                allowingAuthenticationUI: false
            ),
            .notFound
        )
    }

    // MARK: - Biometric storage

    /// When biometric storage works, the passphrase must live ONLY in the
    /// protected item and reads must require Touch ID; otherwise the store
    /// must fall back to the plain item and say why.
    func testBiometricStorageEnforcesAuthenticationOrFallsBack() {
        let warning = KeychainPassphraseStore.setPassphrase("bio-secret", requiresBiometry: true)
        KeychainPassphraseStore.clearSessionState()

        if let warning {
            // Fallback branch (unsigned runner and/or no usable Touch ID):
            // the passphrase is not lost and stays readable without prompts.
            XCTAssertFalse(warning.message.isEmpty)
            XCTAssertFalse(KeychainPassphraseStore.isBiometricProtectionEnabled)
            XCTAssertEqual(
                KeychainPassphraseStore.readSharedPassphrase(allowingAuthenticationUI: false),
                .success("bio-secret")
            )
        } else {
            // Full biometric branch: no plain copy remains, and a read that
            // cannot show Touch ID is refused.
            XCTAssertTrue(KeychainPassphraseStore.isBiometricProtectionEnabled)
            XCTAssertEqual(
                KeychainPassphraseStore.read(
                    account: KeychainPassphraseStore.plainAccount,
                    allowingAuthenticationUI: false
                ),
                .notFound
            )
            guard case .authenticationFailed = KeychainPassphraseStore.readSharedPassphrase(
                allowingAuthenticationUI: false
            ) else {
                XCTFail("a Touch ID-protected passphrase must not be readable without authentication")
                return
            }
        }
    }

    /// A refused biometric read must never create a new passphrase or
    /// overwrite the stored one — that would lock the keyring permanently.
    func testRefusedBiometricReadLeavesStorageUntouched() {
        let warning = KeychainPassphraseStore.setPassphrase("bio-secret", requiresBiometry: true)
        KeychainPassphraseStore.clearSessionState()

        let result = KeychainPassphraseStore.readSharedPassphrase(allowingAuthenticationUI: false)
        if warning == nil {
            guard case .authenticationFailed = result else {
                XCTFail("expected a refused read, got \(result)")
                return
            }
            // No plain item appeared, and the biometric item is still
            // protected (i.e. it was not replaced by a fresh random one).
            XCTAssertEqual(
                KeychainPassphraseStore.read(
                    account: KeychainPassphraseStore.plainAccount,
                    allowingAuthenticationUI: false
                ),
                .notFound
            )
            guard case .failed = KeychainPassphraseStore.read(
                account: KeychainPassphraseStore.biometricAccount,
                allowingAuthenticationUI: false
            ) else {
                XCTFail("the biometric item must still enforce authentication")
                return
            }
        } else {
            XCTAssertEqual(result, .success("bio-secret"))
        }
    }

    /// Storing with `requiresBiometry: false` removes any biometric item and
    /// returns the passphrase to plain, prompt-free storage.
    func testDisablingBiometryRestoresPlainStorage() {
        _ = KeychainPassphraseStore.setPassphrase("bio-secret", requiresBiometry: true)
        let warning = KeychainPassphraseStore.setPassphrase("plain-secret", requiresBiometry: false)
        XCTAssertNil(warning)
        KeychainPassphraseStore.clearSessionState()

        XCTAssertFalse(KeychainPassphraseStore.isBiometricProtectionEnabled)
        XCTAssertEqual(
            KeychainPassphraseStore.read(
                account: KeychainPassphraseStore.biometricAccount,
                allowingAuthenticationUI: false
            ),
            .notFound
        )
        XCTAssertEqual(
            KeychainPassphraseStore.readSharedPassphrase(allowingAuthenticationUI: false),
            .success("plain-secret")
        )
    }

    // MARK: - Manual fallback

    /// The manual-entry fallback caches the verified passphrase for the
    /// process without downgrading the Touch ID protection of the stored
    /// item.
    func testManualUnlockCachesPassphraseWithoutDowngradingStorage() {
        let warning = KeychainPassphraseStore.setPassphrase("chosen-secret", requiresBiometry: true)
        KeychainPassphraseStore.clearSessionState()

        // What the container app does after verifying the typed passphrase.
        KeychainPassphraseStore.cacheVerifiedPassphrase("chosen-secret")
        XCTAssertEqual(KeychainPassphraseStore.sharedPassphrase(), "chosen-secret")

        if warning == nil {
            XCTAssertTrue(KeychainPassphraseStore.isBiometricProtectionEnabled)
            XCTAssertEqual(
                KeychainPassphraseStore.read(
                    account: KeychainPassphraseStore.plainAccount,
                    allowingAuthenticationUI: false
                ),
                .notFound
            )
            KeychainPassphraseStore.clearSessionState()
            guard case .authenticationFailed = KeychainPassphraseStore.readSharedPassphrase(
                allowingAuthenticationUI: false
            ) else {
                XCTFail("manual unlock must not make the stored item readable without Touch ID")
                return
            }
        }
    }

    // MARK: - Session state

    /// `reset()` wipes both the items and the session cache: afterwards a
    /// brand-new random passphrase is created instead of the cached one.
    func testResetClearsSessionState() {
        XCTAssertNil(KeychainPassphraseStore.setPassphrase("secret", requiresBiometry: false))
        XCTAssertEqual(KeychainPassphraseStore.sharedPassphrase(), "secret")

        KeychainPassphraseStore.reset()
        XCTAssertEqual(
            KeychainPassphraseStore.readSharedPassphrase(allowingAuthenticationUI: false),
            .notFound
        )
        let created = KeychainPassphraseStore.sharedPassphrase()
        XCTAssertFalse(created.isEmpty)
        XCTAssertNotEqual(created, "secret")
    }

    /// `sharedPassphrase(requiresBiometry: true)` on a plain-stored
    /// passphrase migrates it behind Touch ID where supported, keeping the
    /// same passphrase either way.
    func testRequiresBiometryMigratesExistingPlainPassphrase() {
        XCTAssertNil(KeychainPassphraseStore.setPassphrase("migrate-me", requiresBiometry: false))
        KeychainPassphraseStore.clearSessionState()

        let (passphrase, warning) = KeychainPassphraseStore.sharedPassphrase(requiresBiometry: true)
        XCTAssertEqual(passphrase, "migrate-me")
        if let warning {
            XCTAssertFalse(warning.message.isEmpty)
            XCTAssertFalse(KeychainPassphraseStore.isBiometricProtectionEnabled)
        } else {
            XCTAssertTrue(KeychainPassphraseStore.isBiometricProtectionEnabled)
            XCTAssertEqual(
                KeychainPassphraseStore.read(
                    account: KeychainPassphraseStore.plainAccount,
                    allowingAuthenticationUI: false
                ),
                .notFound
            )
        }
    }
}

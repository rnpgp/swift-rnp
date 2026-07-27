//
//  KeyServerSettingsTests.swift
//  swift-rnp
//
//  Tests for the keyserver settings model and its UserDefaults-backed
//  store.
//

@testable import KeyServerClient
import XCTest

final class KeyServerSettingsTests: XCTestCase {
    private var suiteNames: [String] = []

    override func tearDownWithError() throws {
        for name in suiteNames {
            UserDefaults.standard.removePersistentDomain(forName: name)
        }
        suiteNames = []
    }

    /// Fresh, isolated defaults suite per test.
    private func makeDefaults() -> UserDefaults {
        let name = "KeyServerSettingsTests.\(UUID().uuidString)"
        suiteNames.append(name)
        return UserDefaults(suiteName: name)!
    }

    // MARK: - Model

    func testDefaultServersMatchPreviousHardcodedBehavior() {
        XCTAssertEqual(KeyServerSettings.defaultServers, [
            KeyServer(kind: .wkd, host: ""),
            KeyServer(kind: .vks, host: "keys.openpgp.org"),
            KeyServer(kind: .hkps, host: "keys.openpgp.org"),
            KeyServer(kind: .hkps, host: "keyserver.ubuntu.com"),
        ])
    }

    func testSettingsCodableRoundtrip() throws {
        let settings = KeyServerSettings(servers: [
            KeyServer(kind: .hkps, host: "keys.example.com"),
            KeyServer(kind: .wkd, host: ""),
        ])
        let data = try JSONEncoder().encode(settings)
        let decoded = try JSONDecoder().decode(KeyServerSettings.self, from: data)
        XCTAssertEqual(decoded, settings)
    }

    func testIsCustomMarksOnlyNonDefaultServers() {
        XCTAssertFalse(KeyServer(kind: .hkps, host: "keys.openpgp.org").isCustom)
        XCTAssertFalse(KeyServer(kind: .wkd, host: "").isCustom)
        XCTAssertTrue(KeyServer(kind: .hkps, host: "keys.example.com").isCustom)
    }

    func testSanitizedDropsDuplicatesAndInvalidEntries() {
        let settings = KeyServerSettings(servers: [
            KeyServer(kind: .hkps, host: "keys.example.com"),
            KeyServer(kind: .hkps, host: "keys.example.com"),
            KeyServer(kind: .hkps, host: "not a host"),
            KeyServer(kind: .wkd, host: "unexpected-host"),
            KeyServer(kind: .wkd, host: ""),
        ])
        XCTAssertEqual(settings.sanitized().servers, [
            KeyServer(kind: .hkps, host: "keys.example.com"),
            KeyServer(kind: .wkd, host: ""),
        ])
    }

    // MARK: - Host normalization

    func testNormalizedHKPSHostAcceptsBareHost() {
        XCTAssertEqual(KeyServerSettings.normalizedHKPSHost("keys.example.com"), "keys.example.com")
    }

    func testNormalizedHKPSHostStripsSchemePathAndCase() {
        XCTAssertEqual(
            KeyServerSettings.normalizedHKPSHost("  HTTPS://Keys.Example.com/pks/lookup "),
            "keys.example.com"
        )
    }

    func testNormalizedHKPSHostRejectsInvalidInput() {
        XCTAssertNil(KeyServerSettings.normalizedHKPSHost(""))
        XCTAssertNil(KeyServerSettings.normalizedHKPSHost("   "))
        XCTAssertNil(KeyServerSettings.normalizedHKPSHost("https://"))
        XCTAssertNil(KeyServerSettings.normalizedHKPSHost("not a host"))
        XCTAssertNil(KeyServerSettings.normalizedHKPSHost("-leading-hyphen.com"))
        XCTAssertNil(KeyServerSettings.normalizedHKPSHost("trailing-hyphen-.com"))
        XCTAssertNil(KeyServerSettings.normalizedHKPSHost("under_score.com"))
        XCTAssertNil(KeyServerSettings.normalizedHKPSHost("double..dot.com"))
        // Leading/trailing dots are trimmed as part of normalization.
        XCTAssertEqual(KeyServerSettings.normalizedHKPSHost(".keys.example.com."), "keys.example.com")
    }

    // MARK: - Store

    func testStoreReturnsDefaultsWhenNothingStored() {
        let store = KeyServerSettingsStore(defaults: makeDefaults())
        XCTAssertEqual(store.load(), KeyServerSettings())
    }

    func testStoreSaveLoadRoundtrip() {
        let defaults = makeDefaults()
        let store = KeyServerSettingsStore(defaults: defaults)
        let settings = KeyServerSettings(servers: [
            KeyServer(kind: .hkps, host: "keys.example.com"),
            KeyServer(kind: .wkd, host: ""),
            KeyServer(kind: .vks, host: "keys.openpgp.org"),
        ])
        store.save(settings)
        XCTAssertEqual(store.load(), settings)
    }

    func testStorePersistsAcrossInstances() {
        let defaults = makeDefaults()
        let settings = KeyServerSettings(servers: [
            KeyServer(kind: .hkps, host: "keys.example.com"),
        ])
        KeyServerSettingsStore(defaults: defaults).save(settings)
        XCTAssertEqual(KeyServerSettingsStore(defaults: defaults).load(), settings)
    }

    func testStoreSaveSanitizesBeforePersisting() {
        let defaults = makeDefaults()
        let store = KeyServerSettingsStore(defaults: defaults)
        store.save(KeyServerSettings(servers: [
            KeyServer(kind: .hkps, host: "keys.example.com"),
            KeyServer(kind: .hkps, host: "keys.example.com"),
        ]))
        XCTAssertEqual(store.load().servers, [KeyServer(kind: .hkps, host: "keys.example.com")])
    }

    func testStoreReturnsDefaultsForCorruptData() {
        let defaults = makeDefaults()
        defaults.set(Data("not json".utf8), forKey: KeyServerSettingsStore.defaultsKey)
        let store = KeyServerSettingsStore(defaults: defaults)
        XCTAssertEqual(store.load(), KeyServerSettings())
    }

    func testStoreReturnsDefaultsWhenStoredListIsEmpty() {
        let defaults = makeDefaults()
        let store = KeyServerSettingsStore(defaults: defaults)
        store.save(KeyServerSettings(servers: []))
        XCTAssertEqual(store.load(), KeyServerSettings())
    }

    func testStoreResetRestoresDefaults() {
        let defaults = makeDefaults()
        let store = KeyServerSettingsStore(defaults: defaults)
        store.save(KeyServerSettings(servers: [KeyServer(kind: .hkps, host: "keys.example.com")]))
        store.reset()
        XCTAssertEqual(store.load(), KeyServerSettings())
    }
}

//
//  SecurityStateRecordStoreTests.swift
//  MailSecurityEngineTests
//

import XCTest
@testable import MailSecurityEngine

final class SecurityStateRecordStoreTests: XCTestCase {

    private var tempDir: URL!

    override func setUp() {
        super.setUp()
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sec-state-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempDir)
        tempDir = nil
        super.tearDown()
    }

    private func sampleRecord(messageID: String = "<test@example.org>") -> RecordedMessageSecurity {
        RecordedMessageSecurity(
            recordVersion: 1,
            messageID: messageID,
            subject: "Test",
            from: "alice@example.org",
            isEncrypted: true,
            signers: [],
            signingError: nil,
            encryptionError: nil
        )
    }

    func testLoadsNilWhenNoRecords() throws {
        let store = try SecurityStateRecordStore(directory: tempDir)
        XCTAssertNil(try store.loadLastMessage())
        XCTAssertNil(try store.loadRecord(forMessageID: "<missing>"))
    }

    func testRoundTripsSignedRecord() throws {
        let store = try SecurityStateRecordStore(directory: tempDir)
        let recorder = SecurityStateRecorder(directory: tempDir)
        let record = sampleRecord()
        recorder.record(record, signingWith: store)

        // The signed store should load it back.
        let loaded = try store.loadLastMessage()
        XCTAssertEqual(loaded?.messageID, "<test@example.org>")
        XCTAssertEqual(loaded?.isEncrypted, true)
    }

    func testRoundTripsPerMessageRecord() throws {
        let store = try SecurityStateRecordStore(directory: tempDir)
        let recorder = SecurityStateRecorder(directory: tempDir)
        let record = sampleRecord(messageID: "<unique@example.org>")
        recorder.record(record, signingWith: store)

        let loaded = try store.loadRecord(forMessageID: "<unique@example.org>")
        XCTAssertEqual(loaded?.messageID, "<unique@example.org>")
    }

    func testTamperedRecordThrows() throws {
        let store = try SecurityStateRecordStore(directory: tempDir)
        let recorder = SecurityStateRecorder(directory: tempDir)
        recorder.record(sampleRecord(), signingWith: store)

        // Tamper with the record bytes.
        let lastURL = tempDir.appendingPathComponent(SecurityStateRecordStore.lastMessageFilename)
        var data = try Data(contentsOf: lastURL)
        data[data.count / 2] ^= 0xFF
        try data.write(to: lastURL)

        XCTAssertThrowsError(try store.loadLastMessage()) { error in
            guard case SecurityStateRecordStoreError.tampered = error else {
                XCTFail("expected tampered, got \(error)")
                return
            }
        }
    }

    func testMigrateSignsExistingUnsignedRecord() throws {
        // Write an unsigned record first.
        let recorder = SecurityStateRecorder(directory: tempDir)
        recorder.record(sampleRecord())

        // No sig yet.
        let sigURL = tempDir.appendingPathComponent(SecurityStateRecordStore.lastMessageSignatureFilename)
        XCTAssertFalse(FileManager.default.fileExists(atPath: sigURL.path))

        // Now create the store and migrate.
        let store = try SecurityStateRecordStore(directory: tempDir)
        store.migrateUnsignedRecords()

        // Sig should now exist.
        XCTAssertTrue(FileManager.default.fileExists(atPath: sigURL.path))

        // Record should load.
        let loaded = try store.loadLastMessage()
        XCTAssertEqual(loaded?.messageID, "<test@example.org>")
    }

    func testLoadAllRecordsIncludesValidOnes() throws {
        let store = try SecurityStateRecordStore(directory: tempDir)
        let recorder = SecurityStateRecorder(directory: tempDir)
        recorder.record(sampleRecord(messageID: "<a@x>"), signingWith: store)
        recorder.record(sampleRecord(messageID: "<b@x>"), signingWith: store)

        let all = store.loadAllRecords()
        XCTAssertEqual(all.count, 2)
        XCTAssertTrue(all.allSatisfy { $0.signatureValid })
    }
}

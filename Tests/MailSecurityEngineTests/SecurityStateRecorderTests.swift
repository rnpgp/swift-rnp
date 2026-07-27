//
//  SecurityStateRecorderTests.swift
//  swift-rnp
//
//  Unit tests for the decode-outcome state recorder used by the Mail
//  end-to-end harness.
//

import XCTest
@testable import MailSecurityEngine

final class SecurityStateRecorderTests: XCTestCase {
    private static let alice = "Alice <alice@example.com>"
    private static let aliceEmail = "alice@example.com"
    private static let bobEmail = "bob@example.com"
    private static let password = "test-password"

    private var tempDirectories: [URL] = []

    override func tearDownWithError() throws {
        for url in tempDirectories {
            try? FileManager.default.removeItem(at: url)
        }
        tempDirectories = []
    }

    private func makeTempDirectory() -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("swift-rnp-tests")
            .appendingPathComponent(UUID().uuidString)
        tempDirectories.append(url)
        return url
    }

    private func makeEngine(keys userIDs: [String] = []) throws -> MailSecurityEngine {
        let engine = try MailSecurityEngine(
            directory: makeTempDirectory(),
            passphraseProvider: { _ in Self.password }
        )
        for userID in userIDs {
            try engine.keyManager.generateKey(userID: userID, algorithm: .ecdsa)
        }
        return engine
    }

    private func readRecord(at url: URL) throws -> RecordedMessageSecurity {
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(RecordedMessageSecurity.self, from: data)
    }

    // MARK: - File naming

    /// The harness computes the same name with
    /// `LC_ALL=C tr -c 'A-Za-z0-9' '-'`; keep the rules in sync.
    func testSanitizedMessageIDMatchesHarnessRule() {
        XCTAssertEqual(
            SecurityStateRecorder.sanitizedMessageID("<e2e-123@rnpmail-e2e>"),
            "-e2e-123-rnpmail-e2e-"
        )
        XCTAssertEqual(SecurityStateRecorder.sanitizedMessageID("plain123"), "plain123")
        XCTAssertEqual(
            SecurityStateRecorder.stateFilename(forMessageID: "<a@b>"),
            "-a-b-.json"
        )
    }

    // MARK: - Recording

    func testRecordWritesLastMessageAndPerMessageFile() throws {
        let directory = makeTempDirectory()
        let recorder = SecurityStateRecorder(directory: directory)
        let record = RecordedMessageSecurity(
            messageID: "<test@example>",
            subject: "Hello",
            from: "Alice <alice@example.com>",
            isEncrypted: true,
            signers: [
                RecordedSigner(
                    label: "Alice <alice@example.com>",
                    fingerprint: "DEADBEEF",
                    status: "valid",
                    trust: "unverified"
                ),
            ],
            signingError: nil,
            encryptionError: nil,
            recordedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        recorder.record(record)

        let lastURL = directory.appendingPathComponent("last-message.json")
        let perMessageURL = directory
            .appendingPathComponent("messages", isDirectory: true)
            .appendingPathComponent(SecurityStateRecorder.stateFilename(forMessageID: "<test@example>"))
        for url in [lastURL, perMessageURL] {
            XCTAssertTrue(FileManager.default.fileExists(atPath: url.path), "missing \(url.path)")
            XCTAssertEqual(try readRecord(at: url), record)
        }
    }

    func testRecordWithoutMessageIDWritesOnlyLastMessage() throws {
        let directory = makeTempDirectory()
        let recorder = SecurityStateRecorder(directory: directory)
        recorder.record(RecordedMessageSecurity(
            messageID: nil,
            subject: nil,
            from: nil,
            isEncrypted: false,
            signers: [],
            signingError: "boom",
            encryptionError: nil
        ))

        XCTAssertTrue(FileManager.default.fileExists(
            atPath: directory.appendingPathComponent("last-message.json").path
        ))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: directory.appendingPathComponent("messages").path
        ))
    }

    // MARK: - Core integration

    /// A signed message decoded through `MessageSecurityCore` must produce a
    /// state record with the signature status, trust state, and the envelope
    /// headers the harness correlates on.
    func testCoreRecordsDecodeOutcome() throws {
        let aliceEngine = try makeEngine(keys: [Self.alice])
        let bobEngine = try makeEngine()
        let aliceFingerprint = try XCTUnwrap(aliceEngine.keyManager.listKeys().first?.fingerprint)
        try bobEngine.keyManager.importKeys(aliceEngine.keyManager.exportKey(fingerprint: aliceFingerprint))

        let recorder = SecurityStateRecorder(directory: makeTempDirectory())
        let aliceCore = MessageSecurityCore(engine: aliceEngine)
        let bobCore = MessageSecurityCore(engine: bobEngine, stateRecorder: recorder)

        struct MockMessage: MailMessage {
            var rawData: Data?
            var fromAddress: String
            var recipientAddresses: [String]
            var isSending: Bool
        }
        struct MockComposeContext: MailComposeContext {
            var shouldSign: Bool
            var shouldEncrypt: Bool
        }

        let headers = [
            "From: alice@example.com",
            "To: bob@example.com",
            "Subject: state recorder test",
            "Message-ID: <state-test-1@example.com>",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=\"utf-8\"",
        ]
        let rawMessage = Data((headers.joined(separator: "\r\n") + "\r\n\r\nBody text.").utf8)
        let message = MockMessage(
            rawData: rawMessage,
            fromAddress: Self.aliceEmail,
            recipientAddresses: [Self.bobEmail],
            isSending: true
        )
        let context = MockComposeContext(shouldSign: true, shouldEncrypt: false)
        let encoded = try XCTUnwrap(aliceCore.encode(message, composeContext: context).encodedMessage)

        let decoded = try XCTUnwrap(bobCore.decodedMessage(forMessageData: encoded.rawData))
        XCTAssertFalse(decoded.securityInformation.isEncrypted)

        let recordURL = recorder.directory
            .appendingPathComponent("messages", isDirectory: true)
            .appendingPathComponent(SecurityStateRecorder.stateFilename(forMessageID: "<state-test-1@example.com>"))
        let record = try readRecord(at: recordURL)

        XCTAssertEqual(record.recordVersion, 1)
        XCTAssertEqual(record.messageID, "<state-test-1@example.com>")
        XCTAssertEqual(record.subject, "state recorder test")
        XCTAssertEqual(record.from, "alice@example.com")
        XCTAssertFalse(record.isEncrypted)
        XCTAssertNil(record.signingError)
        XCTAssertNil(record.encryptionError)

        let signer = try XCTUnwrap(record.signers.first)
        XCTAssertEqual(signer.label, Self.alice)
        XCTAssertEqual(signer.fingerprint, aliceFingerprint)
        XCTAssertEqual(signer.status, "valid")
        XCTAssertEqual(signer.trust, "unverified")
    }
}

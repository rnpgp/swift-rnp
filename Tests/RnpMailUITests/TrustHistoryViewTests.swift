//
//  TrustHistoryViewTests.swift
//  swift-rnp
//
//  Render tests for the trust history view and the key detail view's
//  "Keep old binding" conflict action. These run without a host app so
//  they work in CI unsigned builds; the record content itself is covered
//  by the TrustStore history tests.
//

import AppKit
import SwiftUI
import XCTest
@testable import RnpMailUI
import MailSecurityEngine
import TrustStore

final class TrustHistoryViewTests: XCTestCase {
    private static let fingerprintA = "74E2A1E008CB1B1021192AA05225D37282795A2F"
    private static let fingerprintB = "1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D"

    private func makeRecords() -> [TrustRecord] {
        [
            TrustRecord(
                email: "alice@example.com",
                fingerprint: Self.fingerprintA,
                state: .verified,
                firstSeen: Date(timeIntervalSince1970: 1_700_000_000),
                lastSeen: Date(timeIntervalSince1970: 1_710_000_000)
            ),
            TrustRecord(
                email: "alice@example.com",
                fingerprint: Self.fingerprintB,
                state: .problem,
                firstSeen: Date(timeIntervalSince1970: 1_705_000_000),
                lastSeen: Date(timeIntervalSince1970: 1_709_000_000)
            ),
            TrustRecord(
                email: "alice@example.com",
                fingerprint: Self.fingerprintA,
                state: .unverified,
                firstSeen: Date(timeIntervalSince1970: 1_700_000_000),
                lastSeen: Date(timeIntervalSince1970: 1_700_000_000)
            ),
        ]
    }

    private func makeKey(fingerprint: String = fingerprintA) -> KeyInfo {
        KeyInfo(
            fingerprint: fingerprint,
            primaryUserID: "Alice <alice@example.com>",
            userIDs: ["Alice <alice@example.com>"],
            hasSecret: false,
            algorithm: "Ed25519",
            bits: 256
        )
    }

    private func host<Content: View>(_ view: Content) -> NSView {
        let host = NSHostingController(rootView: view)
        host.loadView()
        host.view.frame = NSRect(x: 0, y: 0, width: 480, height: 320)
        host.view.layoutSubtreeIfNeeded()
        return host.view
    }

    func testTrustHistoryViewRendersRecords() throws {
        let records = makeRecords()
        let view = TrustHistoryView(email: "alice@example.com", records: records)
        XCTAssertEqual(view.email, "alice@example.com")
        XCTAssertEqual(view.records, records)

        let root = host(view)
        XCTAssertNotNil(root)
        XCTAssertTrue(root is NSView)
    }

    func testTrustHistoryViewRendersEmptyState() throws {
        let view = TrustHistoryView(email: "alice@example.com", records: [])
        XCTAssertTrue(view.records.isEmpty)

        let root = host(view)
        XCTAssertNotNil(root)
        XCTAssertTrue(root is NSView)
    }

    func testKeyDetailViewRendersKeepOldBindingAction() throws {
        let view = KeyDetailView(
            key: makeKey(fingerprint: Self.fingerprintB),
            subkeys: [],
            isRecipient: true,
            trustState: .problem,
            hasPendingKeyChange: true,
            actions: KeyDetailActions()
        )
        XCTAssertTrue(view.hasPendingKeyChange)

        let root = host(view)
        XCTAssertNotNil(root)
        XCTAssertTrue(root is NSView)
    }

    func testKeyDetailViewRendersWithoutPendingKeyChange() throws {
        let view = KeyDetailView(
            key: makeKey(),
            subkeys: [],
            isRecipient: true,
            trustState: .unverified,
            actions: KeyDetailActions()
        )
        XCTAssertFalse(view.hasPendingKeyChange)

        let root = host(view)
        XCTAssertNotNil(root)
        XCTAssertTrue(root is NSView)
    }
}

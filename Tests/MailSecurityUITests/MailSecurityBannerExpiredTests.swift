//
//  MailSecurityBannerExpiredTests.swift
//  swift-rnp
//
//  Tests for the banner's expired-signer warning: when the signer's context
//  carries the signing key's expiration date, the banner's detail text says
//  when the key expired.
//

import AppKit
import CryptoKit
import XCTest
import MailSecurityEngine
import Librnp
import TrustStore
@testable import MailSecurityUI

final class MailSecurityBannerExpiredTests: XCTestCase {
    private static let fprAlice = "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"

    private var tempDirectories: [URL] = []

    override func tearDownWithError() throws {
        for url in tempDirectories {
            try? FileManager.default.removeItem(at: url)
        }
        tempDirectories = []
    }

    private func makeStore() throws -> TrustStore {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("swift-rnp-mailsecurityui-tests")
            .appendingPathComponent(UUID().uuidString)
        tempDirectories.append(url)
        return try TrustStore(directory: url, privateKey: Curve25519.Signing.PrivateKey())
    }

    private func allLabels(in view: NSView) -> [String] {
        view.subviews.compactMap { $0 as? NSTextField }.map(\.stringValue)
            + view.subviews.flatMap { allLabels(in: $0) }
    }

    func testExpiredSignerBannerShowsExpirationDate() throws {
        let store = try makeStore()
        let expiration = Date(timeIntervalSince1970: 1_800_000_000)
        let signer = MailSecurityBannerView.Signer(
            label: "alice@example.com",
            context: SignerContext(
                fingerprint: Self.fprAlice,
                status: RnpSignatureStatus.expired.rawValue,
                keyExpiration: expiration
            )
        )
        let view = MailSecurityBannerView(signers: [signer], trustStore: store)

        let labels = allLabels(in: view)
        let formatted = expiration.formatted(date: .long, time: .omitted)
        XCTAssertTrue(
            labels.contains { $0.contains("The key expired on \(formatted).") },
            "no banner label contains the expiration date; labels: \(labels)"
        )
    }

    func testExpiredSignerBannerWithoutDateKeepsOriginalDetail() throws {
        let store = try makeStore()
        let signer = MailSecurityBannerView.Signer(
            label: "alice@example.com",
            context: SignerContext(
                fingerprint: Self.fprAlice,
                status: RnpSignatureStatus.expired.rawValue
            )
        )
        let view = MailSecurityBannerView(signers: [signer], trustStore: store)

        let labels = allLabels(in: view)
        XCTAssertTrue(
            labels.contains("The signature has expired and the key has not been verified."),
            "expected the original expired-signature detail; labels: \(labels)"
        )
        XCTAssertFalse(labels.contains { $0.contains("The key expired on") })
    }
}

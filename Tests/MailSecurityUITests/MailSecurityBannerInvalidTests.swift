//
//  MailSecurityBannerInvalidTests.swift
//  swift-rnp
//
//  Tests for the banner's invalid-signature warning: the reason-specific
//  detail text and the actions offered for invalid signatures — "View Key
//  in RNP" for known keys, "Fetch signer key" for unknown keys, and the
//  pre-filled "Report Issue" link.
//

import AppKit
import CryptoKit
import XCTest
import MailSecurityEngine
import Librnp
import TrustStore
@testable import MailSecurityUI

final class MailSecurityBannerInvalidTests: XCTestCase {
    private static let fprAlice = "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111"
    private static let aliceEmail = "alice@example.com"

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

    private func signer(
        fingerprint: String?,
        email: String? = nil,
        invalidReason: InvalidSignatureReason? = nil,
        status: RnpSignatureStatus = .invalid
    ) -> MailSecurityBannerView.Signer {
        MailSecurityBannerView.Signer(
            label: email ?? "alice@example.com",
            context: SignerContext(
                fingerprint: fingerprint,
                status: status.rawValue,
                email: email,
                invalidReason: invalidReason?.rawValue
            )
        )
    }

    private func findButton(titled title: String, in view: NSView) -> NSButton? {
        allSubviews(of: view)
            .compactMap { $0 as? NSButton }
            .first { $0.title == title }
    }

    private func allSubviews(of view: NSView) -> [NSView] {
        view.subviews + view.subviews.flatMap { allSubviews(of: $0) }
    }

    private func allLabels(in view: NSView) -> [String] {
        allSubviews(of: view).compactMap { ($0 as? NSTextField)?.stringValue }
    }

    /// Taps a button through its target–action wiring; `performClick` is
    /// unreliable for views that are not in a window.
    @discardableResult
    private func tap(_ button: NSButton) -> Bool {
        _ = NSApplication.shared
        return button.sendAction(button.action, to: button.target)
    }

    // MARK: - Reason detail text

    func testInvalidSignerShowsContentMismatchReason() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: Self.fprAlice, invalidReason: .contentMismatch)],
            trustStore: store
        )
        XCTAssertTrue(allLabels(in: view).contains(
            "The signature does not match the message content; the message may have been modified after signing."
        ))
    }

    func testInvalidSignerShowsRevokedKeyReason() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: Self.fprAlice, invalidReason: .keyRevoked)],
            trustStore: store
        )
        XCTAssertTrue(allLabels(in: view).contains(
            "The signature was made by a key that has been revoked. Do not trust this message."
        ))
    }

    func testInvalidSignerShowsUnknownKeyReason() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: nil, email: Self.aliceEmail, invalidReason: .keyUnknown)],
            trustStore: store
        )
        XCTAssertTrue(allLabels(in: view).contains(
            "The signature was made by an unknown or revoked key, so it could not be verified."
        ))
    }

    func testInvalidSignerWithoutReasonKeepsOriginalDetail() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: Self.fprAlice)],
            trustStore: store
        )
        XCTAssertTrue(allLabels(in: view).contains(
            "The signature does not verify; the message may have been modified."
        ))
    }

    // MARK: - "View signer key" action

    func testViewKeyButtonShownForInvalidSignerWithFingerprint() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: Self.fprAlice, invalidReason: .contentMismatch)],
            trustStore: store
        )
        let button = try XCTUnwrap(findButton(titled: "View Key in RNP", in: view))
        XCTAssertEqual(button.identifier?.rawValue, Self.fprAlice)
        XCTAssertEqual(button.accessibilityIdentifier(), "rnp.banner.view-key.\(Self.fprAlice)")
    }

    func testNoViewKeyButtonForInvalidSignerWithUnknownKey() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: Self.fprAlice, invalidReason: .keyUnknown)],
            trustStore: store
        )
        XCTAssertNil(findButton(titled: "View Key in RNP", in: view))
    }

    // MARK: - "Fetch signer key" action

    func testFetchButtonShownForInvalidSignerWithoutFingerprint() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: nil, email: Self.aliceEmail, invalidReason: .keyUnknown)],
            trustStore: store,
            onFetchSignerKey: { _, _ in }
        )
        let button = try XCTUnwrap(findButton(titled: "Fetch signer key", in: view))
        XCTAssertEqual(button.identifier?.rawValue, Self.aliceEmail)
    }

    func testFetchActionInvokedForInvalidSigner() throws {
        let store = try makeStore()
        var fetched: [MailSecurityBannerView.Signer] = []
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: nil, email: Self.aliceEmail, invalidReason: .keyUnknown)],
            trustStore: store,
            onFetchSignerKey: { signer, _ in fetched.append(signer) }
        )
        let button = try XCTUnwrap(findButton(titled: "Fetch signer key", in: view))

        XCTAssertTrue(tap(button))

        XCTAssertEqual(fetched.count, 1)
        XCTAssertEqual(fetched.first?.context?.email, Self.aliceEmail)
    }

    func testNoFetchButtonForInvalidSignerWithFingerprint() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: Self.fprAlice, invalidReason: .contentMismatch)],
            trustStore: store,
            onFetchSignerKey: { _, _ in }
        )
        XCTAssertNil(findButton(titled: "Fetch signer key", in: view))
    }

    // MARK: - "Report Issue" action

    func testReportIssueButtonShownForInvalidSigner() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: Self.fprAlice, invalidReason: .contentMismatch)],
            trustStore: store
        )
        let button = try XCTUnwrap(findButton(titled: "Report Issue", in: view))
        XCTAssertEqual(button.identifier?.rawValue, Self.fprAlice)
        XCTAssertEqual(button.accessibilityIdentifier(), "rnp.banner.report-issue.\(Self.fprAlice)")
    }

    func testNoReportIssueButtonForValidSigner() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: Self.fprAlice, status: .valid)],
            trustStore: store
        )
        XCTAssertNil(findButton(titled: "Report Issue", in: view))
    }

    func testReportIssueURLPrefillsStatusReasonAndFingerprint() throws {
        let signer = signer(fingerprint: Self.fprAlice, invalidReason: .keyRevoked)
        let url = try XCTUnwrap(MailSecurityBannerView.reportIssueURL(for: signer))
        let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))

        XCTAssertEqual(components.host, "github.com")
        XCTAssertEqual(components.path, "/rnpgp/rnp-mailapp-extension/issues/new")
        let body = try XCTUnwrap(components.queryItems?.first { $0.name == "body" }?.value)
        XCTAssertTrue(body.contains("Signature status: invalid"))
        XCTAssertTrue(body.contains("Failure reason: key-revoked"))
        XCTAssertTrue(body.contains("Signer key fingerprint: \(Self.fprAlice)"))
    }

    func testReportIssueURLHandlesMissingContextDetails() throws {
        let signer = MailSecurityBannerView.Signer(
            label: "Unknown signer",
            context: SignerContext(fingerprint: nil, status: RnpSignatureStatus.invalid.rawValue)
        )
        let url = try XCTUnwrap(MailSecurityBannerView.reportIssueURL(for: signer))
        let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let body = try XCTUnwrap(components.queryItems?.first { $0.name == "body" }?.value)
        XCTAssertTrue(body.contains("Failure reason: unknown"))
        XCTAssertTrue(body.contains("Signer key fingerprint: unknown"))
    }
}

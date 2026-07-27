//
//  MailSecurityBannerFetchTests.swift
//  swift-rnp
//
//  Tests for the banner's "Fetch signer key" action: visibility rules for
//  unknown signers, action wiring, the in-progress state, and inline failure
//  reporting.
//

import AppKit
import CryptoKit
import XCTest
import MailSecurityEngine
import Rnp
import TrustStore
@testable import MailSecurityUI

final class MailSecurityBannerFetchTests: XCTestCase {
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
        email: String?,
        status: RnpSignatureStatus
    ) -> MailSecurityBannerView.Signer {
        MailSecurityBannerView.Signer(
            label: email ?? "Unknown signer",
            context: SignerContext(fingerprint: fingerprint, status: status.rawValue, email: email)
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

    /// Taps a button through its target–action wiring; `performClick` is
    /// unreliable for views that are not in a window, and
    /// `NSControl.sendAction` needs a running NSApplication.
    @discardableResult
    private func tap(_ button: NSButton) -> Bool {
        _ = NSApplication.shared
        return button.sendAction(button.action, to: button.target)
    }

    // MARK: - Visibility

    func testFetchButtonShownForUnknownSignerWithFingerprint() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: Self.fprAlice, email: nil, status: .signerUnknown)],
            trustStore: store,
            onFetchSignerKey: { _, _ in }
        )
        let button = try XCTUnwrap(findButton(titled: "Fetch signer key", in: view))
        XCTAssertEqual(button.identifier?.rawValue, Self.fprAlice)
        XCTAssertEqual(
            button.accessibilityIdentifier(),
            "rnp.banner.fetch-signer-key.\(Self.fprAlice)"
        )
    }

    func testFetchButtonShownForUnknownSignerWithEmailOnly() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: nil, email: Self.aliceEmail, status: .signerUnknown)],
            trustStore: store,
            onFetchSignerKey: { _, _ in }
        )
        let button = try XCTUnwrap(findButton(titled: "Fetch signer key", in: view))
        XCTAssertEqual(button.identifier?.rawValue, Self.aliceEmail)
    }

    func testNoFetchButtonWithoutAction() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: Self.fprAlice, email: nil, status: .signerUnknown)],
            trustStore: store
        )
        XCTAssertNil(findButton(titled: "Fetch signer key", in: view))
    }

    func testNoFetchButtonForKnownSigner() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: Self.fprAlice, email: nil, status: .valid)],
            trustStore: store,
            onFetchSignerKey: { _, _ in }
        )
        XCTAssertNil(findButton(titled: "Fetch signer key", in: view))
    }

    func testNoFetchButtonWithoutIdentifier() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: nil, email: nil, status: .signerUnknown)],
            trustStore: store,
            onFetchSignerKey: { _, _ in }
        )
        XCTAssertNil(findButton(titled: "Fetch signer key", in: view))
    }

    // MARK: - Action wiring and states

    func testFetchActionInvokedWithSignerAndShowsProgress() throws {
        let store = try makeStore()
        var fetched: [MailSecurityBannerView.Signer] = []
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: nil, email: Self.aliceEmail, status: .signerUnknown)],
            trustStore: store,
            onFetchSignerKey: { signer, _ in
                fetched.append(signer)
                // Completion intentionally not called: simulates an
                // in-flight keyserver request.
            }
        )
        let button = try XCTUnwrap(findButton(titled: "Fetch signer key", in: view))

        XCTAssertTrue(tap(button))

        XCTAssertEqual(fetched.count, 1)
        XCTAssertEqual(fetched.first?.context?.email, Self.aliceEmail)
        XCTAssertFalse(button.isEnabled)
        XCTAssertEqual(button.title, "Fetching…")
    }

    func testFetchFailureShowsErrorAndRestoresButton() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: Self.fprAlice, email: nil, status: .signerUnknown)],
            trustStore: store,
            onFetchSignerKey: { _, completion in
                completion(.failure("The key was not found on the server."))
            }
        )
        let button = try XCTUnwrap(findButton(titled: "Fetch signer key", in: view))

        XCTAssertTrue(tap(button))

        let labels = allSubviews(of: view).compactMap { ($0 as? NSTextField)?.stringValue }
        XCTAssertTrue(labels.contains("The key was not found on the server."))
        // The banner rebuilt itself: the button is back and enabled so the
        // user can retry.
        let restored = try XCTUnwrap(findButton(titled: "Fetch signer key", in: view))
        XCTAssertTrue(restored.isEnabled)
    }

    func testFetchSuccessDoesNotShowError() throws {
        let store = try makeStore()
        let view = MailSecurityBannerView(
            signers: [signer(fingerprint: Self.fprAlice, email: nil, status: .signerUnknown)],
            trustStore: store,
            onFetchSignerKey: { _, completion in
                completion(.success)
            }
        )
        let button = try XCTUnwrap(findButton(titled: "Fetch signer key", in: view))

        XCTAssertTrue(tap(button))

        // On success the host replaces the banner with the re-verified
        // status; the banner itself must not surface an error or re-enable
        // the button.
        let labels = allSubviews(of: view).compactMap { ($0 as? NSTextField)?.stringValue }
        XCTAssertFalse(labels.contains("The key was not found on the server."))
        XCTAssertEqual(button.title, "Fetching…")
        XCTAssertFalse(button.isEnabled)
    }
}

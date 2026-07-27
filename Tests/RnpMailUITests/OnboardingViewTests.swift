//
//  OnboardingViewTests.swift
//  swift-rnp
//
//  Render tests for the onboarding UI. These run without a host app so they
//  work in CI unsigned builds.
//

import AppKit
import SwiftUI
import XCTest
@testable import RnpMailUI
import MailSecurityEngine

final class OnboardingViewTests: CIBaseTestCase {
    func testOnboardingViewRenders() throws {
        let view = OnboardingView(
            isPresented: .constant(true),
            onGenerate: { _, _, _, _, _ in
                .success(OnboardingGenerationResult(
                    userID: "Test <test@example.com>",
                    fingerprint: "ABCD1234",
                    revocationCertificateURL: URL(fileURLWithPath: "/tmp/rev.asc")
                ))
            },
            onImport: { _ in .success([]) }
        )

        let host = NSHostingController(rootView: view)
        host.loadView()
        XCTAssertNotNil(host.view)
        XCTAssertTrue(host.view is NSView)
    }

    func testGenerateKeyFormRenders() {
        let view = GenerateKeyForm(
            viewModel: OnboardingViewModel(),
            onGenerate: {},
            onBack: {}
        )

        let host = NSHostingController(rootView: view)
        host.loadView()
        XCTAssertNotNil(host.view)
        XCTAssertTrue(host.view is NSView)
    }

    func testOnboardingViewModelAdvancesToGenerateForm() {
        let model = OnboardingViewModel()
        XCTAssertEqual(model.currentStep, .welcome)
        model.continueFromWelcome()
        XCTAssertEqual(model.currentStep, .createOrImport)
        model.chooseCreate()
        XCTAssertEqual(model.currentStep, .generateForm)
        XCTAssertEqual(model.algorithm, .ed25519)
        XCTAssertTrue(model.useTouchID)
    }
}

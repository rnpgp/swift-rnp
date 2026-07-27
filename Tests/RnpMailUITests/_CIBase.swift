import XCTest

/// Base class that skips tests on headless CI runners (no display server
/// available, so SwiftUI/AppKit views can't be rendered).
/// Set RNP_RUN_UI_TESTS=1 to force them on.
class CIBaseTestCase: XCTestCase {
    override class var runsForEachTargetApplicationUIConfiguration: Bool { false }
    override func setUp() {
        super.setUp()
        if ProcessInfo.processInfo.environment["CI"] != nil &&
           ProcessInfo.processInfo.environment["RNP_RUN_UI_TESTS"] == nil {
            throw XCTSkip("UI tests require a display server; set RNP_RUN_UI_TESTS=1 to override")
        }
    }
}

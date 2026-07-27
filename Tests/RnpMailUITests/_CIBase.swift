import XCTest

class CIBaseTestCase: XCTestCase {
    override func setUpWithError() throws {
        try super.setUpWithError()
        if ProcessInfo.processInfo.environment["CI"] != nil &&
           ProcessInfo.processInfo.environment["RNP_RUN_UI_TESTS"] == nil {
            throw XCTSkip("UI tests require a display server; set RNP_RUN_UI_TESTS=1 to override")
        }
    }
}

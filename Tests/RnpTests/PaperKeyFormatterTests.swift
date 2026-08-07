//
//  PaperKeyFormatterTests.swift
//  RnpTests
//

import XCTest
@testable import Librnp

final class PaperKeyFormatterTests: XCTestCase {

    func testRoundTripPreservesBytes() {
        let original = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        let formatted = PaperKeyHexFormatter.format(original)
        let parsed = PaperKeyHexFormatter.parse(formatted)
        XCTAssertEqual(parsed, original)
    }

    func testRoundTripLargerInput() {
        var bytes: [UInt8] = []
        for i in 0..<200 { bytes.append(UInt8(i % 256)) }
        let original = Data(bytes)
        let formatted = PaperKeyHexFormatter.format(original)
        let parsed = PaperKeyHexFormatter.parse(formatted)
        XCTAssertEqual(parsed, original)
    }

    func testFormatHasOffsetPrefixesPerLine() {
        let data = Data(repeating: 0x42, count: PaperKeyHexFormatter.bytesPerGroup * PaperKeyHexFormatter.groupsPerLine * 3)
        let formatted = PaperKeyHexFormatter.format(data)
        let lines = formatted.split(separator: "\n")
        XCTAssertEqual(lines.count, 3)
        XCTAssertEqual(lines[0].hasPrefix("00000000:"), true)
        // Second line offset = 30 bytes (one line) = 0x1E.
        XCTAssertEqual(lines[1].hasPrefix("0000001E:"), true)
        // Third line offset = 60 bytes = 0x3C.
        XCTAssertEqual(lines[2].hasPrefix("0000003C:"), true)
    }

    func testParseSkipsCommentsAndBlanks() {
        let text = """
        # this is a comment

        # another
        00000000: deadbeef
        """
        let parsed = PaperKeyHexFormatter.parse(text)
        XCTAssertEqual(parsed, Data([0xDE, 0xAD, 0xBE, 0xEF]))
    }

    func testParseToleratesPaddingSpacesInLastGroup() {
        // The formatter pads the last group with spaces; parse must
        // tolerate them.
        let text = "00000000: deadbeef          "
        let parsed = PaperKeyHexFormatter.parse(text)
        XCTAssertEqual(parsed, Data([0xDE, 0xAD, 0xBE, 0xEF]))
    }

    func testParseRejectsMalformedHex() {
        let text = "00000000: zztop"
        XCTAssertNil(PaperKeyHexFormatter.parse(text))
    }
}

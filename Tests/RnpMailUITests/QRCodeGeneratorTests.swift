//
//  QRCodeGeneratorTests.swift
//  RnpMailUITests
//

import XCTest
@testable import RnpMailUI

final class QRCodeGeneratorTests: CIBaseTestCase {

    func testChunkAndReassembleRoundTrip() {
        let original = String(repeating: "A", count: 2000)
        let chunks = QRCodeGenerator.chunkForQR(original, maxPerChunk: 800)
        XCTAssertEqual(chunks.count, 3)
        let reassembled = QRCodeGenerator.reassembleFromQR(chunks)
        XCTAssertEqual(reassembled, original)
    }

    func testShortStringProducesSingleChunk() {
        let chunks = QRCodeGenerator.chunkForQR("short", maxPerChunk: 800)
        XCTAssertEqual(chunks.count, 1)
        XCTAssertEqual(QRCodeGenerator.reassembleFromQR(chunks), "short")
    }

    func testEmptyStringProducesNoChunks() {
        let chunks = QRCodeGenerator.chunkForQR("", maxPerChunk: 800)
        XCTAssertTrue(chunks.isEmpty)
        XCTAssertNil(QRCodeGenerator.reassembleFromQR([]))
    }

    func testReassembleRejectsMalformedPrefix() {
        let result = QRCodeGenerator.reassembleFromQR(["BAD/0/1/data"])
        XCTAssertNil(result)
    }

    func testReassembleRejectsMissingChunk() {
        let chunks = ["RNP/0/3/aaa", "RNP/1/3/bbb"]  // missing chunk 2
        XCTAssertNil(QRCodeGenerator.reassembleFromQR(chunks))
    }

    func testReassembleRejectsTotalMismatch() {
        let chunks = ["RNP/0/2/aaa", "RNP/1/3/bbb"]
        XCTAssertNil(QRCodeGenerator.reassembleFromQR(chunks))
    }

    func testGenerateReturnsImageForValidInput() {
        let image = QRCodeGenerator.generate(from: "test data")
        XCTAssertNotNil(image)
        XCTAssertGreaterThan(image!.size.width, 0)
    }
}

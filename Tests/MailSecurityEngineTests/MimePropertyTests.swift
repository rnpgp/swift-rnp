//
//  MimePropertyTests.swift
//  swift-rnp
//
//  Property-based roundtrip and robustness tests for the MIME parser.
//

import XCTest
@testable import MailSecurityEngine

final class MimePropertyTests: XCTestCase {
    /// Number of random iterations per property test. Kept modest so CI stays fast.
    private let iterations = 500

    // MARK: - Property: valid messages parse without losing structure

    func testRandomValidMessagesParseAndPreserveStructure() {
        for iteration in 0 ..< iterations {
            let message = randomValidMessage()
            let parsed = MimeMessage.parse(message)

            XCTAssertFalse(parsed.headers.isEmpty, "iteration \(iteration): expected headers")
            XCTAssertNotNil(parsed.contentType, "iteration \(iteration): expected Content-Type")

            if let contentType = parsed.contentType, contentType.isMultipart {
                XCTAssertNotNil(contentType.boundary, "iteration \(iteration): multipart needs boundary")
                XCTAssertNotNil(parsed.parts, "iteration \(iteration): expected parts")
                XCTAssertGreaterThan(parsed.parts?.count ?? 0, 0, "iteration \(iteration): expected at least one part")
                XCTAssertEqual(parsed.parts?.count, parsed.rawPartEntities?.count, "iteration \(iteration): parts and rawPartEntities must be parallel")
            }
        }
    }

    // MARK: - Property: base64 roundtrip

    func testBase64RoundtripPreservesBytes() {
        for iteration in 0 ..< iterations {
            let size = Int.random(in: 1 ... 4096)
            let payload = randomData(size: size)
            let encoded = payload.base64EncodedString()
            let message = "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n\(encoded)"
            let parsed = MimeMessage.parse(Data(message.utf8))

            XCTAssertEqual(parsed.decodedBody(), payload, "iteration \(iteration): base64 roundtrip failed")
        }
    }

    // MARK: - Property: quoted-printable roundtrip

    func testQuotedPrintableRoundtripPreservesBytes() {
        for iteration in 0 ..< iterations {
            let size = Int.random(in: 1 ... 2048)
            let payload = randomData(size: size)
            let encoded = encodeQuotedPrintable(payload)
            let message = "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n\(encoded)"
            let parsed = MimeMessage.parse(Data(message.utf8))

            XCTAssertEqual(parsed.decodedBody(), payload, "iteration \(iteration): quoted-printable roundtrip failed")
        }
    }

    // MARK: - Property: random invalid inputs do not crash

    func testRandomInvalidInputsDoNotCrash() {
        for _ in 0 ..< iterations {
            let data = randomData(size: Int.random(in: 0 ... 8192))
            let message = MimeMessage.parse(data)

            // The only invariant is no crash. Exercise accessors to catch lazy crashes.
            _ = message.headers
            _ = message.body
            _ = message.parts
            _ = message.decodedBody()
            _ = message.contentType
            _ = message.contentTransferEncoding
        }
    }

    // MARK: - Property: header unfolding preserves values

    func testFoldedHeadersAreUnfolded() {
        for iteration in 0 ..< iterations {
            let name = randomHeaderName()
            let value = randomHeaderValue()
            let folded = foldHeader(value)
            let message = "\(name): \(folded)\r\n\r\nbody"
            let parsed = MimeMessage.parse(Data(message.utf8))

            let expected = folded
                .components(separatedBy: "\r\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
                .joined(separator: " ")
            XCTAssertEqual(parsed.header(name), expected, "iteration \(iteration): header unfolding failed")
        }
    }

    // MARK: - Random generators

    private func randomValidMessage() -> Data {
        let useMultipart = Bool.random()
        let eol = Bool.random() ? "\r\n" : "\n"

        if useMultipart {
            let boundary = randomBoundary()
            let partCount = Int.random(in: 1 ... 5)
            var parts: [String] = []
            for _ in 0 ..< partCount {
                let nested = Bool.random() && partCount > 1
                let partBody = randomBody()
                let partHeaders = nested
                    ? "Content-Type: multipart/mixed; boundary=\"\(randomBoundary())\"\(eol)\(eol)\(randomMultipartBody(eol: eol))"
                    : "Content-Type: text/plain\(eol)\(eol)\(partBody)"
                parts.append("--\(boundary)\(eol)\(partHeaders)\(eol)")
            }
            let body = parts.joined() + "--\(boundary)--\(eol)"
            return Data("Content-Type: multipart/mixed; boundary=\"\(boundary)\"\(eol)Subject: test\(eol)\(eol)\(body)".utf8)
        } else {
            let encoding = ["7bit", "base64", "quoted-printable"].randomElement()!
            let body = encoding == "7bit" ? randomBody() : encodeBody(randomBody(), encoding: encoding)
            let cte = encoding == "7bit" ? "" : "Content-Transfer-Encoding: \(encoding)\(eol)"
            return Data("Content-Type: text/plain\(eol)\(cte)Subject: test\(eol)\(eol)\(body)".utf8)
        }
    }

    private func randomMultipartBody(eol: String) -> String {
        let boundary = randomBoundary()
        let part = "--\(boundary)\(eol)Content-Type: text/plain\(eol)\(eol)\(randomBody())\(eol)--\(boundary)--\(eol)"
        return part
    }

    private func randomBody() -> String {
        let words = ["hello", "world", "mime", "test", "openpgp", "swift", "boundary", "part"]
        let count = Int.random(in: 1 ... 50)
        return (0 ..< count).map { _ in words.randomElement()! }.joined(separator: " ")
    }

    private func randomData(size: Int) -> Data {
        var data = Data(count: size)
        data.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, size, ptr.baseAddress!)
        }
        return data
    }

    private func randomBoundary() -> String {
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return String((0 ..< 16).map { _ in chars.randomElement()! })
    }

    private func randomHeaderName() -> String {
        let names = ["Subject", "From", "To", "Date", "Message-ID", "X-Custom"]
        return names.randomElement()!
    }

    private func randomHeaderValue() -> String {
        let words = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"]
        let count = Int.random(in: 1 ... 20)
        return (0 ..< count).map { _ in words.randomElement()! }.joined(separator: " ")
    }

    private func foldHeader(_ value: String) -> String {
        var result = ""
        var index = value.startIndex
        while index < value.endIndex {
            let chunkSize = Int.random(in: 5 ... 20)
            let end = value.index(index, offsetBy: min(chunkSize, value.distance(from: index, to: value.endIndex)))
            if !result.isEmpty {
                result += "\r\n\t"
            }
            result += value[index ..< end]
            index = end
        }
        return result
    }

    private func encodeBody(_ body: String, encoding: String) -> String {
        switch encoding {
        case "base64":
            return Data(body.utf8).base64EncodedString()
        case "quoted-printable":
            return encodeQuotedPrintable(Data(body.utf8))
        default:
            return body
        }
    }

    private func encodeQuotedPrintable(_ data: Data) -> String {
        var result = ""
        for byte in data {
            if (byte >= 0x21 && byte <= 0x7E && byte != 0x3D) || byte == 0x20 || byte == 0x09 {
                result.append(Character(UnicodeScalar(byte)))
            } else {
                result.append(String(format: "=%02X", byte))
            }
        }
        return result
    }
}

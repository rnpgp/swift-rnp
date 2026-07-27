//
//  MimeCorpusTests.swift
//  swift-rnp
//
//  Crash-regression test for the MIME parser against a small fixture corpus.
//

import XCTest
@testable import MailSecurityEngine

final class MimeCorpusTests: XCTestCase {
    private let fixtureNames = [
        "deep-nesting",
        "nested-10-levels",
        "broken-boundary",
        "duplicate-boundary",
        "empty-parts",
        "huge-header",
        "huge-header-64kb",
        "malformed-base64",
        "malformed-quoted-printable",
        "missing-content-type",
        "mixed-eols",
        "mixed-eols-cr",
    ]

    func testCorpusParsesWithoutCrashing() throws {
        let bundle = Bundle.module
        for name in fixtureNames {
            guard let url = bundle.url(forResource: name, withExtension: "txt", subdirectory: "Fixtures/mime-corpus")
            else {
                XCTFail("Missing corpus fixture: \(name).txt")
                continue
            }

            let data = try Data(contentsOf: url)
            let message = MimeMessage.parse(data)

            // The only invariant is that parsing does not crash. We do exercise
            // the common accessors to catch lazy crashes.
            _ = message.headers
            _ = message.body
            _ = message.parts
            _ = message.decodedBody()
        }
    }
}

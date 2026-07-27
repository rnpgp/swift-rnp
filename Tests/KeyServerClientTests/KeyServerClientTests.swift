//
//  KeyServerClientTests.swift
//  swift-rnp
//
//  Tests for KeyServerClient and WKD encoding.
//

import CryptoKit
@testable import KeyServerClient
import XCTest

final class KeyServerClientTests: XCTestCase {
    // MARK: - WKD encoding

    func testWKDEncodingMatchesDraftExample() throws {
        let url = try WKDEncoding.url(for: "Joe.Doe@Example.ORG", advanced: true)
        let expected = "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe"
        XCTAssertEqual(url.absoluteString, expected)
    }

    func testWKDDirectMethodURL() throws {
        let url = try WKDEncoding.url(for: "Joe.Doe@Example.ORG", advanced: false)
        let expected = "https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe"
        XCTAssertEqual(url.absoluteString, expected)
    }

    func testWKDEncodingLowercasesASCIILocalPart() throws {
        // The hash is computed over the lowercased ASCII local part.
        let url = try WKDEncoding.url(for: "JOE.DOE@example.org", advanced: true)
        XCTAssertTrue(url.absoluteString.contains("/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q"))
    }

    func testWKDEncodingRejectsInvalidEmail() {
        XCTAssertThrowsError(try WKDEncoding.url(for: "not-an-email", advanced: true)) { error in
            XCTAssertEqual(error as? KeyServerError, .invalidEmail)
        }
    }

    // MARK: - Mock client

    func testMockUploadRecordsKeyAndReturnsReceipt() async throws {
        let client = MockKeyServerClient(responses: MockKeyServerResponses(
            uploadResult: .success(UploadReceipt(body: "ok", token: "abc123"))
        ))
        let receipt = try await client.upload(armoredKey: "fake-key")
        XCTAssertEqual(receipt.token, "abc123")
        XCTAssertEqual(client.uploadedKeys, ["fake-key"])
    }

    func testMockFetchByEmailReturnsData() async throws {
        let data = Data("armored-key".utf8)
        let client = MockKeyServerClient(responses: MockKeyServerResponses(
            byEmailResult: .success(data)
        ))
        let result = try await client.fetchByEmail("test@example.org")
        XCTAssertEqual(result, data)
        XCTAssertEqual(client.fetchedEmails, ["test@example.org"])
    }

    func testMockFetchByEmailPropagatesNotFound() async {
        let client = MockKeyServerClient(responses: MockKeyServerResponses(
            byEmailResult: .failure(.notFound)
        ))
        do {
            _ = try await client.fetchByEmail("test@example.org")
            XCTFail("Expected notFound error")
        } catch {
            XCTAssertEqual(error as? KeyServerError, .notFound)
        }
    }

    func testMockFetchByFingerprintCleansFingerprint() async throws {
        let data = Data("armored-key".utf8)
        let client = MockKeyServerClient(responses: MockKeyServerResponses(
            byFingerprintResult: .success(data)
        ))
        let result = try await client.fetchByFingerprint("ABCD 1234 EF56")
        XCTAssertEqual(result, data)
        XCTAssertEqual(client.fetchedFingerprints, ["ABCD 1234 EF56"])
    }

    func testMockFetchWKDRecordsArguments() async throws {
        let data = Data("binary-key".utf8)
        let client = MockKeyServerClient(responses: MockKeyServerResponses(
            wkdResult: .success(data)
        ))
        let result = try await client.fetchWKD(email: "joe@example.org", advanced: true)
        XCTAssertEqual(result, data)
        XCTAssertEqual(client.fetchedWKDs, ["joe@example.org (advanced=true)"])
    }

    func testMockFetchHKPSRecordsArguments() async throws {
        let data = Data("armored-key".utf8)
        let client = MockKeyServerClient(responses: MockKeyServerResponses(
            hkpsResult: .success(data)
        ))
        let result = try await client.fetchHKPS(fingerprint: "ABCD", server: .ubuntu)
        XCTAssertEqual(result, data)
        XCTAssertEqual(client.fetchedHKPS.map { $0.1 }, [.ubuntu])
    }

    // MARK: - URLSession client

    func testURLSessionFetchByFingerprintReturnsData() async throws {
        let expected = Data("armored-public-key".utf8)
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: config)

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.absoluteString, "https://keys.openpgp.org/vks/v1/by-fingerprint/ABCD1234ABCD1234")
            return (expected, HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        }

        let client = URLSessionKeyServerClient(session: session)
        let result = try await client.fetchByFingerprint("ABCD 1234 ABCD 1234")
        XCTAssertEqual(result, expected)
    }

    func testURLSessionFetchByEmailReturnsNotFound() async {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: config)

        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
            return (Data(), response)
        }

        let client = URLSessionKeyServerClient(session: session)
        do {
            _ = try await client.fetchByEmail("missing@example.org")
            XCTFail("Expected notFound")
        } catch {
            XCTAssertEqual(error as? KeyServerError, .notFound)
        }
    }

    func testURLSessionUploadReturnsReceipt() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: config)

        StubURLProtocol.handler = { request in
            let bodyData: Data
            if let body = request.httpBody {
                bodyData = body
            } else if let stream = request.httpBodyStream {
                stream.open()
                defer { stream.close() }
                bodyData = Data(reading: stream)
            } else {
                bodyData = Data()
            }
            let body = String(decoding: bodyData, as: UTF8.self)
            XCTAssertEqual(body, "armored-key")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "text/plain")
            let data = Data("token=abc".utf8)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (data, response)
        }

        let client = URLSessionKeyServerClient(session: session)
        let receipt = try await client.upload(armoredKey: "armored-key")
        XCTAssertEqual(receipt.body, "token=abc")
    }

    func testURLSessionInvalidFingerprintThrows() async {
        let client = URLSessionKeyServerClient()
        do {
            _ = try await client.fetchByFingerprint("short")
            XCTFail("Expected invalidFingerprint")
        } catch {
            XCTAssertEqual(error as? KeyServerError, .invalidFingerprint)
        }
    }

    // MARK: - HKPS

    func testHKPSServerCustomHostURLs() {
        let server = HKPSServer(rawValue: "keys.example.com")
        XCTAssertEqual(server.lookupURL, "https://keys.example.com/pks/lookup")
        XCTAssertEqual(server.addURL, "https://keys.example.com/pks/add")
    }

    func testURLSessionFetchHKPSBuildsLookupURL() async throws {
        let expected = Data("armored-public-key".utf8)
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: config)

        StubURLProtocol.handler = { request in
            let url = request.url?.absoluteString ?? ""
            XCTAssertTrue(url.hasPrefix("https://keyserver.ubuntu.com/pks/lookup?"), url)
            XCTAssertTrue(url.contains("op=get"), url)
            XCTAssertTrue(url.contains("options=mr"), url)
            XCTAssertTrue(url.contains("search=0xABCD1234ABCD1234"), url)
            return (expected, HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        }

        let client = URLSessionKeyServerClient(session: session)
        let result = try await client.fetchHKPS(fingerprint: "abcd 1234 abcd 1234", server: .ubuntu)
        XCTAssertEqual(result, expected)
    }

    func testURLSessionFetchHKPSUsesCustomServerHost() async throws {
        let expected = Data("armored-public-key".utf8)
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: config)

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.host, "keys.example.com")
            return (expected, HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        }

        let client = URLSessionKeyServerClient(session: session)
        let result = try await client.fetchHKPS(
            fingerprint: "ABCD1234ABCD1234",
            server: HKPSServer(rawValue: "keys.example.com")
        )
        XCTAssertEqual(result, expected)
    }

    func testURLSessionFetchHKPSRejectsInvalidFingerprint() async {
        let client = URLSessionKeyServerClient()
        do {
            _ = try await client.fetchHKPS(fingerprint: "short", server: .ubuntu)
            XCTFail("Expected invalidFingerprint")
        } catch {
            XCTAssertEqual(error as? KeyServerError, .invalidFingerprint)
        }
    }

    func testURLSessionFetchHKPSReturnsNotFound() async {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: config)

        StubURLProtocol.handler = { request in
            (Data(), HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!)
        }

        let client = URLSessionKeyServerClient(session: session)
        do {
            _ = try await client.fetchHKPS(fingerprint: "ABCD1234ABCD1234", server: .ubuntu)
            XCTFail("Expected notFound")
        } catch {
            XCTAssertEqual(error as? KeyServerError, .notFound)
        }
    }

    func testURLSessionUploadHKPSPostsKeytext() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: config)

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.absoluteString, "https://keys.example.com/pks/add")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(
                request.value(forHTTPHeaderField: "Content-Type"),
                "application/x-www-form-urlencoded"
            )
            let bodyData: Data
            if let body = request.httpBody {
                bodyData = body
            } else if let stream = request.httpBodyStream {
                stream.open()
                defer { stream.close() }
                bodyData = Data(reading: stream)
            } else {
                bodyData = Data()
            }
            let body = String(decoding: bodyData, as: UTF8.self)
            XCTAssertTrue(body.hasPrefix("keytext="), body)
            XCTAssertTrue(body.contains("armored-key"), body)
            let data = Data("added".utf8)
            return (data, HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        }

        let client = URLSessionKeyServerClient(session: session)
        let receipt = try await client.uploadHKPS(
            armoredKey: "armored-key",
            server: HKPSServer(rawValue: "keys.example.com")
        )
        XCTAssertEqual(receipt.body, "added")
    }

    func testMockUploadHKPSRecordsArguments() async throws {
        let client = MockKeyServerClient(responses: MockKeyServerResponses(
            hkpsUploadResult: .success(UploadReceipt(body: "added"))
        ))
        let receipt = try await client.uploadHKPS(armoredKey: "fake-key", server: .ubuntu)
        XCTAssertEqual(receipt.body, "added")
        XCTAssertEqual(client.hkpsUploads.map { $0.0 }, ["fake-key"])
        XCTAssertEqual(client.hkpsUploads.map { $0.1 }, [.ubuntu])
    }
}

// MARK: - URLProtocol stub

private final class StubURLProtocol: URLProtocol {
    static var handler: ((URLRequest) -> (Data, URLResponse))?

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let handler = StubURLProtocol.handler else {
            fatalError("No handler set")
        }
        let (data, response) = handler(request)
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private extension Data {
    init(reading stream: InputStream) {
        self.init()
        let bufferSize = 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }
        while stream.hasBytesAvailable {
            let read = stream.read(buffer, maxLength: bufferSize)
            if read > 0 {
                append(buffer, count: read)
            } else if read < 0 {
                break
            }
        }
    }
}

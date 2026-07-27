//
//  TestSupport.swift
//  MailSecurityEngineTests
//
//  DRY extraction: every test file that needs librnp duplicates the
//  same probe-availability pattern. This helper centralizes it so
//  new tests don't repeat the 10-line boilerplate.
//

import Foundation
import MailSecurityEngine

/// Test helpers shared across MailSecurityEngineTests.
enum TestSupport {
    /// Probes whether librnp is reachable on the local machine.
    /// CI keeps a local install; developers without it get
    /// XCTSkipUnless results. The probe creates a temp directory,
    /// attempts to construct a KeyManager, and cleans up.
    static func librnpAvailable() -> Bool {
        let probe = FileManager.default.temporaryDirectory
            .appendingPathComponent("librnp-probe-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: probe, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: probe) }
        do {
            _ = try KeyManager(directory: probe, password: "x")
            return true
        } catch {
            return false
        }
    }

    /// Creates a unique temp directory for test isolation. The caller
    /// is responsible for cleanup (typically via tearDown).
    static func makeTempDir(prefix: String = "test") -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
}

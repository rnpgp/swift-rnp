//
//  FFIHelpers.swift
//  swift-rnp
//
//  Internal helpers for feeding Swift `Data` through librnp memory streams.
//

import CRnp
import Foundation

/// RAII-style wrapper around a librnp memory output stream
/// (`rnp_output_to_memory` / `rnp_output_destroy`).
internal final class MemoryOutput {
    let handle: rnp_output_t

    init(maxAlloc: Int = 0) throws {
        var output: rnp_output_t?
        try rnpCheck(rnp_output_to_memory(&output, maxAlloc), operation: "memory output create")
        guard let output else {
            throw RnpError.ffiFailed(
                operation: "memory output create",
                code: rnpStatusSuccess,
                message: "unexpected NULL output"
            )
        }
        handle = output
    }

    deinit {
        rnp_output_destroy(handle)
    }

    /// Copies the accumulated bytes out of the memory output stream.
    func readData() throws -> Data {
        var buf: UnsafeMutablePointer<UInt8>?
        var len = 0
        // do_copy = false: the internal buffer is copied into Swift `Data`
        // below, before the stream is destroyed.
        try rnpCheck(
            rnp_output_memory_get_buf(handle, &buf, &len, false),
            operation: "read memory output"
        )
        guard let buf else {
            if len == 0 {
                return Data()
            }
            throw RnpError.ffiFailed(
                operation: "read memory output",
                code: rnpStatusSuccess,
                message: "unexpected NULL buffer"
            )
        }
        return Data(bytes: buf, count: len)
    }
}

/// Runs `body` with a librnp memory input stream created from `data`,
/// destroying the stream afterwards.
///
/// - Throws: `RnpError.invalidArgument` when `data` is empty
///   (`rnp_input_from_memory` cannot accept a zero-length buffer).
internal func withMemoryInput<T>(
    _ data: Data,
    operation: String,
    _ body: (rnp_input_t) throws -> T
) throws -> T {
    guard !data.isEmpty else {
        throw RnpError.invalidArgument("\(operation): input data must not be empty")
    }
    // The array is passed straight to the C API; do_copy = true makes librnp
    // take its own copy, so no lifetime coupling to the Swift buffer remains.
    let bytes = [UInt8](data)
    var input: rnp_input_t?
    try rnpCheck(
        rnp_input_from_memory(&input, bytes, bytes.count, true),
        operation: "\(operation) input"
    )
    guard let inputHandle = input else {
        throw RnpError.ffiFailed(
            operation: "\(operation) input",
            code: rnpStatusSuccess,
            message: "unexpected NULL input"
        )
    }
    defer { rnp_input_destroy(inputHandle) }
    return try body(inputHandle)
}

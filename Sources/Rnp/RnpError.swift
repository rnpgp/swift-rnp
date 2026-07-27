//
//  RnpError.swift
//  swift-rnp
//
//  Error type mapping librnp result codes (rnp_result_t) to Swift errors.
//

import CRnp
import Foundation

/// Errors thrown by the `Rnp` wrapper.
public enum RnpError: Error, Equatable {
    /// A librnp FFI call returned a non-success status code.
    /// Carries the failing operation, the raw `rnp_result_t` code and the
    /// human-readable description from `rnp_result_to_string()`.
    case ffiFailed(operation: String, code: UInt32, message: String)

    /// A key matching the requested identifier was not found in the keyrings.
    case keyNotFound(type: KeyIdentifierType, identifier: String)

    /// A Swift-side argument was invalid (e.g. empty data, which librnp
    /// cannot accept as an input buffer).
    case invalidArgument(String)
}

extension RnpError: CustomStringConvertible {
    public var description: String {
        switch self {
        case let .ffiFailed(operation, code, message):
            return "librnp \(operation) failed (\(code)): \(message)"
        case let .keyNotFound(type, identifier):
            return "key not found (\(type.rawValue): \(identifier))"
        case let .invalidArgument(reason):
            return "invalid argument: \(reason)"
        }
    }
}

extension RnpError: LocalizedError {
    public var errorDescription: String? {
        description
    }
}

/// `RNP_SUCCESS` from rnp_err.h. The librnp error codes live in an anonymous
/// C enum, which the Swift importer does not surface, hence the literal.
internal let rnpStatusSuccess: rnp_result_t = 0

/// Checks an `rnp_result_t` status and throws `RnpError.ffiFailed` on failure.
///
/// - Parameters:
///   - status: status code returned by a librnp FFI function.
///   - operation: short name of the operation, used in the thrown error.
internal func rnpCheck(_ status: rnp_result_t, operation: String) throws {
    guard status == rnpStatusSuccess else {
        throw RnpError.ffiFailed(
            operation: operation,
            code: status,
            message: String(cString: rnp_result_to_string(status))
        )
    }
}

/// Takes ownership of a NUL-terminated string buffer returned by librnp,
/// converts it to a Swift `String` and releases it with `rnp_buffer_destroy`.
internal func rnpTakeString(_ ptr: UnsafeMutablePointer<CChar>?, operation: String) throws -> String {
    guard let ptr else {
        throw RnpError.ffiFailed(
            operation: operation,
            code: rnpStatusSuccess,
            message: "unexpected NULL result buffer"
        )
    }
    defer { rnp_buffer_destroy(ptr) }
    return String(cString: ptr)
}

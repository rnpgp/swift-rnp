//
//  Rnp+ExperimentalFeatureDetection.swift
//  Rnp
//
//  Runtime detection of librnp's experimental APIs. The PKESK v6 and
//  PQC functions are gated on `RNP_EXPERIMENTAL_CRYPTO_REFRESH` and
//  `RNP_EXPERIMENTAL_PQC` macros at build time; not all librnp builds
//  enable them. We probe with `dlsym` at startup and expose the
//  function pointers via `ExperimentalSymbolTable`, so callers can
//  invoke the APIs only when present.
//

import CRnp
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation

/// Function-pointer type matching `rnp_op_encrypt_enable_pkesk_v6`.
public typealias EnablePKESKv6Fn = @convention(c) (rnp_op_encrypt_t) -> rnp_result_t

/// Function-pointer type matching `rnp_op_generate_set_v6_key`.
public typealias SetV6KeyFn = @convention(c) (rnp_op_generate_t) -> rnp_result_t

/// Function-pointer table populated at startup from `dlsym`. Each
/// property is `nil` when the linked librnp does not export the symbol.
public enum ExperimentalSymbolTable {
    /// `rnp_op_encrypt_enable_pkesk_v6` — present when the build has
    /// `RNP_EXPERIMENTAL_CRYPTO_REFRESH` enabled.
    public static let enablePKESKv6: EnablePKESKv6Fn? = lookup(
        "rnp_op_encrypt_enable_pkesk_v6"
    )

    /// `rnp_op_generate_set_v6_key` — present when the build has
    /// `RNP_EXPERIMENTAL_CRYPTO_REFRESH` enabled.
    public static let setV6Key: SetV6KeyFn? = lookup(
        "rnp_op_generate_set_v6_key"
    )

    private static func lookup<T>(_ name: String) -> T? {
        guard let handle = dlopen(nil, RTLD_NOW) else { return nil }
        guard let raw = dlsym(handle, name) else { return nil }
        return unsafeBitCast(raw, to: T.self)
    }
}

public extension Rnp {
    /// True when the linked librnp exports PKESK v6 support.
    static var supportsPKESKv6: Bool { ExperimentalSymbolTable.enablePKESKv6 != nil }

    /// True when the linked librnp exports v6 key-generation support.
    static var supportsV6Keygen: Bool { ExperimentalSymbolTable.setV6Key != nil }
}

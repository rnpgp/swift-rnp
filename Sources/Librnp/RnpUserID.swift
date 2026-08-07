//
//  RnpUserID.swift
//  Rnp
//
//  RAII wrapper around `rnp_uid_handle_t`. Released on deinit.
//

import CRnp
import Foundation

/// Wrapper around a librnp user-ID handle. Obtain via
/// `RnpKey.userID(at:)`. The handle is released on deinit.
public final class RnpUserID {
    let handle: rnp_uid_handle_t

    init(handle: rnp_uid_handle_t) {
        self.handle = handle
    }

    deinit {
        rnp_uid_handle_destroy(handle)
    }
}

public extension RnpKey {
    /// Returns the user-ID handle at `index`, or `nil` if the index is
    /// out of range.
    func userID(at index: Int) throws -> RnpUserID? {
        var uidHandle: rnp_uid_handle_t?
        let status = rnp_key_get_uid_handle_at(handle, index, &uidHandle)
        guard status == rnpStatusSuccess else {
            return nil
        }
        guard let uidHandle else { return nil }
        return RnpUserID(handle: uidHandle)
    }

    /// All user-ID handles on this key. Named `userIDHandles` to avoid
    /// colliding with the existing string-typed `userIDs` accessor.
    var userIDHandles: [RnpUserID] {
        get throws {
            var result: [RnpUserID] = []
            var index = 0
            while let uid = try userID(at: index) {
                result.append(uid)
                index += 1
            }
            return result
        }
    }
}

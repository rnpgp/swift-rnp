//
//  main.swift
//  RnpDemo
//
//  CLI smoke test of the Rnp Swift package: prints the librnp version and
//  runs a generate/encrypt/decrypt roundtrip. Run via: swift run RnpDemo
//

import Foundation
import Librnp

print("librnp \(Rnp.versionStringFull)")

do {
    let rnp = try Rnp(password: "password")
    let userID = "RnpDemo <demo@example.com>"
    try rnp.generateKey(json: Rnp.rsaKeyGenJSON(userid: userID))
    let key = try rnp.requireKey(userID)
    print("generated RSA key: \(try key.fingerprint)")

    let message = Data("What a day!".utf8)
    let encrypted = try rnp.encrypt(message, for: [key])
    let decrypted = try rnp.decrypt(encrypted)
    guard decrypted == message else {
        fputs("roundtrip mismatch\n", stderr)
        exit(1)
    }
    print("encrypt/decrypt roundtrip OK: \(String(decoding: decrypted, as: UTF8.self))")
} catch {
    fputs("error: \(error.localizedDescription)\n", stderr)
    exit(1)
}

# swift-rnp

Swift bindings for [librnp](https://github.com/rnpgp/rnp), the open-source OpenPGP library.

## Targets

| Target | Purpose |
|---|---|
| `Rnp` | FFI wrapper around librnp. Generate keys, encrypt/decrypt, sign/verify, export formats (paperkey, Autocrypt, v6 PKESK), PQC hybrids. |
| `CRnp` | system-library wrapper that finds librnp via pkg-config. |
| `PostQuantum` | Catalog of post-quantum algorithms exposed by librnp (ML-KEM, ML-DSA, SLH-DSA). |
| `Autocrypt` | Level 1 + 1.1 (Gossip) header parse/emit, per-account prefer-encrypt policy. |
| `KeyStateStore` | Tamper-evident signed-JSON persistence for key state. |
| `TrustStore` | Trust database with Ed25519-signed records. |
| `KeyServerClient` | WKD / VKS / HKP discovery and publish. |
| `MailSecurityEngine` | Compose policy, BCC handling, decryption-failure taxonomy, mailbox scan, recovery actions, offline publish queue. |
| `KeyLifecycle` | Key rotation, expiry extension, transition certifications. |
| `RnpMailUI` | SwiftUI views + view models shared by any RNP-based mail client. |
| `MailSecurityUI` | SwiftUI banner components for security-state display. |

## Usage

```swift
// Package.swift
.package(url: "https://github.com/rnpgp/swift-rnp", from: "0.1.0")

// In your target:
import Rnp

let rnp = try Rnp(password: "keyring-passphrase")
try rnp.generateKey(json: Rnp.rsaKeyGenJSON(userid: "alice@example.com"))
let encrypted = try rnp.encrypt(plaintext, for: [key])
let decrypted = try rnp.decrypt(encrypted)
```

## Building

Requires `librnp` available on the system:

```
brew install rnp        # macOS
apt install librnp-dev  # Debian/Ubuntu
```

Then:

```
swift build
swift test
```

The `MailSecurityEngine` target uses the experimental librnp APIs (PQC, v6 PKESK, AEAD-OCB). These are gated behind `RNP_EXPERIMENTAL_CRYPTO_REFRESH` and `RNP_EXPERIMENTAL_PQC` macros in `Sources/CRnp/shim.h` and detected at runtime via `dlsym`.

## Vendored framework

The Mail.app extension that consumes this library needs `RNPFramework.xcframework` (a static framework built from librnp sources). Build it with:

```
./scripts/build-rnp-framework.sh
```

The script clones librnp at the version pinned in `Vendor/SOURCES.md`, builds it for macOS (arm64 + x86_64), and emits the xcframework into `Vendor/RNPFramework.xcframework`.

## License

BSD-2-Clause, same as librnp.

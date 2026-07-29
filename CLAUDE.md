# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Swift bindings over [librnp](https://github.com/rnpgp/rnp) (OpenPGP). The package composes a low-level FFI wrapper with higher-level mail-security targets (key lifecycle, trust, Autocrypt, keyserver discovery, post-quantum hybrids, SwiftUI components) intended for consumption by a Mail.app extension.

## Common commands

```bash
swift build                              # build all targets
swift test                               # run all tests
swift test --filter RnpTests             # run one test target
swift test --filter RnpTests/RnpKeyGen   # run one test case
swift run RnpDemo                        # smoke-test the FFI wrapper

./scripts/build-rnp-framework.sh                            # CI/release: full source build
USE_PREFIX=/path/to/prefix ./scripts/build-rnp-framework.sh # dev fast path (prebuilt static libs)
```

`swift build` requires either (a) `librnp` discoverable via pkg-config (e.g. `brew install rnp`) **or** (b) the binary `RNPFramework.xcframework` target in `Package.swift` resolving from GitHub Releases. The Mail.app extension consumer requires (b).

## Architecture

### Three-layer FFI chain

`Sources/Rnp` (Swift API) → `Sources/CRnp` (system-module wrapper around `shim.h`) → `RNPFramework` (binary xcframework, fetched from `releases/download/v<ver>/RNPFramework.xcframework.zip`).

- `Sources/CRnp/module.modulemap` exposes `shim.h` as the umbrella header. `shim.h` includes `<rnp/rnp.h>` when present, otherwise falls back to the vendored copies in `Sources/CRnp/rnp/` (used when building from Xcode without pkg-config).
- `Sources/CRnp/dummy.c` exists so SwiftPM's link phase produces `CRnp.o`; do not remove it.
- Bumping the vendored framework means updating **both** the `url` and `checksum` in `Package.swift`, then cutting a release with the matching `v<ver>` tag.

### Experimental librnp APIs

`shim.h` defines `RNP_EXPERIMENTAL_CRYPTO_REFRESH` (PKESK v6 / SEIPDv2) and `RNP_EXPERIMENTAL_PQC` (ML-KEM, ML-DSA, SLH-DSA hybrids) before including `rnp.h`. The macros only gate C-declaration visibility; the underlying librnp build already implements the APIs. Swift callers additionally probe via `dlsym` at runtime (see `Rnp+ExperimentalFeatureDetection.swift`) before invoking PQC/v6 entry points.

### Framework build paths

`scripts/build-rnp-framework.sh` has two modes:

- **Fast path** (`USE_PREFIX` set): assemble a framework from a local prefix with prebuilt `librnp.a`, `libsexpp.a`, plus Homebrew `botan` and `json-c`. For iterative local dev only.
- **Full source build** (default; used by `framework.yml` CI): download pinned tarballs of `rnp`, `Botan`, `json-c`, and the `sexpp` submodule at the refs in `Vendor/SOURCES.md`. Build each as a per-arch static lib for `arm64` and `x86_64`, `lipo` into fat libs, then link a single universal dylib with `-Wl,-exported_symbols_list` set to `rnp/src/lib/librnp.symbols` so Botan/json-c/sexpp internals stay private while the FFI surface is re-exported.

Critical details that are easy to break:
- rnp forces `CXX_VISIBILITY_PRESET hidden` for static builds; the script rewrites it to `default` so FFI symbols re-export. Do not "tidy up" that `sed`.
- Cross-compiling Botan for `x86_64` on Apple Silicon requires the wrapper-script trick in `build_botan()`; the compiler probe otherwise selects the host arch.
- The framework is `codesign --sign -` ad-hoc; pass `SIGN_IDENTITY` to sign with a Developer ID.
- After building, the script writes `Vendor/pkgconfig/librnp.pc` pointing at the concrete xcframework slice so SwiftPM/Xcode can resolve it without `brew install rnp`.

### Higher-level targets

`MailSecurityEngine` is the integration kernel — it depends on `Rnp`, `KeyServerClient`, `TrustStore`, `KeyStateStore`, `Autocrypt`, and `PostQuantum`. `KeyLifecycle` and the SwiftUI targets (`RnpMailUI`, `MailSecurityUI`) sit on top. Keep the dependency graph acyclic and avoid introducing reverse edges back into `Rnp` from leaf targets.

## CI

| Workflow | Purpose |
|---|---|
| `framework.yml` | Build `RNPFramework.xcframework` from source on `macos-14`, verify it imports from Swift. Triggered on changes to the build script, `Vendor/SOURCES.md`, or the workflow itself. |
| `test.yml` | Build librnp from source against Homebrew's OpenSSL backend, then `swift build` / `swift test` against a matrix of rnp versions. |
| `release.yml` | `workflow_dispatch`-driven one-click tag + GitHub Release cutter. Pushing a tag re-triggers it but the `if:` skips the bot actor so the release isn't created twice. |

CI runners ship `aws/tap` pre-tapped but untrusted, which makes `brew install` fail. Both macOS workflows run `brew untap aws/tap 2>/dev/null || true` before any `brew install` to clear this.

The `v*` tag is the release boundary: `Package.swift` points at `releases/download/v0.1.0/...` — never push tags yourself (the user owns that step) and never modify the binary-target URL without a matching release existing.

## Constraints

- **macOS only.** SwiftPM targets macOS 14+; the framework's deployment target is 12.0.
- **No source files in `Vendor/` other than `SOURCES.md`.** The xcframework is gitignored; it's either built locally or fetched as a binary target.
- **`Vendor/SOURCES.md` is the source of truth for pinned dependency versions.** When bumping anything, update that table (and the corresponding `*.sha256` file under `scripts/`) — the build script verifies hashes.

# CONTEXT.md — swift-rnp domain language

This file records the names this project uses for domain concepts, so that
code, docs, and future architecture reviews stay coherent. Update lazily
when a concept is introduced, sharpened, or renamed.

## Key storage and lookup

### KeyringStore

Owns an OpenPGP keyring's persistence: the `Rnp` FFI context (exported by the `Librnp` module), the
recursive lock serializing access to it, the on-disk keyring files
(`pubring.gpg` / `secring.gpg`), the `TrustStore`, and the per-key
usage-state `KeyStateStore`.

Lives in its own SwiftPM target (`Sources/KeyringStore/`) so that
crypto-shaped callers (KeyLifecycle, KeyTransition) can depend on it
without dragging in all of MailSecurityEngine. MailSecurityEngine
`@_exported`-imports it, so existing callers that do
`import MailSecurityEngine` keep seeing `KeyInfo`, `SubkeyInfo`,
`KeyAlgorithm`, etc. without code changes.

All mutating operations on the keyring — generation, import/export,
deletion, foreign-passphrase handling, usage-state transitions — live
here. Crypto call sites that need the live `Rnp` context reach it via
`KeyringStore.withRnp { rnp in ... }`.

Replaces the persistence half of the former `KeyManager` god-object.

### KeyResolver

Read-only key lookup and recipient resolution layered on top of a
`KeyringStore`. Lives in the `KeyringStore` target.

Holds a reference to the store and acquires its lock internally —
callers do not need to. Lookup methods (`publicKey(for:)`,
`secretKey(forUserID:)`, `activeSigningKey(forUserID:)`,
`resolveActiveRecipients(addresses:)`) live here. UI and
compose-diagnostics callers should depend on `KeyResolver`, not on
`KeyringStore`, so they don't drag in the mutating API.

Replaces the lookup half of the former `KeyManager`.

### KeyManager (deprecated)

Source-compatibility façade from before the split. Lives in
`MailSecurityEngine`, holds a `KeyringStore` and a `KeyResolver`, and
forwards every method to the appropriate one. New code should depend
on the underlying types directly.

## Lifecycle

### KeyLifecycle

Pure key-lifecycle operations: rotation, expiry extension,
revocation. Lives in its own SwiftPM target
(`Sources/KeyLifecycle/KeyLifecycle.swift`) and depends only on
`KeyringStore` + `Librnp`. No MailSecurityEngine dependency, which is
what allows MailSecurityEngine to call into it (e.g. for
`MessageSecurityCore.extendRecipientKeyExpiry`) without a circular
import.

### KeyTransition

Multi-step key-transition orchestrator (generate new, copy UIDs,
certify, revoke old, archive). Lives in `MailSecurityEngine`
(not the KeyLifecycle target) because it depends on
`OfflinePublishQueue`, which is a MailSecurityEngine concern. The
crypto primitives it uses come from `KeyringStore`.

## Other domain concepts (pre-existing)

- **MailSecurityEngine** — the OpenPGP encode/decode engine. Holds a
  `KeyringStore` (currently exposed as the deprecated `KeyManager`
  façade), an Autocrypt observation store, and the encode/decode entry
  points. `@_exported import KeyringStore` re-exports KeyringStore's
  public types through this module.
- **TrustStore** — per-email trust state (verified / unverified /
  conflict) backed by an Ed25519-signed JSON database.
- **KeyStateStore** — per-fingerprint usage state (active / archived)
  backed by a tamper-evident signed-JSON store.
- **Autocrypt** — Level 1 + 1.1 (Gossip) header parse/emit and
  per-account prefer-encrypt policy.
- **PostQuantum** — catalog of post-quantum algorithms exposed by
  librnp (ML-KEM, ML-DSA, SLH-DSA).
- **KeyServerClient** — WKD / VKS / HKP key discovery and publish.
- **Librnp** — Swift FFI wrapper around librnp. Owns the `rnp_ffi_t`
  handle. Exports the `Rnp` type plus key/verification types.

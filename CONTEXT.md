# CONTEXT.md — swift-rnp domain language

This file records the names this project uses for domain concepts, so that
code, docs, and future architecture reviews stay coherent. Update lazily
when a concept is introduced, sharpened, or renamed.

## Key storage and lookup

### KeyringStore

Owns an OpenPGP keyring's persistence: the `Rnp` FFI context, the
recursive lock serializing access to it, the on-disk keyring files
(`pubring.gpg` / `secring.gpg`), the `TrustStore`, and the per-key
usage-state `KeyStateStore`.

All mutating operations on the keyring — generation, import/export,
deletion, foreign-passphrase handling, usage-state transitions — live
here. Crypto call sites that need the live `Rnp` context reach it via
`KeyringStore.withRnp { rnp in ... }`.

Replaces the persistence half of the former `KeyManager` god-object.

### KeyResolver

Read-only key lookup and recipient resolution layered on top of a
`KeyringStore`. Holds a reference to the store and acquires its lock
internally — callers do not need to.

Lookup methods (`publicKey(for:)`, `secretKey(forUserID:)`,
`activeSigningKey(forUserID:)`, `resolveActiveRecipients(addresses:)`)
live here. UI and compose-diagnostics callers should depend on
`KeyResolver`, not `KeyringStore`, so they don't drag in the mutating
API.

Replaces the lookup half of the former `KeyManager`.

### KeyManager (deprecated)

Source-compatibility façade from before the split. Holds a
`KeyringStore` and a `KeyResolver` and forwards every method to the
appropriate one. New code should depend on the underlying types
directly.

## Other domain concepts (pre-existing)

- **MailSecurityEngine** — the OpenPGP encode/decode engine. Holds a
  `KeyringStore` (currently exposed as the deprecated `KeyManager`
  façade), an Autocrypt observation store, and the encode/decode entry
  points.
- **TrustStore** — per-email trust state (verified / unverified /
  conflict) backed by an Ed25519-signed JSON database.
- **KeyStateStore** — per-fingerprint usage state (active / archived)
  backed by a tamper-evident signed-JSON store.
- **KeyLifecycle** — key rotation, expiry extension, revocation,
  transition certifications. Depends on `MailSecurityEngine` (currently
  creates a circular-dependency workaround that Card 4 of the
  architecture review removes).
- **Autocrypt** — Level 1 + 1.1 (Gossip) header parse/emit and
  per-account prefer-encrypt policy.
- **PostQuantum** — catalog of post-quantum algorithms exposed by
  librnp (ML-KEM, ML-DSA, SLH-DSA).
- **KeyServerClient** — WKD / VKS / HKP key discovery and publish.
- **Rnp** — Swift FFI wrapper around librnp. Owns the `rnp_ffi_t`
  handle.

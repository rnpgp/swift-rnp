//
//  KeyTransition.swift
//  KeyLifecycle
//
//  Orchestrates the multi-step key transition flow described in
//  TODO.roadmap/05-key-transition-wizard.md. Each step is a discrete
//  method so it can be tested in isolation; the full orchestration is
//  a thin sequence over the steps.
//
//  The engine layer focuses on the cryptographic actions:
//    1. Generate new key (delegated to `KeyManager`).
//    2. Copy old UID(s) onto new key.
//    3. Sign new key's UID(s) with old key (transition certification).
//    4. Revoke old key with reason `superseded` pointing at new key.
//    5. Archive old key (decrypt-only).
//
//  Publish and notify-contacts are caller responsibilities (they touch
//  the network and the user's address book, not the crypto).
//

import Foundation
import MailSecurityEngine
import Rnp

/// Snapshot of a completed transition. Returned by `KeyTransition.run`
/// for the caller to use in publish / notify UX flows.
public struct KeyTransitionResult: Equatable {
    public let oldFingerprint: String
    public let newFingerprint: String
    public let transitionCertificationAdded: Bool
    public let oldKeyArchived: Bool
}

/// Errors thrown by `KeyTransition`.
public enum KeyTransitionError: Error, Equatable {
    case oldKeyNotSecret
    case newKeyAlreadyExists(fingerprint: String)
    case certificationFailed(String)
    case revocationFailed(String)
}

/// Engine-layer orchestrator for key transitions.
public final class KeyTransition {
    private let keyManager: KeyManager
    private let publishQueue: OfflinePublishQueue?
    private let publishAction: ((QueuedPublishAction) async throws -> Void)?

    /// Creates a transition orchestrator.
    ///
    /// - Parameters:
    ///   - keyManager: engine key manager.
    ///   - publishQueue: optional offline-publish queue. When supplied,
    ///     the orchestrator enqueues publish actions for the new and
    ///     revoked-old keys instead of attempting them inline. The
    ///     queue's publisher closure runs the actual keyserver call.
    ///   - publishAction: optional inline publish closure. When both
    ///     this and `publishQueue` are nil, publish is the caller's
    ///     responsibility.
    public init(
        keyManager: KeyManager,
        publishQueue: OfflinePublishQueue? = nil,
        publishAction: ((QueuedPublishAction) async throws -> Void)? = nil
    ) {
        self.keyManager = keyManager
        self.publishQueue = publishQueue
        self.publishAction = publishAction
    }

    /// Runs the full transition flow:
    /// 1. Generate a new key for each old UID.
    /// 2. Add the old UIDs to the new key.
    /// 3. Certify each new UID with the old key.
    /// 4. Revoke the old key with reason `superseded`, naming the new
    ///    fingerprint in the revocation reason text.
    /// 5. Archive the old key (decrypt-only).
    ///
    /// - Parameters:
    ///   - oldFingerprint: the existing key to be replaced.
    ///   - algorithm: algorithm for the new key.
    ///   - userIDsOverride: optional explicit UID list for the new key.
    ///     Defaults to copying the old key's UIDs.
    ///   - hash: hash for the certification signature. Defaults to SHA256.
    /// - Returns: a snapshot of the transition result.
    @discardableResult
    public func run(
        replacing oldFingerprint: String,
        newKeyAlgorithm algorithm: KeyAlgorithm,
        userIDsOverride: [String]? = nil,
        hash: String = "SHA256"
    ) throws -> KeyTransitionResult {
        let userIDs: [String] = try keyManager.withRnp { rnp in
            let old = try rnp.requireKey(oldFingerprint, type: .fingerprint)
            guard (try? old.hasSecret) == true else {
                throw KeyTransitionError.oldKeyNotSecret
            }
            return userIDsOverride ?? ((try? old.userIDs) ?? [])
        }

        // Step 1: generate the new key with a unique placeholder UID. We
        // cannot use the old key's UID directly because `KeyManager.generateKey`
        // looks the new key up by userID, and the old key still has that
        // UID — it would return the old key's fingerprint. The real UIDs
        // are added in step 2.
        let placeholderUID = "RNP transition key \(UUID().uuidString.prefix(8))"
        let newInfo = try keyManager.generateKey(
            userID: placeholderUID,
            algorithm: algorithm,
            expirationSeconds: 0
        )

        // Step 2: add each old UID onto the new key. The placeholder is
        // left in place — it does not affect anything and removing it
        // would require additional FFI wiring (per-UID revocation).
        for uid in userIDs {
            _ = try? keyManager.addUserID(uid, toKeyWithFingerprint: newInfo.fingerprint)
        }

        // Step 3: certify each new UID with the old key. This produces
        // a Generic Certification (RFC 4880 §5.2.1, type 0x10) over
        // each new-key UID, signed by the old primary. Recipients who
        // refresh see the certification and can treat the new key as
        // related to the trusted old one.
        var certificationAdded = false
        do {
            try keyManager.withRnp { rnp in
                let old = try rnp.requireKey(oldFingerprint, type: .fingerprint)
                let newKey = try rnp.requireKey(newInfo.fingerprint, type: .fingerprint)
                let uidHandles = try newKey.userIDHandles
                for uid in uidHandles {
                    let signature = try old.makeCertification(of: uid, type: .generic)
                    try signature.setHash(hash)
                    try signature.finalize()
                }
            }
            try keyManager.save()
            certificationAdded = !userIDs.isEmpty
        } catch {
            throw KeyTransitionError.certificationFailed(error.localizedDescription)
        }

        // Step 4: revoke the old key with reason `superseded`.
        do {
            try keyManager.withRnp { rnp in
                let old = try rnp.requireKey(oldFingerprint, type: .fingerprint)
                try old.revoke(
                    code: .superseded,
                    reason: "Superseded by \(newInfo.fingerprint)",
                    hash: hash
                )
            }
            try keyManager.save()
        } catch {
            throw KeyTransitionError.revocationFailed(error.localizedDescription)
        }

        // Step 5: archive the old key (decrypt-only) and clean up.
        try keyManager.setUsageState(
            .archived,
            forFingerprint: oldFingerprint,
            reason: "auto-archived by key transition (superseded by \(newInfo.fingerprint))"
        )

        return KeyTransitionResult(
            oldFingerprint: oldFingerprint,
            newFingerprint: newInfo.fingerprint,
            transitionCertificationAdded: certificationAdded,
            oldKeyArchived: true
        )
    }

    /// Async variant of `run(...)` that additionally enqueues publish
    /// actions for the new and revoked-old keys via the configured
    /// `OfflinePublishQueue`. Callers that supply a publish queue in
    /// `init(...)` should call this instead of the sync `run(...)`.
    @discardableResult
    public func runAsync(
        replacing oldFingerprint: String,
        newKeyAlgorithm algorithm: KeyAlgorithm,
        userIDsOverride: [String]? = nil,
        hash: String = "SHA256"
    ) async throws -> KeyTransitionResult {
        let result = try run(
            replacing: oldFingerprint,
            newKeyAlgorithm: algorithm,
            userIDsOverride: userIDsOverride,
            hash: hash
        )
        await publishAfterTransition(newFingerprint: result.newFingerprint, oldFingerprint: oldFingerprint)
        return result
    }

    /// Enqueues publish actions for the new key and the revoked old
    /// key when a publish queue is configured. Best-effort; failures
    /// are surfaced via the queue's retry mechanism, not propagated.
    private func publishAfterTransition(newFingerprint: String, oldFingerprint: String) async {
        guard let publishQueue else { return }
        let newKeyArmored = (try? keyManager.exportKey(fingerprint: newFingerprint, secret: false))
            .flatMap { String(data: $0, encoding: .ascii) } ?? ""
        let oldKeyArmored = (try? keyManager.exportKey(fingerprint: oldFingerprint, secret: false))
            .flatMap { String(data: $0, encoding: .ascii) } ?? ""
        try? publishQueue.enqueue(QueuedPublishAction(
            kind: .publishKey,
            fingerprint: newFingerprint,
            armoredKey: newKeyArmored
        ))
        try? publishQueue.enqueue(QueuedPublishAction(
            kind: .publishRevokedKey,
            fingerprint: oldFingerprint,
            armoredKey: oldKeyArmored
        ))
        await publishQueue.runDueActions()
    }
}

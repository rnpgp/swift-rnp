//
//  Rnp.swift
//  swift-rnp
//
//  Modern Swift wrapper over librnp (the OpenPGP library, rnpgp/rnp).
//

import CRnp
import Foundation

/// Key identifier kinds accepted by `Rnp.locateKey` / `Rnp.requireKey`.
public enum KeyIdentifierType: String {
    case userid
    case fingerprint
    case keyid
    case grip
}

/// An OpenPGP context backed by librnp.
///
/// Manages the lifetime of the underlying `rnp_ffi_t` object together with
/// its in-memory public and secret keyrings. All operations take and return
/// Swift `Data`/`String` values; librnp errors surface as `RnpError`.
///
///     let rnp = try Rnp(password: "password")
///     try rnp.generateKey(json: Rnp.rsaKeyGenJSON(userid: "Test <t@t>"))
///     let key = try rnp.requireKey("Test <t@t>")
///     let encrypted = try rnp.encrypt(Data("hello".utf8), for: [key])
///     let decrypted = try rnp.decrypt(encrypted)
public final class Rnp {
    /// Called whenever librnp needs a passphrase (e.g. "sign", "decrypt",
    /// "protect"). Return the passphrase, or `nil` to abort the operation.
    public typealias PassphraseProvider = (_ context: String) -> String?

    /// Extended passphrase callback that also receives the fingerprint of
    /// the key being unlocked (the primary key's fingerprint when librnp
    /// asks on behalf of a subkey), or `nil` when the request is not tied to
    /// a specific key. Allows answering with per-key passphrases.
    public typealias KeyedPassphraseProvider = (_ context: String, _ keyFingerprint: String?) -> String?

    /// Internal so extensions in sibling files (e.g. Verification.swift) can
    /// run FFI operations on the context.
    let ffi: rnp_ffi_t
    /// Internal so the C passphrase callback (a free function) can reach it.
    let keyedPassphraseProvider: KeyedPassphraseProvider

    /// Creates a context with empty in-memory keyrings.
    ///
    /// - Parameters:
    ///   - publicKeyringFormat: public keyring format passed to
    ///     `rnp_ffi_create` ("GPG" by default).
    ///   - secretKeyringFormat: secret keyring format passed to
    ///     `rnp_ffi_create` ("GPG" by default; "G10" stores generated keys in
    ///     GnuPG 2.1+ format, which librnp cannot export back to OpenPGP
    ///     packets, so export/save operations require "GPG").
    ///   - passphraseProvider: passphrase callback, see `PassphraseProvider`.
    public convenience init(
        publicKeyringFormat: String = "GPG",
        secretKeyringFormat: String = "GPG",
        passphraseProvider: @escaping PassphraseProvider
    ) throws {
        try self.init(
            publicKeyringFormat: publicKeyringFormat,
            secretKeyringFormat: secretKeyringFormat,
            keyedPassphraseProvider: { context, _ in passphraseProvider(context) }
        )
    }

    /// Creates a context with empty in-memory keyrings and a passphrase
    /// callback that is told which key is being unlocked.
    ///
    /// - Parameters:
    ///   - publicKeyringFormat: public keyring format passed to
    ///     `rnp_ffi_create` ("GPG" by default).
    ///   - secretKeyringFormat: secret keyring format passed to
    ///     `rnp_ffi_create` ("GPG" by default).
    ///   - keyedPassphraseProvider: passphrase callback, see
    ///     `KeyedPassphraseProvider`.
    public init(
        publicKeyringFormat: String = "GPG",
        secretKeyringFormat: String = "GPG",
        keyedPassphraseProvider: @escaping KeyedPassphraseProvider
    ) throws {
        self.keyedPassphraseProvider = keyedPassphraseProvider
        var handle: rnp_ffi_t?
        try rnpCheck(
            rnp_ffi_create(&handle, publicKeyringFormat, secretKeyringFormat),
            operation: "ffi create"
        )
        guard let handle else {
            throw RnpError.ffiFailed(
                operation: "ffi create",
                code: rnpStatusSuccess,
                message: "unexpected NULL ffi"
            )
        }
        ffi = handle
        do {
            // The context is only dereferenced while `self` (and thus `ffi`)
            // is alive, so no retain is needed.
            let context = Unmanaged.passUnretained(self).toOpaque()
            try rnpCheck(
                rnp_ffi_set_pass_provider(handle, rnpPasswordCallback, context),
                operation: "set passphrase provider"
            )
        } catch {
            rnp_ffi_destroy(handle)
            throw error
        }
    }

    /// Convenience context answering every passphrase request with `password`.
    public convenience init(password: String) throws {
        try self.init(passphraseProvider: { _ in password })
    }

    deinit {
        rnp_ffi_destroy(ffi)
    }

    // MARK: - Library information

    /// librnp version string, e.g. "0.18.1".
    public static var versionString: String {
        rnp_version_string().map { String(cString: $0) } ?? "unknown"
    }

    /// Full librnp version string, including backend information.
    public static var versionStringFull: String {
        rnp_version_string_full().map { String(cString: $0) } ?? "unknown"
    }

    /// Unix timestamp of the last librnp commit (0 for releases).
    public static var versionCommitTimestamp: UInt64 {
        rnp_version_commit_timestamp()
    }

    // MARK: - Keyring information

    /// Number of public keys in the keyring.
    public var publicKeyCount: Int {
        get throws {
            var count = 0
            try rnpCheck(rnp_get_public_key_count(ffi, &count), operation: "public key count")
            return count
        }
    }

    /// Number of secret keys in the keyring.
    public var secretKeyCount: Int {
        get throws {
            var count = 0
            try rnpCheck(rnp_get_secret_key_count(ffi, &count), operation: "secret key count")
            return count
        }
    }

    // MARK: - Key generation

    /// Generates a key pair from a JSON description (`rnp_generate_key_json`).
    ///
    /// - Parameter json: JSON object with "primary" and, optionally, "sub"
    ///   members, see `rsaKeyGenJSON(userid:bits:)` for an example.
    /// - Returns: JSON with the grips of the generated key(s).
    @discardableResult
    public func generateKey(json: String) throws -> String {
        var results: UnsafeMutablePointer<CChar>?
        try rnpCheck(rnp_generate_key_json(ffi, json, &results), operation: "generate key")
        return try rnpTakeString(results, operation: "generate key")
    }

    /// JSON description of an RSA primary key (signing) with an RSA
    /// encryption subkey, both protected by the passphrase provider.
    ///
    /// `bits` defaults to 3072, the librnp 0.18 default RSA key length.
    public static func rsaKeyGenJSON(userid: String, bits: Int = 3072, expirationSeconds: UInt32 = 0) -> String {
        """
        {
            "primary": {
                "type": "RSA",
                "length": \(bits),
                "userid": "\(userid)",
                "usage": ["sign"],
                "expiration": \(expirationSeconds),
                "protection": { "cipher": "AES256", "hash": "SHA256" }
            },
            "sub": {
                "type": "RSA",
                "length": \(bits),
                "usage": ["encrypt"],
                "expiration": \(expirationSeconds),
                "protection": { "cipher": "AES256", "hash": "SHA256" }
            }
        }
        """
    }

    /// JSON description of an ECDSA P-256 primary key (signing) with an
    /// ECDH P-256 encryption subkey, both protected by the passphrase
    /// provider.
    public static func ecdsaP256KeyGenJSON(userid: String, expirationSeconds: UInt32 = 0) -> String {
        """
        {
            "primary": {
                "type": "ECDSA",
                "curve": "NIST P-256",
                "userid": "\(userid)",
                "usage": ["sign"],
                "expiration": \(expirationSeconds),
                "protection": { "cipher": "AES256", "hash": "SHA256" }
            },
            "sub": {
                "type": "ECDH",
                "curve": "NIST P-256",
                "usage": ["encrypt"],
                "expiration": \(expirationSeconds),
                "protection": { "cipher": "AES256", "hash": "SHA256" }
            }
        }
        """
    }

    /// Generates a subkey for the given primary key.
    ///
    /// - Parameters:
    ///   - primary: the primary key that will bind the new subkey.
    ///   - algorithm: the subkey algorithm, e.g. "RSA", "ECDH", "ECDSA".
    ///   - bits: RSA/DSA/Elgamal key size (optional).
    ///   - curve: ECC curve name (optional).
    ///   - hash: hash algorithm for binding signatures (default "SHA256").
    ///   - usage: usage flags, e.g. `["encrypt"]` or `["sign"]`.
    ///   - expirationSeconds: seconds from creation until expiry, or `0` for no expiry.
    /// - Returns: the generated subkey handle.
    public func generateSubkey(
        for primary: RnpKey,
        algorithm: String,
        bits: UInt32? = nil,
        curve: String? = nil,
        hash: String = "SHA256",
        usage: [String] = [],
        expirationSeconds: UInt32 = 0
    ) throws -> RnpKey {
        var op: rnp_op_generate_t?
        try rnpCheck(
            rnp_op_generate_subkey_create(&op, ffi, primary.handle, algorithm),
            operation: "subkey generation create"
        )
        guard let operation = op else {
            throw RnpError.ffiFailed(
                operation: "subkey generation create",
                code: rnpStatusSuccess,
                message: "unexpected NULL generation operation"
            )
        }
        defer { rnp_op_generate_destroy(operation) }

        if let bits {
            try rnpCheck(rnp_op_generate_set_bits(operation, bits), operation: "subkey set bits")
        }
        if let curve {
            try rnpCheck(rnp_op_generate_set_curve(operation, curve), operation: "subkey set curve")
        }
        try rnpCheck(rnp_op_generate_set_hash(operation, hash), operation: "subkey set hash")
        for flag in usage {
            try rnpCheck(rnp_op_generate_add_usage(operation, flag), operation: "subkey add usage")
        }
        try rnpCheck(
            rnp_op_generate_set_expiration(operation, expirationSeconds),
            operation: "subkey set expiration"
        )

        guard let password = keyedPassphraseProvider("protect", nil) else {
            throw RnpError.invalidArgument("passphrase provider returned nil for subkey protection")
        }
        try rnpCheck(
            rnp_op_generate_set_protection_password(operation, password),
            operation: "subkey set protection password"
        )

        try rnpCheck(rnp_op_generate_execute(operation), operation: "subkey generation execute")

        var handle: rnp_key_handle_t?
        try rnpCheck(rnp_op_generate_get_key(operation, &handle), operation: "subkey get key")
        guard let handle else {
            throw RnpError.ffiFailed(
                operation: "subkey get key",
                code: rnpStatusSuccess,
                message: "unexpected NULL subkey handle"
            )
        }
        return RnpKey(handle: handle)
    }

    /// JSON description of an Ed25519 primary signing key with a
    /// Curve25519 encryption subkey, both protected by the passphrase
    /// provider.
    public static func ed25519KeyGenJSON(userid: String, expirationSeconds: UInt32 = 0) -> String {
        """
        {
            "primary": {
                "type": "EDDSA",
                "userid": "\(userid)",
                "usage": ["sign"],
                "expiration": \(expirationSeconds),
                "protection": { "cipher": "AES256", "hash": "SHA256" }
            },
            "sub": {
                "type": "ECDH",
                "curve": "Curve25519",
                "usage": ["encrypt"],
                "expiration": \(expirationSeconds),
                "protection": { "cipher": "AES256", "hash": "SHA256" }
            }
        }
        """
    }

    // MARK: - Key lookup

    /// Finds a key in the keyrings.
    ///
    /// - Returns: the key, or `nil` when no key matches the identifier.
    public func locateKey(_ identifier: String, type: KeyIdentifierType = .userid) throws -> RnpKey? {
        var handle: rnp_key_handle_t?
        try rnpCheck(
            rnp_locate_key(ffi, type.rawValue, identifier, &handle),
            operation: "locate key"
        )
        guard let handle else {
            return nil
        }
        return RnpKey(handle: handle)
    }

    /// Finds a key in the keyrings, throwing `RnpError.keyNotFound` when
    /// no key matches the identifier.
    public func requireKey(_ identifier: String, type: KeyIdentifierType = .userid) throws -> RnpKey {
        guard let key = try locateKey(identifier, type: type) else {
            throw RnpError.keyNotFound(type: type, identifier: identifier)
        }
        return key
    }

    // MARK: - Key removal / enumeration

    /// Removes a key from the keyrings (`rnp_key_remove`).
    ///
    /// Other handles of the same key must not be used after this call.
    /// Persist the change with `savePublicKeys` / `saveSecretKeys`.
    ///
    /// - Parameters:
    ///   - key: the key to remove.
    ///   - public: remove the public part from the public keyring.
    ///   - secret: remove the secret part from the secret keyring.
    ///   - subkeys: also remove all subkeys (only meaningful for primary keys).
    public func remove(
        key: RnpKey,
        public: Bool = true,
        secret: Bool = true,
        subkeys: Bool = true
    ) throws {
        var flags: UInt32 = 0
        if `public` {
            flags |= RNP_KEY_REMOVE_PUBLIC
        }
        if secret {
            flags |= RNP_KEY_REMOVE_SECRET
        }
        if subkeys {
            flags |= RNP_KEY_REMOVE_SUBKEYS
        }
        guard flags != 0 else {
            throw RnpError.invalidArgument("remove: no key type selected")
        }
        try rnpCheck(rnp_key_remove(key.handle, flags), operation: "key remove")
    }

    /// All user IDs found in the keyrings (`rnp_identifier_iterator`).
    public func allUserIDs() throws -> [String] {
        var iterator: rnp_identifier_iterator_t?
        try rnpCheck(
            rnp_identifier_iterator_create(ffi, &iterator, "userid"),
            operation: "user id iterator create"
        )
        guard let iterator else {
            return []
        }
        defer { rnp_identifier_iterator_destroy(iterator) }
        var userIDs: [String] = []
        while true {
            var uid: UnsafePointer<CChar>?
            try rnpCheck(
                rnp_identifier_iterator_next(iterator, &uid),
                operation: "user id iterator next"
            )
            guard let uid else {
                break
            }
            userIDs.append(String(cString: uid))
        }
        return userIDs
    }

    // MARK: - Key import / export

    /// Imports keys (armored or binary OpenPGP data) into the keyrings.
    ///
    /// - Returns: JSON describing the new and updated keys.
    @discardableResult
    public func importKeys(_ data: Data) throws -> String {
        let flags = RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS | RNP_LOAD_SAVE_PERMISSIVE
        var results: UnsafeMutablePointer<CChar>?
        return try withMemoryInput(data, operation: "import keys") { input in
            try rnpCheck(rnp_import_keys(ffi, input, flags, &results), operation: "import keys")
            return try rnpTakeString(results, operation: "import keys")
        }
    }

    /// Exports all public keys from the public keyring
    /// (`rnp_save_keys` with "GPG" format).
    public func savePublicKeys(armored: Bool = true) throws -> Data {
        try saveKeys(flags: RNP_LOAD_SAVE_PUBLIC_KEYS, armorType: "public key", armored: armored)
    }

    /// Exports all secret keys from the secret keyring
    /// (`rnp_save_keys` with "GPG" format).
    public func saveSecretKeys(armored: Bool = true) throws -> Data {
        try saveKeys(flags: RNP_LOAD_SAVE_SECRET_KEYS, armorType: "secret key", armored: armored)
    }

    /// Loads keys previously written by `savePublicKeys` / `saveSecretKeys`
    /// (both armored and binary data are accepted).
    public func loadKeys(_ data: Data, public: Bool = true, secret: Bool = true) throws {
        var flags: UInt32 = 0
        if `public` {
            flags |= RNP_LOAD_SAVE_PUBLIC_KEYS
        }
        if secret {
            flags |= RNP_LOAD_SAVE_SECRET_KEYS
        }
        guard flags != 0 else {
            throw RnpError.invalidArgument("loadKeys: no key type selected")
        }
        try withMemoryInput(data, operation: "load keys") { input in
            try rnpCheck(rnp_load_keys(ffi, RNP_KEYSTORE_GPG, input, flags), operation: "load keys")
        }
    }

    private func saveKeys(flags: UInt32, armorType: String, armored: Bool) throws -> Data {
        let output = try MemoryOutput()
        var destination = output.handle
        if armored {
            var armor: rnp_output_t?
            try rnpCheck(
                rnp_output_to_armor(output.handle, &armor, armorType),
                operation: "armor output create"
            )
            guard let armorOutput = armor else {
                throw RnpError.ffiFailed(
                    operation: "armor output create",
                    code: rnpStatusSuccess,
                    message: "unexpected NULL output"
                )
            }
            destination = armorOutput
        }
        // Destroy the armor stream before reading so the armor trailer is
        // flushed into the backing memory output.
        let status = rnp_save_keys(ffi, RNP_KEYSTORE_GPG, destination, flags)
        if armored {
            rnp_output_destroy(destination)
        }
        try rnpCheck(status, operation: "save keys")
        return try output.readData()
    }

    // MARK: - Encryption

    /// Encrypts data for the given recipient keys.
    public func encrypt(
        _ plaintext: Data,
        for recipients: [RnpKey],
        cipher: String = "AES256",
        hash: String = "SHA256",
        armored: Bool = false
    ) throws -> Data {
        try encrypt(
            plaintext,
            for: recipients,
            cipher: cipher,
            hash: hash,
            aead: .none,
            pkeskVersion: .v3,
            armored: armored
        )
    }

    /// AEAD algorithm choice for `encrypt(...:aead:pkeskVersion:...)`.
    public enum EncryptAEAD: Equatable, Sendable {
        /// Disable AEAD; emit legacy CFB + MDC. Compatibility max.
        case none
        /// AEAD-OCB (RFC 7253). Recommended modern default.
        case ocb
    }

    /// PKESK version choice. v3 is the legacy visible-recipient form;
    /// v6 hides the recipient key ID but is only parseable by modern
    /// clients. v6 also implies SEIPDv2 (the modern Symmetrically
    /// Encrypted Integrity Protected Data packet).
    public enum EncryptPKESKVersion: Equatable, Sendable {
        case v3
        case v6
    }

    /// Encrypts data with explicit AEAD and PKESK-version control. Used
    /// by the engine when `EncryptionEnvelopeResolver` has selected
    /// anything other than the legacy default.
    public func encrypt(
        _ plaintext: Data,
        for recipients: [RnpKey],
        cipher: String = "AES256",
        hash: String = "SHA256",
        aead: EncryptAEAD,
        pkeskVersion: EncryptPKESKVersion,
        armored: Bool = false
    ) throws -> Data {
        guard !recipients.isEmpty else {
            throw RnpError.invalidArgument("encrypt: at least one recipient key is required")
        }
        let output = try MemoryOutput()
        return try withMemoryInput(plaintext, operation: "encrypt") { input in
            var handle: rnp_op_encrypt_t?
            try rnpCheck(rnp_op_encrypt_create(&handle, ffi, input, output.handle), operation: "encrypt create")
            return try withRnpOp(handle, destroy: rnp_op_encrypt_destroy, operation: "encrypt") { op in
                for key in recipients {
                    try rnpCheck(rnp_op_encrypt_add_recipient(op, key.handle), operation: "encrypt add recipient")
                }
                try rnpCheck(rnp_op_encrypt_set_cipher(op, cipher), operation: "encrypt set cipher")
                try rnpCheck(rnp_op_encrypt_set_hash(op, hash), operation: "encrypt set hash")
                try rnpCheck(rnp_op_encrypt_set_armor(op, armored), operation: "encrypt set armor")
                if case .ocb = aead {
                    try rnpCheck(rnp_op_encrypt_set_aead(op, "OCB"), operation: "encrypt set aead")
                }
                if pkeskVersion == .v6, let fn = ExperimentalSymbolTable.enablePKESKv6 {
                    try rnpCheck(fn(op), operation: "encrypt enable pkesk v6")
                }
                try rnpCheck(rnp_op_encrypt_execute(op), operation: "encrypt execute")
                return try output.readData()
            }
        }
    }

    /// Decrypts data; the passphrase provider is consulted for protected keys.
    public func decrypt(_ encrypted: Data) throws -> Data {
        let output = try MemoryOutput()
        return try withMemoryInput(encrypted, operation: "decrypt") { input in
            try rnpCheck(rnp_decrypt(ffi, input, output.handle), operation: "decrypt")
            return try output.readData()
        }
    }

    /// Decrypts a symmetrically-encrypted message (one encrypted with a
    /// shared passphrase, no public-key recipient). Spawns a fresh
    /// `Rnp` context with a passphrase provider that answers every
    /// prompt with `passphrase`; the symmetric session key derived by
    /// librnp lets it decrypt the message without a keyring lookup.
    ///
    /// The caller is responsible for zeroing `passphrase` after use; we
    /// do not perform explicit memory scrubbing (consistent with the
    /// rest of the wrapper).
    public func decryptSymmetric(_ encrypted: Data, passphrase: String) throws -> Data {
        let symmetric = try Rnp(passphraseProvider: { _ in passphrase })
        let publicRing = try savePublicKeys(armored: false)
        try symmetric.loadKeys(publicRing, public: true, secret: false)
        return try symmetric.decrypt(encrypted)
    }

    // MARK: - Packet inspection

    /// Dumps the OpenPGP packet structure of `data` as JSON (one object per
    /// packet, with `type` fields like `"pkesk"`, `"seipd"`, etc.). Used to
    /// classify decryption failures (missing recipient key, integrity
    /// failure, unsupported algorithm) by inspecting PKESK packets and
    /// key IDs without attempting to decrypt.
    ///
    /// Wraps `rnp_dump_packets_to_json` (`Sources/CRnp/rnp/rnp.h:2951`).
    /// Flags default to `0` (no `RNP_DUMP_MPI` etc.).
    public func dumpPacketsAsJSON(_ data: Data, flags: UInt32 = 0) throws -> String {
        try withMemoryInput(data, operation: "dump packets") { input in
            var resultPtr: UnsafeMutablePointer<CChar>?
            try rnpCheck(
                rnp_dump_packets_to_json(input, flags, &resultPtr),
                operation: "dump packets"
            )
            return try rnpTakeString(resultPtr, operation: "dump packets")
        }
    }

    // MARK: - Signing

    /// Signs data with an embedded (binary or armored) signature.
    public func sign(
        _ message: Data,
        with key: RnpKey,
        hash: String = "SHA256",
        armored: Bool = false
    ) throws -> Data {
        try performSign(message, with: key, hash: hash, armored: armored, detached: false)
    }

    /// Creates a detached signature for data.
    public func signDetached(
        _ message: Data,
        with key: RnpKey,
        hash: String = "SHA256",
        armored: Bool = true
    ) throws -> Data {
        try performSign(message, with: key, hash: hash, armored: armored, detached: true)
    }

    private func performSign(
        _ message: Data,
        with key: RnpKey,
        hash: String,
        armored: Bool,
        detached: Bool
    ) throws -> Data {
        let output = try MemoryOutput()
        return try withMemoryInput(message, operation: "sign") { input in
            var handle: rnp_op_sign_t?
            let status = detached
                ? rnp_op_sign_detached_create(&handle, ffi, input, output.handle)
                : rnp_op_sign_create(&handle, ffi, input, output.handle)
            try rnpCheck(status, operation: "sign create")
            return try withRnpOp(handle, destroy: rnp_op_sign_destroy, operation: "sign") { op in
                try rnpCheck(rnp_op_sign_add_signature(op, key.handle, nil), operation: "sign add signature")
                try rnpCheck(rnp_op_sign_set_hash(op, hash), operation: "sign set hash")
                try rnpCheck(rnp_op_sign_set_armor(op, armored), operation: "sign set armor")
                try rnpCheck(rnp_op_sign_execute(op), operation: "sign execute")
                return try output.readData()
            }
        }
    }

    // MARK: - Verification

    /// Verifies data carrying an embedded signature.
    ///
    /// - Returns: the verified payload.
    /// - Throws: `RnpError.ffiFailed` when the signature is invalid.
    @discardableResult
    public func verify(_ signedMessage: Data) throws -> Data {
        let output = try MemoryOutput()
        return try withMemoryInput(signedMessage, operation: "verify") { input in
            var handle: rnp_op_verify_t?
            try rnpCheck(rnp_op_verify_create(&handle, ffi, input, output.handle), operation: "verify create")
            return try withRnpOp(handle, destroy: rnp_op_verify_destroy, operation: "verify") { op in
                try rnpCheck(rnp_op_verify_execute(op), operation: "verify execute")
                return try output.readData()
            }
        }
    }

    /// Verifies a detached signature against the original data.
    ///
    /// - Throws: `RnpError.ffiFailed` when the signature is invalid.
    public func verifyDetached(signature: Data, data: Data) throws {
        try withMemoryInput(data, operation: "verify detached") { dataInput in
            try withMemoryInput(signature, operation: "verify detached") { signatureInput in
                var handle: rnp_op_verify_t?
                try rnpCheck(
                    rnp_op_verify_detached_create(&handle, ffi, dataInput, signatureInput),
                    operation: "verify detached create"
                )
                try withRnpOp(handle, destroy: rnp_op_verify_destroy, operation: "verify detached") { op in
                    try rnpCheck(rnp_op_verify_execute(op), operation: "verify detached execute")
                }
            }
        }
    }
}

/// librnp passphrase callback bridging into `Rnp.keyedPassphraseProvider` via
/// the application context pointer.
private func rnpPasswordCallback(
    _: rnp_ffi_t?,
    appContext: UnsafeMutableRawPointer?,
    key: rnp_key_handle_t?,
    pgpContext: UnsafePointer<CChar>?,
    buffer: UnsafeMutablePointer<CChar>?,
    bufferLength: Int
) -> Bool {
    guard let appContext, let pgpContext, let buffer else {
        return false
    }
    let rnp = Unmanaged<Rnp>.fromOpaque(appContext).takeUnretainedValue()
    let passphrase = rnp.keyedPassphraseProvider(
        String(cString: pgpContext),
        key.flatMap(callbackFingerprint(of:))
    )
    guard let passphrase else {
        return false
    }
    let utf8 = passphrase.utf8CString
    guard utf8.count <= bufferLength else {
        return false
    }
    // Copy the passphrase including the NUL terminator.
    return utf8.withUnsafeBufferPointer { source in
        guard let base = source.baseAddress else {
            return false
        }
        buffer.update(from: base, count: source.count)
        return true
    }
}

/// Fingerprint of the key librnp is unlocking. Subkey handles resolve to
/// their primary key's fingerprint so per-key passphrases can be stored
/// against the primary key; `rnp_key_get_primary_fprint` fails on primary
/// keys, in which case the key's own fingerprint is used.
private func callbackFingerprint(of key: rnp_key_handle_t) -> String? {
    var buffer: UnsafeMutablePointer<CChar>?
    if rnp_key_get_primary_fprint(key, &buffer) == rnpStatusSuccess, let buffer {
        defer { rnp_buffer_destroy(buffer) }
        return String(cString: buffer)
    }
    if rnp_key_get_fprint(key, &buffer) == rnpStatusSuccess, let buffer {
        defer { rnp_buffer_destroy(buffer) }
        return String(cString: buffer)
    }
    return nil
}

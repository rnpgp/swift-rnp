//
//  EncryptionSettingsView.swift
//  RnpMailUI
//
//  Settings UI for the two engine policies that have user-visible
//  effect: the encryption envelope policy (automatic / force-aead /
//  force-legacy) and the Autocrypt prefer-encrypt policy.
//

import MailSecurityEngine
import SwiftUI

@MainActor
public final class EncryptionSettingsViewModel: ObservableObject {
    @Published public var envelopePolicy: EncryptionEnvelopePolicy {
        didSet { persist() }
    }
    @Published public var autocryptPreferEncrypt: AutocryptPolicyChoice {
        didSet { persist() }
    }
    @Published public var pqPolicy: PQPolicyChoice {
        didSet { persist() }
    }

    /// Storage closure; the container app wires this to UserDefaults
    /// or its preferences file.
    public typealias Storage = (
        _ envelope: EncryptionEnvelopePolicy,
        _ preferEncrypt: AutocryptPolicyChoice,
        _ pq: PQPolicyChoice
    ) -> Void

    private let storage: Storage

    public init(
        envelopePolicy: EncryptionEnvelopePolicy = .automatic,
        autocryptPreferEncrypt: AutocryptPolicyChoice = .mutual,
        pqPolicy: PQPolicyChoice = .classical,
        storage: @escaping Storage
    ) {
        self.envelopePolicy = envelopePolicy
        self.autocryptPreferEncrypt = autocryptPreferEncrypt
        self.pqPolicy = pqPolicy
        self.storage = storage
    }

    private func persist() {
        storage(envelopePolicy, autocryptPreferEncrypt, pqPolicy)
    }
}

/// Surfaced choice for Autocrypt prefer-encrypt (autocrypt-policy UI
/// mirrors the `AutocryptPreferEncrypt` enum but is more restrictive
/// because the container-app settings pane only shows the
/// user-facing options).
public enum AutocryptPolicyChoice: String, CaseIterable, Sendable {
    case mutual
    case nopreference
    case encrypt
    case disable

    public var label: String {
        switch self {
        case .mutual: return "Mutual (encrypt when both parties opt in)"
        case .nopreference: return "No preference"
        case .encrypt: return "Encrypt only (manual)"
        case .disable: return "Disable Autocrypt"
        }
    }
}

/// Surfaced choice for the post-quantum policy (UI mirrors the
/// `PostQuantumPolicy` enum from the PostQuantum target).
public enum PQPolicyChoice: String, CaseIterable, Sendable {
    case classical
    case hybrid
    case conservative

    public var label: String {
        switch self {
        case .classical: return "Classical (Ed25519, RSA, ECDSA)"
        case .hybrid: return "Hybrid PQ (ML-DSA-65+ED25519 / ML-KEM-768+X25519)"
        case .conservative: return "Conservative (SLH-DSA-SHA2; classical encryption)"
        }
    }
}

public struct EncryptionSettingsView: View {
    @StateObject public var viewModel: EncryptionSettingsViewModel

    public init(viewModel: EncryptionSettingsViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    public var body: some View {
        Form {
            Section(header: Text("Envelope"), footer: Text("AEAD-OCB is the modern OpenPGP authenticated-encryption mode; v6 PKESK hides the recipient key ID on the wire. Both require modern recipients.").font(.caption)) {
                Picker("Encryption envelope", selection: $viewModel.envelopePolicy) {
                    Text("Automatic (use AEAD/v6 when all recipients support it)")
                        .tag(EncryptionEnvelopePolicy.automatic)
                    Text("Force AEAD (refuse if any recipient lacks AEAD)")
                        .tag(EncryptionEnvelopePolicy.forceAEAD)
                    Text("Force legacy (CFB + MDC; maximum compat)")
                        .tag(EncryptionEnvelopePolicy.forceLegacy)
                }
                .pickerStyle(.radioGroup)
                .accessibilityIdentifier("settings.envelope-policy")
            }

            Section(header: Text("Autocrypt"), footer: Text("Autocrypt embeds your public key in every signed/encrypted outgoing message so recipients using Thunderbird, K-9, or Delta Chat pick it up automatically.").font(.caption)) {
                Picker("Prefer-encrypt", selection: $viewModel.autocryptPreferEncrypt) {
                    ForEach(AutocryptPolicyChoice.allCases, id: \.self) { Text($0.label).tag($0) }
                }
                .pickerStyle(.radioGroup)
                .accessibilityIdentifier("settings.autocrypt-prefer-encrypt")
            }

            Section(header: Text("Post-quantum"), footer: Text("Hybrid PQ provides classical-OR-PQ security: protected if either algorithm is broken. Conservative uses hash-based SLH-DSA signatures; very large signatures, classical-only encryption.").font(.caption)) {
                Picker("Key generation algorithm", selection: $viewModel.pqPolicy) {
                    ForEach(PQPolicyChoice.allCases, id: \.self) { Text($0.label).tag($0) }
                }
                .pickerStyle(.radioGroup)
                .accessibilityIdentifier("settings.pq-policy")
            }
        }
        .padding()
        .frame(minWidth: 560, minHeight: 480)
    }
}

#Preview {
    EncryptionSettingsView(
        viewModel: EncryptionSettingsViewModel(
            storage: { _, _, _ in }
        )
    )
}

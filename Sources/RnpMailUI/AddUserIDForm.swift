//
//  AddUserIDForm.swift
//  RnpMailUI
//
//  SwiftUI sheet for adding a new user ID to an existing key. Consumes
//  `KeyManager.addUserID(...)` (engine-layer wrapper from
//  `Sources/MailSecurityEngine/KeyManager+UserIDs.swift`).
//

import KeyStateStore
import MailSecurityEngine
import SwiftUI

@MainActor
public final class AddUserIDViewModel: ObservableObject {
    @Published public var realName: String = ""
    @Published public var email: String = ""
    @Published public var isPrimary: Bool = false
    @Published public var inFlight: Bool = false
    @Published public var errorMessage: String?

    public let keyFingerprint: String
    private let keyManager: KeyManager
    private var onComplete: ((KeyInfo) -> Void)?

    public init(
        keyFingerprint: String,
        keyManager: KeyManager,
        onComplete: ((KeyInfo) -> Void)? = nil
    ) {
        self.keyFingerprint = keyFingerprint
        self.keyManager = keyManager
        self.onComplete = onComplete
    }

    public var composedUID: String {
        if realName.isEmpty {
            return "<\(email)>"
        }
        return "\(realName) <\(email)>"
    }

    public var canSubmit: Bool {
        !email.isEmpty && email.contains("@") && !inFlight
    }

    public func submit() {
        guard canSubmit else { return }
        inFlight = true
        errorMessage = nil
        let uid = composedUID
        let primary = isPrimary
        Task {
            do {
                let info = try keyManager.addUserID(
                    uid,
                    toKeyWithFingerprint: keyFingerprint,
                    primary: primary
                )
                await MainActor.run {
                    self.inFlight = false
                    self.onComplete?(info)
                }
            } catch {
                await MainActor.run {
                    self.inFlight = false
                    self.errorMessage = error.localizedDescription
                }
            }
        }
    }
}

public struct AddUserIDForm: View {
    @StateObject public var viewModel: AddUserIDViewModel
    @Environment(\.dismiss) private var dismiss

    public init(viewModel: AddUserIDViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Add user ID")
                .font(.title2.bold())

            Form {
                Section("Identity") {
                    TextField("Real name", text: $viewModel.realName)
                        .accessibilityLabel("Real name")
                    TextField("Email", text: $viewModel.email)
                        .accessibilityLabel("Email address")
                }

                Section {
                    Toggle("Make this the primary user ID", isOn: $viewModel.isPrimary)
                } footer: {
                    Text("The primary UID is what RNP uses for Autocrypt headers and the Mail banner by default.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("Preview") {
                    Text(viewModel.composedUID)
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                }
            }

            if let error = viewModel.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.caption)
            }

            HStack {
                Button("Cancel", role: .cancel) { dismiss() }
                Spacer()
                Button {
                    viewModel.submit()
                } label: {
                    if viewModel.inFlight {
                        ProgressView()
                    } else {
                        Text("Add user ID")
                    }
                }
                .keyboardShortcut(.return)
                .disabled(!viewModel.canSubmit)
            }
        }
        .padding()
        .frame(minWidth: 480, minHeight: 420)
    }
}

#Preview {
    let temp = FileManager.default.temporaryDirectory
        .appendingPathComponent("rnp-adduid-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: temp) }
    let km = try! KeyManager(directory: temp, password: "preview")
    let info = try? km.generateKey(userID: "Alice <alice@example.org>", algorithm: .ed25519)
    let vm = AddUserIDViewModel(keyFingerprint: info!.fingerprint, keyManager: km)
    return AddUserIDForm(viewModel: vm)
}

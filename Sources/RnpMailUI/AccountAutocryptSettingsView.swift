//
//  AccountAutocryptSettingsView.swift
//  RnpMailUI
//
//  SwiftUI view for editing per-account Autocrypt prefer-encrypt
//  overrides via AccountKeyedPolicyStore. Additive; container app
//  presents it in Settings → Autocrypt → Per-account overrides.
//

import Autocrypt
import MailSecurityEngine
import SwiftUI

@MainActor
public final class AccountAutocryptSettingsViewModel: ObservableObject {
    @Published public private(set) var overrides: [(account: String, value: AutocryptPreferEncrypt)] = []
    @Published public var newAccountAddress: String = ""
    @Published public var newAccountValue: AutocryptPreferEncrypt = .nopreference
    @Published public var errorMessage: String?

    public let defaultPolicy: AutocryptPreferEncrypt
    private let store: AccountKeyedPolicyStore

    public init(store: AccountKeyedPolicyStore, defaultPolicy: AutocryptPreferEncrypt = .mutual) {
        self.store = store
        self.defaultPolicy = defaultPolicy
        refresh()
    }

    public func refresh() {
        overrides = store.allOverrides()
            .map { (account: $0.key, value: $0.value) }
            .sorted { $0.account < $1.account }
    }

    public func addOverride() {
        let address = newAccountAddress.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !address.isEmpty, address.contains("@") else {
            errorMessage = "Enter a valid email address."
            return
        }
        do {
            try store.setPreferEncrypt(newAccountValue, forAccount: address)
            newAccountAddress = ""
            newAccountValue = .nopreference
            errorMessage = nil
            refresh()
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }

    public func removeOverride(at index: Int) {
        guard index < overrides.count else { return }
        let entry = overrides[index]
        do {
            try store.clear(account: entry.account)
            refresh()
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }
}

public struct AccountAutocryptSettingsView: View {
    @StateObject public var viewModel: AccountAutocryptSettingsViewModel

    public init(viewModel: AccountAutocryptSettingsViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    public var body: some View {
        Form {
            Section(header: Text("Existing overrides")) {
                if viewModel.overrides.isEmpty {
                    Text("No per-account overrides configured.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(viewModel.overrides.indices, id: \.self) { index in
                        let entry = viewModel.overrides[index]
                        HStack {
                            Text(entry.account).font(.system(.body, design: .monospaced))
                            Spacer()
                            Text(label(for: entry.value))
                                .foregroundStyle(.secondary)
                        }
                        .accessibilityIdentifier("autocrypt.override.\(entry.account)")
                    }
                    .onDelete(perform: { indexSet in
                        for i in indexSet { viewModel.removeOverride(at: i) }
                    })
                }
            }

            Section(header: Text("Add override")) {
                TextField("Account email (e.g. alice@work.com)", text: $viewModel.newAccountAddress)
                    .accessibilityIdentifier("autocrypt.new-account")
                Picker("Prefer-encrypt", selection: $viewModel.newAccountValue) {
                    Text("Mutual").tag(AutocryptPreferEncrypt.mutual)
                    Text("No preference").tag(AutocryptPreferEncrypt.nopreference)
                    Text("Encrypt only").tag(AutocryptPreferEncrypt.encrypt)
                    Text("Disable Autocrypt").tag(AutocryptPreferEncrypt.disable)
                }
                Button("Add override", action: viewModel.addOverride)
                    .accessibilityIdentifier("autocrypt.add-override")
            }

            if let error = viewModel.errorMessage {
                Section { Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red) }
            }
        }
        .padding()
        .frame(minWidth: 520, minHeight: 480)
    }

    private func label(for value: AutocryptPreferEncrypt) -> String {
        switch value {
        case .mutual: return "Mutual"
        case .nopreference: return "No preference"
        case .encrypt: return "Encrypt only"
        case .disable: return "Disable"
        }
    }
}

#Preview {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("autocrypt-account-preview-\(UUID().uuidString).json")
    defer { try? FileManager.default.removeItem(at: url) }
    let store: AccountKeyedPolicyStore
    if let s = try? AccountKeyedPolicyStore(storeURL: url) {
        store = s
    } else {
        store = AccountKeyedPolicyStore.inMemory()
    }
    let vm = AccountAutocryptSettingsViewModel(store: store)
    return AccountAutocryptSettingsView(viewModel: vm)
}

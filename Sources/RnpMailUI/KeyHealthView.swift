//
//  KeyHealthView.swift
//  RnpMailUI
//
//  Real Key Health view (replaces the stub in RoadmapUIStubs.swift).
//  Reads from KeyManager + KeyStateStore, computes ExpiryRecovery per
//  key, and renders status chips with one-click recovery buttons. The
//  view is observable-state-driven: pass a `KeyHealthViewModel` and
//  the view reflects whatever the model publishes.
//

import Combine
import KeyStateStore
import MailSecurityEngine
import SwiftUI

/// View model backing `KeyHealthView`. Subscribes to KeyManager state
/// and exposes a per-key `RecoveryRecommendation` for rendering.
@MainActor
public final class KeyHealthViewModel: ObservableObject {
    @Published public private(set) var recommendations: [KeyHealthItem] = []
    @Published public private(set) var error: String?
    @Published public var isRefreshing: Bool = false

    public struct KeyHealthItem: Identifiable, Equatable {
        public let keyInfo: KeyInfo
        public let role: KeyRole
        public let recommendation: RecoveryRecommendation
        public var id: String { keyInfo.fingerprint }
    }

    private let keyManager: KeyManager

    public init(keyManager: KeyManager) {
        self.keyManager = keyManager
    }

    /// Rebuilds the recommendation list from the current keyring state.
    public func refresh() {
        isRefreshing = true
        defer { isRefreshing = false }
        do {
            let keys = try keyManager.listKeys()
            var items: [KeyHealthItem] = []
            for info in keys {
                let role: KeyRole = info.hasSecret ? .ownSecretAvailable : .recipient
                let usageState = keyManager.usageState(forFingerprint: info.fingerprint)
                let state = ExpiryRecovery.state(for: info, role: role, usageState: usageState)
                let address = KeyManager.emailAddress(from: info.primaryUserID)
                let rec = ExpiryRecovery.action(
                    state: state,
                    role: role,
                    address: address,
                    fingerprint: info.fingerprint
                )
                items.append(KeyHealthItem(keyInfo: info, role: role, recommendation: rec))
            }
            recommendations = items.sorted { lhs, rhs in
                Self.healthRank(lhs.recommendation.state) < Self.healthRank(rhs.recommendation.state)
            }
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Filters the recommendation list to only items needing attention.
    public var itemsNeedingAttention: [KeyHealthItem] {
        recommendations.filter { $0.recommendation.state != .healthy }
    }

    /// Sort rank so the most urgent items are at the top.
    private static func healthRank(_ state: KeyHealthState) -> Int {
        switch state {
        case .conflict: return 0
        case .expired: return 1
        case .revoked: return 2
        case .expiringSoon: return 3
        case .archived: return 4
        case .healthy: return 5
        }
    }
}

/// SwiftUI view rendering the Key Health list. Used as a top-level tab
/// in the container app.
public struct KeyHealthView: View {
    @StateObject public var viewModel: KeyHealthViewModel

    public init(viewModel: KeyHealthViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    public var body: some View {
        List {
            if let error = viewModel.error {
                Section {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                }
            }
            Section("Needs attention") {
                let items = viewModel.itemsNeedingAttention
                if items.isEmpty {
                    Label("All keys are healthy.", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                } else {
                    ForEach(items) { item in
                        KeyHealthRow(item: item)
                    }
                }
            }
            Section("All keys") {
                ForEach(viewModel.recommendations) { item in
                    KeyHealthRow(item: item)
                }
            }
        }
        .navigationTitle("Key Health")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    viewModel.refresh()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .accessibilityLabel("Refresh key health")
            }
        }
        .onAppear { viewModel.refresh() }
    }
}

private struct KeyHealthRow: View {
    let item: KeyHealthViewModel.KeyHealthItem

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                statusChip(for: item.recommendation.state)
                Text(item.keyInfo.primaryUserID)
                    .font(.body)
                    .lineLimit(1)
            }
            Text(item.recommendation.explanation)
                .font(.caption)
                .foregroundStyle(.secondary)
            if let primary = item.recommendation.primary {
                ActionButton(action: primary)
            }
            ForEach(Array(item.recommendation.secondary.enumerated()), id: \.offset) { _, action in
                ActionButton(action: action, prominent: false)
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private func statusChip(for state: KeyHealthState) -> some View {
        switch state {
        case .healthy:
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .expiringSoon:
            Image(systemName: "clock.badge.exclamationmark").foregroundStyle(.orange)
        case .expired:
            Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
        case .revoked:
            Image(systemName: "minus.circle.fill").foregroundStyle(.gray)
        case .archived:
            Image(systemName: "archivebox.fill").foregroundStyle(.gray)
        case .conflict:
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
        }
    }
}

private struct ActionButton: View {
    let action: RecoveryAction
    let prominent: Bool

    init(action: RecoveryAction, prominent: Bool = true) {
        self.action = action
        self.prominent = prominent
    }

    var body: some View {
        Button {
            // Actions are handled by the container app's coordinator,
            // which has access to the key lifecycle services. The view
            // layer only renders the affordance; the engine layer
            // performs the action.
        } label: {
            Label(label, systemImage: icon)
                .font(prominent ? .body : .footnote)
        }
        .modifier(ActionButtonStyle(prominent: prominent))
        .disabled(true)  // enabled when coordinator is wired in.
        .accessibilityHint("Wired up by the container app's coordinator")
    }

    private var label: String {
        switch action {
        case .extendExpiry: return "Extend expiry"
        case .rotateEncryptionSubkey: return "Rotate encryption subkey"
        case .rotateSigningSubkey: return "Rotate signing subkey"
        case .publishKey: return "Publish"
        case .notifyContacts: return "Notify contacts"
        case .archiveKey: return "Archive"
        case .generateReplacementKey: return "Generate replacement"
        case .fetchLatestFromKeyserver: return "Fetch latest"
        case .contactOutOfBand: return "Contact out-of-band"
        case .verifyFingerprint: return "Verify fingerprint"
        case .informationalOnly: return ""
        }
    }

    private var icon: String {
        switch action {
        case .extendExpiry: return "calendar.badge.plus"
        case .rotateEncryptionSubkey, .rotateSigningSubkey: return "arrow.triangle.2.circlepath"
        case .publishKey: return "icloud.and.arrow.up"
        case .notifyContacts: return "envelope"
        case .archiveKey: return "archivebox"
        case .generateReplacementKey: return "key.fill"
        case .fetchLatestFromKeyserver: return "arrow.down.circle"
        case .contactOutOfBand: return "phone"
        case .verifyFingerprint: return "checkmark.shield"
        case .informationalOnly: return "info.circle"
        }
    }
}

private struct ActionButtonStyle: ViewModifier {
    let prominent: Bool

    func body(content: Content) -> some View {
        if prominent {
            content.buttonStyle(.borderedProminent)
        } else {
            content.buttonStyle(.bordered)
        }
    }
}

#Preview("All healthy") {
    let temp = FileManager.default.temporaryDirectory
        .appendingPathComponent("rnp-preview-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: temp) }
    let km = try? KeyManager(directory: temp, password: "preview")
    let vm = KeyHealthViewModel(keyManager: km!)
    return NavigationView { KeyHealthView(viewModel: vm) }
}

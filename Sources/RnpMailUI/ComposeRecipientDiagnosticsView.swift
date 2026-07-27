//
//  ComposeRecipientDiagnosticsView.swift
//  RnpMailUI
//
//  Real compose-window per-recipient diagnostics view (replaces the
//  stub in RoadmapUIStubs.swift). Reads from `RecipientResolution` and
//  a per-recipient status map produced by the engine, and renders one
//  row per recipient with a status chip and contextual action button.
//

import MailSecurityEngine
import SwiftUI

/// Per-recipient status summary used by the compose UI. Carries the
/// address, status state, and a short fingerprint/algorithm hint when
/// resolvable.
public struct ComposeRecipientStatus: Identifiable, Equatable {
    public enum State: Equatable {
        case verified
        case unverified
        case missingKey
        case expired(daysUntilExpiry: Int?)
        case keyChangedConflict
        case archived
        case revoked
    }

    public let address: String
    public let displayName: String?
    public let state: State
    public let fingerprintShort: String?
    public let algorithmLabel: String?

    public var id: String { address }

    public init(
        address: String,
        displayName: String? = nil,
        state: State,
        fingerprintShort: String? = nil,
        algorithmLabel: String? = nil
    ) {
        self.address = address
        self.displayName = displayName
        self.state = state
        self.fingerprintShort = fingerprintShort
        self.algorithmLabel = algorithmLabel
    }
}

public struct ComposeRecipientDiagnosticsView: View {
    public let statuses: [ComposeRecipientStatus]
    public let onAction: (ComposeRecipientStatus, ComposeRecipientAction) -> Void

    public init(
        statuses: [ComposeRecipientStatus],
        onAction: @escaping (ComposeRecipientStatus, ComposeRecipientAction) -> Void = { _, _ in }
    ) {
        self.statuses = statuses
        self.onAction = onAction
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(statuses) { status in
                ComposeRecipientRow(status: status, onAction: { action in
                    onAction(status, action)
                })
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Per-recipient encryption status")
    }
}

public enum ComposeRecipientAction: Equatable, Sendable {
    case lookupKey
    case extendOwnKey
    case rotateOwnSubkey
    case resolveConflict
    case restoreFromArchive
    case viewKeyDetail
}

private struct ComposeRecipientRow: View {
    let status: ComposeRecipientStatus
    let onAction: (ComposeRecipientAction) -> Void

    var body: some View {
        HStack(spacing: 10) {
            statusChip
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(displayLabel)
                        .font(.body)
                    if let fpr = status.fingerprintShort {
                        Text(fpr)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
                if let hint = hintLabel {
                    Text(hint)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if let action = primaryAction {
                Button(actionTitle(action), action: { onAction(action) })
                    .buttonStyle(.bordered)
                    .font(.caption)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(displayLabel), \(stateLabel)")
    }

    private var displayLabel: String {
        if let displayName = status.displayName, !displayName.isEmpty {
            return displayName
        }
        return status.address
    }

    private var statusChip: some View {
        let (system, color): (String, Color) = chipAsset
        return Image(systemName: system)
            .foregroundStyle(color)
            .accessibilityHidden(true)
    }

    private var chipAsset: (String, Color) {
        switch status.state {
        case .verified: return ("checkmark.seal.fill", .green)
        case .unverified: return ("checkmark.circle", .secondary)
        case .missingKey: return ("exclamationmark.triangle.fill", .orange)
        case .expired: return ("clock.badge.exclamationmark", .orange)
        case .keyChangedConflict: return ("exclamationmark.octagon.fill", .red)
        case .archived: return ("archivebox.fill", .gray)
        case .revoked: return ("minus.circle.fill", .gray)
        }
    }

    private var stateLabel: String {
        switch status.state {
        case .verified: return "verified"
        case .unverified: return "key present, not verified"
        case .missingKey: return "no key"
        case let .expired(days):
            if let days, days < 0 {
                return "expired \(-days) days ago"
            } else if let days {
                return "expires in \(days) days"
            }
            return "expired"
        case .keyChangedConflict: return "key changed — verify"
        case .archived: return "only an archived key"
        case .revoked: return "revoked"
        }
    }

    private var hintLabel: String? {
        switch status.state {
        case .missingKey:
            return "Lookup from keyserver or import manually."
        case let .expired(days) where days != nil:
            return "Refresh from keyserver to look for an extension."
        case .keyChangedConflict:
            return "Verify the new fingerprint out-of-band before encrypting."
        case .archived:
            return "May not be reachable at this address anymore."
        default:
            return status.algorithmLabel
        }
    }

    private var primaryAction: ComposeRecipientAction? {
        switch status.state {
        case .missingKey: return .lookupKey
        case .expired: return .lookupKey
        case .keyChangedConflict: return .resolveConflict
        case .archived: return .restoreFromArchive
        case .verified, .unverified: return .viewKeyDetail
        case .revoked: return nil
        }
    }

    private func actionTitle(_ action: ComposeRecipientAction) -> String {
        switch action {
        case .lookupKey: return "Lookup"
        case .extendOwnKey: return "Extend"
        case .rotateOwnSubkey: return "Rotate"
        case .resolveConflict: return "Resolve"
        case .restoreFromArchive: return "Restore"
        case .viewKeyDetail: return "Details"
        }
    }
}

#Preview("Mixed recipients") {
    ComposeRecipientDiagnosticsView(statuses: [
        ComposeRecipientStatus(
            address: "alice@x",
            displayName: "Alice",
            state: .verified,
            fingerprintShort: "0123 4567 89AB CDEF",
            algorithmLabel: "Ed25519"
        ),
        ComposeRecipientStatus(address: "bob@x", state: .missingKey),
        ComposeRecipientStatus(address: "carol@x", state: .expired(daysUntilExpiry: 12)),
        ComposeRecipientStatus(address: "dave@x", state: .keyChangedConflict),
        ComposeRecipientStatus(address: "erin@x", state: .archived),
    ])
    .padding()
    .frame(width: 480)
}

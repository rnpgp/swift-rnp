//
//  RecommendedActionBanner.swift
//  RnpMailUI
//
//  Single-line summary banner for the compose window. Reads from
//  RecipientResolution + a per-recipient status map and produces one
//  actionable sentence: "Encrypt to 3 of 4 recipients" or "All
//  recipients have verified keys" or "Encryption blocked for bob@x".
//
//  Companion to ComposeRecipientDiagnosticsView (which renders the
//  per-recipient detail). This is the headline above it.
//

import MailSecurityEngine
import SwiftUI

public struct RecommendedActionBanner: View {
    public let resolution: RecipientResolution
    public let statuses: [ComposeRecipientStatus]

    public init(resolution: RecipientResolution, statuses: [ComposeRecipientStatus]) {
        self.resolution = resolution
        self.statuses = statuses
    }

    public var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .accessibilityHidden(true)
            Text(headline)
                .font(.body.weight(.medium))
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(color.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
        .accessibilityElement(children: .combine)
        .accessibilityLabel(headline)
        .accessibilityIdentifier("compose.recommended-action")
    }

    private var verifiedCount: Int {
        statuses.filter { if case .verified = $0.state { return true } else { return false } }.count
    }

    private var encryptableCount: Int {
        // Verified + unverified recipients can be encrypted to.
        statuses.filter {
            switch $0.state {
            case .verified, .unverified: return true
            default: return false
            }
        }.count
    }

    private var totalCount: Int { statuses.count }

    private var anyConflict: Bool {
        statuses.contains { if case .keyChangedConflict = $0.state { return true } else { return false } }
    }

    private var anyMissing: Bool {
        !resolution.missing.isEmpty
    }

    private var headline: String {
        if anyConflict {
            let conflicts = statuses.filter { if case .keyChangedConflict = $0.state { return true } else { return false } }
            let names = conflicts.map(\.address).prefix(3).joined(separator: ", ")
            let extra = conflicts.count > 3 ? " and \(conflicts.count - 3) more" : ""
            return "Encryption blocked for \(names)\(extra). Resolve the key change first."
        }
        if anyMissing {
            let names = resolution.missing.prefix(3).joined(separator: ", ")
            let extra = resolution.missing.count > 3 ? " and \(resolution.missing.count - 3) more" : ""
            return "Encrypt to \(encryptableCount) of \(totalCount). No key for \(names)\(extra)."
        }
        if encryptableCount == totalCount {
            if verifiedCount == totalCount {
                return "Encrypt to all \(totalCount) recipients. All keys verified."
            }
            let unverified = totalCount - verifiedCount
            return "Encrypt to \(totalCount) recipients. \(unverified) key\(unverified == 1 ? "" : "s") not verified."
        }
        return "Encrypt to \(encryptableCount) of \(totalCount) recipients."
    }

    private var icon: String {
        if anyConflict { return "exclamationmark.octagon.fill" }
        if anyMissing { return "lock.open" }
        if verifiedCount == totalCount { return "checkmark.seal.fill" }
        return "lock.fill"
    }

    private var color: Color {
        if anyConflict { return .red }
        if anyMissing { return .orange }
        if verifiedCount == totalCount { return .green }
        return .blue
    }
}

#Preview("All verified") {
    RecommendedActionBanner(
        resolution: RecipientResolution(resolved: [:], missing: [], archivedOnly: []),
        statuses: [
            ComposeRecipientStatus(address: "alice@x", state: .verified),
            ComposeRecipientStatus(address: "bob@x", state: .verified),
        ]
    )
    .padding()
}

#Preview("Missing key") {
    RecommendedActionBanner(
        resolution: RecipientResolution(
            resolved: [:],
            missing: ["bob@x"],
            archivedOnly: []
        ),
        statuses: [
            ComposeRecipientStatus(address: "alice@x", state: .verified),
            ComposeRecipientStatus(address: "bob@x", state: .missingKey),
        ]
    )
    .padding()
}

#Preview("Conflict") {
    RecommendedActionBanner(
        resolution: RecipientResolution(resolved: [:], missing: [], archivedOnly: []),
        statuses: [
            ComposeRecipientStatus(address: "alice@x", state: .verified),
            ComposeRecipientStatus(address: "bob@x", state: .keyChangedConflict),
        ]
    )
    .padding()
}

//
//  TrustHistoryView.swift
//  swift-rnp
//
//  Trust history for one email address: every key binding seen for the
//  address and the states it went through (first seen, verified, problem),
//  most recent first. Shown as a sheet from the recipient key detail view.
//

import SwiftUI
import TrustStore

/// Lists the `TrustRecord` snapshots recorded for one address.
///
/// Each row shows one recorded state of a binding: the fingerprint, the
/// trust state badge, when the binding was first seen, and when this state
/// was recorded. The rows are passed in by the caller, most recent first
/// (see `TrustStore.history(forEmail:)`).
public struct TrustHistoryView: View {
    /// Address whose history is shown.
    public let email: String
    /// History snapshots, most recent first.
    public let records: [TrustRecord]

    public init(email: String, records: [TrustRecord]) {
        self.email = email
        self.records = records
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: RnpSpacing.md) {
            header
            if records.isEmpty {
                emptyState
            } else {
                recordList
            }
        }
        .padding(RnpSpacing.xl)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .accessibilityIdentifier("trusthistory")
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: RnpSpacing.xxs) {
            Text("trustHistory.title")
                .font(.title2.weight(.semibold))
            Text(email)
                .font(.callout)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("trusthistory.header")
    }

    // MARK: - Empty state

    private var emptyState: some View {
        RnpEmptyState(
            icon: "clock.arrow.circlepath",
            title: "trustHistory.empty.title",
            message: "trustHistory.empty.message".localized
        ) {
            EmptyView()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityIdentifier("trusthistory.empty")
    }

    // MARK: - Record list

    private var recordList: some View {
        ScrollView {
            VStack(spacing: 0) {
                ForEach(Array(records.enumerated()), id: \.offset) { index, record in
                    row(for: record, index: index)
                    if index < records.count - 1 {
                        Divider()
                    }
                }
            }
        }
        .accessibilityIdentifier("trusthistory.list")
    }

    private func row(for record: TrustRecord, index: Int) -> some View {
        let presentation = TrustPresentation(state: record.state)
        return HStack(alignment: .center, spacing: RnpSpacing.sm) {
            Image(systemName: presentation.iconName)
                .font(.system(size: 20))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(presentation.color)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: RnpSpacing.xxs) {
                HStack(spacing: RnpSpacing.xs) {
                    Text(record.fingerprint.groupedFingerprintAbbreviated)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                    RnpBadge(text: presentation.labelKey.localized, color: presentation.color)
                }
                HStack(spacing: RnpSpacing.xs) {
                    dateRow("trustHistory.firstSeen", date: record.firstSeen)
                    dateRow("trustHistory.recorded", date: record.lastSeen)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, RnpSpacing.xs)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("trusthistory.row.\(index)")
        .accessibilityLabel("\(record.fingerprint): \(presentation.labelKey.localized)")
        .accessibilityValue(record.state.rawValue)
    }

    private func dateRow(_ label: LocalizedStringKey, date: Date) -> some View {
        HStack(spacing: RnpSpacing.xxs) {
            Text(label)
            Text(date, style: .date)
        }
        .font(.caption)
        .foregroundStyle(.secondary)
    }
}

#if DEBUG
struct TrustHistoryView_Previews: PreviewProvider {
    static var previews: some View {
        TrustHistoryView(
            email: "alice@example.com",
            records: [
                TrustRecord(email: "alice@example.com", fingerprint: "74E2A1E008CB1B1021192AA05225D37282795A2F", state: .verified),
                TrustRecord(email: "alice@example.com", fingerprint: "1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D", state: .problem),
                TrustRecord(email: "alice@example.com", fingerprint: "74E2A1E008CB1B1021192AA05225D37282795A2F", state: .unverified),
            ]
        )
        TrustHistoryView(email: "alice@example.com", records: [])
    }
}
#endif

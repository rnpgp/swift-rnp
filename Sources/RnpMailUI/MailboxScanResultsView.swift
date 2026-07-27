//
//  MailboxScanResultsView.swift
//  RnpMailUI
//
//  Renders the result of a MailboxKeyScanner run. The view-model
//  drives the scan in chunks and surfaces progress; the user picks
//  which discovered keys to import and which to ignore.
//

import Combine
import MailSecurityEngine
import SwiftUI

@MainActor
public final class MailboxScanViewModel: ObservableObject {
    @Published public private(set) var progress: ScanProgress = .idle
    @Published public private(set) var report: MailboxScanReport?
    @Published public private(set) var importedFingerprints: Set<String> = []
    @Published public private(set) var ignoredFingerprints: Set<String> = []
    @Published public var errorMessage: String?

    public enum ScanProgress: Equatable {
        case idle
        case scanning(messagesProcessed: Int, totalMessages: Int)
        case complete
        case failed
    }

    private let scanner: MailboxKeyScanner
    private let engine: MailSecurityEngine?

    public init(scanner: MailboxKeyScanner = MailboxKeyScanner(), engine: MailSecurityEngine?) {
        self.scanner = scanner
        self.engine = engine
    }

    public func scan(messages: [Data]) {
        guard let engine else {
            errorMessage = "Engine unavailable."
            progress = .failed
            return
        }
        progress = .scanning(messagesProcessed: 0, totalMessages: messages.count)
        Task {
            let report = (try? engine.keyManager.withRnp { rnp in
                self.scanner.scan(messages: messages, using: rnp)
            }) ?? MailboxScanReport(discoveredKeys: [], messagesScanned: 0, errors: ["scan failed"])
            await MainActor.run {
                self.report = report
                self.progress = .complete
            }
        }
    }

    public func importKey(_ discovered: DiscoveredKey) {
        importedFingerprints.insert(discovered.fingerprint)
        ignoredFingerprints.remove(discovered.fingerprint)
    }

    public func ignoreKey(_ discovered: DiscoveredKey) {
        ignoredFingerprints.insert(discovered.fingerprint)
        importedFingerprints.remove(discovered.fingerprint)
    }

    public func importAll() {
        guard let report else { return }
        for key in report.discoveredKeys {
            importKey(key)
        }
    }

    public func ignoreAll() {
        guard let report else { return }
        for key in report.discoveredKeys {
            ignoreKey(key)
        }
    }
}

public struct MailboxScanResultsView: View {
    @StateObject public var viewModel: MailboxScanViewModel

    public init(viewModel: MailboxScanViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            content
        }
        .frame(minWidth: 600, minHeight: 480)
    }

    @ViewBuilder
    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading) {
                Text("Discovered keys")
                    .font(.title2.bold())
                if let report = viewModel.report {
                    Text("\(report.discoveredKeys.count) key\(report.discoveredKeys.count == 1 ? "" : "s") in \(report.messagesScanned) message\(report.messagesScanned == 1 ? "" : "s")")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            HStack {
                Button("Import all") { viewModel.importAll() }
                    .accessibilityIdentifier("mailbox-scan.import-all")
                Button("Ignore all") { viewModel.ignoreAll() }
                    .accessibilityIdentifier("mailbox-scan.ignore-all")
            }
        }
        .padding()
    }

    @ViewBuilder
    private var content: some View {
        switch viewModel.progress {
        case .idle:
            Text("Scan not started.")
                .foregroundStyle(.secondary)
                .padding()

        case let .scanning(processed, total):
            VStack(spacing: 8) {
                ProgressView(value: Double(processed), total: Double(max(total, 1)))
                Text("Scanned \(processed) of \(total) messages…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding()

        case .complete:
            if let report = viewModel.report, !report.discoveredKeys.isEmpty {
                List(report.discoveredKeys) { key in
                    MailboxScanRow(
                        key: key,
                        isImported: viewModel.importedFingerprints.contains(key.fingerprint),
                        isIgnored: viewModel.ignoredFingerprints.contains(key.fingerprint),
                        onImport: { viewModel.importKey(key) },
                        onIgnore: { viewModel.ignoreKey(key) }
                    )
                }
                .listStyle(.inset)
            } else if let report = viewModel.report, report.discoveredKeys.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "questionmark.folder")
                        .font(.system(size: 36))
                        .foregroundStyle(.secondary)
                    Text("No keys found in your mailbox.")
                        .font(.headline)
                    Text("Your contacts may not use Autocrypt or attach their public keys. Try a keyserver lookup from the Recipients tab.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding()
                .frame(maxWidth: .infinity)
            }

        case .failed:
            if let message = viewModel.errorMessage {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .padding()
            }
        }
    }
}

private struct MailboxScanRow: View {
    let key: DiscoveredKey
    let isImported: Bool
    let isIgnored: Bool
    let onImport: () -> Void
    let onIgnore: () -> Void

    var body: some View {
        HStack(alignment: .top) {
            Image(systemName: sourceIcon)
                .foregroundStyle(sourceColor)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(key.primaryUserID).font(.body)
                Text(key.fingerprint)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                Text(sourceLabel)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            stateControl
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private var stateControl: some View {
        if isImported {
            Label("Imported", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .labelStyle(.iconOnly)
        } else if isIgnored {
            Button("Undo", action: onImport)
                .buttonStyle(.bordered)
                .accessibilityIdentifier("mailbox-scan.undo-\(key.fingerprint)")
        } else {
            HStack {
                Button("Ignore", action: onIgnore)
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("mailbox-scan.ignore-\(key.fingerprint)")
                Button("Import", action: onImport)
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("mailbox-scan.import-\(key.fingerprint)")
            }
        }
    }

    private var sourceIcon: String {
        switch key.source {
        case .autocryptHeader: return "envelope.fill"
        case .pgpKeysAttachment: return "paperclip.circle.fill"
        case .signingKey: return "signature"
        }
    }

    private var sourceColor: Color {
        switch key.source {
        case .autocryptHeader: return .blue
        case .pgpKeysAttachment: return .purple
        case .signingKey: return .orange
        }
    }

    private var sourceLabel: String {
        switch key.source {
        case .autocryptHeader: return "Autocrypt header"
        case .pgpKeysAttachment: return "Public-key attachment"
        case .signingKey: return "Signing key"
        }
    }
}

#Preview("Empty") {
    MailboxScanResultsView(viewModel: MailboxScanViewModel(engine: nil))
}

#Preview("Consent") {
    MailboxScanConsentView(onScan: {}, onSkip: {})
}

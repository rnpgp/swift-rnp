//
//  MailboxScanConsentView.swift
//  RnpMailUI
//
//  Consent gate for the mailbox scan. Explains what is scanned, that
//  the scan runs locally (no network), and that the user can re-run
//  later from Settings. On consent, calls `onScan`.
//

import MailSecurityEngine
import SwiftUI

public struct MailboxScanConsentView: View {
    public let onScan: () -> Void
    public let onSkip: () -> Void

    public init(onScan: @escaping () -> Void, onSkip: @escaping () -> Void) {
        self.onScan = onScan
        self.onSkip = onSkip
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Find keys for your contacts", systemImage: "magnifyingglass")
                .font(.title2.bold())

            Text("RNP can scan your local mail to find public keys for people you already correspond with. The scan runs entirely on your Mac; nothing is sent anywhere.")
                .font(.body)
                .foregroundStyle(.secondary)

            GroupBox("Sources we'll check") {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Autocrypt headers", systemImage: "envelope").font(.body)
                    Label("Public-key attachments (application/pgp-keys)", systemImage: "paperclip").font(.body)
                    Label("Embedded keys in signed messages", systemImage: "signature").font(.body)
                }
                .padding(8)
            }

            GroupBox("Privacy") {
                VStack(alignment: .leading, spacing: 6) {
                    Label("No network calls during the scan", systemImage: "wifi.slash").font(.body)
                    Label("No telemetry on what was scanned", systemImage: "hand.raised").font(.body)
                    Label("Ignored keys are remembered (no re-prompt)", systemImage: "eye.slash").font(.body)
                }
                .padding(8)
            }

            Spacer()

            HStack {
                Button("Maybe later", action: onSkip)
                    .accessibilityIdentifier("mailbox-scan.skip")
                Spacer()
                Button {
                    onScan()
                } label: {
                    Label("Scan now", systemImage: "magnifyingglass.circle.fill")
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("mailbox-scan.start")
            }
        }
        .padding()
        .frame(minWidth: 520, minHeight: 480)
    }
}

#Preview {
    MailboxScanConsentView(onScan: {}, onSkip: {})
}

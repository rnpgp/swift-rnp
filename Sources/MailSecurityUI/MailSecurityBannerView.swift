//
//  MailSecurityBannerView.swift
//  swift-rnp
//
//  AppKit OpenPGP security banner shown when the user clicks Mail's security
//  indicator. Surfaces:
//  - the message's encryption status (encrypted / not encrypted / decryption
//    problems), when the handler supplies it;
//  - per-signer signature + trust state, including the specific reason an
//    invalid signature failed verification;
//  - per-signer actions: "View Key in RNP" (deep link
//    `rnpmail://review/<fpr>`), "Copy Fingerprint", "Mark as Verified"
//    for unverified keys, "Fetch signer key" for unknown signers, and —
//    for invalid signatures — "Report Issue" (a pre-filled GitHub issue).
//
//  Moved out of the MailPlugin appex into this SwiftPM target so the banner
//  can be unit- and snapshot-tested without Mail.app. Kept free of MailKit
//  types: the caller translates `MEMessageSigner` into `Signer` values.
//

import AppKit
import MailSecurityEngine
import Librnp
import TrustStore

/// Renders the "OpenPGP signature" banner: a branded header, an optional
/// encryption-status line, and one row stack per signer with the signer's
/// trust state and actions.
public final class MailSecurityBannerView: NSView {

    /// One signer row in the banner.
    public struct Signer {
        /// Display name, typically the signer's user ID or fingerprint.
        public let label: String
        /// Decode-time context for trust lookup; `nil` when unavailable.
        public let context: SignerContext?

        public init(label: String, context: SignerContext?) {
            self.label = label
            self.context = context
        }
    }

    /// Outcome of a "Fetch signer key" attempt, reported back to the banner
    /// through the action's completion handler.
    public enum SignerKeyFetchOutcome: Equatable, Sendable {
        /// The key was imported. The host is expected to rebuild the banner
        /// with the re-verified signature status, so the banner itself does
        /// nothing further.
        case success
        /// The fetch failed; the banner shows the message inline and
        /// re-enables the button so the user can retry.
        case failure(String)
    }

    /// Action invoked when the user taps "Fetch signer key" for a signer.
    /// The completion handler must be called on the main thread.
    public typealias SignerKeyFetchAction = (Signer, @escaping (SignerKeyFetchOutcome) -> Void) -> Void

    /// Encryption status of the decoded message, supplied by the handler.
    public struct EncryptionInfo: Equatable, Sendable {
        /// Whether the message was encrypted (and successfully decrypted).
        public let isEncrypted: Bool
        /// Decryption problem reported at decode time, if any.
        public let errorDescription: String?

        public init(isEncrypted: Bool, errorDescription: String? = nil) {
            self.isEncrypted = isEncrypted
            self.errorDescription = errorDescription
        }
    }

    private let signers: [Signer]
    private let trustStore: TrustStore?
    private let encryption: EncryptionInfo?
    private let onFetchSignerKey: SignerKeyFetchAction?
    /// Failure messages from the most recent fetch attempt per signer,
    /// keyed by `fetchIdentifier`; shown inline under the signer's buttons.
    private var fetchFailures: [String: String] = [:]

    public init(
        signers: [Signer],
        trustStore: TrustStore?,
        encryption: EncryptionInfo? = nil,
        onFetchSignerKey: SignerKeyFetchAction? = nil
    ) {
        self.signers = signers
        self.trustStore = trustStore
        self.encryption = encryption
        self.onFetchSignerKey = onFetchSignerKey
        super.init(frame: NSRect(x: 0, y: 0, width: 360, height: 120))
        setUpViews()
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    // MARK: - View construction

    private func setUpViews() {
        setAccessibilityRole(.group)
        setAccessibilityLabel("OpenPGP security")

        let header = headerRow

        var sections: [NSView] = [header]
        if let encryptionSection = encryptionSection {
            sections.append(encryptionSection)
            sections.append(makeSeparator())
        }
        sections.append(contentsOf: signerRows)

        let stack = NSStackView(views: sections)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.setCustomSpacing(10, after: header)
        stack.translatesAutoresizingMaskIntoConstraints = false

        addSubview(stack)

        // The bottom constraint is not required so that a host forcing an
        // explicit height wins over content sizing, but it is strong enough
        // to give the view a well-defined fitting height for tests.
        let bottom = stack.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -12)
        bottom.priority = .defaultHigh

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 12),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -12),
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 12),
            bottom,
        ])
    }

    /// Rebuilds the banner content, e.g. after a "Mark as Verified" action
    /// changed the trust state.
    private func refreshContent() {
        subviews.forEach { $0.removeFromSuperview() }
        setUpViews()
    }

    /// Header: brand-blue shield glyph plus the banner title.
    private var headerRow: NSView {
        let icon = NSImageView()
        icon.image = NSImage(
            systemSymbolName: "lock.shield.fill",
            accessibilityDescription: nil
        )
        icon.symbolConfiguration = NSImage.SymbolConfiguration(hierarchicalColor: BannerBrand.primary)
            .applying(NSImage.SymbolConfiguration(pointSize: 15, weight: .semibold))
        icon.setContentHuggingPriority(.required, for: .horizontal)
        icon.setAccessibilityHidden(true)

        let title = NSTextField(labelWithString: "OpenPGP signature")
        title.font = .boldSystemFont(ofSize: NSFont.systemFontSize)

        let row = NSStackView(views: [icon, title])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 6
        return row
    }

    /// Encryption-status line, shown when the handler reported one.
    private var encryptionSection: NSView? {
        guard let encryption else { return nil }

        let icon = NSImageView()
        icon.image = NSImage(
            systemSymbolName: encryption.isEncrypted ? "lock.fill" : "lock.open",
            accessibilityDescription: nil
        )
        let tint = encryption.isEncrypted ? BannerBrand.primary : NSColor.secondaryLabelColor
        icon.symbolConfiguration = NSImage.SymbolConfiguration(hierarchicalColor: tint)
            .applying(NSImage.SymbolConfiguration(pointSize: 12, weight: .medium))
        icon.setContentHuggingPriority(.required, for: .horizontal)
        icon.setAccessibilityHidden(true)

        let statusLabel = NSTextField(labelWithString: encryption.isEncrypted
            ? "Encrypted message"
            : "This message was not encrypted")
        statusLabel.font = NSFont.systemFont(ofSize: NSFont.systemFontSize, weight: .medium)
        if !encryption.isEncrypted {
            statusLabel.textColor = .secondaryLabelColor
        }
        statusLabel.setAccessibilityIdentifier("rnp.banner.encryption-status")

        var textRows: [NSView] = [statusLabel]
        if encryption.isEncrypted {
            let detail = NSTextField(wrappingLabelWithString: "This message was protected with OpenPGP and decrypted by RNP.")
            detail.textColor = .secondaryLabelColor
            detail.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
            textRows.append(detail)
        }
        if let error = encryption.errorDescription, !error.isEmpty {
            let errorLabel = NSTextField(wrappingLabelWithString: "Decryption problem: \(error)")
            errorLabel.textColor = BannerBrand.critical
            errorLabel.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
            textRows.append(errorLabel)
        }

        let textStack = NSStackView(views: textRows)
        textStack.orientation = .vertical
        textStack.alignment = .leading
        textStack.spacing = 3

        let row = NSStackView(views: [icon, textStack])
        row.orientation = .horizontal
        row.alignment = .top
        row.spacing = 8
        row.setAccessibilityRole(.group)
        row.setAccessibilityLabel(statusLabel.stringValue)
        return row
    }

    private func makeSeparator() -> NSView {
        let separator = NSBox()
        separator.boxType = .separator
        return separator
    }

    private var signerRows: [NSView] {
        guard !signers.isEmpty else {
            return [NSTextField(wrappingLabelWithString: "No valid signatures found on this message.")]
        }
        return signers.map { row(for: $0) }
    }

    private func row(for signer: Signer) -> NSView {
        let status = signer.context.flatMap { RnpSignatureStatus(rawValue: $0.status) } ?? .unknown
        let model: SignerTrustViewModel
        var trust: TrustState?
        if let trustStore = trustStore {
            if let fingerprint = signer.context?.fingerprint {
                trust = trustStore.state(forFpr: fingerprint)
            } else {
                trust = .unverified
            }
            let invalidReason = signer.context?.invalidReason.flatMap(InvalidSignatureReason.init(rawValue:))
            model = mapSignerTrust(
                status: status,
                trust: trust ?? .unverified,
                keyExpiration: signer.context?.keyExpiration,
                invalidReason: invalidReason
            )
        } else {
            model = SignerTrustViewModel(
                label: "Trust state unavailable",
                detail: "Trust information cannot be loaded while the keyring is unavailable.",
                intent: .caution,
                reviewDeepLink: false
            )
        }

        let intentColor = color(for: model.intent)

        let icon = NSImageView()
        icon.image = NSImage(
            systemSymbolName: symbolName(for: model.intent),
            accessibilityDescription: nil
        )
        icon.symbolConfiguration = NSImage.SymbolConfiguration(hierarchicalColor: intentColor)
            .applying(NSImage.SymbolConfiguration(pointSize: 13, weight: .semibold))
        icon.setContentHuggingPriority(.required, for: .horizontal)
        icon.setAccessibilityHidden(true)

        let nameLabel = NSTextField(labelWithString: signer.label)
        nameLabel.font = NSFont.systemFont(ofSize: NSFont.systemFontSize, weight: .medium)

        let trustLabel = NSTextField(labelWithString: model.label)
        trustLabel.textColor = intentColor
        trustLabel.font = NSFont.boldSystemFont(ofSize: NSFont.smallSystemFontSize)

        let detailLabel = NSTextField(wrappingLabelWithString: model.detail)
        detailLabel.textColor = NSColor.secondaryLabelColor
        detailLabel.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)

        var rows: [NSView] = [
            nameLabel,
            trustLabel,
            detailLabel,
        ]

        let buttons = actionButtons(for: signer, model: model, trust: trust)
        if !buttons.isEmpty {
            let buttonRow = NSStackView(views: buttons)
            buttonRow.orientation = .horizontal
            buttonRow.alignment = .centerY
            buttonRow.spacing = 8
            rows.append(buttonRow)
        }

        if let identifier = fetchIdentifier(for: signer), let message = fetchFailures[identifier] {
            let errorLabel = NSTextField(wrappingLabelWithString: message)
            errorLabel.textColor = BannerBrand.critical
            errorLabel.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
            errorLabel.setAccessibilityIdentifier("rnp.banner.fetch-error.\(identifier)")
            rows.append(errorLabel)
        }

        let textStack = NSStackView(views: rows)
        textStack.orientation = .vertical
        textStack.alignment = .leading
        textStack.spacing = 3
        textStack.setCustomSpacing(6, after: detailLabel)

        let rowStack = NSStackView(views: [icon, textStack])
        rowStack.orientation = .horizontal
        rowStack.alignment = .top
        rowStack.spacing = 8
        rowStack.setAccessibilityRole(.group)
        rowStack.setAccessibilityLabel("\(signer.label): \(model.label)")
        return rowStack
    }

    // MARK: - Actions

    /// Per-signer action buttons, depending on the signer's trust state and
    /// the available context.
    private func actionButtons(for signer: Signer, model: SignerTrustViewModel, trust: TrustState?) -> [NSButton] {
        var buttons: [NSButton] = []

        let status = signer.context.flatMap { RnpSignatureStatus(rawValue: $0.status) } ?? .unknown
        let fingerprint = signer.context?.fingerprint.flatMap { $0.isEmpty ? nil : $0 }

        // Unknown signer — or an invalid signature whose key is not in the
        // keyring: offer to fetch the key from public keyservers when the
        // host wired the action and there is an identifier to look up.
        let keyFetchable = status == .signerUnknown || (status == .invalid && fingerprint == nil)
        if keyFetchable, onFetchSignerKey != nil, let identifier = fetchIdentifier(for: signer) {
            let fetch = NSButton(title: "Fetch signer key", target: self, action: #selector(fetchSignerKey(_:)))
            fetch.identifier = NSUserInterfaceItemIdentifier(identifier)
            fetch.bezelStyle = .inline
            fetch.setAccessibilityIdentifier("rnp.banner.fetch-signer-key.\(identifier)")
            fetch.setAccessibilityHelp("Looks up the signer's public key on public keyservers and imports it.")
            buttons.append(fetch)
        }

        if let fingerprint {
            if model.reviewDeepLink {
                let link = NSButton(title: "View Key in RNP", target: self, action: #selector(openReviewLink(_:)))
                link.identifier = NSUserInterfaceItemIdentifier(fingerprint)
                link.bezelStyle = .inline
                link.setAccessibilityIdentifier("rnp.banner.view-key.\(fingerprint)")
                link.setAccessibilityHelp("Opens the key detail in the RNP app.")
                buttons.append(link)
            }

            let copy = NSButton(title: "Copy Fingerprint", target: self, action: #selector(copyFingerprint(_:)))
            copy.identifier = NSUserInterfaceItemIdentifier(fingerprint)
            copy.bezelStyle = .inline
            copy.setAccessibilityIdentifier("rnp.banner.copy-fingerprint.\(fingerprint)")
            copy.setAccessibilityHelp("Copies the signer's key fingerprint to the clipboard.")
            buttons.append(copy)

            if trustStore != nil, trust == .unverified {
                let verify = NSButton(title: "Mark as Verified", target: self, action: #selector(markVerified(_:)))
                verify.identifier = NSUserInterfaceItemIdentifier(fingerprint)
                verify.bezelStyle = .inline
                verify.setAccessibilityIdentifier("rnp.banner.mark-verified.\(fingerprint)")
                verify.setAccessibilityHelp("Confirms that you verified this key's fingerprint and marks the key as verified.")
                buttons.append(verify)
            }
        }

        // Invalid signature: offer a pre-filled issue report so the status
        // and failure reason reach support without the user describing them.
        if status == .invalid {
            let identifier = reportIdentifier(for: signer)
            let report = NSButton(title: "Report Issue", target: self, action: #selector(reportIssue(_:)))
            report.identifier = NSUserInterfaceItemIdentifier(identifier)
            report.bezelStyle = .inline
            report.setAccessibilityIdentifier("rnp.banner.report-issue.\(identifier)")
            report.setAccessibilityHelp("Opens a pre-filled issue report in your browser.")
            buttons.append(report)
        }

        return buttons
    }

    private func symbolName(for intent: SignerTrustIntent) -> String {
        switch intent {
        case .positive:
            return "checkmark.shield.fill"
        case .neutral:
            return "questionmark.shield"
        case .caution:
            return "exclamationmark.shield.fill"
        case .critical:
            return "xmark.shield.fill"
        }
    }

    private func color(for intent: SignerTrustIntent) -> NSColor {
        switch intent {
        case .positive:
            return BannerBrand.verified
        case .neutral:
            return BannerBrand.unverified
        case .caution:
            return BannerBrand.unverified
        case .critical:
            return BannerBrand.critical
        }
    }

    @objc private func openReviewLink(_ sender: NSButton) {
        guard let fingerprint = sender.identifier?.rawValue,
              let url = URL(string: "rnpmail://review/\(fingerprint)")
        else {
            return
        }
        NSWorkspace.shared.open(url)
    }

    @objc private func copyFingerprint(_ sender: NSButton) {
        guard let fingerprint = sender.identifier?.rawValue else {
            return
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(fingerprint, forType: .string)

        // Brief confirmation feedback on the button itself.
        sender.title = "Copied"
        sender.isEnabled = false
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { [weak sender] in
            sender?.title = "Copy Fingerprint"
            sender?.isEnabled = true
        }
    }

    @objc private func markVerified(_ sender: NSButton) {
        guard let fingerprint = sender.identifier?.rawValue,
              let trustStore = trustStore,
              (try? trustStore.markVerified(fingerprint: fingerprint)) != nil
        else {
            return
        }
        refreshContent()
    }

    /// Identifier used to fetch a signer's key: the fingerprint when known,
    /// otherwise the signer's email address.
    private func fetchIdentifier(for signer: Signer) -> String? {
        if let fingerprint = signer.context?.fingerprint, !fingerprint.isEmpty {
            return fingerprint
        }
        if let email = signer.context?.email, !email.isEmpty {
            return email
        }
        return nil
    }

    @objc private func fetchSignerKey(_ sender: NSButton) {
        guard let identifier = sender.identifier?.rawValue,
              let signer = signers.first(where: { fetchIdentifier(for: $0) == identifier }),
              let onFetchSignerKey
        else {
            return
        }
        fetchFailures.removeValue(forKey: identifier)
        sender.isEnabled = false
        sender.title = "Fetching…"
        onFetchSignerKey(signer) { [weak self] outcome in
            guard let self else { return }
            switch outcome {
            case .success:
                // The host rebuilds the banner with the re-verified status.
                break
            case let .failure(message):
                fetchFailures[identifier] = message
                refreshContent()
            }
        }
    }

    /// Identifier for the "Report Issue" button: the fingerprint when
    /// known, otherwise the signer label.
    private func reportIdentifier(for signer: Signer) -> String {
        if let fingerprint = signer.context?.fingerprint, !fingerprint.isEmpty {
            return fingerprint
        }
        return signer.label
    }

    @objc private func reportIssue(_ sender: NSButton) {
        guard let identifier = sender.identifier?.rawValue,
              let signer = signers.first(where: { reportIdentifier(for: $0) == identifier }),
              let url = Self.reportIssueURL(for: signer)
        else {
            return
        }
        NSWorkspace.shared.open(url)
    }

    /// Pre-filled GitHub issue URL for the "Report Issue" action of an
    /// invalid signature, carrying the verification status and failure
    /// reason so the report is actionable without the user having to
    /// describe them.
    static func reportIssueURL(for signer: Signer) -> URL? {
        let status = signer.context.flatMap { RnpSignatureStatus(rawValue: $0.status) } ?? .unknown
        var components = URLComponents(
            string: "https://github.com/rnpgp/rnp-mailapp-extension/issues/new"
        )
        components?.queryItems = [
            URLQueryItem(name: "title", value: "Invalid OpenPGP signature in Apple Mail"),
            URLQueryItem(name: "body", value: """
            ## What happened

            Mail showed an "Invalid signature" warning for a message.

            - Signer: \(signer.label)
            - Signature status: \(status.rawValue)
            - Failure reason: \(signer.context?.invalidReason ?? "unknown")
            - Signer key fingerprint: \(signer.context?.fingerprint ?? "unknown")

            ## What you expected

            The signature to verify.

            ## Additional context

            (Screenshots, whether the sender recently changed or revoked their key, etc.)
            """),
        ]
        return components?.url
    }
}

// MARK: - Brand palette

/// RNP brand colors for the AppKit banner, mirroring `RnpBrand` in the
/// SwiftUI design system (`Sources/RnpMailUI/DesignSystem.swift`).
enum BannerBrand {
    /// Primary brand blue (#1A7BEC): header glyph, links, encryption tint.
    static let primary = NSColor(srgbRed: 0x1A / 255, green: 0x7B / 255, blue: 0xEC / 255, alpha: 1)

    /// Verified trust state (light/dark aware).
    static let verified = dynamic(light: (0x05, 0xA3, 0x77), dark: (0x2F, 0xD3, 0x9A))
    /// Unverified keys and caution states (light/dark aware).
    static let unverified = dynamic(light: (0xC2, 0x41, 0x0C), dark: (0xF5, 0xA6, 0x23))
    /// Critical states: key problems, invalid signatures (light/dark aware).
    static let critical = dynamic(light: (0xD9, 0x2D, 0x20), dark: (0xFF, 0x5A, 0x52))

    private static func dynamic(
        light: (UInt8, UInt8, UInt8),
        dark: (UInt8, UInt8, UInt8)
    ) -> NSColor {
        NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            let rgb = isDark ? dark : light
            return NSColor(
                srgbRed: CGFloat(rgb.0) / 255,
                green: CGFloat(rgb.1) / 255,
                blue: CGFloat(rgb.2) / 255,
                alpha: 1
            )
        }
    }
}

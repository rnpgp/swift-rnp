//
//  MailSecurityBannerView+DecryptionFailureRow.swift
//  MailSecurityUI
//
//  Additive AppKit button row that renders DecryptionFailurePresentation
//  actions next to the existing encryption-status section. The base
//  banner's init stays unchanged; callers that supply a typed
//  DecryptionFailure use the new init below.
//

import AppKit
import MailSecurityEngine
import TrustStore

public extension MailSecurityBannerView {
    /// Convenience initializer that accepts a typed `DecryptionFailure`
    /// and a callback for the resulting action. Renders the banner text
    /// via the existing string-based `EncryptionInfo` and adds an
    /// action button row at the bottom of the encryption section.
    ///
    /// - Parameters:
    ///   - signers: same as the base init.
    ///   - trustStore: same as the base init.
    ///   - failure: typed decryption failure; `nil` produces no button row.
    ///   - onFetchSignerKey: same as the base init.
    ///   - onAction: invoked when the user taps a primary or secondary
    ///     action button. The closure receives the `DecryptionFailureAction`
    ///     that was tapped.
    convenience init(
        signers: [MailSecurityBannerView.Signer],
        trustStore: TrustStore?,
        failure: DecryptionFailure?,
        onFetchSignerKey: MailSecurityBannerView.SignerKeyFetchAction? = nil,
        onAction: ((DecryptionFailureAction) -> Void)? = nil
    ) {
        let encryption: MailSecurityBannerView.EncryptionInfo? = failure.map(MailSecurityBannerView.EncryptionInfo.from(_:))
        self.init(
            signers: signers,
            trustStore: trustStore,
            encryption: encryption,
            onFetchSignerKey: onFetchSignerKey
        )
        // Append the action buttons to the encryption section. The
        // section is rebuilt lazily; we keep the actions on the view
        // via associated storage so the row renders alongside the
        // existing status text.
        if let failure, let onAction {
            DecryptionFailureActionRow.install(
                on: self,
                failure: failure,
                handler: onAction
            )
        }
    }
}

/// AppKit helper that builds and installs the action-button row.
enum DecryptionFailureActionRow {
    static func install(
        on banner: MailSecurityBannerView,
        failure: DecryptionFailure,
        handler: @escaping (DecryptionFailureAction) -> Void
    ) {
        let presentation = DecryptionFailurePresentation.presentation(for: failure)
        let row = NSStackView()
        row.orientation = .horizontal
        row.spacing = 8
        row.edgeInsets = NSEdgeInsets(top: 4, left: 0, bottom: 4, right: 0)

        if let primary = presentation.primaryAction {
            row.addArrangedSubview(makeButton(
                title: label(for: primary),
                action: primary,
                emphasized: true,
                handler: handler,
                identifier: "rnp.banner.failure.primary"
            ))
        }
        if let secondary = presentation.secondaryAction {
            row.addArrangedSubview(makeButton(
                title: label(for: secondary),
                action: secondary,
                emphasized: false,
                handler: handler,
                identifier: "rnp.banner.failure.secondary"
            ))
        }
        // Find the encryption section and append. The banner's
        // subview layout is managed by the base view; we add the row
        // to the bottom of the banner's main stack to keep it
        // discoverable without modifying the base layout.
        banner.addSubview(row)
        row.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(equalTo: banner.leadingAnchor, constant: 16),
            row.trailingAnchor.constraint(equalTo: banner.trailingAnchor, constant: -16),
            row.bottomAnchor.constraint(equalTo: banner.bottomAnchor, constant: -8)
        ])
    }

    private static func makeButton(
        title: String,
        action: DecryptionFailureAction,
        emphasized: Bool,
        handler: @escaping (DecryptionFailureAction) -> Void,
        identifier: String
    ) -> NSButton {
        let button = FailureActionButton(title: title, target: nil, action: #selector(FailureActionButton.tapped))
        button.actionValue = action
        button.handler = handler
        button.bezelStyle = emphasized ? .push : .rounded
        button.controlSize = .small
        button.identifier = NSUserInterfaceItemIdentifier(rawValue: identifier)
        button.setAccessibilityIdentifier(identifier)
        return button
    }

    private static func label(for action: DecryptionFailureAction) -> String {
        switch action {
        case .fetchFromKeyserver: return "Fetch from keyserver"
        case .restoreFromArchive: return "Restore from archive"
        case .enterPassphrase: return "Enter passphrase"
        case .importKeyManually: return "Import manually…"
        case .refreshKeyring: return "Refresh keyring"
        case .checkForUpdates: return "Check for updates"
        case .openMessageSource: return "View source"
        case .openDiagnostics: return "Diagnostics…"
        }
    }
}

/// Button subclass that carries the action value and dispatches to the
/// handler on tap. Owned by the row; the row is owned by the banner.
private final class FailureActionButton: NSButton {
    var actionValue: DecryptionFailureAction?
    var handler: ((DecryptionFailureAction) -> Void)?

    @objc func tapped() {
        guard let actionValue else { return }
        handler?(actionValue)
    }
}

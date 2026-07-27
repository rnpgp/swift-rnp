//
//  KeyDetailView.swift
//  swift-rnp
//
//  Inspector-style detail view for an OpenPGP key, shown in the container
//  app's detail column and (on macOS 12 or on demand) in a sheet.
//
//  Layout: a pinned header (key avatar, user ID, badges) with the trust
//  card underneath for recipient keys, then a segmented section switcher
//  (Overview / Subkeys / User IDs) and a scrolling content area.
//

import AppKit
import CoreImage
import SwiftUI
import MailSecurityEngine
import TrustStore
import UniformTypeIdentifiers

/// Actions available for a key in the detail view.
public struct KeyDetailActions {
    public var onExportPublic: () -> Void
    public var onExportSecret: () -> Void
    public var onDelete: () -> Void
    public var onExtendExpiry: () -> Void
    public var onRevoke: () -> Void
    public var onRotateEncryption: () -> Void
    public var onRotateSigning: () -> Void
    public var onPublish: () -> Void
    public var onAddUserID: () -> Void
    public var onArchive: () -> Void
    public var onMarkVerified: () -> Void
    /// Rejects the key as the new binding for its address, keeping the
    /// previously recorded binding (key-change conflict resolution).
    public var onRejectNewKey: () -> Void
    /// Opens the trust history for the key's address.
    public var onShowTrustHistory: () -> Void

    public init(
        onExportPublic: @escaping () -> Void = {},
        onExportSecret: @escaping () -> Void = {},
        onDelete: @escaping () -> Void = {},
        onExtendExpiry: @escaping () -> Void = {},
        onRevoke: @escaping () -> Void = {},
        onRotateEncryption: @escaping () -> Void = {},
        onRotateSigning: @escaping () -> Void = {},
        onPublish: @escaping () -> Void = {},
        onAddUserID: @escaping () -> Void = {},
        onArchive: @escaping () -> Void = {},
        onMarkVerified: @escaping () -> Void = {},
        onRejectNewKey: @escaping () -> Void = {},
        onShowTrustHistory: @escaping () -> Void = {}
    ) {
        self.onExportPublic = onExportPublic
        self.onExportSecret = onExportSecret
        self.onDelete = onDelete
        self.onExtendExpiry = onExtendExpiry
        self.onRevoke = onRevoke
        self.onRotateEncryption = onRotateEncryption
        self.onRotateSigning = onRotateSigning
        self.onPublish = onPublish
        self.onAddUserID = onAddUserID
        self.onArchive = onArchive
        self.onMarkVerified = onMarkVerified
        self.onRejectNewKey = onRejectNewKey
        self.onShowTrustHistory = onShowTrustHistory
    }
}

/// Detail view showing metadata and subkeys for a single OpenPGP key.
public struct KeyDetailView: View {
    public let key: KeyInfo
    public let subkeys: [SubkeyInfo]
    public let isRecipient: Bool
    public let trustState: TrustState
    public let actions: KeyDetailActions
    /// Whether this key is the newly seen key of an unresolved key-change
    /// conflict for its address; shows the "Keep old binding" reject action.
    public let hasPendingKeyChange: Bool
    /// Prefix for the view's accessibility identifiers. The sheet uses the
    /// default `keydetail`; embedding contexts (e.g. the split-view detail
    /// column) pass a distinct prefix so identifiers stay unique when both
    /// presentations are on screen.
    public let identifierPrefix: String

    @State private var showDeleteConfirmation = false
    @State private var showSecretExportConfirmation = false
    @State private var selectedSection: DetailSection = .overview
    /// Transient checkmark state after copying the fingerprint.
    @State private var didCopyFingerprint = false

    /// Sections available in the segmented switcher. Signatures and history
    /// are intentionally absent: the engine does not expose that data.
    private enum DetailSection: String, CaseIterable, Identifiable {
        case overview
        case subkeys
        case userIDs

        var id: String { rawValue }

        var localizedName: String {
            switch self {
            case .overview:
                return "detail.tab.overview".localized
            case .subkeys:
                return "detail.tab.subkeys".localized
            case .userIDs:
                return "detail.tab.userIDs".localized
            }
        }
    }

    public init(
        key: KeyInfo,
        subkeys: [SubkeyInfo],
        isRecipient: Bool,
        trustState: TrustState = .unverified,
        hasPendingKeyChange: Bool = false,
        actions: KeyDetailActions,
        identifierPrefix: String = "keydetail"
    ) {
        self.key = key
        self.subkeys = subkeys
        self.isRecipient = isRecipient
        self.trustState = trustState
        self.hasPendingKeyChange = hasPendingKeyChange
        self.actions = actions
        self.identifierPrefix = identifierPrefix
    }

    public var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: RnpSpacing.md) {
                header
                if isRecipient {
                    trustCard
                }
                sectionPicker
            }
            .padding(.horizontal, RnpSpacing.xl)
            .padding(.top, RnpSpacing.lg)
            .padding(.bottom, RnpSpacing.sm)

            Divider()

            ScrollView {
                tabContent
                    .padding(RnpSpacing.xl)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .id(selectedSection)
                    .transition(.opacity)
            }
            .animation(.default, value: selectedSection)
        }
        .alert("detail.delete.title", isPresented: $showDeleteConfirmation) {
            Button("button.delete", role: .destructive) { actions.onDelete() }
            Button("button.cancel", role: .cancel) {}
        } message: {
            Text("detail.delete.message")
        }
        .alert(
            "detail.exportSecret.title",
            isPresented: $showSecretExportConfirmation
        ) {
            Button("button.export", role: .destructive) { actions.onExportSecret() }
            Button("button.cancel", role: .cancel) {}
        } message: {
            Text("detail.exportSecret.message")
        }
    }

    // MARK: - Header

    private var trustPresentation: TrustPresentation {
        TrustPresentation(state: trustState)
    }

    private var header: some View {
        HStack(alignment: .center, spacing: RnpSpacing.md) {
            RnpKeyAvatar(
                hasSecret: key.hasSecret,
                isDimmed: key.isRevoked || key.isExpired,
                size: 56
            )
            VStack(alignment: .leading, spacing: RnpSpacing.xxs + 2) {
                Text(key.primaryUserID)
                    .font(.title2.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: RnpSpacing.xs) {
                    Text(key.algorithmLabel)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, RnpSpacing.xxs + 2)
                        .padding(.vertical, 2)
                        .background(
                            .quaternary,
                            in: RoundedRectangle(cornerRadius: RnpRadius.badge, style: .continuous)
                        )
                    if key.isRevoked {
                        RnpBadge(text: "badge.revoked".localized, color: RnpBrand.critical)
                    } else if key.isExpired {
                        RnpBadge(text: "badge.expired".localized, color: RnpBrand.critical)
                    } else if isRecipient {
                        miniTrustBadge
                    }
                }
            }
            Spacer(minLength: 0)
        }
    }

    /// Compact trust capsule shown in the header. The actionable trust card
    /// below carries the accessibility identifiers.
    private var miniTrustBadge: some View {
        HStack(spacing: RnpSpacing.xxs) {
            Image(systemName: trustPresentation.iconName)
                .imageScale(.small)
            Text(trustPresentation.labelKey.localized)
                .font(.caption.weight(.medium))
        }
        .foregroundStyle(trustPresentation.color)
        .padding(.horizontal, RnpSpacing.xxs + 2)
        .padding(.vertical, 2)
        .background(
            trustPresentation.color.opacity(0.12),
            in: RoundedRectangle(cornerRadius: RnpRadius.badge, style: .continuous)
        )
        .accessibilityHidden(true)
    }

    // MARK: - Trust card

    private var trustCard: some View {
        HStack(alignment: .center, spacing: RnpSpacing.sm) {
            Image(systemName: trustPresentation.iconName)
                .font(.system(size: 28))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(trustPresentation.color)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: RnpSpacing.xxs) {
                Text(trustPresentation.labelKey.localized)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(trustPresentation.color)
                    .accessibilityIdentifier("\(identifierPrefix).trust-badge")
                    .accessibilityValue(trustState.rawValue)
                Text(trustPresentation.descriptionKey.localized)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: RnpSpacing.xs)
            VStack(alignment: .trailing, spacing: RnpSpacing.xs) {
                if trustState != .verified {
                    Button("detail.markVerified") { actions.onMarkVerified() }
                        .buttonStyle(.borderedProminent)
                        .tint(trustState == .problem ? RnpBrand.critical : Color.accentColor)
                        .accessibilityIdentifier("\(identifierPrefix).mark-verified")
                }
                if hasPendingKeyChange {
                    Button("detail.keepOldBinding") { actions.onRejectNewKey() }
                        .buttonStyle(.bordered)
                        .accessibilityIdentifier("\(identifierPrefix).keep-old-binding")
                        .help("detail.keepOldBinding.help")
                }
                Button("trustHistory.title") { actions.onShowTrustHistory() }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .accessibilityIdentifier("\(identifierPrefix).trust-history")
                    .help("trustHistory.title")
            }
        }
        .padding(RnpSpacing.sm)
        .background(
            trustPresentation.color.opacity(0.09),
            in: RoundedRectangle(cornerRadius: RnpRadius.panel, style: .continuous)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RnpRadius.panel, style: .continuous)
                .strokeBorder(trustPresentation.color.opacity(0.25), lineWidth: 1)
        )
        .animation(.default, value: trustState)
    }

    // MARK: - Section switcher

    private var sectionPicker: some View {
        Picker("detail.sections", selection: $selectedSection) {
            ForEach(DetailSection.allCases) { section in
                Text(section.localizedName).tag(section)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .accessibilityIdentifier("\(identifierPrefix).section-picker")
    }

    @ViewBuilder
    private var tabContent: some View {
        switch selectedSection {
        case .overview:
            overviewTab
        case .subkeys:
            subkeysTab
        case .userIDs:
            userIDsTab
        }
    }

    // MARK: - Overview

    private var overviewTab: some View {
        VStack(alignment: .leading, spacing: RnpSpacing.xl) {
            fingerprintCard
            metadataSection
            if !isRecipient {
                actionsSection
            }
        }
    }

    private var fingerprintCard: some View {
        VStack(alignment: .leading, spacing: RnpSpacing.xs) {
            Text("detail.fingerprint")
                .font(.headline)
            HStack(alignment: .top, spacing: RnpSpacing.lg) {
                VStack(alignment: .leading, spacing: RnpSpacing.xs) {
                    Text(key.fingerprint.groupedFingerprintBlocks)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    Button {
                        copyToClipboard(key.fingerprint)
                        didCopyFingerprint = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) {
                            didCopyFingerprint = false
                        }
                    } label: {
                        Label(
                            didCopyFingerprint ? "detail.copied".localized : "contextmenu.copyFingerprint".localized,
                            systemImage: didCopyFingerprint ? "checkmark" : "doc.on.doc"
                        )
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .tint(didCopyFingerprint ? RnpBrand.verified : nil)
                    .animation(.easeInOut(duration: 0.15), value: didCopyFingerprint)
                    .help("detail.copyFingerprint.help")
                    .accessibilityIdentifier("\(identifierPrefix).copy-fingerprint")
                    .accessibilityLabel("detail.copyFingerprint.help")
                }
                Spacer(minLength: 0)
                qrCodeCard
            }
            .padding(RnpSpacing.md)
            .background(
                .regularMaterial,
                in: RoundedRectangle(cornerRadius: RnpRadius.panel, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: RnpRadius.panel, style: .continuous)
                    .strokeBorder(Color(nsColor: .separatorColor), lineWidth: 1)
            )
        }
    }

    @ViewBuilder
    private var qrCodeCard: some View {
        if let qrCode = qrCodeImage {
            VStack(spacing: RnpSpacing.xs) {
                Image(nsImage: qrCode)
                    .resizable()
                    .interpolation(.none)
                    .frame(width: 96, height: 96)
                    .padding(RnpSpacing.xs)
                    .background(Color.white, in: RoundedRectangle(cornerRadius: RnpRadius.card, style: .continuous))
                    .shadow(color: .black.opacity(0.12), radius: 2, y: 1)
                Text("detail.qrCode")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Button {
                    saveQRCodeImage()
                } label: {
                    Label("detail.qr.save", systemImage: "square.and.arrow.down")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .accessibilityIdentifier("\(identifierPrefix).qr-save")
            }
            .accessibilityElement(children: .contain)
            .accessibilityLabel("detail.qrCode".localized)
        }
    }

    /// QR code for the `OPENPGP4FPR:<fingerprint>` URI, rendered via the
    /// system's CoreImage QR generator.
    private var qrCodeImage: NSImage? {
        guard let scaled = scaledQRCode(targetSize: 288) else { return nil }
        let representation = NSCIImageRep(ciImage: scaled)
        let image = NSImage(size: representation.size)
        image.addRepresentation(representation)
        return image
    }

    private func scaledQRCode(targetSize: CGFloat) -> CIImage? {
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(Data("OPENPGP4FPR:\(key.fingerprint)".utf8), forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let output = filter.outputImage else { return nil }
        let scale = targetSize / max(output.extent.width, output.extent.height)
        return output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
    }

    /// Offers to save the fingerprint QR code as a PNG via the save panel
    /// (allowed by the user-selected read/write sandbox entitlement).
    private func saveQRCodeImage() {
        guard let scaled = scaledQRCode(targetSize: 512),
              let png = NSBitmapImageRep(ciImage: scaled).representation(using: .png, properties: [:])
        else {
            return
        }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.png]
        panel.nameFieldStringValue = "OPENPGP4FPR-\(key.fingerprint.prefix(8)).png"
        panel.message = "detail.qr.save.panelMessage".localized
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? png.write(to: url, options: .atomic)
    }

    // MARK: - Metadata

    private var metadataSection: some View {
        VStack(alignment: .leading, spacing: RnpSpacing.xs) {
            Text("detail.metadata.title")
                .font(.headline)
            VStack(alignment: .leading, spacing: RnpSpacing.xxs + 2) {
                metadataRow("detail.algorithm") {
                    Text(key.algorithmLabel)
                }
                metadataRow("table.type") {
                    Text(key.hasSecret ? "key.type.keyPair".localized : "key.type.publicOnly".localized)
                }
                metadataRow("detail.created") {
                    Text(key.creationDate, style: .date)
                }
                metadataRow("detail.expires") {
                    if let expiration = key.expirationDate {
                        Text(expiration, style: .date)
                    } else {
                        Text("detail.subkeys.never")
                    }
                }
            }
        }
    }

    private func metadataRow<Content: View>(
        _ label: LocalizedStringKey,
        @ViewBuilder value: () -> Content
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: RnpSpacing.sm) {
            Text(label)
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(width: 90, alignment: .trailing)
            value()
                .font(.callout)
                .textSelection(.enabled)
        }
    }

    // MARK: - User IDs

    private var userIDsTab: some View {
        VStack(alignment: .leading, spacing: RnpSpacing.xs) {
            Text("detail.userIDs")
                .font(.headline)
            VStack(spacing: 0) {
                ForEach(Array(key.userIDs.enumerated()), id: \.element) { index, userID in
                    HStack(spacing: RnpSpacing.xs) {
                        Image(systemName: index == 0 ? "person.crop.circle.fill" : "person.crop.circle")
                            .foregroundStyle(index == 0 ? Color.accentColor : Color.secondary)
                            .accessibilityHidden(true)
                        Text(userID)
                            .textSelection(.enabled)
                        if index == 0 {
                            RnpBadge(text: "detail.userIDs.primary".localized, color: .accentColor)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(.vertical, RnpSpacing.xs)
                    .padding(.horizontal, RnpSpacing.xxs)
                    if index < key.userIDs.count - 1 {
                        Divider()
                    }
                }
            }
        }
    }

    // MARK: - Subkeys

    private var subkeysTab: some View {
        VStack(alignment: .leading, spacing: RnpSpacing.xs) {
            Text(String(format: "detail.subkeys.title".localized, subkeys.count))
                .font(.headline)
            Table(subkeys) {
                TableColumn("detail.subkeys.algorithm") { subkey in
                    Text(subkey.algorithmLabel)
                }
                TableColumn("detail.subkeys.created") { subkey in
                    Text(subkey.creationDate, style: .date)
                        .foregroundStyle(.secondary)
                }
                TableColumn("detail.subkeys.expires") { subkey in
                    if let date = subkey.expirationDate {
                        Text(date, style: .date)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("detail.subkeys.never")
                            .foregroundStyle(.secondary)
                    }
                }
                TableColumn("detail.subkeys.capabilities") { subkey in
                    Text(subkey.capabilities.joined(separator: ", ").capitalized)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(minHeight: 160)
        }
    }

    // MARK: - Actions

    private var actionsSection: some View {
        VStack(alignment: .leading, spacing: RnpSpacing.sm) {
            Text("detail.actions.title")
                .font(.headline)
            VStack(alignment: .leading, spacing: RnpSpacing.xs) {
                HStack(spacing: RnpSpacing.sm) {
                    Button("detail.exportPublic") { actions.onExportPublic() }
                        .accessibilityIdentifier("\(identifierPrefix).export-public")
                    Button("detail.exportSecret") { showSecretExportConfirmation = true }
                        .accessibilityIdentifier("\(identifierPrefix).export-secret")
                    Button("detail.publish") { actions.onPublish() }
                        .accessibilityIdentifier("\(identifierPrefix).publish")
                }
                HStack(spacing: RnpSpacing.sm) {
                    Button("detail.extendExpiry") { actions.onExtendExpiry() }
                        .accessibilityIdentifier("\(identifierPrefix).extend-expiry")
                    Button("detail.rotateEncryption") { actions.onRotateEncryption() }
                        .accessibilityIdentifier("\(identifierPrefix).rotate-encryption")
                    Button("detail.rotateSigning") { actions.onRotateSigning() }
                        .accessibilityIdentifier("\(identifierPrefix).rotate-signing")
                }
                if !isRecipient {
                    HStack(spacing: RnpSpacing.sm) {
                        Button("detail.addUserID") { actions.onAddUserID() }
                            .accessibilityIdentifier("\(identifierPrefix).add-userid")
                    }
                }
                HStack(spacing: RnpSpacing.sm) {
                    Button("detail.revoke") { actions.onRevoke() }
                        .accessibilityIdentifier("\(identifierPrefix).revoke")
                    Button("detail.archive") { actions.onArchive() }
                        .accessibilityIdentifier("\(identifierPrefix).archive")
                    Button("detail.deleteKey", role: .destructive) { showDeleteConfirmation = true }
                        .accessibilityIdentifier("\(identifierPrefix).delete")
                }
            }
            .buttonStyle(.bordered)
        }
    }

    // MARK: - Helpers

    private func copyToClipboard(_ text: String) {
        #if canImport(AppKit)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        #endif
    }
}

#if DEBUG
struct KeyDetailView_Previews: PreviewProvider {
    static var previews: some View {
        KeyDetailView(
            key: KeyInfo(
                fingerprint: "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890",
                primaryUserID: "Preview <preview@example.com>",
                userIDs: ["Preview <preview@example.com>"],
                hasSecret: true,
                algorithm: "RSA",
                bits: 3072,
                creationDate: Date(),
                expirationDate: Date().addingTimeInterval(86400 * 365),
                isRevoked: false,
                subkeyCount: 1
            ),
            subkeys: [],
            isRecipient: true,
            trustState: .unverified,
            actions: KeyDetailActions()
        )
    }
}
#endif

//
//  InlineRecoverySheets.swift
//  RnpMailUI
//
//  View modifiers that the container app attaches at compose / banner /
//  onboarding to handle inline recovery. Each modifier observes a
//  binding to an optional `RecoveryAction` and presents the matching
//  sheet when one is set.
//
//  The sheets themselves are mostly placeholders that call back into
//  the container-app coordinator; the engine-layer types they
//  manipulate (KeyLifecycle, KeyManager) are already in place.
//

import KeyLifecycle
import MailSecurityEngine
import SwiftUI

/// Surfaced inline-recovery actions. Each maps to a sheet the user
/// can dismiss or complete in-place.
public enum InlineRecoveryAction: Identifiable, Equatable {
    case extendExpiry(fingerprint: String)
    case rotateEncryptionSubkey(fingerprint: String)
    case rotateSigningSubkey(fingerprint: String)
    case generateReplacementKey
    case fetchLatestFromKeyserver(address: String)
    case verifyFingerprint(fingerprint: String)
    case archiveKey(fingerprint: String)
    case notifyContacts(fingerprint: String)

    public var id: String {
        switch self {
        case let .extendExpiry(fpr): return "extend-\(fpr)"
        case let .rotateEncryptionSubkey(fpr): return "rotate-enc-\(fpr)"
        case let .rotateSigningSubkey(fpr): return "rotate-sig-\(fpr)"
        case .generateReplacementKey: return "generate-replacement"
        case let .fetchLatestFromKeyserver(addr): return "fetch-\(addr)"
        case let .verifyFingerprint(fpr): return "verify-\(fpr)"
        case let .archiveKey(fpr): return "archive-\(fpr)"
        case let .notifyContacts(fpr): return "notify-\(fpr)"
        }
    }
}

/// Maps an engine-layer `RecoveryAction` to an `InlineRecoveryAction`.
/// Kept here so callers don't repeat the switch.
public extension RecoveryAction {
    var inline: InlineRecoveryAction? {
        switch self {
        case let .extendExpiry(fpr, _): return .extendExpiry(fingerprint: fpr)
        case let .rotateEncryptionSubkey(fpr): return .rotateEncryptionSubkey(fingerprint: fpr)
        case let .rotateSigningSubkey(fpr): return .rotateSigningSubkey(fingerprint: fpr)
        case .generateReplacementKey: return .generateReplacementKey
        case let .fetchLatestFromKeyserver(addr): return .fetchLatestFromKeyserver(address: addr)
        case let .verifyFingerprint(fpr): return .verifyFingerprint(fingerprint: fpr)
        case let .archiveKey(fpr): return .archiveKey(fingerprint: fpr)
        case let .notifyContacts(fpr): return .notifyContacts(fingerprint: fpr)
        case .contactOutOfBand, .publishKey, .informationalOnly:
            return nil
        }
    }
}

/// Container view modifier that presents the right sheet for an
/// `InlineRecoveryAction` binding. The container app uses this on
/// whatever view hosts the banner / compose / onboarding.
public struct InlineRecoverySheetsModifier: ViewModifier {
    @Binding var action: InlineRecoveryAction?
    public let handlers: InlineRecoveryHandlers

    public init(action: Binding<InlineRecoveryAction?>, handlers: InlineRecoveryHandlers) {
        _action = action
        self.handlers = handlers
    }

    public func body(content: Content) -> some View {
        content.sheet(item: $action) { value in
            sheetView(for: value)
        }
    }

    @ViewBuilder
    private func sheetView(for value: InlineRecoveryAction) -> some View {
        switch value {
        case let .extendExpiry(fpr):
            handlers.extendExpirySheet(fpr)
        case let .rotateEncryptionSubkey(fpr):
            handlers.rotateEncryptionSubkeySheet(fpr)
        case let .rotateSigningSubkey(fpr):
            handlers.rotateSigningSubkeySheet(fpr)
        case .generateReplacementKey:
            handlers.generateReplacementSheet()
        case let .fetchLatestFromKeyserver(addr):
            handlers.fetchFromKeyserverSheet(addr)
        case let .verifyFingerprint(fpr):
            handlers.verifyFingerprintSheet(fpr)
        case let .archiveKey(fpr):
            handlers.archiveKeySheet(fpr)
        case let .notifyContacts(fpr):
            handlers.notifyContactsSheet(fpr)
        }
    }
}

/// Closure bundle supplied by the container app. Each closure returns
/// the sheet `View` for one recovery action. Defaulting to a
/// placeholder view keeps the type constructible in tests / previews.
public struct InlineRecoveryHandlers {
    public var extendExpirySheet: (String) -> AnyView
    public var rotateEncryptionSubkeySheet: (String) -> AnyView
    public var rotateSigningSubkeySheet: (String) -> AnyView
    public var generateReplacementSheet: () -> AnyView
    public var fetchFromKeyserverSheet: (String) -> AnyView
    public var verifyFingerprintSheet: (String) -> AnyView
    public var archiveKeySheet: (String) -> AnyView
    public var notifyContactsSheet: (String) -> AnyView

    public init(
        extendExpirySheet: @escaping (String) -> AnyView = { fpr in AnyView(Text("Extend expiry for \(fpr)").padding()) },
        rotateEncryptionSubkeySheet: @escaping (String) -> AnyView = { fpr in AnyView(Text("Rotate encryption subkey for \(fpr)").padding()) },
        rotateSigningSubkeySheet: @escaping (String) -> AnyView = { fpr in AnyView(Text("Rotate signing subkey for \(fpr)").padding()) },
        generateReplacementSheet: @escaping () -> AnyView = { AnyView(Text("Generate replacement key").padding()) },
        fetchFromKeyserverSheet: @escaping (String) -> AnyView = { addr in AnyView(Text("Fetch latest for \(addr)").padding()) },
        verifyFingerprintSheet: @escaping (String) -> AnyView = { fpr in AnyView(Text("Verify \(fpr)").padding()) },
        archiveKeySheet: @escaping (String) -> AnyView = { fpr in AnyView(Text("Archive \(fpr)").padding()) },
        notifyContactsSheet: @escaping (String) -> AnyView = { fpr in AnyView(Text("Notify contacts for \(fpr)").padding()) }
    ) {
        self.extendExpirySheet = extendExpirySheet
        self.rotateEncryptionSubkeySheet = rotateEncryptionSubkeySheet
        self.rotateSigningSubkeySheet = rotateSigningSubkeySheet
        self.generateReplacementSheet = generateReplacementSheet
        self.fetchFromKeyserverSheet = fetchFromKeyserverSheet
        self.verifyFingerprintSheet = verifyFingerprintSheet
        self.archiveKeySheet = archiveKeySheet
        self.notifyContactsSheet = notifyContactsSheet
    }
}

public extension View {
    /// Attaches inline-recovery sheets driven by an
    /// `InlineRecoveryAction` binding.
    func inlineRecoverySheets(
        action: Binding<InlineRecoveryAction?>,
        handlers: InlineRecoveryHandlers = InlineRecoveryHandlers()
    ) -> some View {
        modifier(InlineRecoverySheetsModifier(action: action, handlers: handlers))
    }
}

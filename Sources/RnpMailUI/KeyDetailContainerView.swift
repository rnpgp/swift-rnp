//
//  KeyDetailContainerView.swift
//  RnpMailUI
//
//  Self-contained KeyDetailView wrapper that uses EngineEnvironment to
//  supply the KeyManager for sheet presentation (AddUserID, Delete
//  forever). The container app supplies the engine once at the
//  navigation root via `.engineEnvironment(engine)`; this wrapper
//  then handles the in-view sheets without each container-app call
//  site having to wire them up.
//

import MailSecurityEngine
import SwiftUI
import TrustStore

public struct KeyDetailContainerView: View {
    public let key: KeyInfo
    public let subkeys: [SubkeyInfo]
    public let isRecipient: Bool
    public let trustState: TrustStateAlias
    public let hasPendingKeyChange: Bool

    @Environment(\.engine) private var engine
    @State private var presentedSheet: SheetKind?

    public enum SheetKind: Identifiable {
        case addUserID
        case deleteForever
        public var id: Self { self }
    }

    /// Local TrustState alias to avoid importing the TrustStore module
    /// symbol directly here (it's already re-exported by MailSecurityEngine
    /// through KeyManager.trustStore). The container-app caller passes
    /// the same value it would have passed to KeyDetailView.
    public enum TrustStateAlias: String, Sendable {
        case unverified, verified, problem
    }

    public init(
        key: KeyInfo,
        subkeys: [SubkeyInfo] = [],
        isRecipient: Bool = false,
        trustState: TrustStateAlias = .unverified,
        hasPendingKeyChange: Bool = false
    ) {
        self.key = key
        self.subkeys = subkeys
        self.isRecipient = isRecipient
        self.trustState = trustState
        self.hasPendingKeyChange = hasPendingKeyChange
    }

    public var body: some View {
        KeyDetailView(
            key: key,
            subkeys: subkeys,
            isRecipient: isRecipient,
            trustState: mapTrustState(trustState),
            hasPendingKeyChange: hasPendingKeyChange,
            actions: KeyDetailActions(
                onExportPublic: { },
                onExportSecret: { },
                onDelete: { presentedSheet = .deleteForever },
                onExtendExpiry: { },
                onRevoke: { },
                onRotateEncryption: { },
                onRotateSigning: { },
                onPublish: { },
                onAddUserID: { presentedSheet = .addUserID },
                onArchive: { },
                onMarkVerified: { },
                onRejectNewKey: { },
                onShowTrustHistory: { }
            )
        )
        .sheet(item: $presentedSheet) { kind in
            switch kind {
            case .addUserID:
                if let km = engine?.keyManager {
                    AddUserIDForm(viewModel: AddUserIDViewModel(
                        keyFingerprint: key.fingerprint,
                        keyManager: km
                    ))
                } else {
                    Text("Engine unavailable").padding()
                }
            case .deleteForever:
                DeleteForeverConfirmation(
                    viewModel: DeleteForeverConfirmationViewModel(
                        fingerprint: key.fingerprint,
                        primaryUserID: key.primaryUserID
                    ),
                    onConfirm: {
                        if let km = engine?.keyManager {
                            try? km.deleteKey(fingerprint: key.fingerprint)
                        }
                    }
                )
            }
        }
    }

    private func mapTrustState(_ alias: TrustStateAlias) -> TrustState {
        switch alias {
        case .unverified: return .unverified
        case .verified: return .verified
        case .problem: return .problem
        }
    }
}

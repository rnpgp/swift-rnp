//
//  ArchivedKeysSection.swift
//  RnpMailUI
//
//  Collapsible section showing archived (decrypt-only) keys with
//  restore-to-active and delete-forever actions. Intended as a
//  component within a keys list. Reads from KeyManager.archivedKeys()
//  and consults the engine environment.
//

import MailSecurityEngine
import SwiftUI

@MainActor
public final class ArchivedKeysViewModel: ObservableObject {
    @Published public private(set) var archived: [KeyInfo] = []
    @Published public var isExpanded: Bool = false
    @Published public var errorMessage: String?

    private let keyManager: KeyManager?
    public let onRestore: (String) -> Void
    public let onDeleteForever: (String) -> Void

    public init(
        keyManager: KeyManager?,
        onRestore: @escaping (String) -> Void,
        onDeleteForever: @escaping (String) -> Void
    ) {
        self.keyManager = keyManager
        self.onRestore = onRestore
        self.onDeleteForever = onDeleteForever
    }

    public func refresh() {
        guard let keyManager else {
            archived = []
            return
        }
        do {
            archived = try keyManager.archivedKeys()
            errorMessage = nil
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }
}

public struct ArchivedKeysSection: View {
    @StateObject public var viewModel: ArchivedKeysViewModel

    public init(viewModel: ArchivedKeysViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    public var body: some View {
        DisclosureGroup(isExpanded: $viewModel.isExpanded) {
            if viewModel.archived.isEmpty {
                Text("No archived keys.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 4)
            } else {
                ForEach(viewModel.archived) { key in
                    ArchivedKeyRow(
                        key: key,
                        onRestore: { viewModel.onRestore(key.fingerprint) },
                        onDeleteForever: { viewModel.onDeleteForever(key.fingerprint) }
                    )
                }
            }
        } label: {
            HStack {
                Label("Archived", systemImage: "archivebox")
                    .font(.headline)
                Spacer()
                Text("\(viewModel.archived.count)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(Color(nsColor: .separatorColor), in: Capsule())
            }
        }
        .onAppear { viewModel.refresh() }
    }
}

private struct ArchivedKeyRow: View {
    let key: KeyInfo
    let onRestore: () -> Void
    let onDeleteForever: () -> Void

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                Text(key.primaryUserID)
                    .font(.body)
                    .strikethrough()
                Text(key.fingerprint)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Menu {
                Button("Restore to active", action: onRestore)
                Divider()
                Button("Delete forever…", role: .destructive, action: onDeleteForever)
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .accessibilityIdentifier("archived.menu-\(key.fingerprint)")
        }
        .padding(.vertical, 4)
    }
}

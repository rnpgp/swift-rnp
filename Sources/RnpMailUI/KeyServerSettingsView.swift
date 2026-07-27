//
//  KeyServerSettingsView.swift
//  swift-rnp
//
//  Keyserver settings: the ordered list of servers used for key discovery
//  and publishing. Users can reorder the list, add custom HKPS servers,
//  remove them again, and reset to the built-in defaults. Shown as a sheet
//  from the container app's menu.
//

import KeyServerClient
import SwiftUI

extension Notification.Name {
    /// Posted to open the keyserver settings sheet.
    public static let showKeyServerSettings = Notification.Name("com.rnpgp.RNPForMail.showKeyServerSettings")
}

/// Editable view over `KeyServerSettings`.
///
/// Every mutation (add, remove, reorder, reset) is persisted immediately
/// via the store, so the Mail extension picks changes up on its next
/// lookup without a restart.
public struct KeyServerSettingsView: View {
    @Environment(\.dismiss) private var dismiss

    private let store: KeyServerSettingsStore

    @State private var servers: [KeyServer]
    @State private var selection: KeyServer.ID?
    @State private var newHost = ""
    @State private var addError: String?

    public init(store: KeyServerSettingsStore = KeyServerSettingsStore()) {
        self.store = store
        _servers = State(initialValue: store.load().servers)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: RnpSpacing.md) {
            header
            serverList
            listControls
            Divider()
            addRow
            if let addError {
                Text(addError)
                    .font(.caption)
                    .foregroundStyle(RnpBrand.critical)
                    .accessibilityIdentifier("keyservers.add.error")
            }
            HStack {
                Spacer()
                Button("button.done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("keyservers.done")
            }
        }
        .padding(RnpSpacing.xl)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .accessibilityIdentifier("keyservers")
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: RnpSpacing.xxs) {
            Text("keyservers.title")
                .font(.title2.weight(.semibold))
            Text("keyservers.message")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("keyservers.header")
    }

    // MARK: - Server list

    private var serverList: some View {
        List(selection: $selection) {
            ForEach(servers) { server in
                row(for: server)
                    .tag(server.id)
            }
        }
        .accessibilityIdentifier("keyservers.list")
    }

    private func row(for server: KeyServer) -> some View {
        HStack(spacing: RnpSpacing.sm) {
            RnpBadge(text: kindLabel(for: server.kind), color: kindColor(for: server.kind))
                .frame(width: 44, alignment: .leading)
            Text(displayHost(for: server))
                .font(.callout)
                .textSelection(.enabled)
            Spacer(minLength: 0)
            if server.isCustom {
                RnpBadge(text: "keyservers.custom".localized, color: RnpBrand.primary)
            }
        }
        .padding(.vertical, RnpSpacing.xxs)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("keyservers.row.\(server.id)")
    }

    // MARK: - List controls

    private var listControls: some View {
        HStack(spacing: RnpSpacing.sm) {
            Button {
                moveSelected(by: -1)
            } label: {
                Label("keyservers.moveUp", systemImage: "chevron.up")
            }
            .disabled(!canMove(by: -1))
            .accessibilityIdentifier("keyservers.moveUp")

            Button {
                moveSelected(by: 1)
            } label: {
                Label("keyservers.moveDown", systemImage: "chevron.down")
            }
            .disabled(!canMove(by: 1))
            .accessibilityIdentifier("keyservers.moveDown")

            Button(role: .destructive) {
                removeSelected()
            } label: {
                Label("keyservers.remove", systemImage: "minus")
            }
            .disabled(!selectedServerIsCustomHKPS)
            .accessibilityIdentifier("keyservers.remove")

            Spacer()

            Button("keyservers.reset") {
                servers = KeyServerSettings.defaultServers
                selection = nil
                persist()
            }
            .accessibilityIdentifier("keyservers.reset")
        }
        .controlSize(.small)
    }

    // MARK: - Add row

    private var addRow: some View {
        HStack(spacing: RnpSpacing.sm) {
            TextField("keyservers.add.placeholder", text: $newHost)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("keyservers.add.host")
            Button("keyservers.add") {
                addServer()
            }
            .disabled(newHost.trimmingCharacters(in: .whitespaces).isEmpty)
            .accessibilityIdentifier("keyservers.add")
        }
    }

    // MARK: - Actions

    private var selectedServer: KeyServer? {
        servers.first { $0.id == selection }
    }

    private var selectedServerIsCustomHKPS: Bool {
        guard let server = selectedServer else {
            return false
        }
        return server.kind == .hkps && server.isCustom
    }

    private func canMove(by offset: Int) -> Bool {
        guard let index = servers.firstIndex(where: { $0.id == selection }) else {
            return false
        }
        let target = index + offset
        return servers.indices.contains(target)
    }

    private func moveSelected(by offset: Int) {
        guard let index = servers.firstIndex(where: { $0.id == selection }),
              canMove(by: offset)
        else {
            return
        }
        servers.swapAt(index, index + offset)
        persist()
    }

    private func removeSelected() {
        guard selectedServerIsCustomHKPS else {
            return
        }
        servers.removeAll { $0.id == selection }
        selection = nil
        persist()
    }

    private func addServer() {
        guard let host = KeyServerSettings.normalizedHKPSHost(newHost) else {
            addError = "keyservers.add.invalid".localized
            return
        }
        let server = KeyServer(kind: .hkps, host: host)
        guard !servers.contains(server) else {
            addError = "keyservers.add.duplicate".localized
            return
        }
        servers.append(server)
        selection = server.id
        newHost = ""
        addError = nil
        persist()
    }

    private func persist() {
        store.save(KeyServerSettings(servers: servers))
    }

    // MARK: - Presentation helpers

    private func kindLabel(for kind: KeyServerKind) -> String {
        switch kind {
        case .vks:
            return "keyservers.kind.vks".localized
        case .wkd:
            return "keyservers.kind.wkd".localized
        case .hkps:
            return "keyservers.kind.hkps".localized
        }
    }

    private func kindColor(for kind: KeyServerKind) -> Color {
        switch kind {
        case .vks:
            return RnpBrand.primary
        case .wkd:
            return RnpBrand.verified
        case .hkps:
            return RnpBrand.unverified
        }
    }

    private func displayHost(for server: KeyServer) -> String {
        server.kind == .wkd ? "keyservers.wkd.description".localized : server.host
    }
}

#if DEBUG
struct KeyServerSettingsView_Previews: PreviewProvider {
    static var previews: some View {
        KeyServerSettingsView()
            .frame(width: 480, height: 420)
    }
}
#endif

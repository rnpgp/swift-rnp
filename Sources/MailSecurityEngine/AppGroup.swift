//
//  AppGroup.swift
//  swift-rnp
//
//  Locations shared between the container app and the Mail extension.
//

import Foundation

/// App group and keyring location shared by both processes.
public enum AppGroup {
    /// App group identifier shared by the container app and the Mail
    /// extension (see both targets' entitlements).
    ///
    /// The value is injected via the `RNPMAILAppGroup` Info.plist key so it
    /// can be driven by `Shared/IDs.xcconfig`. A hardcoded fallback keeps
    /// unsigned local builds working when no entitlements are present.
    public static let identifier: String = {
        if let value = Bundle.main.object(forInfoDictionaryKey: "RNPMAILAppGroup") as? String,
           !value.isEmpty,
           !value.hasPrefix("$(") {
            return value
        }
        return "group.com.rnpgp.RNPForMail"
    }()

    /// Directory holding the shared OpenPGP keyring (pubring.gpg and
    /// secring.gpg).
    ///
    /// Lives in the app group container so the container app and the
    /// extension see the same keys. Falls back to Application Support when
    /// the group container is unavailable (e.g. unsigned local builds
    /// without entitlements).
    public static func keyringDirectory(fileManager: FileManager = .default) -> URL {
        if let container = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: identifier
        ) {
            return container.appendingPathComponent("Keyrings", isDirectory: true)
        }
        let support = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return support.appendingPathComponent("RNP for Mail", isDirectory: true)
    }

    /// Directory holding the extension's message-security state records
    /// (`last-message.json` and per-message files).
    ///
    /// Lives in the app group container next to the keyring so test harnesses
    /// (and later diagnostics UI) can read the last verification results.
    /// Falls back to Application Support like the keyring directory.
    public static func extensionStateDirectory(fileManager: FileManager = .default) -> URL {
        if let container = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: identifier
        ) {
            return container.appendingPathComponent("ExtensionState", isDirectory: true)
        }
        let support = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return support.appendingPathComponent("RNP for Mail/ExtensionState", isDirectory: true)
    }
}

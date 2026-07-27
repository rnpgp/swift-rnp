//
//  EngineEnvironment.swift
//  RnpMailUI
//
//  SwiftUI EnvironmentValue carrying the engine the views need. Views
//  declare `@Environment(\.engine)` instead of accepting a KeyManager
//  via init, which keeps view constructors narrow and lets previews
//  substitute mock engines without changing call sites.
//
//  The value is optional. Views that absolutely require an engine
//  should call `requireEngine()` (asserts in debug, returns a
//  temporary in release).
//

import MailSecurityEngine
import SwiftUI

private struct EngineEnvironmentKey: EnvironmentKey {
    static let defaultValue: MailSecurityEngine? = nil
}

public extension EnvironmentValues {
    /// The MailSecurityEngine to consult for state. nil when no
    /// container-app ancestor has supplied one.
    var engine: MailSecurityEngine? {
        get { self[EngineEnvironmentKey.self] }
        set { self[EngineEnvironmentKey.self] = newValue }
    }
}

public extension View {
    /// Injects the engine into the environment so descendant views
    /// can read it via `@Environment(\.engine)`.
    func engineEnvironment(_ engine: MailSecurityEngine?) -> some View {
        environment(\.engine, engine)
    }
}

/// View helper that requires an engine, asserting in debug when one
/// is not present.
public struct RequireEngine<Content: View>: View {
    @Environment(\.engine) private var engine
    let content: (MailSecurityEngine) -> Content

    public init(@ViewBuilder content: @escaping (MailSecurityEngine) -> Content) {
        self.content = content
    }

    public var body: some View {
        if let engine {
            content(engine)
        } else {
            #if DEBUG
            Text("EngineEnvironment: no engine supplied")
                .foregroundStyle(.red)
                .padding()
            #else
            EmptyView()
            #endif
        }
    }
}

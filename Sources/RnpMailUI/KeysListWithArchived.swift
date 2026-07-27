//
//  KeysListWithArchived.swift
//  RnpMailUI
//
//  Composition wrapper that places `ArchivedKeysSection` below a
//  caller-supplied primary keys list. The container app uses this
//  wrapper instead of bare KeysListView when it wants archived keys
//  surfaced in the same NavigationView.
//
//  Additive: KeysListView stays unchanged.
//

import MailSecurityEngine
import SwiftUI

public struct KeysListWithArchived<Primary: View>: View {
    @ViewBuilder public let primary: () -> Primary
    public let archivedViewModel: ArchivedKeysViewModel

    public init(
        archivedViewModel: ArchivedKeysViewModel,
        @ViewBuilder primary: @escaping () -> Primary
    ) {
        self.archivedViewModel = archivedViewModel
        self.primary = primary
    }

    public var body: some View {
        VStack(spacing: 0) {
            primary()
            Divider()
            ArchivedKeysSection(viewModel: archivedViewModel)
                .padding(.horizontal)
                .padding(.bottom, 8)
        }
    }
}

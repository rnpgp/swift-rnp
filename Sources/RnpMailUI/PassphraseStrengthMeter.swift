//
//  PassphraseStrengthMeter.swift
//  swift-rnp
//
//  Horizontal segmented meter showing the estimated passphrase strength.
//

import SwiftUI

/// A compact segmented meter that updates as the user types a passphrase.
public struct PassphraseStrengthMeter: View {
    let passphrase: String

    public init(passphrase: String) {
        self.passphrase = passphrase
    }

    public var body: some View {
        let strength = estimatePassphraseStrength(passphrase)

        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 4) {
                ForEach(0 ..< 4) { index in
                    RoundedRectangle(cornerRadius: 2)
                        .fill(barColor(strength: strength, index: index))
                        .frame(height: 6)
                }
            }
            Text(strength.label)
                .font(.caption)
                .foregroundStyle(labelColor(strength: strength))
        }
    }

    private func barColor(strength: PassphraseStrength, index: Int) -> Color {
        if strength.score <= index {
            return Color.gray.opacity(0.25)
        }
        switch strength {
        case .veryWeak: return .red
        case .weak: return .orange
        case .fair: return .yellow
        case .strong: return .green
        case .veryStrong: return .teal
        }
    }

    private func labelColor(strength: PassphraseStrength) -> Color {
        switch strength {
        case .veryWeak: return .red
        case .weak: return .orange
        case .fair: return .primary
        case .strong: return .green
        case .veryStrong: return .teal
        }
    }
}

#if DEBUG
struct PassphraseStrengthMeter_Previews: PreviewProvider {
    static var previews: some View {
        PassphraseStrengthMeter(passphrase: "Hello1!")
    }
}
#endif

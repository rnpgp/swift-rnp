//
//  PassphraseStrength.swift
//  swift-rnp
//
//  Simple passphrase-strength estimation for the onboarding flow.
//

import Foundation

/// Rough strength estimate used to drive the onboarding meter.
public enum PassphraseStrength: Comparable {
    case veryWeak
    case weak
    case fair
    case strong
    case veryStrong

    /// Score from 0 (very weak) to 4 (very strong).
    public var score: Int {
        switch self {
        case .veryWeak: return 0
        case .weak: return 1
        case .fair: return 2
        case .strong: return 3
        case .veryStrong: return 4
        }
    }

    /// User-facing label for the current strength.
    public var label: String {
        switch self {
        case .veryWeak: return "passphrase.veryWeak".localized
        case .weak: return "passphrase.weak".localized
        case .fair: return "passphrase.fair".localized
        case .strong: return "passphrase.strong".localized
        case .veryStrong: return "passphrase.veryStrong".localized
        }
    }

    /// Color name used by the SwiftUI meter.
    public var color: String {
        switch self {
        case .veryWeak: return "red"
        case .weak: return "orange"
        case .fair: return "yellow"
        case .strong: return "green"
        case .veryStrong: return "teal"
        }
    }
}

/// Estimates the strength of a passphrase from its length and character
/// classes.
public func estimatePassphraseStrength(_ passphrase: String) -> PassphraseStrength {
    guard !passphrase.isEmpty else { return .veryWeak }

    var score = 0
    let length = passphrase.count
    if length >= 8 { score += 1 }
    if length >= 12 { score += 1 }
    if length >= 16 { score += 1 }

    let hasLower = passphrase.range(of: "[a-z]", options: .regularExpression) != nil
    let hasUpper = passphrase.range(of: "[A-Z]", options: .regularExpression) != nil
    let hasDigit = passphrase.range(of: "[0-9]", options: .regularExpression) != nil
    let hasSymbol = passphrase.range(of: "[^a-zA-Z0-9]", options: .regularExpression) != nil

    let classes = [hasLower, hasUpper, hasDigit, hasSymbol].filter { $0 }.count
    if classes >= 3 { score += 1 }
    if classes >= 4 { score += 1 }

    switch score {
    case 0, 1: return .veryWeak
    case 2: return .weak
    case 3: return .fair
    case 4: return .strong
    default: return .veryStrong
    }
}

//
//  DesignSystem.swift
//  swift-rnp
//
//  Shared design tokens and small building blocks for the RnpMail user
//  interface: an 8 pt spacing grid, consistent corner radii, trust-state
//  presentation, badges, avatars, empty states, and a search field.
//
//  Everything here is macOS 12 compatible and Dynamic Type friendly (no
//  fixed-height text containers).
//

import SwiftUI
import TrustStore

// MARK: - Tokens

/// Spacing and sizing constants for the RnpMail design language.
///
/// All layout uses the 8 pt grid: 4 / 8 / 12 / 16 / 20 / 24 / 32.
public enum RnpSpacing {
    public static let xxs: CGFloat = 4
    public static let xs: CGFloat = 8
    public static let sm: CGFloat = 12
    public static let md: CGFloat = 16
    public static let lg: CGFloat = 20
    public static let xl: CGFloat = 24
    public static let xxl: CGFloat = 32
}

/// Corner radii: 6 pt for badges, 8 pt for cards, 10 pt for panels.
public enum RnpRadius {
    public static let badge: CGFloat = 6
    public static let card: CGFloat = 8
    public static let panel: CGFloat = 10
}

// MARK: - Brand palette

/// RNP brand colors, sampled from the project logo (`icon.png`): brand blue
/// `#1A7BEC`, logo yellow `#FFDC4A`, teal `#00DFB7`, wordmark navy `#2E3349`.
///
/// `primary` matches the app asset catalog's `AccentColor`, so SwiftUI
/// controls tinted via `Color.accentColor` (buttons, links, selection) and
/// explicit brand uses stay in sync. The trust colors follow the engine's
/// intent mapping (see `mapSignerTrust`): green for verified, orange for
/// unverified, red for critical/problem states.
public enum RnpBrand {
    /// Primary brand blue (#1A7BEC): primary actions, links, selection.
    public static let primary = Color(red: 0x1A / 255, green: 0x7B / 255, blue: 0xEC / 255)
    /// Deeper brand blue (#0B54B8), used as the gradient end of brand tiles.
    public static let primaryDeep = Color(red: 0x0B / 255, green: 0x54 / 255, blue: 0xB8 / 255)
    /// Logo yellow (#FFDC4A); reserved for small highlights.
    public static let highlight = Color(red: 0xFF / 255, green: 0xDC / 255, blue: 0x4A / 255)
    /// Wordmark navy (#2E3349): strong text on brand surfaces.
    public static let ink = Color(red: 0x2E / 255, green: 0x33 / 255, blue: 0x49 / 255)

    /// Verified trust state: the logo teal, tuned for text/icon legibility.
    public static let verified = dynamic(
        light: (0x05, 0xA3, 0x77),
        dark: (0x2F, 0xD3, 0x9A)
    )
    /// Unverified keys and "expires soon" warnings.
    public static let unverified = dynamic(
        light: (0xC2, 0x41, 0x0C),
        dark: (0xF5, 0xA6, 0x23)
    )
    /// Critical states: key conflicts, revoked and expired keys.
    public static let critical = dynamic(
        light: (0xD9, 0x2D, 0x20),
        dark: (0xFF, 0x5A, 0x52)
    )

    /// Light/dark-aware brand color (macOS 12 compatible).
    private static func dynamic(
        light: (UInt8, UInt8, UInt8),
        dark: (UInt8, UInt8, UInt8)
    ) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            let rgb = isDark ? dark : light
            return NSColor(
                srgbRed: CGFloat(rgb.0) / 255,
                green: CGFloat(rgb.1) / 255,
                blue: CGFloat(rgb.2) / 255,
                alpha: 1
            )
        })
    }
}

// MARK: - Brand mark

/// The RNP brand mark: a shield-and-lock glyph on a brand-blue gradient
/// tile. Used where the real app icon is unavailable (unit tests, SwiftUI
/// previews); the app itself shows the asset-catalog app icon instead.
public struct RnpLogoView: View {
    public let size: CGFloat

    public init(size: CGFloat = 88) {
        self.size = size
    }

    public var body: some View {
        Image(systemName: "lock.shield.fill")
            .font(.system(size: size * 0.52, weight: .semibold))
            .symbolRenderingMode(.hierarchical)
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(
                LinearGradient(
                    colors: [RnpBrand.primary, RnpBrand.primaryDeep],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                ),
                in: RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
            )
            .accessibilityHidden(true)
    }
}

// MARK: - Trust presentation

/// Colors and SF Symbols describing a recipient key's trust state.
public struct TrustPresentation {
    public let color: Color
    public let iconName: String
    public let labelKey: String
    /// Short explanation shown under the label in the trust card.
    public let descriptionKey: String

    public init(state: TrustState) {
        switch state {
        case .verified:
            color = RnpBrand.verified
            iconName = "checkmark.shield.fill"
            labelKey = "trust.verified"
            descriptionKey = "trust.description.verified"
        case .problem:
            color = RnpBrand.critical
            iconName = "exclamationmark.shield.fill"
            labelKey = "trust.conflict"
            descriptionKey = "trust.description.problem"
        case .unverified:
            color = RnpBrand.unverified
            iconName = "questionmark.shield"
            labelKey = "trust.unverified"
            descriptionKey = "trust.description.unverified"
        }
    }
}

// MARK: - Badge

/// Small tinted label for states such as "Revoked" or "Expires in 12 days".
public struct RnpBadge: View {
    public let text: String
    public let color: Color

    public init(text: String, color: Color) {
        self.text = text
        self.color = color
    }

    public var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, RnpSpacing.xxs + 2)
            .padding(.vertical, 1)
            .foregroundStyle(color)
            .background(
                color.opacity(0.12),
                in: RoundedRectangle(cornerRadius: RnpRadius.badge, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: RnpRadius.badge, style: .continuous)
                    .strokeBorder(color.opacity(0.45), lineWidth: 1)
            )
    }
}

// MARK: - Key avatar

/// Gradient glyph tile representing a key (filled glyph for key pairs,
/// outline for public-only keys; dimmed when revoked or expired).
public struct RnpKeyAvatar: View {
    public let hasSecret: Bool
    public let isDimmed: Bool
    public let size: CGFloat

    public init(hasSecret: Bool, isDimmed: Bool = false, size: CGFloat = 48) {
        self.hasSecret = hasSecret
        self.isDimmed = isDimmed
        self.size = size
    }

    public var body: some View {
        let gradientColors: [Color] = isDimmed
            ? [Color(nsColor: .tertiaryLabelColor), Color(nsColor: .quaternaryLabelColor)]
            : [RnpBrand.primary, RnpBrand.primaryDeep]
        Image(systemName: hasSecret ? "key.fill" : "key")
            .font(.system(size: size * 0.44, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(
                LinearGradient(
                    colors: gradientColors,
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                ),
                in: RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
            )
            .accessibilityHidden(true)
    }
}

// MARK: - Section header with count

/// Small uppercase section label with a count, e.g. "MY KEYS — 3".
public struct RnpSectionHeader: View {
    public let title: String
    public let count: Int

    public init(title: String, count: Int) {
        self.title = title
        self.count = count
    }

    public var body: some View {
        HStack(spacing: RnpSpacing.xxs) {
            Text(title.uppercased())
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            Text("\(count)")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, RnpSpacing.xxs)
                .padding(.vertical, 1)
                .background(
                    .quaternary,
                    in: RoundedRectangle(cornerRadius: RnpRadius.badge, style: .continuous)
                )
            Spacer()
        }
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Search field

/// Sidebar search field with a magnifying glass and a clear button.
///
/// Implemented with plain controls instead of `.searchable` so it renders
/// identically inside and outside a navigation context (macOS 12 fallback).
public struct RnpSearchField: View {
    @Binding public var text: String
    public let prompt: String
    public let accessibilityIdentifier: String?

    @FocusState private var isFocused: Bool

    public init(text: Binding<String>, prompt: String, accessibilityIdentifier: String? = nil) {
        self._text = text
        self.prompt = prompt
        self.accessibilityIdentifier = accessibilityIdentifier
    }

    public var body: some View {
        HStack(spacing: RnpSpacing.xxs + 2) {
            Image(systemName: "magnifyingglass")
                .font(.callout)
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            TextField(prompt, text: $text)
                .textFieldStyle(.plain)
                .focused($isFocused)
                .accessibilityLabel(prompt)
                .accessibilityIdentifier(accessibilityIdentifier ?? "rnp.searchfield")
            if !text.isEmpty {
                Button {
                    text = ""
                    isFocused = true
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("search.clear".localized)
                .accessibilityIdentifier("rnp.searchfield.clear")
            }
        }
        .padding(.horizontal, RnpSpacing.xs)
        .padding(.vertical, RnpSpacing.xxs + 1)
        .background(
            Color(nsColor: .controlBackgroundColor),
            in: RoundedRectangle(cornerRadius: RnpRadius.badge, style: .continuous)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RnpRadius.badge, style: .continuous)
                .strokeBorder(Color(nsColor: .separatorColor), lineWidth: 1)
        )
    }
}

// MARK: - Empty state

/// Friendly empty/error placeholder: symbol, title, message, and actions.
public struct RnpEmptyState<Actions: View>: View {
    public let icon: String
    public let title: LocalizedStringKey
    public let message: String
    public let actions: Actions

    public init(
        icon: String,
        title: LocalizedStringKey,
        message: String,
        @ViewBuilder actions: () -> Actions
    ) {
        self.icon = icon
        self.title = title
        self.message = message
        self.actions = actions()
    }

    public var body: some View {
        VStack(spacing: RnpSpacing.md) {
            Image(systemName: icon)
                .font(.system(size: 36, weight: .light))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(.tertiary)
                .accessibilityHidden(true)
            VStack(spacing: RnpSpacing.xxs + 2) {
                Text(title)
                    .font(.title3.weight(.semibold))
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            actions
                .padding(.top, RnpSpacing.xxs)
        }
        .padding(RnpSpacing.xxl)
        .frame(maxWidth: 360)
    }
}

// MARK: - Inline error

/// Inline, non-modal error message with a recovery suggestion and an
/// optional dismiss button.
public struct RnpInlineError: View {
    public let message: String
    public let recoverySuggestion: String?
    public let onDismiss: (() -> Void)?

    public init(message: String, recoverySuggestion: String? = nil, onDismiss: (() -> Void)? = nil) {
        self.message = message
        self.recoverySuggestion = recoverySuggestion
        self.onDismiss = onDismiss
    }

    public var body: some View {
        HStack(alignment: .top, spacing: RnpSpacing.xs) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: RnpSpacing.xxs) {
                Text(message)
                    .font(.callout.weight(.medium))
                    .fixedSize(horizontal: false, vertical: true)
                if let recoverySuggestion {
                    Text(recoverySuggestion)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
            if let onDismiss {
                Button(action: onDismiss) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("button.dismiss".localized)
            }
        }
        .padding(RnpSpacing.sm)
        .background(
            Color.red.opacity(0.08),
            in: RoundedRectangle(cornerRadius: RnpRadius.card, style: .continuous)
        )
        .overlay(
            RoundedRectangle(cornerRadius: RnpRadius.card, style: .continuous)
                .strokeBorder(Color.red.opacity(0.25), lineWidth: 1)
        )
        .accessibilityElement(children: .contain)
    }
}

// MARK: - Fingerprint formatting

public extension String {
    /// Groups a hex fingerprint into blocks of four characters.
    /// "AB12CD34EF56" -> "AB12 CD34 EF56".
    var groupedFingerprintBlocks: String {
        stride(from: 0, to: count, by: 4)
            .map { offset -> String in
                let start = index(startIndex, offsetBy: offset)
                let end = index(start, offsetBy: 4, limitedBy: endIndex) ?? endIndex
                return String(self[start ..< end])
            }
            .joined(separator: " ")
    }

    /// First 16 hex characters in grouped form, with an ellipsis when the
    /// fingerprint was truncated.
    var groupedFingerprintAbbreviated: String {
        let truncated = count > 16
        return String(prefix(16)).groupedFingerprintBlocks + (truncated ? " …" : "")
    }
}

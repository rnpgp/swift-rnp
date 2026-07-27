//
//  NotifyContactsTemplate.swift
//  MailSecurityEngine
//
//  Builds the templated email body that the engine offers to send to
//  contacts when a key action changes what they should refresh. Pure;
//  no network, no MailKit. The compose UI passes the resulting text to
//  Mail's standard compose flow.
//
//  Templates cover the four key actions that change the published key:
//  extend expiry, rotate encryption subkey, rotate signing subkey,
//  revoke, and transition to a new key.
//

import Foundation

/// The action that triggered the notify flow. Determines the template
/// wording.
public enum NotifyContactsTrigger: Equatable, Sendable {
    case extendExpiry(newExpiration: Date)
    case rotateEncryptionSubkey
    case rotateSigningSubkey
    case revoke(reason: String)
    case transitionToNewKey(newFingerprint: String)
}

/// One rendered notify-contacts email.
public struct NotifyContactsEmail: Equatable, Sendable {
    public let subject: String
    public let body: String
    /// Suggested To: line — typically the contacts the engine knows
    /// encrypted to your old key recently. Empty when no such list is
    /// available; the user fills in recipients manually.
    public let suggestedRecipients: [String]

    public init(subject: String, body: String, suggestedRecipients: [String]) {
        self.subject = subject
        self.body = body
        self.suggestedRecipients = suggestedRecipients
    }
}

/// Pure template builder.
public enum NotifyContactsTemplate {
    /// Renders the email for the given trigger and context.
    /// - Parameters:
    ///   - trigger: what action the user just performed.
    ///   - senderName: human-readable name to sign off with. Falls back
    ///     to the key's primary user ID if empty.
    ///   - senderAddress: From: address of the user.
    ///   - primaryUserID: the key's primary UID string (e.g.,
    ///     `"Alice <alice@example.org>"`).
    ///   - fingerprint: the key's fingerprint (formatted with spaces).
    ///   - shortFingerprint: last 16 hex chars, for inline reference.
    ///   - suggestedRecipients: addresses to pre-fill the To: line.
    public static func render(
        trigger: NotifyContactsTrigger,
        senderName: String,
        senderAddress: String,
        primaryUserID: String,
        fingerprint: String,
        shortFingerprint: String,
        suggestedRecipients: [String] = []
    ) -> NotifyContactsEmail {
        let signature = signatureLine(name: senderName, userID: primaryUserID)
        let subject = subjectLine(for: trigger)
        let body = bodyText(
            trigger: trigger,
            senderAddress: senderAddress,
            primaryUserID: primaryUserID,
            fingerprint: fingerprint,
            shortFingerprint: shortFingerprint,
            signature: signature
        )
        return NotifyContactsEmail(
            subject: subject,
            body: body,
            suggestedRecipients: suggestedRecipients
        )
    }

    // MARK: - Internal formatting helpers (visible to tests)

    private static func subjectLine(for trigger: NotifyContactsTrigger) -> String {
        switch trigger {
        case .extendExpiry:
            return "My PGP key was updated (expiry extended)"
        case .rotateEncryptionSubkey:
            return "My PGP key was updated (new encryption subkey)"
        case .rotateSigningSubkey:
            return "My PGP key was updated (new signing subkey)"
        case .revoke:
            return "My PGP key was revoked"
        case .transitionToNewKey:
            return "My PGP key has moved to a new fingerprint"
        }
    }

    private static func bodyText(
        trigger: NotifyContactsTrigger,
        senderAddress: String,
        primaryUserID: String,
        fingerprint: String,
        shortFingerprint: String,
        signature: String
    ) -> String {
        let header = """
        Hi,

        I just updated my PGP key (\(primaryUserID)).

        """

        let specifics: String
        switch trigger {
        case let .extendExpiry(newExpiration):
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withFullDate]
            let date = formatter.string(from: newExpiration)
            specifics = """
            The key's expiry has been extended to \(date). The fingerprint is unchanged.
            """
        case .rotateEncryptionSubkey:
            specifics = """
            I rotated my encryption subkey. The primary key and fingerprint are unchanged; \
            you should refresh from the keyserver before sending me new encrypted mail. Old \
            encrypted mail still decrypts normally.
            """
        case .rotateSigningSubkey:
            specifics = """
            I rotated my signing subkey. The primary key and fingerprint are unchanged; \
            refresh from the keyserver before verifying new signatures from me.
            """
        case let .revoke(reason):
            specifics = """
            I revoked my key (\(shortFingerprint)) with reason: \(reason). Please refresh \
            from the keyserver and stop using the old key. If you have a verified channel \
            with me, I'll share a new fingerprint separately.
            """
        case let .transitionToNewKey(newFingerprint):
            specifics = """
            I moved my key to a new fingerprint. The new fingerprint is:

              \(groupedFingerprint(newFingerprint))

            The old key (\(shortFingerprint)) has been revoked with reason "superseded." \
            Refresh from the keyserver to pick up the new key; the new key is signed by the \
            old one, so certifications carry over.
            """
        }

        let footer = """

        My fingerprint (still \(shortFingerprint)):

          \(groupedFingerprint(fingerprint))

        If you verify fingerprints out-of-band, please update your records. Refreshing \
        from the keyserver should pick up the change automatically.

        \(signature)
        """

        return header + specifics + footer
    }

    private static func signatureLine(name: String, userID: String) -> String {
        if !name.isEmpty { return "Thanks,\n\(name)" }
        // Fall back to the UID's "Real Name" portion if present.
        if let openAngle = userID.firstIndex(of: "<"),
           let closeAngle = userID.firstIndex(of: ">") {
            let prefix = userID[..<openAngle].trimmingCharacters(in: .whitespaces)
            if !prefix.isEmpty { return "Thanks,\n\(prefix)" }
        }
        return "Thanks."
    }

    /// Groups a fingerprint into 4-hex chunks separated by spaces, the
    /// format humans compare.
    public static func groupedFingerprint(_ fingerprint: String) -> String {
        let stripped = fingerprint
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: ":", with: "")
            .uppercased()
        var result = ""
        for (index, char) in stripped.enumerated() {
            if index > 0 && index % 4 == 0 { result += " " }
            result.append(char)
        }
        return result
    }
}

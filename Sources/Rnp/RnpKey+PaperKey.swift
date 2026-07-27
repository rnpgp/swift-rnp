//
//  RnpKey+PaperKey.swift
//  Rnp
//
//  paperkey-format exporter for disaster-recovery backups.
//
//  paperkey (https://www.jabberwocky.com/software/paperkey/) is a
//  long-standing tool that extracts just the secret-key packets from an
//  OpenPGP key and prints them as hex, suitable for printing on paper.
//  The public-key half is regenerable from the secret-key packets via
//  OpenPGP's binding signatures, so the paper form is sufficient for
//  full recovery.
//
//  We emit a paperkey-compatible text format:
//
//    # RNP paperkey backup
//    # Key fingerprint: <FPR>
//    # Created: <ISO date>
//    # Algorithm: <algo + bits>
//    #
//    # To restore: paste this text into RNP's Restore-from-paper flow,
//    # or run: paperkey --restore < this-file | gpg --import
//
//    <hex of the secret-key packets>
//
//  The hex format follows paperkey's convention: 12 hex digits per
//  group, 5 groups per line, separated by spaces, with the byte offset
//  at the start of each line. This is the same format `paperkey` emits
//  and accepts on restore.
//

import CRnp
import Foundation

public extension RnpKey {
    /// Exports the secret key in paperkey-format hex.
    ///
    /// - Parameters:
    ///   - fingerprint: the key's fingerprint, used in the header.
    ///   - algorithm: human-readable algorithm label for the header.
    ///   - bits: key size in bits, for the header.
    ///   - creationDate: timestamp printed in the header.
    /// - Returns: the paperkey text, including header and hex body.
    func exportPaperKeyText(
        fingerprint: String,
        algorithm: String,
        bits: Int,
        creationDate: Date = Date()
    ) throws -> String {
        // Export the secret packets only, binary. We do NOT use the
        // armored form because paperkey's format is hex of the raw
        // packet bytes, not hex of the ASCII armor.
        let secret = try exportKey(secret: true, armored: false)
        let hex = PaperKeyHexFormatter.format(secret)

        let dateFormatter = ISO8601DateFormatter()
        dateFormatter.formatOptions = [.withInternetDateTime]
        let created = dateFormatter.string(from: creationDate)

        let algoLabel = bits > 0 ? "\(algorithm)-\(bits)" : algorithm
        return """
        # RNP paperkey backup
        # Key fingerprint: \(fingerprint)
        # Created: \(created)
        # Algorithm: \(algoLabel)
        #
        # To restore: paste this text into RNP's Restore-from-paper flow,
        # or run: paperkey --restore < this-file | gpg --import

        \(hex)
        """
    }
}

/// Pure formatter from binary `Data` to paperkey-style hex. Split out so
/// tests can construct inputs without touching FFI.
public enum PaperKeyHexFormatter {
    /// Bytes per hex group on a printed line (paperkey uses 6 bytes / 12
    /// hex digits per group).
    public static let bytesPerGroup = 6
    /// Groups per printed line.
    public static let groupsPerLine = 5

    /// Formats `data` as paperkey-compatible hex, with offset prefixes
    /// and line wrapping matching the upstream tool's output.
    public static func format(_ data: Data) -> String {
        var lines: [String] = []
        var offset = 0
        var lineHex = ""
        var groupsOnLine = 0

        while offset < data.count {
            let groupEnd = min(offset + bytesPerGroup, data.count)
            var groupHex = ""
            for index in offset..<groupEnd {
                groupHex += String(format: "%02x", data[index])
            }
            // Pad the last group to the standard width so the column
            // alignment matches upstream paperkey output even on short
            // final groups.
            let padCount = (bytesPerGroup * 2) - groupHex.count
            if padCount > 0 {
                groupHex += String(repeating: " ", count: padCount)
            }
            if groupsOnLine == 0 {
                lineHex = String(format: "%08X:", offset)
            }
            lineHex += " " + groupHex
            groupsOnLine += 1
            offset = groupEnd

            if groupsOnLine == groupsPerLine || offset >= data.count {
                lines.append(lineHex)
                lineHex = ""
                groupsOnLine = 0
            }
        }
        return lines.joined(separator: "\n")
    }

    /// Parses paperkey-format hex back to binary `Data`. Skips comment
    /// lines (`#`) and blank lines; tolerates whitespace differences.
    public static func parse(_ text: String) -> Data? {
        var bytes: [UInt8] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") { continue }
            // Drop the offset prefix ("00000000:") if present.
            let hexPart: String
            if let colonRange = line.range(of: ":") {
                hexPart = String(line[colonRange.upperBound...])
            } else {
                hexPart = line
            }
            // Strip whitespace within (line wraps, padding spaces).
            let compacted = hexPart.replacingOccurrences(of: " ", with: "")
                                    .replacingOccurrences(of: "\t", with: "")
            // Decode pairs.
            var index = compacted.startIndex
            while index < compacted.endIndex {
                let next = compacted.index(index, offsetBy: 2, limitedBy: compacted.endIndex) ?? compacted.endIndex
                let pair = String(compacted[index..<next])
                guard pair.count == 2, let byte = UInt8(pair, radix: 16) else {
                    return nil
                }
                bytes.append(byte)
                index = next
            }
        }
        return Data(bytes)
    }
}

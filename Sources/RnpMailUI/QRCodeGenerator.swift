//
//  QRCodeGenerator.swift
//  RnpMailUI
//
//  Pure helper for rendering QR codes via CoreImage's CIQRCodeGenerator
//  filter. No external dependencies. Used by the paper-key print layout
//  to add machine-readable QR codes alongside the human-readable hex.
//

import AppKit
import CoreImage

public enum QRCodeGenerator {
    /// Generates a QR code `NSImage` for the given string.
    /// Returns `nil` when CoreImage cannot produce the image (rare;
    /// typically only on data that exceeds QR capacity).
    public static func generate(from string: String, scale: CGFloat = 10) -> NSImage? {
        let data = Data(string.utf8)
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(data, forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")  // medium error correction
        guard let ciImage = filter.outputImage else { return nil }
        let transformed = ciImage.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let rep = NSCIImageRep(ciImage: transformed)
        let nsImage = NSImage(size: rep.size)
        nsImage.addRepresentation(rep)
        return nsImage
    }

    /// Splits a long string into QR-code-sized chunks. QR codes have
    /// a maximum capacity (~2900 alphanumeric chars at correction
    /// level M). For paper-key data (hex), each chunk is prefixed
    /// with its index and total so the scanner can reassemble:
    ///
    ///     RNP/0/5/<hex-data>
    ///     RNP/1/5/<hex-data>
    ///     ...
    public static func chunkForQR(_ string: String, maxPerChunk: Int = 800) -> [String] {
        guard !string.isEmpty else { return [] }
        guard string.count > maxPerChunk else {
            return ["RNP/0/1/\(string)"]
        }
        var chunks: [String] = []
        var index = 0
        var remaining = Substring(string)
        while !remaining.isEmpty {
            let end = remaining.index(remaining.startIndex, offsetBy: min(maxPerChunk, remaining.count))
            let piece = String(remaining[..<end])
            remaining = remaining[end...]
            index += 1
        }
        let total = index
        var i = 0
        remaining = Substring(string)
        while !remaining.isEmpty {
            let end = remaining.index(remaining.startIndex, offsetBy: min(maxPerChunk, remaining.count))
            let piece = String(remaining[..<end])
            remaining = remaining[end...]
            chunks.append("RNP/\(i)/\(total)/\(piece)")
            i += 1
        }
        return chunks
    }

    /// Reassembles QR chunks back into the original string. Validates
    /// the chunk index/total prefix; returns `nil` on any mismatch.
    public static func reassembleFromQR(_ chunks: [String]) -> String? {
        guard !chunks.isEmpty else { return nil }
        var ordered: [Int: String] = [:]
        var total = 0
        for chunk in chunks {
            let parts = chunk.split(separator: "/", maxSplits: 3, omittingEmptySubsequences: false)
            guard parts.count == 4, parts[0] == "RNP" else { return nil }
            guard let index = Int(parts[1]), let parsedTotal = Int(parts[2]) else { return nil }
            if total == 0 { total = parsedTotal }
            guard total == parsedTotal else { return nil }
            ordered[index] = String(parts[3])
        }
        guard ordered.count == total else { return nil }
        return (0..<total).compactMap { ordered[$0] }.joined()
    }
}

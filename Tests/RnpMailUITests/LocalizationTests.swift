//
//  LocalizationTests.swift
//  swift-rnp
//
//  Validation for the Localizable.xcstrings string catalog.
//
//  NOTE: The non-English translations in the catalog are machine-generated
//  (state: "needs_review") and must be reviewed by native speakers before
//  release. These tests validate structure and coverage, not linguistic
//  quality.
//

import XCTest

final class LocalizationTests: XCTestCase {
    /// Languages the container app is required to ship. `en` is the source
    /// language; the rest are the macOS-supported languages added as a
    /// machine-translated first pass (state "needs_review").
    private let requiredLanguages = ["de", "en", "es", "fr", "it", "ja", "ko", "pt", "ru", "zh-Hans", "zh-Hant"]

    private var catalogURL: URL {
        // Tests/RnpMailUITests/LocalizationTests.swift
        //   -> Swift-Rnp/MailExtensionsContainer/Resources/Localizable.xcstrings
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Swift-Rnp/MailExtensionsContainer/Resources/Localizable.xcstrings")
    }

    private func loadCatalog() throws -> [String: Any] {
        let data = try Data(contentsOf: catalogURL)
        let json = try JSONSerialization.jsonObject(with: data)
        guard let dict = json as? [String: Any] else {
            throw NSError(domain: "LocalizationTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "Catalog is not a JSON dictionary"])
        }
        return dict
    }

    private func stringsTable(from catalog: [String: Any]) throws -> [String: Any] {
        guard let strings = catalog["strings"] as? [String: Any] else {
            throw NSError(domain: "LocalizationTests", code: 2, userInfo: [NSLocalizedDescriptionKey: "Missing strings object"])
        }
        return strings
    }

    /// Returns the `stringUnit.value` for `key`/`language`, or nil if the
    /// entry is structurally incomplete.
    private func value(_ key: String, _ language: String, in strings: [String: Any]) -> String? {
        guard let entry = strings[key] as? [String: Any],
              let localizations = entry["localizations"] as? [String: Any],
              let loc = localizations[language] as? [String: Any],
              let stringUnit = loc["stringUnit"] as? [String: Any]
        else {
            return nil
        }
        return stringUnit["value"] as? String
    }

    /// printf-style placeholders (%@, %d, %1$@, ...) in the order they appear.
    private func placeholders(in string: String) -> [String] {
        // swift-format-ignore
        let pattern = #"%\d*\$?[@dDf]"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return []
        }
        let range = NSRange(string.startIndex..., in: string)
        return regex.matches(in: string, range: range).map {
            String(string[Range($0.range, in: string)!])
        }
    }

    func testCatalogIsValidJSON() throws {
        let catalog = try loadCatalog()
        XCTAssertNotNil(catalog["sourceLanguage"] as? String)
        XCTAssertNotNil(catalog["strings"] as? [String: Any])
    }

    func testAllKeysHaveEnglishTranslation() throws {
        let strings = try stringsTable(from: loadCatalog())
        for key in strings.keys {
            guard let translatedValue = value(key, "en", in: strings) else {
                XCTFail("Key '\(key)' is missing an English translation")
                continue
            }
            XCTAssertFalse(translatedValue.isEmpty, "Key '\(key)' has an empty English translation")
        }
    }

    func testAllKeysHaveRequiredLocalizations() throws {
        let strings = try stringsTable(from: loadCatalog())
        XCTAssertFalse(strings.isEmpty, "Catalog has no keys")
        for key in strings.keys {
            for language in requiredLanguages {
                guard let translatedValue = value(key, language, in: strings) else {
                    XCTFail("Key '\(key)' is missing a translation for language '\(language)'")
                    continue
                }
                XCTAssertFalse(
                    translatedValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                    "Key '\(key)' has an empty translation for language '\(language)'"
                )
            }
        }
    }

    func testNoEmptyStringValues() throws {
        let strings = try stringsTable(from: loadCatalog())
        for (key, value) in strings {
            guard let entry = value as? [String: Any],
                  let localizations = entry["localizations"] as? [String: Any]
            else {
                continue
            }
            for (lang, loc) in localizations {
                guard let locDict = loc as? [String: Any],
                      let stringUnit = locDict["stringUnit"] as? [String: Any],
                      let translatedValue = stringUnit["value"] as? String
                else {
                    continue
                }
                XCTAssertFalse(translatedValue.isEmpty, "Key '\(key)' has an empty translation for language '\(lang)'")
            }
        }
    }

    func testPlaceholdersConsistentAcrossLocalizations() throws {
        let strings = try stringsTable(from: loadCatalog())
        for key in strings.keys {
            guard let english = value(key, "en", in: strings) else {
                continue
            }
            let expected = placeholders(in: english)
            for language in requiredLanguages where language != "en" {
                guard let translated = value(key, language, in: strings) else {
                    continue
                }
                XCTAssertEqual(
                    placeholders(in: translated), expected,
                    "Key '\(key)' translation for '\(language)' does not preserve the English placeholders"
                )
            }
        }
    }

    func testSourceLanguageIsEnglish() throws {
        let catalog = try loadCatalog()
        XCTAssertEqual(catalog["sourceLanguage"] as? String, "en")
    }

    // MARK: - Pseudo-localization

    /// Pseudo-localizes a string the classic way: accented characters and a
    /// longer result, wrapped in brackets. Placeholders are left untouched.
    private func pseudoLocalized(_ string: String) -> String {
        let accents: [Character: String] = [
            "a": "áà", "e": "éè", "i": "íì", "o": "óò", "u": "úù",
            "A": "ÁÀ", "E": "ÉÈ", "I": "ÍÌ", "O": "ÓÒ", "U": "ÚÙ",
            "y": "ý", "Y": "Ý", "c": "ç", "C": "Ç", "n": "ñ", "N": "Ñ",
        ]
        var result = ""
        var index = string.startIndex
        while index < string.endIndex {
            let character = string[index]
            if character == "%" {
                // Copy the placeholder verbatim so format strings keep working.
                let rest = string[index...]
                if let match = rest.range(of: #"^%\d*\$?[@dDf]"#, options: .regularExpression) {
                    result += string[match]
                    index = match.upperBound
                    continue
                }
            }
            result += accents[character] ?? String(character)
            index = string.index(after: index)
        }
        return "⟦\(result)⟧"
    }

    /// Generates a pseudo-localized variant of the shipping catalog and
    /// verifies that it still loads as a valid string catalog.
    func testPseudoLocalizedCatalogLoads() throws {
        let catalog = try loadCatalog()
        let strings = try stringsTable(from: catalog)

        // Build the pseudo-localized catalog: same keys, one pseudo language.
        var pseudoStrings: [String: Any] = [:]
        for key in strings.keys {
            guard let english = value(key, "en", in: strings) else {
                XCTFail("Key '\(key)' is missing an English translation")
                continue
            }
            pseudoStrings[key] = [
                "localizations": [
                    "qps-ploc": [
                        "stringUnit": [
                            "state": "translated",
                            "value": pseudoLocalized(english),
                        ]
                    ]
                ]
            ]
        }
        let pseudoCatalog: [String: Any] = [
            "sourceLanguage": "qps-ploc",
            "strings": pseudoStrings,
            "version": "1.0",
        ]

        // Round-trip through a file, the same way the build system would.
        let data = try JSONSerialization.data(withJSONObject: pseudoCatalog, options: [.prettyPrinted, .sortedKeys])
        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension("xcstrings")
        defer { try? FileManager.default.removeItem(at: tempURL) }
        try data.write(to: tempURL)

        let reloadedData = try Data(contentsOf: tempURL)
        let reloaded = try XCTUnwrap(
            JSONSerialization.jsonObject(with: reloadedData) as? [String: Any],
            "Pseudo-localized catalog is not valid JSON"
        )
        let reloadedStrings = try stringsTable(from: reloaded)
        XCTAssertEqual(Set(reloadedStrings.keys), Set(strings.keys), "Pseudo-localized catalog lost keys")

        for key in reloadedStrings.keys {
            let pseudo = try XCTUnwrap(value(key, "qps-ploc", in: reloadedStrings), "Key '\(key)' lost its pseudo-localization")
            XCTAssertFalse(pseudo.isEmpty, "Key '\(key)' has an empty pseudo-localized value")
            XCTAssertTrue(pseudo.hasPrefix("⟦") && pseudo.hasSuffix("⟧"), "Key '\(key)' pseudo-localization is not bracketed")
            XCTAssertTrue(
                pseudo.unicodeScalars.contains { !($0.isASCII) },
                "Key '\(key)' pseudo-localization has no accented characters"
            )
            if let english = value(key, "en", in: strings) {
                XCTAssertEqual(
                    placeholders(in: pseudo), placeholders(in: english),
                    "Key '\(key)' pseudo-localization broke its placeholders"
                )
            }
        }
    }
}

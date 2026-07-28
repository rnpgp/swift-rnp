// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "swift-rnp",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "Rnp", targets: ["Rnp"]),
        .library(name: "MailSecurityEngine", targets: ["MailSecurityEngine"]),
        .library(name: "KeyLifecycle", targets: ["KeyLifecycle"]),
        .library(name: "KeyServerClient", targets: ["KeyServerClient"]),
        .library(name: "RnpMailUI", targets: ["RnpMailUI"]),
        .library(name: "MailSecurityUI", targets: ["MailSecurityUI"]),
        .library(name: "TrustStore", targets: ["TrustStore"]),
        .library(name: "KeyStateStore", targets: ["KeyStateStore"]),
        .library(name: "Autocrypt", targets: ["Autocrypt"]),
        .library(name: "PostQuantum", targets: ["PostQuantum"])
    ],
    targets: [
        .binaryTarget(
            name: "RNPFramework",
            url: "https://github.com/rnpgp/swift-rnp/releases/download/v0.1.0/RNPFramework.xcframework.zip",
            checksum: "600417d407b13efea194c1ddd43fccff42a57811561136f8ac47de0a2e020176"
        ),
        .target(
            name: "CRnp",
            dependencies: ["RNPFramework"],
            path: "Sources/CRnp",
            publicHeadersPath: "."
        ),
        .target(
            name: "Rnp",
            dependencies: ["CRnp"]
        ),
        .target(
            name: "TrustStore",
            dependencies: ["KeyStateStore"]
        ),
        .target(
            name: "KeyStateStore",
            dependencies: []
        ),
        .target(
            name: "Autocrypt",
            dependencies: []
        ),
        .target(
            name: "PostQuantum",
            dependencies: []
        ),
        .target(
            name: "MailSecurityEngine",
            dependencies: ["Rnp", "KeyServerClient", "TrustStore", "KeyStateStore", "Autocrypt", "PostQuantum"]
        ),
        .target(
            name: "KeyLifecycle",
            dependencies: ["Rnp", "MailSecurityEngine"]
        ),
        .target(
            name: "RnpMailUI",
            dependencies: ["MailSecurityEngine", "KeyLifecycle", "KeyServerClient", "TrustStore", "KeyStateStore"],
            resources: [
                .copy("Resources/Licenses")
            ]
        ),
        .target(
            name: "MailSecurityUI",
            dependencies: ["MailSecurityEngine", "TrustStore"]
        ),
        .target(
            name: "KeyServerClient",
            dependencies: []
        ),
        .executableTarget(
            name: "RnpDemo",
            dependencies: ["Rnp"]
        ),
        .testTarget(
            name: "RnpTests",
            dependencies: ["Rnp"]
        ),
        .testTarget(
            name: "MailSecurityEngineTests",
            dependencies: ["MailSecurityEngine"],
            resources: [
                .copy("Fixtures")
            ]
        ),
        .testTarget(
            name: "KeyLifecycleTests",
            dependencies: ["KeyLifecycle"]
        ),
        .testTarget(
            name: "KeyServerClientTests",
            dependencies: ["KeyServerClient"]
        ),
        .testTarget(
            name: "TrustStoreTests",
            dependencies: ["TrustStore"]
        ),
        .testTarget(
            name: "KeyStateStoreTests",
            dependencies: ["KeyStateStore"]
        ),
        .testTarget(
            name: "AutocryptTests",
            dependencies: ["Autocrypt"]
        ),
        .testTarget(
            name: "PostQuantumTests",
            dependencies: ["PostQuantum"]
        )
    ]
)

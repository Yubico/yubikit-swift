// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let twinKitEnabled = !(Context.environment["YUBIKIT_ENABLE_TWINKIT"] ?? "").isEmpty

let twinKitDependencies: [Target.Dependency] = twinKitEnabled ? [.target(name: "YubiKitTwinSupport")] : []
let twinKitSwiftSettings: [SwiftSetting] = twinKitEnabled ? [.define("YUBIKIT_TWINKIT", .when(platforms: [.iOS]))] : []

let twinKitTargets: [Target] =
    twinKitEnabled
    ? [
        .target(
            name: "YubiKitTwinSupport",
            dependencies: [
                .product(name: "TwinKit", package: "hardware-digital-twin")
            ],
            path: "IntegrationTesting/TwinKitSupport",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .target(
            name: "YubiKitTwinTesting",
            dependencies: [
                "YubiKit",
                "YubiKitIntegrationScenarios",
                "YubiKitTwinSupport",
            ],
            path: "IntegrationTesting/TwinKit",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ] : []

var packageDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.1.0"),
    .package(url: "https://github.com/apple/swift-log", from: "1.6.0"),
]
if twinKitEnabled {
    // YUBIKIT_TWIN_PATH resolves TwinKit from a local checkout, unpushed changes included.
    if let localTwinPath = Context.environment["YUBIKIT_TWIN_PATH"] {
        packageDependencies.append(.package(path: localTwinPath))
    } else {
        packageDependencies.append(
            .package(url: "https://github.com/Yubico/hardware-digital-twin", branch: "main")
        )
    }
}

let package = Package(
    name: "YubiKit",
    platforms: [
        .macOS(.v13), .iOS(.v16),
    ],
    products: [
        .library(
            name: "YubiKit",
            targets: ["YubiKit"]
        ),
        // Shared integration scenario engine, providers, and catalog.
        .library(
            name: "YubiKitIntegrationScenarios",
            targets: ["YubiKitIntegrationScenarios"]
        ),
    ],
    dependencies: packageDependencies,
    targets: [
        .target(
            name: "YubiKit",
            dependencies: [.product(name: "Logging", package: "swift-log")] + twinKitDependencies,
            path: "YubiKit/YubiKit",
            swiftSettings: twinKitSwiftSettings
        ),
        .target(
            name: "YubiKitIntegrationScenarios",
            dependencies: ["YubiKit"],
            path: "YubiKit/IntegrationScenarios",
            // Scenario bodies still pass SDK types that are not fully Sendable-annotated.
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "YubiKitTests",
            dependencies: ["YubiKit"],
            path: "YubiKit/UnitTests"
        ),
    ] + twinKitTargets + [
        // Hardware scenarios are selected by YUBIKEY_TEST_SERIALS; the private TwinKit
        // backend is selected by enabling the opt-in package graph above.
        .testTarget(
            name: "IntegrationTests",
            dependencies: ["YubiKitIntegrationScenarios"]
                + (twinKitEnabled ? ["YubiKitTwinTesting", "YubiKitTwinSupport"] : []),
            path: "IntegrationTesting/Tests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        )
    ]
)

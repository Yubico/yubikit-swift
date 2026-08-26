// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

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
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.1.0")
    ],
    targets: [
        .target(
            name: "YubiKit",
            path: "YubiKit/YubiKit"
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
        // Hardware-backed scenario tests; self-disabled unless YUBIKEY_TEST_SERIALS is set.
        .testTarget(
            name: "IntegrationTests",
            dependencies: ["YubiKitIntegrationScenarios"],
            path: "IntegrationTesting/Tests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)

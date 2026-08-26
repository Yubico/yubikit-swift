// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let twinKitEnabled = !(Context.environment["YUBIKIT_ENABLE_TWINKIT"] ?? "").isEmpty

var packageDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.1.0")
]
var yubiKitDependencies: [Target.Dependency] = []
var yubiKitSwiftSettings: [SwiftSetting] = []
var integrationTestDependencies: [Target.Dependency] = ["YubiKitIntegrationScenarios"]

if twinKitEnabled {
    packageDependencies.append(
        .package(url: "https://github.com/Yubico/hardware-digital-twin", branch: "main")
    )
    yubiKitDependencies.append(
        .target(name: "YubiKitTwinSupport", condition: .when(platforms: [.iOS]))
    )
    yubiKitSwiftSettings.append(
        .define("YUBIKIT_TWINKIT", .when(platforms: [.iOS]))
    )
    integrationTestDependencies.append("YubiKitTwinTesting")
}

var packageTargets: [Target] = [
    .target(
        name: "YubiKit",
        dependencies: yubiKitDependencies,
        path: "YubiKit/YubiKit",
        swiftSettings: yubiKitSwiftSettings
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
]

if twinKitEnabled {
    packageTargets.append(
        contentsOf: [
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
        ]
    )
}

packageTargets.append(
    // Hardware scenarios are selected by YUBIKEY_TEST_SERIALS; the private TwinKit
    // backend is selected by enabling the opt-in package graph above.
    .testTarget(
        name: "IntegrationTests",
        dependencies: integrationTestDependencies,
        path: "IntegrationTesting/Tests",
        swiftSettings: [.swiftLanguageMode(.v5)]
    )
)

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
    targets: packageTargets
)

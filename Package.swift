// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "YubiKit",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "YubiKit", targets: ["YubiKit"]),
        .library(name: "YubiKitIntegrationScenarios", targets: ["YubiKitIntegrationScenarios"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.1.0"),
        .package(url: "https://github.com/apple/swift-log", from: "1.6.0"),
    ],
    targets: [
        .target(
            name: "YubiKit",
            dependencies: [.product(name: "Logging", package: "swift-log")],
            path: "YubiKit/YubiKit"
        ),
        .target(
            name: "YubiKitIntegrationScenarios",
            dependencies: ["YubiKit"],
            path: "YubiKit/IntegrationScenarios",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(name: "YubiKitTests", dependencies: ["YubiKit"], path: "YubiKit/UnitTests"),
    ]
)

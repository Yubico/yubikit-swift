// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "YubiKitIntegration",
    platforms: [.macOS(.v13), .iOS(.v16)],
    dependencies: [.package(name: "YubiKitSDK", path: "..")],
    targets: [
        .testTarget(
            name: "IntegrationTests",
            dependencies: [
                .product(name: "YubiKit", package: "YubiKitSDK"),
                .product(name: "YubiKitIntegrationScenarios", package: "YubiKitSDK"),
            ],
            path: "Tests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        )
    ]
)

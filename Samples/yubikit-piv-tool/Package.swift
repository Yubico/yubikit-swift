// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "yubikit-piv-tool",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "yubikit-piv-tool",
            targets: ["yubikit-piv-tool"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
        .package(url: "https://github.com/apple/swift-asn1", from: "1.0.0"),
        .package(url: "https://github.com/outfoxx/Shield", from: "3.0.0"),
        .package(name: "YubiKit", path: "../.."),  // YubiKit SDK from repository root
    ],
    targets: [
        .executableTarget(
            name: "yubikit-piv-tool",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Shield", package: "Shield"),
                .product(name: "YubiKit", package: "YubiKit"),
            ]
        )
    ]
)

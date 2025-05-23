// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "YubiKit",
    platforms: [
        .macOS(.v13), .iOS(.v16)
    ],
    products: [
        .library(
            name: "YubiKit",
            targets: ["YubiKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.1.0"),
    ],
    targets: [
        .target(
            name: "YubiKit",
            path: "YubiKit/YubiKit"
        ),
        .testTarget(
            name: "YubiKitTests",
            dependencies: ["YubiKit"],
            path: "YubiKit/UnitTests"
        ),
    ]
)

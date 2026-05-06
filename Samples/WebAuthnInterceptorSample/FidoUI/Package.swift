// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "FidoUI",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .library(name: "FidoUI", targets: ["FidoUI"])
    ],
    dependencies: [
        .package(name: "YubiKit", path: "../../../")
    ],
    targets: [
        .target(
            name: "FidoUI",
            dependencies: [.product(name: "YubiKit", package: "YubiKit")]
        ),
        .testTarget(
            name: "FidoUITests",
            dependencies: [
                "FidoUI",
                .product(name: "YubiKit", package: "YubiKit"),
            ]
        ),
    ]
)

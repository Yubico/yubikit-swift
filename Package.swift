// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "YubiKit",
    platforms: [
        .macOS(.v13), .iOS(.v16)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "YubiKit",
            targets: ["YubiKit"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        
        // The name of the GzipSwift repository is different from the package
        // name which confuses SPM. This is a kludge until we either solve
        // the issue or simply copy the source code from GzipSwift to our
        // repo instead.
        .package(url: "https://github.com/jensutbult/Gzip", branch: "main"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "YubiKit",
            dependencies: ["Gzip"],
            path: "YubiKit/YubiKit"
        ),
        .testTarget(
            name: "YubiKitTests",
            dependencies: ["YubiKit"],
            path: "YubiKit/UnitTests"
        ),
    ]
)

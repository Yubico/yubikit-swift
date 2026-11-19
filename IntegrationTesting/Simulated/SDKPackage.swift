// swift-tools-version: 6.1
import PackageDescription

let buildsTwin = Context.environment["YUBIKIT_BUILD_TWIN"] == "1"
var dependencies: [Package.Dependency] = [
    .package(url: "https://github.com/apple/swift-log", from: "1.6.0")
]
var sdkDependencies: [Target.Dependency] = [.product(name: "Logging", package: "swift-log")]
var targets: [Target] = []

if buildsTwin {
    if let path = Context.environment["YUBIKIT_TWIN_PATH"], !path.isEmpty {
        dependencies.append(.package(path: path))
    } else {
        dependencies.append(
            .package(
                url: "https://github.com/Yubico/hardware-digital-twin",
                revision: "e050e2e251b8516aa7ac1e6fd99cf3b3068afbbb"
            )
        )
    }
    sdkDependencies.append("YubiKitTwinSupport")
    targets.append(
        .target(
            name: "YubiKitTwinSupport",
            dependencies: [.product(name: "TwinKit", package: "hardware-digital-twin")],
            path: "IntegrationTesting/Simulated/Support",
            swiftSettings: [.swiftLanguageMode(.v5)]
        )
    )
}

let hardwareDrivers = [
    "Connection/ConnectionEnvironment.swift",
    "Connection/FIDO/HIDFIDOConnection+IOKit.swift",
    "Connection/OTP/HIDOTPConnection+IOKit.swift",
    "Connection/SmartCard/LightningSmartCardConnection+ExternalAccessory.swift",
    "Connection/SmartCard/NFCSmartCardConnection+CoreNFC.swift",
    "Connection/SmartCard/USBSmartCardConnection+CryptoTokenKit.swift",
]

targets.append(
    .target(
        name: "YubiKit",
        dependencies: sdkDependencies,
        path: "YubiKit/YubiKit",
        exclude: buildsTwin ? hardwareDrivers : []
    )
)
targets.append(
    .target(
        name: "YubiKitIntegrationScenarios",
        dependencies: ["YubiKit"],
        path: "YubiKit/IntegrationScenarios",
        swiftSettings: [.swiftLanguageMode(.v5)]
    )
)

let package = Package(
    name: "YubiKit",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(
            name: "YubiKit",
            type: .dynamic,
            targets: ["YubiKit", "YubiKitIntegrationScenarios"]
        )
    ],
    dependencies: dependencies,
    targets: targets
)

// swift-tools-version: 6.1
// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import PackageDescription

let package = Package(
    name: "OATHSample",
    platforms: [.macOS(.v13), .iOS(.v16)],
    dependencies: [.package(name: "YubiKit", path: "../..")],
    targets: [
        .target(
            name: "OATHSampleModel",
            dependencies: [.product(name: "YubiKit", package: "YubiKit")],
            path: "OATHSample",
            exclude: [
                "Assets.xcassets", "Preview Content", "Info.plist", "OATHSample.entitlements",
                "OATHSampleApp.swift", "OATHListView.swift", "SettingsView.swift",
            ],
            sources: ["Model.swift", "ConnectionType.swift"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "OATHSampleTests",
            dependencies: ["OATHSampleModel"],
            path: "Tests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)

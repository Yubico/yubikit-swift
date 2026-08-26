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

#if YUBIKIT_TWINKIT && DEBUG && targetEnvironment(simulator)

import Foundation

/// Simulator ``USBSmartCardConnection`` backed by TwinKit's embedded YubiKey
/// instead of real CryptoTokenKit hardware.
@available(iOS 16.0, macOS 13.0, *)
public struct USBSmartCardConnection: SmartCardConnection, Sendable {
    public let slot: USBSmartCard.YubiKeyDevice

    private let connection: SimulatorTwinConnection

    public init() async throws(SmartCardConnectionError) {
        self.connection = try await SimulatorTwinBackend.shared.openConnection(transport: .usb)
        self.slot = USBSmartCard.YubiKeyDevice(name: "YubiKey Simulator (USB)")!
    }

    public init(slot: USBSmartCard.YubiKeyDevice) async throws(SmartCardConnectionError) {
        try await self.init()
    }

    public static func availableDevices() async throws(SmartCardConnectionError) -> [USBSmartCard.YubiKeyDevice] {
        guard await SimulatorTwinBackend.shared.isAvailable() else { return [] }
        return [USBSmartCard.YubiKeyDevice(name: "YubiKey Simulator (USB)")!]
    }

    public static func makeConnection() async throws(SmartCardConnectionError) -> USBSmartCardConnection {
        try await USBSmartCardConnection()
    }

    public static func makeConnection(
        slot: USBSmartCard.YubiKeyDevice
    ) async throws(SmartCardConnectionError) -> USBSmartCardConnection {
        try await USBSmartCardConnection()
    }

    public func close(error: Error?) async {
        connection.close(error: error)
    }

    public func waitUntilClosed() async -> Error? {
        await connection.waitUntilClosed()
    }

    @discardableResult
    public func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        try await connection.send(data: data)
    }
}

#endif

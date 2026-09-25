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

#if YUBIKIT_TWINKIT && DEBUG && targetEnvironment(simulator) && os(iOS)

import Foundation

/// Simulator ``NFCSmartCardConnection`` backed by TwinKit's embedded YubiKey
/// instead of real CoreNFC hardware.
@available(iOS 16.0, *)
public struct NFCSmartCardConnection: SmartCardConnection, Sendable {

    private let connection: SimulatorTwinConnection

    public init() async throws(SmartCardConnectionError) {
        self.connection = try await SimulatorTwinBackend.shared.openConnection(transport: .nfc)
    }

    public init(alertMessage: String?) async throws(SmartCardConnectionError) {
        try await self.init()
    }

    public static func makeConnection() async throws(SmartCardConnectionError) -> NFCSmartCardConnection {
        try await NFCSmartCardConnection()
    }

    public static func makeConnection(
        alertMessage message: String?
    ) async throws(SmartCardConnectionError) -> NFCSmartCardConnection {
        try await NFCSmartCardConnection()
    }

    public func setAlertMessage(_ message: String) async {}

    public func close(error: Error?) async {
        connection.close(error: error)
    }

    public func close(message: String? = nil) async {
        connection.close(error: nil)
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

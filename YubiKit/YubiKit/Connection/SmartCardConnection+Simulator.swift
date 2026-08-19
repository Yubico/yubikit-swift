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
import YubiKitTwinSupport

enum SimulatorTwinTransport: Sendable {
    case usb
    case nfc

    var twinKitTransport: TwinKitSmartCardTransport {
        switch self {
        case .usb: .usb
        case .nfc: .nfc
        }
    }
}

actor SimulatorTwinBackend {
    static let shared = SimulatorTwinBackend()

    func isAvailable() async -> Bool {
        await TwinKitBackend.shared.isAvailable()
    }

    func openConnection(
        transport: SimulatorTwinTransport
    ) async throws(SmartCardConnectionError) -> SimulatorTwinConnection {
        do {
            let channel = try await TwinKitBackend.shared.openSmartCard(transport: transport.twinKitTransport)
            return SimulatorTwinConnection(channel: channel)
        } catch {
            throw .setupFailed("TwinKit embedded YubiKey simulator is unavailable", error)
        }
    }
}

final class SimulatorTwinConnection: @unchecked Sendable {
    private let channel: TwinKitSmartCardChannel

    init(channel: TwinKitSmartCardChannel) {
        self.channel = channel
    }

    func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        do {
            return try await channel.send(data)
        } catch TwinKitSupportError.connectionLost {
            throw .connectionLost
        } catch {
            throw .transmitFailed("TwinKit APDU exchange failed", error)
        }
    }

    func close(error: Error?) {
        channel.close(error: error)
    }

    func waitUntilClosed() async -> Error? {
        await channel.waitUntilClosed()
    }
}

#endif

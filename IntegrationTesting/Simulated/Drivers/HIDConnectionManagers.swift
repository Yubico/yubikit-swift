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

#if os(macOS)

import Foundation
import YubiKitTwinSupport

private let twinHIDDevice = HID.YubiKeyDevice(hidLocationID: 1, name: "YubiKey TwinKit", usbVendorID: 0x1050)

actor HIDConnectionManager {
    static let shared = HIDConnectionManager()

    private var channel: TwinKitFIDOChannel?
    private var didClose: Promise<Error?>?
    private var opening = false

    func availableDevices() async throws(FIDOConnectionError) -> [HID.YubiKeyDevice] {
        TwinKitConfiguration.exposesUSBInterface(0x02) ? [twinHIDDevice] : []
    }

    func open(device: HID.YubiKeyDevice, didClose: Promise<Error?>) async throws(FIDOConnectionError) {
        guard device == twinHIDDevice, TwinKitConfiguration.exposesUSBInterface(0x02) else {
            throw .noDevicesFound
        }
        guard channel == nil, !opening else { throw .busy }
        opening = true
        defer { opening = false }
        do {
            channel = try await TwinKitBackend.shared.openFIDO()
            self.didClose = didClose
        } catch {
            throw .setupFailed("Could not open TwinKit FIDO HID", error)
        }
    }

    func close(locationID: Int, didClose: Promise<Error?>, error: Error?) async {
        guard locationID == twinHIDDevice.locationID, self.didClose === didClose, let channel else { return }
        self.channel = nil
        self.didClose = nil
        channel.close(error: error)
        await didClose.fulfill(error)
    }

    func sendPacket(_ packet: Data, to locationID: Int, didClose: Promise<Error?>) async throws(FIDOConnectionError) {
        guard locationID == twinHIDDevice.locationID, self.didClose === didClose, let channel else {
            throw .connectionLost
        }
        guard packet.count <= hidPayloadSize else { throw .transmitFailed("HID packet exceeds report size") }
        let report = packet + Data(repeating: 0, count: hidPayloadSize - packet.count)
        do {
            try await channel.send(report)
        } catch TwinKitSupportError.connectionLost {
            throw .connectionLost
        } catch {
            throw .transmitFailed("TwinKit CTAPHID write failed", error)
        }
    }

    func receivePacket(from locationID: Int, didClose: Promise<Error?>) async throws(FIDOConnectionError) -> Data {
        guard locationID == twinHIDDevice.locationID, self.didClose === didClose, let channel else {
            throw .connectionLost
        }
        do {
            return try await channel.receive()
        } catch TwinKitSupportError.connectionLost {
            throw .connectionLost
        } catch {
            throw .receiveFailed("TwinKit CTAPHID read failed", error)
        }
    }
}

actor HIDOTPConnectionManager {
    static let shared = HIDOTPConnectionManager()

    private struct Connection {
        let channel: TwinKitKeyboardChannel
        let didClose: Promise<Error?>
    }
    private var connection: Connection?
    private var opening = false

    func availableDevices() -> [HID.YubiKeyDevice] {
        TwinKitConfiguration.exposesUSBInterface(0x01) ? [twinHIDDevice] : []
    }

    func open(device: HID.YubiKeyDevice, didClose: Promise<Error?>) async throws(OTPConnectionError) {
        guard device == twinHIDDevice, !availableDevices().isEmpty else { throw .noDevicesFound }
        guard connection == nil, !opening else { throw .busy }
        opening = true
        defer { opening = false }
        do {
            let channel = try await TwinKitBackend.shared.openKeyboard()
            connection = Connection(channel: channel, didClose: didClose)
        } catch {
            throw .setupFailed("Could not open TwinKit keyboard HID", error)
        }
    }

    func close(locationID: Int, didClose: Promise<Error?>, error: Error?) async {
        guard locationID == twinHIDDevice.locationID, let connection, connection.didClose === didClose else { return }
        self.connection = nil
        connection.channel.close(error: error)
        await connection.didClose.fulfill(error)
    }

    func setFeatureReport(
        _ report: Data,
        to locationID: Int,
        didClose: Promise<Error?>
    ) async throws(OTPConnectionError) {
        let channel = try channel(locationID: locationID, didClose: didClose)
        do {
            try await channel.send(report)
        } catch TwinKitSupportError.connectionLost {
            throw .connectionLost
        } catch {
            throw .transmitFailed("TwinKit keyboard write failed", error)
        }
    }

    func getFeatureReport(from locationID: Int, didClose: Promise<Error?>) async throws(OTPConnectionError) -> Data {
        let channel = try channel(locationID: locationID, didClose: didClose)
        do {
            return try await channel.receive()
        } catch TwinKitSupportError.connectionLost {
            throw .connectionLost
        } catch {
            throw .receiveFailed("TwinKit keyboard read failed", error)
        }
    }

    private func channel(
        locationID: Int,
        didClose: Promise<Error?>
    ) throws(OTPConnectionError) -> TwinKitKeyboardChannel {
        guard locationID == twinHIDDevice.locationID, let connection, connection.didClose === didClose else {
            throw .connectionLost
        }
        return connection.channel
    }
}

#endif

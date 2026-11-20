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

import Foundation
import YubiKitTwinSupport

final actor SmartCardConnectionsManager {
    static let shared = SmartCardConnectionsManager()
    private init() {}
    private static let slot = USBSmartCard.YubiKeyDevice(name: "YubiKey Simulator (USB)")
    private static let contactlessSlot = USBSmartCard.YubiKeyDevice(name: "YubiKey Simulator (NFC)")
    private var connections: [USBSmartCard.YubiKeyDevice: State] = [:]
    private var isEstablishing = false

    func close(slot: USBSmartCard.YubiKeyDevice, id: UUID, error: Error?) async {
        guard let state = connections[slot], state.lifetime.id == id else { return }
        connections[slot] = nil
        state.channel.close(error: error)
        await state.lifetime.didClose.fulfill(error)
    }

    func isConnected(for slot: USBSmartCard.YubiKeyDevice, id: UUID) -> Bool {
        connections[slot]?.lifetime.id == id
    }

    func availableDevices(matching: String?) async throws(SmartCardConnectionError) -> [USBSmartCard.YubiKeyDevice] {
        let slots: [USBSmartCard.YubiKeyDevice]
        #if os(macOS)
        if try TwinKitConfiguration.isPresent(.nfc) {
            slots = [Self.contactlessSlot]
        } else {
            slots = try TwinKitConfiguration.isPresent(.usb) ? [Self.slot] : []
        }
        #else
        slots = try TwinKitConfiguration.isPresent(.usb) ? [Self.slot] : []
        #endif
        guard let matching else { return slots }
        return slots.filter { $0.name.localizedCaseInsensitiveContains(matching) }
    }

    func connect(
        slot: USBSmartCard.YubiKeyDevice,
        lifetime: ConnectionLifetime
    ) async throws(SmartCardConnectionError) -> Data? {
        guard !Task.isCancelled else { throw .cancelled }
        guard try await availableDevices(matching: nil).contains(slot) else { throw .noDevicesFound }
        let contactless = slot == Self.contactlessSlot
        guard connections[slot] == nil, !isEstablishing else { throw .busy }
        isEstablishing = true
        defer { isEstablishing = false }
        let channel: TwinKitSmartCardChannel
        do { channel = try await TwinKitBackend.shared.openSmartCard(transport: contactless ? .nfc : .usb) } catch {
            throw .setupFailed("TwinKit USB open failed", error)
        }
        if Task.isCancelled {
            channel.close(error: nil)
            throw .cancelled
        }
        connections[slot] = State(channel: channel, lifetime: lifetime)
        return Data([0x3b, contactless ? 0x00 : 0xf0])
    }

    func transmit(
        request: Data,
        for slot: USBSmartCard.YubiKeyDevice,
        id: UUID
    ) async throws(SmartCardConnectionError) -> Data {
        guard let state = connections[slot], state.lifetime.id == id else { throw .connectionLost }
        do {
            logger.traceRequest(request)
            let response = try await state.channel.send(request)
            logger.traceResponse(response)
            return response
        } catch TwinKitSupportError.connectionLost {
            throw .connectionLost
        } catch {
            throw .transmitFailed("TwinKit USB exchange failed", error)
        }
    }

    private final class State {
        let channel: TwinKitSmartCardChannel
        let lifetime: ConnectionLifetime
        init(channel: TwinKitSmartCardChannel, lifetime: ConnectionLifetime) {
            self.channel = channel
            self.lifetime = lifetime
        }
    }
}

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

@preconcurrency import CryptoTokenKit.TKSmartCard
import Foundation
import Logging

// Handles TKSmartCard creation and connections, plus KVOs for changes
final actor SmartCardConnectionsManager {

    // Singleton
    static let shared = SmartCardConnectionsManager()
    private init() {}

    // We must lock around slot.makeSmartCard() and card.beginSession()
    // we can only establish a connection at once
    private var isEstablishing: Bool = false

    private var slotManager: TKSmartCardSlotManager {
        get throws(SmartCardConnectionError) {
            guard let manager = TKSmartCardSlotManager.default else {
                assertionFailure("🪪 No default TKSmartCardSlotManager, check entitlements for com.apple.smartcard.")
                logger.debug("USB smart card slot manager is unavailable")
                throw SmartCardConnectionError.unsupported
            }

            return manager
        }
    }

    private var connections = [USBSmartCard.YubiKeyDevice: ConnectionState]()

    func close(slot: USBSmartCard.YubiKeyDevice, id: UUID, error: Error?) async {
        guard let state = connections[slot], state.lifetime.id == id else { return }
        await state.lifetime.didClose.fulfill(error)
        endSession(state, for: slot)
    }

    func isConnected(for slot: USBSmartCard.YubiKeyDevice, id: UUID) -> Bool {
        guard let state = connections[slot], state.lifetime.id == id else {
            return false
        }

        return state.card.isValid && state.card.currentProtocol != []
    }

    func transmit(
        request: Data,
        for slot: USBSmartCard.YubiKeyDevice,
        id: UUID
    ) async throws(SmartCardConnectionError) -> Data {
        guard let state = connections[slot], state.lifetime.id == id else {
            throw SmartCardConnectionError.connectionLost
        }

        do {
            logger.traceRequest(request)
            let response = try await state.card.transmit(request)
            logger.traceResponse(response)
            return response
        } catch let error as SmartCardConnectionError {
            throw error
        } catch {
            // Map TKSmartCard errors to SmartCardConnectionError
            throw SmartCardConnectionError.transmitFailed("USB transmit failed", flatten: error)
        }
    }

    // Returns the ATR of the connected card.
    func connect(
        slot: USBSmartCard.YubiKeyDevice,
        lifetime: ConnectionLifetime
    ) async throws(SmartCardConnectionError) -> Data? {
        guard !Task.isCancelled else { throw .cancelled }
        // if there is already a connection for this slot we throw `SmartCardConnectionError.busy`.
        // The caller must close the connection first.
        guard connections[slot] == nil else {
            logger.debug("USB smart card is already connected")
            throw SmartCardConnectionError.busy
        }

        // To proceed with a new connection we need to acquire a lock
        // so we can guarantee balanced calls to beginSession()
        guard !isEstablishing else {
            logger.debug("USB smart card connection setup is already in progress")
            throw SmartCardConnectionError.busy
        }
        defer { isEstablishing = false }
        isEstablishing = true

        // get a TKSmartCard from a slot
        // can fail if no cards are connected
        let tkSlot = try? await slotManager.getSlot(withName: slot.name)
        guard !Task.isCancelled else { throw .cancelled }

        guard let tkSlot else {
            logger.debug("USB smart card slot is no longer available")
            throw SmartCardConnectionError.setupFailed("Failed to connect to slot \(slot.name)")
        }

        guard let card = tkSlot.makeSmartCard() else {
            logger.debug("Failed to create USB smart card")
            throw SmartCardConnectionError.setupFailed("Failed to create SmartCard from slot")
        }

        logger.debug("Opening USB smart card session")
        do {
            guard try await card.beginSession() else {
                logger.debug("USB smart card session was not opened")
                throw SmartCardConnectionError.setupFailed("Failed to begin SmartCard session (returned nil)")
            }
        } catch {
            logger.debug(
                "USB smart card session setup failed",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
            if Task.isCancelled { throw SmartCardConnectionError.cancelled }
            throw SmartCardConnectionError.setupFailed("Failed to begin SmartCard session", error)
        }
        if Task.isCancelled {
            card.endSession()
            throw SmartCardConnectionError.cancelled
        }
        logger.debug("USB smart card connection established")

        // create and save a new connection state
        let state = ConnectionState(card: card, lifetime: lifetime)
        connections[slot] = state

        // register for the eventual clean up when the connection is closed
        Task {
            _ = try await state.lifetime.didClose.value()
            endSession(state, for: slot)
        }

        return tkSlot.atr?.bytes
    }

    private func endSession(_ state: ConnectionState, for slot: USBSmartCard.YubiKeyDevice) {
        guard connections[slot] === state else { return }
        state.card.endSession()
        connections[slot] = nil
        logger.debug("USB smart card session closed")
    }

    func availableDevices(matching: String?) async throws(SmartCardConnectionError) -> [USBSmartCard.YubiKeyDevice] {
        let loweredFilter = matching?.lowercased()
        return try slotManager.slotNames
            .filter { name in
                guard let loweredFilter else { return true }
                return name.lowercased().contains(loweredFilter)
            }
            .map(USBSmartCard.YubiKeyDevice.init)
    }
}

private class ConnectionState {
    let card: TKSmartCard

    let lifetime: ConnectionLifetime

    private let isValidObserver: NSKeyValueObservation
    private let stateObserver: NSKeyValueObservation

    init(card: TKSmartCard, lifetime: ConnectionLifetime) {
        self.lifetime = lifetime
        let didClose = lifetime.didClose
        self.card = card

        stateObserver = card.observe(\.currentProtocol, options: [.new]) { [didClose] card, _ in
            if card.currentProtocol == [] {
                Task { await didClose.fulfill(nil) }
            }
        }

        isValidObserver = card.observe(\.isValid, options: [.new]) { [didClose] card, _ in
            if !card.isValid {
                Task { await didClose.fulfill(nil) }
            }
        }
    }
}

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

/// Namespace for USB SmartCard related types.
public enum USBSmartCard {
    /// Represents a YubiKey device available as a smart card slot.
    public struct YubiKeyDevice: Sendable, Hashable, CustomStringConvertible {
        /// The name of the smart card slot.
        public let name: String

        /// String representation of the device, same as name.
        public var description: String { name }

        init?(name: String) {
            guard name.lowercased().contains("yubikey") else { return nil }
            self.name = name
        }
    }
}

#if !(YUBIKIT_TWINKIT && DEBUG && targetEnvironment(simulator))

@preconcurrency import CryptoTokenKit.TKSmartCard
import Logging

/// A connection to the YubiKey utilizing the USB port and the TKSmartCard implementation from
/// the CryptoTokenKit framework.
@available(iOS 16.0, macOS 13.0, *)
public struct USBSmartCardConnection: Sendable {
    /// The smart card slot this connection is associated with.
    public let slot: USBSmartCard.YubiKeyDevice

    private let didClose: Promise<Error?>

    /// Creates a new USB connection to the first available YubiKey.
    ///
    /// Waits for a YubiKey to be connected via USB and establishes a connection to it.
    /// This method waits until a YubiKey becomes available.
    ///
    /// - Throws: ``SmartCardConnectionError/busy`` if there is already an active connection.
    public init() async throws(SmartCardConnectionError) {
        while true {
            guard let slot = try await Self.availableDevices().first else {
                try? await Task.sleep(for: .seconds(1))
                continue
            }
            try await self.init(slot: slot)
            return
        }
    }

    /// Creates a new USB connection to a specific YubiKey device.
    ///
    /// Establishes a connection to the specified YubiKey device slot.
    ///
    /// - Parameter slot: The ``USBSmartCard/YubiKeyDevice`` to connect to.
    /// - Throws: ``SmartCardConnectionError/busy`` if there is already an active connection to this slot.
    public init(slot: USBSmartCard.YubiKeyDevice) async throws(SmartCardConnectionError) {
        let didClose = Promise<Error?>()
        try await SmartCardConnectionsManager.shared.connect(slot: slot, didClose: didClose)
        self.slot = slot
        self.didClose = didClose
    }

    /// Returns all available smart card slots that contain YubiKeys.
    public static func availableDevices() async throws(SmartCardConnectionError) -> [USBSmartCard.YubiKeyDevice] {
        try await SmartCardConnectionsManager.shared.availableDevices()
    }

}

extension USBSmartCardConnection: SmartCardConnection {

    /// Creates a connection to the first available YubiKey smart card slot.
    ///
    /// > Warning: Connections must be explicitly closed using ``close(error:)``.
    /// Only one connection can exist at a time - attempting to create another will throw ``SmartCardConnectionError/busy``.
    ///
    /// - Returns: A fully–established connection ready for APDU exchange.
    /// - Throws: ``SmartCardConnectionError/busy`` if another connection is active, or other SmartCardConnectionError if no YubiKey is found or connection fails.
    public static func makeConnection() async throws(SmartCardConnectionError) -> USBSmartCardConnection {
        try await USBSmartCardConnection()
    }

    /// Creates a connection to a specific smart card slot.
    ///
    /// > Warning: Connections must be explicitly closed using ``close(error:)``.
    /// Only one connection can exist at a time - attempting to create another will throw ``SmartCardConnectionError/busy``.
    ///
    /// - Parameter slot: The smart card slot to connect to.
    /// - Returns: A fully–established connection ready for APDU exchange.
    /// - Throws: ``SmartCardConnectionError/busy`` if another connection is active, or other SmartCardConnectionError if connection fails.
    public static func makeConnection(
        slot: USBSmartCard.YubiKeyDevice
    ) async throws(SmartCardConnectionError) -> USBSmartCardConnection {
        try await USBSmartCardConnection(slot: slot)
    }

    /// Closes the smart card connection with an optional error.
    ///
    /// - Parameter error: Optional error to indicate why the connection was closed.
    public func close(error: Error?) async {
        await didClose.fulfill(error)
        if let error {
            logger.debug(
                "Closing USB smart card connection with an error",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
        } else {
            logger.debug("Closing USB smart card connection")
        }
    }

    /// Waits for the connection to close and returns any error that caused the closure.
    ///
    /// - Returns: An error if the connection was closed due to an error, nil otherwise.
    public func waitUntilClosed() async -> Error? {
        logger.debug("Waiting for USB smart card connection to close")
        let error = try? await didClose.value()
        if let error {
            logger.debug(
                "USB smart card connection closed with an error",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
        } else {
            logger.debug("USB smart card connection closed")
        }
        return error
    }

    /// Sends raw data to the smart card and returns the response.
    ///
    /// - Parameter data: Raw APDU bytes to send.
    /// - Returns: The response data from the card.

    public func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        logger.debug("Sending USB smart card request", metadata: ["bytes": .stringConvertible(data.count)])
        let response = try await SmartCardConnectionsManager.shared.transmit(
            request: data,
            for: slot,
            didClose: didClose
        )
        logger.debug("Received USB smart card response", metadata: ["bytes": .stringConvertible(response.count)])
        return response
    }
}

// MARK: - Internal helpers / extensions
extension USBSmartCardConnection: HasSmartCardLogger {}
extension SmartCardConnectionsManager: HasSmartCardLogger {}

// MARK: - Private helpers

// Handles TKSmartCard creation and connections, plus KVOs for changes
private final actor SmartCardConnectionsManager {

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

    func transmit(
        request: Data,
        for slot: USBSmartCard.YubiKeyDevice,
        didClose: Promise<Error?>
    ) async throws(SmartCardConnectionError) -> Data {
        guard let state = connections[slot], state.didClose === didClose,
            state.card.isValid, state.card.currentProtocol != []
        else {
            logger.debug("Cannot send on a closed USB smart card connection")
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

    func connect(slot: USBSmartCard.YubiKeyDevice, didClose: Promise<Error?>) async throws(SmartCardConnectionError) {
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
            throw SmartCardConnectionError.cancelled
        }
        defer { isEstablishing = false }
        isEstablishing = true

        // get a TKSmartCard from a slot
        // can fail if no cards are connected
        let tkSlot = try? await slotManager.getSlot(withName: slot.name)

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
            throw SmartCardConnectionError.setupFailed("Failed to begin SmartCard session", error)
        }
        logger.debug("USB smart card connection established")

        // create and save a new connection state
        let state = ConnectionState(card: card, didClose: didClose)
        connections[slot] = state

        // register for the eventual clean up when the connection is closed
        Task {
            _ = try await state.didClose.value()
            state.card.endSession()
            logger.debug("USB smart card session closed")
            if connections[slot] === state {
                connections[slot] = nil
            }
        }

        // success; otherwise it would throw
        return
    }

    func availableDevices() async throws(SmartCardConnectionError) -> [USBSmartCard.YubiKeyDevice] {
        try slotManager.slotNames.compactMap(USBSmartCard.YubiKeyDevice.init)
    }
}

private class ConnectionState {
    let card: TKSmartCard

    let didClose: Promise<Error?>

    private let isValidObserver: NSKeyValueObservation
    private let stateObserver: NSKeyValueObservation

    init(card: TKSmartCard, didClose: Promise<Error?>) {
        self.card = card
        self.didClose = didClose

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

#endif

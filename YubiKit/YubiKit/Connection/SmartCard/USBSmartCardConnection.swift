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
import Logging

/// A connection to the YubiKey utilizing the USB port and the TKSmartCard implementation from
/// the CryptoTokenKit framework.
@available(iOS 16.0, macOS 13.0, *)
public struct USBSmartCardConnection: Sendable {
    /// The smart card slot this connection is associated with.
    public let slot: USBSmartCard.YubiKeyDevice

    /// Whether the reader communicates with the YubiKey over NFC, inferred from the card's ATR.
    /// The host-to-reader connection still uses USB.
    package let isContactless: Bool

    private let didClose = Promise<Error?>()

    @usableFromInline static let defaultNameFilter = "YubiKey"

    /// Creates a new USB connection to the first available YubiKey.
    ///
    /// Waits until a YubiKey becomes available, then establishes a connection to it.
    ///
    /// - Throws: ``SmartCardConnectionError/cancelled`` if the task is cancelled while waiting,
    ///   or ``SmartCardConnectionError/busy`` if there is already an active connection.
    public init() async throws(SmartCardConnectionError) {
        let slot = try await waitForDevice(cancellationError: SmartCardConnectionError.cancelled) {
            () async throws(SmartCardConnectionError) in
            try await Self.availableDevices()
        }
        try await self.init(slot: slot)
    }

    /// Creates a new USB connection to a specific YubiKey device.
    ///
    /// Establishes a connection to the specified YubiKey device slot.
    ///
    /// - Parameter slot: The ``USBSmartCard/YubiKeyDevice`` to connect to.
    /// - Throws: ``SmartCardConnectionError/busy`` if there is already an active connection to this slot.
    public init(slot: USBSmartCard.YubiKeyDevice) async throws(SmartCardConnectionError) {
        guard !Task.isCancelled else { throw .cancelled }
        let atr = try await SmartCardConnectionsManager.shared.connect(slot: slot, didClose: didClose)
        self.slot = slot
        self.isContactless = USBSmartCard.isNFC(atr: atr)
    }

    /// Returns the available smart card slots.
    ///
    /// - Parameter matching: A case-insensitive substring a slot's name must contain, or `nil` for every slot.
    public static func availableDevices(
        matching: String? = Self.defaultNameFilter
    ) async throws(SmartCardConnectionError) -> [USBSmartCard.YubiKeyDevice] {
        try await SmartCardConnectionsManager.shared.availableDevices(matching: matching)
    }

    private var isConnected: Bool {
        get async { await SmartCardConnectionsManager.shared.isConnected(for: slot, didClose: didClose) }
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
        await SmartCardConnectionsManager.shared.close(slot: slot, didClose: didClose, error: error)
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
        guard await isConnected else {
            logger.debug("Cannot send on a closed USB smart card connection")
            throw SmartCardConnectionError.connectionLost
        }
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

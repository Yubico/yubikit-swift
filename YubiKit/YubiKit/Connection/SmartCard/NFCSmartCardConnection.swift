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

#if os(iOS)

import Foundation

extension SmartCardConnection {
    /// Returns this connection as an NFCSmartCardConnection if it is one.
    public var nfcConnection: NFCSmartCardConnection? {
        self as? NFCSmartCardConnection
    }
}

import Logging

// MARK: - Public API

/// A NFC connection to the YubiKey.
///
/// The  NFCSmartCardConnection is short lived and should be closed as soon as the commands sent to the YubiKey have finished processing. It is up to the user of
/// the connection to close it when it no longer is needed. As long as the connection is open the NFC modal will cover the lower part of the iPhone screen.
/// In addition to the ``close(error:)`` method defined in the SmartCardConnection protocol the NFCSmartCardConnection has an additional ``close(success:)``
/// method that will close the connection and set the alertMessage of the NFC alert to the provided message.
///
/// > Note: NFC is only supported on iPhones from iPhone 6 and forward. It will not work on iPads since there's no NFC chip in these devices.
public struct NFCSmartCardConnection: SmartCardConnection, Sendable {
    let lifetime = ConnectionLifetime()

    /// Creates a new NFC connection to a YubiKey.
    ///
    /// Presents the NFC sheet and waits for the user to tap a YubiKey to establish a connection.
    ///
    /// - Throws: ``SmartCardConnectionError.unsupported`` when NFC is unavailable or
    ///           ``SmartCardConnectionError.busy`` if there is already an active connection.
    public init() async throws(SmartCardConnectionError) {
        Self.logger.debug("Requesting NFC connection")
        try await NFCConnectionManagerWrapper.shared.connect(message: nil, lifetime: lifetime)
    }

    /// Creates a new NFC connection to a YubiKey.
    ///
    /// Presents the NFC sheet and waits for the user to tap a YubiKey to establish a connection.
    ///
    /// - Parameter alertMessage: Optional text shown while scanning.
    /// - Throws: ``SmartCardConnectionError.unsupported`` when NFC is unavailable or
    ///           ``SmartCardConnectionError.busy`` if there is already an active connection.
    public init(alertMessage: String?) async throws(SmartCardConnectionError) {
        Self.logger.debug("Requesting NFC connection")
        try await NFCConnectionManagerWrapper.shared.connect(message: alertMessage, lifetime: lifetime)
    }

    /// Creates a new NFC connection to a YubiKey.
    ///
    /// Presents the NFC sheet and waits for the user to tap a YubiKey to establish a connection.
    ///
    /// - Returns: A fully–established connection ready for APDU exchange.
    /// - Throws: ``SmartCardConnectionError.unsupported`` when NFC is unavailable or
    ///           ``SmartCardConnectionError.busy`` if there is already an active connection.
    public static func makeConnection() async throws(SmartCardConnectionError) -> NFCSmartCardConnection {
        Self.logger.debug("Requesting NFC connection")
        return try await NFCSmartCardConnection(alertMessage: nil)
    }

    /// Creates a new NFC connection to a YubiKey.
    ///
    /// Presents the NFC sheet and waits for the user to tap a YubiKey to establish a connection.
    ///
    /// - Parameter message: Optional text shown while scanning.
    /// - Returns: A fully–established connection ready for APDU exchange.
    /// - Throws: ``SmartCardConnectionError.unsupported`` when NFC is unavailable or
    ///           ``SmartCardConnectionError.busy`` if there is already an active connection.
    public static func makeConnection(
        alertMessage message: String?
    ) async throws(SmartCardConnectionError) -> NFCSmartCardConnection {
        Self.logger.debug("Requesting NFC connection")
        return try await NFCSmartCardConnection(alertMessage: message)
    }

    /// Sets the alert message displayed on the NFC scanning sheet.
    ///
    /// - Parameter message: The message to display while scanning.
    public func setAlertMessage(_ message: String) async {
        logger.debug("Updating NFC alert message")
        await NFCConnectionManagerWrapper.shared.set(alertMessage: message, id: lifetime.id)
    }

    /// Closes the NFC connection with an optional error.
    ///
    /// - Parameter error: Optional error to indicate why the connection was closed.
    public func close(error: Error?) async {
        if let error = error {
            logger.debug(
                "Closing NFC connection with an error",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
            await NFCConnectionManagerWrapper.shared.stop(id: lifetime.id, with: .failure(error))
        } else {
            logger.debug("Closing NFC connection")
            await NFCConnectionManagerWrapper.shared.stop(id: lifetime.id, with: .success(nil))
        }
    }

    /// Closes the NFC connection with a success message.
    ///
    /// - Parameter message: Optional success message to display when closing.
    public func close(message: String? = nil) async {
        logger.debug("Closing NFC connection")
        await NFCConnectionManagerWrapper.shared.stop(id: lifetime.id, with: .success(message))
    }

    /// Waits for the connection to close and returns any error that caused the closure.
    ///
    /// - Returns: An error if the connection was closed due to an error, nil otherwise.
    public func waitUntilClosed() async -> Error? {
        logger.debug("Waiting for NFC connection to close")
        let error = try? await lifetime.didClose.value()
        if let error {
            logger.debug(
                "NFC connection closed with an error",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
        } else {
            logger.debug("NFC connection closed")
        }
        return error
    }

    /// Sends an APDU over the active NFC link.
    ///
    /// - Parameter data: Raw APDU bytes.
    /// - Returns: The response payload concatenated with status words SW1 SW2.
    /// - Throws: ``SmartCardConnectionError.connectionLost`` if the tag is no longer
    ///           attached or ``SmartCardConnectionError.malformedData`` when `data`
    ///           is not a valid APDU.
    public func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        logger.debug("Sending NFC request", metadata: ["bytes": .stringConvertible(data.count)])
        let response = try await NFCConnectionManagerWrapper.shared.transmit(request: data, for: self)
        logger.debug("Received NFC response", metadata: ["bytes": .stringConvertible(response.count)])
        return response
    }

}

// MARK: - Extensions

extension NFCSmartCardConnection: HasNFCLogger {}

#endif

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
import Logging

/// A connection to the YubiKey utilizing the Lightning port and External Accessory framework.
@available(iOS 16.0, *)
public struct LightningSmartCardConnection: SmartCardConnection, Sendable {
    let lifetime: ConnectionLifetime

    /// Creates a new Lightning connection to a YubiKey.
    ///
    /// Waits for a YubiKey to be connected via Lightning port and establishes a connection.
    ///
    /// - Throws: ``SmartCardConnectionError.busy`` if there is already an active connection.
    public init() async throws(SmartCardConnectionError) {
        lifetime = try await LightningConnectionManager.shared.connect()
    }

    /// Creates a connection to a YubiKey via Lightning port.
    ///
    /// > Warning: Connections must be explicitly closed using ``close(error:)``.
    /// Only one connection can exist at a time - attempting to create another will throw ``SmartCardConnectionError/busy``.
    /// - Returns: A fully–established connection ready for APDU exchange.
    /// - Throws: ``SmartCardConnectionError.busy`` if there is already an active connection.
    public static func makeConnection() async throws(SmartCardConnectionError) -> LightningSmartCardConnection {
        logger.debug("Requesting Lightning connection")
        return try await LightningSmartCardConnection()
    }

    public func close(error: Error?) async {
        if let error {
            logger.debug(
                "Closing Lightning connection with an error",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
        } else {
            logger.debug("Closing Lightning connection")
        }
        await LightningConnectionManager.shared.close(id: lifetime.id, error: error)
    }

    public func waitUntilClosed() async -> Error? {
        logger.debug("Waiting for Lightning connection to close")
        let error = try? await lifetime.didClose.value()
        if let error {
            logger.debug(
                "Lightning connection closed with an error",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
        } else {
            logger.debug("Lightning connection closed")
        }
        return error
    }

    public func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        logger.debug("Sending Lightning request", metadata: ["bytes": .stringConvertible(data.count)])
        let commands = data.lightningCommands
        var response = Data()
        for (index, command) in commands.enumerated() {
            response = try await LightningConnectionManager.shared.transmit(request: command, id: lifetime.id)
            // A chained part is acknowledged with 9000; anything else ends the command early.
            if index < commands.count - 1, response.suffix(2) != Data([0x90, 0x00]) { break }
        }
        logger.debug("Received Lightning response", metadata: ["bytes": .stringConvertible(response.count)])
        return response
    }

}

// MARK: - Internal helpers / extensions

// Downcast helper
extension SmartCardConnection {
    public var lightningConnection: LightningSmartCardConnection? {
        self as? LightningSmartCardConnection
    }
}

extension LightningSmartCardConnection: HasLightningLogger {}
extension LightningConnectionManager: HasLightningLogger {}

// MARK: - Command chaining

extension Data {
    // A YLP frame carries at most 512 bytes: the 1-byte header and the APDU. An extended APDU that does
    // not fit is sent as short APDUs linked with the ISO 7816 chaining bit (CLA 0x10).
    fileprivate var lightningCommands: [Data] {
        let bytes = [UInt8](self)
        guard bytes.count + 1 > 512, bytes[4] == 0x00 else { return [self] }
        let length = Int(bytes[5]) << 8 | Int(bytes[6])
        guard length > 0, bytes.count >= 7 + length else { return [self] }
        let body = bytes[7..<(7 + length)]
        // A 2-byte extended Le becomes the short Le 0x00 (as much as possible); the rest follows via 61xx.
        let le: [UInt8] = bytes.count > 7 + length ? [0x00] : []

        var commands: [Data] = []
        var offset = body.startIndex
        while offset < body.endIndex {
            let chunk = body[offset..<Swift.min(offset + 255, body.endIndex)]
            offset = chunk.endIndex
            let isLast = offset == body.endIndex
            let cla = isLast ? bytes[0] : bytes[0] | 0x10
            commands.append(Data([cla, bytes[1], bytes[2], bytes[3], UInt8(chunk.count)] + chunk + (isLast ? le : [])))
        }
        return commands
    }
}

#endif

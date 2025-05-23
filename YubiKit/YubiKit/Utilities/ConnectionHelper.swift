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

#if canImport(CoreNFC)
import CoreNFC
#endif

/// ConnectionHelper simplifies the creation of different connections to the YubiKey. It can either return
/// a connection of any type from a single function or provide a AsyncSequence implementation allowing
/// you to use a for loop awaiting YubiKeys to be inserted and removed from a device.
///
/// The ConnectionHelper provides functions to simplify implementation supporting different types of
/// connections.
///
/// ```swift
///// Get a Lightning or a SmartCard connection to the YubiKey
///let wiredConnection = try await ConnectionHelper.anyWiredConnection()
///
///// Get a wired or an NFC connection to the YubiKey. If no wired YubiKey
///// is present and the device supports NFC the SDK will start a NFC scan.
///let anyConnection = try await ConnectionHelper.anyConnection()
///
///// Create a AsyncSequence of wired connections to the YubiKey. Every
///// time a YubiKey is inserted it will return a new Connection.
///for try await connection in ConnectionHelper.wiredConnections() {
///    let session = try await OATHSession.session(withConnection: connection)
///    // Use session to calculate codes
///    await connection.connectionDidClose()
///    // Clean up when YubiKey is removed from device
///}
/// ```
public enum ConnectionHelper {

    /// Returns a Connection of any type. If a USB-C or Lightning YubiKey is present a connection to that key will be returned, otherwise
    /// the NFCConnection will start scanning for a YubiKey.
    /// >Note: LightningConnection and NFCConnection are only available on iOS.
    public static func anyConnection(nfcAlertMessage: String? = nil) async throws -> Connection {
        let connection = try await withThrowingTaskGroup(of: Connection.self) { group -> Connection in
            #if os(iOS)
            if NFCNDEFReaderSession.readingAvailable {
                group.addTask {
                    try await Task.sleep(for: .seconds(1))  // wait for wired connected yubikeys to connect before starting NFC
                    try Task.checkCancellation()
                    return try await NFCConnection.connection(alertMessage: nfcAlertMessage)
                }
            }
            group.addTask {
                return try await LightningConnection.connection()
            }
            #endif
            group.addTask {
                return try await SmartCardConnection.connection()
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
        return connection
    }

    /// Returns either a LightningConnection or a SmartCardConnection. If a YubiKey is present it will return the connection
    /// immediately. If no key is present it will wait and return the connection once a YubiKey has been inserted into the device.
    public static func anyWiredConnection() async throws -> Connection {
        let connection = try await withThrowingTaskGroup(of: Connection.self) { group -> Connection in
            #if os(iOS)
            group.addTask {
                return try await LightningConnection.connection()
            }
            #endif
            group.addTask {
                return try await SmartCardConnection.connection()
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
        return connection
    }

    /// Returns an AsyncSequence of wired connections.
    public static func wiredConnections() -> ConnectionHelper.AnyWiredConnections {
        AnyWiredConnections()
    }

    public struct AnyWiredConnections: AsyncSequence {
        public typealias Element = Connection
        var current: Connection? = nil
        public struct AsyncIterator: AsyncIteratorProtocol {
            mutating public func next() async -> Element? {
                while true {
                    return try? await ConnectionHelper.anyWiredConnection()
                }
            }
        }

        public func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator()
        }
    }
}

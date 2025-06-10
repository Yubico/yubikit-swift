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
///let wiredConnection = try await Connections.new(kind: .wired)
///
///// Get a wired or an NFC connection to the YubiKey. If no wired YubiKey
///// is present and the device supports NFC the SDK will start a NFC scan.
///let someConnection = try await Connections.new()
/// ```
public enum Connections {

    public enum Kind {
        case smartCard
        case wired
        case any(nfcAlertMessage: String? = nil)

        static let any = Kind.any(nfcAlertMessage: nil)

        #if os(iOS)
        case lightning
        case nfc(alertMessage: String? = nil)

        static let nfc = Kind.nfc(alertMessage: nil)
        #endif
    }

    public static func new(kind: Connections.Kind = .any()) async throws -> Connection {
        switch kind {
        case .smartCard:
            return try await SmartCardConnection.connection()
        #if os(iOS)
        case .lightning:
            return try await LightningConnection.connection()
        case let .nfc(alertMessage):
            return try await NFCConnection.connection(alertMessage: alertMessage)
        #endif
        case .wired:
            return try await wired()
        case let .any(nfcAlertMessage):
            return try await any(nfcAlertMessage: nfcAlertMessage)
        }
    }

    private static func wired() async throws -> Connection {
        let connection = try await withThrowingTaskGroup(of: Connection.self) { group -> Connection in
            #if os(iOS)
            group.addTask {
                try await LightningConnection.connection()
            }
            #endif
            group.addTask {
                try await SmartCardConnection.connection()
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
        return connection
    }

    private static func any(nfcAlertMessage: String? = nil) async throws -> Connection {
        let connection = try await withThrowingTaskGroup(of: Connection.self) { group -> Connection in
            #if os(iOS)
            if NFCNDEFReaderSession.readingAvailable {
                group.addTask {
                    // wait for wired connected yubikeys to connect before starting NFC
                    try await Task.sleep(for: .seconds(1))
                    try Task.checkCancellation()
                    return try await NFCConnection.connection(alertMessage: nfcAlertMessage)
                }
            }
            group.addTask {
                try await LightningConnection.connection()
            }
            #endif
            group.addTask {
                try await SmartCardConnection.connection()
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
        return connection
    }
}

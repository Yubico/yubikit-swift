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

public enum WiredConnection {
    /// Establishes a Lightning or SmartCard connection to a YubiKey.
    ///
    /// Call this method to connect to a YubiKey using a wired interface such as Lightning or SmartCard.
    /// The method will suspend until a compatible YubiKey is detected and a connection is established.
    ///
    /// - Returns: A ``Connection`` instance representing the established wired connection.
    /// - Throws: An error if a connection could not be established.
    ///
    /// ```swift
    /// let wiredConnection = try await WiredConnection.connection()
    /// ```
    public static func connection() async throws -> Connection {
        try await Connections.new(kind: .wired)
    }
}

public enum AnyConnection {
    /// Establishes a connection to a YubiKey over either wired or NFC.
    ///
    /// Use this method to connect to a YubiKey using any available interface. If no wired YubiKey
    /// is present and the device supports NFC, the SDK will initiate an NFC scan.
    ///
    /// You can optionally provide a custom NFC alert message to be displayed to the user when
    /// prompting for NFC scanning.
    ///
    /// - Parameter nfcAlertMessage: An optional message shown to the user during NFC scanning.
    /// - Returns: A ``Connection`` instance representing the established connection, either wired or NFC.
    /// - Throws: An error if a connection could not be established.
    ///
    /// ```swift
    /// let someConnection = try await AnyConnection.connection()
    /// ```
    public static func connection(nfcAlertMessage: String? = nil) async throws -> Connection {
        try await Connections.new(kind: .any(nfcAlertMessage: nfcAlertMessage))
    }
}

private enum Connections {

    fileprivate enum Kind {
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

    fileprivate static func new(kind: Connections.Kind) async throws -> Connection {
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

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

public enum WiredSmartCardConnection: Sendable {
    /// Establishes a Lightning or SmartCard connection to a YubiKey.
    ///
    /// Call this method to connect to a YubiKey using a wired interface such as Lightning or SmartCard.
    /// The method will suspend until a compatible YubiKey is detected and a connection is established.
    ///
    /// - Returns: A ``SmartCardConnection`` instance representing the established wired connection.
    /// - Throws: An error if a connection could not be established.
    ///
    /// ```swift
    /// let wiredConnection = try await WiredSmartCardConnection.connection()
    /// ```
    public static func connection() async throws -> SmartCardConnection {
        try await SmartCardConnections.new(kind: .wired)
    }
}

private enum SmartCardConnections {

    fileprivate enum Kind {
        case usb
        case wired
        case any(nfcAlertMessage: String? = nil)

        static let any = Kind.any(nfcAlertMessage: nil)

        #if os(iOS)
        case lightning
        case nfc(alertMessage: String? = nil)

        static let nfc = Kind.nfc(alertMessage: nil)
        #endif
    }

    fileprivate static func new(kind: SmartCardConnections.Kind) async throws -> SmartCardConnection {
        switch kind {
        case .usb:
            return try await USBSmartCardConnection()
        #if os(iOS)
        case .lightning:
            return try await LightningSmartCardConnection()
        case let .nfc(alertMessage):
            return try await NFCSmartCardConnection(alertMessage: alertMessage)
        #endif
        case .wired:
            return try await wired()
        case let .any(nfcAlertMessage):
            return try await any(nfcAlertMessage: nfcAlertMessage)
        }
    }

    private static func wired() async throws -> SmartCardConnection {
        let connection = try await withThrowingTaskGroup(of: SmartCardConnection.self) { group -> SmartCardConnection in
            #if os(iOS)
            if Device.hasLightningPort {
                group.addTask {
                    try await LightningSmartCardConnection()
                }
            } else {
                group.addTask {
                    try await USBSmartCardConnection()
                }
            }
            #else
            group.addTask {
                try await USBSmartCardConnection()
            }
            #endif

            let result = try await group.next()!
            group.cancelAll()
            return result
        }
        return connection
    }

    private static func any(nfcAlertMessage: String? = nil) async throws -> SmartCardConnection {
        let connection = try await withThrowingTaskGroup(of: SmartCardConnection.self) { group -> SmartCardConnection in
            #if os(iOS)
            if Device.supportsNFC {
                group.addTask {
                    // wait for wired connected yubikeys to connect before starting NFC
                    try await Task.sleep(for: .seconds(0.75))
                    try Task.checkCancellation()
                    return try await NFCSmartCardConnection(alertMessage: nfcAlertMessage)
                }
            }
            #endif
            group.addTask {
                try await wired()
            }

            let result = try await group.next()!
            group.cancelAll()
            return result
        }
        return connection
    }
}

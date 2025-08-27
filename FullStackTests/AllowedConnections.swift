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
import OSLog
import XCTest

@testable import YubiKit

// These Yubikeys are allowed for tests.
// Add your own personal test YubiKeys to this list.
let allowedSerialNumbers: [UInt] = [
    14_453_003,  // 5C NFC (5.2.6)
    30_617_000,  // 5C NFC (5.7.1)
    32_133_203,  // NFC FIPS (5.7.4)
    31_683_782,  // YubiKey 5C FIPS (5.7.4)
]

enum TestableConnection {

    public enum Kind {
        // This is the default connection for the tests.
        // Change to test different types of connection.
        static let `default`: TestableConnection.Kind = .smartCard

        case smartCard

        #if os(iOS)
        case lightning
        case nfc(alertMessage: String?)

        static let nfc = Kind.nfc(alertMessage: nil)
        #endif
    }

    static func shared(with kind: Kind = .default) async throws -> SmartCardConnection {
        try await ConnectionManager.shared.connection(with: kind)
    }

    static func create(with kind: Kind = .default) async throws -> SmartCardConnection {

        let connection: SmartCardConnection?
        switch kind {
        case .smartCard:
            connection = try await smartCard()

        #if os(iOS)
        case .lightning:
            connection = try await lightning()
        case let .nfc(alertMessage):
            connection = try await nfc(alertMessage: alertMessage)
        #endif
        }

        guard let connection = connection else {
            fatalError(
                """
                No YubiKey found.

                Please insert a YubiKey and run the test again.

                If a YubiKey is inserted but not recognized, it may not be allowed.
                Consider adding its serial number to the `allowedSerialNumbers` array.
                """
            )
        }

        return connection
    }

    private static func smartCard() async throws -> SmartCardConnection? {
        let smartCardConnections = try await USBSmartCardConnection.all
        for connection in smartCardConnections {
            if try await connection.isAllowed {
                return connection
            } else {
                continue
            }
        }
        return nil
    }

    #if os(iOS)
    private static func lightning() async throws -> SmartCardConnection? {
        let connection = try await LightningSmartCardConnection.connection()
        guard try await connection.isAllowed else { return nil }
        return connection
    }

    private static func nfc(alertMessage: String? = nil) async throws -> SmartCardConnection? {
        let connection = try await NFCSmartCardConnection.connection(alertMessage: alertMessage)
        guard try await connection.isAllowed else { return nil }
        return connection
    }
    #endif
}

extension USBSmartCardConnection {
    fileprivate static var all: [SmartCardConnection] {
        get async throws {
            let slots = try await USBSmartCardConnection.availableDevices

            var connections: [SmartCardConnection?] = []
            for slot in slots {
                connections.append(try? await USBSmartCardConnection.connection(slot: slot))
            }
            return connections.compactMap { $0 }
        }
    }
}

extension SmartCardConnection {
    fileprivate var isAllowed: Bool {
        get async throws {
            let session = try await ManagementSession.session(withConnection: self)
            let deviceInfo = try await session.getDeviceInfo()
            return allowedSerialNumbers.contains(deviceInfo.serialNumber)
        }
    }
}

private final class ConnectionManager {
    static let shared = ConnectionManager()

    func connection(with kind: TestableConnection.Kind = .default) async throws -> SmartCardConnection {
        if let previous = previous, previous.kind == kind {
            return previous.connection
        }

        let new = try await TestableConnection.create(with: kind)
        previous = (kind, new)

        return new
    }

    private init() {}
    private var previous: (kind: TestableConnection.Kind, connection: SmartCardConnection)? = nil
}

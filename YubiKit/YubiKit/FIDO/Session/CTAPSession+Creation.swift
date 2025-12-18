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

// MARK: - Session Creation

extension CTAP2.Session {
    /// Create a FIDO2 session over USB/HID connection.
    ///
    /// - Parameter connection: A FIDO (USB HID) connection to the YubiKey.
    /// - Returns: A new FIDO2 session.
    /// - Throws: ``CTAP2/SessionError`` if session creation fails.
    public static func makeSession(connection: FIDOConnection) async throws -> CTAP2.Session {
        let fidoInterface = try await FIDOInterface<CTAP2.SessionError>(connection: connection)
        return await CTAP2.Session(interface: Interface(interface: fidoInterface))
    }
}

extension CTAP2.Session {
    /// Create a FIDO2 session over NFC/SmartCard connection.
    ///
    /// - Parameters:
    ///   - connection: A SmartCard (NFC) connection to the YubiKey.
    ///   - application: The FIDO2 application to select (defaults to .fido2).
    /// - Returns: A new FIDO2 session over NFC.
    /// - Throws: ``CTAP2/SessionError`` if session creation fails.
    public static func makeSession(
        connection: SmartCardConnection,
        application: Application = .fido2
    ) async throws -> CTAP2.Session {
        let smartCardInterface = try await SmartCardInterface<CTAP2.SessionError>(
            connection: connection,
            application: application
        )
        return await CTAP2.Session(interface: Interface(interface: smartCardInterface))
    }
}

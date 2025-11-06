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

// Type aliases for convenience
typealias FIDO2Session = CTAP.Session<FIDOInterface<FIDO2SessionError>>
typealias FIDO2SessionOverSmartCard = CTAP.Session<SmartCardInterface<FIDO2SessionError>>

extension CTAP {

    /// A generic interface to the FIDO2/CTAP2 authenticator on the YubiKey.
    ///
    /// Use the FIDO2 session to interact with the CTAP2 authenticator for WebAuthn/FIDO2
    /// operations like credential creation, authentication, and device information.
    /// This generic version works with any interface that conforms to ``CBORInterface``,
    /// allowing FIDO2 operations over both USB (HID) and NFC (SmartCard) transports.
    ///
    /// Read more about FIDO2/WebAuthn on the
    /// [FIDO Alliance website](https://fidoalliance.org/fido2/).
    final actor Session<I: CBORInterface> where I.Error == FIDO2SessionError {

        typealias Error = FIDO2SessionError

        /// The underlying interface for communication (FIDOInterface or SmartCardInterface).
        let interface: I

        /// The firmware version of the YubiKey.
        let version: Version

        init(interface: I) async {
            self.interface = interface
            self.version = await interface.version
        }

        /// Get authenticator information.
        ///
        /// Returns information about the authenticator including supported versions,
        /// extensions, capabilities, and configuration.
        ///
        /// This command does not require user verification or PIN.
        ///
        /// > Note: This functionality requires support for ``CTAP/Feature/getInfo``, available on YubiKey 5.0 or later.
        ///
        /// - Returns: The authenticator information structure.
        /// - Throws: ``FIDO2SessionError`` if the operation fails.
        func getInfo() async throws -> AuthenticatorInfo {
            let info: AuthenticatorInfo? = try await interface.send(command: .getInfo)

            guard let info = info else {
                throw Error.responseParseError("Failed to parse authenticatorGetInfo response", source: .here())
            }

            return info
        }
    }
}

// MARK: - Session Creation

extension CTAP.Session where I == FIDOInterface<FIDO2SessionError> {
    /// Create a FIDO2 session over USB/HID connection.
    ///
    /// - Parameter connection: A FIDO (USB HID) connection to the YubiKey.
    /// - Returns: A new FIDO2 session.
    /// - Throws: ``FIDO2SessionError`` if session creation fails.
    static func makeSession(connection: FIDOConnection) async throws -> FIDO2Session {
        let interface = try await FIDOInterface<FIDO2SessionError>(connection: connection)
        return await CTAP.Session(interface: interface)
    }
}

extension CTAP.Session where I == SmartCardInterface<FIDO2SessionError> {
    /// Create a FIDO2 session over NFC/SmartCard connection.
    ///
    /// - Parameters:
    ///   - connection: A SmartCard (NFC) connection to the YubiKey.
    ///   - application: The FIDO2 application to select (defaults to .fido2).
    /// - Returns: A new FIDO2 session over NFC.
    /// - Throws: ``FIDO2SessionError`` if session creation fails.
    static func makeSession(
        connection: SmartCardConnection,
        application: Application = .fido2
    ) async throws -> FIDO2SessionOverSmartCard {
        let interface = try await SmartCardInterface<FIDO2SessionError>(
            connection: connection,
            application: application
        )
        return await CTAP.Session(interface: interface)
    }
}

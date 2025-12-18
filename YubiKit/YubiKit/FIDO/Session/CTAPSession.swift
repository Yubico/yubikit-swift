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

extension CTAP2 {

    /// Interface to the FIDO2/CTAP authenticator on the YubiKey.
    ///
    /// Use the FIDO2 session to interact with the CTAP authenticator for WebAuthn/FIDO2
    /// operations like credential creation, authentication, and device information.
    /// Supports both USB (HID) and NFC (SmartCard) transports.
    ///
    /// Read more about FIDO2/WebAuthn on the
    /// [FIDO Alliance website](https://fidoalliance.org/fido2/).
    public actor Session {
        /// The firmware version of the YubiKey.
        public let version: Version

        /// Get authenticator information.
        ///
        /// Returns information about the authenticator including supported versions,
        /// extensions, capabilities, and configuration.
        ///
        /// This command does not require user verification or PIN.
        ///
        /// > Note: This functionality is available on YubiKey 5.0 or later.
        ///
        /// - Returns: The authenticator information structure.
        /// - Throws: ``CTAP2/SessionError`` if the operation fails.
        public func getInfo() async throws(CTAP2.SessionError) -> CTAP2.GetInfo.Response {
            let stream: CTAP2.StatusStream<CTAP2.GetInfo.Response> = await interface.send(command: .getInfo)
            let response = try await stream.value
            cachedInfo = response
            await interface.setMaxMsgSize(Int(response.maxMsgSize))
            return response
        }

        /// Request user presence check for authenticator selection.
        ///
        /// This command allows the platform to let a user select a specific authenticator
        /// by asking for user presence (typically a touch or button press). This is useful
        /// when multiple authenticators are available and the user needs to indicate which
        /// one to use.
        ///
        /// The command will wait for the user to confirm their presence on the authenticator.
        /// It completes successfully once user presence is detected.
        ///
        /// > Note: This functionality is available on YubiKey 5.0 or later.
        ///
        /// - Returns: A ``CTAP2/StatusStream`` that yields status updates and completes with `Void`.
        public func selection() async -> CTAP2.StatusStream<Void> {
            await interface.send(command: .selection)
        }

        /// Reset the CTAP authenticator.
        ///
        /// This command deletes all FIDO credentials, removes the PIN, and resets
        /// the authenticator to factory settings.
        ///
        /// > Warning: Over USB this command must be sent within a few seconds of
        /// > plugging the YubiKey in, and it requires user presence confirmation (touch).
        /// > Over NFC, this command requires user presence confirmation.
        ///
        /// > Note: This functionality is available on YubiKey 5.0 or later.
        ///
        /// - Returns: A ``CTAP2/StatusStream`` that yields status updates and completes with `Void`.
        public func reset() async -> CTAP2.StatusStream<Void> {
            await interface.send(command: .reset)
        }

        // MARK: - Internal

        internal let interface: Interface

        // Cached GetInfo.Response, populated after first getInfo() call.
        fileprivate var cachedInfo: CTAP2.GetInfo.Response?

        internal init(interface: Interface) async {
            self.interface = interface
            self.version = await interface.version
        }

    }
}

extension CTAP2 {
    /// Status updates for long-running CTAP operations.
    ///
    /// These status values are derived from CTAP keep-alive messages sent by the authenticator
    /// during operations that require user interaction or processing time.
    ///
    /// - Note: Operations return an `AsyncStream` of status updates, culminating in a `.finished(Response)` value.
    public enum Status<Response>: Sendable where Response: Sendable {
        /// The authenticator is processing the request.
        case processing

        /// The authenticator is waiting for user interaction.
        ///
        /// - Parameter cancel: Closure to cancel the operation. Any errors during cancellation
        ///   will be propagated through the stream.
        case waitingForUser(cancel: @Sendable () async -> Void)

        /// The operation completed successfully with a response.
        ///
        /// - Parameter response: The decoded response from the authenticator.
        case finished(Response)
    }
}

// MARK: - Internal helpers for ClientPin decision-making
extension CTAP2.Session {

    private var getInfoResponse: CTAP2.GetInfo.Response {
        get async throws(CTAP2.SessionError) {
            if let cachedInfo {
                return cachedInfo
            } else {
                return try await getInfo()
            }
        }
    }

    // Prefer v2 when available
    var preferredClientPinProtocol: CTAP2.ClientPin.ProtocolVersion {
        get async throws(CTAP2.SessionError) {
            if try await getInfoResponse.pinUVAuthProtocols.contains(.v2) {
                return .v2
            } else {
                return .v1
            }
        }
    }

    // Check if authenticator supports pinUVAuthToken (CTAP 2.1+)
    var supportsTokenPermissions: Bool {
        get async throws(CTAP2.SessionError) {
            try await getInfoResponse.options.pinUVAuthToken == true
        }
    }
}

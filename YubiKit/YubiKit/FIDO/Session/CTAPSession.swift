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
typealias FIDO2Session = CTAP.Session<FIDOInterface<CTAP.SessionError>>
typealias FIDO2SessionOverSmartCard = CTAP.Session<SmartCardInterface<CTAP.SessionError>>

extension CTAP {

    /// A generic interface to the FIDO2/CTAP authenticator on the YubiKey.
    ///
    /// Use the FIDO2 session to interact with the CTAP authenticator for WebAuthn/FIDO2
    /// operations like credential creation, authentication, and device information.
    /// This generic version works with any interface that conforms to ``CBORInterface``,
    /// allowing FIDO2 operations over both USB (HID) and NFC (SmartCard) transports.
    ///
    /// Read more about FIDO2/WebAuthn on the
    /// [FIDO Alliance website](https://fidoalliance.org/fido2/).
    final actor Session<I: CBORInterface> where I.Error == CTAP.SessionError {

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
        /// - Throws: ``CTAP.SessionError`` if the operation fails.
        func getInfo() async throws(CTAP.SessionError) -> CTAP.GetInfo.Response {
            let stream: CTAP.StatusStream<CTAP.GetInfo.Response> = await interface.send(command: .getInfo)
            return try await stream.value
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
        /// > Note: This functionality requires support for ``CTAP/Feature/reset``, available on YubiKey 5.0 or later.
        ///
        /// - Throws: ``CTAP.SessionError`` if the operation fails.
        func reset() async throws(CTAP.SessionError) {
            let stream: CTAP.StatusStream<Never?> = await interface.send(command: .reset)
            let _ = try await stream.value
            return
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
        /// > Note: This functionality requires support for ``CTAP/Feature/selection``, available on YubiKey 5.0 or later.
        ///
        /// - Throws: ``CTAP.SessionError`` if the operation fails or times out.
        func selection() async throws(CTAP.SessionError) {
            let stream: CTAP.StatusStream<Never?> = await interface.send(command: .selection)
            let _ = try await stream.value
            return
        }
    }
}

extension CTAP {
    /// Status updates for long-running CTAP operations.
    ///
    /// These status values are derived from CTAP keep-alive messages sent by the authenticator
    /// during operations that require user interaction or processing time.
    ///
    /// - Note: Operations return an `AsyncStream` of status updates, culminating in a `.finished(Response)` value.
    public enum Status<Response>: Sendable where Response: Sendable {
        /// The authenticator is processing the request.
        case processing

        /// The authenticator is waiting for user presence (touch).
        ///
        /// - Parameter cancel: Closure to cancel the operation. Any errors during cancellation
        ///   will be propagated through the stream.
        case waitingForUserPresence(cancel: @Sendable () async -> Void)

        /// The authenticator is waiting for user verification (PIN or biometric).
        ///
        /// - Parameter cancel: Closure to cancel the operation. Any errors during cancellation
        ///   will be propagated through the stream.
        case waitingForUserVerification(cancel: @Sendable () async -> Void)

        /// The operation completed successfully with a response.
        ///
        /// - Parameter response: The decoded response from the authenticator.
        case finished(Response)
    }
}

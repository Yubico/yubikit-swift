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
        func getInfo() async throws -> CTAP.GetInfo.Response {
            let info: CTAP.GetInfo.Response? = try await interface.send(command: .getInfo)

            guard let info = info else {
                throw Error.responseParseError("Failed to parse authenticatorGetInfo response", source: .here())
            }

            return info
        }

        /// Reset the CTAP2 authenticator.
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
        /// - Throws: ``FIDO2SessionError`` if the operation fails.
        func reset() async throws {
            try await interface.send(command: .reset)
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
        /// - Throws: ``FIDO2SessionError`` if the operation fails or times out.
        func selection() async throws {
            try await interface.send(command: .selection)
        }

        /// Cancel any ongoing CTAP operation waiting for user interaction.
        ///
        /// Sends a cancel command to abort operations such as `makeCredential` or `getAssertion`
        /// that are waiting for user presence (touch) or user verification (PIN/biometric).
        /// The cancelled operation will throw ``FIDO2SessionError/ctapError(_:source:)``
        /// with ``CTAP/Error/keepaliveCancel``.
        ///
        /// > Note: The session remains usable after cancellation and can be used for subsequent operations.
        ///
        /// - Throws: ``FIDO2SessionError`` if the cancel command fails to send.
        ///
        /// - SeeAlso: [CTAP 2.2 - CTAPHID_CANCEL](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#usb-hid-cancel)
        func cancel() async throws {
            try await interface.cancel()
        }

        /// Create a new credential on the authenticator.
        ///
        /// This command registers a new FIDO2 credential with the authenticator. The authenticator
        /// will verify user presence (and optionally user verification via PIN/biometric), generate
        /// a new credential keypair, and return attestation data.
        ///
        /// > Important: This operation requires user interaction (touch) and may require PIN entry
        /// > if user verification is requested.
        ///
        /// > Note: This functionality requires support for ``CTAP/Feature/makeCredential``, available on YubiKey 5.0 or later.
        ///
        /// - Parameter parameters: The credential creation parameters.
        /// - Returns: The credential data including attestation information.
        /// - Throws: ``FIDO2SessionError`` if the operation fails.
        ///
        /// - SeeAlso: [CTAP2 authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#authenticatorMakeCredential)
        func makeCredential(parameters: CTAP.MakeCredential.Parameters) async throws -> CTAP.MakeCredential.Response {
            let credentialData: CTAP.MakeCredential.Response? = try await interface.send(
                command: .makeCredential,
                payload: parameters
            )

            guard let credentialData = credentialData else {
                throw Error.responseParseError(
                    "Failed to parse makeCredential response",
                    source: .here()
                )
            }

            return credentialData
        }

        /// Get an authentication assertion from the authenticator.
        ///
        /// This command generates an authentication assertion for an existing credential. The authenticator
        /// will verify user presence (and optionally user verification via PIN/biometric), locate the
        /// credential, and return an assertion containing a signature over the authenticator data and
        /// client data hash.
        ///
        /// > Important: This operation requires user interaction (touch) unless the `up` option is set to false.
        /// > It may require PIN entry if user verification is requested.
        ///
        /// > Note: This functionality requires support for ``CTAP/Feature/getAssertion``, available on YubiKey 5.0 or later.
        ///
        /// - Parameter parameters: The assertion request parameters.
        /// - Returns: The assertion response including signature and authenticator data.
        /// - Throws: ``FIDO2SessionError`` if the operation fails.
        ///
        /// - SeeAlso: [CTAP2 authenticatorGetAssertion](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#authenticatorGetAssertion)
        func getAssertion(parameters: CTAP.GetAssertion.Parameters) async throws -> CTAP.GetAssertion.Response {
            let assertionResponse: CTAP.GetAssertion.Response? = try await interface.send(
                command: .getAssertion,
                payload: parameters
            )

            guard let assertionResponse = assertionResponse else {
                throw Error.responseParseError(
                    "Failed to parse getAssertion response",
                    source: .here()
                )
            }

            return assertionResponse
        }

        /// Get the next assertion when multiple credentials are available.
        ///
        /// After calling ``getAssertion(parameters:)``, if the response contains `numberOfCredentials > 1`,
        /// call this method repeatedly to retrieve the remaining assertions. Each call returns the next
        /// available assertion until all have been retrieved.
        ///
        /// > Important: This command must only be called after a successful ``getAssertion(parameters:)`` call
        /// > that returned `numberOfCredentials > 1`. Calling it at other times will result in an error.
        ///
        /// > Note: This functionality requires support for ``CTAP/Feature/getNextAssertion``, available on YubiKey 5.0 or later.
        ///
        /// - Returns: The next assertion response.
        /// - Throws: ``FIDO2SessionError`` if the operation fails.
        ///
        /// - SeeAlso: [CTAP2 authenticatorGetNextAssertion](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#authenticatorGetNextAssertion)
        func getNextAssertion() async throws -> CTAP.GetAssertion.Response {
            let assertionResponse: CTAP.GetAssertion.Response? = try await interface.send(
                command: .getNextAssertion
            )

            guard let assertionResponse = assertionResponse else {
                throw Error.responseParseError(
                    "Failed to parse getNextAssertion response",
                    source: .here()
                )
            }

            return assertionResponse
        }

        // MARK: - Multiple Assertions

        /// Get all assertions as an async sequence.
        ///
        /// Returns an async sequence that lazily fetches assertions one at a time. This automatically
        /// handles calling ``getAssertion(parameters:)`` for the first assertion and ``getNextAssertion()``
        /// for subsequent assertions based on `numberOfCredentials`.
        ///
        /// When only one credential matches, the sequence yields a single assertion. When multiple credentials
        /// are available (resident key discovery with no allowList), the sequence yields all of them.
        ///
        /// - Parameter parameters: The assertion request parameters.
        /// - Returns: An async sequence of assertion responses.
        /// - SeeAlso: ``getAssertion(parameters:)`` for low-level access to a single assertion.
        func getAssertions(
            parameters: CTAP.GetAssertion.Parameters
        ) -> AssertionSequence<I> {
            AssertionSequence(session: self, parameters: parameters)
        }
    }
}

// MARK: - AssertionSequence

/// An async sequence of assertion responses.
///
/// This sequence lazily fetches assertions from the authenticator, calling ``CTAP/Session/getAssertion(parameters:)``
/// for the first assertion and ``CTAP/Session/getNextAssertion()`` for subsequent assertions.
///
/// Use ``CTAP/Session/getAssertions(parameters:)`` to create instances of this type.
struct AssertionSequence<I: CBORInterface>: AsyncSequence where I.Error == FIDO2SessionError {
    typealias Element = CTAP.GetAssertion.Response
    typealias Failure = any Error

    let session: CTAP.Session<I>
    let parameters: CTAP.GetAssertion.Parameters

    fileprivate init(session: CTAP.Session<I>, parameters: CTAP.GetAssertion.Parameters) {
        self.session = session
        self.parameters = parameters
    }

    func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(session: session, parameters: parameters)
    }

    /// Iterator for assertion responses.
    struct AsyncIterator: AsyncIteratorProtocol {
        typealias Element = CTAP.GetAssertion.Response

        let session: CTAP.Session<I>
        let parameters: CTAP.GetAssertion.Parameters

        var currentIndex = 0
        var totalCredentials = 0

        mutating func next() async throws -> CTAP.GetAssertion.Response? {
            if currentIndex == 0 {
                // Get first assertion
                let response = try await session.getAssertion(parameters: parameters)
                totalCredentials = response.numberOfCredentials ?? 1
                currentIndex = 1
                return response
            } else if currentIndex < totalCredentials {
                // Get next assertion
                currentIndex += 1
                return try await session.getNextAssertion()
            } else {
                // Done iterating
                return nil
            }
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

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

// MARK: - GetAssertion

extension CTAP.Session {

    /// Authenticate with a credential.
    ///
    /// Generates an authentication assertion for an existing credential. This is used during
    /// WebAuthn authentication to prove possession of the private key for a credential.
    ///
    /// The authenticator validates the request, locates the credential, and generates a signature
    /// over the authenticator data and client data hash using the credential's private key.
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

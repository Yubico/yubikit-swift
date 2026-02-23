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

extension CTAP2.Session {

    /// Authenticate with a credential on the authenticator.
    ///
    /// When a `token` is provided, the `uv` option is automatically cleared.
    ///
    /// - Parameters:
    ///   - parameters: The assertion request parameters.
    ///   - token: Optional PIN/UV auth token obtained via ``getPinUVToken(using:permissions:rpId:protocol:)``.
    /// - Returns: AsyncStream of status updates, ending with `.finished(response)` containing the assertion data
    ///
    /// - SeeAlso: [CTAP 2.2 authenticatorGetAssertion](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorGetAssertion)
    public func getAssertion(
        parameters: CTAP2.GetAssertion.Parameters,
        token: CTAP2.Token? = nil
    ) async -> CTAP2.StatusStream<CTAP2.GetAssertion.Response> {
        guard let token else {
            return await interface.send(command: .getAssertion, payload: parameters)
        }
        var params = parameters
        params.setAuthentication(token: token)
        return await interface.send(command: .getAssertion, payload: params)
    }

    /// Get the next assertion when multiple credentials are available.
    ///
    /// After calling ``getAssertion(parameters:token:)``, if the response contains `numberOfCredentials > 1`,
    /// call this method repeatedly to retrieve the remaining assertions. Each call returns the next
    /// available assertion until all have been retrieved.
    ///
    /// > Important: This command must only be called after a successful ``getAssertion(parameters:token:)`` call
    /// > that returned `numberOfCredentials > 1`. Calling it at other times will result in an error.
    ///
    /// > Note: This functionality is available on YubiKey 5.0 or later.
    ///
    /// - Returns: AsyncStream of status updates, ending with `.finished(response)` containing the next assertion
    ///
    /// - SeeAlso: [CTAP 2.2 authenticatorGetNextAssertion](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorGetNextAssertion)
    public func getNextAssertion() async -> CTAP2.StatusStream<CTAP2.GetAssertion.Response> {
        await interface.send(command: .getNextAssertion)
    }

    // MARK: - Multiple Assertions

    /// Get all assertions as an async sequence.
    ///
    /// Returns an async sequence that lazily fetches assertions one at a time. This automatically
    /// handles calling ``getAssertion(parameters:token:)`` for the first assertion and
    /// ``getNextAssertion()`` for subsequent assertions based on `numberOfCredentials`.
    ///
    /// When a `token` is provided, the `uv` option is automatically cleared.
    ///
    /// - Parameters:
    ///   - parameters: The assertion request parameters.
    ///   - token: Optional PIN/UV auth token obtained via ``getPinUVToken(using:permissions:rpId:protocol:)``.
    /// - Returns: An async sequence of assertion responses.
    ///
    /// - SeeAlso: ``getAssertion(parameters:token:)`` for low-level access to a single assertion.
    public func getAssertions(
        parameters: CTAP2.GetAssertion.Parameters,
        token: CTAP2.Token? = nil
    ) async -> CTAP2.GetAssertion.Sequence {
        guard let token else {
            return .init(session: self, parameters: parameters)
        }
        var params = parameters
        params.setAuthentication(token: token)
        return .init(session: self, parameters: params)
    }
}

// MARK: - CTAP.GetAssertion.Sequence

/// An async sequence of assertion responses.
///
/// This sequence lazily fetches assertions from the authenticator, calling
/// ``CTAP2/Session/getAssertion(parameters:token:)`` for the first assertion and
/// ``CTAP2/Session/getNextAssertion()`` for subsequent assertions.
///
/// Use ``CTAP2/Session/getAssertions(parameters:token:)`` to create instances of this type.
///
/// > Note: When created with a `token`, the PIN/UV auth fields are pre-set on the stored
/// > parameters before the sequence is constructed. The iterator sends these pre-authenticated
/// > parameters without a separate token.
extension CTAP2.GetAssertion {
    public struct Sequence: AsyncSequence {
        public typealias Element = CTAP2.GetAssertion.Response

        let session: CTAP2.Session
        /// Parameters with optional PIN/UV auth fields pre-set by the session method.
        let parameters: CTAP2.GetAssertion.Parameters

        fileprivate init(
            session: CTAP2.Session,
            parameters: CTAP2.GetAssertion.Parameters
        ) {
            self.session = session
            self.parameters = parameters
        }

        public func makeAsyncIterator() -> Iterator {
            Iterator(session: session, parameters: parameters)
        }
    }
}

extension CTAP2.GetAssertion {
    /// Iterator that fetches assertions one at a time from the authenticator.
    ///
    /// Created by ``Sequence/makeAsyncIterator()``. Use ``CTAP2/Session/getAssertions(parameters:token:)`` instead of instantiating directly.
    public actor Iterator: AsyncIteratorProtocol {
        public typealias Element = CTAP2.GetAssertion.Response

        let session: CTAP2.Session
        let parameters: CTAP2.GetAssertion.Parameters

        var currentIndex = 0
        var totalCredentials = 0

        fileprivate init(
            session: CTAP2.Session,
            parameters: CTAP2.GetAssertion.Parameters
        ) {
            self.session = session
            self.parameters = parameters
        }

        public func next() async throws(CTAP2.SessionError) -> CTAP2.GetAssertion.Response? {
            if currentIndex == 0 {
                // Send parameters as-is (auth fields already set if pinToken was provided)
                let stream = await session.getAssertion(parameters: parameters)
                for try await status in stream {
                    if case .finished(let response) = status {
                        totalCredentials = response.numberOfCredentials ?? 1
                        currentIndex = 1
                        return response
                    }
                }
                throw CTAP2.SessionError.responseParseError("No response from GetAssertion", source: .here())
            } else if currentIndex < totalCredentials {
                // Get next assertion
                let stream = await session.getNextAssertion()
                for try await status in stream {
                    if case .finished(let response) = status {
                        currentIndex += 1
                        return response
                    }
                }
                throw CTAP2.SessionError.responseParseError("No response from GetNextAssertion", source: .here())
            } else {
                // Done iterating
                return nil
            }
        }
    }
}

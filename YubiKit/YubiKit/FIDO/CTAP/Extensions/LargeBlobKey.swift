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

// MARK: - LargeBlobKey Extension

extension CTAP2.Extension {
    /// The largeBlobKey extension for associating large blobs with credentials.
    ///
    /// This extension is used to request a largeBlobKey during credential creation
    /// or assertion. The key can then be used with the LargeBlobs API to store
    /// and retrieve arbitrary data associated with the credential.
    ///
    /// ## MakeCredential Usage
    ///
    /// Request a largeBlobKey when creating a credential:
    /// ```swift
    /// let largeBlobKey = CTAP2.Extension.LargeBlobKey()
    /// let params = CTAP2.MakeCredential.Parameters(
    ///     ...,
    ///     extensions: [largeBlobKey.makeCredential.input()]
    /// )
    /// let response = try await session.makeCredential(params)
    /// if let key = largeBlobKey.makeCredential.output(from: response) {
    ///     // Store key for later blob operations
    /// }
    /// ```
    ///
    /// ## GetAssertion Usage
    ///
    /// Retrieve a largeBlobKey during authentication:
    /// ```swift
    /// let largeBlobKey = CTAP2.Extension.LargeBlobKey()
    /// let params = CTAP2.GetAssertion.Parameters(
    ///     ...,
    ///     extensions: [largeBlobKey.getAssertion.input()]
    /// )
    /// let response = try await session.getAssertion(params)
    /// if let key = largeBlobKey.getAssertion.output(from: response) {
    ///     // Use key with LargeBlobs API
    /// }
    /// ```
    ///
    /// - SeeAlso: [CTAP2 largeBlobKey Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-largeBlobKey-extension)
    public struct LargeBlobKey: Sendable {
        /// The extension identifier for largeBlobKey.
        static let identifier: Identifier = .largeBlobKey

        // MARK: - Initializer

        /// Creates a LargeBlobKey extension instance.
        public init() {}

        /// Checks if the authenticator supports largeBlobKey.
        ///
        /// - Parameter session: The CTAP2 session to check.
        /// - Returns: `true` if the authenticator supports large blobs.
        public static func isSupported(
            by session: CTAP2.Session
        ) async throws(CTAP2.SessionError) -> Bool {
            let info = try await session.getInfo()
            return info.options.largeBlobs == true
        }

        // MARK: - Operations

        /// Operations for MakeCredential.
        public var makeCredential: MakeCredentialOperations {
            MakeCredentialOperations()
        }

        /// Operations for GetAssertion.
        public var getAssertion: GetAssertionOperations {
            GetAssertionOperations()
        }
    }
}

// MARK: - MakeCredential Operations

extension CTAP2.Extension.LargeBlobKey {
    /// MakeCredential operations for largeBlobKey.
    public struct MakeCredentialOperations: Sendable {

        /// Creates a MakeCredential input to request a largeBlobKey.
        ///
        /// - Returns: An extension input for MakeCredential.
        public func input() -> CTAP2.Extension.MakeCredential.Input {
            CTAP2.Extension.MakeCredential.Input(
                encoded: [CTAP2.Extension.LargeBlobKey.identifier: .boolean(true)]
            )
        }

        /// Extracts the largeBlobKey from a MakeCredential response.
        ///
        /// The largeBlobKey is returned in the top-level response, not in
        /// authenticator data extensions.
        ///
        /// - Parameter response: The MakeCredential response from the authenticator.
        /// - Returns: The 32-byte largeBlobKey, or `nil` if not present.
        public func output(from response: CTAP2.MakeCredential.Response) -> Data? {
            response.largeBlobKey
        }
    }
}

// MARK: - GetAssertion Operations

extension CTAP2.Extension.LargeBlobKey {
    /// GetAssertion operations for largeBlobKey.
    public struct GetAssertionOperations: Sendable {

        /// Creates a GetAssertion input to request a largeBlobKey.
        ///
        /// - Returns: An extension input for GetAssertion.
        public func input() -> CTAP2.Extension.GetAssertion.Input {
            CTAP2.Extension.GetAssertion.Input(
                encoded: [CTAP2.Extension.LargeBlobKey.identifier: .boolean(true)]
            )
        }

        /// Extracts the largeBlobKey from a GetAssertion response.
        ///
        /// The largeBlobKey is returned in the top-level response, not in
        /// authenticator data extensions.
        ///
        /// - Parameter response: The GetAssertion response from the authenticator.
        /// - Returns: The 32-byte largeBlobKey, or `nil` if not present.
        public func output(from response: CTAP2.GetAssertion.Response) -> Data? {
            response.largeBlobKey
        }
    }
}

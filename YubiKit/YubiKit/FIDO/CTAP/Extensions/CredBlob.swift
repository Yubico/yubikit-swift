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

// MARK: - CredBlob Extension

extension CTAP2.Extension {
    /// The credBlob extension for storing small blobs with discoverable credentials.
    ///
    /// This extension allows storing a small amount of data (up to `maxCredBlobLength`
    /// bytes) with a credential during registration, and retrieving it during authentication.
    ///
    /// - SeeAlso: [CTAP2 credBlob Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-credBlob-extension)
    public struct CredBlob: Sendable {
        /// The extension identifier for credBlob.
        static let identifier: Identifier = .credBlob

        /// Maximum blob length supported by the authenticator.
        private let maxLength: UInt?

        // MARK: - Initializer

        /// Creates a CredBlob extension instance.
        ///
        /// - Parameter session: The CTAP2 session to check for support.
        /// - Throws: `CTAP2.SessionError.extensionNotSupported` if credBlob is not supported.
        public init(session: CTAP2.Session) async throws(CTAP2.SessionError) {
            let info = try await session.cachedInfo
            guard info.extensions.contains(Self.identifier) else {
                throw .extensionNotSupported(Self.identifier, source: .here())
            }
            self.maxLength = info.maxCredBlobLength
        }

        /// Checks if the authenticator supports credBlob.
        ///
        /// - Parameter session: The CTAP2 session to check.
        /// - Returns: `true` if the authenticator supports credBlob.
        public static func isSupported(by session: CTAP2.Session) async throws(CTAP2.SessionError) -> Bool {
            let info = try await session.cachedInfo
            return info.extensions.contains(identifier)
        }

        // MARK: - Operations

        /// Operations for MakeCredential.
        public var makeCredential: MakeCredentialOperations {
            MakeCredentialOperations(parent: self)
        }

        /// Operations for GetAssertion.
        public var getAssertion: GetAssertionOperations {
            GetAssertionOperations()
        }
    }
}

// MARK: - MakeCredential Operations

extension CTAP2.Extension.CredBlob {
    /// MakeCredential operations for credBlob.
    public struct MakeCredentialOperations: Sendable {
        fileprivate let parent: CTAP2.Extension.CredBlob

        /// Creates a MakeCredential input to store a blob with the credential.
        ///
        /// - Parameter blob: The data to store (must not exceed `maxCredBlobLength`).
        /// - Returns: An extension input for MakeCredential.
        /// - Throws: `CTAP2.SessionError.illegalArgument` if the blob exceeds the maximum length.
        public func input(blob: Data) throws(CTAP2.SessionError) -> CTAP2.Extension.MakeCredential.Input {
            if let maxLength = parent.maxLength, blob.count > maxLength {
                throw .illegalArgument("Blob exceeds max length (\(blob.count) > \(maxLength))", source: .here())
            }
            return CTAP2.Extension.MakeCredential.Input(
                encoded: [CTAP2.Extension.CredBlob.identifier: .byteString(blob)]
            )
        }

        /// Extracts the credBlob result from a MakeCredential response.
        ///
        /// - Parameter response: The MakeCredential response from the authenticator.
        /// - Returns: `true` if stored, `false` if failed, or `nil` if not present.
        public func output(from response: CTAP2.MakeCredential.Response) -> Bool? {
            response.authenticatorData.extensions?[CTAP2.Extension.CredBlob.identifier]?.boolValue
        }
    }
}

// MARK: - GetAssertion Operations

extension CTAP2.Extension.CredBlob {
    /// GetAssertion operations for credBlob.
    public struct GetAssertionOperations: Sendable {

        /// Creates a GetAssertion input to retrieve the stored blob.
        ///
        /// - Returns: An extension input for GetAssertion.
        public func input() -> CTAP2.Extension.GetAssertion.Input {
            CTAP2.Extension.GetAssertion.Input(
                encoded: [CTAP2.Extension.CredBlob.identifier: .boolean(true)]
            )
        }

        /// Extracts the credBlob data from a GetAssertion response.
        ///
        /// - Parameter response: The GetAssertion response from the authenticator.
        /// - Returns: The stored blob data, or `nil` if not present.
        public func output(from response: CTAP2.GetAssertion.Response) -> Data? {
            response.authenticatorData.extensions?[CTAP2.Extension.CredBlob.identifier]?.dataValue
        }
    }
}

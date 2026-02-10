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

// MARK: - MinPinLength Extension

extension CTAP2.Extension {
    /// The minPinLength extension for returning minimum PIN length in authenticator data.
    ///
    /// This extension allows a relying party to verify that the authenticator enforces
    /// a minimum PIN length policy. The RP must be configured via authenticatorConfig
    /// for the value to be returned.
    ///
    /// - SeeAlso: [CTAP2 minPinLength Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-minpinlength-extension)
    public struct MinPinLength: Sendable {
        /// The extension identifier for minPinLength.
        static let identifier: Identifier = .minPinLength

        // MARK: - Initializer

        /// Creates a MinPinLength extension instance.
        ///
        /// - Parameter session: The CTAP2 session to check for support.
        /// - Throws: `CTAP2.SessionError.extensionNotSupported` if minPinLength is not supported.
        public init(session: CTAP2.Session) async throws(CTAP2.SessionError) {
            guard try await Self.isSupported(by: session) else {
                throw .extensionNotSupported(Self.identifier, source: .here())
            }
        }

        /// Checks if the authenticator supports minPinLength.
        ///
        /// - Parameter session: The CTAP2 session to check.
        /// - Returns: `true` if the authenticator supports minPinLength.
        public static func isSupported(by session: CTAP2.Session) async throws(CTAP2.SessionError) -> Bool {
            let info = try await session.cachedInfo
            return info.options.setMinPINLength
        }

        // MARK: - Operations

        /// Operations for MakeCredential.
        public var makeCredential: MakeCredentialOperations {
            MakeCredentialOperations()
        }
    }
}

// MARK: - MakeCredential Operations

extension CTAP2.Extension.MinPinLength {
    /// MakeCredential operations for minPinLength.
    public struct MakeCredentialOperations: Sendable {

        /// Creates a MakeCredential input to request the minimum PIN length.
        ///
        /// - Returns: An extension input for MakeCredential.
        public func input() -> CTAP2.Extension.MakeCredential.Input {
            CTAP2.Extension.MakeCredential.Input(
                encoded: [CTAP2.Extension.MinPinLength.identifier: .boolean(true)]
            )
        }

        /// Extracts the minimum PIN length from a MakeCredential response.
        ///
        /// - Parameter response: The MakeCredential response from the authenticator.
        /// - Returns: The minimum PIN length, or `nil` if not present.
        public func output(from response: CTAP2.MakeCredential.Response) -> UInt? {
            let identifier = CTAP2.Extension.MinPinLength.identifier
            guard let value = response.authenticatorData.extensions?[identifier]?.uint64Value else {
                return nil
            }
            return UInt(value)
        }
    }
}

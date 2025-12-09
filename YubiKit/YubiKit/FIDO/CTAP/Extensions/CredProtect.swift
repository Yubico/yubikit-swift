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

// MARK: - CredProtect Extension

extension CTAP2.Extension {
    /// The credProtect extension for setting credential protection policy.
    ///
    /// This extension allows a relying party to specify the protection level for a credential,
    /// controlling when user verification is required.
    ///
    /// Usage:
    /// ```swift
    /// // Request credential protection during registration
    /// let credProtect = CTAP2.Extension.CredProtect(level: .userVerificationRequired)
    /// let params = CTAP2.MakeCredential.Parameters(..., extensions: [credProtect])
    /// let response = try await session.makeCredential(params)
    ///
    /// // Check the protection level applied
    /// if let result = credProtect.result(from: response) {
    ///     print("Applied protection level: \(result.level)")
    /// }
    /// ```
    ///
    /// - SeeAlso: [CTAP2.3 credProtect Extension](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-credProtect-extension)
    struct CredProtect: CTAP2.Extension.MakeCredential.Parameters,
        CTAP2.Extension.MakeCredential.Response
    {
        static let identifier: Identifier = .credProtect

        /// Checks if the authenticator supports credProtect.
        ///
        /// - Parameter session: The CTAP2 session to check.
        /// - Returns: `true` if the authenticator supports credProtect.
        static func isSupported<I: CBORInterface>(
            by session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> Bool where I.Error == CTAP2.SessionError {
            let info = try await session.getInfo()
            return info.extensions.contains(identifier)
        }

        /// The credential protection level.
        let level: Level

        /// Creates a credProtect extension with the specified protection level.
        init(level: Level) {
            self.level = level
        }

        func asExtensionInputs() -> [Identifier: CBOR.Value] {
            [Self.identifier: .int(level.rawValue)]
        }

        /// Decodes from CBOR response.
        init?(cbor: CBOR.Value) {
            guard let rawValue = cbor.intValue,
                let level = Level(rawValue: rawValue)
            else {
                return nil
            }
            self.level = level
        }

        /// Extracts the credProtect output from a MakeCredential response.
        ///
        /// - Parameter response: The MakeCredential response from the authenticator.
        /// - Returns: The credProtect extension output, or nil if not present.
        func result(from response: CTAP2.MakeCredential.Response) -> CredProtect? {
            guard let value = response.authenticatorData.extensions?[Self.identifier] else {
                return nil
            }
            return CredProtect(cbor: value)
        }
    }
}

// MARK: - Protection Level

extension CTAP2.Extension.CredProtect {
    /// Credential protection levels.
    ///
    /// Higher levels provide more protection but may require user verification
    /// in more scenarios.
    enum Level: Int, Sendable {
        /// User verification is optional.
        ///
        /// The credential can be used with or without user verification.
        /// This is the default if credProtect is not specified.
        case userVerificationOptional = 1

        /// User verification is optional with credential ID list.
        ///
        /// User verification is required for discoverable credentials,
        /// but optional if the credential ID is provided in allowList.
        case userVerificationOptionalWithCredentialIDList = 2

        /// User verification is always required.
        ///
        /// The credential cannot be used without user verification,
        /// regardless of whether the credential ID is known.
        case userVerificationRequired = 3
    }
}

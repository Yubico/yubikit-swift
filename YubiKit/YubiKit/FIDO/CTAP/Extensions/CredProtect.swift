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
    /// // Without enforcement:
    /// let credProtect = try await CTAP2.Extension.CredProtect(
    ///     level: .userVerificationRequired,
    ///     session: session
    /// )
    /// let ext = credProtect.input()
    ///
    /// // With enforcement (throws if authenticator doesn't support credProtect):
    /// let credProtect = try await CTAP2.Extension.CredProtect(
    ///     level: .userVerificationRequired,
    ///     session: session,
    ///     enforce: true
    /// )
    /// let ext = credProtect.input()
    ///
    /// let params = CTAP2.MakeCredential.Parameters(
    ///     ...,
    ///     extensions: [ext]
    /// )
    /// let response = try await session.makeCredential(params)
    ///
    /// if let level = credProtect.output(from: response) {
    ///     print("Applied protection level: \(level)")
    /// }
    /// ```
    ///
    /// - SeeAlso: [CTAP2 credProtect Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-credProtect-extension)
    public struct CredProtect: Sendable {
        /// The extension identifier for credProtect.
        static let identifier: Identifier = .credProtect

        /// The credential protection level.
        private let level: Level

        // MARK: - Initializer

        /// Creates a CredProtect extension with the specified protection level.
        ///
        /// When `enforce` is `true` and the requested level is higher than
        /// `.userVerificationOptional`, this initializer throws if the authenticator
        /// doesn't support the credProtect extension.
        ///
        /// - Parameters:
        ///   - level: The credential protection level to request.
        ///   - session: The CTAP2 session to check for support.
        ///   - enforce: If `true`, throws when the authenticator doesn't support
        ///              credProtect and level > `.userVerificationOptional`.
        /// - Throws: `CTAP2.SessionError.extensionNotSupported` if enforcement fails.
        public init(
            level: Level,
            session: CTAP2.Session,
            enforce: Bool = false
        ) async throws(CTAP2.SessionError) {
            self.level = level
            let isSupported = try await Self.isSupported(by: session)
            if enforce && !isSupported && level != .userVerificationOptional {
                throw .extensionNotSupported(Self.identifier, source: .here())
            }
        }

        /// Checks if the authenticator supports credProtect.
        ///
        /// - Parameter session: The CTAP2 session to check.
        /// - Returns: `true` if the authenticator supports credProtect.
        public static func isSupported(
            by session: CTAP2.Session
        ) async throws(CTAP2.SessionError) -> Bool {
            let info = try await session.getInfo()
            return info.extensions.contains(identifier)
        }

        // MARK: - Input

        /// Creates a MakeCredential input for the configured protection level.
        ///
        /// - Returns: An extension input for MakeCredential.
        public func input() -> Input {
            Input(encoded: [Self.identifier: level.cbor()])
        }

        // MARK: - Output

        /// Extracts the credProtect output from a MakeCredential response.
        ///
        /// - Parameter response: The MakeCredential response from the authenticator.
        /// - Returns: The credProtect level, or nil if not present.
        public func output(from response: CTAP2.MakeCredential.Response) -> Level? {
            guard let value = response.authenticatorData.extensions?[Self.identifier] else {
                return nil
            }
            return Level(cbor: value)
        }
    }
}

// MARK: - Input Type

extension CTAP2.Extension.CredProtect {
    /// Extension input for MakeCredential.
    public struct Input: CTAP2.Extension.MakeCredential.Input {
        internal static let identifier = CTAP2.Extension.CredProtect.identifier

        private let encoded: [CTAP2.Extension.Identifier: CBOR.Value]

        fileprivate init(encoded: [CTAP2.Extension.Identifier: CBOR.Value]) {
            self.encoded = encoded
        }

        internal func encode() -> [CTAP2.Extension.Identifier: CBOR.Value] {
            encoded
        }
    }
}

// MARK: - Protection Level

extension CTAP2.Extension.CredProtect {
    /// Credential protection levels.
    public enum Level: Int, Sendable, CBOR.Encodable, CBOR.Decodable {
        /// User verification is optional.
        ///
        /// The credential can be used with or without user verification.
        /// This is the default if credProtect is not specified.
        case userVerificationOptional = 0x01

        /// User verification is optional with credential ID list.
        ///
        /// User verification is required for discoverable credentials,
        /// but optional if the credential ID is provided in allowList.
        case userVerificationOptionalWithCredentialIDList = 0x02

        /// User verification is always required.
        ///
        /// The credential cannot be used without user verification,
        /// regardless of whether the credential ID is known.
        case userVerificationRequired = 0x03
    }
}

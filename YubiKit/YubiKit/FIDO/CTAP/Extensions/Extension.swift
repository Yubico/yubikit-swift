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

// MARK: - Extension Identifier

extension CTAP2.Extension {
    /// A CTAP2 extension identifier.
    ///
    /// Extension identifiers are strings that identify specific CTAP2 extensions
    /// reported in the authenticator's GetInfo response.
    public enum Identifier: Hashable, Sendable {
        /// The hmac-secret extension for deriving secrets at GetAssertion.
        case hmacSecret

        /// The hmac-secret-mc extension for deriving secrets at MakeCredential (CTAP 2.2).
        case hmacSecretMC

        /// The credProtect extension for setting credential protection levels.
        case credProtect

        /// Other extension not explicitly defined.
        case other(String)

        /// The raw extension identifier string.
        public var value: String {
            switch self {
            case .hmacSecret: return "hmac-secret"
            case .hmacSecretMC: return "hmac-secret-mc"
            case .credProtect: return "credProtect"
            case .other(let value): return value
            }
        }

        /// Initialize from a raw extension identifier string.
        ///
        /// - Parameter value: Extension identifier string
        public init(_ value: String) {
            switch value {
            case "hmac-secret": self = .hmacSecret
            case "hmac-secret-mc": self = .hmacSecretMC
            case "credProtect": self = .credProtect
            default: self = .other(value)
            }
        }
    }
}

// MARK: - Extension Namespaces

extension CTAP2.Extension {
    /// Namespace for MakeCredential extension input protocol.
    public enum MakeCredential {}

    /// Namespace for GetAssertion extension input protocol.
    public enum GetAssertion {}
}

// MARK: - MakeCredential Extension Input

extension CTAP2.Extension.MakeCredential {
    /// An extension input for authenticatorMakeCredential.
    ///
    /// Extension inputs cannot be created directly. Instead, use the helper methods
    /// provided by each extension type:
    ///
    /// ```swift
    /// // Using credProtect extension
    /// let credProtect = try await CTAP2.Extension.CredProtect(
    ///     level: .userVerificationRequired,
    ///     session: session
    /// )
    /// let params = CTAP2.MakeCredential.Parameters(
    ///     ...,
    ///     extensions: [credProtect.input()]
    /// )
    ///
    /// // Using hmac-secret extension
    /// let hmacSecret = try await CTAP2.Extension.HmacSecret(session: session)
    /// let params = CTAP2.MakeCredential.Parameters(
    ///     ...,
    ///     extensions: [hmacSecret.makeCredential.input()]
    /// )
    /// ```
    ///
    /// - SeeAlso: ``CTAP2/Extension/CredProtect/input()``
    /// - SeeAlso: ``CTAP2/Extension/HmacSecret/MakeCredentialOperations/input()``
    public struct Input: Sendable {
        private let encoded: [CTAP2.Extension.Identifier: CBOR.Value]

        internal init(encoded: [CTAP2.Extension.Identifier: CBOR.Value]) {
            self.encoded = encoded
        }

        internal func encode() -> [CTAP2.Extension.Identifier: CBOR.Value] {
            encoded
        }
    }
}

// MARK: - GetAssertion Extension Input

extension CTAP2.Extension.GetAssertion {
    /// An extension input for authenticatorGetAssertion.
    ///
    /// Extension inputs cannot be created directly. Instead, use the helper methods
    /// provided by each extension type:
    ///
    /// ```swift
    /// // Using hmac-secret extension to derive secrets
    /// let hmacSecret = try await CTAP2.Extension.HmacSecret(session: session)
    /// let salt = Data(repeating: 0x42, count: 32)
    /// let params = CTAP2.GetAssertion.Parameters(
    ///     ...,
    ///     extensions: [try hmacSecret.getAssertion.input(salt1: salt)]
    /// )
    /// ```
    ///
    /// - SeeAlso: ``CTAP2/Extension/HmacSecret/GetAssertionOperations/input(salt1:salt2:)``
    public struct Input: Sendable {
        private let encoded: [CTAP2.Extension.Identifier: CBOR.Value]

        internal init(encoded: [CTAP2.Extension.Identifier: CBOR.Value]) {
            self.encoded = encoded
        }

        internal func encode() -> [CTAP2.Extension.Identifier: CBOR.Value] {
            encoded
        }
    }
}

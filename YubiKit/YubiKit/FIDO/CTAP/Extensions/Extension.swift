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
    enum Identifier: Hashable, Sendable {
        /// The hmac-secret extension for deriving secrets at GetAssertion.
        case hmacSecret

        /// The hmac-secret-mc extension for deriving secrets at MakeCredential (CTAP 2.2).
        case hmacSecretMC

        /// The credProtect extension for setting credential protection levels.
        case credProtect

        /// Other extension not explicitly defined.
        case other(String)

        /// The raw extension identifier string.
        var value: String {
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
        init(_ value: String) {
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
    enum MakeCredential {}

    /// Namespace for GetAssertion extension input protocol.
    enum GetAssertion {}
}

// MARK: - MakeCredential Extension Input

extension CTAP2.Extension.MakeCredential {
    /// Protocol for extension inputs sent with authenticatorMakeCredential.
    ///
    /// Extensions encode to a dictionary of extension identifier to CBOR value.
    /// Most extensions return a single entry, but some (like hmac-secret with
    /// hmac-secret-mc) may return multiple entries.
    protocol Input: Sendable {
        /// The CTAP2 extension identifier (e.g., `.credProtect`, `.hmacSecret`).
        static var identifier: CTAP2.Extension.Identifier { get }

        /// Encodes the extension as CTAP2 extension inputs.
        ///
        /// - Returns: A dictionary of extension identifier to CBOR value.
        func encode() -> [CTAP2.Extension.Identifier: CBOR.Value]
    }
}

// MARK: - GetAssertion Extension Input

extension CTAP2.Extension.GetAssertion {
    /// Protocol for extension inputs sent with authenticatorGetAssertion.
    ///
    /// Extensions encode to a dictionary of extension identifier to CBOR value.
    protocol Input: Sendable {
        /// The CTAP2 extension identifier (e.g., `.credProtect`, `.hmacSecret`).
        static var identifier: CTAP2.Extension.Identifier { get }

        /// Encodes the extension as CTAP2 extension inputs.
        ///
        /// - Returns: A dictionary of extension identifier to CBOR value.
        func encode() -> [CTAP2.Extension.Identifier: CBOR.Value]
    }
}

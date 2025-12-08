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

// MARK: - Extension Namespaces

extension CTAP2.Extension {
    /// Namespace for MakeCredential extension protocols.
    enum MakeCredential {}

    /// Namespace for GetAssertion extension protocols.
    enum GetAssertion {}
}

// MARK: - MakeCredential Extension Types

extension CTAP2.Extension.MakeCredential {
    /// Protocol for extension parameters sent with authenticatorMakeCredential.
    protocol Parameters: CBOR.Encodable, Sendable {
        /// The extension identifier.
        static var name: String { get }
    }

    /// Protocol for extracting typed results from MakeCredential responses.
    ///
    /// Conform to this protocol to provide type-safe extraction of extension outputs
    /// from authenticatorMakeCredential responses.
    ///
    /// Example:
    /// ```swift
    /// let credProtect = CTAP2.Extension.CredProtect(level: .userVerificationRequired)
    /// let params = CTAP2.MakeCredential.Parameters(..., extensions: [credProtect])
    /// let response = try await session.makeCredential(params)
    ///
    /// if let result = credProtect.result(from: response) {
    ///     print("Applied level: \(result.level)")
    /// }
    /// ```
    protocol Response {
        /// The type of result extracted from the response.
        associatedtype Result

        /// Extracts the extension result from a MakeCredential response.
        ///
        /// - Parameter response: The MakeCredential response from the authenticator.
        /// - Returns: The typed result, or nil if the extension output is not present.
        func result(from response: CTAP2.MakeCredential.Response) throws -> Result?
    }
}

extension Array where Element == any CTAP2.Extension.MakeCredential.Parameters {
    /// Encodes the extension parameters array as a CBOR map keyed by extension name.
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        for ext in self {
            map[.textString(type(of: ext).name)] = ext.cbor()
        }
        return .map(map)
    }
}

// MARK: - GetAssertion Extension Types

extension CTAP2.Extension.GetAssertion {
    /// Protocol for extension parameters sent with authenticatorGetAssertion.
    protocol Parameters: CBOR.Encodable, Sendable {
        /// The extension identifier.
        static var name: String { get }
    }

    /// Protocol for extracting typed results from GetAssertion responses.
    ///
    /// Conform to this protocol to provide type-safe extraction of extension outputs
    /// from authenticatorGetAssertion responses.
    ///
    /// Example:
    /// ```swift
    /// let hmacSecret = try await CTAP2.Extension.HmacSecret.encrypt(salt1: salt, session: session)
    /// let params = CTAP2.GetAssertion.Parameters(..., extensions: [hmacSecret])
    /// let response = try await session.getAssertion(params)
    ///
    /// if let (output1, output2) = try hmacSecret.result(from: response) {
    ///     // Use derived secrets
    /// }
    /// ```
    protocol Response {
        /// The type of result extracted from the response.
        associatedtype Result

        /// Extracts the extension result from a GetAssertion response.
        ///
        /// - Parameter response: The GetAssertion response from the authenticator.
        /// - Returns: The typed result, or nil if the extension output is not present.
        func result(from response: CTAP2.GetAssertion.Response) throws -> Result?
    }
}

extension Array where Element == any CTAP2.Extension.GetAssertion.Parameters {
    /// Encodes the extension parameters array as a CBOR map keyed by extension name.
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        for ext in self {
            map[.textString(type(of: ext).name)] = ext.cbor()
        }
        return .map(map)
    }
}

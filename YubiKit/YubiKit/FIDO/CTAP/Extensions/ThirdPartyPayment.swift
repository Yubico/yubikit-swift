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

// MARK: - ThirdPartyPayment Extension

extension CTAP2.Extension {
    /// The thirdPartyPayment extension for Secure Payment Confirmation (CTAP 2.2+).
    ///
    /// This extension allows a Relying Party to indicate that a credential can be used
    /// for payment authentication initiated by a third party.
    ///
    /// - Important: Most of the processing for Secure Payment Confirmation must be done
    ///   by the WebAuthn client. This extension only handles the CTAP2 authenticator
    ///   interaction and should not be used without a client that supports the WebAuthn
    ///   payment extension.
    ///
    /// - SeeAlso: [CTAP2 thirdPartyPayment Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-thirdPartyPayment-extension)
    /// - SeeAlso: [Secure Payment Confirmation](https://www.w3.org/TR/secure-payment-confirmation)
    public struct ThirdPartyPayment: Sendable {
        /// The extension identifier for thirdPartyPayment.
        static let identifier: Identifier = .thirdPartyPayment

        // MARK: - Initializer

        /// Creates a ThirdPartyPayment extension instance.
        ///
        /// - Parameter session: The CTAP2 session to check for support.
        /// - Throws: `CTAP2.SessionError.extensionNotSupported` if thirdPartyPayment is not supported.
        public init(session: CTAP2.Session) async throws(CTAP2.SessionError) {
            guard try await Self.isSupported(by: session) else {
                throw .extensionNotSupported(Self.identifier, source: .here())
            }
        }

        /// Checks if the authenticator supports thirdPartyPayment.
        ///
        /// - Parameter session: The CTAP2 session to check.
        /// - Returns: `true` if the authenticator supports thirdPartyPayment.
        public static func isSupported(
            by session: CTAP2.Session
        ) async throws(CTAP2.SessionError) -> Bool {
            let info = try await session.cachedInfo
            return info.extensions.contains(identifier)
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

extension CTAP2.Extension.ThirdPartyPayment {
    /// MakeCredential operations for thirdPartyPayment.
    public struct MakeCredentialOperations: Sendable {

        /// Creates a MakeCredential input to mark credential as payment-capable.
        ///
        /// - Returns: An extension input for MakeCredential.
        public func input() -> CTAP2.Extension.MakeCredential.Input {
            CTAP2.Extension.MakeCredential.Input(
                encoded: [CTAP2.Extension.ThirdPartyPayment.identifier: .boolean(true)]
            )
        }

        /// Extracts the thirdPartyPayment result from a MakeCredential response.
        ///
        /// - Parameter response: The MakeCredential response from the authenticator.
        /// - Returns: `true` if enabled, `false` if failed, or `nil` if not present.
        public func output(from response: CTAP2.MakeCredential.Response) -> Bool? {
            response.authenticatorData.extensions?[CTAP2.Extension.ThirdPartyPayment.identifier]?
                .boolValue
        }
    }
}

// MARK: - GetAssertion Operations

extension CTAP2.Extension.ThirdPartyPayment {
    /// GetAssertion operations for thirdPartyPayment.
    public struct GetAssertionOperations: Sendable {

        /// Creates a GetAssertion input to request payment confirmation.
        ///
        /// - Returns: An extension input for GetAssertion.
        public func input() -> CTAP2.Extension.GetAssertion.Input {
            CTAP2.Extension.GetAssertion.Input(
                encoded: [CTAP2.Extension.ThirdPartyPayment.identifier: .boolean(true)]
            )
        }

        /// Extracts the thirdPartyPayment result from a GetAssertion response.
        ///
        /// - Parameter response: The GetAssertion response from the authenticator.
        /// - Returns: `true` if enabled, `false` if failed, or `nil` if not present.
        public func output(from response: CTAP2.GetAssertion.Response) -> Bool? {
            response.authenticatorData.extensions?[CTAP2.Extension.ThirdPartyPayment.identifier]?
                .boolValue
        }
    }
}

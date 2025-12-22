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

// MARK: - ClientPin Types

extension CTAP2.ClientPin {
    /// PIN/UV Auth Protocol version.
    ///
    /// Defines the cryptographic algorithms used for PIN/UV authentication.
    /// Protocol v1 is supported by all CTAP2 authenticators, v2 adds improved security.
    ///
    /// - SeeAlso: [CTAP2 PIN/UV Auth Protocol One](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#pinProto1)
    /// - SeeAlso: [CTAP2 PIN/UV Auth Protocol Two](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#pinProto2)
    public enum ProtocolVersion: Int, Sendable, CBOR.Encodable {
        /// Protocol version 1 (CTAP 2.0).
        case v1 = 1

        /// Protocol version 2 (CTAP 2.1+).
        case v2 = 2
    }

    /// Method for PIN/UV user verification.
    public enum Method: Sendable {
        /// Verify using a PIN.
        case pin(String)

        /// Verify using built-in user verification (e.g., fingerprint on YubiKey Bio).
        case uv
    }

    /// A PIN/UV auth token obtained from the authenticator for authenticating CTAP operations.
    ///
    /// Use ``CTAP2/Session/getPinUVToken(using:permissions:rpId:protocol:)`` to obtain a token,
    /// then pass it to operations like ``CTAP2/Session/makeCredential(parameters:pinToken:)``
    /// and ``CTAP2/Session/getAssertion(parameters:pinToken:)``.
    public struct Token: Sendable {
        /// The decrypted PIN token.
        private let token: Data

        /// The PIN/UV auth protocol version used to obtain this token.
        public let protocolVersion: ProtocolVersion

        internal init(token: Data, protocolVersion: ProtocolVersion) {
            self.token = token
            self.protocolVersion = protocolVersion
        }

        /// Compute the pinUVAuthParam for a given message.
        ///
        /// - Parameter message: The data to authenticate (typically clientDataHash).
        /// - Returns: The authentication parameter to include in the CTAP request.
        func authenticate(message: Data) -> Data {
            protocolVersion.authenticate(key: token, message: message)
        }
    }
}

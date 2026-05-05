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

extension CTAP2.GetAssertion {
    /// Parameters for the authenticatorGetAssertion command.
    ///
    /// - SeeAlso: [CTAP 2.2 authenticatorGetAssertion](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorGetAssertion)
    public struct Parameters: Sendable {
        /// Relying Party identifier (e.g., "example.com").
        public let rpId: String

        /// SHA-256 hash of the client data.
        public let clientDataHash: Data

        /// List of credentials acceptable to the RP (omit for resident key discovery).
        public let allowList: [WebAuthn.CredentialDescriptor]?

        /// Extension inputs for additional authenticator processing.
        public let extensions: [CTAP2.Extension.GetAssertion.Input]

        /// Require user presence (default: true when omitted).
        public internal(set) var up: Bool?

        /// Require user verification during the command (ignored if token is provided).
        public internal(set) var uv: Bool?

        /// PIN/UV auth parameter (populated automatically when using a PIN/UV token).
        private(set) var pinUVAuthParam: Data?

        /// PIN/UV protocol version (populated automatically when using a PIN/UV token).
        private(set) var pinUVAuthProtocol: CTAP2.ClientPin.ProtocolVersion?

        /// Sets the PIN/UV authentication parameters.
        ///
        /// Clears `uv` since it must not coexist with `pinUvAuthParam`.
        mutating func setAuthentication(token: CTAP2.Token) {
            self.uv = nil
            self.pinUVAuthParam = token.authenticate(message: clientDataHash)
            self.pinUVAuthProtocol = token.protocolVersion
        }

        public init(
            rpId: String,
            clientDataHash: Data,
            allowList: [WebAuthn.CredentialDescriptor]? = nil,
            extensions: [CTAP2.Extension.GetAssertion.Input] = [],
            up: Bool? = nil,
            uv: Bool? = nil
        ) {
            self.rpId = rpId
            self.clientDataHash = clientDataHash
            self.allowList = allowList
            self.extensions = extensions
            self.up = up
            self.uv = uv
        }
    }
}

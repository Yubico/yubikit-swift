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
    /// - SeeAlso: [CTAP2 authenticatorGetAssertion](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#authenticatorGetAssertion)
    public struct Parameters: Sendable {
        /// Relying Party identifier (e.g., "example.com").
        public let rpId: String

        /// SHA-256 hash of the client data.
        public let clientDataHash: Data

        /// List of credentials acceptable to the RP (omit for resident key discovery).
        public let allowList: [PublicKeyCredential.Descriptor]?

        /// Extension inputs for additional authenticator processing.
        public let extensions: [CTAP2.Extension.GetAssertion.Input]

        /// Authenticator options.
        public let options: Options?

        /// PIN/UV auth parameter (populated automatically when using PIN authentication).
        private(set) var pinUVAuthParam: Data?

        /// PIN/UV protocol version (populated automatically when using PIN authentication).
        private(set) var pinUVAuthProtocol: CTAP2.ClientPin.ProtocolVersion?

        /// Sets the PIN/UV authentication parameters using a PIN token.
        mutating func setAuthentication(pinToken: CTAP2.ClientPin.Token) {
            self.pinUVAuthParam = pinToken.authenticate(message: clientDataHash)
            self.pinUVAuthProtocol = pinToken.protocolVersion
        }

        public init(
            rpId: String,
            clientDataHash: Data,
            allowList: [PublicKeyCredential.Descriptor]? = nil,
            extensions: [CTAP2.Extension.GetAssertion.Input] = [],
            options: Options? = nil
        ) {
            self.rpId = rpId
            self.clientDataHash = clientDataHash
            self.allowList = allowList
            self.extensions = extensions
            self.options = options
        }

        /// Authenticator options for getAssertion.
        public struct Options: Sendable {
            /// Require user presence (default: true).
            public let up: Bool?

            /// Require user verification.
            public let uv: Bool?

            public init(up: Bool? = nil, uv: Bool? = nil) {
                self.up = up
                self.uv = uv
            }
        }
    }
}

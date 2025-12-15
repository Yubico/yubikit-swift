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

extension CTAP2.MakeCredential {
    /// Parameters for the authenticatorMakeCredential command.
    ///
    /// - SeeAlso: [CTAP2 authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#authenticatorMakeCredential)
    public struct Parameters: Sendable {
        /// SHA-256 hash of the client data.
        public let clientDataHash: Data

        /// Relying Party information.
        public let rp: PublicKeyCredential.RPEntity

        /// User account information.
        public let user: PublicKeyCredential.UserEntity

        /// Supported public key algorithms in order of preference.
        public let pubKeyCredParams: [COSE.Algorithm]

        /// Credentials to exclude (already registered).
        public let excludeList: [PublicKeyCredential.Descriptor]?

        /// Extension inputs for additional authenticator processing.
        public let extensions: [CTAP2.Extension.MakeCredential.Input]

        /// Authenticator options.
        public let options: Options?

        /// Enterprise attestation level (1 or 2).
        public let enterpriseAttestation: Int?

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
            clientDataHash: Data,
            rp: PublicKeyCredential.RPEntity,
            user: PublicKeyCredential.UserEntity,
            pubKeyCredParams: [COSE.Algorithm],
            excludeList: [PublicKeyCredential.Descriptor]? = nil,
            extensions: [CTAP2.Extension.MakeCredential.Input] = [],
            options: Options? = nil,
            enterpriseAttestation: Int? = nil
        ) {
            self.clientDataHash = clientDataHash
            self.rp = rp
            self.user = user
            self.pubKeyCredParams = pubKeyCredParams
            self.excludeList = excludeList
            self.extensions = extensions
            self.options = options
            self.enterpriseAttestation = enterpriseAttestation
        }

        /// Authenticator options for makeCredential.
        public struct Options: Sendable {
            /// Require resident key (discoverable credential).
            public let rk: Bool?

            /// Require user verification.
            public let uv: Bool?

            public init(rk: Bool? = nil, uv: Bool? = nil) {
                self.rk = rk
                self.uv = uv
            }
        }
    }
}

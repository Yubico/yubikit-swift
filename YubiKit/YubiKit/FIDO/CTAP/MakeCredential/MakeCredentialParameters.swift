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
    /// - SeeAlso: [CTAP 2.2 authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorMakeCredential)
    public struct Parameters: Sendable {
        /// SHA-256 hash of the client data.
        public let clientDataHash: Data

        /// Relying Party information.
        public let rp: WebAuthn.RelyingParty

        /// User account information.
        public let user: WebAuthn.User

        /// Supported public key algorithms in order of preference.
        public let pubKeyCredParams: [COSE.Algorithm]

        /// Credentials to exclude (already registered).
        public let excludeList: [WebAuthn.CredentialDescriptor]?

        /// Extension inputs for additional authenticator processing.
        public let extensions: [CTAP2.Extension.MakeCredential.Input]

        /// Require resident key (discoverable credential).
        public internal(set) var rk: Bool

        /// Require user verification during the command (ignored if token is provided).
        public internal(set) var uv: Bool?

        /// Enterprise attestation level (1 or 2).
        public let enterpriseAttestation: Int?

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
            clientDataHash: Data,
            rp: WebAuthn.RelyingParty,
            user: WebAuthn.User,
            pubKeyCredParams: [COSE.Algorithm],
            excludeList: [WebAuthn.CredentialDescriptor]? = nil,
            extensions: [CTAP2.Extension.MakeCredential.Input] = [],
            rk: Bool,
            uv: Bool? = nil,
            enterpriseAttestation: Int? = nil
        ) {
            self.clientDataHash = clientDataHash
            self.rp = rp
            self.user = user
            self.pubKeyCredParams = pubKeyCredParams
            self.excludeList = excludeList
            self.extensions = extensions
            self.rk = rk
            self.uv = uv
            self.enterpriseAttestation = enterpriseAttestation
        }
    }
}

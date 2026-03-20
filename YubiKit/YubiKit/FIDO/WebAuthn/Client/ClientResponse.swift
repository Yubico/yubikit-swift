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

extension WebAuthn.Registration {

    /// Authenticator response from a successful credential creation.
    public struct Response: Sendable {

        public let credentialId: Data
        public let rawAttestationObject: Data
        public let authenticatorData: WebAuthn.AuthenticatorData
        public let attestationStatement: WebAuthn.AttestationStatement
        public let transports: [WebAuthn.Transport]

        public var publicKey: COSE.Key? { authenticatorData.attestedCredentialData?.credentialPublicKey }
        public var aaguid: WebAuthn.AAGUID? { authenticatorData.attestedCredentialData?.aaguid }

        /// The clientDataJSON bytes, stored internally for `toJSON()` serialization.
        internal let clientDataJSON: Data
    }
}

extension WebAuthn.Authentication {

    /// Authenticator response from a successful credential authentication.
    public struct Response: Sendable {

        public let credentialId: Data
        public let rawAuthenticatorData: Data
        public let signature: Data
        public let userHandle: Data?
        public let authenticatorData: WebAuthn.AuthenticatorData

        public var signCount: UInt32 { authenticatorData.signCount }

        /// The clientDataJSON bytes, stored internally for `toJSON()` serialization.
        internal let clientDataJSON: Data
    }

    /// A complete assertion with credential info and signed response.
    ///
    /// Returned when multiple discoverable credentials match the request.
    /// Display `userName`/`userDisplayName` for selection UI, then use `response` for the server.
    public struct Assertion: Sendable {

        public let credentialId: Data
        public let userHandle: Data?
        public let userName: String?
        public let userDisplayName: String?
        public let response: Response
    }
}

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

// MARK: - Registration Response

extension WebAuthn.Registration {

    /// Authenticator response from a successful credential creation.
    public struct Response: Sendable {

        public let credentialId: Data
        public let rawAttestationObject: Data
        public let rawAuthenticatorData: Data
        public let attestationStatement: WebAuthn.AttestationStatement
        public let transports: [WebAuthn.Transport]
        public let clientExtensionResults: WebAuthn.Extension.RegistrationOutputs

        /// The credential public key.
        public let publicKey: COSE.Key

        /// Authenticator Attestation Global Unique ID.
        public let aaguid: WebAuthn.AAGUID

        /// Signature counter value.
        public let signCount: UInt32

        /// Parsed authenticator data for internal extension processing.
        internal let authenticatorData: WebAuthn.AuthenticatorData

        /// The clientDataJSON bytes, stored internally for `toJSON()` serialization.
        ///
        /// This is `nil` for credential provider flows where only the hash was provided.
        internal let clientDataJSON: Data?
    }
}

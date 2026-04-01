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

// MARK: - Registration Options

extension WebAuthn {

    /// Namespace for credential registration types.
    public enum Registration {}
}

extension WebAuthn.Registration {

    /// Options for registering a new passkey credential.
    ///
    /// Equivalent to `PublicKeyCredentialCreationOptions` in the WebAuthn spec.
    public struct Options: Sendable {
        public let challenge: Data
        public let rp: WebAuthn.RelyingParty
        public let user: WebAuthn.User
        public let excludeCredentials: [WebAuthn.CredentialDescriptor]
        public let residentKey: WebAuthn.ResidentKeyPreference
        public let userVerification: WebAuthn.UserVerificationPreference
        public let attestation: WebAuthn.AttestationPreference
        public let pubKeyCredParams: [COSE.Algorithm]
        public let timeout: Duration?
        public let extensions: WebAuthn.Extension.RegistrationInputs?

        public init(
            challenge: Data,
            rp: WebAuthn.RelyingParty,
            user: WebAuthn.User,
            excludeCredentials: [WebAuthn.CredentialDescriptor] = [],
            residentKey: WebAuthn.ResidentKeyPreference = .preferred,
            userVerification: WebAuthn.UserVerificationPreference = .preferred,
            attestation: WebAuthn.AttestationPreference = .none,
            pubKeyCredParams: [COSE.Algorithm] = [.es256, .edDSA, .rs256],
            timeout: Duration? = nil,
            extensions: WebAuthn.Extension.RegistrationInputs? = nil
        ) {
            self.challenge = challenge
            self.rp = rp
            self.user = user
            self.excludeCredentials = excludeCredentials
            self.residentKey = residentKey
            self.userVerification = userVerification
            self.attestation = attestation
            self.pubKeyCredParams = pubKeyCredParams
            self.timeout = timeout
            self.extensions = extensions
        }
    }
}

/// WebAuthn Level 3 type alias for credential creation options.
///
/// - SeeAlso: [WebAuthn PublicKeyCredentialCreationOptions](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions)
public typealias PublicKeyCredentialCreationOptions = WebAuthn.Registration.Options

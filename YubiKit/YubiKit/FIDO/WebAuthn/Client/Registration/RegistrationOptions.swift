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
        /// Cryptographic challenge from the relying party. Signed into the
        /// returned attestation to prove freshness.
        public let challenge: Data

        /// Relying party the credential is being created for.
        public let rp: WebAuthn.RelyingParty

        /// User account the credential is being created for.
        public let user: WebAuthn.User

        /// Credentials the relying party already has for this user. The
        /// authenticator refuses to create a duplicate, throwing
        /// ``WebAuthn/ClientError/credentialExcluded(source:)``.
        public let excludeCredentials: [WebAuthn.CredentialDescriptor]

        /// Whether to create a discoverable (resident) credential.
        public let residentKey: WebAuthn.ResidentKeyPreference

        /// Relying-party preference for built-in user verification (PIN /
        /// biometric). The per-ceremony ``WebAuthn/Authorization`` `uv`
        /// policy decides what the SDK actually attempts.
        public let userVerification: WebAuthn.UserVerificationPreference

        /// Whether (and how) the authenticator should attest its identity.
        /// ``WebAuthn/AttestationPreference/none`` disables attestation for
        /// user privacy; the others request progressively stronger forms.
        public let attestation: WebAuthn.AttestationPreference

        /// Acceptable signing algorithms, in the relying party's order of preference.
        public let pubKeyCredParams: [COSE.Algorithm]

        /// SDK-side ceremony timeout. `nil` means no SDK timeout — only the
        /// authenticator's own user-presence timeout applies.
        public let timeout: Duration?

        /// Extension inputs. The client filters these against its
        /// `allowedExtensions` set before sending to the authenticator.
        public let extensions: WebAuthn.Extension.RegistrationInputs?

        public init(
            challenge: Data,
            rp: WebAuthn.RelyingParty,
            user: WebAuthn.User,
            excludeCredentials: [WebAuthn.CredentialDescriptor] = [],
            residentKey: WebAuthn.ResidentKeyPreference = .discouraged,
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

extension WebAuthn {
    /// Type alias matching the W3C
    /// [PublicKeyCredentialCreationOptions](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions)
    /// dictionary name, for code that mirrors the JavaScript API.
    public typealias PublicKeyCredentialCreationOptions = Registration.Options
}

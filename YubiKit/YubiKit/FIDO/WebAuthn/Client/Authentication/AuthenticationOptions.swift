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

// MARK: - Authentication Options

extension WebAuthn {

    /// Namespace for credential authentication types.
    public enum Authentication {}
}

extension WebAuthn.Authentication {

    /// Options for authenticating with an existing passkey credential.
    ///
    /// Equivalent to `PublicKeyCredentialRequestOptions` in the WebAuthn spec.
    public struct Options: Sendable {
        /// Cryptographic challenge from the relying party. Signed into the
        /// returned assertion to prove freshness.
        public let challenge: Data

        /// Relying party identifier. When `nil`, the client falls back to
        /// the host of its ``WebAuthn/Origin``.
        public let rpId: String?

        /// Credentials the authenticator may use. An empty array requests a
        /// discoverable-credential lookup; a non-empty array narrows to
        /// specific credentials.
        public let allowCredentials: [WebAuthn.CredentialDescriptor]

        /// Relying-party preference for built-in user verification (PIN /
        /// biometric). The per-ceremony ``WebAuthn/Authorization`` `uv`
        /// policy decides what the SDK actually attempts.
        public let userVerification: WebAuthn.UserVerificationPreference

        /// SDK-side ceremony timeout. `nil` means no SDK timeout — only the
        /// authenticator's own user-presence timeout applies.
        public let timeout: Duration?

        /// Extension inputs. The client filters these against its
        /// `allowedExtensions` set before sending to the authenticator.
        public let extensions: WebAuthn.Extension.AuthenticationInputs?

        public init(
            challenge: Data,
            rpId: String? = nil,
            allowCredentials: [WebAuthn.CredentialDescriptor] = [],
            userVerification: WebAuthn.UserVerificationPreference = .preferred,
            timeout: Duration? = nil,
            extensions: WebAuthn.Extension.AuthenticationInputs? = nil
        ) {
            self.challenge = challenge
            self.rpId = rpId
            self.allowCredentials = allowCredentials
            self.userVerification = userVerification
            self.timeout = timeout
            self.extensions = extensions
        }
    }
}

extension WebAuthn {
    /// Type alias matching the W3C
    /// [PublicKeyCredentialRequestOptions](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions)
    /// dictionary name, for code that mirrors the JavaScript API.
    public typealias PublicKeyCredentialRequestOptions = Authentication.Options
}

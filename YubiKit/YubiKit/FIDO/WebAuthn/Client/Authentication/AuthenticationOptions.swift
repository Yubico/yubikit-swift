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
        public let challenge: Data
        public let rpId: String?
        public let allowCredentials: [WebAuthn.CredentialDescriptor]
        public let userVerification: WebAuthn.UserVerificationPreference
        public let timeout: Duration?

        public init(
            challenge: Data,
            rpId: String? = nil,
            allowCredentials: [WebAuthn.CredentialDescriptor] = [],
            userVerification: WebAuthn.UserVerificationPreference = .preferred,
            timeout: Duration? = nil
        ) {
            self.challenge = challenge
            self.rpId = rpId
            self.allowCredentials = allowCredentials
            self.userVerification = userVerification
            self.timeout = timeout
        }
    }
}

/// WebAuthn Level 3 type alias for credential request options.
///
/// - SeeAlso: [WebAuthn PublicKeyCredentialRequestOptions](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions)
public typealias PublicKeyCredentialRequestOptions = WebAuthn.Authentication.Options

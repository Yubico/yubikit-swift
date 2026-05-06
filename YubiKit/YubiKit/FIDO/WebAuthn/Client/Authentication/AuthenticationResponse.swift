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

// MARK: - Authentication Response

extension WebAuthn.Authentication {

    /// Authenticator response from a successful credential authentication.
    ///
    /// For discoverable credentials, use `user?.name` and `user?.displayName` for selection UI.
    public struct Response: Sendable {

        /// Identifier of the credential that produced this assertion.
        public let credentialId: Data

        /// Raw authenticator data bytes signed alongside the client data hash.
        public let rawAuthenticatorData: Data

        /// Signature over `rawAuthenticatorData || clientDataHash` produced by
        /// the credential's private key. Verify against ``credentialId``'s
        /// public key on the server.
        public let signature: Data

        /// User identity for discoverable credentials. `nil` when the
        /// ceremony used an allow-list (the relying party already knows the
        /// user).
        public let user: WebAuthn.User?

        /// Outputs from extensions the client processed for this ceremony.
        public let clientExtensionResults: WebAuthn.Extension.AuthenticationOutputs

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

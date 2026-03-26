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

        public let credentialId: Data
        public let rawAuthenticatorData: Data
        public let signature: Data
        public let user: WebAuthn.User?
        public let authenticatorData: WebAuthn.AuthenticatorData

        public var signCount: UInt32 { authenticatorData.signCount }

        /// The clientDataJSON bytes, stored internally for `toJSON()` serialization.
        ///
        /// This is `nil` for credential provider flows where only the hash was provided.
        internal let clientDataJSON: Data?
    }
}

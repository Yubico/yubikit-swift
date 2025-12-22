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

extension WebAuthn.PublicKeyCredential {
    /// User account entity information.
    ///
    /// Identifies the user account for which a credential is being registered
    /// or that owns an existing credential.
    ///
    /// - SeeAlso: [WebAuthn PublicKeyCredentialUserEntity](https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialuserentity)
    public struct UserEntity: Sendable {
        /// User handle (opaque byte sequence).
        public let id: Data

        /// User identifier (e.g., "alice@example.com").
        public let name: String?

        /// Display name (e.g., "Alice Smith").
        public let displayName: String?

        public init(id: Data, name: String? = nil, displayName: String? = nil) {
            self.id = id
            self.name = name
            self.displayName = displayName
        }
    }
}

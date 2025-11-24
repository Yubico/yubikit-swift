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

extension PublicKeyCredential {
    /// Public key credential descriptor (credential ID and type).
    struct Descriptor: Sendable {
        /// Credential type (always "public-key" for FIDO2).
        let type: String

        /// Credential ID (opaque byte sequence).
        let id: Data

        /// Optional transports hint.
        let transports: [String]?

        init(type: String = "public-key", id: Data, transports: [String]? = nil) {
            self.type = type
            self.id = id
            self.transports = transports
        }
    }
}

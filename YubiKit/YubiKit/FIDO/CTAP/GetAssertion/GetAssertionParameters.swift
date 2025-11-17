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

/// Parameters for the authenticatorGetAssertion command.
///
/// - SeeAlso: [CTAP2 authenticatorGetAssertion](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#authenticatorGetAssertion)
struct GetAssertionParameters: Sendable {
    /// Relying Party identifier (e.g., "example.com").
    let rpId: String

    /// SHA-256 hash of the client data.
    let clientDataHash: Data

    /// List of credentials acceptable to the RP (omit for resident key discovery).
    let allowList: [PublicKeyCredentialDescriptor]?

    /// Extension inputs for additional authenticator processing.
    let extensions: GetAssertionExtensions?

    /// Authenticator options.
    let options: Options?

    /// PIN/UV auth parameter.
    let pinUvAuthParam: Data?

    /// PIN/UV protocol version (1 or 2).
    let pinUvAuthProtocol: Int?

    init(
        rpId: String,
        clientDataHash: Data,
        allowList: [PublicKeyCredentialDescriptor]? = nil,
        extensions: GetAssertionExtensions? = nil,
        options: Options? = nil,
        pinUvAuthParam: Data? = nil,
        pinUvAuthProtocol: Int? = nil
    ) {
        self.rpId = rpId
        self.clientDataHash = clientDataHash
        self.allowList = allowList
        self.extensions = extensions
        self.options = options
        self.pinUvAuthParam = pinUvAuthParam
        self.pinUvAuthProtocol = pinUvAuthProtocol
    }

    /// Authenticator options for getAssertion.
    struct Options: Sendable {
        /// Require user presence (default: true).
        let up: Bool?

        /// Require user verification.
        let uv: Bool?

        init(up: Bool? = nil, uv: Bool? = nil) {
            self.up = up
            self.uv = uv
        }
    }
}

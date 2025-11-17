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

/// Parameters for the authenticatorMakeCredential command.
///
/// - SeeAlso: [CTAP2 authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#authenticatorMakeCredential)
struct MakeCredentialParameters: Sendable {
    /// SHA-256 hash of the client data.
    let clientDataHash: Data

    /// Relying Party information.
    let rp: PublicKeyCredentialRPEntity

    /// User account information.
    let user: PublicKeyCredentialUserEntity

    /// Supported public key algorithms in order of preference.
    let pubKeyCredParams: [COSE.Algorithm]

    /// Credentials to exclude (already registered).
    let excludeList: [PublicKeyCredentialDescriptor]?

    /// Extension inputs for additional authenticator processing.
    let extensions: MakeCredentialExtensions?

    /// Authenticator options.
    let options: Options?

    /// PIN/UV auth parameter.
    let pinUvAuthParam: Data?

    /// PIN/UV protocol version (1 or 2).
    let pinUvAuthProtocol: Int?

    /// Enterprise attestation level (1 or 2).
    let enterpriseAttestation: Int?

    init(
        clientDataHash: Data,
        rp: PublicKeyCredentialRPEntity,
        user: PublicKeyCredentialUserEntity,
        pubKeyCredParams: [COSE.Algorithm],
        excludeList: [PublicKeyCredentialDescriptor]? = nil,
        extensions: MakeCredentialExtensions? = nil,
        options: Options? = nil,
        pinUvAuthParam: Data? = nil,
        pinUvAuthProtocol: Int? = nil,
        enterpriseAttestation: Int? = nil
    ) {
        self.clientDataHash = clientDataHash
        self.rp = rp
        self.user = user
        self.pubKeyCredParams = pubKeyCredParams
        self.excludeList = excludeList
        self.extensions = extensions
        self.options = options
        self.pinUvAuthParam = pinUvAuthParam
        self.pinUvAuthProtocol = pinUvAuthProtocol
        self.enterpriseAttestation = enterpriseAttestation
    }

    /// Authenticator options for makeCredential.
    struct Options: Sendable {
        /// Require resident key (discoverable credential).
        let rk: Bool?

        /// Require user verification.
        let uv: Bool?

        init(rk: Bool? = nil, uv: Bool? = nil) {
            self.rk = rk
            self.uv = uv
        }
    }
}

// MARK: - Supporting Types

/// Relying Party entity information.
struct PublicKeyCredentialRPEntity: Sendable {
    /// Relying Party identifier (e.g., "example.com").
    let id: String

    /// Human-readable relying party name.
    let name: String?

    init(id: String, name: String? = nil) {
        self.id = id
        self.name = name
    }
}

/// User account entity information.
struct PublicKeyCredentialUserEntity: Sendable {
    /// User handle (opaque byte sequence).
    let id: Data

    /// User identifier (e.g., "alice@example.com").
    let name: String?

    /// Display name (e.g., "Alice Smith").
    let displayName: String?

    init(id: Data, name: String? = nil, displayName: String? = nil) {
        self.id = id
        self.name = name
        self.displayName = displayName
    }
}

/// Public key credential descriptor (credential ID and type).
struct PublicKeyCredentialDescriptor: Sendable {
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

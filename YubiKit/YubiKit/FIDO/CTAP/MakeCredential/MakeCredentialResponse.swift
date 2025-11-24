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

extension CTAP.MakeCredential {
    /// Data returned from the authenticator after making a new credential.
    ///
    /// Contains the attestation object with the new credential's public key,
    /// credential ID, and attestation information.
    ///
    /// - SeeAlso: [CTAP2 authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#authenticatorMakeCredential)
    /// - SeeAlso: [WebAuthn AuthenticatorData](https://www.w3.org/TR/webauthn/#authenticator-data)
    struct Response: Sendable {

        /// Attestation statement format identifier (e.g., "packed", "fido-u2f", "none").
        public let format: String

        /// Parsed authenticator data containing RP ID hash, flags, counter, and credential info.
        public let authenticatorData: WebAuthn.AuthenticatorData

        /// Attestation statement with strongly-typed access based on format.
        /// Unknown formats are represented as `.unknown(format:)`.
        public let attestationStatement: WebAuthn.AttestationStatement

        /// Whether enterprise attestation was returned.
        public let enterpriseAttestation: Bool?

        /// Large blob key if the largeBlobKey extension was requested.
        public let largeBlobKey: Data?

        /// Unsigned extension outputs not included in signed authenticator data.
        public let unsignedExtensionOutputs: WebAuthn.ExtensionOutputs?
    }
}

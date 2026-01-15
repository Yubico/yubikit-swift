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

extension CTAP2.MakeCredential {
    /// Data returned from the authenticator after making a new credential.
    ///
    /// Contains the attestation object with the new credential's public key,
    /// credential ID, and attestation information.
    ///
    /// - SeeAlso: [CTAP 2.2 authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorMakeCredential)
    /// - SeeAlso: [WebAuthn AuthenticatorData](https://www.w3.org/TR/webauthn/#authenticator-data)
    public struct Response: Sendable {

        /// Parsed authenticator data containing RP ID hash, flags, counter, and credential info.
        public var authenticatorData: WebAuthn.AuthenticatorData {
            attestationObject.authenticatorData
        }

        /// Attestation object containing format, statement, and CBOR-encoded data.
        ///
        /// - `attestationObject.rawData`: CBOR bytes for WebAuthn API
        /// - `attestationObject.format`: Format identifier (e.g., "packed")
        /// - `attestationObject.statement`: Parsed attestation statement
        /// - `attestationObject.authenticatorData`:  Parsed authenticator data
        public let attestationObject: WebAuthn.AttestationObject

        /// Whether enterprise attestation was returned.
        public let enterpriseAttestation: Bool?

        /// Large blob key if the largeBlobKey extension was requested.
        public let largeBlobKey: Data?

        /// Unsigned extension outputs not included in signed authenticator data.
        ///
        /// Use extension-specific `result(from:)` methods for typed access to extension outputs.
        internal let unsignedExtensionOutputs: [String: CBOR.Value]?

        // MARK: - Deprecated

        /// Attestation statement format identifier.
        @available(*, deprecated, renamed: "attestationObject.format")
        public var format: String { attestationObject.format }

        /// Parsed attestation statement.
        @available(*, deprecated, renamed: "attestationObject.statement")
        public var attestationStatement: WebAuthn.AttestationStatement { attestationObject.statement }
    }
}

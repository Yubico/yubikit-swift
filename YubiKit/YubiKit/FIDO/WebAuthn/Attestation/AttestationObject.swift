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

extension WebAuthn {

    /// Attestation object from a credential creation operation.
    ///
    /// Contains both the CBOR-encoded data for the WebAuthn API and
    /// parsed access to the attestation statement.
    ///
    /// - SeeAlso: [WebAuthn Attestation Object](https://www.w3.org/TR/webauthn/#sctn-attestation)
    public struct AttestationObject: Sendable {

        /// CBOR-encoded attestation object for the WebAuthn API.
        /// Pass this to `navigator.credentials.create()` response.
        public let rawData: Data

        /// Attestation statement format identifier - 'fmt' (e.g., "packed", "fido-u2f", "none").
        public let format: String

        /// Parsed attestation statement with typed access based on format - 'attStmt'
        public var statement: AttestationStatement

        /// The authenticator data structure - 'authData'
        /// Contains information about the relying party, flags, signature counter, and optionally
        /// attested credential data.
        public let authenticatorData: AuthenticatorData

        /// Creates an attestation object from its components.
        internal init(format: String, statementCBOR: CBOR.Value, authenticatorData: AuthenticatorData) {
            self.format = format
            self.statement = .init(format: format, statementCBOR: statementCBOR)
            self.authenticatorData = authenticatorData

            // Build WebAuthn attestationObject CBOR
            let map: [CBOR.Value: CBOR.Value] = [
                "fmt": format.cbor(),
                "attStmt": statementCBOR,
                "authData": authenticatorData.rawData.cbor(),
            ]

            self.rawData = map.cbor().encode()
        }
    }
}

// MARK: - Private helper
extension WebAuthn.AttestationStatement {
    fileprivate init(format: String, statementCBOR: CBOR.Value) {
        switch format {
        case "packed":
            if let packed = Packed(cbor: statementCBOR) {
                self = .packed(packed)
            } else {
                self = .unknown(format: format)
            }
        case "fido-u2f":
            if let fidoU2F = FIDOU2F(cbor: statementCBOR) {
                self = .fidoU2F(fidoU2F)
            } else {
                self = .unknown(format: format)
            }
        case "apple":
            if let apple = Apple(cbor: statementCBOR) {
                self = .apple(apple)
            } else {
                self = .unknown(format: format)
            }
        case "none":
            self = .none

        default:
            self = .unknown(format: format)
        }
    }
}

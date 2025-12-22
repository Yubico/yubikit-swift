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

extension WebAuthn.AttestationStatement {
    /// Packed attestation statement.
    ///
    /// - SeeAlso: [Packed Attestation Statement Format](https://www.w3.org/TR/webauthn/#sctn-packed-attestation)
    public struct Packed: Sendable {
        /// Attestation signature.
        public let sig: Data

        /// Signature algorithm (COSE algorithm identifier).
        public let alg: Int

        /// Attestation certificate chain (optional for self-attestation).
        public let x5c: [Data]?

        /// ECDAA-Issuer public key (optional, rarely used).
        public let ecdaaKeyId: Data?
    }
}

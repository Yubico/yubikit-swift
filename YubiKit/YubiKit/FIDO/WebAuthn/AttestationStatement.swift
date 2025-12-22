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
    /// Attestation statement from the authenticator.
    ///
    /// The structure varies by attestation format. This type provides strongly-typed
    /// access to common formats, with a fallback for unknown formats.
    ///
    /// - SeeAlso: [WebAuthn Attestation Statement Formats](https://www.w3.org/TR/webauthn/#sctn-attestation-formats)
    public enum AttestationStatement: Sendable {
        /// Packed attestation format (FIDO2).
        case packed(Packed)

        /// FIDO U2F attestation format.
        case fidoU2F(FIDOU2F)

        /// No attestation (self-attestation).
        case none

        /// Apple anonymous attestation.
        case apple(Apple)

        /// Unknown or unsupported attestation format.
        /// The format identifier is preserved for future compatibility.
        case unknown(format: String)

        /// The attestation format identifier.
        public var format: AttestationFormat {
            switch self {
            case .packed: return .packed
            case .fidoU2F: return .fidoU2F
            case .none: return .none
            case .apple: return .apple
            case .unknown(let format): return .unknown(format)
            }
        }
    }
}

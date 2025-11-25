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
    /// Extension outputs from the authenticator.
    ///
    /// WebAuthn/CTAP2 extensions allow RPs to request additional functionality.
    /// This type provides strongly-typed access to common extensions.
    ///
    /// - SeeAlso: [WebAuthn Extensions](https://www.w3.org/TR/webauthn/#sctn-extensions)
    /// - SeeAlso: [CTAP2 Extensions](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-defined-extensions)
    struct ExtensionOutputs: Sendable {
        /// Credential properties extension output.
        let credProps: CredentialPropertiesOutput?

        /// Large blob key for this credential.
        let largeBlobKey: Data?

        /// Whether the hmac-secret extension is supported.
        let hmacSecret: Bool?

        /// Credential protection level applied to this credential.
        let credProtect: CredentialProtectionPolicy?

        /// Minimum PIN length enforced by the authenticator.
        let minPINLength: Int?

        /// Third-party payment extension output.
        let thirdPartyPayment: Bool?

        /// Credential properties extension output.
        struct CredentialPropertiesOutput: Sendable {
            /// Whether the credential is client-side discoverable (resident key).
            let rk: Bool?
        }

        /// Credential protection policy levels.
        enum CredentialProtectionPolicy: Sendable, Equatable {
            /// User verification optional.
            case userVerificationOptional

            /// User verification optional with credential ID list.
            case userVerificationOptionalWithCredentialIDList

            /// User verification required.
            case userVerificationRequired

            /// Unknown or future credential protection level.
            case unknown(Int)

            /// The raw integer value.
            var rawValue: Int {
                switch self {
                case .userVerificationOptional: return 1
                case .userVerificationOptionalWithCredentialIDList: return 2
                case .userVerificationRequired: return 3
                case .unknown(let value): return value
                }
            }

            /// Initialize from raw integer value.
            init(rawValue: Int) {
                switch rawValue {
                case 1: self = .userVerificationOptional
                case 2: self = .userVerificationOptionalWithCredentialIDList
                case 3: self = .userVerificationRequired
                default: self = .unknown(rawValue)
                }
            }
        }
    }
}

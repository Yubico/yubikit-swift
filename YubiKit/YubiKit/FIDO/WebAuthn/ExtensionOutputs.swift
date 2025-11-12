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

// MARK: - Extension Outputs

/// Extension outputs from the authenticator.
///
/// WebAuthn/CTAP2 extensions allow RPs to request additional functionality.
/// This type provides strongly-typed access to common extensions.
///
/// - SeeAlso: [WebAuthn Extensions](https://www.w3.org/TR/webauthn/#sctn-extensions)
/// - SeeAlso: [CTAP2 Extensions](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-extensions)
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
    enum CredentialProtectionPolicy: Int, Sendable {
        /// User verification optional.
        case userVerificationOptional = 1

        /// User verification optional with credential ID list.
        case userVerificationOptionalWithCredentialIDList = 2

        /// User verification required.
        case userVerificationRequired = 3
    }
}

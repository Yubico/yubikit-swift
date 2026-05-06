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

// MARK: - CredProtect Extension

extension WebAuthn.Extension {

    /// The [credentialProtectionPolicy extension](https://www.w3.org/TR/webauthn-3/#sctn-credential-protection-extension)
    /// for controlling credential protection.
    ///
    /// This WebAuthn extension wraps the CTAP2 credProtect extension, allowing
    /// relying parties to specify when user verification is required.
    ///
    /// ## Registration
    ///
    /// Request credential protection when creating a credential:
    ///
    /// ```swift
    /// let options = WebAuthn.Registration.Options(
    ///     ...,
    ///     extensions: .init(
    ///         credProtect: .enforced(.userVerificationRequired)
    ///     )
    /// )
    /// let response = try await client.makeCredential(options, authorization: .pin(pin)).value
    /// if let policy = response.clientExtensionResults.credProtect {
    ///     // Verify the applied protection level
    /// }
    /// ```
    public enum CredProtect {}
}

// MARK: - Policy (alias to CTAP2)

extension WebAuthn.Extension.CredProtect {

    /// Credential protection policy levels.
    ///
    /// Alias for `CTAP2.Extension.CredProtect.Level`.
    public typealias Policy = CTAP2.Extension.CredProtect.Level
}

// MARK: - Registration Input/Output

extension WebAuthn.Extension.CredProtect {

    /// Namespace for credProtect registration types.
    public enum Registration {
        /// Input for credProtect extension at registration.
        public struct Input: Sendable, Equatable {
            /// The credential protection policy to request.
            public let policy: Policy

            /// Whether to fail registration if the authenticator doesn't support
            /// the requested policy.
            public let enforce: Bool

            public init(policy: Policy, enforce: Bool = false) {
                self.policy = policy
                self.enforce = enforce
            }

            /// Request user verification optional (default policy).
            public static let userVerificationOptional = Self(
                policy: .userVerificationOptional
            )

            /// Request user verification optional with credential ID list.
            public static let userVerificationOptionalWithCredentialIDList = Self(
                policy: .userVerificationOptionalWithCredentialIDList
            )

            /// Request user verification required.
            public static let userVerificationRequired = Self(
                policy: .userVerificationRequired
            )

            /// Create an enforced input that fails if the policy can't be applied.
            ///
            /// - Parameter policy: The credential protection policy to enforce.
            public static func enforced(_ policy: Policy) -> Self {
                Self(policy: policy, enforce: true)
            }
        }

        /// Output from credProtect extension at registration.
        public struct Output: Sendable, Equatable {
            /// The credential protection policy applied to the credential.
            public let policy: Policy

            public init(policy: Policy) {
                self.policy = policy
            }
        }
    }
}

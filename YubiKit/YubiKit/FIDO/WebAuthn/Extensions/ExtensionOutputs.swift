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

// MARK: - Registration Extension Outputs

extension WebAuthn.Extension {

    /// Extension outputs from credential registration (makeCredential).
    ///
    /// Access via `WebAuthn.Registration.Response.clientExtensionResults`.
    public struct RegistrationOutputs: Sendable, Equatable {

        /// PRF extension result.
        ///
        /// `.enabled` if PRF is supported, `.secrets` if hmac-secret-mc returned
        /// derived secrets, or `nil` if PRF was not requested or not supported.
        public let prf: PRF.Registration.Output?

        /// Applied credential protection policy.
        ///
        /// The protection level applied to the credential, or `nil` if credProtect
        /// was not requested or not supported.
        public let credentialProtectionPolicy: CredentialProtectionPolicy?

        /// Whether the credential blob was stored successfully.
        ///
        /// `true` if stored, `false` if storage failed, or `nil` if credBlob
        /// was not requested or not supported.
        public let credBlobSet: Bool?

        /// Minimum PIN length enforced by the authenticator.
        ///
        /// Only returned if the RP is configured in the authenticator's
        /// `minPINLengthRPIDs` list. `nil` if not authorized or not supported.
        public let minPinLength: UInt?

        /// Large blob support result.
        ///
        /// `supported` is `true` if the authenticator supports large blob storage.
        /// `nil` if largeBlob was not requested.
        public let largeBlob: LargeBlob.Registration.Output?

        public init(
            prf: PRF.Registration.Output? = nil,
            credentialProtectionPolicy: CredentialProtectionPolicy? = nil,
            credBlobSet: Bool? = nil,
            minPinLength: UInt? = nil,
            largeBlob: LargeBlob.Registration.Output? = nil
        ) {
            self.prf = prf
            self.credentialProtectionPolicy = credentialProtectionPolicy
            self.credBlobSet = credBlobSet
            self.minPinLength = minPinLength
            self.largeBlob = largeBlob
        }

        /// Empty extension outputs (no extensions requested or supported).
        public static let empty = RegistrationOutputs()
    }
}

// MARK: - Authentication Extension Outputs

extension WebAuthn.Extension {

    /// Extension outputs from credential authentication (getAssertion).
    ///
    /// Access via `WebAuthn.Authentication.Response.clientExtensionResults`.
    public struct AuthenticationOutputs: Sendable, Equatable {

        /// Derived PRF secrets.
        ///
        /// Contains the derived 32-byte secrets, or `nil` if PRF was not
        /// requested or the credential doesn't support PRF.
        public let prf: PRF.Authentication.Output?

        /// Retrieved credential blob.
        ///
        /// The blob data stored during registration, or `nil` if getCredBlob
        /// was not requested or the credential has no stored blob.
        public let credBlob: Data?

        /// Large blob read/write result.
        ///
        /// For reads: `blob` contains the retrieved data (or `nil` if none stored).
        /// For writes: `written` indicates success or failure.
        /// `nil` if largeBlob was not requested.
        public let largeBlob: LargeBlob.Authentication.Output?

        public init(
            prf: PRF.Authentication.Output? = nil,
            credBlob: Data? = nil,
            largeBlob: LargeBlob.Authentication.Output? = nil
        ) {
            self.prf = prf
            self.credBlob = credBlob
            self.largeBlob = largeBlob
        }

        /// Empty extension outputs (no extensions requested or supported).
        public static let empty = AuthenticationOutputs()
    }
}

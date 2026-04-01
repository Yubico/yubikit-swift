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

// MARK: - WebAuthn Extension Namespace

extension WebAuthn {
    /// Namespace for WebAuthn extensions.
    public enum Extension {
        /// Extension identifier type (shared with CTAP2).
        public typealias Identifier = CTAP2.Extension.Identifier

        /// Credential protection policy (alias for CTAP2 credProtect level).
        public typealias CredentialProtectionPolicy = CTAP2.Extension.CredProtect.Level
    }
}

// MARK: - Registration Extension Inputs

extension WebAuthn.Extension {

    /// Extension inputs for credential registration (makeCredential).
    ///
    /// ```swift
    /// let options = WebAuthn.Registration.Options(
    ///     challenge: challenge,
    ///     rp: .init(id: "example.com", name: "Example"),
    ///     user: .init(id: userId, name: "alice@example.com"),
    ///     extensions: .init(
    ///         prf: .enable,
    ///         credentialProtectionPolicy: .userVerificationRequired,
    ///         enforceCredentialProtectionPolicy: true
    ///     )
    /// )
    /// ```
    public struct RegistrationInputs: Sendable, Equatable {

        /// PRF extension input.
        ///
        /// Use `.enable` to enable PRF, or `.eval(first:second:)` to derive
        /// secrets at registration (requires hmac-secret-mc support).
        public let prf: PRF.Registration.Input?

        /// Credential protection policy.
        ///
        /// Controls when user verification is required to use the credential.
        public let credentialProtectionPolicy: CredentialProtectionPolicy?

        /// Enforce credential protection policy.
        ///
        /// If `true`, registration will fail if the authenticator doesn't support
        /// the requested `credentialProtectionPolicy`.
        public let enforceCredentialProtectionPolicy: Bool

        /// Credential blob to store with the credential.
        ///
        /// Must not exceed `maxCredBlobLength` reported by the authenticator.
        public let credBlob: Data?

        /// Request the authenticator's minimum PIN length.
        ///
        /// If `true` and the authenticator supports the `setMinPINLength` option,
        /// the minimum PIN length will be returned in the registration outputs.
        public let minPinLength: Bool

        /// Large blob support request.
        ///
        /// Use `.required` to fail registration if the authenticator doesn't
        /// support large blobs, or `.preferred` to succeed either way.
        public let largeBlob: LargeBlob.Registration.Input?

        public init(
            prf: PRF.Registration.Input? = nil,
            credentialProtectionPolicy: CredentialProtectionPolicy? = nil,
            enforceCredentialProtectionPolicy: Bool = false,
            credBlob: Data? = nil,
            minPinLength: Bool = false,
            largeBlob: LargeBlob.Registration.Input? = nil
        ) {
            self.prf = prf
            self.credentialProtectionPolicy = credentialProtectionPolicy
            self.enforceCredentialProtectionPolicy = enforceCredentialProtectionPolicy
            self.credBlob = credBlob
            self.minPinLength = minPinLength
            self.largeBlob = largeBlob
        }
    }
}

// MARK: - Authentication Extension Inputs

extension WebAuthn.Extension {

    /// Extension inputs for credential authentication (getAssertion).
    ///
    /// ```swift
    /// let options = WebAuthn.Authentication.Options(
    ///     challenge: challenge,
    ///     rpId: "example.com",
    ///     extensions: .init(
    ///         prf: .eval(first: encryptionSeed),
    ///         getCredBlob: true
    ///     )
    /// )
    /// ```
    public struct AuthenticationInputs: Sendable, Equatable {

        /// PRF extension input.
        ///
        /// Use `.eval(first:second:)` to derive secrets during authentication.
        public let prf: PRF.Authentication.Input?

        /// Request credential blob retrieval.
        ///
        /// If `true`, the credential blob stored during registration will be returned.
        public let getCredBlob: Bool

        /// Large blob read or write request.
        ///
        /// Use `.read` to retrieve the blob associated with the credential,
        /// or `.write(data)` to store a blob. Read and write are mutually exclusive.
        public let largeBlob: LargeBlob.Authentication.Input?

        public init(
            prf: PRF.Authentication.Input? = nil,
            getCredBlob: Bool = false,
            largeBlob: LargeBlob.Authentication.Input? = nil
        ) {
            self.prf = prf
            self.getCredBlob = getCredBlob
            self.largeBlob = largeBlob
        }
    }
}

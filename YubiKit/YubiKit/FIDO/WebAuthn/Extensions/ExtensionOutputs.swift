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
        /// Contains `enabled: true` if PRF is supported. If hmac-secret-mc returned
        /// derived secrets, `results` will contain them.
        public let prf: PRF.Registration.Output?

        /// Applied credential protection policy.
        ///
        /// The `policy` applied to the credential, or `nil` if credProtect
        /// was not requested or not supported.
        public let credProtect: CredProtect.Registration.Output?

        /// Credential blob storage result.
        ///
        /// `stored` is `true` if successful, `false` if storage failed,
        /// or `nil` if credBlob was not requested or not supported.
        public let credBlob: CredBlob.Registration.Output?

        /// Minimum PIN length enforced by the authenticator.
        ///
        /// `length` contains the minimum PIN length. Only returned if the RP is
        /// configured in the authenticator's `minPINLengthRPIDs` list.
        public let minPinLength: MinPinLength.Registration.Output?

        /// Large blob support result.
        ///
        /// `supported` is `true` if the authenticator supports large blob storage.
        public let largeBlob: LargeBlob.Registration.Output?

        /// Credential properties result.
        ///
        /// `rk` indicates whether the credential is discoverable (resident key).
        public let credProps: CredProps.Registration.Output?

        /// PreviewSign extension result.
        ///
        /// Contains the generated signing key pair if previewSign was requested.
        public let previewSign: PreviewSign.Registration.Output?

        /// ThirdPartyPayment extension result.
        ///
        /// `isPaymentEnabled` is `true` if the credential was registered as
        /// third-party payment enabled, or `nil` if the authenticator did not
        /// echo the bit.
        public let thirdPartyPayment: ThirdPartyPayment.Registration.Output?

        public init(
            prf: PRF.Registration.Output? = nil,
            credProtect: CredProtect.Registration.Output? = nil,
            credBlob: CredBlob.Registration.Output? = nil,
            minPinLength: MinPinLength.Registration.Output? = nil,
            largeBlob: LargeBlob.Registration.Output? = nil,
            credProps: CredProps.Registration.Output? = nil,
            previewSign: PreviewSign.Registration.Output? = nil,
            thirdPartyPayment: ThirdPartyPayment.Registration.Output? = nil
        ) {
            self.prf = prf
            self.credProtect = credProtect
            self.credBlob = credBlob
            self.minPinLength = minPinLength
            self.largeBlob = largeBlob
            self.credProps = credProps
            self.previewSign = previewSign
            self.thirdPartyPayment = thirdPartyPayment
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
        /// Contains `results` with the derived 32-byte secrets, or `nil` if PRF
        /// was not requested or the credential doesn't support PRF.
        public let prf: PRF.Authentication.Output?

        /// Retrieved credential blob.
        ///
        /// Contains `blob` with the data stored during registration, or `nil`
        /// if credBlob was not requested or the credential has no stored blob.
        public let credBlob: CredBlob.Authentication.Output?

        /// Large blob read/write result.
        ///
        /// For reads: `blob` contains the retrieved data (or `nil` if none stored).
        /// For writes: `written` indicates success or failure.
        public let largeBlob: LargeBlob.Authentication.Output?

        /// PreviewSign extension result.
        ///
        /// Contains the signature if previewSign signing was requested.
        public let previewSign: PreviewSign.Authentication.Output?

        /// ThirdPartyPayment extension result.
        ///
        /// `isPaymentEnabled` is `true` if the credential is third-party payment
        /// enabled, `false` if the authenticator supports the extension but the
        /// credential was not registered as such, or `nil` if the authenticator
        /// did not echo the bit.
        public let thirdPartyPayment: ThirdPartyPayment.Authentication.Output?

        public init(
            prf: PRF.Authentication.Output? = nil,
            credBlob: CredBlob.Authentication.Output? = nil,
            largeBlob: LargeBlob.Authentication.Output? = nil,
            previewSign: PreviewSign.Authentication.Output? = nil,
            thirdPartyPayment: ThirdPartyPayment.Authentication.Output? = nil
        ) {
            self.prf = prf
            self.credBlob = credBlob
            self.largeBlob = largeBlob
            self.previewSign = previewSign
            self.thirdPartyPayment = thirdPartyPayment
        }

        /// Empty extension outputs (no extensions requested or supported).
        public static let empty = AuthenticationOutputs()
    }
}

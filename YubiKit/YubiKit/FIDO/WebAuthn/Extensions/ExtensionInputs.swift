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
        /// Identifier for a WebAuthn-level extension.
        ///
        /// One case per supported WebAuthn extension. Distinct from the CTAP
        /// wire vocabulary in ``CTAP2/Extension/Identifier``.
        public enum Identifier: Hashable, Sendable, CaseIterable {
            /// WebAuthn wrapper over CTAP2 hmac-secret.
            case prf
            case credProtect
            case credBlob
            /// Client-side only; not echoed by the authenticator.
            case credProps
            case largeBlob
            case minPinLength
            /// WebAuthn JSON key is `payment`.
            case thirdPartyPayment
            /// Experimental; see ``WebAuthn/Extension/PreviewSign``.
            case previewSign
        }
    }
}

extension Set where Element == WebAuthn.Extension.Identifier {
    /// Every WebAuthn extension identifier the SDK supports.
    public static var all: Set<Element> { Set(Element.allCases) }

    /// Extensions enabled by default.
    ///
    /// Excludes ``WebAuthn/Extension/Identifier/thirdPartyPayment`` (payment
    /// semantics — opt in explicitly) and ``WebAuthn/Extension/Identifier/previewSign``
    /// (experimental).
    public static let standard: Set<Element> = [
        .prf, .credProtect, .credBlob, .credProps, .largeBlob, .minPinLength,
    ]
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
    ///         credProtect: .enforced(.userVerificationRequired),
    ///         credProps: true
    ///     )
    /// )
    /// ```
    public struct RegistrationInputs: Sendable, Equatable {

        /// PRF extension input.
        ///
        /// Use `.enable` to enable PRF, or `.eval(first:second:)` to derive
        /// secrets at registration (requires hmac-secret-mc support).
        public let prf: PRF.Registration.Input?

        /// Credential protection policy input.
        ///
        /// Controls when user verification is required to use the credential.
        public let credProtect: CredProtect.Registration.Input?

        /// Credential blob to store with the credential.
        ///
        /// Must not exceed `maxCredBlobLength` reported by the authenticator.
        public let credBlob: CredBlob.Registration.Input?

        /// Request the authenticator's minimum PIN length.
        ///
        /// If set and the authenticator supports the `setMinPINLength` option,
        /// the minimum PIN length will be returned in the registration outputs.
        public let minPinLength: MinPinLength.Registration.Input?

        /// Large blob support request.
        ///
        /// Use `.required` to fail registration if the authenticator doesn't
        /// support large blobs, or `.preferred` to succeed either way.
        public let largeBlob: LargeBlob.Registration.Input?

        /// Request credential properties in the response.
        ///
        /// If `true`, the response will include whether the credential is
        /// discoverable (resident key).
        public let credProps: CredProps.Registration.Input?

        /// PreviewSign extension input for key generation.
        ///
        /// Use `.generateKey(algorithms:)` to generate a signing key pair
        /// during credential registration.
        public let previewSign: PreviewSign.Registration.Input?

        /// Mark the credential as usable for Secure Payment Confirmation.
        public let thirdPartyPayment: ThirdPartyPayment.Registration.Input?

        public init(
            prf: PRF.Registration.Input? = nil,
            credProtect: CredProtect.Registration.Input? = nil,
            credBlob: CredBlob.Registration.Input? = nil,
            minPinLength: MinPinLength.Registration.Input? = nil,
            largeBlob: LargeBlob.Registration.Input? = nil,
            credProps: CredProps.Registration.Input? = nil,
            previewSign: PreviewSign.Registration.Input? = nil,
            thirdPartyPayment: ThirdPartyPayment.Registration.Input? = nil
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
        public let getCredBlob: CredBlob.Authentication.Input?

        /// Large blob read or write request.
        ///
        /// Use `.read` to retrieve the blob associated with the credential,
        /// or `.write(data)` to store a blob. Read and write are mutually exclusive.
        public let largeBlob: LargeBlob.Authentication.Input?

        /// PreviewSign extension input for signing.
        ///
        /// Maps credential IDs to signing parameters for delegated signing.
        public let previewSign: PreviewSign.Authentication.Input?

        /// Signal that this assertion is a Secure Payment Confirmation payment assertion.
        public let thirdPartyPayment: ThirdPartyPayment.Authentication.Input?

        public init(
            prf: PRF.Authentication.Input? = nil,
            getCredBlob: CredBlob.Authentication.Input? = nil,
            largeBlob: LargeBlob.Authentication.Input? = nil,
            previewSign: PreviewSign.Authentication.Input? = nil,
            thirdPartyPayment: ThirdPartyPayment.Authentication.Input? = nil
        ) {
            self.prf = prf
            self.getCredBlob = getCredBlob
            self.largeBlob = largeBlob
            self.previewSign = previewSign
            self.thirdPartyPayment = thirdPartyPayment
        }
    }
}

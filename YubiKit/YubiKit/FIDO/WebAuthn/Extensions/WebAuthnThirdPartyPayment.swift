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

// MARK: - ThirdPartyPayment Extension

extension WebAuthn.Extension {

    /// The `thirdPartyPayment` (WebAuthn JSON: `payment`) CTAP2 extension.
    ///
    /// At registration, marks a credential as usable for third-party payment
    /// authentication. At authentication, signals that the assertion is a
    /// payment assertion. Only `isPayment` is propagated to CTAP.
    ///
    /// > Important: This covers **only** the CTAP2 layer. Full Secure Payment
    /// > Confirmation requires a WebAuthn-level client that rebuilds
    /// > `clientDataJSON` with `type: "payment.get"` and the SPC payment
    /// > dictionary — YubiKit does not currently provide that. RPs that need
    /// > end-to-end SPC binding must layer it themselves, and must verify the
    /// > echoed `thirdPartyPayment` bit directly from the authenticator data
    /// > extensions (this library does not surface it in `clientExtensionResults`,
    /// > matching python-fido2 and yubikit-android).
    ///
    /// - SeeAlso: [Secure Payment Confirmation](https://www.w3.org/TR/secure-payment-confirmation/)
    /// - SeeAlso: [CTAP 2.2 thirdPartyPayment](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-thirdPartyPayment-extension)
    public enum ThirdPartyPayment {}
}

// MARK: - Registration Input/Output

extension WebAuthn.Extension.ThirdPartyPayment {

    public enum Registration {
        /// Input for thirdPartyPayment at registration.
        ///
        /// Set `isPayment: true` to mark the credential as payment-capable.
        public struct Input: Sendable, Equatable {
            public let isPayment: Bool

            public init(isPayment: Bool = true) {
                self.isPayment = isPayment
            }

            /// Convenience: request payment capability.
            public static let enable = Input(isPayment: true)
        }
    }
}

// MARK: - Authentication Input/Output

extension WebAuthn.Extension.ThirdPartyPayment {

    public enum Authentication {
        /// Input for thirdPartyPayment at authentication.
        ///
        /// Only `isPayment` is forwarded to CTAP. SPC payment metadata
        /// (`rpId`, `topOrigin`, `payeeName`, `total`, `instrument`, …) that
        /// RPs send in the WebAuthn `payment` dictionary is ignored at this
        /// layer — see the type-level documentation.
        public struct Input: Sendable, Equatable {
            public let isPayment: Bool

            public init(isPayment: Bool = true) {
                self.isPayment = isPayment
            }
        }
    }
}

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

extension WebAuthn.Extension {

    /// The `thirdPartyPayment` (WebAuthn JSON: `payment`) CTAP2 extension.
    ///
    /// Marks a credential as usable for
    /// [Secure Payment Confirmation (SPC)](https://www.w3.org/TR/secure-payment-confirmation)
    /// and reports back whether a credential was registered with that mark.
    ///
    /// This SDK forwards the `thirdPartyPayment` flag to the authenticator only.
    /// It does **not** synthesize the SPC `clientDataJSON` (`type: "payment.get"`,
    /// embedded `payment` member) required by W3C SPC; consumers wanting full
    /// SPC support must build that out-of-band.
    public enum ThirdPartyPayment {

        public enum Registration {
            public struct Input: Sendable, Equatable {
                public let isPayment: Bool

                public init(isPayment: Bool) {
                    self.isPayment = isPayment
                }

                /// Mark the credential as usable for Secure Payment Confirmation.
                public static let enabled = Self(isPayment: true)
            }

            /// Output from thirdPartyPayment extension at registration.
            public struct Output: Sendable, Equatable {
                /// Whether the credential was registered as third-party payment enabled.
                public let isPaymentEnabled: Bool

                public init(isPaymentEnabled: Bool) {
                    self.isPaymentEnabled = isPaymentEnabled
                }
            }
        }

        public enum Authentication {
            public struct Input: Sendable, Equatable {
                public let isPayment: Bool

                public init(isPayment: Bool) {
                    self.isPayment = isPayment
                }

                /// Signal that this assertion is a Secure Payment Confirmation payment assertion.
                public static let enabled = Self(isPayment: true)
            }

            /// Output from thirdPartyPayment extension at authentication.
            public struct Output: Sendable, Equatable {
                /// Whether the credential is third-party payment enabled.
                public let isPaymentEnabled: Bool

                public init(isPaymentEnabled: Bool) {
                    self.isPaymentEnabled = isPaymentEnabled
                }
            }
        }
    }
}

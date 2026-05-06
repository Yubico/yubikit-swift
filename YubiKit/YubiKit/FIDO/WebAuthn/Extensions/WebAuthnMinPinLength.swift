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

// MARK: - MinPinLength Extension

extension WebAuthn.Extension {

    /// The [minPinLength extension](https://www.w3.org/TR/webauthn-3/#sctn-minpinlength-extension)
    /// for retrieving authenticator PIN length requirements.
    ///
    /// This WebAuthn extension wraps the CTAP2 minPinLength extension, allowing
    /// authorized relying parties to retrieve the minimum PIN length enforced
    /// by the authenticator.
    ///
    /// ## Registration
    ///
    /// Request minimum PIN length when creating a credential:
    ///
    /// ```swift
    /// let options = WebAuthn.Registration.Options(
    ///     ...,
    ///     extensions: .init(minPinLength: true)
    /// )
    /// let response = try await client.makeCredential(options, authorization: .pin(pin)).value
    /// if let length = response.clientExtensionResults.minPinLength?.length {
    ///     print("Minimum PIN length: \(length)")
    /// }
    /// ```
    ///
    /// - Note: The RP ID must be configured in the authenticator's `minPINLengthRPIDs`
    ///   list for the minimum PIN length to be returned.
    public enum MinPinLength {}
}

// MARK: - Registration Input/Output

extension WebAuthn.Extension.MinPinLength {

    /// Namespace for minPinLength registration types.
    public enum Registration {

        /// Input for minPinLength extension at registration.
        ///
        /// Set to `true` to request the minimum PIN length from the authenticator.
        public typealias Input = Bool

        /// Output from minPinLength extension at registration.
        public struct Output: Sendable, Equatable {
            /// The minimum PIN length enforced by the authenticator.
            public let length: UInt

            public init(length: UInt) {
                self.length = length
            }
        }
    }
}

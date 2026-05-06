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

// MARK: - CredProps Extension

extension WebAuthn.Extension {

    /// The [Credential Properties (credProps) extension](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension).
    ///
    /// This is a client-side WebAuthn extension that reports whether the created
    /// credential is discoverable (resident key). Unlike other extensions, `credProps`
    /// does not require authenticator support — the client computes the result based
    /// on the requested options and authenticator capabilities.
    ///
    /// ## Registration
    ///
    /// Request credential properties when creating a credential:
    ///
    /// ```swift
    /// let options = WebAuthn.Registration.Options(
    ///     ...,
    ///     residentKey: .preferred,
    ///     extensions: .init(credProps: true)
    /// )
    /// let response = try await client.makeCredential(options, authorization: .pin(pin)).value
    /// if response.clientExtensionResults.credProps?.rk == true {
    ///     // Credential is discoverable - user can sign in without typing username
    /// } else {
    ///     // Credential is not discoverable - store credential ID server-side
    /// }
    /// ```
    public enum CredProps {}
}

// MARK: - Registration Input/Output

extension WebAuthn.Extension.CredProps {

    /// Namespace for credProps registration types.
    public enum Registration {
        /// Input for credProps extension at registration.
        ///
        /// Set to `true` to request credential properties in the response.
        public typealias Input = Bool

        /// Output from credProps extension at registration.
        public struct Output: Sendable, Equatable {
            /// Whether the credential is discoverable (resident key).
            ///
            /// - `true`: The credential is discoverable and can be used for
            ///   username-less authentication.
            /// - `false`: The credential is server-side and requires the
            ///   credential ID to be provided during authentication.
            public let rk: Bool

            public init(rk: Bool) {
                self.rk = rk
            }
        }
    }
}

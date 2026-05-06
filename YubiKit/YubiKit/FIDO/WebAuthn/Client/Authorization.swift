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

// MARK: - Authorization

extension WebAuthn {

    /// PIN/UV policy for a single WebAuthn ceremony.
    ///
    /// `Authorization` carries the PIN-providing closure and the UV
    /// policy for one ceremony. It is supplied per call to
    /// ``Client/makeCredential(_:authorization:)`` and
    /// ``Client/getAssertion(_:authorization:)``.
    ///
    /// Use a built-in factory for trivial cases:
    ///
    /// ```swift
    /// let r = try await client.makeCredential(opts, authorization: .pin("1234")).value
    /// ```
    ///
    /// Or build a custom instance to bridge into a UI:
    ///
    /// ```swift
    /// let auth = WebAuthn.Authorization(providePIN: {
    ///     guard let pin = await viewModel.askForPIN() else { return .cancel }
    ///     return .pin(pin)
    /// })
    /// let r = try await client.makeCredential(opts, authorization: auth).value
    /// ```
    ///
    /// PIN attempts are one-shot: a wrong PIN throws
    /// ``ClientError/pinRejected(retriesRemaining:source:)`` and the caller
    /// decides whether to re-prompt and retry the ceremony with a fresh
    /// `Authorization`.
    public struct Authorization: Sendable {

        /// Caller answer to a PIN prompt from the SDK.
        public enum PINReply: Sendable {
            /// Submit this PIN to the authenticator.
            case pin(String)
            /// Abort the ceremony — the SDK throws ``ClientError/cancelled(source:)``.
            case cancel
        }

        /// How the SDK should handle built-in user verification (biometric
        /// or on-device PIN) for this ceremony.
        public enum UVPolicy: Sendable {
            /// Attempt built-in UV first. If UV is locked out
            /// (``ClientError/uvBlocked(source:)``) and `clientPin` is
            /// configured, fall through to the PIN closure within the
            /// same ceremony. A wrong-attempt failure surfaces as
            /// ``ClientError/uvRejected(retriesRemaining:source:)`` so the
            /// caller decides whether to re-prompt UV or switch to PIN.
            /// The default for most ceremonies.
            case preferred
            /// Skip built-in UV entirely and go straight to the PIN closure.
            case skipped
            /// Attempt built-in UV; never fall through to PIN. A wrong
            /// attempt throws ``ClientError/uvRejected(retriesRemaining:source:)``;
            /// lockout throws ``ClientError/uvBlocked(source:)``. The PIN
            /// closure is never invoked.
            case required
        }

        /// Called when the SDK needs a PIN. Return ``PINReply/pin(_:)`` to
        /// submit a PIN or ``PINReply/cancel`` to abort the ceremony.
        public let providePIN: @Sendable () async -> PINReply

        /// How to handle built-in UV for this ceremony. See ``UVPolicy``.
        public let uv: UVPolicy

        /// Build an authorization from a custom PIN-providing closure.
        ///
        /// - Parameters:
        ///   - providePIN: Called when the SDK needs a PIN. Return
        ///     ``PINReply/pin(_:)`` or ``PINReply/cancel``.
        ///   - uv: UV policy for this ceremony. Defaults to ``UVPolicy/preferred``.
        public init(
            providePIN: @Sendable @escaping () async -> PINReply,
            uv: UVPolicy = .preferred
        ) {
            self.providePIN = providePIN
            self.uv = uv
        }

        /// Pre-supplied PIN authorization.
        ///
        /// The supplied PIN is used directly — built-in UV is skipped.
        /// If the authenticator rejects the PIN the ceremony throws
        /// ``ClientError/pinRejected(retriesRemaining:source:)``.
        ///
        /// To pre-supply a PIN but still attempt built-in UV first, use
        /// the explicit initializer:
        ///
        /// ```swift
        /// Authorization(providePIN: { .pin("1234") }, uv: .preferred)
        /// ```
        public static func pin(_ pin: String) -> Authorization {
            Authorization(providePIN: { .pin(pin) }, uv: .skipped)
        }

        /// Built-in UV only. The PIN closure is never invoked; a wrong UV
        /// attempt throws ``ClientError/uvRejected(retriesRemaining:source:)``
        /// and lockout throws ``ClientError/uvBlocked(source:)``.
        public static let uvOnly = Authorization(
            providePIN: { .cancel },
            uv: .required
        )
    }
}

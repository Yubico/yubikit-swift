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

/// WebAuthn (Web Authentication) namespace.
///
/// Contains types for WebAuthn protocol structures including authenticator data,
/// attestation statements, and extension outputs.
///
/// - SeeAlso: [Web Authentication: An API for accessing Public Key Credentials](https://www.w3.org/TR/webauthn/)
public enum WebAuthn {

    /// Authenticator Attestation Global Unique ID (128 bits).
    ///
    /// Opaque identifier for the authenticator model.
    public typealias AAGUID = CTAP2.GetInfo.Opaque128

    /// Status updates during WebAuthn operations.
    ///
    /// These status values are emitted during operations that may require user interaction
    /// or extended processing time.
    public typealias Status = CTAP2.Status

    /// An async sequence that yields status updates during WebAuthn operations.
    ///
    /// ## Usage
    ///
    /// For simple cases where you don't need status updates, use the ``StatusStream/value`` property:
    ///
    /// ```swift
    /// let response = try await client.makeCredential(options: opts, origin: origin).value
    /// ```
    ///
    /// For UI feedback or cancellation support, iterate the stream:
    ///
    /// ```swift
    /// let stream = client.makeCredential(options: opts, origin: origin)
    ///
    /// for try await status in stream {
    ///     switch status {
    ///     case .processing:
    ///         showSpinner()
    ///     case .waitingForUser(let cancel):
    ///         showTouchPrompt(onCancel: { Task { await cancel() } })
    ///     case .finished(let response):
    ///         return response
    ///     }
    /// }
    /// ```
    public typealias StatusStream<R: Sendable> = StatusStreamBase<R, ClientError>
}

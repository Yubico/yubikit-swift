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
    public enum Status<Response: Sendable>: Sendable {
        /// The authenticator is processing the request.
        case processing

        /// The authenticator is waiting for user interaction.
        ///
        /// - Parameter cancel: Closure to cancel the operation.
        case waitingForUser(cancel: @Sendable () async -> Void)

        /// The client is about to request user verification (biometric).
        ///
        /// Call the respond closure with `true` to proceed with UV, or `false` to skip UV
        /// and use PIN instead. This is called before UV starts, giving the user a chance
        /// to opt for PIN entry.
        ///
        /// - Parameter respond: Closure to call with the user's choice.
        case requestingUV(respond: @Sendable (Bool) -> Void)

        /// The operation completed successfully with a response.
        case finished(Response)
    }

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
    ///     case .requestingUV(let respond):
    ///         askUserAboutUV { proceed in respond(proceed) }
    ///     case .finished(let response):
    ///         return response
    ///     }
    /// }
    /// ```
    public typealias StatusStream<R: Sendable> = StatusStreamBase<Status<R>, ClientError>
}

extension WebAuthn.Status: StreamStatus {
    public var finishedResponse: Response? {
        if case .finished(let response) = self { return response }
        return nil
    }

    public static func areDuplicates(_ lhs: Self, _ rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case (.processing, .processing), (.waitingForUser, .waitingForUser):
            true
        default:
            false
        }
    }
}

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
    public typealias StatusStream<R: Sendable> = StatusStreamBase<Status<R>, Error>

    /// Relying Party entity information.
    ///
    /// Identifies the relying party (website or service) that is requesting
    /// credential registration or authentication.
    ///
    /// - SeeAlso: [WebAuthn PublicKeyCredentialRpEntity](https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialrpentity)
    public struct RelyingParty: Sendable {
        /// Relying Party identifier (e.g., "example.com").
        public let id: String

        /// Human-readable relying party name.
        public let name: String?

        public init(id: String, name: String? = nil) {
            self.id = id
            self.name = name
        }
    }

    /// User account entity information.
    ///
    /// Identifies the user account for which a credential is being registered
    /// or that owns an existing credential.
    ///
    /// - SeeAlso: [WebAuthn PublicKeyCredentialUserEntity](https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialuserentity)
    public struct User: Sendable {
        /// User handle (opaque byte sequence).
        public let id: Data

        /// User identifier (e.g., "alice@example.com").
        public let name: String?

        /// Display name (e.g., "Alice Smith").
        public let displayName: String?

        public init(id: Data, name: String? = nil, displayName: String? = nil) {
            self.id = id
            self.name = name
            self.displayName = displayName
        }
    }

    /// Public key credential descriptor identifying a specific credential.
    ///
    /// Used in `allowList` and `excludeList` parameters to identify credentials
    /// for authentication or exclusion during registration.
    ///
    /// - SeeAlso: [WebAuthn PublicKeyCredentialDescriptor](https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor)
    public struct CredentialDescriptor: Sendable, Hashable {
        /// Credential type (always "public-key" for FIDO2).
        public let type: String

        /// Credential ID (opaque byte sequence).
        public let id: Data

        /// Optional transports hint.
        public let transports: Set<Transport>?

        public init(type: String = "public-key", id: Data, transports: Set<Transport>? = nil) {
            self.type = type
            self.id = id
            self.transports = transports
        }
    }

    public enum ResidentKeyPreference: String, Sendable, Decodable {
        case required, preferred, discouraged
    }

    public enum UserVerificationPreference: String, Sendable, Decodable {
        case required, preferred, discouraged
    }

    public enum AttestationPreference: String, Sendable, Decodable {
        case none, indirect, direct, enterprise
    }
}

// MARK: - StreamStatus Conformance

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

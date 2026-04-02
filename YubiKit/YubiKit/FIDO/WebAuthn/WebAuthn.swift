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
/// - SeeAlso: [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
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
        /// Call `useUV(true)` to proceed with biometric verification, or `useUV(false)`
        /// to skip UV and use PIN instead. This is called before UV starts, giving the
        /// user a chance to opt for PIN entry.
        ///
        /// - Parameter useUV: Closure to call with `true` for UV or `false` for PIN.
        case requestingUV(useUV: @Sendable (Bool) -> Void)

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
    ///     case .requestingUV(let useUV):
    ///         askUserAboutUV { useUV($0) }
    ///     case .finished(let response):
    ///         return response
    ///     }
    /// }
    /// ```
    public typealias StatusStream<R: Sendable> = StatusStreamBase<Status<R>, ClientError>

    /// Relying Party entity information.
    ///
    /// Identifies the relying party (website or service) that is requesting
    /// credential registration or authentication.
    ///
    /// - SeeAlso: [WebAuthn PublicKeyCredentialRpEntity](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrpentity)
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
    /// - SeeAlso: [WebAuthn PublicKeyCredentialUserEntity](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentity)
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
    /// - SeeAlso: [WebAuthn PublicKeyCredentialDescriptor](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptor)
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

    /// Preference for creating a discoverable (resident) credential.
    ///
    /// - SeeAlso: [WebAuthn ResidentKeyRequirement](https://www.w3.org/TR/webauthn-3/#enumdef-residentkeyrequirement)
    public enum ResidentKeyPreference: String, Sendable, Decodable {
        /// Require a discoverable credential. Fails if the authenticator doesn't support it.
        case required
        /// Prefer discoverable if supported, fall back to non-discoverable.
        case preferred
        /// Prefer a non-discoverable (server-side) credential.
        case discouraged
    }

    /// Preference for user verification during an operation.
    ///
    /// - SeeAlso: [WebAuthn UserVerificationRequirement](https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement)
    public enum UserVerificationPreference: String, Sendable, Decodable {
        /// Require user verification (PIN or biometric). Fails if not possible.
        case required
        /// Prefer user verification if available, but allow without.
        case preferred
        /// Skip user verification if possible.
        case discouraged
    }

    /// Preference for attestation statement conveyance.
    ///
    /// - SeeAlso: [WebAuthn AttestationConveyancePreference](https://www.w3.org/TR/webauthn-3/#enumdef-attestationconveyancepreference)
    public enum AttestationPreference: String, Sendable, Decodable {
        /// No attestation statement required.
        case none
        /// Client may replace direct attestation with an anonymized version.
        case indirect
        /// Return the authenticator's attestation statement unmodified.
        case direct
        /// Request enterprise attestation (requires authenticator and RP support).
        case enterprise
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

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
/// Contains the high-level passkey ``Client`` and the request, response, and
/// data-model types defined by the
/// [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
/// specification.
public enum WebAuthn {

    /// Authenticator Attestation Global Unique ID (128 bits).
    ///
    /// Opaque identifier for the authenticator model.
    public typealias AAGUID = CTAP2.GetInfo.Opaque128

    /// Status updates during WebAuthn operations.
    ///
    /// These status values report progress of an in-flight ceremony. PIN
    /// entry and UV decisions are handled out-of-band via the
    /// ``Authorization`` parameter on ``Client/makeCredential(_:authorization:)``
    /// and ``Client/getAssertion(_:authorization:)`` — they do not appear
    /// on this stream.
    public enum Status<Response: Sendable>: Sendable {
        /// The authenticator is processing the request.
        case processing

        /// The authenticator is performing built-in user verification (e.g.
        /// fingerprint capture on a YubiKey Bio).
        ///
        /// - Parameters:
        ///   - cancel: Cancel the ceremony — surfaces as ``ClientError/cancelled(source:)``.
        ///   - fallbackToPIN: Abandon UV and route into the PIN path within the
        ///     same ceremony, calling ``Authorization/providePIN`` for the PIN.
        ///     `nil` under ``Authorization/UVPolicy/required`` or when no
        ///     `clientPin` is configured.
        case waitingForUserVerification(
            cancel: @Sendable () async -> Void,
            fallbackToPIN: (@Sendable () async -> Void)?
        )

        /// The authenticator is waiting for user interaction.
        ///
        /// - Parameter cancel: Closure to cancel the operation.
        case waitingForUser(cancel: @Sendable () async -> Void)

        /// The operation completed successfully with a response.
        case finished(Response)
    }

    /// An async sequence that yields status updates during WebAuthn operations.
    ///
    /// ## Usage
    ///
    /// For simple cases without UI feedback, drain the stream with ``value``:
    ///
    /// ```swift
    /// let response = try await client.makeCredential(opts, authorization: .pin(pin)).value
    /// ```
    ///
    /// For UI feedback or cancellation support, iterate the stream:
    ///
    /// ```swift
    /// let stream = await client.makeCredential(opts, authorization: .pin(pin))
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
    ///
    /// PIN entry and UV decisions are handled out-of-band via the
    /// ``Authorization`` parameter on ``Client/makeCredential(_:authorization:)``
    /// and ``Client/getAssertion(_:authorization:)``.
    public struct StatusStream<R: Sendable>: AsyncSequence, @unchecked Sendable {
        public typealias Element = Status<R>

        typealias Base = StatusStreamBase<Status<R>, ClientError>
        typealias Continuation = Base.Continuation

        private let base: Base

        init(_ build: @escaping (Continuation) -> Void) {
            self.base = Base(build)
        }

        init(_ base: Base) {
            self.base = base
        }

        static func error(_ error: ClientError) -> Self {
            Self(Base.error(error))
        }

        func withTimeout(_ duration: Duration?) -> Self {
            guard let duration else { return self }
            return Self(base.timeout(duration, error: .timeout(source: .here())))
        }

        // MARK: - Value Accessor

        /// Consumes the stream and returns the final response value.
        ///
        /// Errors raised by the ceremony propagate as thrown errors.
        public var value: R {
            get async throws(ClientError) {
                for try await status in self {
                    if case .finished(let response) = status { return response }
                }
                preconditionFailure("StatusStream must yield .finished before ending")
            }
        }

        // MARK: - AsyncSequence

        public func makeAsyncIterator() -> Iterator {
            Iterator(base.makeAsyncIterator())
        }

        public struct Iterator: AsyncIteratorProtocol {
            private var base: Base.Iterator
            private var last: Status<R>?

            fileprivate init(_ base: Base.Iterator) {
                self.base = base
            }

            public mutating func next() async throws(ClientError) -> Status<R>? {
                while true {
                    guard let status = try await base.next() else { return nil }
                    if let last, Status<R>.areDuplicates(last, status) {
                        continue
                    }
                    last = status
                    return status
                }
            }
        }
    }

    /// Relying Party entity information.
    ///
    /// Identifies the relying party (website or service) requesting credential
    /// registration or authentication. Mirrors the W3C
    /// [PublicKeyCredentialRpEntity](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrpentity).
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
    /// or that owns an existing credential. Mirrors the W3C
    /// [PublicKeyCredentialUserEntity](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentity).
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
    /// for authentication or exclusion during registration. Mirrors the W3C
    /// [PublicKeyCredentialDescriptor](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptor).
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
    /// Mirrors the W3C
    /// [ResidentKeyRequirement](https://www.w3.org/TR/webauthn-3/#enumdef-residentkeyrequirement).
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
    /// Mirrors the W3C
    /// [UserVerificationRequirement](https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement).
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
    /// Mirrors the W3C
    /// [AttestationConveyancePreference](https://www.w3.org/TR/webauthn-3/#enumdef-attestationconveyancepreference).
    public enum AttestationPreference: String, Sendable, Decodable {
        /// The relying party doesn't want attestation. The client requests
        /// a `none`-format (empty) attestation statement from the authenticator.
        case none
        /// The relying party allows the client to mediate attestation —
        /// passing it through, anonymizing it, or replacing it.
        case indirect
        /// Return the authenticator's attestation statement unmodified.
        case direct
        /// Request enterprise attestation (requires authenticator and RP support).
        case enterprise
    }
}

// MARK: - StreamStatus Conformance

extension WebAuthn.Status: StreamStatus {
    var finishedResponse: Response? {
        if case .finished(let response) = self { return response }
        return nil
    }
}

// MARK: - Deduplication

extension WebAuthn.Status {
    fileprivate static func areDuplicates(_ lhs: Self, _ rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case (.processing, .processing),
            (.waitingForUser, .waitingForUser),
            (.waitingForUserVerification, .waitingForUserVerification):
            true
        default:
            false
        }
    }
}

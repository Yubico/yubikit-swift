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

extension WebAuthn {

    /// Client for performing WebAuthn passkey operations.
    ///
    /// Provides a unified interface for passkey registration and authentication
    /// backed by a YubiKey via CTAP2 protocol (USB/NFC).
    ///
    /// ```swift
    /// let session = try await CTAP2.Session(connection: connection)
    /// let client = WebAuthn.Client(
    ///     session: session,
    ///     origin: try .init("https://example.com"),
    ///     pinProvider: { await promptUserForPIN() },
    ///     isPublicSuffix: { publicSuffixList.contains($0) }
    /// )
    ///
    /// let credential = try await client.makeCredential(
    ///     .init(
    ///         challenge: challenge,
    ///         rp: .init(id: "example.com", name: "Example"),
    ///         user: .init(id: userId, name: "alice@example.com", displayName: "Alice")
    ///     )
    /// ).value
    /// ```
    ///
    /// - SeeAlso: [Web Authentication](https://www.w3.org/TR/webauthn-3/)
    public struct Client: Sendable {

        // MARK: - Properties

        private let backend: any Backend
        private let origin: Origin
        private let isPublicSuffix: PublicSuffixChecker

        // MARK: - Initialization

        /// Create a WebAuthn client backed by a CTAP2 session.
        ///
        /// - Parameters:
        ///   - session: The CTAP2 session to use.
        ///   - origin: The origin URL for this client (e.g., `https://example.com`).
        ///   - pinProvider: Closure called when PIN is required. Return `nil` to cancel.
        ///   - enterpriseRpIds: RP IDs that support platform-facilitated enterprise attestation.
        ///     When a credential is created with `.enterprise` attestation for an RP ID in this set,
        ///     the client uses platform-facilitated mode (value 2). For other RP IDs, it uses
        ///     vendor-facilitated mode (value 1). See CTAP 2.2 §6.1.1.
        ///   - isPublicSuffix: Returns `true` if the domain is in the Public Suffix List.
        public init(
            session: CTAP2.Session,
            origin: Origin,
            pinProvider: PINProvider? = nil,
            enterpriseRpIds: Set<String> = [],
            isPublicSuffix: @escaping PublicSuffixChecker
        ) {
            self.backend = CTAP2Backend(
                session: session,
                pinProvider: pinProvider,
                enterpriseRpIds: enterpriseRpIds
            )
            self.origin = origin
            self.isPublicSuffix = isPublicSuffix
        }

        // MARK: - Public API

        /// Create a new passkey credential.
        ///
        /// Uses the client's origin and validates the RP ID.
        public func makeCredential(
            _ options: Registration.Options
        ) async -> StatusStream<Registration.Response> {
            let rpId = options.rp.id
            let clientData = ClientData.webauthn(
                type: "webauthn.create",
                challenge: options.challenge,
                origin: origin,
                rpId: rpId
            )
            return await makeCredential(options, clientData: clientData)
        }

        /// Create a new passkey credential with custom client data.
        public func makeCredential(
            _ options: Registration.Options,
            clientData: ClientData
        ) async -> StatusStream<Registration.Response> {
            if let error = validateRpId(clientData.rpId, origin: clientData.origin) {
                return .error(error)
            }
            return await backend.makeCredential(options: options, clientData: clientData)
                .withTimeout(options.timeout)
        }

        /// Authenticate with an existing passkey credential.
        ///
        /// Uses the client's origin and validates the RP ID.
        public func getAssertion(
            _ options: Authentication.Options
        ) async -> StatusStream<Authentication.Response> {
            let rpId = options.rpId ?? origin.host
            let clientData = ClientData.webauthn(
                type: "webauthn.get",
                challenge: options.challenge,
                origin: origin,
                rpId: rpId
            )
            return await getAssertion(options, clientData: clientData)
        }

        /// Authenticate with an existing passkey credential using custom client data.
        public func getAssertion(
            _ options: Authentication.Options,
            clientData: ClientData
        ) async -> StatusStream<Authentication.Response> {
            if let error = validateRpId(clientData.rpId, origin: clientData.origin) {
                return .error(error)
            }
            return await backend.getAssertion(options: options, clientData: clientData)
                .withTimeout(options.timeout)
        }

        /// Get all matching assertions for credential selection UI.
        ///
        /// Uses the client's origin and validates the RP ID.
        public func getAssertions(
            _ options: Authentication.Options
        ) async -> StatusStream<[Authentication.Assertion]> {
            let rpId = options.rpId ?? origin.host
            let clientData = ClientData.webauthn(
                type: "webauthn.get",
                challenge: options.challenge,
                origin: origin,
                rpId: rpId
            )
            return await getAssertions(options, clientData: clientData)
        }

        /// Get all matching assertions using custom client data.
        public func getAssertions(
            _ options: Authentication.Options,
            clientData: ClientData
        ) async -> StatusStream<[Authentication.Assertion]> {
            if let error = validateRpId(clientData.rpId, origin: clientData.origin) {
                return .error(error)
            }
            return await backend.getAssertions(options: options, clientData: clientData)
                .withTimeout(options.timeout)
        }

        // MARK: - Private Helpers

        private func validateRpId(_ rpId: String, origin: Origin) -> ClientError? {
            let rpIdLower = rpId.lowercased()
            let hostLower = origin.host.lowercased()

            // RP ID cannot be a public suffix (e.g., "co.uk", "github.io")
            if isPublicSuffix(rpIdLower) {
                return .invalidRequest(
                    "RP ID '\(rpId)' is a public suffix",
                    source: .here()
                )
            }

            // RP ID must be equal to or a registrable suffix of the origin's host
            guard hostLower == rpIdLower || hostLower.hasSuffix("." + rpIdLower) else {
                return .invalidRequest(
                    "RP ID '\(rpId)' is not valid for origin '\(origin)'",
                    source: .here()
                )
            }
            return nil
        }
    }

    // MARK: - Type Aliases

    /// Closure called when PIN is required. Return `nil` to cancel.
    public typealias PINProvider = @Sendable () async -> String?

    /// Closure that returns `true` if the given domain is in the [Public Suffix List](https://publicsuffix.org/).
    public typealias PublicSuffixChecker = @Sendable (String) -> Bool

    // MARK: - Backend Protocol

    protocol Backend: Sendable {
        func makeCredential(
            options: Registration.Options,
            clientData: ClientData
        ) async -> StatusStream<Registration.Response>

        func getAssertion(
            options: Authentication.Options,
            clientData: ClientData
        ) async -> StatusStream<Authentication.Response>

        func getAssertions(
            options: Authentication.Options,
            clientData: ClientData
        ) async -> StatusStream<[Authentication.Assertion]>
    }
}

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

// MARK: - WebAuthn Client

extension WebAuthn {

    /// Client for performing WebAuthn passkey operations.
    ///
    /// Provides a unified interface for passkey registration and authentication
    /// backed by a YubiKey via CTAP2 protocol (USB/NFC).
    ///
    /// All user interaction (PIN entry, UV approval) is communicated through the
    /// status stream. Iterate the stream to handle these requests:
    ///
    /// ```swift
    /// let session = try await CTAP2.Session(connection: connection)
    /// let client = WebAuthn.Client(
    ///     session: session,
    ///     origin: try .init("https://example.com"),
    ///     isPublicSuffix: { publicSuffixList.contains($0) }
    /// )
    ///
    /// for try await status in client.makeCredential(options) {
    ///     switch status {
    ///     case .processing: showSpinner()
    ///     case .waitingForUser(let cancel): showTouchPrompt()
    ///     case .requestingUV(let useUV): useUV(true)
    ///     case .requestingPIN(let submitPIN): submitPIN(await askForPIN())
    ///     case .finished(let response): return response
    ///     }
    /// }
    /// ```
    ///
    /// - SeeAlso: [Web Authentication](https://www.w3.org/TR/webauthn-3/)
    public actor Client {

        // MARK: - Internal Properties

        let backend: any Backend
        let origin: Origin
        let enterpriseRpIds: Set<String>
        let allowedExtensions: Set<WebAuthn.Extension.Identifier>
        let isPublicSuffix: PublicSuffixChecker

        // MARK: - Initialization

        /// Create a WebAuthn client backed by a CTAP2 session.
        ///
        /// - Parameters:
        ///   - session: The CTAP2 session to use.
        ///   - origin: The origin URL for this client (e.g., `https://example.com`).
        ///   - enterpriseRpIds: RP IDs that support platform-facilitated enterprise attestation.
        ///     When a credential is created with `.enterprise` attestation for an RP ID in this set,
        ///     the client uses platform-facilitated mode (value 2). For other RP IDs, it uses
        ///     vendor-facilitated mode (value 1). See CTAP 2.2 §6.1.1.
        ///   - allowedExtensions: Extensions this client will process. Anything the RP sends
        ///     that isn't in this list is silently dropped. Defaults to `.standard`
        ///     (every extension except `thirdPartyPayment` and `previewSign`).
        ///     Pass `.all` for every supported extension, `[]` to ignore them all,
        ///     or a custom subset.
        ///   - isPublicSuffix: Returns `true` if the domain is in the Public Suffix List.
        public init(
            session: CTAP2.Session,
            origin: Origin,
            enterpriseRpIds: Set<String> = [],
            allowedExtensions: Set<WebAuthn.Extension.Identifier> = .standard,
            isPublicSuffix: @escaping PublicSuffixChecker
        ) {
            self.init(
                backend: session,
                origin: origin,
                enterpriseRpIds: enterpriseRpIds,
                allowedExtensions: allowedExtensions,
                isPublicSuffix: isPublicSuffix
            )
        }

        /// Internal initializer for testing with a mock backend.
        ///
        /// `allowedExtensions` has no default here on purpose: tests must opt in
        /// explicitly so the suite never silently drifts from the public `.standard`.
        init(
            backend: any Backend,
            origin: Origin,
            enterpriseRpIds: Set<String> = [],
            allowedExtensions: Set<WebAuthn.Extension.Identifier>,
            isPublicSuffix: @escaping PublicSuffixChecker
        ) {
            self.backend = backend
            self.origin = origin
            self.enterpriseRpIds = enterpriseRpIds
            self.allowedExtensions = allowedExtensions
            self.isPublicSuffix = isPublicSuffix
        }
    }

    // MARK: - Type Aliases

    /// Closure that returns `true` if the given domain is in the [Public Suffix List](https://publicsuffix.org/).
    public typealias PublicSuffixChecker = @Sendable (String) -> Bool
}

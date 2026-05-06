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

// MARK: - PRF Extension

extension WebAuthn.Extension {
    /// The [PRF (Pseudo-Random Function) extension](https://www.w3.org/TR/webauthn-3/#prf-extension)
    /// for deriving symmetric keys.
    ///
    /// This WebAuthn extension wraps the CTAP2 hmac-secret extension, transforming
    /// PRF secrets into hmac-secret salts using `SHA-256("WebAuthn PRF\0" + secret)`.
    ///
    /// ## Simple Usage (single credential)
    ///
    /// ```swift
    /// let prf = try await WebAuthn.Extension.PRF(session: session)
    /// let ext = try prf.getAssertion.input(first: userSecret)
    /// let params = CTAP2.GetAssertion.Parameters(..., extensions: [ext])
    /// let response = try await session.getAssertion(parameters: params)
    /// if let secrets = try prf.getAssertion.output(from: response) {
    ///     // Use derived keys
    /// }
    /// ```
    ///
    /// ## Multi-credential Usage (evalByCredential)
    ///
    /// ```swift
    /// let prf = try await WebAuthn.Extension.PRF(
    ///     first: defaultSecret,
    ///     evalByCredential: [credIdA: (secretA, nil), credIdB: (secretB, nil)],
    ///     session: session
    /// )
    ///
    /// // After credential selection:
    /// let ext = try prf.getAssertion.input(for: selectedCredentialId)
    /// let params = CTAP2.GetAssertion.Parameters(..., extensions: [ext])
    /// let response = try await session.getAssertion(parameters: params)
    /// if let secrets = try prf.getAssertion.output(from: response) {
    ///     // Use derived keys
    /// }
    /// ```
    public struct PRF: Sendable {
        /// The underlying hmac-secret extension.
        private let hmacSecret: CTAP2.Extension.HmacSecret

        /// Default PRF secrets when credential not in evalByCredential.
        private let defaultSecrets: (first: Data, second: Data?)?

        /// Per-credential PRF secrets keyed by credential ID.
        private let evalByCredential: [Data: (first: Data, second: Data?)]

        // MARK: - Initializers

        /// Creates a PRF extension for simple single-credential usage.
        ///
        /// - Parameter session: The CTAP2 session to use for key agreement.
        public init(
            session: CTAP2.Session
        ) async throws(CTAP2.SessionError) {
            self.hmacSecret = try await CTAP2.Extension.HmacSecret(session: session)
            self.defaultSecrets = nil
            self.evalByCredential = [:]
        }

        /// Creates a PRF extension with default secrets and optional per-credential overrides.
        ///
        /// - Parameters:
        ///   - first: Default first PRF secret when credential not in evalByCredential.
        ///   - second: Default second PRF secret.
        ///   - evalByCredential: Per-credential PRF secrets keyed by credential ID.
        ///   - session: The CTAP2 session to use for key agreement.
        public init(
            first: Data,
            second: Data? = nil,
            evalByCredential: [Data: (first: Data, second: Data?)] = [:],
            session: CTAP2.Session
        ) async throws(CTAP2.SessionError) {
            self.hmacSecret = try await CTAP2.Extension.HmacSecret(session: session)
            self.defaultSecrets = (first, second)
            self.evalByCredential = evalByCredential
        }

        /// Creates a PRF extension with only per-credential secrets (no default fallback).
        ///
        /// Use this when `evalByCredential` is provided without `eval`. If the selected
        /// credential is not in `evalByCredential`, `getAssertion.input(for:)` will throw.
        ///
        /// - Parameters:
        ///   - evalByCredential: Per-credential PRF secrets keyed by credential ID.
        ///   - session: The CTAP2 session to use for key agreement.
        public init(
            evalByCredential: [Data: (first: Data, second: Data?)],
            session: CTAP2.Session
        ) async throws(CTAP2.SessionError) {
            self.hmacSecret = try await CTAP2.Extension.HmacSecret(session: session)
            self.defaultSecrets = nil
            self.evalByCredential = evalByCredential
        }

        // MARK: - Operations

        /// Operations for MakeCredential.
        public var makeCredential: MakeCredentialOperations {
            MakeCredentialOperations(parent: self)
        }

        /// Operations for GetAssertion.
        public var getAssertion: GetAssertionOperations {
            GetAssertionOperations(parent: self)
        }

        // MARK: - Salt Transformation

        /// Transforms a PRF secret into an hmac-secret salt.
        ///
        /// The transformation is: `SHA-256("WebAuthn PRF\0" + secret)`
        ///
        /// - Parameter secret: The PRF secret (any length).
        /// - Returns: A 32-byte salt for hmac-secret.
        public static func salt(_ secret: Data) -> Data {
            var data = Data("WebAuthn PRF".utf8)
            data.append(0x00)
            data.append(secret)
            return data.sha256()
        }
    }
}

// MARK: - MakeCredential Operations

extension WebAuthn.Extension.PRF {
    /// MakeCredential operations for PRF.
    public struct MakeCredentialOperations: Sendable {
        fileprivate let parent: WebAuthn.Extension.PRF

        /// Creates a MakeCredential input to enable PRF.
        ///
        /// Use this when you only need to enable PRF at registration without
        /// deriving secrets immediately.
        ///
        /// - Returns: A MakeCredential extension input.
        public func input() -> CTAP2.Extension.MakeCredential.Input {
            parent.hmacSecret.makeCredential.input()
        }

        /// Creates a MakeCredential input with PRF secrets for hmac-secret-mc.
        ///
        /// If the authenticator supports hmac-secret-mc, secrets will be derived
        /// during registration using the PRF salt transformation. Otherwise,
        /// this just enables PRF/hmac-secret.
        ///
        /// - Parameters:
        ///   - first: First PRF secret (any length).
        ///   - second: Optional second PRF secret (any length).
        /// - Returns: A MakeCredential extension input.
        public func input(
            first: Data,
            second: Data? = nil
        ) throws(CTAP2.SessionError) -> CTAP2.Extension.MakeCredential.Input {
            try parent.hmacSecret.makeCredential.input(
                salt1: WebAuthn.Extension.PRF.salt(first),
                salt2: second.map { WebAuthn.Extension.PRF.salt($0) }
            )
        }

        /// Extracts the PRF output from a MakeCredential response.
        ///
        /// - Parameter response: The MakeCredential response from the authenticator.
        /// - Returns: `.enabled` if PRF is supported, `.secrets` if hmac-secret-mc
        ///            returned derived secrets, or `nil` if the extension output is not present.
        public func output(
            from response: CTAP2.MakeCredential.Response
        ) throws(CTAP2.SessionError) -> Result? {
            try parent.hmacSecret.makeCredential.output(from: response)
        }

        /// Result type for PRF MakeCredential extension.
        public typealias Result = CTAP2.Extension.HmacSecret.MakeCredentialOperations.Result
    }
}

// MARK: - GetAssertion Operations

extension WebAuthn.Extension.PRF {
    /// GetAssertion operations for PRF.
    public struct GetAssertionOperations: Sendable {
        fileprivate let parent: WebAuthn.Extension.PRF

        /// Creates a GetAssertion input with PRF secrets.
        ///
        /// - Parameters:
        ///   - first: First PRF secret (any length).
        ///   - second: Optional second PRF secret (any length).
        /// - Returns: A GetAssertion extension input.
        public func input(
            first: Data,
            second: Data? = nil
        ) throws(CTAP2.SessionError) -> CTAP2.Extension.GetAssertion.Input {
            try parent.hmacSecret.getAssertion.input(
                salt1: WebAuthn.Extension.PRF.salt(first),
                salt2: second.map { WebAuthn.Extension.PRF.salt($0) }
            )
        }

        /// Creates a GetAssertion input for a specific credential (evalByCredential).
        ///
        /// Uses the credential-specific secrets if available, otherwise falls back
        /// to the default secrets. Returns `nil` if neither is available, allowing
        /// the assertion to continue without PRF output (matching WebAuthn spec behavior).
        ///
        /// - Parameter credentialId: The credential ID to look up secrets for,
        ///                           or nil to use default secrets.
        /// - Returns: A GetAssertion extension input, or `nil` if no secrets are configured
        ///            for this credential.
        public func input(
            for credentialId: Data?
        ) throws(CTAP2.SessionError) -> CTAP2.Extension.GetAssertion.Input? {
            let secrets = credentialId.flatMap { parent.evalByCredential[$0] } ?? parent.defaultSecrets

            guard let secrets else {
                // No matching credential in evalByCredential and no default eval.
                // Skip PRF silently and continue assertion (matches python-fido2/YubiKit Android).
                return nil
            }

            return try input(first: secrets.first, second: secrets.second)
        }

        /// Extracts and decrypts the PRF output from a GetAssertion response.
        ///
        /// - Parameter response: The GetAssertion response from the authenticator.
        /// - Returns: The derived secrets, or nil if the extension output is not present.
        public func output(
            from response: CTAP2.GetAssertion.Response
        ) throws(CTAP2.SessionError) -> Secrets? {
            try parent.hmacSecret.getAssertion.output(from: response)
        }
    }

    /// Derived PRF secrets returned from a GetAssertion ceremony.
    public typealias Secrets = CTAP2.Extension.HmacSecret.Secrets
}

// MARK: - WebAuthn Client Input/Output Types

extension WebAuthn.Extension.PRF {

    /// PRF evaluation secrets (first and optional second).
    public struct Eval: Sendable, Equatable {
        public let first: Data
        public let second: Data?

        public init(first: Data, second: Data? = nil) {
            self.first = first
            self.second = second
        }
    }

    /// Namespace for PRF registration types.
    public enum Registration {
        /// Input for PRF extension at registration.
        ///
        /// Use `.enable` to enable PRF without deriving secrets, or `.eval(first:second:)`
        /// to derive secrets at registration (requires hmac-secret-mc support).
        public struct Input: Sendable, Equatable {
            /// Secrets to derive at registration (hmac-secret-mc).
            public let eval: Eval?

            init(eval: Eval?) {
                self.eval = eval
            }

            /// Enable PRF without deriving secrets at registration.
            public static var enable: Input { .init(eval: nil) }

            /// Derive secrets at registration (requires hmac-secret-mc support).
            ///
            /// - Parameters:
            ///   - first: First PRF secret (any length).
            ///   - second: Optional second PRF secret (any length).
            public static func eval(first: Data, second: Data? = nil) -> Input {
                .init(eval: .init(first: first, second: second))
            }
        }

        /// Output from PRF extension at registration.
        public struct Output: Sendable, Equatable {
            /// Whether PRF is enabled for this credential.
            public let enabled: Bool

            /// Derived secrets from hmac-secret-mc (if supported).
            public let results: Results?

            public init(enabled: Bool, results: Results? = nil) {
                self.enabled = enabled
                self.results = results
            }

            internal init(ctapResult: CTAP2.Extension.HmacSecret.MakeCredentialOperations.Result) {
                switch ctapResult {
                case .enabled:
                    self.enabled = true
                    self.results = nil
                case .secrets(let secrets):
                    self.enabled = true
                    self.results = Results(first: secrets.first, second: secrets.second)
                }
            }
        }
    }

    /// Namespace for PRF authentication types.
    public enum Authentication {
        /// Input for PRF extension at authentication.
        ///
        /// Use `.eval(first:second:)` to derive secrets for all credentials, or provide
        /// `evalByCredential` to use different secrets per credential.
        public struct Input: Sendable, Equatable {
            /// Default secrets for all credentials.
            public let eval: Eval?
            /// Per-credential secrets keyed by credential ID.
            public let evalByCredential: [Data: Eval]

            /// Derive secrets using the same values for all credentials.
            ///
            /// - Parameters:
            ///   - first: First PRF secret (any length).
            ///   - second: Optional second PRF secret (any length).
            public static func eval(first: Data, second: Data? = nil) -> Input {
                .init(eval: .init(first: first, second: second), evalByCredential: [:])
            }

            public init(
                eval: Eval? = nil,
                evalByCredential: [Data: Eval] = [:]
            ) {
                self.eval = eval
                self.evalByCredential = evalByCredential
            }
        }

        /// Output from PRF extension at authentication.
        public struct Output: Sendable, Equatable {
            /// The derived PRF secrets.
            public let results: Results

            public init(results: Results) {
                self.results = results
            }

            internal init(ctapSecrets: CTAP2.Extension.HmacSecret.Secrets) {
                self.results = Results(first: ctapSecrets.first, second: ctapSecrets.second)
            }
        }
    }

    /// Derived PRF secrets (first and optional second).
    public struct Results: Sendable, Equatable {
        /// First derived secret (32 bytes).
        public let first: Data

        /// Second derived secret (32 bytes), if second secret was provided.
        public let second: Data?

        public init(first: Data, second: Data? = nil) {
            self.first = first
            self.second = second
        }
    }
}

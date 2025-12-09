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

import CryptoKit
import Foundation

// MARK: - WebAuthn Extension Namespace

extension WebAuthn {
    /// Namespace for WebAuthn extensions.
    enum Extension {}
}

// MARK: - PRF Extension

extension WebAuthn.Extension {
    /// The PRF (Pseudo-Random Function) extension for deriving symmetric keys.
    ///
    /// This WebAuthn extension wraps the CTAP2 hmac-secret extension, transforming
    /// PRF secrets into hmac-secret salts using `SHA-256("WebAuthn PRF\0" + secret)`.
    ///
    /// ## Simple Usage (single credential)
    ///
    /// ```swift
    /// let ext = try await WebAuthn.Extension.PRF.getAssertion(
    ///     first: userSecret,
    ///     session: session
    /// )
    /// let params = CTAP2.GetAssertion.Parameters(..., extensions: [ext])
    /// let response = try await session.getAssertion(parameters: params)
    /// if let (output1, output2) = try ext.result(from: response) {
    ///     // Use derived keys
    /// }
    /// ```
    ///
    /// ## Multi-credential Usage (evalByCredential)
    ///
    /// ```swift
    /// let processor = try await WebAuthn.Extension.PRF.processor(
    ///     first: defaultSecret,
    ///     evalByCredential: [credIdA: (secretA, nil), credIdB: (secretB, nil)],
    ///     session: session
    /// )
    ///
    /// // After credential selection:
    /// let ext = try processor.makeExtension(for: selectedCredentialId)
    /// let params = CTAP2.GetAssertion.Parameters(..., extensions: [ext])
    /// let response = try await session.getAssertion(parameters: params)
    /// if let (output1, output2) = try processor.result(from: response) {
    ///     // Use derived keys
    /// }
    /// ```
    ///
    /// - SeeAlso: [WebAuthn PRF Extension](https://www.w3.org/TR/webauthn-3/#prf-extension)
    enum PRF {
        /// Derive secrets during authentication using PRF.
        ///
        /// This transforms the PRF secrets to hmac-secret salts and performs key agreement.
        ///
        /// - Parameters:
        ///   - first: First PRF secret (any length).
        ///   - second: Optional second PRF secret (any length).
        ///   - session: The CTAP2 session to use for key agreement.
        /// - Returns: A GetAssertion extension ready to be included in the request.
        static func getAssertion<I: CBORInterface>(
            first: Data,
            second: Data? = nil,
            session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> CTAP2.Extension.HmacSecret.GetAssertion
        where I.Error == CTAP2.SessionError {
            try await CTAP2.Extension.HmacSecret.getAssertion(
                salt1: prfSalt(first),
                salt2: second.map { prfSalt($0) },
                session: session
            )
        }

        /// Create a processor for deriving secrets with per-credential secret selection.
        ///
        /// Use this when you have multiple credentials in the allowList and need
        /// different PRF secrets for each credential (evalByCredential).
        ///
        /// - Parameters:
        ///   - first: Default first PRF secret when credential not in evalByCredential.
        ///   - second: Default second PRF secret.
        ///   - evalByCredential: Per-credential PRF secrets keyed by credential ID.
        ///   - session: The CTAP2 session to use for key agreement.
        /// - Returns: A processor that can generate extensions for any credential.
        static func processor<I: CBORInterface>(
            first: Data,
            second: Data? = nil,
            evalByCredential: [Data: (first: Data, second: Data?)] = [:],
            session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> Processor where I.Error == CTAP2.SessionError {
            try await Processor.create(
                first: first,
                second: second,
                evalByCredential: evalByCredential,
                session: session
            )
        }

        /// Transforms a PRF secret into an hmac-secret salt.
        ///
        /// The transformation is: `SHA-256("WebAuthn PRF\0" + secret)`
        ///
        /// - Parameter secret: The PRF secret (any length).
        /// - Returns: A 32-byte salt for hmac-secret.
        static func prfSalt(_ secret: Data) -> Data {
            var sha = SHA256()
            sha.update(data: Data("WebAuthn PRF".utf8))
            sha.update(data: [0x00])
            sha.update(data: secret)
            return Data(sha.finalize())
        }
    }
}

// MARK: - PRF Processor

extension WebAuthn.Extension.PRF {
    /// Processor for PRF with per-credential secret selection (evalByCredential).
    ///
    /// The processor performs key agreement at creation time but defers salt
    /// encryption until a credential is selected via ``makeExtension(for:)``.
    struct Processor: Sendable {
        /// Shared secret state for encryption/decryption.
        private let sharedSecret: CTAP2.Extension.HmacSecret.SharedSecret

        /// Default PRF secrets when credential not in evalByCredential.
        private let defaultSecrets: (first: Data, second: Data?)

        /// Per-credential PRF secrets keyed by credential ID.
        private let evalByCredential: [Data: (first: Data, second: Data?)]

        static func create<I: CBORInterface>(
            first: Data,
            second: Data? = nil,
            evalByCredential: [Data: (first: Data, second: Data?)] = [:],
            session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> Processor where I.Error == CTAP2.SessionError {
            let sharedSecret = try await CTAP2.Extension.HmacSecret.SharedSecret.create(
                session: session
            )

            return Processor(
                sharedSecret: sharedSecret,
                defaultSecrets: (first, second),
                evalByCredential: evalByCredential
            )
        }

        /// Creates a GetAssertion extension with PRF secrets for the specified credential.
        ///
        /// - Parameter credentialId: The credential ID to look up secrets for,
        ///                           or nil to use default secrets.
        /// - Returns: A GetAssertion extension ready to be included in the request.
        func makeExtension(
            for credentialId: Data?
        ) throws(CTAP2.SessionError) -> CTAP2.Extension.HmacSecret.GetAssertion {
            let secrets = credentialId.flatMap { evalByCredential[$0] } ?? defaultSecrets

            let salt1 = WebAuthn.Extension.PRF.prfSalt(secrets.first)
            let salt2 = secrets.second.map { WebAuthn.Extension.PRF.prfSalt($0) }

            return try CTAP2.Extension.HmacSecret.getAssertion(
                salt1: salt1,
                salt2: salt2,
                sharedSecret: sharedSecret
            )
        }

        /// Extracts and decrypts the PRF output from a GetAssertion response.
        ///
        /// - Parameter response: The GetAssertion response from the authenticator.
        /// - Returns: A tuple of (output1, output2) where output2 is nil if second was not provided,
        ///            or nil if the extension output is not present.
        func result(
            from response: CTAP2.GetAssertion.Response
        ) throws(CTAP2.SessionError) -> (output1: Data, output2: Data?)? {
            guard
                let ciphertext = response.authenticatorData.extensions?[
                    CTAP2.Extension.HmacSecret.name
                ]?.dataValue
            else {
                return nil
            }
            return try CTAP2.Extension.HmacSecret.decryptOutputs(
                ciphertext: ciphertext,
                using: sharedSecret
            )
        }
    }
}

// MARK: - HmacSecret Extension for PRF

extension CTAP2.Extension.HmacSecret {
    /// Creates a GetAssertion extension using an existing shared secret.
    ///
    /// Used by WebAuthn PRF for evalByCredential where key agreement
    /// happens once but salts are selected per-credential.
    ///
    /// - Parameters:
    ///   - salt1: First salt (must be exactly 32 bytes).
    ///   - salt2: Optional second salt (must be exactly 32 bytes if provided).
    ///   - sharedSecret: Pre-established shared secret from key agreement.
    /// - Returns: A GetAssertion extension ready to be included in the request.
    static func getAssertion(
        salt1: Data,
        salt2: Data? = nil,
        sharedSecret: SharedSecret
    ) throws(CTAP2.SessionError) -> GetAssertion {
        try validateSalts(salt1: salt1, salt2: salt2)
        let saltsData = salt2.map { salt1 + $0 } ?? salt1
        let (saltEnc, saltAuth) = try sharedSecret.encrypt(salts: saltsData)
        return GetAssertion(sharedSecret: sharedSecret, saltEnc: saltEnc, saltAuth: saltAuth)
    }
}

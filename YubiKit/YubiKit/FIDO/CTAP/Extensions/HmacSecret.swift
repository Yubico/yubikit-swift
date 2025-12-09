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

// MARK: - HmacSecret Extension

extension CTAP2.Extension {
    /// The hmac-secret extension for deriving symmetric keys from credentials.
    ///
    /// This extension allows a relying party to derive symmetric keys from a credential
    /// using HMAC-SHA-256 with user-provided salts. The derived keys can be used for
    /// encryption or other cryptographic operations.
    ///
    /// ## MakeCredential Usage
    ///
    /// Request hmac-secret support when creating a credential:
    /// ```swift
    /// let ext = CTAP2.Extension.HmacSecret.makeCredential()
    /// let params = CTAP2.MakeCredential.Parameters(..., extensions: [ext])
    /// let response = try await session.makeCredential(params)
    /// ```
    ///
    /// Or derive secrets at registration time (CTAP 2.2 hmac-secret-mc).
    /// If the authenticator supports hmac-secret-mc, secrets will be derived;
    /// otherwise it falls back to just enabling hmac-secret:
    /// ```swift
    /// let ext = try await CTAP2.Extension.HmacSecret.makeCredential(
    ///     salt1: salt,
    ///     session: session
    /// )
    /// let params = CTAP2.MakeCredential.Parameters(..., extensions: [ext])
    /// let response = try await session.makeCredential(params)
    /// if let result = try ext.result(from: response) {
    ///     switch result {
    ///     case .enabled(let enabled):
    ///         // hmac-secret-mc not supported, but hmac-secret is enabled
    ///     case .secrets(let output1, let output2):
    ///         // Use derived keys
    ///     }
    /// }
    /// ```
    ///
    /// ## GetAssertion Usage
    ///
    /// Derive keys during authentication:
    /// ```swift
    /// let ext = try await CTAP2.Extension.HmacSecret.getAssertion(
    ///     salt1: salt,
    ///     session: session
    /// )
    /// let params = CTAP2.GetAssertion.Parameters(..., extensions: [ext])
    /// let response = try await session.getAssertion(params)
    /// if let (output1, output2) = try ext.result(from: response) {
    ///     // Use derived keys
    /// }
    /// ```
    ///
    /// - SeeAlso: [CTAP2 hmac-secret Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-extension)
    /// - SeeAlso: [CTAP2.2 hmac-secret-mc Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-make-cred-extension)
    enum HmacSecret {
        /// Encrypted salts with authentication tag.
        typealias EncryptedSalts = (enc: Data, auth: Data)

        /// Salt length required by hmac-secret (32 bytes).
        static let saltLength = 32

        /// The extension identifier for hmac-secret.
        static let identifier: CTAP2.Extension.Identifier = .hmacSecret

        /// The extension identifier for hmac-secret-mc (CTAP 2.2).
        static let mcIdentifier: CTAP2.Extension.Identifier = .hmacSecretMC

        /// Checks if the authenticator supports hmac-secret.
        ///
        /// - Parameter session: The CTAP2 session to check.
        /// - Returns: `true` if the authenticator supports hmac-secret.
        static func isSupported<I: CBORInterface>(
            by session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> Bool where I.Error == CTAP2.SessionError {
            let info = try await session.getInfo()
            return info.extensions.contains(identifier)
        }

        // MARK: - MakeCredential Helpers

        /// Request hmac-secret support for a new credential.
        ///
        /// - Returns: A MakeCredential extension that enables hmac-secret.
        static func makeCredential() -> MakeCredential {
            MakeCredential()
        }

        /// Request hmac-secret support, optionally deriving secrets at registration (CTAP 2.2).
        ///
        /// If salts are provided and the authenticator supports hmac-secret-mc,
        /// secrets will be derived during registration. Otherwise, it just enables
        /// hmac-secret for later use with GetAssertion.
        ///
        /// - Parameters:
        ///   - salt1: First salt for hmac-secret-mc (must be exactly 32 bytes).
        ///   - salt2: Optional second salt (must be exactly 32 bytes if provided).
        ///   - session: The CTAP2 session to use.
        /// - Returns: A MakeCredential extension, upgraded to hmac-secret-mc if possible.
        static func makeCredential<I: CBORInterface>(
            salt1: Data,
            salt2: Data? = nil,
            session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> MakeCredential where I.Error == CTAP2.SessionError {
            try await MakeCredential.create(salt1: salt1, salt2: salt2, session: session)
        }

        // MARK: - GetAssertion Helpers

        /// Derive secrets during authentication.
        ///
        /// This method performs ECDH key agreement with the authenticator and encrypts
        /// the provided salts. Use this for simple single-credential scenarios.
        ///
        /// For multi-credential scenarios with per-credential salts, use
        /// ``processor(salt1:salt2:saltsByCredential:session:)`` instead.
        ///
        /// - Parameters:
        ///   - salt1: First salt (must be exactly 32 bytes).
        ///   - salt2: Optional second salt (must be exactly 32 bytes if provided).
        ///   - session: The CTAP2 session to use for key agreement.
        /// - Returns: A GetAssertion extension ready to be included in the request.
        static func getAssertion<I: CBORInterface>(
            salt1: Data,
            salt2: Data? = nil,
            session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> GetAssertion where I.Error == CTAP2.SessionError {
            try await GetAssertion.create(salt1: salt1, salt2: salt2, session: session)
        }

        // MARK: - Internal Helpers

        /// Fetches the authenticator's public key for ECDH key agreement.
        static func getKeyAgreement<I: CBORInterface>(
            session: CTAP2.Session<I>,
            protocol pinProtocol: CTAP2.ClientPin.ProtocolVersion
        ) async throws(CTAP2.SessionError) -> COSE.Key where I.Error == CTAP2.SessionError {
            let params = CTAP2.ClientPin.GetKeyAgreement.Parameters(pinUVAuthProtocol: pinProtocol)
            let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetKeyAgreement.Response> =
                await session.interface.send(
                    command: .clientPin,
                    payload: params
                )
            return try await stream.value.keyAgreement
        }
    }
}

// MARK: - MakeCredential Extension

extension CTAP2.Extension.HmacSecret {
    /// hmac-secret extension parameters for MakeCredential.
    ///
    /// Create instances using ``CTAP2/Extension/HmacSecret/makeCredential()`` or
    /// ``CTAP2/Extension/HmacSecret/makeCredential(salt1:salt2:session:)``.
    struct MakeCredential: CTAP2.Extension.MakeCredential.Parameters,
        CTAP2.Extension.MakeCredential.Response
    {
        static let identifier = CTAP2.Extension.HmacSecret.identifier

        /// Shared secret state for hmac-secret-mc, or nil for simple hmac-secret enable.
        private let sharedSecret: SharedSecret?

        /// Encrypted salts for hmac-secret-mc.
        private let salts: EncryptedSalts?

        fileprivate init(
            sharedSecret: SharedSecret? = nil,
            salts: EncryptedSalts? = nil
        ) {
            self.sharedSecret = sharedSecret
            self.salts = salts
        }

        fileprivate static func create<I: CBORInterface>(
            salt1: Data? = nil,
            salt2: Data? = nil,
            session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> MakeCredential where I.Error == CTAP2.SessionError {
            // If no salts provided, just enable hmac-secret
            guard let salt1 else {
                return MakeCredential()
            }

            // Check if authenticator supports hmac-secret-mc
            let info = try await session.getInfo()
            guard info.extensions.contains(CTAP2.Extension.HmacSecret.mcIdentifier) else {
                return MakeCredential()
            }

            // Auto-upgrade to hmac-secret-mc
            try CTAP2.Extension.HmacSecret.validateSalts(salt1: salt1, salt2: salt2)
            let sharedSecret = try await SharedSecret.create(session: session)
            let saltsData = salt2.map { salt1 + $0 } ?? salt1
            let salts = try sharedSecret.encrypt(salts: saltsData)

            return MakeCredential(sharedSecret: sharedSecret, salts: salts)
        }

        func asExtensionInputs() -> [CTAP2.Extension.Identifier: CBOR.Value] {
            if let sharedSecret, let salts {
                return [
                    CTAP2.Extension.HmacSecret.identifier: .boolean(true),
                    CTAP2.Extension.HmacSecret.mcIdentifier: .map([
                        .int(1): sharedSecret.keyAgreement.cbor(),
                        .int(2): .byteString(salts.enc),
                        .int(3): .byteString(salts.auth),
                        .int(4): .int(sharedSecret.protocolVersion.rawValue),
                    ]),
                ]
            } else {
                return [CTAP2.Extension.HmacSecret.identifier: .boolean(true)]
            }
        }

        /// Extracts the hmac-secret or hmac-secret-mc output from a MakeCredential response.
        ///
        /// - Parameter response: The MakeCredential response from the authenticator.
        /// - Returns: If secrets were requested: derived secrets from hmac-secret-mc.
        ///            Otherwise: a Bool indicating if hmac-secret is enabled.
        ///            Returns nil if the extension output is not present.
        func result(
            from response: CTAP2.MakeCredential.Response
        ) throws(CTAP2.SessionError) -> Result? {
            if let sharedSecret {
                guard
                    let ciphertext = response.authenticatorData.extensions?[
                        CTAP2.Extension.HmacSecret.mcIdentifier
                    ]?.dataValue
                else {
                    return nil
                }
                let decrypted = try sharedSecret.decrypt(ciphertext: ciphertext)
                let (output1, output2) = try Self.parseSecrets(from: decrypted)
                return .secrets(output1: output1, output2: output2)
            } else {
                guard let value = response.authenticatorData.extensions?[Self.identifier] else {
                    return nil
                }
                guard let enabled = value.boolValue else {
                    throw .responseParseError(
                        "hmac-secret extension output must be boolean",
                        source: .here()
                    )
                }
                return .enabled(enabled)
            }
        }

        private static func parseSecrets(
            from decrypted: Data
        ) throws(CTAP2.SessionError) -> (output1: Data, output2: Data?) {
            guard decrypted.count >= CTAP2.Extension.HmacSecret.saltLength else {
                throw .responseParseError(
                    "hmac-secret-mc output too short: expected at least \(CTAP2.Extension.HmacSecret.saltLength) bytes",
                    source: .here()
                )
            }

            let output1 = Data(decrypted.prefix(CTAP2.Extension.HmacSecret.saltLength))
            let output2: Data? =
                if decrypted.count >= CTAP2.Extension.HmacSecret.saltLength * 2 {
                    Data(
                        decrypted.dropFirst(CTAP2.Extension.HmacSecret.saltLength).prefix(
                            CTAP2.Extension.HmacSecret.saltLength
                        )
                    )
                } else {
                    nil
                }

            return (output1, output2)
        }

        /// Result type for hmac-secret MakeCredential extension.
        enum Result {
            /// hmac-secret is enabled for this credential.
            case enabled(Bool)

            /// Derived secrets from hmac-secret-mc.
            case secrets(output1: Data, output2: Data?)
        }
    }
}

// MARK: - Shared Secret State

extension CTAP2.Extension.HmacSecret {
    /// Shared cryptographic state for hmac-secret operations.
    ///
    /// This holds the ECDH key agreement result and provides encryption/decryption
    /// for hmac-secret salt exchange.
    struct SharedSecret: Sendable {
        /// Client's COSE public key for ECDH.
        let keyAgreement: COSE.Key

        /// The derived shared secret.
        private let secret: Data

        /// PIN/UV auth protocol version.
        let protocolVersion: CTAP2.ClientPin.ProtocolVersion

        static func create<I: CBORInterface>(
            session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> SharedSecret where I.Error == CTAP2.SessionError {
            let pinProtocol = try await session.preferredClientPinProtocol
            let authenticatorKey = try await CTAP2.Extension.HmacSecret.getKeyAgreement(
                session: session,
                protocol: pinProtocol
            )

            let keyPair = P256.KeyAgreement.PrivateKey()
            let sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
            let clientKey = pinProtocol.coseKey(from: keyPair)

            return SharedSecret(
                keyAgreement: clientKey,
                secret: sharedSecret,
                protocolVersion: pinProtocol
            )
        }

        func encrypt(salts: Data) throws(CTAP2.SessionError) -> EncryptedSalts {
            let enc = try protocolVersion.encrypt(key: secret, plaintext: salts)
            let auth = protocolVersion.authenticate(key: secret, message: enc)
            return (enc, auth)
        }

        func decrypt(ciphertext: Data) throws(CTAP2.SessionError) -> Data {
            try protocolVersion.decrypt(key: secret, ciphertext: ciphertext)
        }
    }
}

// MARK: - GetAssertion Extension

extension CTAP2.Extension.HmacSecret {
    /// hmac-secret extension for GetAssertion.
    ///
    /// Create instances using ``CTAP2/Extension/HmacSecret/getAssertion(salt1:salt2:session:)``.
    ///
    /// For multi-credential scenarios with per-credential salts (WebAuthn PRF evalByCredential),
    /// use ``WebAuthn/Extension/PRF/Processor`` instead.
    struct GetAssertion: CTAP2.Extension.GetAssertion.Parameters,
        CTAP2.Extension.GetAssertion.Response
    {
        static let identifier = CTAP2.Extension.HmacSecret.identifier

        /// Shared secret state for encryption/decryption.
        private let sharedSecret: SharedSecret

        /// Encrypted salts.
        private let salts: EncryptedSalts

        /// Creates a GetAssertion extension from a shared secret and salts.
        ///
        /// Used by ``WebAuthn/Extension/PRF/Processor`` for evalByCredential support.
        ///
        /// - Parameters:
        ///   - sharedSecret: Pre-established shared secret from key agreement.
        ///   - salt1: First salt (must be exactly 32 bytes).
        ///   - salt2: Optional second salt (must be exactly 32 bytes if provided).
        init(
            sharedSecret: SharedSecret,
            salt1: Data,
            salt2: Data?
        ) throws(CTAP2.SessionError) {
            try CTAP2.Extension.HmacSecret.validateSalts(salt1: salt1, salt2: salt2)
            let saltsData = salt2.map { salt1 + $0 } ?? salt1

            self.sharedSecret = sharedSecret
            self.salts = try sharedSecret.encrypt(salts: saltsData)
        }

        fileprivate static func create<I: CBORInterface>(
            salt1: Data,
            salt2: Data? = nil,
            session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> GetAssertion where I.Error == CTAP2.SessionError {
            guard try await CTAP2.Extension.HmacSecret.isSupported(by: session) else {
                throw .extensionNotSupported(Self.identifier, source: .here())
            }
            let sharedSecret = try await SharedSecret.create(session: session)
            return try GetAssertion(sharedSecret: sharedSecret, salt1: salt1, salt2: salt2)
        }

        func asExtensionInputs() -> [CTAP2.Extension.Identifier: CBOR.Value] {
            [
                Self.identifier: .map([
                    .int(1): sharedSecret.keyAgreement.cbor(),
                    .int(2): .byteString(salts.enc),
                    .int(3): .byteString(salts.auth),
                    .int(4): .int(sharedSecret.protocolVersion.rawValue),
                ])
            ]
        }

        /// Extracts and decrypts the hmac-secret output from a GetAssertion response.
        ///
        /// - Parameter response: The GetAssertion response from the authenticator.
        /// - Returns: A tuple of (output1, output2) where output2 is nil if salt2 was not provided,
        ///            or nil if the hmac-secret extension was not present in the response.
        func result(
            from response: CTAP2.GetAssertion.Response
        ) throws(CTAP2.SessionError) -> (output1: Data, output2: Data?)? {
            guard let ciphertext = response.authenticatorData.extensions?[Self.identifier]?.dataValue
            else {
                return nil
            }

            let decrypted = try sharedSecret.decrypt(ciphertext: ciphertext)

            guard decrypted.count >= saltLength else {
                throw .responseParseError(
                    "hmac-secret output too short: expected at least \(saltLength) bytes",
                    source: .here()
                )
            }

            let output1 = Data(decrypted.prefix(saltLength))
            let output2: Data? =
                if decrypted.count >= saltLength * 2 {
                    Data(decrypted.dropFirst(saltLength).prefix(saltLength))
                } else {
                    nil
                }

            return (output1, output2)
        }
    }
}

// MARK: - Helpers

extension CTAP2.Extension.HmacSecret {
    /// Validates salt lengths.
    fileprivate static func validateSalts(
        salt1: Data,
        salt2: Data?
    ) throws(CTAP2.SessionError) {
        guard salt1.count == saltLength else {
            throw .illegalArgument(
                "salt1 must be exactly \(saltLength) bytes",
                source: .here()
            )
        }
        if let salt2, salt2.count != saltLength {
            throw .illegalArgument(
                "salt2 must be exactly \(saltLength) bytes",
                source: .here()
            )
        }
    }
}

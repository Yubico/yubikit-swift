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
        static let name = "hmac-secret"
        static let mcName = "hmac-secret-mc"

        /// Salt length required by hmac-secret (32 bytes).
        static let saltLength = 32

        /// Checks if the authenticator supports hmac-secret.
        ///
        /// - Parameter session: The CTAP2 session to check.
        /// - Returns: `true` if the authenticator supports hmac-secret.
        static func isSupported<I: CBORInterface>(
            by session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> Bool where I.Error == CTAP2.SessionError {
            let info = try await session.getInfo()
            return info.extensions.contains(name)
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
        /// the provided salts.
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
        static let name = CTAP2.Extension.HmacSecret.name

        /// Encrypted secrets for hmac-secret-mc, or nil for simple hmac-secret enable.
        private let encryptedSecrets: EncryptedSecrets?

        fileprivate init(encryptedSecrets: EncryptedSecrets? = nil) {
            self.encryptedSecrets = encryptedSecrets
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
            guard info.extensions.contains(mcName) else {
                return MakeCredential()
            }

            // Auto-upgrade to hmac-secret-mc
            let encrypted = try await EncryptedSecrets.create(
                salt1: salt1,
                salt2: salt2,
                session: session
            )
            return MakeCredential(encryptedSecrets: encrypted)
        }

        func asExtensionInputs() -> [String: CBOR.Value] {
            if let encryptedSecrets {
                return [
                    CTAP2.Extension.HmacSecret.name: .boolean(true),
                    CTAP2.Extension.HmacSecret.mcName: encryptedSecrets.cbor(),
                ]
            } else {
                return [CTAP2.Extension.HmacSecret.name: .boolean(true)]
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
            if let encryptedSecrets {
                guard
                    let ciphertext = response.authenticatorData.extensions?[
                        CTAP2.Extension.HmacSecret.mcName
                    ]?.dataValue
                else {
                    return nil
                }
                let (output1, output2) = try encryptedSecrets.decrypt(ciphertext: ciphertext)
                return .secrets(output1: output1, output2: output2)
            } else {
                guard
                    let value = response.authenticatorData.extensions?[
                        CTAP2.Extension.HmacSecret.name
                    ]
                else {
                    return nil
                }
                return .enabled(value.boolValue ?? false)
            }
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

// MARK: - EncryptedSecrets for MakeCredential

extension CTAP2.Extension.HmacSecret.MakeCredential {
    /// Encrypted salts for hmac-secret-mc during MakeCredential.
    struct EncryptedSecrets: Sendable {
        /// Client's COSE public key for ECDH.
        private let keyAgreement: COSE.Key

        /// Encrypted salts (AES-CBC).
        private let saltEnc: Data

        /// HMAC authentication tag over encrypted salts.
        private let saltAuth: Data

        /// PIN/UV auth protocol version.
        private let pinUvAuthProtocol: CTAP2.ClientPin.ProtocolVersion

        /// Shared secret for decrypting the response.
        private let sharedSecret: Data

        static func create<I: CBORInterface>(
            salt1: Data,
            salt2: Data? = nil,
            session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> EncryptedSecrets where I.Error == CTAP2.SessionError {
            guard salt1.count == CTAP2.Extension.HmacSecret.saltLength else {
                throw .illegalArgument(
                    "salt1 must be exactly \(CTAP2.Extension.HmacSecret.saltLength) bytes",
                    source: .here()
                )
            }
            if let salt2, salt2.count != CTAP2.Extension.HmacSecret.saltLength {
                throw .illegalArgument(
                    "salt2 must be exactly \(CTAP2.Extension.HmacSecret.saltLength) bytes",
                    source: .here()
                )
            }

            let pinProtocol = try await session.preferredClientPinProtocol
            let authenticatorKey = try await getKeyAgreement(session: session, protocol: pinProtocol)

            let keyPair = P256.KeyAgreement.PrivateKey()
            let sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
            let clientKey = pinProtocol.coseKey(from: keyPair)

            let saltsData = salt2.map { salt1 + $0 } ?? salt1
            let saltEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: saltsData)
            let saltAuth = pinProtocol.authenticate(key: sharedSecret, message: saltEnc)

            return EncryptedSecrets(
                keyAgreement: clientKey,
                saltEnc: saltEnc,
                saltAuth: saltAuth,
                pinUvAuthProtocol: pinProtocol,
                sharedSecret: sharedSecret
            )
        }

        func cbor() -> CBOR.Value {
            .map([
                .int(1): keyAgreement.cbor(),
                .int(2): .byteString(saltEnc),
                .int(3): .byteString(saltAuth),
                .int(4): .int(pinUvAuthProtocol.rawValue),
            ])
        }

        func decrypt(ciphertext: Data) throws(CTAP2.SessionError) -> (output1: Data, output2: Data?) {
            let decrypted = try pinUvAuthProtocol.decrypt(
                key: sharedSecret,
                ciphertext: ciphertext
            )

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

        private static func getKeyAgreement<I: CBORInterface>(
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

// MARK: - GetAssertion Extension

extension CTAP2.Extension.HmacSecret {
    /// hmac-secret extension for GetAssertion.
    ///
    /// Create instances using ``CTAP2/Extension/HmacSecret/getAssertion(salt1:salt2:session:)``.
    struct GetAssertion: CTAP2.Extension.GetAssertion.Parameters,
        CTAP2.Extension.GetAssertion.Response
    {
        static let name = CTAP2.Extension.HmacSecret.name

        /// Client's COSE public key for ECDH.
        private let keyAgreement: COSE.Key

        /// Encrypted salts (AES-CBC).
        private let saltEnc: Data

        /// HMAC authentication tag over encrypted salts.
        private let saltAuth: Data

        /// PIN/UV auth protocol version.
        private let pinUvAuthProtocol: CTAP2.ClientPin.ProtocolVersion

        /// Shared secret for decrypting the response.
        private let sharedSecret: Data

        fileprivate static func create<I: CBORInterface>(
            salt1: Data,
            salt2: Data? = nil,
            session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> GetAssertion where I.Error == CTAP2.SessionError {
            guard salt1.count == CTAP2.Extension.HmacSecret.saltLength else {
                throw .illegalArgument(
                    "salt1 must be exactly \(CTAP2.Extension.HmacSecret.saltLength) bytes",
                    source: .here()
                )
            }
            if let salt2, salt2.count != CTAP2.Extension.HmacSecret.saltLength {
                throw .illegalArgument(
                    "salt2 must be exactly \(CTAP2.Extension.HmacSecret.saltLength) bytes",
                    source: .here()
                )
            }

            let pinProtocol = try await session.preferredClientPinProtocol
            let authenticatorKey = try await getKeyAgreement(session: session, protocol: pinProtocol)

            let keyPair = P256.KeyAgreement.PrivateKey()
            let sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
            let clientKey = pinProtocol.coseKey(from: keyPair)

            let saltsData = salt2.map { salt1 + $0 } ?? salt1
            let saltEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: saltsData)
            let saltAuth = pinProtocol.authenticate(key: sharedSecret, message: saltEnc)

            return GetAssertion(
                keyAgreement: clientKey,
                saltEnc: saltEnc,
                saltAuth: saltAuth,
                pinUvAuthProtocol: pinProtocol,
                sharedSecret: sharedSecret
            )
        }

        func asExtensionInputs() -> [String: CBOR.Value] {
            [
                CTAP2.Extension.HmacSecret.name: .map([
                    .int(1): keyAgreement.cbor(),
                    .int(2): .byteString(saltEnc),
                    .int(3): .byteString(saltAuth),
                    .int(4): .int(pinUvAuthProtocol.rawValue),
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
            guard
                let ciphertext = response.authenticatorData.extensions?[
                    CTAP2.Extension.HmacSecret.name
                ]?.dataValue
            else {
                return nil
            }
            return try decrypt(ciphertext: ciphertext)
        }

        private func decrypt(ciphertext: Data) throws(CTAP2.SessionError) -> (output1: Data, output2: Data?) {
            let decrypted = try pinUvAuthProtocol.decrypt(
                key: sharedSecret,
                ciphertext: ciphertext
            )

            guard decrypted.count >= CTAP2.Extension.HmacSecret.saltLength else {
                throw .responseParseError(
                    "hmac-secret output too short: expected at least \(CTAP2.Extension.HmacSecret.saltLength) bytes",
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

        private static func getKeyAgreement<I: CBORInterface>(
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

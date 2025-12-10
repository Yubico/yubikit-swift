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
    /// let hmacSecret = CTAP2.Extension.HmacSecret()
    /// let ext = hmacSecret.makeCredential.input()
    /// let params = CTAP2.MakeCredential.Parameters(..., extensions: [ext])
    /// let response = try await session.makeCredential(params)
    /// if let result = try hmacSecret.makeCredential.output(from: response) {
    ///     // hmac-secret is enabled
    /// }
    /// ```
    ///
    /// Or derive secrets at registration time (CTAP 2.2 hmac-secret-mc):
    /// ```swift
    /// let hmacSecret = try await CTAP2.Extension.HmacSecret(session: session)
    /// let ext = try hmacSecret.makeCredential.input(salt1: salt, salt2: salt2)
    /// let params = CTAP2.MakeCredential.Parameters(..., extensions: [ext])
    /// let response = try await session.makeCredential(params)
    /// if let result = try hmacSecret.makeCredential.output(from: response) {
    ///     switch result {
    ///     case .enabled:
    ///         // hmac-secret-mc not supported, but hmac-secret is enabled
    ///     case .secrets(let secrets):
    ///         // Use derived keys (secrets.first, secrets.second)
    ///     }
    /// }
    /// ```
    ///
    /// ## GetAssertion Usage
    ///
    /// Derive keys during authentication:
    /// ```swift
    /// let hmacSecret = try await CTAP2.Extension.HmacSecret(session: session)
    /// let ext = try hmacSecret.getAssertion.input(salt1: salt)
    /// let params = CTAP2.GetAssertion.Parameters(..., extensions: [ext])
    /// let response = try await session.getAssertion(params)
    /// if let secrets = try hmacSecret.getAssertion.output(from: response) {
    ///     // Use derived keys (secrets.first, secrets.second)
    /// }
    /// ```
    ///
    /// - SeeAlso: [CTAP2 hmac-secret Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-extension)
    /// - SeeAlso: [CTAP2.2 hmac-secret-mc Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-make-cred-extension)
    struct HmacSecret: Sendable {
        /// Salt length required by hmac-secret (32 bytes).
        static let saltLength = 32

        /// The extension identifier for hmac-secret.
        static let identifier: Identifier = .hmacSecret

        /// The extension identifier for hmac-secret-mc (CTAP 2.2).
        static let mcIdentifier: Identifier = .hmacSecretMC

        /// Shared secret for encryption/decryption, or nil for simple enable-only mode.
        fileprivate let sharedSecret: SharedSecret?

        /// Whether hmac-secret-mc is supported (for MakeCredential with salts).
        fileprivate let supportsMC: Bool

        // MARK: - Initializers

        /// Creates an HmacSecret extension for simple enable-only mode.
        ///
        /// Use this when you only need to enable hmac-secret at registration
        /// without deriving secrets.
        init() {
            self.sharedSecret = nil
            self.supportsMC = false
        }

        /// Creates an HmacSecret extension with key agreement for encryption.
        ///
        /// Use this when you need to derive secrets (at MakeCredential with
        /// hmac-secret-mc, or at GetAssertion).
        ///
        /// - Parameter session: The CTAP2 session to use for key agreement.
        init<I: CBORInterface>(
            session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) where I.Error == CTAP2.SessionError {
            guard try await Self.isSupported(by: session) else {
                throw .extensionNotSupported(Self.identifier, source: .here())
            }
            let info = try await session.getInfo()
            self.supportsMC = info.extensions.contains(Self.mcIdentifier)
            self.sharedSecret = try await SharedSecret.create(session: session)
        }

        /// Checks if the authenticator supports hmac-secret.
        static func isSupported<I: CBORInterface>(
            by session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> Bool where I.Error == CTAP2.SessionError {
            let info = try await session.getInfo()
            return info.extensions.contains(identifier)
        }

        // MARK: - Operations

        /// Operations for MakeCredential.
        var makeCredential: MakeCredentialOperations {
            MakeCredentialOperations(parent: self)
        }

        /// Operations for GetAssertion.
        var getAssertion: GetAssertionOperations {
            GetAssertionOperations(parent: self)
        }
    }
}

// MARK: - MakeCredential Operations

extension CTAP2.Extension.HmacSecret {
    /// MakeCredential operations for hmac-secret.
    struct MakeCredentialOperations: Sendable {
        fileprivate let parent: CTAP2.Extension.HmacSecret

        /// Creates a MakeCredential input to enable hmac-secret.
        ///
        /// - Returns: An extension input for MakeCredential.
        func input() -> Input {
            Input(encoded: [CTAP2.Extension.HmacSecret.identifier: .boolean(true)])
        }

        /// Creates a MakeCredential input with salts for hmac-secret-mc.
        ///
        /// If the authenticator supports hmac-secret-mc, secrets will be derived
        /// during registration. Otherwise, this just enables hmac-secret.
        ///
        /// - Parameters:
        ///   - salt1: First salt (must be exactly 32 bytes).
        ///   - salt2: Optional second salt (must be exactly 32 bytes if provided).
        /// - Returns: An extension input for MakeCredential.
        func input(salt1: Data, salt2: Data? = nil) throws(CTAP2.SessionError) -> Input {
            guard let sharedSecret = parent.sharedSecret, parent.supportsMC else {
                // Fall back to simple enable
                return input()
            }

            try CTAP2.Extension.HmacSecret.validateSalts(salt1: salt1, salt2: salt2)
            let saltsData = salt2.map { salt1 + $0 } ?? salt1
            let encrypted = try sharedSecret.encrypt(salts: saltsData)

            let encoded: [CTAP2.Extension.Identifier: CBOR.Value] = [
                CTAP2.Extension.HmacSecret.identifier: .boolean(true),
                CTAP2.Extension.HmacSecret.mcIdentifier: .map([
                    .int(1): sharedSecret.keyAgreement.cbor(),
                    .int(2): .byteString(encrypted.enc),
                    .int(3): .byteString(encrypted.auth),
                    .int(4): .int(sharedSecret.protocolVersion.rawValue),
                ]),
            ]

            return Input(encoded: encoded)
        }

        /// Extracts the hmac-secret output from a MakeCredential response.
        ///
        /// - Parameter response: The MakeCredential response from the authenticator.
        /// - Returns: `.enabled` if hmac-secret is supported, `.secrets` if hmac-secret-mc
        ///            returned derived secrets, or `nil` if the extension output is not present.
        func output(from response: CTAP2.MakeCredential.Response) throws(CTAP2.SessionError) -> Result? {
            // Try hmac-secret-mc first if we have shared secret
            if let sharedSecret = parent.sharedSecret {
                let mcIdentifier = CTAP2.Extension.HmacSecret.mcIdentifier
                if let ciphertext = response.authenticatorData.extensions?[mcIdentifier]?.dataValue {
                    let decrypted = try sharedSecret.decrypt(ciphertext: ciphertext)
                    let secrets = try Secrets.parse(from: decrypted)
                    return .secrets(secrets)
                }
            }

            // Fall back to simple hmac-secret boolean
            guard let value = response.authenticatorData.extensions?[CTAP2.Extension.HmacSecret.identifier],
                value.boolValue == true
            else {
                return nil
            }
            return .enabled
        }

        /// Result type for hmac-secret MakeCredential extension.
        enum Result: Sendable {
            /// hmac-secret is enabled for this credential.
            case enabled

            /// Derived secrets from hmac-secret-mc.
            case secrets(Secrets)
        }

        /// Extension input for MakeCredential.
        struct Input: CTAP2.Extension.MakeCredential.Input {
            static let identifier = CTAP2.Extension.HmacSecret.identifier

            private let encoded: [CTAP2.Extension.Identifier: CBOR.Value]

            fileprivate init(encoded: [CTAP2.Extension.Identifier: CBOR.Value]) {
                self.encoded = encoded
            }

            func encode() -> [CTAP2.Extension.Identifier: CBOR.Value] {
                encoded
            }
        }
    }
}

// MARK: - GetAssertion Operations

extension CTAP2.Extension.HmacSecret {
    /// GetAssertion operations for hmac-secret.
    struct GetAssertionOperations: Sendable {
        fileprivate let parent: CTAP2.Extension.HmacSecret

        /// Creates a GetAssertion input with salts for hmac-secret.
        ///
        /// - Parameters:
        ///   - salt1: First salt (must be exactly 32 bytes).
        ///   - salt2: Optional second salt (must be exactly 32 bytes if provided).
        /// - Returns: An extension input for GetAssertion.
        func input(salt1: Data, salt2: Data? = nil) throws(CTAP2.SessionError) -> Input {
            guard let sharedSecret = parent.sharedSecret else {
                throw .illegalArgument(
                    "HmacSecret must be initialized with session for GetAssertion",
                    source: .here()
                )
            }

            try CTAP2.Extension.HmacSecret.validateSalts(salt1: salt1, salt2: salt2)
            let saltsData = salt2.map { salt1 + $0 } ?? salt1
            let encrypted = try sharedSecret.encrypt(salts: saltsData)

            let encoded: [CTAP2.Extension.Identifier: CBOR.Value] = [
                CTAP2.Extension.HmacSecret.identifier: .map([
                    .int(1): sharedSecret.keyAgreement.cbor(),
                    .int(2): .byteString(encrypted.enc),
                    .int(3): .byteString(encrypted.auth),
                    .int(4): .int(sharedSecret.protocolVersion.rawValue),
                ])
            ]

            return Input(encoded: encoded)
        }

        /// Extracts and decrypts the hmac-secret output from a GetAssertion response.
        ///
        /// - Parameter response: The GetAssertion response from the authenticator.
        /// - Returns: The derived secrets, or nil if the extension output is not present.
        func output(from response: CTAP2.GetAssertion.Response) throws(CTAP2.SessionError) -> Secrets? {
            guard let sharedSecret = parent.sharedSecret else {
                throw .illegalArgument(
                    "HmacSecret must be initialized with session for GetAssertion",
                    source: .here()
                )
            }

            let identifier = CTAP2.Extension.HmacSecret.identifier
            guard let ciphertext = response.authenticatorData.extensions?[identifier]?.dataValue else {
                return nil
            }

            let decrypted = try sharedSecret.decrypt(ciphertext: ciphertext)
            return try Secrets.parse(from: decrypted)
        }

        /// Extension input for GetAssertion.
        struct Input: CTAP2.Extension.GetAssertion.Input {
            static let identifier = CTAP2.Extension.HmacSecret.identifier

            private let encoded: [CTAP2.Extension.Identifier: CBOR.Value]

            fileprivate init(encoded: [CTAP2.Extension.Identifier: CBOR.Value]) {
                self.encoded = encoded
            }

            func encode() -> [CTAP2.Extension.Identifier: CBOR.Value] {
                encoded
            }
        }
    }
}

// MARK: - Shared Secret State

extension CTAP2.Extension.HmacSecret {
    /// Shared cryptographic state for hmac-secret operations.
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
            let authenticatorKey = try await getKeyAgreement(session: session, protocol: pinProtocol)

            let keyPair = P256.KeyAgreement.PrivateKey()
            let sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
            let clientKey = pinProtocol.coseKey(from: keyPair)

            return SharedSecret(
                keyAgreement: clientKey,
                secret: sharedSecret,
                protocolVersion: pinProtocol
            )
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

        func encrypt(salts: Data) throws(CTAP2.SessionError) -> (enc: Data, auth: Data) {
            let enc = try protocolVersion.encrypt(key: secret, plaintext: salts)
            let auth = protocolVersion.authenticate(key: secret, message: enc)
            return (enc, auth)
        }

        func decrypt(ciphertext: Data) throws(CTAP2.SessionError) -> Data {
            try protocolVersion.decrypt(key: secret, ciphertext: ciphertext)
        }
    }
}

// MARK: - Secrets

extension CTAP2.Extension.HmacSecret {
    /// Derived secrets from hmac-secret.
    struct Secrets: Sendable, Equatable {
        /// First derived secret (32 bytes).
        let first: Data

        /// Second derived secret (32 bytes), if salt2 was provided.
        let second: Data?
    }
}

extension CTAP2.Extension.HmacSecret.Secrets {
    fileprivate static func parse(
        from decrypted: Data
    ) throws(CTAP2.SessionError) -> CTAP2.Extension.HmacSecret.Secrets {
        let saltLength = CTAP2.Extension.HmacSecret.saltLength
        guard decrypted.count >= saltLength else {
            throw .responseParseError(
                "hmac-secret output too short: expected at least \(saltLength) bytes",
                source: .here()
            )
        }

        let first = Data(decrypted.prefix(saltLength))
        let second: Data? =
            if decrypted.count >= saltLength * 2 {
                Data(decrypted.dropFirst(saltLength).prefix(saltLength))
            } else {
                nil
            }

        return CTAP2.Extension.HmacSecret.Secrets(first: first, second: second)
    }
}

// MARK: - Helpers

extension CTAP2.Extension.HmacSecret {
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

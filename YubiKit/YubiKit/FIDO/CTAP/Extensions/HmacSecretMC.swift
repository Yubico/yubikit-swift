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

// MARK: - HmacSecretMC Extension

extension CTAP2.Extension {
    /// The hmac-secret-mc extension for deriving symmetric keys during credential creation.
    ///
    /// This CTAP2.2 extension allows deriving symmetric secrets at registration time,
    /// rather than waiting until authentication. It uses the same cryptographic
    /// mechanism as hmac-secret but operates during MakeCredential.
    ///
    /// The CTAP2.2 spec requires that `hmac-secret-mc` always be accompanied by `hmac-secret`.
    /// The ``encrypt(salt1:salt2:session:)`` method enforces this at compile time by
    /// returning both extensions as a tuple.
    ///
    /// Usage:
    /// ```swift
    /// // Check if authenticator supports hmac-secret-mc
    /// let info = try await session.getInfo()
    /// guard info.extensions?.contains("hmac-secret-mc") == true else {
    ///     // Fall back to basic hmac-secret at GetAssertion time
    /// }
    ///
    /// // MakeCredential with hmac-secret-mc
    /// let salt = Data(repeating: 0, count: 32)
    /// let (hmacSecret, hmacSecretMC) = try await CTAP2.Extension.HmacSecretMC.encrypt(
    ///     salt1: salt,
    ///     session: session
    /// )
    ///
    /// let params = CTAP2.MakeCredential.Parameters(
    ///     ...,
    ///     extensions: [hmacSecret, hmacSecretMC]
    /// )
    /// let response = try await session.makeCredential(params)
    /// if let (output1, output2) = try hmacSecretMC.result(from: response) {
    ///     // Use derived keys
    /// }
    /// ```
    ///
    /// - SeeAlso: [CTAP2.2 hmac-secret-mc Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-make-cred-extension)
    /// - SeeAlso: ``HmacSecret``
    enum HmacSecretMC: Sendable {
        static let name = "hmac-secret-mc"

        /// Salt length required by hmac-secret-mc (32 bytes).
        static let saltLength = 32

        /// Encrypts salts for the hmac-secret-mc extension during MakeCredential.
        ///
        /// This method performs ECDH key agreement with the authenticator and encrypts
        /// the provided salts. Both the required `hmac-secret` extension and the
        /// `hmac-secret-mc` extension are returned, enforcing the CTAP2.2 requirement
        /// that both be present at compile time.
        ///
        /// - Parameters:
        ///   - salt1: First salt (must be exactly 32 bytes).
        ///   - salt2: Optional second salt (must be exactly 32 bytes if provided).
        ///   - session: The CTAP2 session to use for key agreement.
        /// - Returns: A tuple containing both the required `HmacSecret` extension and the
        ///            `Encrypted` extension. Include both in the MakeCredential extensions array.
        static func encrypt<I: CBORInterface>(
            salt1: Data,
            salt2: Data? = nil,
            session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> (HmacSecret, Encrypted)
        where I.Error == CTAP2.SessionError {
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

            let pinProtocol = try await session.preferredClientPinProtocol
            let authenticatorKey = try await getKeyAgreement(session: session, protocol: pinProtocol)

            let keyPair = P256.KeyAgreement.PrivateKey()
            let sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
            let clientKey = pinProtocol.coseKey(from: keyPair)

            let saltsData = salt2.map { salt1 + $0 } ?? salt1
            let saltEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: saltsData)
            let saltAuth = pinProtocol.authenticate(key: sharedSecret, message: saltEnc)

            let encrypted = Encrypted(
                keyAgreement: clientKey,
                saltEnc: saltEnc,
                saltAuth: saltAuth,
                pinUvAuthProtocol: pinProtocol,
                sharedSecret: sharedSecret
            )
            return (HmacSecret(), encrypted)
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

// MARK: - Encrypted Extension

extension CTAP2.Extension.HmacSecretMC {
    /// An hmac-secret-mc extension with encrypted salts for MakeCredential.
    ///
    /// This type holds the cryptographic state needed to send the extension
    /// and decrypt the response. Create instances using
    /// ``CTAP2/Extension/HmacSecretMC/encrypt(salt1:salt2:session:)``.
    struct Encrypted: CTAP2.Extension.MakeCredential.Parameters,
        CTAP2.Extension.MakeCredential.Response
    {
        static let name = CTAP2.Extension.HmacSecretMC.name

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

        init(
            keyAgreement: COSE.Key,
            saltEnc: Data,
            saltAuth: Data,
            pinUvAuthProtocol: CTAP2.ClientPin.ProtocolVersion,
            sharedSecret: Data
        ) {
            self.keyAgreement = keyAgreement
            self.saltEnc = saltEnc
            self.saltAuth = saltAuth
            self.pinUvAuthProtocol = pinUvAuthProtocol
            self.sharedSecret = sharedSecret
        }

        func cbor() -> CBOR.Value {
            var map: [CBOR.Value: CBOR.Value] = [
                .int(1): keyAgreement.cbor(),
                .int(2): .byteString(saltEnc),
                .int(3): .byteString(saltAuth),
            ]
            // CTAP2.1+ platforms must include this if not protocol v1
            if pinUvAuthProtocol != .v1 {
                map[.int(4)] = .int(pinUvAuthProtocol.rawValue)
            }
            return .map(map)
        }

        /// Extracts and decrypts the hmac-secret-mc output from a MakeCredential response.
        ///
        /// - Parameter response: The MakeCredential response from the authenticator.
        /// - Returns: A tuple of (output1, output2) where output2 is nil if salt2 was not provided,
        ///            or nil if the hmac-secret-mc extension was not present in the response.
        func result(
            from response: CTAP2.MakeCredential.Response
        ) throws(CTAP2.SessionError) -> (output1: Data, output2: Data?)? {
            guard let ciphertext = response.authenticatorData.extensions?[Self.name]?.dataValue else {
                return nil
            }
            return try decrypt(ciphertext: ciphertext)
        }

        /// Decrypts the hmac-secret-mc ciphertext from the authenticator.
        ///
        /// - Parameter ciphertext: The encrypted hmac-secret-mc output bytes.
        /// - Returns: A tuple of (output1, output2) where output2 is nil if salt2 was not provided.
        func decrypt(ciphertext: Data) throws(CTAP2.SessionError) -> (output1: Data, output2: Data?) {
            let decrypted = try pinUvAuthProtocol.decrypt(
                key: sharedSecret,
                ciphertext: ciphertext
            )

            guard decrypted.count >= CTAP2.Extension.HmacSecretMC.saltLength else {
                throw .responseParseError(
                    "hmac-secret-mc output too short: expected at least \(CTAP2.Extension.HmacSecretMC.saltLength) bytes",
                    source: .here()
                )
            }

            let output1 = Data(decrypted.prefix(CTAP2.Extension.HmacSecretMC.saltLength))
            let output2: Data? =
                if decrypted.count >= CTAP2.Extension.HmacSecretMC.saltLength * 2 {
                    Data(
                        decrypted.dropFirst(CTAP2.Extension.HmacSecretMC.saltLength).prefix(
                            CTAP2.Extension.HmacSecretMC.saltLength
                        )
                    )
                } else {
                    nil
                }

            return (output1, output2)
        }
    }
}

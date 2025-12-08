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
    /// Usage:
    /// ```swift
    /// // MakeCredential - request hmac-secret support
    /// let params = CTAP2.MakeCredential.Parameters(..., extensions: [CTAP2.Extension.HmacSecret()])
    /// let response = try await session.makeCredential(params)
    /// // Check if hmac-secret is enabled for this credential
    /// if let enabled = CTAP2.Extension.HmacSecret.result(from: response) {
    ///     print("hmac-secret enabled: \(enabled)")
    /// }
    ///
    /// // GetAssertion - derive keys using salts
    /// let salt = Data(repeating: 0, count: 32)
    /// let hmacExt = try await CTAP2.Extension.HmacSecret.encrypt(
    ///     salt1: salt,
    ///     session: session
    /// )
    /// let params = CTAP2.GetAssertion.Parameters(..., extensions: [hmacExt])
    /// let response = try await session.getAssertion(params)
    /// if let (output1, output2) = try hmacExt.result(from: response) {
    ///     // Use derived keys
    /// }
    /// ```
    ///
    /// - SeeAlso: [CTAP2.2 hmac-secret Extension](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-extension)
    struct HmacSecret: CTAP2.Extension.MakeCredential.Parameters, Sendable {
        static let name = "hmac-secret"

        /// Salt length required by hmac-secret (32 bytes).
        static let saltLength = 32

        /// Creates an hmac-secret extension parameter for MakeCredential.
        ///
        /// Use this to request hmac-secret support when creating a new credential.
        init() {}

        func cbor() -> CBOR.Value {
            .boolean(true)
        }

        /// Extracts the hmac-secret output from a MakeCredential response.
        ///
        /// - Parameter response: The MakeCredential response from the authenticator.
        /// - Returns: Whether hmac-secret is enabled for this credential, or nil if not present.
        static func result(from response: CTAP2.MakeCredential.Response) -> Bool? {
            response.authenticatorData.extensions?[name]?.boolValue
        }

        /// Encrypts salts for the hmac-secret extension during GetAssertion.
        ///
        /// This method performs ECDH key agreement with the authenticator and encrypts
        /// the provided salts. The returned extension can be included in GetAssertion
        /// and used to decrypt the response.
        ///
        /// - Parameters:
        ///   - salt1: First salt (must be exactly 32 bytes).
        ///   - salt2: Optional second salt (must be exactly 32 bytes if provided).
        ///   - session: The CTAP2 session to use for key agreement.
        /// - Returns: An encrypted extension ready to be included in GetAssertion.
        static func encrypt<I: CBORInterface>(
            salt1: Data,
            salt2: Data? = nil,
            session: CTAP2.Session<I>
        ) async throws(CTAP2.SessionError) -> Encrypted where I.Error == CTAP2.SessionError {
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

            return Encrypted(
                keyAgreement: clientKey,
                saltEnc: saltEnc,
                saltAuth: saltAuth,
                pinUvAuthProtocol: pinProtocol,
                sharedSecret: sharedSecret
            )
        }

        private static func getKeyAgreement<I: CBORInterface>(
            session: CTAP2.Session<I>,
            protocol pinProtocol: CTAP2.ClientPin.ProtocolVersion
        ) async throws(CTAP2.SessionError) -> COSE.Key where I.Error == CTAP2.SessionError {
            let params = CTAP2.ClientPin.GetKeyAgreement.Parameters(pinUVAuthProtocol: pinProtocol)
            let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetKeyAgreement.Response> = await session.interface.send(
                command: .clientPin,
                payload: params
            )
            return try await stream.value.keyAgreement
        }
    }
}

// MARK: - Encrypted Extension for GetAssertion

extension CTAP2.Extension.HmacSecret {
    /// An hmac-secret extension with encrypted salts for GetAssertion.
    ///
    /// This type holds the cryptographic state needed to send the extension
    /// and decrypt the response. Create instances using
    /// ``CTAP2/Extension/HmacSecret/encrypt(salt1:salt2:session:)``.
    struct Encrypted: CTAP2.Extension.GetAssertion.Parameters,
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
            if pinUvAuthProtocol != .v1 {
                map[.int(4)] = .int(pinUvAuthProtocol.rawValue)
            }
            return .map(map)
        }

        /// Extracts and decrypts the hmac-secret output from a GetAssertion response.
        ///
        /// - Parameter response: The GetAssertion response from the authenticator.
        /// - Returns: A tuple of (output1, output2) where output2 is nil if salt2 was not provided,
        ///            or nil if the hmac-secret extension was not present in the response.
        func result(
            from response: CTAP2.GetAssertion.Response
        ) throws(CTAP2.SessionError) -> (output1: Data, output2: Data?)? {
            guard let ciphertext = response.authenticatorData.extensions?[Self.name]?.dataValue else {
                return nil
            }
            return try decrypt(ciphertext: ciphertext)
        }

        /// Decrypts the hmac-secret ciphertext from the authenticator.
        ///
        /// - Parameter ciphertext: The encrypted hmac-secret output bytes.
        /// - Returns: A tuple of (output1, output2) where output2 is nil if salt2 was not provided.
        func decrypt(ciphertext: Data) throws(CTAP2.SessionError) -> (output1: Data, output2: Data?) {
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
    }
}

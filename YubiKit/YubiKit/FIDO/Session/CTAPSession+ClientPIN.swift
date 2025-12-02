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

// MARK: - PinToken

extension CTAP2 {
    /// A PIN token obtained from the authenticator for authenticating CTAP operations.
    ///
    /// Use ``ClientPIN/getToken(pin:permissions:rpId:)`` to obtain a token,
    /// then pass it to operations like ``Session/makeCredential(parameters:pinToken:)``
    /// and ``Session/getAssertion(parameters:pinToken:)``.
    struct PinToken: Sendable {
        /// The decrypted PIN token.
        let token: Data

        /// The PIN/UV auth protocol version used to obtain this token.
        let protocolVersion: PinUVAuth.ProtocolVersion

        /// Compute the pinUVAuthParam for a given message.
        ///
        /// - Parameter message: The data to authenticate (typically clientDataHash).
        /// - Returns: The authentication parameter to include in the CTAP request.
        func authenticate(message: Data) -> Data {
            protocolVersion.authenticate(key: token, message: message)
        }
    }
}

// MARK: - Session Factory

extension CTAP2.Session {
    /// Creates a ClientPIN accessor for PIN-related operations.
    ///
    /// - Parameter pinProtocol: The PIN/UV auth protocol version to use.
    ///   If nil, automatically selects the best protocol from device capabilities.
    /// - Returns: A ClientPIN accessor with device capabilities and selected protocol.
    func clientPIN(
        protocol pinProtocol: PinUVAuth.ProtocolVersion? = nil
    ) async throws(CTAP2.SessionError) -> CTAP2.ClientPIN<I> {
        let preferredClientPinProtocol = try await preferredClientPinProtocol
        return CTAP2.ClientPIN(
            interface: interface,
            pinProtocol: pinProtocol ?? preferredClientPinProtocol,
            supportsTokenPermissions: try await supportsTokenPermissions
        )
    }
}

// MARK: - ClientPIN

extension CTAP2 {
    /// Accessor for ClientPIN operations.
    ///
    /// Use ``Session/clientPIN(protocol:)`` to create an instance.
    ///
    /// Example:
    /// ```swift
    /// let pin = try await session.clientPIN()
    /// let token = try await pin.getToken(pin: "1234", permissions: .makeCredential, rpId: "example.com")
    /// ```
    struct ClientPIN<I: CBORInterface>: Sendable where I.Error == CTAP2.SessionError {
        fileprivate let interface: I
        fileprivate let pinProtocol: PinUVAuth.ProtocolVersion
        fileprivate let supportsTokenPermissions: Bool

        /// Get the number of PIN retries remaining.
        ///
        /// - Returns: The number of retries remaining and whether a power cycle is required.
        func getRetries() async throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response {
            let params = CTAP2.ClientPin.GetRetries.Parameters(pinUVAuthProtocol: pinProtocol)
            let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetRetries.Response> = await interface.send(
                command: .clientPin,
                payload: params
            )
            return try await stream.value
        }

        /// Get the number of UV (user verification) retries remaining.
        ///
        /// - Returns: The number of UV retries remaining.
        func getUVRetries() async throws(CTAP2.SessionError) -> Int {
            let params = CTAP2.ClientPin.GetUVRetries.Parameters(pinUVAuthProtocol: pinProtocol)
            let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetUVRetries.Response> = await interface.send(
                command: .clientPin,
                payload: params
            )
            return try await stream.value.retries
        }

        /// Get the authenticator's public key for ECDH key agreement.
        ///
        /// - Returns: The authenticator's COSE key for key agreement.
        func getKeyAgreement() async throws(CTAP2.SessionError) -> COSE.Key {
            let params = CTAP2.ClientPin.GetKeyAgreement.Parameters(pinUVAuthProtocol: pinProtocol)
            let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetKeyAgreement.Response> = await interface.send(
                command: .clientPin,
                payload: params
            )
            return try await stream.value.keyAgreement
        }

        /// Get a PIN token using the provided PIN.
        ///
        /// The returned token can be used to authenticate subsequent CTAP operations
        /// like ``Session/makeCredential(parameters:pinToken:)`` and ``Session/getAssertion(parameters:pinToken:)``.
        ///
        /// This method automatically selects the appropriate CTAP command based on authenticator
        /// capabilities: uses `getPinUVAuthTokenUsingPinWithPermissions` (0x09) if the authenticator
        /// supports `pinUVAuthToken` and permissions are provided, otherwise falls back to
        /// `getPinToken` (0x05).
        ///
        /// - Parameters:
        ///   - pin: The PIN string.
        ///   - permissions: Optional permissions for the token.
        ///   - rpId: Optional relying party ID (required for mc/ga permissions).
        /// - Returns: A PIN token that can be used to authenticate CTAP operations.
        func getToken(
            pin: String,
            permissions: CTAP2.ClientPin.Permission? = nil,
            rpId: String? = nil
        ) async throws(CTAP2.SessionError) -> CTAP2.PinToken {
            let authenticatorKey = try await getKeyAgreement()

            // Generate ephemeral key pair and derive shared secret
            let keyPair = P256.KeyAgreement.PrivateKey()
            let sharedSecret: Data
            do {
                sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
            } catch {
                throw CTAP2.SessionError.authError(error, source: .here())
            }

            // Hash and encrypt PIN
            let normalizedPin = pin.precomposedStringWithCanonicalMapping
            let pinHash = Data(SHA256.hash(data: Data(normalizedPin.utf8)).prefix(16))

            let pinHashEnc: Data
            do {
                pinHashEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: pinHash)
            } catch {
                throw CTAP2.SessionError.authError(error, source: .here())
            }

            let platformKey = pinProtocol.coseKey(from: keyPair)

            // Use 0x09 if supported and permissions provided, otherwise fall back to 0x05
            let response: CTAP2.ClientPin.GetToken.Response
            var params: CBOR.Encodable
            if supportsTokenPermissions, let permissions {
                params = CTAP2.ClientPin.GetTokenWithPermissions.Parameters(
                    pinUVAuthProtocol: pinProtocol,
                    keyAgreement: platformKey,
                    pinHashEnc: pinHashEnc,
                    permissions: permissions,
                    rpId: rpId
                )
            } else {
                params = CTAP2.ClientPin.GetToken.Parameters(
                    pinUVAuthProtocol: pinProtocol,
                    keyAgreement: platformKey,
                    pinHashEnc: pinHashEnc
                )
            }

            let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetToken.Response> = await interface.send(
                command: .clientPin,
                payload: params
            )
            response = try await stream.value

            let pinToken: Data
            do {
                pinToken = try pinProtocol.decrypt(key: sharedSecret, ciphertext: response.pinUVAuthToken)
            } catch {
                throw CTAP2.SessionError.authError(error, source: .here())
            }

            // Validate token size: V1 allows 16 or 32 bytes, V2 requires exactly 32 bytes
            let validSize =
                pinProtocol == .v1 ? (pinToken.count == 16 || pinToken.count == 32) : pinToken.count == 32
            guard validSize else {
                throw CTAP2.SessionError.authError(.invalidTokenSize, source: .here())
            }

            return CTAP2.PinToken(token: pinToken, protocolVersion: pinProtocol)
        }

        /// Set a new PIN on the authenticator (must not already have a PIN).
        ///
        /// - Parameter pin: The PIN to set.
        func set(_ pin: String) async throws(CTAP2.SessionError) {
            let authenticatorKey = try await getKeyAgreement()

            // Generate ephemeral key pair and derive shared secret
            let keyPair = P256.KeyAgreement.PrivateKey()
            let sharedSecret: Data
            do {
                sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
            } catch {
                throw CTAP2.SessionError.authError(error, source: .here())
            }

            let paddedPin: Data
            do {
                paddedPin = try pinProtocol.padPin(pin)
            } catch {
                throw CTAP2.SessionError.authError(error, source: .here())
            }

            let newPinEnc: Data
            do {
                newPinEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: paddedPin)
            } catch {
                throw CTAP2.SessionError.authError(error, source: .here())
            }

            let pinUVAuthParam = pinProtocol.authenticate(key: sharedSecret, message: newPinEnc)

            let params = CTAP2.ClientPin.SetPin.Parameters(
                pinUVAuthProtocol: pinProtocol,
                keyAgreement: pinProtocol.coseKey(from: keyPair),
                newPinEnc: newPinEnc,
                pinUVAuthParam: pinUVAuthParam
            )

            let stream: CTAP2.StatusStream<Void> = await interface.send(
                command: .clientPin,
                payload: params
            )
            try await stream.value
        }

        /// Change the existing PIN on the authenticator.
        ///
        /// - Parameters:
        ///   - currentPin: The current PIN.
        ///   - newPin: The new PIN to set.
        func change(from currentPin: String, to newPin: String) async throws(CTAP2.SessionError) {
            let authenticatorKey = try await getKeyAgreement()

            // Generate ephemeral key pair and derive shared secret
            let keyPair = P256.KeyAgreement.PrivateKey()
            let sharedSecret: Data
            do {
                sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
            } catch {
                throw CTAP2.SessionError.authError(error, source: .here())
            }

            let paddedNewPin: Data
            do {
                paddedNewPin = try pinProtocol.padPin(newPin)
            } catch {
                throw CTAP2.SessionError.authError(error, source: .here())
            }

            let newPinEnc: Data
            do {
                newPinEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: paddedNewPin)
            } catch {
                throw CTAP2.SessionError.authError(error, source: .here())
            }

            // Hash and encrypt current PIN
            let normalizedCurrentPin = currentPin.precomposedStringWithCanonicalMapping
            let pinHash = Data(SHA256.hash(data: Data(normalizedCurrentPin.utf8)).prefix(16))
            let pinHashEnc: Data
            do {
                pinHashEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: pinHash)
            } catch {
                throw CTAP2.SessionError.authError(error, source: .here())
            }

            // pinUVAuthParam = HMAC(sharedSecret, newPinEnc || pinHashEnc)
            var hmacData = newPinEnc
            hmacData.append(pinHashEnc)
            let pinUVAuthParam = pinProtocol.authenticate(key: sharedSecret, message: hmacData)

            let params = CTAP2.ClientPin.ChangePin.Parameters(
                pinUVAuthProtocol: pinProtocol,
                keyAgreement: pinProtocol.coseKey(from: keyPair),
                newPinEnc: newPinEnc,
                pinHashEnc: pinHashEnc,
                pinUVAuthParam: pinUVAuthParam
            )

            let stream: CTAP2.StatusStream<Void> = await interface.send(
                command: .clientPin,
                payload: params
            )
            try await stream.value
        }
    }
}

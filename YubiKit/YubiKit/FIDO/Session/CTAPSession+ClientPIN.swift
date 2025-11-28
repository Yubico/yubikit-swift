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

// MARK: - ClientPIN

extension CTAP2.Session {

    /// Get the number of PIN retries remaining.
    ///
    /// - Parameter pinProtocol: The PIN/UV auth protocol version (default: v1).
    /// - Returns: The number of retries remaining and whether a power cycle is required.
    func getPinRetries(
        pinProtocol: PinAuth.ProtocolVersion = .v1
    ) async throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response {
        let params = CTAP2.ClientPin.GetRetries.Parameters(pinUVAuthProtocol: pinProtocol)
        let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetRetries.Response> = await interface.send(
            command: .clientPin,
            payload: params
        )
        return try await stream.value
    }

    /// Get the number of UV (user verification) retries remaining.
    ///
    /// - Parameter pinProtocol: The PIN/UV auth protocol version (default: v1).
    /// - Returns: The number of UV retries remaining.
    func getUVRetries(
        pinProtocol: PinAuth.ProtocolVersion = .v1
    ) async throws(CTAP2.SessionError) -> Int {
        let params = CTAP2.ClientPin.GetUVRetries.Parameters(pinUVAuthProtocol: pinProtocol)
        let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetUVRetries.Response> = await interface.send(
            command: .clientPin,
            payload: params
        )
        return try await stream.value.retries
    }

    /// Get the authenticator's public key for ECDH key agreement.
    ///
    /// - Parameter pinProtocol: The PIN/UV auth protocol version (default: v1).
    /// - Returns: The authenticator's COSE key for key agreement.
    func getKeyAgreement(
        pinProtocol: PinAuth.ProtocolVersion = .v1
    ) async throws(CTAP2.SessionError) -> COSE.Key {
        let params = CTAP2.ClientPin.GetKeyAgreement.Parameters(pinUVAuthProtocol: pinProtocol)
        let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetKeyAgreement.Response> = await interface.send(
            command: .clientPin,
            payload: params
        )
        return try await stream.value.keyAgreement
    }

    /// Get a PIN token using the provided PIN.
    ///
    /// - Parameters:
    ///   - pin: The PIN string.
    ///   - permissions: Optional permissions for the token (uses 0x09 subcommand if provided).
    ///   - rpId: Optional relying party ID (required for mc/ga permissions).
    ///   - pinProtocol: The PIN/UV auth protocol version (default: v1).
    /// - Returns: The decrypted PIN token.
    func getPinToken(
        pin: String,
        permissions: CTAP2.ClientPin.Permission? = nil,
        rpId: String? = nil,
        pinProtocol: PinAuth.ProtocolVersion = .v1
    ) async throws(CTAP2.SessionError) -> Data {
        let authenticatorKey = try await getKeyAgreement(pinProtocol: pinProtocol)

        // Generate ephemeral key pair and derive shared secret
        let keyPair = P256.KeyAgreement.PrivateKey()
        let sharedSecret: Data
        do {
            sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
        } catch {
            throw CTAP2.SessionError.pinError(error, source: .here())
        }

        // Hash and encrypt PIN
        let normalizedPin = pin.precomposedStringWithCanonicalMapping
        let pinHash = Data(SHA256.hash(data: Data(normalizedPin.utf8)).prefix(16))

        let pinHashEnc: Data
        do {
            pinHashEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: pinHash)
        } catch {
            throw CTAP2.SessionError.pinError(error, source: .here())
        }

        let platformKey = pinProtocol.coseKey(from: keyPair)

        // Use typed command based on whether permissions are provided
        let response: CTAP2.ClientPin.GetToken.Response
        if let permissions {
            let params = CTAP2.ClientPin.GetTokenWithPermissions.Parameters(
                pinUVAuthProtocol: pinProtocol,
                keyAgreement: platformKey,
                pinHashEnc: pinHashEnc,
                permissions: permissions,
                rpId: rpId
            )
            let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetToken.Response> = await interface.send(
                command: .clientPin,
                payload: params
            )
            response = try await stream.value
        } else {
            let params = CTAP2.ClientPin.GetToken.Parameters(
                pinUVAuthProtocol: pinProtocol,
                keyAgreement: platformKey,
                pinHashEnc: pinHashEnc
            )
            let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetToken.Response> = await interface.send(
                command: .clientPin,
                payload: params
            )
            response = try await stream.value
        }

        let pinToken: Data
        do {
            pinToken = try pinProtocol.decrypt(key: sharedSecret, ciphertext: response.pinUVAuthToken)
        } catch {
            throw CTAP2.SessionError.pinError(error, source: .here())
        }

        // Validate token size: V1 allows 16 or 32 bytes, V2 requires exactly 32 bytes
        let validSize = pinProtocol == .v1 ? (pinToken.count == 16 || pinToken.count == 32) : pinToken.count == 32
        guard validSize else {
            throw CTAP2.SessionError.pinError(PinAuth.Error.invalidTokenSize, source: .here())
        }

        return pinToken
    }

    /// Set a new PIN on the authenticator (must not already have a PIN).
    ///
    /// - Parameters:
    ///   - pin: The PIN to set.
    ///   - pinProtocol: The PIN/UV auth protocol version (default: v1).
    func setPin(to pin: String, pinProtocol: PinAuth.ProtocolVersion = .v1) async throws(CTAP2.SessionError) {
        let authenticatorKey = try await getKeyAgreement(pinProtocol: pinProtocol)

        // Generate ephemeral key pair and derive shared secret
        let keyPair = P256.KeyAgreement.PrivateKey()
        let sharedSecret: Data
        do {
            sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
        } catch {
            throw CTAP2.SessionError.pinError(error, source: .here())
        }

        let paddedPin: Data
        do {
            paddedPin = try pinProtocol.padPin(pin)
        } catch {
            throw CTAP2.SessionError.pinError(error, source: .here())
        }

        let newPinEnc: Data
        do {
            newPinEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: paddedPin)
        } catch {
            throw CTAP2.SessionError.pinError(error, source: .here())
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
    ///   - pinProtocol: The PIN/UV auth protocol version (default: v1).
    func changePin(
        from currentPin: String,
        to newPin: String,
        pinProtocol: PinAuth.ProtocolVersion = .v1
    ) async throws(CTAP2.SessionError) {
        let authenticatorKey = try await getKeyAgreement(pinProtocol: pinProtocol)

        // Generate ephemeral key pair and derive shared secret
        let keyPair = P256.KeyAgreement.PrivateKey()
        let sharedSecret: Data
        do {
            sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
        } catch {
            throw CTAP2.SessionError.pinError(error, source: .here())
        }

        let paddedNewPin: Data
        do {
            paddedNewPin = try pinProtocol.padPin(newPin)
        } catch {
            throw CTAP2.SessionError.pinError(error, source: .here())
        }

        let newPinEnc: Data
        do {
            newPinEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: paddedNewPin)
        } catch {
            throw CTAP2.SessionError.pinError(error, source: .here())
        }

        // Hash and encrypt current PIN
        let normalizedCurrentPin = currentPin.precomposedStringWithCanonicalMapping
        let pinHash = Data(SHA256.hash(data: Data(normalizedCurrentPin.utf8)).prefix(16))
        let pinHashEnc: Data
        do {
            pinHashEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: pinHash)
        } catch {
            throw CTAP2.SessionError.pinError(error, source: .here())
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

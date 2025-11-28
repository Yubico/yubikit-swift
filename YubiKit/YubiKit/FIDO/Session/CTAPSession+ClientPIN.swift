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
    /// - Returns: The number of retries remaining and whether a power cycle is required.
    func getPinRetries() async throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response {
        let params = CTAP2.ClientPin.GetRetries.Parameters()
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
        let params = CTAP2.ClientPin.GetUVRetries.Parameters()
        let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetUVRetries.Response> = await interface.send(
            command: .clientPin,
            payload: params
        )
        return try await stream.value.retries
    }

    /// Get the authenticator's public key for ECDH key agreement.
    ///
    /// - Parameter protocolVersion: The PIN/UV auth protocol version (default: v1).
    /// - Returns: The authenticator's COSE key for key agreement.
    func getKeyAgreement(
        protocolVersion: PinAuth.Version = .v1
    ) async throws(CTAP2.SessionError) -> COSE.Key {
        let params = CTAP2.ClientPin.GetKeyAgreement.Parameters(pinUVAuthProtocol: protocolVersion)
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
    ///   - pinAuth: The PIN auth protocol instance (default: v1).
    /// - Returns: The decrypted PIN token.
    func getPinToken(
        pin: String,
        permissions: CTAP2.ClientPin.Permission? = nil,
        rpId: String? = nil,
        pinAuth: PinAuth = .default
    ) async throws(CTAP2.SessionError) -> Data {
        let authenticatorKeyAgreement = try await getKeyAgreement(protocolVersion: pinAuth.version)

        let keyAgreementResult: KeyAgreementResult
        do {
            keyAgreementResult = try pinAuth.keyAgreement(peerKey: authenticatorKeyAgreement)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        // Hash and encrypt PIN
        let pinUtf8 = Data(pin.utf8)
        let pinHash = Data(SHA256.hash(data: pinUtf8).prefix(16))

        let pinHashEnc: Data
        do {
            pinHashEnc = try pinAuth.encrypt(key: keyAgreementResult.sharedSecret, plaintext: pinHash)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        let platformKey = pinAuth.platformKeyAgreementKey()

        // Use typed command based on whether permissions are provided
        let response: CTAP2.ClientPin.GetToken.Response
        if let permissions {
            let params = CTAP2.ClientPin.GetTokenWithPermissions.Parameters(
                pinUVAuthProtocol: pinAuth.version,
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
                pinUVAuthProtocol: pinAuth.version,
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
            pinToken = try pinAuth.decrypt(
                key: keyAgreementResult.sharedSecret,
                ciphertext: response.pinUVAuthToken
            )
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        return pinToken
    }

    /// Set a new PIN on the authenticator (must not already have a PIN).
    ///
    /// - Parameters:
    ///   - pin: The PIN to set.
    ///   - pinAuth: The PIN auth protocol instance (default: v1).
    func setPin(pin: String, pinAuth: PinAuth = .default) async throws(CTAP2.SessionError) {
        let authenticatorKeyAgreement = try await getKeyAgreement(protocolVersion: pinAuth.version)

        let keyAgreementResult: KeyAgreementResult
        do {
            keyAgreementResult = try pinAuth.keyAgreement(peerKey: authenticatorKeyAgreement)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        let paddedPin = pinAuth.padPin(pin)
        let newPinEnc: Data
        do {
            newPinEnc = try pinAuth.encrypt(key: keyAgreementResult.sharedSecret, plaintext: paddedPin)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        let pinUVAuthParam = pinAuth.authenticate(key: keyAgreementResult.sharedSecret, message: newPinEnc)

        let params = CTAP2.ClientPin.SetPin.Parameters(
            pinUVAuthProtocol: pinAuth.version,
            keyAgreement: pinAuth.platformKeyAgreementKey(),
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
    ///   - pinAuth: The PIN auth protocol instance (default: v1).
    func changePin(
        currentPin: String,
        newPin: String,
        pinAuth: PinAuth = .default
    ) async throws(CTAP2.SessionError) {
        let authenticatorKeyAgreement = try await getKeyAgreement(protocolVersion: pinAuth.version)

        let keyAgreementResult: KeyAgreementResult
        do {
            keyAgreementResult = try pinAuth.keyAgreement(peerKey: authenticatorKeyAgreement)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        let paddedNewPin = pinAuth.padPin(newPin)
        let newPinEnc: Data
        do {
            newPinEnc = try pinAuth.encrypt(key: keyAgreementResult.sharedSecret, plaintext: paddedNewPin)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        // Hash and encrypt current PIN
        let currentPinUtf8 = Data(currentPin.utf8)
        let pinHash = Data(SHA256.hash(data: currentPinUtf8).prefix(16))
        let pinHashEnc: Data
        do {
            pinHashEnc = try pinAuth.encrypt(key: keyAgreementResult.sharedSecret, plaintext: pinHash)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        // pinUvAuthParam = HMAC(sharedSecret, newPinEnc || pinHashEnc)
        var hmacData = newPinEnc
        hmacData.append(pinHashEnc)
        let pinUVAuthParam = pinAuth.authenticate(key: keyAgreementResult.sharedSecret, message: hmacData)

        let params = CTAP2.ClientPin.ChangePin.Parameters(
            pinUVAuthProtocol: pinAuth.version,
            keyAgreement: pinAuth.platformKeyAgreementKey(),
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

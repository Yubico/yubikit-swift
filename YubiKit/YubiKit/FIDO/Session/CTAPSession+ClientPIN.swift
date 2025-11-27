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
    func getPinRetries() async throws(CTAP2.SessionError) -> (retries: Int, powerCycleRequired: Bool) {
        let parameters = CTAP2.ClientPIN.Parameters(
            pinUvAuthProtocol: .v1,
            subCommand: .getPinRetries
        )

        let stream: CTAP2.StatusStream<CTAP2.ClientPIN.Response> = await interface.send(
            command: .clientPIN,
            payload: parameters
        )
        let response = try await stream.value

        guard let pinRetries = response.pinRetries else {
            throw CTAP2.SessionError.ctapError(.missingParameter, source: .here())
        }

        return (retries: pinRetries, powerCycleRequired: response.powerCycleState ?? false)
    }

    /// Get the number of UV (user verification) retries remaining.
    func getUvRetries() async throws(CTAP2.SessionError) -> Int {
        let parameters = CTAP2.ClientPIN.Parameters(
            pinUvAuthProtocol: .v1,
            subCommand: .getUVRetries
        )

        let stream: CTAP2.StatusStream<CTAP2.ClientPIN.Response> = await interface.send(
            command: .clientPIN,
            payload: parameters
        )
        let response = try await stream.value

        guard let uvRetries = response.uvRetries else {
            throw CTAP2.SessionError.ctapError(.missingParameter, source: .here())
        }

        return uvRetries
    }

    /// Get the authenticator's public key for ECDH key agreement.
    func getKeyAgreement(protocol: PinAuth.Version = .v1) async throws(CTAP2.SessionError) -> COSE.Key {
        let parameters = CTAP2.ClientPIN.Parameters(
            pinUvAuthProtocol: `protocol`,
            subCommand: .getKeyAgreement
        )

        let stream: CTAP2.StatusStream<CTAP2.ClientPIN.Response> = await interface.send(
            command: .clientPIN,
            payload: parameters
        )
        let response = try await stream.value

        guard let keyAgreement = response.keyAgreement else {
            throw CTAP2.SessionError.ctapError(.missingParameter, source: .here())
        }

        return keyAgreement
    }

    /// Get a PIN token using the provided PIN.
    func getPinToken(
        pin: String,
        permissions: CTAP2.ClientPIN.Permission? = nil,
        rpId: String? = nil,
        pinAuth: PinAuth = .default
    ) async throws(CTAP2.SessionError) -> Data {
        let authenticatorKeyAgreement = try await getKeyAgreement(protocol: pinAuth.version)

        let keyAgreementResult: KeyAgreementResult
        do {
            keyAgreementResult = try pinAuth.keyAgreement(peerKey: authenticatorKeyAgreement)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        // Hash and encrypt PIN (hash raw UTF-8, not padded)
        let pinUtf8 = Data(pin.utf8)
        let pinHash = Data(SHA256.hash(data: pinUtf8).prefix(16))

        let pinHashEnc: Data
        do {
            pinHashEnc = try pinAuth.encrypt(key: keyAgreementResult.sharedSecret, plaintext: pinHash)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        // Use permissions subcommand (0x09) if permissions provided, else legacy (0x05)
        let subCommand: CTAP2.ClientPIN.Subcommand
        let requestPermissions: CTAP2.ClientPIN.Permission?
        let requestRpId: String?

        if let permissions {
            subCommand = .getPinUvAuthTokenUsingPinWithPermissions
            requestPermissions = permissions
            requestRpId = rpId
        } else {
            subCommand = .getPinToken
            requestPermissions = nil
            requestRpId = nil
        }

        let parameters = CTAP2.ClientPIN.Parameters(
            pinUvAuthProtocol: pinAuth.version,
            subCommand: subCommand,
            keyAgreement: pinAuth.platformKeyAgreementKey(),
            pinHashEnc: pinHashEnc,
            permissions: requestPermissions,
            rpId: requestRpId
        )

        let stream: CTAP2.StatusStream<CTAP2.ClientPIN.Response> = await interface.send(
            command: .clientPIN,
            payload: parameters
        )
        let response = try await stream.value

        guard let encryptedToken = response.pinUvAuthToken else {
            throw CTAP2.SessionError.ctapError(.missingParameter, source: .here())
        }

        let pinToken: Data
        do {
            pinToken = try pinAuth.decrypt(key: keyAgreementResult.sharedSecret, ciphertext: encryptedToken)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        return pinToken
    }

    /// Set a new PIN on the authenticator (must not already have a PIN).
    func setPIN(pin: String, pinAuth: PinAuth = .default) async throws(CTAP2.SessionError) {
        let authenticatorKeyAgreement = try await getKeyAgreement(protocol: pinAuth.version)

        let keyAgreementResult: KeyAgreementResult
        do {
            keyAgreementResult = try pinAuth.keyAgreement(peerKey: authenticatorKeyAgreement)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        let paddedPin = pinAuth.padPIN(pin)
        let newPinEnc: Data
        do {
            newPinEnc = try pinAuth.encrypt(key: keyAgreementResult.sharedSecret, plaintext: paddedPin)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        let pinUvAuthParam = pinAuth.authenticate(key: keyAgreementResult.sharedSecret, message: newPinEnc)

        let parameters = CTAP2.ClientPIN.Parameters(
            pinUvAuthProtocol: pinAuth.version,
            subCommand: .setPIN,
            keyAgreement: pinAuth.platformKeyAgreementKey(),
            pinUvAuthParam: pinUvAuthParam,
            newPinEnc: newPinEnc
        )

        let stream: CTAP2.StatusStream<CTAP2.ClientPIN.Response> = await interface.send(
            command: .clientPIN,
            payload: parameters
        )
        _ = try await stream.value
    }

    /// Change the existing PIN on the authenticator.
    func changePIN(currentPin: String, newPin: String, pinAuth: PinAuth = .default) async throws(CTAP2.SessionError) {
        let authenticatorKeyAgreement = try await getKeyAgreement(protocol: pinAuth.version)

        let keyAgreementResult: KeyAgreementResult
        do {
            keyAgreementResult = try pinAuth.keyAgreement(peerKey: authenticatorKeyAgreement)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        let paddedNewPin = pinAuth.padPIN(newPin)
        let newPinEnc: Data
        do {
            newPinEnc = try pinAuth.encrypt(key: keyAgreementResult.sharedSecret, plaintext: paddedNewPin)
        } catch {
            throw CTAP2.SessionError.ctapError(.invalidParameter, source: .here())
        }

        // Hash and encrypt current PIN (hash raw UTF-8, not padded)
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
        let pinUvAuthParam = pinAuth.authenticate(key: keyAgreementResult.sharedSecret, message: hmacData)

        let parameters = CTAP2.ClientPIN.Parameters(
            pinUvAuthProtocol: pinAuth.version,
            subCommand: .changePIN,
            keyAgreement: pinAuth.platformKeyAgreementKey(),
            pinUvAuthParam: pinUvAuthParam,
            newPinEnc: newPinEnc,
            pinHashEnc: pinHashEnc
        )

        let stream: CTAP2.StatusStream<CTAP2.ClientPIN.Response> = await interface.send(
            command: .clientPIN,
            payload: parameters
        )
        _ = try await stream.value
    }
}

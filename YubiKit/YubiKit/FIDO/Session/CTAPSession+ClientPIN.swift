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

// MARK: - ClientPin Operations on Session

extension CTAP2.Session {

    /// Get the number of PIN retries remaining.
    ///
    /// - Parameter pinProtocol: The PIN/UV auth protocol version to use. If nil, auto-selects.
    /// - Returns: The number of retries remaining and whether a power cycle is required.
    func getPinRetries(
        protocol pinProtocol: CTAP2.ClientPin.ProtocolVersion? = nil
    ) async throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response {
        let handler = try await clientPinHandler(protocol: pinProtocol)
        return try await handler.getRetries()
    }

    /// Get the number of UV (user verification) retries remaining.
    ///
    /// - Parameter pinProtocol: The PIN/UV auth protocol version to use. If nil, auto-selects.
    /// - Returns: The number of UV retries remaining.
    func getUVRetries(
        protocol pinProtocol: CTAP2.ClientPin.ProtocolVersion? = nil
    ) async throws(CTAP2.SessionError) -> Int {
        let handler = try await clientPinHandler(protocol: pinProtocol)
        return try await handler.getUVRetries()
    }

    /// Get a PIN/UV auth token from the authenticator.
    ///
    /// The returned token can be used to authenticate subsequent CTAP operations
    /// like ``makeCredential(parameters:pinToken:)`` and ``getAssertion(parameters:pinToken:)``.
    ///
    /// - Parameters:
    ///   - method: The authentication method to use (PIN or built-in UV).
    ///   - permissions: Permissions for the token.
    ///   - rpId: Optional relying party ID (required for mc/ga permissions).
    ///   - pinProtocol: The PIN/UV auth protocol version to use. If nil, auto-selects.
    /// - Returns: A PIN/UV auth token that can be used to authenticate CTAP operations.
    ///
    /// Example:
    /// ```swift
    /// // Using PIN
    /// let token = try await session.getPinUVToken(using: .pin("1234"), permissions: .makeCredential, rpId: "example.com")
    ///
    /// // Using biometrics (YubiKey Bio)
    /// let token = try await session.getPinUVToken(using: .uv, permissions: .makeCredential, rpId: "example.com")
    /// ```
    public func getPinUVToken(
        using method: CTAP2.ClientPin.Method,
        permissions: CTAP2.ClientPin.Permission,
        rpId: String? = nil,
        protocol pinProtocol: CTAP2.ClientPin.ProtocolVersion? = nil
    ) async throws(CTAP2.SessionError) -> CTAP2.ClientPin.Token {
        let handler = try await clientPinHandler(protocol: pinProtocol)
        return try await handler.getToken(using: method, permissions: permissions, rpId: rpId)
    }

    /// Set a new PIN on the authenticator (must not already have a PIN).
    ///
    /// - Parameters:
    ///   - pin: The PIN to set.
    ///   - pinProtocol: The PIN/UV auth protocol version to use. If nil, auto-selects.
    public func setPin(
        _ pin: String,
        protocol pinProtocol: CTAP2.ClientPin.ProtocolVersion? = nil
    ) async throws(CTAP2.SessionError) {
        let handler = try await clientPinHandler(protocol: pinProtocol)
        try await handler.set(pin)
    }

    /// Change the existing PIN on the authenticator.
    ///
    /// - Parameters:
    ///   - currentPin: The current PIN.
    ///   - newPin: The new PIN to set.
    ///   - pinProtocol: The PIN/UV auth protocol version to use. If nil, auto-selects.
    public func changePin(
        from currentPin: String,
        to newPin: String,
        protocol pinProtocol: CTAP2.ClientPin.ProtocolVersion? = nil
    ) async throws(CTAP2.SessionError) {
        let handler = try await clientPinHandler(protocol: pinProtocol)
        try await handler.change(from: currentPin, to: newPin)
    }

    // MARK: - Private

    private func clientPinHandler(
        protocol pinProtocol: CTAP2.ClientPin.ProtocolVersion?
    ) async throws(CTAP2.SessionError) -> ClientPinHandler<I> {
        let selectedProtocol: CTAP2.ClientPin.ProtocolVersion
        if let pinProtocol {
            selectedProtocol = pinProtocol
        } else {
            selectedProtocol = try await preferredClientPinProtocol
        }
        return ClientPinHandler(
            interface: interface,
            pinProtocol: selectedProtocol,
            supportsTokenPermissions: try await supportsTokenPermissions
        )
    }
}

// MARK: - ClientPinHandler (Internal)

/// Internal handler for ClientPIN operations.
private struct ClientPinHandler<I: CBORInterface>: Sendable where I.Error == CTAP2.SessionError {
    let interface: I
    let pinProtocol: CTAP2.ClientPin.ProtocolVersion
    let supportsTokenPermissions: Bool

    func getRetries() async throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response {
        let params = CTAP2.ClientPin.GetRetries.Parameters(pinUVAuthProtocol: pinProtocol)
        let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetRetries.Response> = await interface.send(
            command: .clientPin,
            payload: params
        )
        return try await stream.value
    }

    func getUVRetries() async throws(CTAP2.SessionError) -> Int {
        let params = CTAP2.ClientPin.GetUVRetries.Parameters(pinUVAuthProtocol: pinProtocol)
        let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetUVRetries.Response> = await interface.send(
            command: .clientPin,
            payload: params
        )
        return try await stream.value.retries
    }

    func getKeyAgreement() async throws(CTAP2.SessionError) -> COSE.Key {
        let params = CTAP2.ClientPin.GetKeyAgreement.Parameters(pinUVAuthProtocol: pinProtocol)
        let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetKeyAgreement.Response> = await interface.send(
            command: .clientPin,
            payload: params
        )
        return try await stream.value.keyAgreement
    }

    func getToken(
        using method: CTAP2.ClientPin.Method,
        permissions: CTAP2.ClientPin.Permission,
        rpId: String? = nil
    ) async throws(CTAP2.SessionError) -> CTAP2.ClientPin.Token {
        // UV requires pinUvAuthToken support
        if case .uv = method, !supportsTokenPermissions {
            throw CTAP2.SessionError.featureNotSupported(source: .here())
        }

        let authenticatorKey = try await getKeyAgreement()

        // Generate ephemeral key pair and derive shared secret
        let keyPair = P256.KeyAgreement.PrivateKey()
        let sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
        let platformKey = pinProtocol.coseKey(from: keyPair)

        // Build command parameters based on auth method
        let params: CBOR.Encodable
        switch method {
        case .pin(let pin):
            // Hash and encrypt PIN
            let normalizedPin = pin.precomposedStringWithCanonicalMapping
            let pinHash = Data(SHA256.hash(data: Data(normalizedPin.utf8)).prefix(16))
            let pinHashEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: pinHash)

            if supportsTokenPermissions {
                // Use 0x09 (getPinUvAuthTokenUsingPinWithPermissions)
                params = CTAP2.ClientPin.GetTokenWithPermissions.Parameters(
                    pinUVAuthProtocol: pinProtocol,
                    keyAgreement: platformKey,
                    pinHashEnc: pinHashEnc,
                    permissions: permissions,
                    rpId: rpId
                )
            } else {
                // Fall back to 0x05 (legacy getPinToken)
                params = CTAP2.ClientPin.GetToken.Parameters(
                    pinUVAuthProtocol: pinProtocol,
                    keyAgreement: platformKey,
                    pinHashEnc: pinHashEnc
                )
            }

        case .uv:
            // Use 0x06 (getPinUvAuthTokenUsingUvWithPermissions)
            params = CTAP2.ClientPin.GetTokenUsingUV.Parameters(
                pinUVAuthProtocol: pinProtocol,
                keyAgreement: platformKey,
                permissions: permissions,
                rpId: rpId
            )
        }

        let stream: CTAP2.StatusStream<CTAP2.ClientPin.GetToken.Response> = await interface.send(
            command: .clientPin,
            payload: params
        )
        let response = try await stream.value
        let pinToken = try pinProtocol.decrypt(key: sharedSecret, ciphertext: response.pinUVAuthToken)

        // Validate token size: V1 allows 16 or 32 bytes, V2 requires exactly 32 bytes
        let validSize =
            pinProtocol == .v1 ? (pinToken.count == 16 || pinToken.count == 32) : pinToken.count == 32
        guard validSize else {
            throw CTAP2.SessionError.responseParseError(
                "Invalid PIN token size: expected \(pinProtocol == .v1 ? "16 or 32" : "32") bytes, got \(pinToken.count)",
                source: .here()
            )
        }

        return CTAP2.ClientPin.Token(token: pinToken, protocolVersion: pinProtocol)
    }

    func set(_ pin: String) async throws(CTAP2.SessionError) {
        let authenticatorKey = try await getKeyAgreement()

        // Generate ephemeral key pair and derive shared secret
        let keyPair = P256.KeyAgreement.PrivateKey()
        let sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
        let paddedPin = try pinProtocol.padPin(pin)
        let newPinEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: paddedPin)
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

    func change(from currentPin: String, to newPin: String) async throws(CTAP2.SessionError) {
        let authenticatorKey = try await getKeyAgreement()

        // Generate ephemeral key pair and derive shared secret
        let keyPair = P256.KeyAgreement.PrivateKey()
        let sharedSecret = try pinProtocol.sharedSecret(keyPair: keyPair, peerKey: authenticatorKey)
        let paddedNewPin = try pinProtocol.padPin(newPin)
        let newPinEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: paddedNewPin)

        // Hash and encrypt current PIN
        let normalizedCurrentPin = currentPin.precomposedStringWithCanonicalMapping
        let pinHash = Data(SHA256.hash(data: Data(normalizedCurrentPin.utf8)).prefix(16))
        let pinHashEnc = try pinProtocol.encrypt(key: sharedSecret, plaintext: pinHash)

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

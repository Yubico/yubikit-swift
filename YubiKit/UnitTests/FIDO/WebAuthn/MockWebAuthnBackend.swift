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

import Foundation

@testable import YubiKit

// MARK: - MockWebAuthnBackend

/// Mock backend for WebAuthn tests. Set closures to control behavior.
actor MockWebAuthnBackend: WebAuthn.Backend {

    // MARK: Configurable Closures

    nonisolated(unsafe) var onGetInfo: (() throws(CTAP2.SessionError) -> CTAP2.GetInfo.Response)!
    nonisolated(unsafe) var onGetUVRetries: (() throws(CTAP2.SessionError) -> Int)!
    nonisolated(unsafe) var onGetPinRetries: (() throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response)!
    /// Set one of these. Use the updates form to drive `.waitingForUser` keep-alives.
    nonisolated(unsafe) var onGetPinUVToken:
        (
            (CTAP2.ClientPin.Method, CTAP2.ClientPin.Permission, String?)
                throws(CTAP2.SessionError) -> CTAP2.Token
        )?
    nonisolated(unsafe) var onGetPinUVTokenUpdates:
        (
            (CTAP2.ClientPin.Method, CTAP2.ClientPin.Permission, String?)
                throws(CTAP2.SessionError) -> CTAP2.StatusStream<CTAP2.Token>
        )?
    nonisolated(unsafe) var onMakeCredential:
        ((CTAP2.MakeCredential.Parameters) -> CTAP2.StatusStream<CTAP2.MakeCredential.Response>)!
    nonisolated(unsafe) var onGetAssertion:
        ((CTAP2.GetAssertion.Parameters) -> CTAP2.StatusStream<CTAP2.GetAssertion.Response>)!
    nonisolated(unsafe) var onGetNextAssertion: (() -> CTAP2.StatusStream<CTAP2.GetAssertion.Response>)!

    // MARK: WebAuthn.Backend Protocol

    var cachedInfo: CTAP2.GetInfo.ImmutableView {
        get async throws(CTAP2.SessionError) { try CTAP2.GetInfo.ImmutableView(onGetInfo()) }
    }

    func getInfo() async throws(CTAP2.SessionError) -> CTAP2.GetInfo.Response { try onGetInfo() }
    func getUVRetries() async throws(CTAP2.SessionError) -> Int { try onGetUVRetries() }
    func getPinRetries() async throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response {
        try onGetPinRetries()
    }

    func getPinUVTokenUpdates(
        using method: CTAP2.ClientPin.Method,
        permissions: CTAP2.ClientPin.Permission,
        rpId: String?
    ) async throws(CTAP2.SessionError) -> CTAP2.StatusStream<CTAP2.Token> {
        if let onGetPinUVTokenUpdates {
            return try onGetPinUVTokenUpdates(method, permissions, rpId)
        }
        guard let onGetPinUVToken else {
            preconditionFailure("Set onGetPinUVToken or onGetPinUVTokenUpdates")
        }
        do throws(CTAP2.SessionError) {
            let token = try onGetPinUVToken(method, permissions, rpId)
            return .mocked(.finished(token))
        } catch {
            return .mocked(error: error)
        }
    }

    func makeCredential(
        parameters: CTAP2.MakeCredential.Parameters,
        token: CTAP2.Token?
    ) async -> CTAP2.StatusStream<CTAP2.MakeCredential.Response> {
        onMakeCredential(parameters)
    }

    func getAssertion(
        parameters: CTAP2.GetAssertion.Parameters,
        token: CTAP2.Token?
    ) async -> CTAP2.StatusStream<CTAP2.GetAssertion.Response> {
        onGetAssertion(parameters)
    }

    func getNextAssertion() async -> CTAP2.StatusStream<CTAP2.GetAssertion.Response> {
        onGetNextAssertion()
    }

    // MARK: Extensions (Not Implemented)

    // PRF (hmac-secret)
    func makePRF() async throws(CTAP2.SessionError) -> WebAuthn.Extension.PRF { fatalError() }
    func makePRF(
        first: Data,
        second: Data?,
        evalByCredential: [Data: (first: Data, second: Data?)]
    ) async throws(CTAP2.SessionError) -> WebAuthn.Extension.PRF { fatalError() }
    func makePRF(
        evalByCredential: [Data: (first: Data, second: Data?)]
    ) async throws(CTAP2.SessionError) -> WebAuthn.Extension.PRF { fatalError() }

    // credProtect
    func makeCredProtect(
        level: WebAuthn.Extension.CredProtect.Policy,
        enforce: Bool
    ) async throws(CTAP2.SessionError) -> CTAP2.Extension.CredProtect { fatalError() }

    // credBlob
    func makeCredBlob() async throws(CTAP2.SessionError) -> CTAP2.Extension.CredBlob { fatalError() }

    // minPinLength
    func isMinPinLengthSupported() async throws(CTAP2.SessionError) -> Bool { fatalError() }
    func makeMinPinLength() async throws(CTAP2.SessionError) -> CTAP2.Extension.MinPinLength { fatalError() }

    // largeBlob
    func makeLargeBlobKey() async throws(CTAP2.SessionError) -> CTAP2.Extension.LargeBlobKey { fatalError() }
    func isLargeBlobSupported() async throws(CTAP2.SessionError) -> Bool { fatalError() }
    func getBlob(key: Data) async throws(CTAP2.SessionError) -> Data? { fatalError() }
    func putBlob(key: Data, data: Data, token: CTAP2.Token) async throws(CTAP2.SessionError) { fatalError() }

    // previewSign
    func makePreviewSign() async throws(CTAP2.SessionError) -> CTAP2.Extension.PreviewSign { fatalError() }

    // thirdPartyPayment
    func makeThirdPartyPayment() async throws(CTAP2.SessionError) -> CTAP2.Extension.ThirdPartyPayment { fatalError() }
}

// MARK: - StatusStream Helpers

extension CTAP2.StatusStream {
    static func mocked(_ status: CTAP2.Status<R>) -> Self { .init { $0.yield(status) } }
    static func mocked(error: CTAP2.SessionError) -> Self { .init { $0.yield(error: error) } }
}

// MARK: - Client Helpers

extension WebAuthn.Client {
    static func make(
        backend: WebAuthn.Backend,
        origin: String = "https://example.com"
    ) throws -> WebAuthn.Client {
        WebAuthn.Client(
            backend: backend,
            origin: try WebAuthn.Origin(origin),
            allowedExtensions: .standard,
            isPublicSuffix: { _ in false }
        )
    }
}

// MARK: - Test Stubs

extension CTAP2.GetInfo.Response {
    static func stub(
        maxCredentialIdLength: UInt? = nil,
        maxCredentialCountInList: UInt? = nil,
        clientPin: Bool = false,
        userVerification: Bool = false,
        pinUvAuthToken: Bool = false,
        forcePinChange: Bool? = nil
    ) -> Self {
        var optionsMap: [CBOR.Value: CBOR.Value] = [
            .textString("up"): .boolean(true),
            .textString("rk"): .boolean(true),
        ]
        if clientPin { optionsMap[.textString("clientPin")] = .boolean(true) }
        if userVerification { optionsMap[.textString("uv")] = .boolean(true) }
        if pinUvAuthToken { optionsMap[.textString("pinUvAuthToken")] = .boolean(true) }
        let options: CTAP2.GetInfo.Options = CBOR.Value.map(optionsMap).cborDecoded()!

        return Self(
            versions: [.fido2_1],
            aaguid: CTAP2.GetInfo.AAGUID(rawValue: Data(repeating: 0, count: 16))!,
            extensions: [],
            options: options,
            maxMsgSize: 1200,
            pinUVAuthProtocols: [.v2],
            maxCredentialCountInList: maxCredentialCountInList,
            maxCredentialIdLength: maxCredentialIdLength,
            transports: [.usb],
            algorithms: [.es256],
            maxSerializedLargeBlobArray: nil,
            forcePinChange: forcePinChange,
            minPinLength: nil,
            firmwareVersion: nil,
            maxCredBlobLength: nil,
            maxRPIDsForSetMinPinLength: nil,
            preferredPlatformUVAttempts: nil,
            uvModality: nil,
            certifications: [:],
            remainingDiscoverableCredentials: nil,
            vendorPrototypeConfigCommands: nil,
            attestationFormats: [],
            uvCountSinceLastPinEntry: nil,
            longTouchForReset: nil,
            encIdentifier: nil,
            transportsForReset: [],
            pinComplexityPolicy: nil,
            pinComplexityPolicyURL: nil,
            maxPINLength: nil,
            encCredStoreState: nil,
            authenticatorConfigCommands: nil
        )
    }
}

extension CTAP2.GetAssertion.Response {
    static func stub(credentialId: Data) -> Self {
        var authData = Data(repeating: 0, count: 32)
        authData.append(0x01)
        authData.append(contentsOf: [0, 0, 0, 1])
        return Self(
            credential: WebAuthn.CredentialDescriptor(id: credentialId),
            authenticatorData: WebAuthn.AuthenticatorData(data: authData)!,
            signature: Data([0x30, 0x44]),
            user: nil,
            numberOfCredentials: 1,
            userSelected: nil,
            largeBlobKey: nil
        )
    }
}

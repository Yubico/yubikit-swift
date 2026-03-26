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

/// Mock backend - set closures to control behavior. Crashes if closure not set.
actor MockWebAuthnBackend: WebAuthn.Backend {

    // MARK: - Closures (must be set before use)

    nonisolated(unsafe) var onGetInfo: (() throws(CTAP2.SessionError) -> CTAP2.GetInfo.Response)!
    nonisolated(unsafe) var onGetUVRetries: (() throws(CTAP2.SessionError) -> Int)!
    nonisolated(unsafe) var onGetPinRetries: (() throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response)!
    nonisolated(unsafe) var onGetPinUVToken:
        ((CTAP2.ClientPin.Method, CTAP2.ClientPin.Permission, String?) throws(CTAP2.SessionError) -> CTAP2.Token)!
    nonisolated(unsafe) var onMakeCredential:
        ((CTAP2.MakeCredential.Parameters) -> CTAP2.StatusStream<CTAP2.MakeCredential.Response>)!
    nonisolated(unsafe) var onGetAssertion:
        ((CTAP2.GetAssertion.Parameters) -> CTAP2.StatusStream<CTAP2.GetAssertion.Response>)!
    nonisolated(unsafe) var onGetNextAssertion: (() -> CTAP2.StatusStream<CTAP2.GetAssertion.Response>)!

    // MARK: - Backend Protocol

    var cachedInfo: CTAP2.GetInfo.ImmutableView {
        get async throws(CTAP2.SessionError) {
            try CTAP2.GetInfo.ImmutableView(onGetInfo())
        }
    }

    func getInfo() async throws(CTAP2.SessionError) -> CTAP2.GetInfo.Response {
        try onGetInfo()
    }

    func getUVRetries() async throws(CTAP2.SessionError) -> Int {
        try onGetUVRetries()
    }

    func getPinRetries() async throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response {
        try onGetPinRetries()
    }

    func getPinUVToken(
        using method: CTAP2.ClientPin.Method,
        permissions: CTAP2.ClientPin.Permission,
        rpId: String?
    ) async throws(CTAP2.SessionError) -> CTAP2.Token {
        try onGetPinUVToken(method, permissions, rpId)
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
}

// MARK: - StatusStream Helpers

extension StatusStreamBase where Failure == CTAP2.SessionError {
    static func mocked(_ status: Status) -> Self {
        .init { $0.yield(status) }
    }

    static func mocked(error: CTAP2.SessionError) -> Self {
        .init { $0.yield(error: error) }
    }
}

// MARK: - Test Stubs

extension CTAP2.GetInfo.Response {
    static func stub(
        maxCredentialIdLength: UInt? = nil,
        maxCredentialCountInList: UInt? = nil
    ) -> Self {
        let options: CTAP2.GetInfo.Options = CBOR.Value.map([
            .textString("up"): .boolean(true),
            .textString("rk"): .boolean(true),
        ]).cborDecoded()!

        return Self(
            versions: [.fido2_1],
            aaguid: UUID(),
            extensions: [],
            options: options,
            maxMsgSize: 1200,
            pinUVAuthProtocols: [.v2],
            maxCredentialCountInList: maxCredentialCountInList,
            maxCredentialIdLength: maxCredentialIdLength,
            transports: [.usb],
            algorithms: [.es256],
            maxSerializedLargeBlobArray: nil,
            forcePinChange: nil,
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

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

// MARK: - WebAuthn Backend Protocol

extension WebAuthn {

    /// Internal protocol abstracting CTAP2.Session for testability.
    ///
    /// This protocol defines the CTAP2 operations required by WebAuthn.Client,
    /// allowing the client logic to be tested with mock implementations.
    protocol Backend: Actor {

        // MARK: - Authenticator Info

        var cachedInfo: CTAP2.GetInfo.ImmutableView { get async throws(CTAP2.SessionError) }

        func getInfo() async throws(CTAP2.SessionError) -> CTAP2.GetInfo.Response

        // MARK: - PIN/UV

        func getUVRetries() async throws(CTAP2.SessionError) -> Int

        func getPinRetries() async throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response

        func getPinUVTokenUpdates(
            using method: CTAP2.ClientPin.Method,
            permissions: CTAP2.ClientPin.Permission,
            rpId: String?
        ) async throws(CTAP2.SessionError) -> CTAP2.StatusStream<CTAP2.Token>

        // MARK: - Credentials

        func makeCredential(
            parameters: CTAP2.MakeCredential.Parameters,
            token: CTAP2.Token?
        ) async -> CTAP2.StatusStream<CTAP2.MakeCredential.Response>

        func getAssertion(
            parameters: CTAP2.GetAssertion.Parameters,
            token: CTAP2.Token?
        ) async -> CTAP2.StatusStream<CTAP2.GetAssertion.Response>

        func getNextAssertion() async -> CTAP2.StatusStream<CTAP2.GetAssertion.Response>

        // MARK: - Extensions

        // PRF (hmac-secret)
        func makePRF() async throws(CTAP2.SessionError) -> WebAuthn.Extension.PRF
        func makePRF(
            first: Data,
            second: Data?,
            evalByCredential: [Data: (first: Data, second: Data?)]
        ) async throws(CTAP2.SessionError) -> WebAuthn.Extension.PRF
        func makePRF(
            evalByCredential: [Data: (first: Data, second: Data?)]
        ) async throws(CTAP2.SessionError) -> WebAuthn.Extension.PRF

        // credProtect
        func makeCredProtect(
            level: WebAuthn.Extension.CredProtect.Policy,
            enforce: Bool
        ) async throws(CTAP2.SessionError) -> CTAP2.Extension.CredProtect

        // credBlob
        func makeCredBlob() async throws(CTAP2.SessionError) -> CTAP2.Extension.CredBlob

        // minPinLength
        func isMinPinLengthSupported() async throws(CTAP2.SessionError) -> Bool
        func makeMinPinLength() async throws(CTAP2.SessionError) -> CTAP2.Extension.MinPinLength

        // largeBlob
        func makeLargeBlobKey() async throws(CTAP2.SessionError) -> CTAP2.Extension.LargeBlobKey
        func isLargeBlobSupported() async throws(CTAP2.SessionError) -> Bool
        func getBlob(key: Data) async throws(CTAP2.SessionError) -> Data?
        func putBlob(key: Data, data: Data, token: CTAP2.Token) async throws(CTAP2.SessionError)

        // previewSign
        func makePreviewSign() async throws(CTAP2.SessionError) -> CTAP2.Extension.PreviewSign

        // thirdPartyPayment
        func makeThirdPartyPayment() async throws(CTAP2.SessionError) -> CTAP2.Extension.ThirdPartyPayment
    }
}

// MARK: - Default Implementations

extension WebAuthn.Backend {

    func getPinUVToken(
        using method: CTAP2.ClientPin.Method,
        permissions: CTAP2.ClientPin.Permission,
        rpId: String?
    ) async throws(CTAP2.SessionError) -> CTAP2.Token {
        try await getPinUVTokenUpdates(using: method, permissions: permissions, rpId: rpId).value
    }
}

// MARK: - CTAP2.Session Conformance

extension CTAP2.Session: WebAuthn.Backend {

    func getPinRetries() async throws(CTAP2.SessionError) -> CTAP2.ClientPin.GetRetries.Response {
        try await getPinRetries(protocol: nil)
    }

    func getUVRetries() async throws(CTAP2.SessionError) -> Int {
        try await getUVRetries(protocol: nil)
    }

    func getPinUVTokenUpdates(
        using method: CTAP2.ClientPin.Method,
        permissions: CTAP2.ClientPin.Permission,
        rpId: String?
    ) async throws(CTAP2.SessionError) -> CTAP2.StatusStream<CTAP2.Token> {
        try await getPinUVTokenUpdates(using: method, permissions: permissions, rpId: rpId, protocol: nil)
    }

    // MARK: - Extensions

    // PRF (hmac-secret)
    func makePRF() async throws(CTAP2.SessionError) -> WebAuthn.Extension.PRF {
        try await WebAuthn.Extension.PRF(session: self)
    }
    func makePRF(
        first: Data,
        second: Data?,
        evalByCredential: [Data: (first: Data, second: Data?)]
    ) async throws(CTAP2.SessionError) -> WebAuthn.Extension.PRF {
        try await WebAuthn.Extension.PRF(
            first: first,
            second: second,
            evalByCredential: evalByCredential,
            session: self
        )
    }
    func makePRF(
        evalByCredential: [Data: (first: Data, second: Data?)]
    ) async throws(CTAP2.SessionError) -> WebAuthn.Extension.PRF {
        try await WebAuthn.Extension.PRF(evalByCredential: evalByCredential, session: self)
    }

    // credProtect
    func makeCredProtect(
        level: WebAuthn.Extension.CredProtect.Policy,
        enforce: Bool
    ) async throws(CTAP2.SessionError) -> CTAP2.Extension.CredProtect {
        try await CTAP2.Extension.CredProtect(level: level, session: self, enforce: enforce)
    }

    // credBlob
    func makeCredBlob() async throws(CTAP2.SessionError) -> CTAP2.Extension.CredBlob {
        try await CTAP2.Extension.CredBlob(session: self)
    }

    // minPinLength
    func isMinPinLengthSupported() async throws(CTAP2.SessionError) -> Bool {
        try await CTAP2.Extension.MinPinLength.isSupported(by: self)
    }
    func makeMinPinLength() async throws(CTAP2.SessionError) -> CTAP2.Extension.MinPinLength {
        try await CTAP2.Extension.MinPinLength(session: self)
    }

    // largeBlob
    func makeLargeBlobKey() async throws(CTAP2.SessionError) -> CTAP2.Extension.LargeBlobKey {
        try await CTAP2.Extension.LargeBlobKey(session: self)
    }
    func isLargeBlobSupported() async throws(CTAP2.SessionError) -> Bool {
        try await CTAP2.Extension.LargeBlobKey.isSupported(by: self)
    }

    // previewSign
    func makePreviewSign() async throws(CTAP2.SessionError) -> CTAP2.Extension.PreviewSign {
        try await CTAP2.Extension.PreviewSign(session: self)
    }

    // thirdPartyPayment
    func makeThirdPartyPayment() async throws(CTAP2.SessionError) -> CTAP2.Extension.ThirdPartyPayment {
        try await CTAP2.Extension.ThirdPartyPayment(session: self)
    }
}

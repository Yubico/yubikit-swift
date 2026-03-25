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

        func getPinUVToken(
            using method: CTAP2.ClientPin.Method,
            permissions: CTAP2.ClientPin.Permission,
            rpId: String?
        ) async throws(CTAP2.SessionError) -> CTAP2.Token

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

    func getPinUVToken(
        using method: CTAP2.ClientPin.Method,
        permissions: CTAP2.ClientPin.Permission,
        rpId: String?
    ) async throws(CTAP2.SessionError) -> CTAP2.Token {
        try await getPinUVToken(using: method, permissions: permissions, rpId: rpId, protocol: nil)
    }
}

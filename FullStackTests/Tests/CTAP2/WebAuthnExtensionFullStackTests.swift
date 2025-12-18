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
import Testing
import YubiKit

/// WebAuthn Extension Full Stack Tests
///
/// These tests mirror Python's `test_prf` and `test_prf_mc` from
/// `tests/device/test_prf.py` in the python-fido2 library.
@Suite("WebAuthn Extension Full Stack Tests", .serialized)
struct WebAuthnExtensionFullStackTests {

    // MARK: - PRF Extension Tests (mirrors Python's test_prf)

    @Test("PRF - Enable at MakeCredential and Derive Secrets at GetAssertion")
    func testPRF() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session
            guard try await CTAP2.Extension.HmacSecret.isSupported(by: session) else {
                print("Device doesn't support hmac-secret - skipping PRF test")
                return
            }

            let info = try await session.getInfo()
            guard info.options.clientPin == true else {
                print("PIN not set - skipping PRF test")
                return
            }

            let rpId = "prf-test.example.com"
            let clientDataHash = Data(repeating: 0xCD, count: 32)

            // 1. Create a credential with PRF enabled (via hmac-secret) (requires UP)
            session = try await reconnectWhenOverNFC()

            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential],
                rpId: rpId
            )

            let hmacSecret = CTAP2.Extension.HmacSecret()
            let hmacSecretInput = hmacSecret.makeCredential.input()

            let makeCredParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "PRF Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x60, count: 32),
                    name: "prf@test.com",
                    displayName: "PRF User"
                ),
                pubKeyCredParams: [.es256],
                extensions: [hmacSecretInput],
                options: .init(rk: true)
            )

            print("👆 Touch the YubiKey to create credential with PRF support...")
            let makeCredResponse = try await session.makeCredential(
                parameters: makeCredParams,
                pinToken: pinToken
            ).value

            // Verify hmac-secret is enabled (PRF enabled = hmac-secret enabled)
            let hmacResult = try hmacSecret.makeCredential.output(from: makeCredResponse)
            if case .enabled = hmacResult {
                print("✅ PRF enabled")
            }

            guard let attestedData = makeCredResponse.authenticatorData.attestedCredentialData else {
                Issue.record("Missing attested credential data")
                return
            }
            let credentialId = attestedData.credentialId
            print("✅ Credential created")

            // 2. Authenticate with PRF using one secret (requires UP)
            session = try await reconnectWhenOverNFC()

            let secret1 = Data(repeating: 0xAA, count: 32)

            let prf = try await WebAuthn.Extension.PRF(session: session)
            let prfInput1 = try prf.getAssertion.input(first: secret1)

            let pinToken2 = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.getAssertion],
                rpId: rpId
            )

            let getAssertionParams1 = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash,
                allowList: [.init(id: credentialId)],
                extensions: [prfInput1],
                options: .init(up: true)
            )

            print("👆 Touch the YubiKey for PRF assertion (one secret)...")
            let assertionResponse1 = try await session.getAssertion(
                parameters: getAssertionParams1,
                pinToken: pinToken2
            ).value

            guard let secrets1 = try prf.getAssertion.output(from: assertionResponse1) else {
                Issue.record("Expected PRF output in first assertion")
                return
            }
            #expect(secrets1.first.count == 32)
            print("✅ PRF secrets.first: \(secrets1.first.prefix(8).hexEncodedString)...")

            // 3. Authenticate again with two secrets using evalByCredential (requires UP)
            session = try await reconnectWhenOverNFC()

            let secret2 = Data(repeating: 0xBB, count: 32)

            let prf2 = try await WebAuthn.Extension.PRF(
                first: secret1,
                second: secret2,
                evalByCredential: [credentialId: (first: secret1, second: secret2)],
                session: session
            )

            let prfInput2 = try prf2.getAssertion.input(for: credentialId)

            let pinToken3 = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.getAssertion],
                rpId: rpId
            )

            let getAssertionParams2 = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash,
                allowList: [.init(id: credentialId)],
                extensions: [prfInput2],
                options: .init(up: true)
            )

            print("👆 Touch the YubiKey for PRF assertion (two secrets, evalByCredential)...")
            let assertionResponse2 = try await session.getAssertion(
                parameters: getAssertionParams2,
                pinToken: pinToken3
            ).value

            guard let secrets2 = try prf2.getAssertion.output(from: assertionResponse2) else {
                Issue.record("Expected PRF output in second assertion")
                return
            }

            // Same secret1 should produce same output
            #expect(secrets2.first == secrets1.first, "Same secret should produce same output")
            // Second output should be different
            #expect(secrets2.second != nil, "Should have second output")
            #expect(secrets2.second != secrets2.first, "Different secrets should produce different outputs")

            print("✅ PRF evalByCredential results:")
            print("   first:  \(secrets2.first.prefix(8).hexEncodedString)... (matches previous)")
            print("   second: \(secrets2.second?.prefix(8).hexEncodedString ?? "nil")...")
        }
    }

    // MARK: - PRF MC Extension Tests (mirrors Python's test_prf_mc)

    @Test("PRF MC - Derive Secrets at MakeCredential (CTAP2.2)")
    func testPRFMakeCredential() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session
            let info = try await session.getInfo()

            // hmac-secret-mc requires CTAP 2.2
            guard info.extensions.contains(.hmacSecretMC) else {
                print("Device doesn't support hmac-secret-mc (CTAP2.2) - skipping PRF MC test")
                return
            }

            guard info.options.clientPin == true else {
                print("PIN not set - skipping PRF MC test")
                return
            }

            let rpId = "prf-mc-test.example.com"
            let clientDataHash = Data(repeating: 0xCD, count: 32)

            // Generate PRF secrets
            let secret1 = Data(repeating: 0xCC, count: 32)
            let secret2 = Data(repeating: 0xDD, count: 32)

            // 1. Create credential with PRF secrets (requires UP)
            session = try await reconnectWhenOverNFC()

            let prf = try await WebAuthn.Extension.PRF(session: session)
            let prfMcInput = try prf.makeCredential.input(first: secret1, second: secret2)

            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential],
                rpId: rpId
            )

            let makeCredParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "PRF MC Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x70, count: 32),
                    name: "prf-mc@test.com",
                    displayName: "PRF MC User"
                ),
                pubKeyCredParams: [.es256],
                extensions: [prfMcInput],
                options: .init(rk: true)
            )

            print("👆 Touch the YubiKey to create credential with PRF secrets...")
            let makeCredResponse = try await session.makeCredential(
                parameters: makeCredParams,
                pinToken: pinToken
            ).value

            // Verify we got secrets back at registration
            guard let result = try prf.makeCredential.output(from: makeCredResponse) else {
                Issue.record("Expected PRF response")
                return
            }

            guard case .secrets(let mcSecrets) = result else {
                Issue.record("Expected .secrets result from PRF at MakeCredential")
                return
            }

            #expect(mcSecrets.first.count == 32)
            #expect(mcSecrets.second?.count == 32)
            print("✅ PRF MakeCredential derived secrets:")
            print("   first:  \(mcSecrets.first.prefix(8).hexEncodedString)...")
            print("   second: \(mcSecrets.second?.prefix(8).hexEncodedString ?? "nil")...")

            guard let attestedData = makeCredResponse.authenticatorData.attestedCredentialData else {
                Issue.record("Missing attested credential data")
                return
            }
            let credentialId = attestedData.credentialId

            // 2. Authenticate with the same secrets and verify determinism (requires UP)
            session = try await reconnectWhenOverNFC()

            let prfGa = try await WebAuthn.Extension.PRF(session: session)
            let prfGaInput = try prfGa.getAssertion.input(first: secret1, second: secret2)

            let pinToken2 = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.getAssertion],
                rpId: rpId
            )

            let getAssertionParams = CTAP2.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash,
                allowList: [.init(id: credentialId)],
                extensions: [prfGaInput],
                options: .init(up: true)
            )

            print("👆 Touch the YubiKey for PRF assertion (verifying determinism)...")
            let assertionResponse = try await session.getAssertion(
                parameters: getAssertionParams,
                pinToken: pinToken2
            ).value

            guard let gaSecrets = try prfGa.getAssertion.output(from: assertionResponse) else {
                Issue.record("Expected PRF output in assertion")
                return
            }

            // Outputs should match what we got at MakeCredential
            #expect(gaSecrets == mcSecrets, "GetAssertion secrets should match MakeCredential secrets")

            print("✅ PRF outputs are deterministic:")
            print("   MakeCredential first:  \(mcSecrets.first.prefix(8).hexEncodedString)...")
            print("   GetAssertion first:    \(gaSecrets.first.prefix(8).hexEncodedString)...")
            print("   Match: \(gaSecrets == mcSecrets)")
        }
    }
}

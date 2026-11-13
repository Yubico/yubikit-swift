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

@_spi(YubiInternal) @testable import YubiKit

@Suite("WebAuthn UV cancellation")
struct WebAuthnUVCancellationTests {
    private static let options = WebAuthn.Authentication.Options(
        challenge: Data(repeating: 0x01, count: 32),
        rpId: "example.com",
        userVerification: .required
    )

    @Test("cancel without fallback aborts ceremony with .cancelled")
    func testCancelAbortsCeremony() async throws {
        let mock = MockCTAP2Backend()
        mock.onGetInfo = { .stub(clientPin: true, userVerification: true, pinUvAuthToken: true) }
        mock.onGetUVRetries = { 3 }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }

        let gate = Promise<Void>()
        let pinAttempts = Box(0)
        mock.onGetPinUVTokenUpdates = { method, _, _ in
            switch method {
            case .uv:
                return uvWaitingStream(gate: gate)
            case .pin:
                pinAttempts.value += 1
                return .mocked(
                    .finished(CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2))
                )
            }
        }
        mock.onGetAssertion = { _ in .mocked(.finished(.stub(credentialId: Data([0xAA])))) }

        let client = try WebAuthn.Client.make(backend: mock)
        let auth = WebAuthn.Authorization(providePIN: { .pin("1234") }, uv: .preferred)
        let stream = await client.getAssertion(Self.options, authorization: auth)

        var caught: WebAuthn.ClientError?
        do throws(WebAuthn.ClientError) {
            for try await status in stream {
                if case .waitingForUserVerification(let cancel, _) = status {
                    await cancel()
                }
            }
        } catch {
            caught = error
        }

        guard case .cancelled = caught else {
            Issue.record("Expected .cancelled, got \(String(describing: caught))")
            return
        }
        #expect(pinAttempts.value == 0, "PIN path must not run after a plain cancel")
    }
}

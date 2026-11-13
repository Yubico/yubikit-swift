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

@Suite("WebAuthn ceremony cancellation")
struct WebAuthnCeremonyCancellationTests {
    private let registrationOptions = WebAuthn.Registration.Options(
        challenge: Data(repeating: 0x01, count: 32),
        rp: .init(id: "example.com", name: "Example RP"),
        user: .init(id: Data(repeating: 0x02, count: 32), name: "user@example.com", displayName: "User"),
        residentKey: .discouraged
    )

    @Test("cancelling makeCredential from the status stream stops the ceremony")
    func testCancelMakeCredential() async throws {
        let mock = MockCTAP2Backend()
        mock.onGetInfo = { .stub(clientPin: true, pinUvAuthToken: true) }
        mock.onGetPinRetries = { .init(retries: 8, powerCycleState: false) }
        mock.onGetUVRetries = { 0 }
        mock.onGetPinUVToken = { _, _, _ throws(CTAP2.SessionError) in
            CTAP2.Token(token: Data(repeating: 0, count: 32), protocolVersion: .v2)
        }
        mock.onMakeCredential = { _ in
            CTAP2.StatusStream { continuation in
                Task {
                    continuation.yield(
                        .waitingForUser(cancel: {
                            continuation.yield(error: .ctapError(.keepaliveCancel, source: .here()))
                        })
                    )
                }
            }
        }

        let client = try WebAuthn.Client.make(backend: mock)

        var caught: WebAuthn.ClientError?
        var reachedFinished = false
        do throws(WebAuthn.ClientError) {
            for try await status in await client.makeCredential(registrationOptions, authorization: .pin("1234")) {
                switch status {
                case .waitingForUser(let cancel):
                    await cancel()
                case .finished:
                    reachedFinished = true
                default:
                    break
                }
            }
        } catch {
            caught = error
        }

        #expect(!reachedFinished, "makeCredential should have been cancelled before finishing")
        guard case .cancelled = caught else {
            Issue.record("Expected cancelled, got \(String(describing: caught))")
            return
        }
    }
}

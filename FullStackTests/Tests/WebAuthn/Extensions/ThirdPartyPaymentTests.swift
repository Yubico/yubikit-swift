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

@testable import YubiKit

@Suite("WebAuthn ThirdPartyPayment Extension Tests", .serialized)
struct WebAuthnThirdPartyPaymentExtensionTests {

    @Test(
        "ThirdPartyPayment - Echoed false when credential not registered as payment",
        arguments: [true, false]
    )
    func testEchoedFalseWithoutRegistration(discoverable: Bool) async throws {
        try await runTest(registerWithPayment: false, discoverable: discoverable, expectedEcho: false)
    }

    @Test(
        "ThirdPartyPayment - Echoed true when credential registered as payment",
        arguments: [true, false]
    )
    func testEchoedTrueWithRegistration(discoverable: Bool) async throws {
        try await runTest(registerWithPayment: true, discoverable: discoverable, expectedEcho: true)
    }

    private func runTest(
        registerWithPayment: Bool,
        discoverable: Bool,
        expectedEcho: Bool
    ) async throws {
        try await withReconnectableWebAuthnClient { client, session, reconnect in
            var client = client

            guard try await CTAP2.Extension.ThirdPartyPayment.isSupported(by: session) else {
                print("thirdPartyPayment not supported - skipping")
                return
            }

            let rpId = "example.com"

            let createOptions = WebAuthn.Registration.Options(
                challenge: randomBytes(count: 32),
                rp: .init(id: rpId, name: "ThirdPartyPayment Test"),
                user: .init(
                    id: randomBytes(count: 32),
                    name: "tpp@example.com",
                    displayName: "TPP User"
                ),
                residentKey: discoverable ? .required : .discouraged,
                userVerification: .discouraged,
                extensions: registerWithPayment
                    ? .init(thirdPartyPayment: .enabled)
                    : nil
            )

            let createResponse = try await client.makeCredential(createOptions, authorization: .pin(defaultTestPin))
                .value

            client = try await reconnect().client

            let authOptions = WebAuthn.Authentication.Options(
                challenge: randomBytes(count: 32),
                rpId: rpId,
                allowCredentials: discoverable ? [] : [.init(id: createResponse.credentialId)],
                extensions: .init(thirdPartyPayment: .enabled)
            )

            let authResponse = try await client.getAssertion(authOptions, authorization: .pin(defaultTestPin))
                .value[0]

            let echoedBit = authResponse.clientExtensionResults.thirdPartyPayment?.isPaymentEnabled
            #expect(echoedBit == expectedEcho)
        }
    }
}

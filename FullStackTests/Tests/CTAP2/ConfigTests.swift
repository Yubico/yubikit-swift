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

@Suite("AuthenticatorConfig Full Stack Tests", .serialized)
struct ConfigFullStackTests {

    // MARK: - Support Check

    @Test("Check authenticatorConfig support")
    func testConfigSupport() async throws {
        try await withCTAP2Session { session in
            let info = try await session.getInfo()
            let isSupported = info.options.authenticatorConfig == true

            if isSupported {
                print("✅ authenticatorConfig is supported")
            } else {
                print("ℹ️ authenticatorConfig is not supported by this authenticator")
            }
        }
    }

    // MARK: - Toggle AlwaysUV

    @Test("Toggle alwaysUV setting")
    func testToggleAlwaysUV() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session

            let info = try await session.getInfo()
            guard info.options.authenticatorConfig == true else {
                print("authenticatorConfig not supported - skipping")
                return
            }

            guard info.options.alwaysUV != nil else {
                print("alwaysUV option not supported - skipping")
                return
            }

            let initialAlwaysUV = info.options.alwaysUV ?? false

            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.authenticatorConfig]
            )

            let config = session.config(pinToken: pinToken)
            try await config.toggleAlwaysUV()

            let newInfo = try await session.getInfo()
            let newAlwaysUV = newInfo.options.alwaysUV ?? false
            #expect(newAlwaysUV != initialAlwaysUV, "alwaysUV should have toggled")
            print("✅ alwaysUV toggled from \(initialAlwaysUV) to \(newAlwaysUV)")

            // Reconnect if over NFC before second toggle
            session = try await reconnectWhenOverNFC()

            // Toggle back to restore original state
            let pinToken2 = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.authenticatorConfig]
            )
            try await session.config(pinToken: pinToken2).toggleAlwaysUV()

            let restoredInfo = try await session.getInfo()
            let restoredAlwaysUV = restoredInfo.options.alwaysUV ?? false
            #expect(restoredAlwaysUV == initialAlwaysUV, "alwaysUV should be restored")
            print("✅ alwaysUV restored to \(restoredAlwaysUV)")
        }
    }

    // MARK: - Enterprise Attestation

    @Test("Enable enterprise attestation")
    func testEnableEnterpriseAttestation() async throws {
        try await withCTAP2Session { session in
            let info = try await session.getInfo()
            guard info.options.authenticatorConfig == true else {
                print("authenticatorConfig not supported - skipping")
                return
            }

            guard info.options.enterpriseAttestation != nil else {
                print("Enterprise attestation not supported - skipping")
                return
            }

            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.authenticatorConfig]
            )

            try await session.config(pinToken: pinToken).enableEnterpriseAttestation()

            let newInfo = try await session.getInfo()
            #expect(newInfo.options.enterpriseAttestation == true)
            print("✅ Enterprise attestation enabled")
        }
    }

    @Test(
        "Set force PIN change",
        .disabled("Destructive - requires PIN change or reset to restore")
    )
    func testSetForcePinChange() async throws {
        try await withCTAP2Session { session in
            let info = try await session.getInfo()
            guard info.options.authenticatorConfig == true else {
                print("authenticatorConfig not supported - skipping")
                return
            }

            guard info.forcePinChange != true else {
                print("Force PIN change already set - reset key and retry")
                return
            }

            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.authenticatorConfig]
            )

            try await session.config(pinToken: pinToken).setMinPINLength(forceChangePin: true)

            let newInfo = try await session.getInfo()
            #expect(newInfo.forcePinChange == true)
            print("✅ Force PIN change set - reset authenticator to restore")
        }
    }

    @Test(
        "Set minimum PIN length",
        .disabled("Destructive - minPinLength can only increase, requires reset to restore")
    )
    func testSetMinPinLength() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session

            let info = try await session.getInfo()
            guard info.options.authenticatorConfig == true else {
                print("authenticatorConfig not supported - skipping")
                return
            }

            guard let currentMinPinLength = info.minPinLength else {
                print("minPinLength not reported - skipping")
                return
            }

            guard let maxPinLength = info.maxPINLength else {
                print("maxPINLength not reported - skipping")
                return
            }

            let newMinPinLength = currentMinPinLength + 1
            guard newMinPinLength <= maxPinLength else {
                print("Cannot increase minPinLength (\(currentMinPinLength) near max \(maxPinLength)) - skipping")
                return
            }

            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.authenticatorConfig]
            )

            try await session.config(pinToken: pinToken).setMinPINLength(newMinPINLength: newMinPinLength)

            let newInfo = try await session.getInfo()
            #expect(newInfo.minPinLength == newMinPinLength)
            print("✅ minPinLength increased from \(currentMinPinLength) to \(newMinPinLength)")

            // Reconnect if over NFC before second operation
            session = try await reconnectWhenOverNFC()

            // Verify we cannot decrease it (spec requirement)
            let pinToken2 = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.authenticatorConfig]
            )

            do {
                try await session.config(pinToken: pinToken2).setMinPINLength(newMinPINLength: currentMinPinLength)
                Issue.record("Should not be able to decrease minPinLength")
            } catch is CTAP2.SessionError {
                print("✅ Decreasing minPinLength correctly rejected")
            }

            print("✅ Test complete - reset authenticator to restore default minPinLength")
        }
    }

    // MARK: - MinPinLength Extension Integration

    @Test("Configure minPinLength RP IDs for extension")
    func testSetMinPinLengthRPIDs() async throws {
        try await withReconnectableCTAP2Session { session, reconnectWhenOverNFC in
            var session = session

            let info = try await session.getInfo()
            guard info.options.authenticatorConfig == true else {
                print("authenticatorConfig not supported - skipping")
                return
            }

            guard info.options.setMinPINLength == true else {
                print("setMinPINLength not supported - skipping")
                return
            }

            let rpId = "minpinlength-config-test.example.com"

            // Configure RP ID to receive minPinLength
            let configToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.authenticatorConfig]
            )
            let config = session.config(pinToken: configToken)
            try await config.setMinPINLength(rpIDs: [rpId])
            print("✅ Configured RP ID for minPinLength extension")

            // Reconnect if over NFC before makeCredential
            session = try await reconnectWhenOverNFC()

            // Now create a credential with minPinLength extension
            let minPinLength = try await CTAP2.Extension.MinPinLength(session: session)

            let makeCredToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.makeCredential],
                rpId: rpId
            )

            let makeCredParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: Data(repeating: 0xCD, count: 32),
                rp: WebAuthn.PublicKeyCredential.RPEntity(id: rpId, name: "Config Test"),
                user: WebAuthn.PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x01, count: 32),
                    name: "config@test.com",
                    displayName: "Config Test User"
                ),
                pubKeyCredParams: [.es256],
                extensions: [minPinLength.makeCredential.input()]
            )

            print("👆 Touch YubiKey: creating credential with minPinLength extension...")
            let credential = try await session.makeCredential(
                parameters: makeCredParams,
                pinToken: makeCredToken
            ).value

            // Now the extension should return a value since RP is configured
            let length = minPinLength.makeCredential.output(from: credential)

            if let length {
                #expect(length >= 4, "minPinLength should be at least 4")
                print("✅ minPinLength extension returned: \(length)")

                if let infoMinPinLength = info.minPinLength {
                    #expect(length == infoMinPinLength, "Should match info.minPinLength")
                }
            } else {
                // This might happen if the RP ID list was already full or other edge cases
                print("⚠️ minPinLength not returned (unexpected)")
            }
        }
    }
}

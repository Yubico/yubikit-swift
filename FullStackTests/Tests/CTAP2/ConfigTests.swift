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
            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.authenticatorConfig]
            )

            do {
                _ = try await session.config(token: pinToken)
                print("✅ authenticatorConfig is supported")
            } catch CTAP2.SessionError.featureNotSupported {
                print("ℹ️ authenticatorConfig is not supported by this authenticator")
            }
        }
    }

    // MARK: - Toggle AlwaysUV

    @Test("Toggle alwaysUV setting")
    func testToggleAlwaysUV() async throws {
        try await withCTAP2Session { session in
            let info = try await session.getInfo()
            guard info.options.authenticatorConfig == true else {
                print("authenticatorConfig not supported - skipping")
                return
            }

            guard info.options.supportsAlwaysUV else {
                print("alwaysUV option not supported - skipping")
                return
            }

            let initialAlwaysUV = info.options.alwaysUV ?? false

            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.authenticatorConfig]
            )

            let config = try await session.config(token: pinToken)
            try await config.toggleAlwaysUV()

            let newInfo = try await session.getInfo()
            let newAlwaysUV = newInfo.options.alwaysUV ?? false
            #expect(newAlwaysUV != initialAlwaysUV, "alwaysUV should have toggled")
            print("✅ alwaysUV toggled from \(initialAlwaysUV) to \(newAlwaysUV)")

            // Toggle back to restore original state
            try await config.toggleAlwaysUV()

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

            guard info.options.supportsEnterpriseAttestation else {
                print("Enterprise attestation not supported - skipping")
                return
            }

            let pinToken = try await session.getPinUVToken(
                using: .pin(defaultTestPin),
                permissions: [.authenticatorConfig]
            )

            try await session.config(token: pinToken).enableEnterpriseAttestation()

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

            try await session.config(token: pinToken).setMinPINLength(forceChangePin: true)

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
        try await withCTAP2Session { session in
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

            let config = try await session.config(token: pinToken)
            try await config.setMinPINLength(newMinPINLength: newMinPinLength)

            let newInfo = try await session.getInfo()
            #expect(newInfo.minPinLength == newMinPinLength)
            print("✅ minPinLength increased from \(currentMinPinLength) to \(newMinPinLength)")

            // Verify we cannot decrease it (spec requirement)
            do {
                try await config.setMinPINLength(newMinPINLength: currentMinPinLength)
                Issue.record("Should not be able to decrease minPinLength")
            } catch is CTAP2.SessionError {
                print("✅ Decreasing minPinLength correctly rejected")
            }

            print("✅ Test complete - reset authenticator to restore default minPinLength")
        }
    }
}

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

@testable import FullStackTests
@testable import YubiKit

private let defaultPIN = "123456"

@Suite("BIO Full Stack Tests", .serialized, .timeLimit(.minutes(10)))
struct BIOFullStackTests {

    // MARK: - PIV Bio Authentication Tests

    // This will test auth on a YubiKey Bio. To run the test at least one fingerprint needs to be registered.
    @Test("Bio Authentication")
    func bioAuthentication() async throws {
        // First check if it's a bio device
        let connection = try await TestableConnection.shared()
        let managementSession = try await ManagementSession.session(withConnection: connection)
        let deviceInfo = try await managementSession.getDeviceInfo()
        guard deviceInfo.formFactor == .usbCBio || deviceInfo.formFactor == .usbABio else {
            reportSkip(reason: "Not a YubiKey Bio device")
            return
        }

        // Now use runPIVTest for proper session reset
        let pivTests = PIVFullStackTests()
        try await pivTests.runPIVTest { session in
            var bioMetadata = try await session.getBioMetadata()
            guard bioMetadata.isConfigured else {
                reportSkip(reason: "No fingerprints enrolled")
                return
            }
            #expect(bioMetadata.attemptsRemaining > 0)
            var verifyResult = try await session.verifyUv(requestTemporaryPin: false, checkOnly: false)
            #expect(verifyResult == nil)
            trace("verifyUV() passed")
            guard let pinData = try await session.verifyUv(requestTemporaryPin: true, checkOnly: false) else {
                reportSkip(reason: "Pin data returned was nil. Expected a value.")
                return
            }
            trace("got temporary pin: \(pinData.hexEncodedString).")
            bioMetadata = try await session.getBioMetadata()
            #expect(bioMetadata.temporaryPin == true)
            trace("temporary pin reported as set.")
            verifyResult = try await session.verifyUv(requestTemporaryPin: false, checkOnly: true)
            #expect(verifyResult == nil)
            trace("verifyUv successful.")
            try await session.verifyTemporaryPin(pinData)
            trace("temporary pin verified.")
        }
    }

    // MARK: - Management Bio Tests

    @Test("Bio device reset")
    func bioDeviceReset() async throws {
        try await runManagementTest { connection, session, transport in
            let deviceInfo = try await session.getDeviceInfo()
            guard deviceInfo.formFactor == .usbCBio || deviceInfo.formFactor == .usbABio else {
                reportSkip(reason: "Not a YubiKey Bio device")
                return
            }
            try await session.deviceReset()
            var pivSession = try await PIVSession.session(withConnection: connection)
            var pinMetadata = try await pivSession.getPinMetadata()
            #expect(pinMetadata.isDefault)
            try await pivSession.setPin("654321", oldPin: "123456")
            pinMetadata = try await pivSession.getPinMetadata()
            #expect(!pinMetadata.isDefault)
            let managementSession = try await ManagementSession.session(withConnection: connection)
            try await managementSession.deviceReset()
            pivSession = try await PIVSession.session(withConnection: connection)
            pinMetadata = try await pivSession.getPinMetadata()
            #expect(pinMetadata.isDefault)
        }
    }
}

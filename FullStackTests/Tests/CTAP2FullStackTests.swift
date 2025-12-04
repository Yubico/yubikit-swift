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

@Suite("CTAP2 Full Stack Tests", .serialized)
struct CTAP2FullStackTests {

    // MARK: - Core Tests

    @Test("Get Authenticator Info")
    func testGetAuthenticatorInfo() async throws {
        try await withCTAP2Session { session in
            let info = try await session.getInfo()

            // Check versions contain a recognized FIDO version
            let hasRecognizedVersion = info.versions.contains { version in
                switch version {
                case .u2fV2, .fido2_0, .fido2_1Pre, .fido2_1: return true
                case .unknown: return false
                }
            }
            #expect(hasRecognizedVersion, "Should support a recognized FIDO version")

            // Check options
            #expect(info.options.platformDevice == false, "Option 'plat' should be false")
            #expect(info.options.residentKey == true, "Option 'rk' should be true")
            #expect(info.options.userPresence == true, "Option 'up' should be true")

            // Check PIN/UV Auth protocols
            #expect(info.pinUVAuthProtocols.count >= 1, "Should support at least one PIN protocol")
        }
    }

    @Test("Make Credential and Get Assertion")
    func testMakeCredentialGetAssertion() async throws {
        try await withCTAP2Session { session in
            let clientDataHash = Data(repeating: 0xCD, count: 32)

            // 1. Make a non-resident credential
            let nonRkParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredential.RPEntity(id: "example.com", name: "Example Corp"),
                user: PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x02, count: 32),
                    name: "nonrk@example.com",
                    displayName: "Non-RK User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: false)
            )

            print("👆 Touch the YubiKey to create a non-resident credential...")
            let nonRkCredential = try await session.makeCredential(parameters: nonRkParams).value

            #expect(["packed", "none"].contains(nonRkCredential.format), "Expected packed or none format")
            #expect(nonRkCredential.authenticatorData.attestedCredentialData != nil, "Missing attested credential data")
            print("✅ Non-resident credential created")

            // 2. Make a resident credential
            let rkParams = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredential.RPEntity(id: "example.com", name: "Example Corp"),
                user: PublicKeyCredential.UserEntity(
                    id: Data(repeating: 0x03, count: 32),
                    name: "rk@example.com",
                    displayName: "RK User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: true)
            )

            print("👆 Touch the YubiKey to create a resident credential...")
            let rkCredential = try await session.makeCredential(parameters: rkParams).value

            guard rkCredential.authenticatorData.attestedCredentialData != nil else {
                Issue.record("Missing attested credential data for RK")
                return
            }
            print("✅ Resident credential created")

            // 3. Get assertion (discovers resident credentials)
            let getAssertionParams = CTAP2.GetAssertion.Parameters(
                rpId: "example.com",
                clientDataHash: clientDataHash
            )

            print("👆 Touch the YubiKey to authenticate...")
            let assertion = try await session.getAssertion(parameters: getAssertionParams).value

            #expect(assertion.authenticatorData.rpIdHash.count == 32)
            #expect(assertion.authenticatorData.flags.contains(.userPresent), "User presence flag should be set")
            #expect(assertion.signature.count > 0, "Signature should be present")
            #expect(assertion.user != nil, "User handle should be present for RK")
            print("✅ Get assertion successful! Signature length: \(assertion.signature.count) bytes")
        }
    }

    @Test("Selection - User Presence Check")
    func testSelection() async throws {
        try await withCTAP2Session { session in
            print("👆 Touch the YubiKey to confirm selection...")

            var receivedWaitingForUser = false
            for try await status in await session.selection() {
                switch status {
                case .processing:
                    print("Processing...")
                case .waitingForUser:
                    print("Waiting for user presence...")
                    receivedWaitingForUser = true
                case .finished:
                    print("Selection completed!")
                }
            }

            #expect(receivedWaitingForUser, "Should receive waitingForUser status during selection")
            print("✅ Selection command successful")
        }
    }

    #if os(macOS)
    @Test("Cancel MakeCredential")
    func testCancelMakeCredential() async throws {
        try await withCTAP2Session { session in
            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let userId = Data(repeating: 0x98, count: 32)

            let params = CTAP2.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredential.RPEntity(id: "example.com", name: "Example Corp"),
                user: PublicKeyCredential.UserEntity(
                    id: userId,
                    name: "cancel-test@example.com",
                    displayName: "Cancel Test User"
                ),
                pubKeyCredParams: [.es256]
            )

            print("DO NOT touch the YubiKey - operation will be cancelled...")

            do {
                for try await status in await session.makeCredential(parameters: params) {
                    switch status {
                    case .processing:
                        print("Processing...")
                    case .waitingForUser(let cancel):
                        print("Waiting for user - cancelling now!")
                        await cancel()
                    case .finished(let response):
                        Issue.record(
                            "makeCredential should have been cancelled but got response: \(String(describing: response))"
                        )
                    }
                }

                Issue.record("makeCredential should have thrown cancellation error")
            } catch let error as CTAP2.SessionError {
                // Verify we got the expected cancellation error
                guard case .ctapError(.keepaliveCancel, _) = error else {
                    Issue.record("Expected keepaliveCancel error, got: \(error)")
                    return
                }
                print("✅ Cancellation successful - received keepaliveCancel error")
            } catch {
                Issue.record("Unexpected error type: \(error)")
            }

            // Verify connection still works
            let info = try await session.getInfo()
            #expect(!info.versions.isEmpty)
            print("✅ Connection still functional")
        }
    }
    #endif

    // MARK: - ClientPIN Tests

    @Test(
        "ClientPIN - Setup: Ensure PIN is Set",
        arguments: [PinUVAuth.ProtocolVersion.v1, PinUVAuth.ProtocolVersion.v2]
    )
    func testClientPinSetup(pinProtocol: PinUVAuth.ProtocolVersion) async throws {
        try await withCTAP2Session { session in
            let testPin = "11234567"

            let info = try await session.getInfo()

            // Skip if device doesn't support clientPin
            guard info.options.clientPin != nil else {
                print("Device doesn't support clientPin - skipping")
                return
            }

            let pinIsSet = info.options.clientPin == true
            let pin = try await session.clientPIN(protocol: pinProtocol)
            if !pinIsSet {
                print("PIN not set, setting default PIN: \(testPin)")
                try await pin.set(testPin)
                print("✅ PIN set to default: \(testPin)")
            } else {
                print("PIN already set")
            }

            // Reset retry counter via successful PIN auth
            _ = try await pin.getToken(
                using: .pin(testPin),
                permissions: [.makeCredential],
                rpId: "localhost"
            )

            // Verify retries are reset to 8
            let pinRetriesResponse = try await pin.getRetries()
            #expect(pinRetriesResponse.retries == 8, "Should have 8 PIN retries after successful auth")
            print("✅ PIN retries: \(pinRetriesResponse.retries)")
        }
    }

    @Test(
        "ClientPIN - Change PIN and Verify Retry Counter",
        arguments: [PinUVAuth.ProtocolVersion.v1, PinUVAuth.ProtocolVersion.v2]
    )
    func testClientPinChangePin(pinProtocol: PinUVAuth.ProtocolVersion) async throws {
        try await withCTAP2Session { session in
            let testPin = "11234567"
            let otherPin = "76543211"

            let info = try await session.getInfo()

            // Skip if PIN is not set
            guard info.options.clientPin == true else {
                print("PIN not set - run testClientPinSetup first - skipping")
                return
            }

            let pin = try await session.clientPIN(protocol: pinProtocol)

            // Reset retries before testing
            _ = try await pin.getToken(
                using: .pin(testPin),
                permissions: [.makeCredential],
                rpId: "localhost"
            )

            let initialRetriesResponse = try await pin.getRetries()
            #expect(initialRetriesResponse.retries == 8, "Should start with 8 PIN retries")
            print("Protocol v\(pinProtocol.rawValue), retries: \(initialRetriesResponse.retries)")

            // Change PIN
            try await pin.change(from: testPin, to: otherPin)
            print("✅ PIN changed")

            // Old PIN should fail
            do {
                _ = try await pin.getToken(
                    using: .pin(testPin),
                    permissions: [.makeCredential, .getAssertion],
                    rpId: "localhost"
                )
                Issue.record("Old PIN should have been rejected")
            } catch let error as CTAP2.SessionError {
                guard case .ctapError(.pinInvalid, _) = error else {
                    Issue.record("Expected PIN_INVALID error, got: \(error)")
                    return
                }
                print("✅ Old PIN rejected")
            }

            let retriesAfterWrongPin = try await pin.getRetries()
            #expect(retriesAfterWrongPin.retries == 7, "Retries should decrement after wrong PIN")

            // New PIN should succeed and reset retries
            _ = try await pin.getToken(
                using: .pin(otherPin),
                permissions: [.makeCredential, .getAssertion],
                rpId: "localhost"
            )
            print("✅ New PIN accepted")

            let retriesAfterCorrectPin = try await pin.getRetries()
            #expect(retriesAfterCorrectPin.retries == 8, "Retries should reset after correct PIN")

            // Restore original PIN
            try await pin.change(from: otherPin, to: testPin)
            print("✅ PIN restored")
        }
    }

    @Test(
        "ClientPIN - Get Token Using UV (Biometrics)",
        arguments: [PinUVAuth.ProtocolVersion.v1, PinUVAuth.ProtocolVersion.v2]
    )
    func testClientPinGetTokenUsingUV(pinProtocol: PinUVAuth.ProtocolVersion) async throws {
        try await withCTAP2Session { session in
            let info = try await session.getInfo()
            let pin = try await session.clientPIN(protocol: pinProtocol)

            // If device doesn't support pinUvAuthToken, verify it throws featureNotSupported
            guard info.options.pinUVAuthToken == true else {
                do {
                    _ = try await pin.getToken(
                        using: .uv,
                        permissions: [.makeCredential, .getAssertion],
                        rpId: "example.com"
                    )
                    Issue.record("Should have thrown featureNotSupported")
                } catch let error as CTAP2.SessionError {
                    guard case .featureNotSupported = error else {
                        Issue.record("Expected featureNotSupported, got: \(error)")
                        return
                    }
                    print("✅ Correctly threw featureNotSupported on non-UV device")
                }
                return
            }

            // Skip if UV is not configured (no fingerprints enrolled)
            guard info.options.userVerification == true else {
                print("UV supported but not configured (no fingerprints enrolled) - skipping")
                return
            }

            print("👆 Touch the fingerprint sensor on YubiKey Bio...")
            let token = try await pin.getToken(
                using: .uv,
                permissions: [.makeCredential, .getAssertion],
                rpId: "example.com"
            )

            #expect(token.token.count > 0, "Token should not be empty")
            #expect(token.protocolVersion == pinProtocol, "Token protocol should match requested")
            print("✅ Got UV token, length: \(token.token.count) bytes")
        }
    }

    // MARK: - FIPS Tests

    @Test(
        "ClientPIN - PIN Complexity Enforcement",
        arguments: [PinUVAuth.ProtocolVersion.v1, PinUVAuth.ProtocolVersion.v2]
    )
    func testPinComplexity(pinProtocol: PinUVAuth.ProtocolVersion) async throws {
        try await withCTAP2Session { session in
            let testPin = "11234567"

            let info = try await session.getInfo()

            // Skip if device doesn't enforce PIN complexity
            guard info.pinComplexityPolicy == true else {
                print("Device doesn't enforce PIN complexity - skipping")
                return
            }

            let pin = try await session.clientPIN(protocol: pinProtocol)

            // Try weak PIN (repeated chars)
            do {
                try await pin.change(from: testPin, to: "33333333")
                Issue.record("Weak PIN should have been rejected")
            } catch let error as CTAP2.SessionError {
                guard case .ctapError(.pinPolicyViolation, _) = error else {
                    Issue.record("Expected PIN_POLICY_VIOLATION, got: \(error)")
                    return
                }
                print("✅ Weak PIN correctly rejected with PIN_POLICY_VIOLATION")
            }

            // Policy violation doesn't decrement retries
            let pinRetriesResponse = try await pin.getRetries()
            #expect(pinRetriesResponse.retries == 8)
            print("✅ PIN complexity enforced")
        }
    }

    // MARK: - Destructive Tests (Disabled)

    @Test(
        "ClientPIN - Retry Exhaustion and Soft-Lock",
        .disabled("Leaves YubiKey soft-locked - requires power cycle to unlock"),
        arguments: [PinUVAuth.ProtocolVersion.v1, PinUVAuth.ProtocolVersion.v2]
    )
    func testClientPinRetryExhaustion(pinProtocol: PinUVAuth.ProtocolVersion) async throws {
        try await withCTAP2Session { session in
            let testPin = "11234567"
            let wrongPin = "99999999"

            let info = try await session.getInfo()

            // Skip if PIN is not set
            guard info.options.clientPin == true else {
                print("PIN not set - skipping")
                return
            }

            let pin = try await session.clientPIN(protocol: pinProtocol)

            // Reset retries before testing
            _ = try await pin.getToken(
                using: .pin(testPin),
                permissions: [.makeCredential, .getAssertion],
                rpId: "localhost"
            )
            var retriesResponse = try await pin.getRetries()
            #expect(retriesResponse.retries == 8)

            // Make 3 wrong attempts: 8 → 7 → 6 → 5 (third attempt may soft-lock)
            for expectedRetries in [7, 6, 5] {
                do {
                    _ = try await pin.getToken(
                        using: .pin(wrongPin),
                        permissions: [.makeCredential, .getAssertion],
                        rpId: "localhost"
                    )
                    Issue.record("Wrong PIN should have been rejected")
                } catch let error as CTAP2.SessionError {
                    if case .ctapError(.pinInvalid, _) = error {
                        // Expected
                    } else if case .ctapError(.pinAuthBlocked, _) = error {
                        // Expected (soft-lock)
                    } else {
                        Issue.record("Expected PIN_INVALID or PIN_AUTH_BLOCKED, got: \(error)")
                    }
                }
                retriesResponse = try await pin.getRetries()
                #expect(retriesResponse.retries == expectedRetries)
            }

            // Soft-locked - counter should freeze
            let frozenRetries = retriesResponse.retries
            do {
                _ = try await pin.getToken(
                    using: .pin(wrongPin),
                    permissions: [.makeCredential, .getAssertion],
                    rpId: "localhost"
                )
                Issue.record("Wrong PIN should be blocked")
            } catch let error as CTAP2.SessionError {
                guard case .ctapError(.pinAuthBlocked, _) = error else {
                    Issue.record("Expected PIN_AUTH_BLOCKED, got: \(error)")
                    return
                }
            }
            retriesResponse = try await pin.getRetries()
            #expect(retriesResponse.retries == frozenRetries)

            // Even correct PIN is blocked
            do {
                _ = try await pin.getToken(
                    using: .pin(testPin),
                    permissions: [.makeCredential, .getAssertion],
                    rpId: "localhost"
                )
                Issue.record("Correct PIN should be blocked")
            } catch let error as CTAP2.SessionError {
                guard case .ctapError(.pinAuthBlocked, _) = error else {
                    Issue.record("Expected PIN_AUTH_BLOCKED, got: \(error)")
                    return
                }
            }
            retriesResponse = try await pin.getRetries()
            #expect(retriesResponse.retries == frozenRetries)
            print("⚠️ YubiKey soft-locked. Power cycle to unlock.")
        }
    }

    @Test(
        "Reset - Factory Reset",
        .disabled("Destructive - clears all credentials and PIN")
    )
    func testReset() async throws {
        try await withCTAP2Session { session in
            print("👆 Touch the YubiKey to confirm reset...")
            var receivedWaitingForUser = false
            for try await status in await session.reset() {
                print("Status: \(status)")
                if case .waitingForUser = status {
                    receivedWaitingForUser = true
                }
            }
            #expect(receivedWaitingForUser)
            print("✅ Reset successful")

            let info = try await session.getInfo()
            #expect(info.options.clientPin != true, "PIN should be cleared after reset")
        }
    }

    // MARK: - Helper Methods

    #if os(macOS)
    private func withCTAP2Session<T>(
        _ body: (FIDO2Session) async throws -> T
    ) async throws -> T {
        let connection = try await HIDFIDOConnection.makeConnection()
        let session = try await CTAP2.Session.makeSession(connection: connection)
        let result = try await body(session)
        await connection.close(error: nil)
        return result
    }

    #elseif os(iOS)
    private func withCTAP2Session<T>(
        _ body: (FIDO2SessionOverSmartCard) async throws -> T
    ) async throws -> T {
        let connection = try await TestableConnection.create(with: .nfc)
        let session = try await CTAP.Session.makeSession(connection: connection)
        let result = try await body(session)
        await connection.close(error: nil)
        return result
    }
    #endif
}

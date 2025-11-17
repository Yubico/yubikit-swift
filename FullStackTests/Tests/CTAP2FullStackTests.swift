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

    @Test("Get Authenticator Info")
    func getAuthenticatorInfo() async throws {
        try await withCTAP2Session { session in
            let info = try await session.getInfo()

            // Check versions contain a recognized FIDO version
            let hasRecognizedVersion = info.versions.contains { version in
                version == "U2F_V2" || version == "FIDO_2_0" || version == "FIDO_2_1_PRE" || version == "FIDO_2_1"
            }
            #expect(hasRecognizedVersion, "Should support a recognized FIDO version")

            // Check AAGUID is 16 bytes
            #expect(info.aaguid.count == 16, "AAGUID should be 16 bytes")

            // Check options
            #expect(info.options["plat"] == false, "Option 'plat' should be false")
            #expect(info.options["rk"] == true, "Option 'rk' should be true")
            #expect(info.options["up"] == true, "Option 'up' should be true")
            #expect(info.options.keys.contains("clientPin"), "Options should contain 'clientPin'")

            // Check PIN/UV Auth protocols
            #expect(info.pinUvAuthProtocols.count >= 1, "Should support at least one PIN protocol")
        }
    }

    @Test("Make Credential - Non-Resident Key")
    func testMakeCredentialNonResidentKey() async throws {
        try await withCTAP2Session { session in
            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let userId = Data(repeating: 0x02, count: 32)

            let params = CTAP.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredentialRPEntity(id: "example.com", name: "Example Corp"),
                user: PublicKeyCredentialUserEntity(
                    id: userId,
                    name: "nonrk@example.com",
                    displayName: "Non-RK User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: false)  // Explicitly non-resident
            )

            print("Touch the YubiKey to create a non-resident credential...")
            let credential = try await session.makeCredential(parameters: params)

            // Verify response structure
            #expect(["packed", "none"].contains(credential.format), "Expected packed or none format")
            #expect(credential.authenticatorData.rpIdHash.count == 32, "RP ID hash should be 32 bytes")
            #expect(
                credential.authenticatorData.flags.contains(.userPresent),
                "User presence flag should be set"
            )
            #expect(
                credential.authenticatorData.flags.contains(.attestedCredentialData),
                "Attested credential data flag should be set"
            )

            // Verify credential data exists
            guard let attestedData = credential.authenticatorData.attestedCredentialData else {
                Issue.record("Missing attested credential data")
                return
            }
            #expect(attestedData.credentialId.count >= 16, "Credential ID should be at least 16 bytes")
            print("Non-resident credential created! Format: \(credential.format)")
        }
    }

    @Test("Make Credential - Resident Key")
    func testMakeCredentialResidentKey() async throws {
        try await withCTAP2Session { session in
            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let userId = Data(repeating: 0x03, count: 32)

            let params = CTAP.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredentialRPEntity(id: "example.com", name: "Example Corp"),
                user: PublicKeyCredentialUserEntity(
                    id: userId,
                    name: "rk@example.com",
                    displayName: "RK User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: true)  // Resident key
            )

            print("Touch the YubiKey to create a resident credential...")
            let credential = try await session.makeCredential(parameters: params)

            // Verify response structure
            #expect(["packed", "none"].contains(credential.format), "Expected packed or none format")
            #expect(credential.authenticatorData.rpIdHash.count == 32, "RP ID hash should be 32 bytes")
            #expect(
                credential.authenticatorData.flags.contains(.userPresent),
                "User presence flag should be set"
            )
            #expect(
                credential.authenticatorData.flags.contains(.attestedCredentialData),
                "Attested credential data flag should be set"
            )

            // Verify credential data exists
            guard let attestedData = credential.authenticatorData.attestedCredentialData else {
                Issue.record("Missing attested credential data")
                return
            }
            #expect(attestedData.credentialId.count >= 16, "Credential ID should be at least 16 bytes")
            print("Resident credential created! Format: \(credential.format)")

            // TODO: Store credential ID for cleanup once credentialManagement is implemented
        }
    }

    @Test("Make Credential - With Exclude List")
    func testMakeCredentialWithExcludeList() async throws {
        try await withCTAP2Session { session in
            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let userId = Data(repeating: 0x04, count: 32)

            // First, create a credential
            let params1 = CTAP.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredentialRPEntity(id: "example.com", name: "Example Corp"),
                user: PublicKeyCredentialUserEntity(
                    id: userId,
                    name: "exclude@example.com",
                    displayName: "Exclude Test User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: false)
            )

            print("Touch the YubiKey to create the first credential...")
            let credential1 = try await session.makeCredential(parameters: params1)

            // Extract credential ID from authenticatorData
            guard let attestedData = credential1.authenticatorData.attestedCredentialData else {
                Issue.record("No attested credential data in response")
                return
            }

            let credentialId = attestedData.credentialId

            // Now try to create another credential with excludeList containing the first
            let params2 = CTAP.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredentialRPEntity(id: "example.com", name: "Example Corp"),
                user: PublicKeyCredentialUserEntity(
                    id: userId,
                    name: "exclude@example.com",
                    displayName: "Exclude Test User"
                ),
                pubKeyCredParams: [.es256],
                excludeList: [PublicKeyCredentialDescriptor(id: credentialId)],
                options: .init(rk: false)
            )

            print("Touch the YubiKey - this should fail with CREDENTIAL_EXCLUDED...")
            do {
                _ = try await session.makeCredential(parameters: params2)
                Issue.record("Expected CREDENTIAL_EXCLUDED error but makeCredential succeeded")
            } catch let error as FIDO2SessionError {
                // Verify it's specifically the credentialExcluded error
                if case .ctapError(let ctapError, _) = error,
                    case .credentialExcluded = ctapError
                {
                    print("✅ Got expected CREDENTIAL_EXCLUDED error")
                } else {
                    Issue.record("Expected CREDENTIAL_EXCLUDED but got: \(error)")
                }
            } catch {
                Issue.record("Got unexpected error type: \(error)")
            }
        }
    }

    @Test("Make Credential - Algorithm Preference Order")
    func testMakeCredentialAlgorithmPreference() async throws {
        // Test that EdDSA is preferred when listed first, with ES256 as fallback
        try await withCTAP2Session { session in
            let clientDataHash = Data(repeating: 0xCD, count: 32)

            let params = CTAP.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredentialRPEntity(id: "example.com", name: "Example Corp"),
                user: PublicKeyCredentialUserEntity(
                    id: Data(repeating: 0x40, count: 32),
                    name: "algpref@example.com",
                    displayName: "Algorithm Preference User"
                ),
                pubKeyCredParams: [.edDSA, .es256]  // EdDSA preferred, ES256 fallback
            )

            print("Touch the YubiKey to test algorithm preference (EdDSA preferred, ES256 fallback)...")
            let credential = try await session.makeCredential(parameters: params)

            guard let attestedData = credential.authenticatorData.attestedCredentialData else {
                Issue.record("Failed to parse credential")
                return
            }

            // Should use EdDSA if supported, otherwise fall back to ES256
            let coseKey = attestedData.credentialPublicKey

            switch coseKey {
            case .okp(let alg, _, let crv, _) where alg == .edDSA && crv == 6:
                print("✅ EdDSA was used as preferred algorithm")
            case .ec2(let alg, _, let crv, _, _) where alg == .es256 && crv == 1:
                print("✅ EdDSA not supported, ES256 was used as fallback")
            default:
                Issue.record("Unexpected key type: \(coseKey)")
            }
        }
    }

    // MARK: - GetAssertion Tests

    @Test("Get Assertion - Basic Flow")
    func testGetAssertionBasic() async throws {
        try await withCTAP2Session { session in
            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let userId = Data(repeating: 0x10, count: 32)

            // First, create a credential to authenticate with
            let makeCredParams = CTAP.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredentialRPEntity(id: "example.com", name: "Example Corp"),
                user: PublicKeyCredentialUserEntity(
                    id: userId,
                    name: "getassertion@example.com",
                    displayName: "Get Assertion User"
                ),
                pubKeyCredParams: [.es256],
                options: .init(rk: false)
            )

            print("Touch the YubiKey to create a credential...")
            let credential = try await session.makeCredential(parameters: makeCredParams)

            guard let attestedData = credential.authenticatorData.attestedCredentialData else {
                Issue.record("No attested credential data in response")
                return
            }

            let credentialId = attestedData.credentialId

            // Now authenticate with the credential
            let getAssertionParams = CTAP.GetAssertion.Parameters(
                rpId: "example.com",
                clientDataHash: clientDataHash,
                allowList: [PublicKeyCredentialDescriptor(id: credentialId)]
            )

            print("Touch the YubiKey to authenticate...")
            let assertion = try await session.getAssertion(parameters: getAssertionParams)

            // Verify response structure
            #expect(assertion.authenticatorData.rpIdHash.count == 32)
            #expect(assertion.authenticatorData.flags.contains(.userPresent), "User presence flag should be set")
            #expect(assertion.signature.count > 0, "Signature should be present")
            #expect(assertion.credential?.id == credentialId, "Credential ID should match")

            print("✅ Get assertion successful! Signature length: \(assertion.signature.count) bytes")
        }
    }

    @Test("Get Assertions - AsyncSequence")
    func testGetAssertions() async throws {
        try await withCTAP2Session { session in
            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let rpId = "multiassert.example.com"

            // Create multiple resident keys for the same RP
            for i in 1...3 {
                let makeCredParams = CTAP.MakeCredential.Parameters(
                    clientDataHash: clientDataHash,
                    rp: PublicKeyCredentialRPEntity(id: rpId, name: "Multi Assert Corp"),
                    user: PublicKeyCredentialUserEntity(
                        id: Data(repeating: UInt8(0x20 + i), count: 32),
                        name: "user\(i)@example.com",
                        displayName: "User \(i)"
                    ),
                    pubKeyCredParams: [.es256],
                    options: .init(rk: true)
                )

                print("Touch the YubiKey to create credential \(i)/3...")
                _ = try await session.makeCredential(parameters: makeCredParams)
            }

            let getAssertionParams = CTAP.GetAssertion.Parameters(
                rpId: rpId,
                clientDataHash: clientDataHash,
                allowList: nil  // Resident key discovery
            )

            print("Touch the YubiKey to iterate through assertions...")

            // Iterate through all assertions
            let sequence = await session.getAssertions(parameters: getAssertionParams)
            var count = 0
            for try await assertion in sequence {
                count += 1
                #expect(assertion.signature.count > 0)
                print("  Assertion \(count): signature length \(assertion.signature.count) bytes")
            }

            print("✅ Iterated through \(count) assertions")
            #expect(count >= 1)
        }
    }

    // MARK: - Cancellation Tests

    #if os(macOS)
    @Test("Cancel MakeCredential")
    func testCancelMakeCredential() async throws {
        try await withCTAP2Session { session in
            let clientDataHash = Data(repeating: 0xCD, count: 32)
            let userId = Data(repeating: 0x98, count: 32)

            let params = CTAP.MakeCredential.Parameters(
                clientDataHash: clientDataHash,
                rp: PublicKeyCredentialRPEntity(id: "example.com", name: "Example Corp"),
                user: PublicKeyCredentialUserEntity(
                    id: userId,
                    name: "cancel-delayed@example.com",
                    displayName: "Cancel Delayed Test User"
                ),
                pubKeyCredParams: [.es256]
            )

            print("Starting makeCredential - will cancel after 500ms...")
            print("DO NOT touch the YubiKey - operation will be cancelled")

            // Create a task for the makeCredential operation
            let makeCredential = Task {
                try await session.makeCredential(parameters: params)
            }

            // Schedule cancellation after 500ms delay
            try await Task.sleep(for: .milliseconds(500))
            print("Sending cancellation...")
            try await session.cancel()

            do {
                _ = try await makeCredential.value
                Issue.record("makeCredential should have been cancelled")
            } catch let error as FIDO2SessionError {
                // Verify we got the expected cancellation error
                guard case .ctapError(.keepaliveCancel, _) = error else {
                    Issue.record("Expected keepaliveCancel error, got: \(error)")
                    return
                }
                print("✅ Delayed cancellation successful - received keepaliveCancel error")
            } catch {
                Issue.record("Unexpected error type: \(error)")
            }

            // Verify the connection still works after cancellation
            print("Verifying connection still works...")
            let info = try await session.getInfo()
            #expect(!info.versions.isEmpty, "Should be able to get info after cancellation")
            print("✅ Connection still functional after cancellation")
        }
    }

    #endif  // os(macOS)

    @Test(
        "Reset - Factory Reset",
        .disabled("Destructive operation - manually enable when needed to reset YubiKey to factory settings")
    )
    func testReset() async throws {
        // This test destructively resets the authenticator
        try await withCTAP2Session { session in
            // The reset command must be called within a few seconds of plugging in the YubiKey
            // and requires user presence confirmation otherwise it will fail
            print("Touch the YubiKey to confirm reset...")
            try await session.reset()
            print("Reset successful!")

            // Verify the authenticator was reset by checking info
            let info = try await session.getInfo()
            // After reset, clientPin should not be set
            #expect(info.options["clientPin"] == false, "clientPin should be false after reset")
        }
    }

    // MARK: - Helper Methods

    #if os(macOS)
    private func withCTAP2Session<T>(
        _ body: (FIDO2Session) async throws -> T
    ) async throws -> T {
        let connection = try await HIDFIDOConnection.makeConnection()
        let session = try await CTAP.Session.makeSession(connection: connection)
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
